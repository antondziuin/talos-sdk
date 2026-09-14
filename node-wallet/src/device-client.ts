import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign,
  type KeyObject,
} from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { dirname } from "node:path";
import { performance } from "node:perf_hooks";
import lockfile from "proper-lockfile";
import {
  collectFingerprint,
  defaultStatePath,
  StateStore,
} from "@antondziuin/talos-sdk";
import {
  keccak256,
  toHex,
  encodeFunctionData,
  decodeFunctionResult,
  parseAbi,
  type Hex,
} from "viem";
import {
  deviceTypedData,
  deviceRef,
  licenseRef,
  verifyDevice,
  type DeviceAuthorization,
  type Trust,
  type SignedMessage,
} from "./protocol.js";
import {
  deviceCertificateTypedData,
  consentContext,
  verifyEnrollment,
  verifyDeviceCertificate,
  verifyRenewalChallenge,
  renewalEndpoint,
  DEVICE_RENEW_AFTER_SECONDS,
  type Enrollment,
  type DeviceCertificate,
} from "./device-protocol.js";
export interface DeviceLicenseOptions extends Trust {
  statePath?: string;
  fingerprintComponents?: Record<string, string>;
  renewalUrl?: string;
  fetch?: typeof globalThis.fetch;
  onRefreshError?: (reason: string) => void;
}
/** Offline execution permit; background renewal never invalidates an unexpired certificate. */
export class DeviceLicenseClient {
  readonly deviceKey: Hex;
  readonly fingerprintHash: Hex;
  private enrollment?: Enrollment;
  private authorization?: DeviceAuthorization;
  private certificate?: DeviceCertificate;
  private entitlements: Record<string, unknown> = {};
  private timer?: ReturnType<typeof setTimeout>;
  private timerEpoch = 0;
  private started = false;
  private pending?: Promise<void>;
  private starting?: Promise<void>;
  private epoch = 0;
  private highWater = Date.now();
  private anchor = performance.now();
  private constructor(
    private options: DeviceLicenseOptions,
    private key: KeyObject,
    device: Hex,
    fingerprint: string,
    private path: string,
  ) {
    this.deviceKey = device;
    this.fingerprintHash = keccak256(toHex(fingerprint));
  }
  static async create(
    options: DeviceLicenseOptions,
  ): Promise<DeviceLicenseClient> {
    options = { ...options };
    const scope = `wallet-device:${options.issuer.toLowerCase()}:${options.productId.toLowerCase()}`;
    const fp = collectFingerprint(scope, options.fingerprintComponents);
    const path = options.statePath ?? defaultStatePath(scope);
    mkdirSync(dirname(path), { recursive: true });
    const unlock = await lockfile.lock(path, {
      realpath: false,
      retries: { retries: 70, minTimeout: 500, maxTimeout: 500 },
      stale: 30000,
    });
    try {
      const store = new StateStore(path, scope, fp.composite);
      let saved = store.load();
      if (!saved?.machineKey || !saved.machinePublicKey) {
        const kp = generateKeyPairSync("ed25519");
        saved = {
          licenseKeyHash: "",
          activationSecret: "",
          machineId: "",
          fingerprint: fp.composite,
          machineKey: kp.privateKey
            .export({ format: "der", type: "pkcs8" })
            .toString("base64"),
          machinePublicKey: kp.publicKey
            .export({ format: "der", type: "spki" })
            .subarray(-32)
            .toString("base64"),
        };
        if (!store.save(saved)) throw new Error("device_key_not_saved");
      }
      const key = createPrivateKey({
        key: Buffer.from(saved.machineKey!, "base64"),
        format: "der",
        type: "pkcs8",
      });
      const c = new DeviceLicenseClient(
        options,
        key,
        toHex(
          createPublicKey(key)
            .export({ format: "der", type: "spki" })
            .subarray(-32),
        ),
        fp.composite,
        path,
      );
      let cache;
      try {
        cache = JSON.parse(readFileSync(path + ".device.json", "utf8"));
      } catch {
        /* first use */
      }
      if (cache) {
        if (
          Number.isSafeInteger(cache.observed_at) &&
          cache.observed_at > c.highWater
        )
          c.highWater = cache.observed_at;
        try {
          await c.importEnrollment(cache.enrollment, false);
          if (cache.authorization)
            await c.acceptDeviceAuthorization(cache.authorization, false);
        } catch {
          /* invalid bootstrap never permits execution */
        }
        if (c.enrollment && c.authorization && cache.certificate) {
          try {
            c.entitlements = await verifyDeviceCertificate(
              cache.certificate,
              c.enrollment,
              c.authorization,
              options,
              c.now(),
            );
            c.certificate = cache.certificate;
          } catch {
            /* expired certificate can still be renewed online */
          }
        }
      }
      return c;
    } finally {
      await unlock();
    }
  }
  private now(): number {
    const mono = performance.now();
    this.highWater = Math.max(
      Date.now(),
      this.highWater + Math.max(0, mono - this.anchor),
    );
    this.anchor = mono;
    return Math.floor(this.highWater / 1000);
  }
  get isDeviceAuthorized(): boolean {
    return !!this.enrollment && !!this.authorization;
  }
  get canRun(): boolean {
    return (
      this.started &&
      !!this.certificate &&
      this.now() < this.certificate.license.expires_at
    );
  }
  get expiresAt(): number | undefined {
    return this.certificate?.license.expires_at;
  }
  requireValidCertificate(): void {
    if (!this.canRun) throw new Error("device_certificate_expired");
  }
  getEntitlement<T = unknown>(name: string): T | undefined {
    this.requireValidCertificate();
    return this.entitlements[name] as T | undefined;
  }
  async importEnrollment(e: Enrollment, persist = true): Promise<void> {
    if (this.started) throw new Error("stop_before_import");
    e = JSON.parse(JSON.stringify(e));
    await verifyEnrollment(e, this.options);
    if (this.enrollment?.signature === e.signature) {
      if (persist) await this.save();
      return;
    }
    this.epoch++;
    this.enrollment = e;
    this.authorization = undefined;
    this.certificate = undefined;
    this.entitlements = {};
    if (persist) await this.save();
  }
  createDeviceAuthorization() {
    if (!this.enrollment) throw new Error("enrollment_required");
    return deviceTypedData(consentContext(this.enrollment), {
      device_key: this.deviceKey,
      fingerprint_hash: this.fingerprintHash,
    });
  }
  async acceptDeviceAuthorization(
    value: Hex | DeviceAuthorization,
    persist = true,
  ): Promise<void> {
    if (!this.enrollment) throw new Error("enrollment_required");
    const d =
      typeof value === "string"
        ? {
            device_key: this.deviceKey,
            fingerprint_hash: this.fingerprintHash,
            signature: value,
          }
        : (JSON.parse(JSON.stringify(value)) as DeviceAuthorization);
    if (
      d.device_key !== this.deviceKey ||
      d.fingerprint_hash !== this.fingerprintHash
    )
      throw new Error("wrong_device");
    await verifyDevice(consentContext(this.enrollment), d);
    this.authorization = d;
    if (persist) await this.save();
  }
  start(): Promise<void> {
    if (this.starting) return this.starting;
    const work = this.startInternal();
    this.starting = work;
    void work
      .finally(() => {
        if (this.starting === work) this.starting = undefined;
      })
      .catch(() => {});
    return work;
  }
  private async startInternal(): Promise<void> {
    if (this.started) return;
    this.started = true;
    const epoch = this.epoch;
    try {
      if (!this.canRun) await this.refresh();
      if (!this.started || epoch !== this.epoch || !this.canRun)
        throw new Error("start_interrupted");
      await this.save();
      this.schedule();
    } catch (e) {
      if (epoch === this.epoch) this.started = false;
      throw e;
    }
  }
  async stop(): Promise<void> {
    this.started = false;
    this.epoch++;
    this.timerEpoch++;
    if (this.timer) clearTimeout(this.timer);
    if (this.pending) await this.pending.catch(() => {});
    await this.save();
  }
  /** Call on connectivity restoration or wake; an existing offline permit stays valid. */
  notifyResume(): void {
    if (this.started) {
      if (this.timer) clearTimeout(this.timer);
      this.schedule(true);
    }
  }
  async refresh(): Promise<void> {
    if (this.pending) return this.pending;
    const epoch = this.epoch;
    const work = this.renew(epoch);
    this.pending = work;
    try {
      await work;
    } finally {
      if (this.pending === work) this.pending = undefined;
    }
  }
  private async renew(epoch: number): Promise<void> {
    const e = this.enrollment,
      d = this.authorization;
    if (!e || !d) throw new Error("device_authorization_required");
    const context = { enrollment: e, device: d };
    const endpoint = renewalEndpoint(this.options.renewalUrl ?? e.renewal_url);
    const post = async <T>(path: string, body: unknown): Promise<T> => {
      const response = await (this.options.fetch ?? fetch)(
        endpoint + "/v1/client/wallet/" + path,
        {
          method: "POST",
          redirect: "error",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(10000),
        },
      );
      if (!response.ok)
        throw new Error("device_renewal_http_" + response.status);
      const text = await response.text();
      if (text.length > 65536) throw new Error("response_too_large");
      return JSON.parse(text) as T;
    };
    const challenge = await post<SignedMessage>("challenge", context);
    const c = await verifyRenewalChallenge(e.issuer, challenge);
    const now = this.now();
    if (
      c.license_ref !== licenseRef(consentContext(e)) ||
      c.device_ref !== deviceRef(d) ||
      c.revision !== e.revision ||
      !Number.isSafeInteger(c.issued_at) ||
      !Number.isSafeInteger(c.expires_at) ||
      c.issued_at > now + 30 ||
      c.expires_at <= now ||
      c.expires_at > c.issued_at + 120
    )
      throw new Error("invalid_challenge");
    const proof = toHex(
      sign(
        null,
        Buffer.from("talos-wallet.2.proof." + challenge.payload),
        this.key,
      ),
    );
    const next = await post<DeviceCertificate>("renew", {
      context,
      challenge,
      proof,
    });
    const ent = await verifyDeviceCertificate(
      next,
      e,
      d,
      this.options,
      this.now(),
    );
    if (epoch !== this.epoch) return;
    if (
      this.certificate &&
      next.license.not_before < this.certificate.license.not_before
    )
      throw new Error("certificate_rollback");
    this.certificate = next;
    this.entitlements = ent;
    await this.save();
  }
  private schedule(resume = false): void {
    if (!this.started) return;
    if (this.timer) clearTimeout(this.timer);
    const timerEpoch = ++this.timerEpoch;
    const due =
      Math.min(
        (this.certificate?.license.not_before ?? 0) +
          DEVICE_RENEW_AFTER_SECONDS,
        (this.certificate?.license.expires_at ?? 0) - 3600,
      ) - this.now();
    this.timer = setTimeout(
      () => {
        void this.refresh()
          .catch((e) => {
            try {
              this.options.onRefreshError?.(String(e));
            } catch {
              /* application callback */
            }
          })
          .finally(() => {
            if (this.started && timerEpoch === this.timerEpoch) {
              this.timer = setTimeout(() => this.schedule(), 3600000);
              this.timer.unref?.();
            }
          });
      },
      Math.max(resume ? 0 : 1000, Math.min(due * 1000, 86400000)),
    );
    this.timer.unref?.();
  }
  private async save(): Promise<void> {
    this.now();
    const unlock = await lockfile.lock(this.path, {
      realpath: false,
      retries: { retries: 70, minTimeout: 500, maxTimeout: 500 },
      stale: 30000,
    });
    try {
      let observed = this.highWater;
      let saved = {
        enrollment: this.enrollment,
        authorization: this.authorization,
        certificate: this.certificate,
      };
      try {
        const old = JSON.parse(
          readFileSync(this.path + ".device.json", "utf8"),
        );
        if (Number.isSafeInteger(old.observed_at))
          observed = Math.max(observed, old.observed_at);
        // Another process may have renewed or imported a transfer since we loaded.
        // Never replace that shared state with our older snapshot on shutdown.
        if (old.enrollment) {
          await verifyEnrollment(old.enrollment, this.options);
          const sameLicense =
            !this.enrollment ||
            licenseRef(consentContext(old.enrollment)) ===
              licenseRef(consentContext(this.enrollment));
          if (
            sameLicense &&
            (!this.enrollment ||
              old.enrollment.revision > this.enrollment.revision)
          ) {
            saved = old;
          } else if (
            sameLicense &&
            old.enrollment.revision === this.enrollment?.revision &&
            old.authorization &&
            old.certificate &&
            old.authorization.device_key === this.deviceKey &&
            old.authorization.fingerprint_hash === this.fingerprintHash &&
            (!this.certificate ||
              old.certificate.license.not_before >
                this.certificate.license.not_before ||
              (old.certificate.license.not_before ===
                this.certificate.license.not_before &&
                old.certificate.license.expires_at >
                  this.certificate.license.expires_at))
          ) {
            await verifyDevice(
              consentContext(old.enrollment),
              old.authorization,
            );
            await verifyDeviceCertificate(
              old.certificate,
              old.enrollment,
              old.authorization,
              this.options,
              this.now(),
            );
            saved = old;
          }
        }
      } catch {
        /* no cache */
      }
      const temp = this.path + ".device." + randomUUID() + ".tmp";
      writeFileSync(
        temp,
        JSON.stringify({
          enrollment: saved.enrollment,
          authorization: saved.authorization,
          certificate: saved.certificate,
          observed_at: Math.ceil(observed),
        }),
        { mode: 0o600 },
      );
      renameSync(temp, this.path + ".device.json");
    } finally {
      await unlock();
    }
  }
  async verifyViaContract(rpcUrl: string): Promise<boolean> {
    if (!this.certificate) throw new Error("certificate_required");
    if (!this.enrollment || !this.authorization)
      throw new Error("device_authorization_required");
    await verifyDeviceCertificate(
      this.certificate,
      this.enrollment,
      this.authorization,
      this.options,
      this.now(),
    );
    const abi = parseAbi([
      "function verifyDeviceCertificate((bytes32 tenantId,bytes32 productId,bytes32 licenseId,address holder,bytes32 deviceKey,bytes32 fingerprintHash,uint64 revision,uint64 notBefore,uint64 expiresAt,bytes32 entitlementsHash) l,bytes signature,address expectedIssuer) view returns(bool)",
    ]);
    const data = encodeFunctionData({
      abi,
      functionName: "verifyDeviceCertificate",
      args: [
        deviceCertificateTypedData(this.certificate).message,
        this.certificate.signature,
        this.options.issuer,
      ],
    });
    const chainResponse = await (this.options.fetch ?? fetch)(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_chainId",
        params: [],
      }),
      signal: AbortSignal.timeout(10000),
    });
    const chainBody = await chainResponse.json();
    if (
      !chainResponse.ok ||
      chainBody.error ||
      Number(chainBody.result) !== this.options.chainId
    )
      throw new Error("wrong_rpc_chain");
    const r = await (this.options.fetch ?? fetch)(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "eth_call",
        params: [{ to: this.options.contract, data }, "latest"],
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) throw new Error("rpc_unavailable");
    const body = await r.json();
    if (body.error) throw new Error("rpc_unavailable");
    return decodeFunctionResult({
      abi,
      functionName: "verifyDeviceCertificate",
      data: body.result,
    });
  }
}
