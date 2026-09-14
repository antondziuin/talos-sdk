import {
  createPrivateKey,
  generateKeyPairSync,
  randomUUID,
  sign,
  type KeyObject,
} from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { performance } from "node:perf_hooks";
import lockfile from "proper-lockfile";
import {
  collectFingerprint,
  defaultStatePath,
  StateStore,
} from "@antondziuin/talos-sdk";
import {
  encodeFunctionData,
  decodeFunctionResult,
  keccak256,
  parseAbi,
  toHex,
  type Hex,
} from "viem";
import {
  deviceRef,
  deviceTypedData,
  licenseRef,
  licenseTypedData,
  verifyCertificate,
  verifyDevice,
  verifyMessage,
  type Certificate,
  type DeviceAuthorization,
  type Trust,
  type Challenge,
  type SignedMessage,
  type Lease,
} from "./protocol.js";
export * from "./protocol.js";
export * from "./device-protocol.js";
export * from "./device-client.js";

export interface WalletOptions extends Trust {
  statePath?: string;
  fingerprintComponents?: Record<string, string>;
  coordinatorUrl?: string;
  fetch?: typeof globalThis.fetch;
  onSessionLost?: (reason: string) => void;
}
/** One instance per running process. Device identity and wallet consent are shared on disk. */
export class WalletLicenseClient {
  private sessionId = randomUUID();
  get instanceId() {
    return this.sessionId;
  }
  readonly deviceKey: Hex;
  readonly fingerprintHash: Hex;
  private certificate?: Certificate;
  private authorization?: DeviceAuthorization;
  private entitlements: Record<string, unknown> = {};
  private timer?: ReturnType<typeof setTimeout>;
  private deadline = 0;
  private lastMono = performance.now();
  private lastWall = Date.now();
  private generation = 0;
  private started = false;
  private pending: Promise<void> = Promise.resolve();
  private stopping?: Promise<void>;
  private leaseEpoch = 0;
  private constructor(
    private options: WalletOptions,
    private key: KeyObject,
    deviceKey: Hex,
    fingerprint: string,
    private path: string,
  ) {
    this.deviceKey = deviceKey;
    this.fingerprintHash = keccak256(toHex(fingerprint));
  }
  static async create(options: WalletOptions): Promise<WalletLicenseClient> {
    const scope = `wallet:${options.issuer.toLowerCase()}:${options.productId.toLowerCase()}`;
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
      const client = new WalletLicenseClient(
        options,
        key,
        toHex(Buffer.from(saved.machinePublicKey!, "base64")),
        fp.composite,
        path,
      );
      let cached: string | undefined;
      try {
        cached = readFileSync(path + ".wallet.json", "utf8");
      } catch {
        /* first use */
      }
      if (cached) {
        try {
          const { certificate, authorization } = JSON.parse(cached);
          await client.importCertificate(certificate, false);
          if (authorization)
            await client.acceptDeviceAuthorization(authorization, false);
        } catch {
          /* Invalid or expired public cache never grants access. */
        }
      }
      return client;
    } finally {
      await unlock();
    }
  }
  async importCertificate(
    certificate: Certificate,
    persist = true,
  ): Promise<void> {
    if (this.started) throw new Error("stop_session_before_import");
    const c = JSON.parse(JSON.stringify(certificate)) as Certificate;
    const ent = await verifyCertificate(c, this.options);
    if (
      this.authorization &&
      this.certificate &&
      licenseRef(this.certificate) !== licenseRef(c)
    )
      this.authorization = undefined;
    this.certificate = c;
    this.entitlements = ent;
    if (persist) await this.save();
  }
  createDeviceAuthorization() {
    if (!this.certificate) throw new Error("certificate_required");
    return deviceTypedData(this.certificate, {
      device_key: this.deviceKey,
      fingerprint_hash: this.fingerprintHash,
    });
  }
  async acceptDeviceAuthorization(
    value: Hex | DeviceAuthorization,
    persist = true,
  ): Promise<void> {
    if (!this.certificate) throw new Error("certificate_required");
    const d =
      typeof value === "string"
        ? {
            device_key: this.deviceKey,
            fingerprint_hash: this.fingerprintHash,
            signature: value,
          }
        : { ...value };
    if (
      d.device_key !== this.deviceKey ||
      d.fingerprint_hash !== this.fingerprintHash
    )
      throw new Error("wrong_device");
    await verifyDevice(this.certificate, d);
    this.authorization = d;
    if (persist) await this.save();
  }
  private async save() {
    const unlock = await lockfile.lock(this.path, {
      realpath: false,
      retries: 5,
    });
    try {
      const temp = this.path + `.${randomUUID()}.tmp`;
      writeFileSync(
        temp,
        JSON.stringify({
          certificate: this.certificate,
          authorization: this.authorization,
        }),
        { mode: 0o600 },
      );
      renameSync(temp, this.path + ".wallet.json");
    } finally {
      await unlock();
    }
  }
  get isDeviceAuthorized() {
    return !!this.certificate && !!this.authorization;
  }
  get canRun(): boolean {
    const mono = performance.now(),
      wall = Date.now();
    // Detect suspension and wall-clock steps, including platforms whose monotonic clock pauses in sleep.
    if (Math.abs(wall - this.lastWall - (mono - this.lastMono)) > 1500) {
      this.notifyResume();
      this.lastWall = wall;
      this.lastMono = mono;
    }
    return this.started && mono < this.deadline;
  }
  requireActiveSession(): void {
    if (!this.canRun) throw new Error("active_session_required");
  }
  getEntitlement(name: string): unknown {
    this.requireActiveSession();
    return this.entitlements[name];
  }
  notifyResume(): void {
    this.deadline = 0;
    this.leaseEpoch++;
  }
  async startSession(): Promise<void> {
    if (this.started || this.stopping)
      throw new Error("session_already_started_or_stopping");
    this.sessionId = randomUUID();
    const generation = ++this.generation;
    this.started = true;
    try {
      await this.exchange("acquire");
      if (!this.started || generation !== this.generation)
        throw new Error("session_interrupted");
      this.schedule();
    } catch (e) {
      if (generation === this.generation) this.started = false;
      throw e;
    }
  }
  async stopSession(): Promise<void> {
    if (this.stopping) return this.stopping;
    this.generation++;
    this.started = false;
    this.deadline = 0;
    clearTimeout(this.timer);
    this.stopping = (async () => {
      if (this.isDeviceAuthorized) {
        try {
          await this.exchange("release");
        } catch {
          /* occupancy still expires within 60s */
        }
      }
    })();
    try {
      await this.stopping;
    } finally {
      this.stopping = undefined;
    }
  }
  private schedule() {
    clearTimeout(this.timer);
    const generation = this.generation;
    this.timer = setTimeout(
      () =>
        void (async () => {
          try {
            await this.exchange("renew");
          } catch (e) {
            if (!this.canRun)
              this.options.onSessionLost?.(
                e instanceof Error ? e.message : "coordinator_unavailable",
              );
          }
          if (this.started && generation === this.generation) this.schedule();
        })(),
      this.canRun ? 20000 : 2000,
    );
    this.timer.unref?.();
  }
  private async request(
    path: string,
    body: unknown,
    method = "POST",
  ): Promise<SignedMessage> {
    if (!this.certificate) throw new Error("certificate_required");
    const url = new URL(
      this.options.coordinatorUrl ?? this.certificate.coordinator_url,
    );
    if (
      url.username ||
      url.password ||
      (url.protocol !== "https:" &&
        !(
          url.protocol === "http:" &&
          ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
        ))
    )
      throw new Error("insecure_coordinator_url");
    const response = await (this.options.fetch ?? fetch)(
      url.href.replace(/\/$/, "") + path,
      {
        method,
        body: JSON.stringify(body),
        headers: { "content-type": "application/json" },
        signal: AbortSignal.timeout(10000),
        redirect: "error",
      },
    );
    if (!response.ok) {
      const e = await response.json().catch(() => ({}));
      throw new Error(e.error ?? "coordinator_unavailable");
    }
    return (await response.json()) as SignedMessage;
  }
  private async exchange(
    action: "acquire" | "renew" | "release",
  ): Promise<void> {
    const generation = this.generation;
    const next = this.pending.then(() =>
      this.performExchange(action, generation),
    );
    this.pending = next.catch(() => {});
    return next;
  }
  private async performExchange(
    action: "acquire" | "renew" | "release",
    generation: number,
  ): Promise<void> {
    if (!this.certificate || !this.authorization)
      throw new Error("device_authorization_required");
    if (
      action !== "release" &&
      (!this.started || generation !== this.generation)
    )
      throw new Error("session_interrupted");
    const leaseEpoch = this.leaseEpoch;
    const context = {
      certificate: this.certificate,
      device: this.authorization,
      instance_id: this.instanceId,
      action,
    };
    const signed = await this.request("/v1/leases/challenge", context);
    const challenge = verifyMessage<Challenge>(
      this.certificate.license.coordinator_key,
      "challenge",
      signed,
    );
    if (
      challenge.license_ref !== licenseRef(this.certificate) ||
      challenge.device_ref !== deviceRef(this.authorization) ||
      challenge.instance_id !== this.instanceId ||
      challenge.action !== action ||
      challenge.expires_at - challenge.issued_at !== 30
    )
      throw new Error("challenge_mismatch");
    const proof = toHex(
      sign(
        null,
        Buffer.from(`talos-wallet.1.proof.${signed.payload}`),
        this.key,
      ),
    );
    const start = performance.now(),
      startWall = Date.now();
    const result = await this.request(
      action === "acquire"
        ? "/v1/leases"
        : `/v1/leases/${this.instanceId}${action === "renew" ? "/renew" : ""}`,
      { context, challenge: signed, proof },
      action === "release" ? "DELETE" : "POST",
    );
    const lease = verifyMessage<Lease>(
      this.certificate.license.coordinator_key,
      action === "release" ? "released" : "lease",
      result,
    );
    if (
      lease.nonce !== challenge.nonce ||
      lease.license_ref !== challenge.license_ref ||
      lease.device_ref !== challenge.device_ref ||
      lease.instance_id !== this.instanceId ||
      !Number.isSafeInteger(lease.issued_at) ||
      !Number.isSafeInteger(lease.expires_at) ||
      lease.expires_at - lease.issued_at > 60 ||
      lease.issued_at < challenge.issued_at ||
      (this.certificate.license.expires_at !== 0 &&
        lease.expires_at > this.certificate.license.expires_at)
    )
      throw new Error("lease_mismatch");
    if (
      action !== "release" &&
      generation === this.generation &&
      this.started
    ) {
      if (
        leaseEpoch !== this.leaseEpoch ||
        Math.abs(Date.now() - startWall - (performance.now() - start)) > 1500
      )
        throw new Error("session_interrupted_by_clock_or_resume");
      // Five seconds cover timestamp rounding, bounded clock drift, and resume detection tolerance.
      const deadline =
        start + (lease.expires_at - lease.issued_at) * 1000 - 5000;
      if (performance.now() >= deadline)
        throw new Error("lease_expired_in_transit");
      this.deadline = deadline;
      this.lastMono = performance.now();
      this.lastWall = Date.now();
    }
  }
  /** Additional certificate check only; it cannot replace a coordinator session. */
  async verifyViaContract(rpcUrl: string): Promise<boolean> {
    if (!this.certificate) throw new Error("certificate_required");
    await verifyCertificate(this.certificate, this.options);
    const abi = parseAbi([
      "function verifyLicense((bytes32 tenantId,bytes32 productId,bytes32 licenseId,address holder,uint64 notBefore,uint64 expiresAt,bytes32 entitlementsHash,bytes32 coordinatorKey,uint8 maxConcurrentDevices) l,bytes signature,address expectedIssuer) view returns(bool)",
    ]);
    const data = encodeFunctionData({
      abi,
      functionName: "verifyLicense",
      args: [
        licenseTypedData(this.certificate).message,
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
      functionName: "verifyLicense",
      data: body.result,
    });
  }
}
