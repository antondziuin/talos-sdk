import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { performance } from "node:perf_hooks";
import lockfile from "proper-lockfile";
import { collectFingerprint, defaultStatePath, StateStore } from "@antondziuin/talos-sdk";
import { decodeFunctionResult, encodeFunctionData, toHex, type Hex } from "viem";
import { checkHex, type Trust } from "./protocol.js";
import { registryAbi, registryManifest, registryActivationEndpoint, registryActivationProofText, registryActivationStatusProofText, registryUuid, RegistryLicenseError, type RegistryLicenseManifest } from "./registry-protocol.js";
import { registryBlock, registryChainState, sameRegistryHead, type RegistryBlock, type RegistryChainState } from "./registry-chain-state.js";

export interface RegistryLicenseOptions extends Trust {
  rpcUrls: readonly string[];
  statePath?: string;
  fingerprintComponents?: Record<string, string>;
  fetch?: typeof globalThis.fetch;
  /** Trusted application configuration, never taken from an imported customer file. */
  activationUrl?: string;
  productToken?: string;
}

export interface RegistryActivationProgress {
  status: "pending" | "validating" | "ready";
  activationId: string;
  retryAfterSeconds: number;
}

export interface RegistryActivationOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
  onProgress?: (progress: RegistryActivationProgress) => void;
}

interface ActivationResponse {
  status: "pending" | "ready" | "failed";
  activation_id: string;
  manifest: RegistryLicenseManifest | null;
  error: string | null;
  retry_after_s: number;
}

/** A fresh observation, never an offline execution permit. Recheck before each protected operation. */
export interface RegistryLicenseState {
  isValid: true;
  entitlements: Record<string, unknown>;
  expiresAt: number | null;
  notBefore: number;
  revision: number;
  blockNumber: bigint;
  blockHash: Hex;
  checkedAt: number;
}

class TransientRpcError extends RegistryLicenseError {}

/** Validity comes directly from RPC. Optional code activation contacts Talos only to arrange publication. */
export class RegistryLicenseClient {
  private license?: ReturnType<typeof registryManifest>;
  private generation = 0;
  private highWater: number;
  private anchor = performance.now();
  private activationId?: string;
  private activationWork?: Promise<RegistryLicenseState>;

  private constructor(
    private options: RegistryLicenseOptions,
    private store: StateStore,
    readonly deviceKey: Hex,
    private path: string,
    observed: number,
    private key: KeyObject,
  ) {
    this.highWater = Math.max(Date.now() / 1000, observed);
  }

  static async create(options: RegistryLicenseOptions): Promise<RegistryLicenseClient> {
    try {
      for (const a of [options.issuer, options.contract]) {
        checkHex(a, 20);
        if (/^0x0+$/.test(a)) throw new Error();
      }
      checkHex(options.productId, 32);
      if (/^0x0+$/.test(options.productId) || ![8453, 11155111, 31337].includes(options.chainId)
        || !Array.isArray(options.rpcUrls) || options.rpcUrls.length < 1 || options.rpcUrls.length > 5) throw new Error();
      for (const value of options.rpcUrls) {
        const url = new URL(value);
        if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) throw new Error();
        if (url.username || url.password || url.hash) throw new Error();
      }
      if (options.activationUrl !== undefined || options.productToken !== undefined) {
        if (typeof options.productToken !== "string" || !options.productToken || options.productToken.length > 256 || !options.activationUrl) throw new Error();
        registryActivationEndpoint(options.activationUrl);
      }
    } catch {
      throw new RegistryLicenseError("invalid_registry_configuration");
    }
    options = { ...options, rpcUrls: [...options.rpcUrls] };
    const scope = `wallet-registry:${options.chainId}:${options.contract.toLowerCase()}:${options.issuer.toLowerCase()}:${options.productId.toLowerCase()}`;
    const fp = collectFingerprint(scope, options.fingerprintComponents);
    const path = options.statePath ?? defaultStatePath(scope);
    mkdirSync(dirname(path), { recursive: true });
    const unlock = await lockfile.lock(path, { realpath: false, retries: { retries: 70, minTimeout: 500, maxTimeout: 500 }, stale: 30000 });
    try {
      const store = new StateStore(path, scope, fp.composite);
      let saved = store.load();
      if (!saved?.machineKey) {
        const pair = generateKeyPairSync("ed25519");
        saved = {
          licenseKeyHash: "", activationSecret: "", machineId: "", fingerprint: fp.composite,
          machineKey: pair.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
          machinePublicKey: pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64"),
        };
        if (!store.save(saved)) throw new RegistryLicenseError("device_key_not_saved");
      }
      const privateKey = createPrivateKey({ key: Buffer.from(saved.machineKey!, "base64"), format: "der", type: "pkcs8" });
      if (privateKey.asymmetricKeyType !== "ed25519") throw new RegistryLicenseError("invalid_device_key");
      const deviceKey = toHex(createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32));
      const client = new RegistryLicenseClient(options, store, deviceKey, path, Math.max(saved.timeHighWater ?? 0, saved.offlineSeen ?? 0), privateKey);
      client.restoreActivationState();
      return client;
    } finally { await unlock(); }
  }

  importLicense(value: RegistryLicenseManifest | string): void {
    this.license = registryManifest(value, this.options);
    this.generation++;
  }

  /** A manifest is held locally. This is not a validity decision; protected work still requires validate(). */
  get isActivated(): boolean { return !!this.license; }
  get hasPendingActivation(): boolean { return !!this.activationId; }

  private restoreActivationState(): void {
    const saved = this.store.load();
    if (!this.license && saved?.registryManifest) {
      try { this.importLicense(saved.registryManifest); } catch { /* Untrusted cached manifests never authorize execution. */ }
    }
    if (!this.license && registryUuid(saved?.registryActivationId)) this.activationId = saved.registryActivationId.toLowerCase();
  }

  /** Claims a code once, then polls with device proofs. No Ethereum wallet or transaction is used by the SDK. */
  activate(code?: string, options: RegistryActivationOptions = {}): Promise<RegistryLicenseState> {
    if (this.activationWork) return this.activationWork;
    const work = this.activateWithDeadline(code, options);
    this.activationWork = work;
    void work.finally(() => { if (this.activationWork === work) this.activationWork = undefined; }).catch(() => {});
    return work;
  }

  resumeActivation(options: RegistryActivationOptions = {}): Promise<RegistryLicenseState> {
    return this.activate(undefined, options);
  }

  private async activateWithDeadline(code: string | undefined, options: RegistryActivationOptions): Promise<RegistryLicenseState> {
    const timeout = options.timeoutMs ?? (this.options.chainId === 8453 ? 600000 : 120000);
    if (!Number.isFinite(timeout) || timeout < 1 || timeout > 600000) throw new RegistryLicenseError("invalid_registry_activation_timeout");
    if (options.signal?.aborted) throw new RegistryLicenseError("registry_activation_aborted");
    const controller = new AbortController();
    let reason = "registry_activation_aborted", rejectAbort!: (error: Error) => void;
    const aborted = new Promise<never>((_, reject) => { rejectAbort = reject; });
    const abort = () => { controller.abort(); rejectAbort(new RegistryLicenseError(reason)); };
    const cancelled = () => abort();
    options.signal?.addEventListener("abort", cancelled, { once: true });
    const timer = setTimeout(() => { reason = "registry_activation_timeout"; abort(); }, timeout);
    const assertActive = () => { if (controller.signal.aborted) throw new RegistryLicenseError(reason); };
    try {
      return await Promise.race([this.activateInternal(code, options, controller.signal, assertActive), aborted]);
    } finally {
      clearTimeout(timer); options.signal?.removeEventListener("abort", cancelled); controller.abort();
    }
  }

  private async activationPost(path: string, body: unknown, signal: AbortSignal): Promise<ActivationResponse> {
    const endpoint = registryActivationEndpoint(this.options.activationUrl!);
    let response: Response, raw: string;
    try {
      response = await (this.options.fetch ?? fetch)(endpoint + "/v1/client/registry/" + path, {
        method: "POST", redirect: "error", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal,
      });
      raw = await response.text();
    } catch { throw new RegistryLicenseError("registry_activation_unavailable"); }
    if (raw.length > 65536) throw new RegistryLicenseError("invalid_registry_activation_response");
    let value;
    try { value = JSON.parse(raw); } catch { throw new RegistryLicenseError("invalid_registry_activation_response"); }
    if (!response.ok) {
      const known = ["license_not_found", "activation_already_bound", "automatic_activation_not_enabled", "invalid_registry_activation", "invalid_device_proof", "activation_not_found", "license_inactive", "tenant_closed"];
      throw new RegistryLicenseError(known.includes(value?.error) ? value.error : "registry_activation_http_" + response.status);
    }
    if (!value || !["pending", "ready", "failed"].includes(value.status) || !registryUuid(value.activation_id)
      || !Number.isInteger(value.retry_after_s) || value.retry_after_s < 0 || value.retry_after_s > 60
      || (value.status === "ready" ? !value.manifest || value.error !== null : value.manifest !== null))
      throw new RegistryLicenseError("invalid_registry_activation_response");
    return { ...value, activation_id: value.activation_id.toLowerCase() };
  }

  private async saveActivation(id: string, manifest: ReturnType<typeof registryManifest> | undefined,
    failed: boolean, generation: number, assertActive: () => void): Promise<void> {
    const unlock = await lockfile.lock(this.path, { realpath: false, retries: { retries: 70, minTimeout: 500, maxTimeout: 500 }, stale: 30000 });
    try {
      assertActive();
      if (generation !== this.generation) throw new RegistryLicenseError("registry_activation_interrupted");
      const saved = this.store.load();
      if (!saved?.machineKey || !saved.machinePublicKey || toHex(Buffer.from(saved.machinePublicKey, "base64")) !== this.deviceKey)
        throw new RegistryLicenseError("device_key_missing");
      if (saved.registryActivationId && saved.registryActivationId.toLowerCase() !== id) throw new RegistryLicenseError("registry_activation_state_conflict");
      if (manifest) {
        if (saved.registryManifest) {
          const prior = registryManifest(saved.registryManifest, this.options).manifest, next = manifest.manifest;
          if (!Object.entries(next).every(([name, value]) => typeof value === "string" && name !== "entitlements" && name !== "kind"
            ? value.toLowerCase() === String(prior[name as keyof RegistryLicenseManifest]).toLowerCase() : value === prior[name as keyof RegistryLicenseManifest]))
            throw new RegistryLicenseError("registry_activation_state_conflict");
        }
        saved.registryManifest = JSON.stringify(manifest.manifest);
        delete saved.registryActivationId;
      } else if (failed) delete saved.registryActivationId;
      else {
        if (saved.registryManifest) throw new RegistryLicenseError("registry_activation_state_conflict");
        saved.registryActivationId = id;
      }
      if (!this.store.save(saved)) throw new RegistryLicenseError("device_state_not_saved");
      this.activationId = manifest || failed ? undefined : id;
    } finally { await unlock(); }
  }

  private async activateInternal(code: string | undefined, options: RegistryActivationOptions, signal: AbortSignal, checkDeadline: () => void): Promise<RegistryLicenseState> {
    checkDeadline(); this.restoreActivationState();
    if (this.license) return this.validate();
    if (!this.options.activationUrl || !this.options.productToken) throw new RegistryLicenseError("registry_activation_not_configured");
    let generation = this.generation;
    const assertActive = () => { checkDeadline(); if (generation !== this.generation) throw new RegistryLicenseError("registry_activation_interrupted"); };
    const notify = (status: RegistryActivationProgress["status"], id: string, retry: number) => {
      try { options.onProgress?.({ status, activationId: id, retryAfterSeconds: retry }); } catch { /* Application callback. */ }
    };
    const poll = async (id: string): Promise<ActivationResponse> => {
      try { return await this.pollActivation(id, signal); }
      catch (error) {
        // The server no longer has this job. Forget it, or every later activate(code) polls it forever.
        if (error instanceof RegistryLicenseError && error.code === "activation_not_found")
          await this.saveActivation(id, undefined, true, generation, assertActive);
        throw error;
      }
    };
    let response: ActivationResponse;
    if (this.activationId) {
      response = await poll(this.activationId);
    } else {
      if (typeof code !== "string" || !code.trim() || code.trim().length > 512) throw new RegistryLicenseError("activation_code_required");
      const requestId = randomUUID().toLowerCase();
      const body = { product_token: this.options.productToken, license_key: code.trim(), device_key: this.deviceKey,
        request_id: requestId, proof: toHex(sign(null, Buffer.from(registryActivationProofText(this.options.productToken, code, this.deviceKey, requestId)), this.key)) };
      try { response = await this.activationPost("activate", body, signal); }
      finally { body.license_key = ""; }
    }
    while (true) {
      assertActive();
      if (this.activationId && response.activation_id !== this.activationId) throw new RegistryLicenseError("invalid_registry_activation_response");
      if (response.status === "failed") {
        await this.saveActivation(response.activation_id, undefined, true, generation, assertActive);
        throw new RegistryLicenseError("registry_activation_failed");
      }
      if (response.status === "ready") {
        const candidate = registryManifest(response.manifest!, this.options);
        // Ready is only a publication claim. Keep the resumable job until RPC
        // independently confirms this exact manifest, device and current status.
        await this.saveActivation(response.activation_id, undefined, false, generation, assertActive);
        notify("validating", response.activation_id, 0);
        await this.validateCandidate(candidate, generation);
        assertActive();
        await this.saveActivation(response.activation_id, candidate, false, generation, assertActive);
        assertActive(); this.importLicense(candidate.manifest); generation = this.generation;
        const result = await this.validate(); assertActive(); notify("ready", response.activation_id, 0); return result;
      }
      await this.saveActivation(response.activation_id, undefined, false, generation, assertActive);
      notify("pending", response.activation_id, response.retry_after_s);
      assertActive();
      response = await poll(response.activation_id);
      if (response.status === "pending") {
        const delay = Math.max(1, response.retry_after_s) * 1000;
        await new Promise<void>((resolve, reject) => {
          const aborted = () => { clearTimeout(timer); reject(new RegistryLicenseError("registry_activation_aborted")); };
          const timer = setTimeout(() => { signal.removeEventListener("abort", aborted); resolve(); }, delay);
          signal.addEventListener("abort", aborted, { once: true });
          if (signal.aborted) aborted();
        });
      }
    }
  }

  private pollActivation(id: string, signal: AbortSignal): Promise<ActivationResponse> {
    const token = this.options.productToken!;
    return this.activationPost("activation-status", { product_token: token, activation_id: id, device_key: this.deviceKey,
      proof: toHex(sign(null, Buffer.from(registryActivationStatusProofText(token, id, this.deviceKey)), this.key)) }, signal);
  }

  createDeviceBinding() {
    const { manifest: m } = this.requireManifest();
    return {
      chainId: this.options.chainId,
      to: this.options.contract,
      data: encodeFunctionData({ abi: registryAbi, functionName: "bindDevice", args: [this.options.issuer, this.options.productId, m.license_id, this.deviceKey] }),
      value: 0n,
      expectedHolder: m.holder,
    };
  }

  private requireManifest() {
    if (!this.license) throw new RegistryLicenseError("registry_manifest_required");
    return this.license;
  }

  private now(): number {
    const mono = performance.now();
    this.highWater = Math.max(Date.now() / 1000, this.highWater + Math.max(0, mono - this.anchor) / 1000);
    this.anchor = mono;
    return Math.floor(this.highWater);
  }

  private async rpc(url: string, method: string, params: unknown[]): Promise<unknown> {
    let response: Response;
    try {
      response = await (this.options.fetch ?? fetch)(url, {
        method: "POST", redirect: "error", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(10000),
      });
    } catch { throw new TransientRpcError("registry_rpc_unavailable"); }
    if (!response.ok) {
      if ([408, 429].includes(response.status) || response.status >= 500) throw new TransientRpcError("registry_rpc_unavailable");
      throw new RegistryLicenseError("registry_rpc_rejected");
    }
    let raw: string;
    try { raw = await response.text(); }
    catch { throw new TransientRpcError("registry_rpc_unavailable"); }
    let body;
    try {
      if (raw.length > 1048576) throw new Error();
      body = JSON.parse(raw);
      if (!body || body.jsonrpc !== "2.0" || body.id !== 1) throw new Error();
    } catch { throw new RegistryLicenseError("invalid_registry_rpc_response"); }
    if (body.error) {
      if ([-32005, -32002, -32603].includes(body.error.code)) throw new TransientRpcError("registry_rpc_unavailable");
      throw new RegistryLicenseError("registry_rpc_rejected");
    }
    if (!("result" in body)) throw new RegistryLicenseError("invalid_registry_rpc_response");
    return body.result;
  }

  /** Always reads fresh chain state. An authoritative refusal never falls back to another provider. */
  async validate(): Promise<RegistryLicenseState> {
    return this.validateCandidate(this.requireManifest(), this.generation);
  }

  private async validateCandidate(license: ReturnType<typeof registryManifest>, generation: number): Promise<RegistryLicenseState> {
    let transient: RegistryLicenseError | undefined;
    for (const url of this.options.rpcUrls) {
      try { return await this.read(url, license, generation); }
      catch (error) {
        if (!(error instanceof TransientRpcError)) throw error;
        transient = error;
      }
    }
    throw transient ?? new RegistryLicenseError("registry_rpc_unavailable");
  }

  private async read(url: string, license: ReturnType<typeof registryManifest>, generation: number): Promise<RegistryLicenseState> {
    const chain = await this.rpc(url, "eth_chainId", []);
    if (typeof chain !== "string" || !/^0x[0-9a-f]+$/i.test(chain) || BigInt(chain) !== BigInt(this.options.chainId)) throw new RegistryLicenseError("wrong_rpc_chain");
    const saved = this.store.load();
    const initial = registryChainState(saved?.registryChainState);
    let block = registryBlock(await this.rpc(url, "eth_getBlockByNumber", ["latest", false]));
    let reorg = false;
    if (initial) {
      const highest = BigInt(initial.head.number);
      if (block.number < highest) {
        if (highest - block.number !== 1n) throw new TransientRpcError("rpc_block_lag");
        const canonical = await this.rpc(url, "eth_getBlockByNumber", [toHex(highest), false]);
        if (!canonical || !sameRegistryHead(initial.head, this.head(registryBlock(canonical)))) throw new TransientRpcError("rpc_block_lag");
        // A single-provider load balancer gets one bounded retry. A second pinned
        // provider is preferred; a lower snapshot is never used for authorization.
        if (this.options.rpcUrls.length > 1) throw new TransientRpcError("rpc_block_lag");
        await new Promise(resolve => setTimeout(resolve, 1000));
        block = registryBlock(await this.rpc(url, "eth_getBlockByNumber", ["latest", false]));
        if (block.number < highest) throw new TransientRpcError("rpc_block_lag");
      }
      const anchor = await this.rpc(url, "eth_getBlockByNumber", [toHex(highest), false]);
      if (!anchor) throw new TransientRpcError("rpc_canonicality_unavailable");
      const canonical = registryBlock(anchor);
      if (canonical.number !== highest) throw new TransientRpcError("rpc_canonicality_unavailable");
      if (block.number === highest && !sameRegistryHead(this.head(block), this.head(canonical))) throw new TransientRpcError("rpc_snapshot_reorg");
      reorg = canonical.hash !== initial.head.hash.toLowerCase();
      if (!reorg && canonical.timestamp !== initial.head.timestamp) throw new TransientRpcError("rpc_block_rollback");
      if (!reorg && block.timestamp < canonical.timestamp) throw new TransientRpcError("rpc_block_rollback");
    } else if (block.timestamp < (saved?.timeHighWater ?? 0)) throw new TransientRpcError("rpc_block_rollback");
    const timestamp = block.timestamp, now = this.now();
    if (timestamp < now - 300 || timestamp > now + 30) throw new TransientRpcError("stale_rpc_block");
    const code = await this.rpc(url, "eth_getCode", [this.options.contract, block.tag]);
    if (typeof code !== "string" || !/^0x(?:[0-9a-f]{2})+$/i.test(code)) throw new RegistryLicenseError("registry_contract_missing");
    const call = async (data: Hex) => {
      const result = await this.rpc(url, "eth_call", [{ to: this.options.contract, data }, block.tag]);
      if (typeof result !== "string" || !/^0x(?:[0-9a-f]{2})*$/i.test(result)) throw new RegistryLicenseError("invalid_registry_rpc_response");
      return result as Hex;
    };
    const version = decodeFunctionResult({ abi: registryAbi, functionName: "registryVersion", data: await call(encodeFunctionData({ abi: registryAbi, functionName: "registryVersion" })) });
    if (version !== 1n) throw new RegistryLicenseError("wrong_registry_version");
    const m = license.manifest;
    const record = decodeFunctionResult({ abi: registryAbi, functionName: "getLicense", data: await call(encodeFunctionData({ abi: registryAbi, functionName: "getLicense", args: [this.options.issuer, this.options.productId, m.license_id] })) });
    const [holder, device, notBefore, expiresAt, entitlementsHash, revision, status] = record;
    if (status > 3 || (status !== 0 && revision === 0n) || [notBefore, expiresAt, revision].some(v => v > BigInt(Number.MAX_SAFE_INTEGER))) throw new RegistryLicenseError("invalid_registry_record");
    const current = this.now();
    let refusal = status !== 1 ? ["license_missing", "", "license_suspended", "license_revoked"][status]
      : holder.toLowerCase() !== m.holder.toLowerCase() ? "wrong_license_holder"
      : /^0x0+$/.test(device) ? "device_not_bound" : device.toLowerCase() !== this.deviceKey.toLowerCase() ? "wrong_device"
      : entitlementsHash.toLowerCase() !== license.entitlementsHash.toLowerCase() ? "invalid_entitlements_hash"
      : notBefore > BigInt(timestamp) || notBefore > BigInt(current) ? "license_not_started"
      : expiresAt !== 0n && (expiresAt <= BigInt(timestamp) || expiresAt <= BigInt(current) || expiresAt <= notBefore) ? "license_expired" : undefined;
    if (!refusal) {
      const valid = decodeFunctionResult({ abi: registryAbi, functionName: "checkLicense", data: await call(encodeFunctionData({ abi: registryAbi, functionName: "checkLicense", args: [this.options.issuer, this.options.productId, m.license_id, m.holder, this.deviceKey, license.entitlementsHash] })) });
      if (!valid) refusal = "registry_license_rejected";
    }
    const canonical = await this.rpc(url, "eth_getBlockByNumber", [block.tag, false]);
    if (!canonical || !sameRegistryHead(this.head(block), this.head(registryBlock(canonical)))) throw new TransientRpcError("rpc_snapshot_reorg");
    const revoked = await this.observe(block, initial, m.license_id, Number(revision), status === 3, !!refusal, reorg, generation);
    if (revoked) throw new RegistryLicenseError("license_revoked");
    if (refusal) throw new RegistryLicenseError(refusal);
    const checkedAt = this.now();
    if (generation !== this.generation) throw new RegistryLicenseError("license_changed_during_validation");
    if (expiresAt !== 0n && expiresAt <= BigInt(checkedAt)) throw new RegistryLicenseError("license_expired");
    if (timestamp < checkedAt - 300) throw new TransientRpcError("stale_rpc_block");
    return { isValid: true, entitlements: structuredClone(license.entitlements), expiresAt: expiresAt === 0n ? null : Number(expiresAt), notBefore: Number(notBefore), revision: Number(revision), blockNumber: block.number, blockHash: block.hash, checkedAt };
  }

  private head(block: RegistryBlock): RegistryChainState["head"] { return { number: String(block.number), hash: block.hash, timestamp: block.timestamp }; }

  private async observe(block: RegistryBlock, initial: RegistryChainState | undefined, licenseId: Hex,
    revision: number, revoked: boolean, refused: boolean, reorg: boolean, generation: number): Promise<boolean> {
    const unlock = await lockfile.lock(this.path, { realpath: false, retries: { retries: 70, minTimeout: 500, maxTimeout: 500 }, stale: 30000 });
    try {
      if (generation !== this.generation) throw new RegistryLicenseError("license_changed_during_validation");
      const state = this.store.load();
      if (!state?.machineKey || !state.machinePublicKey || toHex(Buffer.from(state.machinePublicKey, "base64")) !== this.deviceKey) throw new RegistryLicenseError("device_key_missing");
      const seen = registryChainState(state.registryChainState);
      const head = this.head(block), id = licenseId.toLowerCase();
      if (seen && block.number < BigInt(seen.head.number)) throw new TransientRpcError("rpc_block_lag");
      if (seen && !sameRegistryHead(seen.head, head) && (!initial || !sameRegistryHead(seen.head, initial.head))) throw new TransientRpcError("rpc_head_changed");
      const prior = seen?.licenses[id];
      if (!refused && prior && revision < prior.revision) {
        if (reorg) throw new RegistryLicenseError("registry_reorg_conflict");
        throw new TransientRpcError("rpc_state_rollback");
      }
      const licenses = seen?.licenses ?? {};
      if (!Object.hasOwn(licenses, id) && Object.keys(licenses).length >= 64) throw new RegistryLicenseError("registry_observation_limit");
      const terminal = revoked || prior?.revoked === true;
      licenses[id] = { revision: Math.max(revision, prior?.revision ?? 0), revoked: terminal };
      state.registryChainState = JSON.stringify({ v: 1, head, licenses } satisfies RegistryChainState);
      state.timeHighWater = Math.max(state.timeHighWater ?? 0, block.timestamp);
      state.offlineSeen = Math.max(state.offlineSeen ?? 0, this.now());
      if (!this.store.save(state)) throw new RegistryLicenseError("device_state_not_saved");
      return terminal;
    } finally { await unlock(); }
  }

  async requireValidLicense(): Promise<RegistryLicenseState> { return this.validate(); }

  async getEntitlement<T = unknown>(name: string): Promise<T | undefined> {
    const entitlements = (await this.validate()).entitlements;
    return Object.hasOwn(entitlements, name) ? entitlements[name] as T : undefined;
  }
}
