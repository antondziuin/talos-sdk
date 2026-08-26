import { createHash, randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import os from "node:os";
import { type KeyObject } from "node:crypto";

import { TalosApiError, TalosError, TalosSignatureError } from "./errors.js";
import { collectFingerprint, type FingerprintData } from "./fingerprint.js";
import {
  StateStore,
  defaultStatePath,
  stateKeyMaterial,
  type StoredBinding,
} from "./state.js";
import {
  b64urlEncode,
  publicKeyFromBase64,
  verifyCachedToken,
  verifyKeyset,
  verifyManifest,
  verifyToken,
} from "./talos-compact.js";

/**
 * Tolerance for a slow or slightly-off clock, in seconds. Matches the token
 * verifier's; the point is to be forgiving about drift while still catching a
 * clock that has been moved.
 */
const CLOCK_SKEW_SECONDS = 60;

/** Minimal fetch signature (Node 18+ global fetch, or an injected one). */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ status: number; text(): Promise<string> }>;

export interface TalosOptions {
  /** The product's public token (`tpt_…`) from the portal. */
  productToken: string;
  /**
   * The product's **anchor** public key, base64 (from the portal's Integration
   * page). The rotation-safe root: the SDK fetches the anchor-signed keyset and
   * learns the current license/release keys from it, so rotating a signing key
   * never breaks a deployed app. Strongly recommended — pin this. If set,
   * {@link publicKey} is optional (a fallback for when the keyset is unavailable).
   */
  anchorPublicKey?: string;
  /**
   * The product's Ed25519 license public key, base64. A direct pin used to
   * verify activation/validation tokens when no keyset is loaded. Optional if
   * {@link anchorPublicKey} is set.
   */
  publicKey?: string;
  /**
   * The product's **release**-signing public key, base64. Direct pin used to
   * verify update manifests when no keyset is loaded. Falls back to
   * {@link publicKey} when omitted.
   */
  releasePublicKey?: string;
  /** Base URL of the Talos (or self-hosted) server. */
  serverUrl: string;
  /** Optional app version reported in telemetry/heartbeats. */
  appVersion?: string;
  /** Optional fetch implementation (defaults to the global `fetch`). */
  fetch?: FetchLike;
  /**
   * Extra fingerprint components, merged over the ones the SDK collects.
   *
   * Node cannot read hardware identifiers on Windows or macOS without native
   * modules, so on those hosts the server falls back to exact matching and a
   * NIC change forces a re-activation. If your app can supply a stable
   * identifier — an Electron native module, or a value you already hold — pass
   * it here (e.g. `{ machine_guid: "<value>" }`) and the server can keep the
   * seat across hardware changes instead. Values are hashed like any other
   * component, so raw identifiers never leave the machine. See
   * `docs/FINGERPRINT.md` for the recognised ids and their weights.
   */
  fingerprintComponents?: Record<string, string>;
  /**
   * Where to keep this machine's activation across restarts. Defaults to a
   * per-product file under the OS user-data directory (see
   * {@link defaultStatePath}).
   */
  statePath?: string;
  /**
   * Persist the machine binding (default `true`).
   *
   * Turn it off only for a process that should not leave a licence on disk — a
   * test, or a short-lived worker. The cost is that every start must
   * `activate` again, which rotates the activation secret and is refused while
   * the tenant is suspended, so a long-lived desktop app wants this on.
   */
  persistState?: boolean;
}

/** One downloadable artifact of an available update (from a verified manifest). */
export interface UpdateArtifact {
  platform: string;
  arch: string;
  kind: string;
  filename: string;
  /** Expected size in bytes (from the signed manifest). */
  size: number;
  /** Expected SHA-256, lowercase hex (from the signed manifest). */
  sha256: string;
  /** Untrusted transport path; the downloaded bytes are verified against `sha256`. */
  downloadPath?: string;
}

/** A verified available update (its metadata all comes from the signed manifest). */
export interface UpdateInfo {
  version: string;
  releaseSeq: number;
  mandatory: boolean;
  notesUrl: string | null;
  artifacts: UpdateArtifact[];
}

/** A held floating seat. Renew before {@link expiresAt} or it is reclaimed. */
export interface Lease {
  /** Server-side lease id (from the signed token). */
  id: string;
  /** This process's instance id. */
  instanceId: string;
  /** Unix seconds when the seat is reclaimed unless renewed. */
  expiresAt: number;
  /** Renew after this many seconds (server-chosen, ttl/3). */
  renewAfterSeconds: number;
  seatsInUse: number;
  maxSeats: number;
}

export interface AcquireLeaseOptions {
  /**
   * Identifies this running process. Re-acquiring with the same value renews
   * instead of taking a second seat. Defaults to a random per-client id.
   */
  instanceId?: string;
  /** Auto-renew in the background (default true). Call {@link TalosClient.releaseLease} to stop. */
  autoRenew?: boolean;
  /** Called if a renewal fails and the seat is lost (e.g. revoked, server down). */
  onLeaseLost?: (reason: string) => void;
}

export interface CheckForUpdateOptions {
  /** Currently installed version (informational). */
  currentVersion?: string;
  /** Installed manifest `release_seq` high-water mark (anti-downgrade). */
  currentReleaseSeq?: number;
  /** Update channel; defaults to `stable`. */
  channel?: string;
}

/** The current, cryptographically-verified license verdict. */
export class LicenseState {
  constructor(
    /**
     * `valid | expired | revoked | suspended | deactivated | machine_revoked |
     * invalid`, plus two verdicts only the client can reach:
     * `grace_expired` (offline past the licence's grace window) and
     * `clock_tampered` (the system clock moved back behind a signed server
     * time we had already seen).
     */
    readonly decision: string,
    /** Entitlement bag (server-defined). */
    readonly features: Record<string, unknown>,
    /** Business expiry (unix seconds), or null for perpetual. */
    readonly licenseExpiresAt: number | null,
    /**
     * True when this verdict came from the local cache rather than a live
     * server — the licence is being honoured on trust, inside the window the
     * policy allows.
     */
    readonly isOffline: boolean = false,
    /**
     * Unix seconds after which the app should validate again. Chosen by the
     * server and carried in a signed claim, so it cannot be lengthened in
     * transit.
     */
    readonly revalidateAfter: number | null = null,
    /** Unix seconds until which this verdict may be honoured offline. */
    readonly graceUntil: number | null = null,
  ) {}

  get isValid(): boolean {
    return this.decision === "valid";
  }

  isFeatureEnabled(name: string): boolean {
    const v = this.features[name];
    if (typeof v === "boolean") return v;
    if (typeof v === "number") return v !== 0;
    if (typeof v === "string") return v.length > 0;
    return false;
  }

  getEntitlement(name: string): unknown {
    return this.features[name];
  }
}

/**
 * Online-first Talos client. Every trust decision is a signed token verified
 * against the pinned product key, so a fake/MITM server cannot forge an
 * acceptable answer. One instance per product; holds the per-machine activation
 * secret after {@link TalosClient.activate}.
 */
export class TalosClient {
  private readonly options: TalosOptions;
  private readonly anchorKey: KeyObject | null;
  private readonly publicKey: KeyObject | null;
  private readonly releaseKey: KeyObject | null;
  private readonly fingerprint: string;
  private readonly fp: FingerprintData;
  private readonly doFetch: FetchLike;

  // Learned from the anchor-signed keyset; take precedence over the direct pins.
  private keysetLicenseKeys: KeyObject[] = [];
  private keysetReleaseKeys: KeyObject[] = [];

  private licenseKey: string | null = null;
  private activationSecret: string | null = null;
  private machineId: string | null = null;
  private readonly store: StateStore | null;
  /** Everything persisted for this product; written back as one file. */
  private binding: StoredBinding | null = null;
  /**
   * True while the adopted keyset came off disk. One refresh per process
   * upgrades it, so a rotation is picked up, but a client that cannot reach the
   * server keeps verifying with what it already trusts.
   */
  private keysetFromCache = false;
  private lease: Lease | null = null;
  private renewTimer: ReturnType<typeof setTimeout> | null = null;
  /** Bumped on release so an in-flight renewal cannot resurrect the seat. */
  private leaseGeneration = 0;
  /** Default instance id for floating leases: one per client object. */
  private readonly instanceId: string = b64urlEncode(randomBytes(9));
  current: LicenseState | null = null;

  constructor(options: TalosOptions) {
    if (!options.productToken) throw new TalosError("productToken required");
    if (!options.serverUrl) throw new TalosError("serverUrl required");
    if (!options.anchorPublicKey && !options.publicKey) {
      throw new TalosError("anchorPublicKey or publicKey required");
    }
    this.options = options;
    this.anchorKey = options.anchorPublicKey
      ? publicKeyFromBase64(options.anchorPublicKey)
      : null;
    this.publicKey = options.publicKey ? publicKeyFromBase64(options.publicKey) : null;
    // Direct release pin falls back to the license pin (keyset overrides both).
    this.releaseKey = options.releasePublicKey
      ? publicKeyFromBase64(options.releasePublicKey)
      : this.publicKey;
    this.fp = collectFingerprint(options.productToken, options.fingerprintComponents);
    this.fingerprint = this.fp.composite;
    this.doFetch = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
    if (!this.doFetch) throw new TalosError("no fetch available (need Node 18+ or options.fetch)");

    // Restore the machine binding synchronously, so a client constructed at
    // startup is already usable: `validate()` works with no `activate()` call
    // and no user prompt for the licence key.
    this.store =
      options.persistState === false
        ? null
        : new StateStore(
            options.statePath ?? defaultStatePath(options.productToken),
            options.productToken,
            stateKeyMaterial(this.fp),
          );
    const stored = this.store?.load() ?? null;
    if (stored) {
      this.binding = stored;
      this.licenseKey = stored.licenseKey;
      this.activationSecret = stored.activationSecret;
      this.machineId = stored.machineId;
      // Adopt the cached keyset before anything asks for a verification key.
      // Without it an anchor-only client has nothing to verify a cached
      // decision with, and the offline path is unreachable in exactly the
      // situation it exists for.
      if (stored.keyset) {
        try {
          this.adoptKeyset(stored.keyset);
          this.keysetFromCache = this.keysetLicenseKeys.length > 0;
        } catch {
          // A keyset that no longer verifies under the pinned anchor is not a
          // startup failure: fall back to fetching one.
        }
      }
    }
  }

  /**
   * Whether this machine already holds an activation — restored from disk on
   * construction, so this is the startup question: prompt for a licence key, or
   * go straight to {@link validate}?
   */
  get isActivated(): boolean {
    return this.activationSecret !== null && this.licenseKey !== null;
  }

  /** The server's id for this machine, once activated. */
  get currentMachineId(): string | null {
    return this.machineId;
  }

  isFeatureEnabled(name: string): boolean {
    return this.current?.isFeatureEnabled(name) ?? false;
  }

  /**
   * Fetch and verify the product's keyset (signed by the pinned anchor) and
   * adopt its current license/release keys. Called automatically during
   * {@link activate}; call it again after a server-side key rotation to keep
   * verifying without any config change. No-op if no `anchorPublicKey` is pinned.
   */
  async refreshKeyset(): Promise<void> {
    if (!this.anchorKey) return;
    const body = await this.post("/v1/client/keyset", {
      product_token: this.options.productToken,
    });
    this.adoptKeyset(body["keyset"]);
    this.keysetFromCache = false;
    if (typeof body["keyset"] === "string") this.persist({ keyset: body["keyset"] });
  }

  /**
   * Make sure a verification key exists before a response has to be verified.
   *
   * A restored binding goes straight to `validate`, skipping `activate` — which
   * is the only place the keyset used to be adopted. An anchor-only client (the
   * recommended pinning, and the one that survives key rotation) therefore had
   * nothing to verify with on the app's *second* launch, and every call failed
   * with "keyset unavailable". Only persistence made that reachable: before it,
   * `activate` always ran first.
   *
   * The keyset is also cached on disk, so the *first* call of a launch with no
   * network can still verify a cached decision. A cached one is refreshed once
   * per process so a rotation is picked up, but a client that cannot reach the
   * server keeps verifying with what it already trusts.
   */
  private async ensureKeyset(): Promise<void> {
    if (!this.anchorKey) return;
    if (this.keysetLicenseKeys.length > 0 && !this.keysetFromCache) return;
    await this.refreshKeyset();
  }

  /** Verify a keyset token against the anchor and adopt its keys. */
  private adoptKeyset(token: unknown): void {
    if (!this.anchorKey || typeof token !== "string") return;
    const claims = verifyKeyset(this.anchorKey, this.options.productToken, token);
    const licenseKeys: KeyObject[] = [];
    const releaseKeys: KeyObject[] = [];
    for (const entry of asArray(claims["keys"])) {
      const o = entry as Record<string, unknown>;
      if (typeof o["pk"] !== "string") continue;
      const key = publicKeyFromBase64(o["pk"]);
      if (o["purpose"] === "license") licenseKeys.push(key);
      else if (o["purpose"] === "release") releaseKeys.push(key);
    }
    this.keysetLicenseKeys = licenseKeys;
    this.keysetReleaseKeys = releaseKeys;
  }

  /** Keys to verify license tokens with: the keyset if loaded, else the direct pin. */
  private licenseVerifyKeys(): KeyObject[] {
    if (this.keysetLicenseKeys.length) return this.keysetLicenseKeys;
    if (this.publicKey) return [this.publicKey];
    throw new TalosSignatureError("no license verification key (keyset unavailable)");
  }

  /** Keys to verify manifests with: the keyset if loaded, else the direct pin. */
  private releaseVerifyKeys(): KeyObject[] {
    if (this.keysetReleaseKeys.length) return this.keysetReleaseKeys;
    if (this.releaseKey) return [this.releaseKey];
    throw new TalosSignatureError("no release verification key (keyset unavailable)");
  }

  /**
   * Ensure this machine is activated on `licenseKey`, and return the verified
   * state. Safe to call on every start.
   *
   * When a binding for the same key is already held, this **re-validates**
   * instead of re-activating. Same one round trip, three different outcomes:
   * the activation secret is not rotated (so a second copy of the app on the
   * same machine does not knock the first one out), no seat accounting is
   * touched, and — because `activate` is the only client route refused for a
   * suspended tenant — the developer's own paying users keep working while
   * their vendor's account is suspended, which is what "graduated suspension"
   * was supposed to mean.
   *
   * It falls back to a real activation when the stored binding is no longer
   * usable: the seat was released from the portal, or the secret was rotated
   * elsewhere.
   */
  async activate(licenseKey: string): Promise<LicenseState> {
    if (this.isActivated && this.licenseKey === licenseKey) {
      try {
        const state = await this.validate();
        // `deactivated` means the developer released the seat; taking it again
        // is exactly what re-activating is for. Every other verdict —
        // including `machine_revoked` — is the server's answer, and re-
        // activating would only replace it with a less specific error.
        if (state.decision !== "deactivated") return state;
      } catch (e) {
        // 401: the secret was rotated elsewhere. 404: the machine (or licence)
        // is gone. Anything else is a real failure and must not be papered
        // over by silently spending a seat.
        const stale =
          e instanceof TalosApiError && (e.statusCode === 401 || e.statusCode === 404);
        if (!stale) throw e;
      }
      this.forgetBinding();
    }
    const nonce = newNonce();
    const body = await this.post("/v1/client/activate", {
      product_token: this.options.productToken,
      license_key: licenseKey,
      fingerprint: { composite: this.fingerprint, components: this.fp.components },
      nonce,
      os: `${os.type()} ${os.release()}`,
      arch: os.arch(),
      app_version: this.options.appVersion,
      sdk_version: "node/0.0.0",
    });

    // Adopt the keyset delivered with activation, then verify the activation
    // token against the current license keys (so a rotated key still works).
    this.adoptKeyset(body["keyset"]);
    const claims = verifyToken(
      this.licenseVerifyKeys(),
      "activation",
      this.options.productToken,
      nonce,
      body["activation_token"] as string,
    );
    this.licenseKey = licenseKey;
    this.activationSecret = body["activation_secret"] as string;
    this.machineId = (body["machine_id"] as string) ?? null;
    this.binding = {
      licenseKey,
      activationSecret: this.activationSecret,
      machineId: this.machineId ?? "",
      fingerprint: this.fingerprint,
      // A fresh activation invalidates any cached verdict for the previous
      // binding; keep only the keyset, which is per product, not per machine.
      keyset: typeof body["keyset"] === "string" ? (body["keyset"] as string) : this.binding?.keyset,
      timeHighWater: this.binding?.timeHighWater,
    };
    this.advanceClock(claims);
    this.store?.save(this.binding);
    this.current = stateFromClaims(claims, "valid", false);
    return this.current;
  }

  /** Drop the machine binding, in memory and on disk. */
  private forgetBinding(): void {
    this.licenseKey = null;
    this.activationSecret = null;
    this.machineId = null;
    this.current = null;
    this.binding = null;
    this.store?.clear();
  }

  /** Merge fields into the persisted binding and write it back. */
  private persist(patch: Partial<StoredBinding>): void {
    if (!this.store || !this.binding) return;
    this.binding = { ...this.binding, ...patch };
    this.store.save(this.binding);
  }

  /**
   * Advance the server-time high-water mark from a signed claim.
   *
   * Only ever forward: this is the mark that keeps offline grace bounded when
   * the user owns the clock. `iat` is used when a token carries no explicit
   * `server_time` (activation does not) — both are the server's clock, signed.
   */
  private advanceClock(claims: Record<string, unknown>): void {
    const seen = num(claims["server_time"]) ?? num(claims["iat"]);
    if (seen === null) return;
    const current = this.binding?.timeHighWater ?? 0;
    if (seen > current) {
      if (this.binding) this.binding.timeHighWater = seen;
    }
  }

  async validate(): Promise<LicenseState> {
    this.requireActivated();
    try {
      await this.ensureKeyset();
      const nonce = newNonce();
      const body = await this.post("/v1/client/validate", {
        product_token: this.options.productToken,
        license_key: this.licenseKey,
        fingerprint: { composite: this.fingerprint, components: this.fp.components },
        activation_secret: this.activationSecret,
        nonce,
      });
      const token = body["validation_token"] as string;
      const claims = verifyToken(
        this.licenseVerifyKeys(),
        "validation",
        this.options.productToken,
        nonce,
        token,
      );
      const decision =
        typeof claims["decision"] === "string" ? (claims["decision"] as string) : "invalid";
      this.advanceClock(claims);
      this.persist({ validation: token, timeHighWater: this.binding?.timeHighWater });
      this.current = stateFromClaims(claims, decision, false);
      return this.current;
    } catch (e) {
      // An HTTP status is an *answer* — "revoked", "no such machine", "tenant
      // suspended". Honouring a cached verdict over one would turn every
      // negative answer into 72 hours of grace, which is the opposite of what
      // grace is for. Only the absence of an answer falls back: a dead network,
      // or a response that fails verification (a garbled or forged reply tells
      // us nothing, so per the trust model it is treated as unreachable, never
      // as valid).
      if (e instanceof TalosApiError) throw e;
      const offline = this.offlineDecision();
      if (!offline) throw e;
      this.current = offline;
      return offline;
    }
  }

  /**
   * The verdict from the local cache, or null when there is nothing usable.
   *
   * This is the whole offline story, and every check here is load-bearing:
   *
   * - the token is re-verified under the pinned key, so a cache edited on disk
   *   is worthless;
   * - `fph` must be this machine, so copying a state file to a second computer
   *   and pulling the network cable does not licence it;
   * - `grace_until` — the policy's `offline_grace_hours`, signed — bounds how
   *   long a verdict may outlive its issuance;
   * - the licence's own expiry is re-checked, because a cached "valid" must not
   *   outlive the subscription it was issued under;
   * - and the clock is checked against a mark that only moves forward, since
   *   every deadline above is evaluated against a clock the user controls.
   */
  private offlineDecision(): LicenseState | null {
    const token = this.binding?.validation;
    if (!token) return null;
    const now = nowSeconds();

    const highWater = this.binding?.timeHighWater ?? 0;
    if (highWater > 0 && now + CLOCK_SKEW_SECONDS < highWater) {
      // Distinct from "expired": nothing has run out, the machine is lying
      // about the time. Say so, rather than reporting a licence problem the
      // user cannot act on.
      return new LicenseState("clock_tampered", {}, null, true, null, null);
    }

    let claims: Record<string, unknown>;
    try {
      claims = verifyCachedToken(
        this.licenseVerifyKeys(),
        "validation",
        this.options.productToken,
        token,
      );
    } catch {
      return null;
    }
    if (claims["fph"] !== this.fingerprint) return null;

    const graceUntil = num(claims["grace_until"]);
    const cached = stateFromClaims(
      claims,
      typeof claims["decision"] === "string" ? (claims["decision"] as string) : "invalid",
      true,
    );
    if (graceUntil === null || now > graceUntil) {
      return new LicenseState(
        "grace_expired",
        cached.features,
        cached.licenseExpiresAt,
        true,
        cached.revalidateAfter,
        graceUntil,
      );
    }
    if (cached.licenseExpiresAt !== null && now > cached.licenseExpiresAt) {
      return new LicenseState(
        "expired",
        cached.features,
        cached.licenseExpiresAt,
        true,
        cached.revalidateAfter,
        graceUntil,
      );
    }
    return cached;
  }

  async deactivate(): Promise<void> {
    this.requireActivated();
    await this.post("/v1/client/deactivate", {
      product_token: this.options.productToken,
      license_key: this.licenseKey,
      fingerprint: { composite: this.fingerprint, components: this.fp.components },
      activation_secret: this.activationSecret,
    });
    this.forgetBinding();
  }

  /**
   * Send a heartbeat: refreshes this machine's last-seen state, feeds the
   * developer's monitoring (version adoption / active installs), and returns the
   * current signed decision — so a revocation reaches the app within one
   * heartbeat interval. Call it periodically while the app runs.
   *
   * The response is a signed `typ=heartbeat` token, so a MITM cannot forge the
   * status or lengthen the interval.
   */
  async heartbeat(): Promise<LicenseState> {
    this.requireActivated();
    await this.ensureKeyset();
    const nonce = newNonce();
    const body = await this.post("/v1/client/heartbeat", {
      product_token: this.options.productToken,
      license_key: this.licenseKey,
      fingerprint: { composite: this.fingerprint, components: this.fp.components },
      activation_secret: this.activationSecret,
      nonce,
      app_version: this.options.appVersion,
      os: `${os.type()} ${os.release()}`,
      arch: os.arch(),
    });
    const claims = verifyToken(
      this.licenseVerifyKeys(),
      "heartbeat",
      this.options.productToken,
      nonce,
      body["heartbeat_token"] as string,
    );
    const decision =
      typeof claims["decision"] === "string" ? (claims["decision"] as string) : "invalid";
    // Every signed server clock we see pushes the high-water mark forward, not
    // just validation's — a heartbeat is the most frequent call there is.
    this.advanceClock(claims);
    this.persist({ timeHighWater: this.binding?.timeHighWater });
    // A heartbeat carries the decision but not the entitlement bag; keep the
    // features from the last activate/validate.
    this.current = new LicenseState(
      decision,
      this.current?.features ?? {},
      this.current?.licenseExpiresAt ?? null,
      false,
      this.current?.revalidateAfter ?? null,
      this.current?.graceUntil ?? null,
    );
    return this.current;
  }

  /**
   * Acquire a floating seat (concurrent-use license). The server arbitrates the
   * cap atomically, so this either returns a seat or throws
   * {@link TalosApiError} with `seat_limit_reached` (HTTP 409).
   *
   * By default the seat is auto-renewed in the background at the server-chosen
   * interval; a lost renewal invokes `onLeaseLost`. Always
   * {@link releaseLease} on clean exit — a crash simply lets the seat expire.
   */
  async acquireLease(opts: AcquireLeaseOptions = {}): Promise<Lease> {
    this.requireActivated();
    await this.ensureKeyset();
    const instanceId = opts.instanceId ?? this.instanceId;
    // Snapshot the generation: if releaseLease() runs while this request is in
    // flight, we must not adopt the seat we just took (and should hand it back).
    const generation = this.leaseGeneration;
    const nonce = newNonce();
    const body = await this.post("/v1/client/leases", {
      product_token: this.options.productToken,
      license_key: this.licenseKey,
      fingerprint: { composite: this.fingerprint, components: this.fp.components },
      activation_secret: this.activationSecret,
      instance_id: instanceId,
      nonce,
    });

    // The lease token is signed: a MITM cannot fabricate a seat.
    const claims = verifyToken(
      this.licenseVerifyKeys(),
      "lease",
      this.options.productToken,
      nonce,
      body["lease_token"] as string,
    );

    // The signed grant must be for the instance and machine we asked about —
    // otherwise a server could hand every process one shared seat's token.
    if (claims["inst"] !== instanceId || claims["fph"] !== this.fingerprint) {
      throw new TalosSignatureError("lease token does not match this instance");
    }

    // Seat facts come from the SIGNED claims, never the unsigned envelope, so a
    // MITM cannot misreport occupancy. `renew_after_s` is only a scheduling
    // hint; the budget is derived from the token's own clock (`exp` vs
    // `server_time`) so a wrong local clock cannot collapse the renew loop.
    const expiresAt = typeof claims["exp"] === "number" ? (claims["exp"] as number) : 0;
    const serverNow =
      typeof claims["server_time"] === "number"
        ? (claims["server_time"] as number)
        : Math.floor(Date.now() / 1000);
    const budget = Math.max(1, expiresAt - serverNow);
    const hinted = Number(body["renew_after_s"] ?? 0);
    const lease: Lease = {
      id: String(claims["lease"] ?? ""),
      instanceId,
      expiresAt,
      renewAfterSeconds:
        hinted > 0 && hinted <= budget ? hinted : Math.max(1, Math.floor(budget / 3)),
      seatsInUse: Number(claims["seats_in_use"] ?? 0),
      maxSeats: Number(claims["max_seats"] ?? 0),
    };

    if (generation !== this.leaseGeneration) {
      // Released while this was in flight: hand the seat straight back instead
      // of holding it until the TTL expires, and never re-adopt it locally.
      void this.releaseInstance(instanceId).catch(() => {});
      return lease;
    }
    this.lease = lease;

    if (opts.autoRenew !== false) this.scheduleRenew(opts);
    return lease;
  }

  /** Best-effort DELETE of one instance's seat (used for stale-renewal cleanup). */
  private async releaseInstance(instanceId: string): Promise<void> {
    if (!this.activationSecret || !this.licenseKey) return;
    await this.request("DELETE", "/v1/client/leases", {
      product_token: this.options.productToken,
      license_key: this.licenseKey,
      fingerprint: { composite: this.fingerprint, components: this.fp.components },
      activation_secret: this.activationSecret,
      instance_id: instanceId,
    });
  }

  /** The currently held floating seat, if any. */
  get currentLease(): Lease | null {
    return this.lease;
  }

  /** Release the floating seat (clean exit) and stop auto-renewal. */
  async releaseLease(): Promise<void> {
    // Bump the generation FIRST: an already in-flight renewal will see that it
    // is stale and neither re-adopt the seat nor re-arm the timer. Without this
    // a renewal racing the release resurrects the lease for the process
    // lifetime — the seat would stay held long after the app "released" it.
    this.leaseGeneration += 1;
    this.stopRenew();
    const lease = this.lease;
    this.lease = null;
    if (!lease) return;
    await this.releaseInstance(lease.instanceId);
  }

  private scheduleRenew(opts: AcquireLeaseOptions): void {
    this.stopRenew();
    const generation = this.leaseGeneration;
    const instanceId = this.lease?.instanceId;
    const delay = Math.max(1, this.lease?.renewAfterSeconds ?? 200) * 1000;
    this.renewTimer = setTimeout(() => {
      void (async () => {
        try {
          await this.acquireLease({ ...opts, instanceId, autoRenew: false });
          // Released (or re-acquired) while we were awaiting → do not re-adopt.
          if (generation !== this.leaseGeneration) return;
          this.scheduleRenew(opts);
        } catch (e) {
          if (generation !== this.leaseGeneration) return;
          this.lease = null;
          opts.onLeaseLost?.(e instanceof Error ? e.message : "lease renewal failed");
        }
      })();
    }, delay);
    // Never hold the event loop open for a background renewal.
    this.renewTimer.unref?.();
  }

  private stopRenew(): void {
    if (this.renewTimer) {
      clearTimeout(this.renewTimer);
      this.renewTimer = null;
    }
  }

  /**
   * Ask whether a newer release is available. Returns a verified {@link UpdateInfo}
   * (all metadata comes from the manifest signed by the pinned release key), or
   * `null` when up to date. Enforces anti-downgrade: a manifest whose
   * `release_seq` is at or below `currentReleaseSeq` is rejected as no update.
   */
  async checkForUpdate(opts: CheckForUpdateOptions = {}): Promise<UpdateInfo | null> {
    this.requireActivated();
    await this.ensureKeyset();
    const body = await this.post("/v1/client/updates/check", {
      product_token: this.options.productToken,
      license_key: this.licenseKey,
      fingerprint: { composite: this.fingerprint, components: this.fp.components },
      activation_secret: this.activationSecret,
      current_version: opts.currentVersion ?? this.options.appVersion,
      current_release_seq: opts.currentReleaseSeq,
      channel: opts.channel,
    });
    if (body["update_available"] !== true) return null;

    const manifestToken = body["manifest"];
    if (typeof manifestToken !== "string") {
      throw new TalosSignatureError("update available but no manifest");
    }
    // Trust only the signed manifest for version/seq/artifact metadata.
    const m = verifyManifest(this.releaseVerifyKeys(), this.options.productToken, manifestToken);
    const releaseSeq = typeof m["release_seq"] === "number" ? (m["release_seq"] as number) : 0;
    if (opts.currentReleaseSeq !== undefined && releaseSeq <= opts.currentReleaseSeq) {
      return null; // anti-downgrade: never surface an older-or-equal manifest.
    }

    // Untrusted transport map: platform/arch/kind → download path.
    const downloads = new Map<string, string>();
    for (const d of asArray(body["artifacts"])) {
      const o = d as Record<string, unknown>;
      if (typeof o["download_path"] === "string") {
        downloads.set(selKey(o["platform"], o["arch"], o["kind"]), o["download_path"]);
      }
    }

    const artifacts: UpdateArtifact[] = asArray(m["artifacts"]).map((a) => {
      const o = a as Record<string, unknown>;
      const platform = String(o["platform"] ?? "");
      const arch = String(o["arch"] ?? "");
      const kind = String(o["kind"] ?? "");
      return {
        platform,
        arch,
        kind,
        filename: String(o["filename"] ?? ""),
        size: typeof o["size"] === "number" ? (o["size"] as number) : 0,
        sha256: String(o["sha256"] ?? ""),
        downloadPath: downloads.get(selKey(platform, arch, kind)),
      };
    });

    return {
      version: String(m["version"] ?? ""),
      releaseSeq,
      mandatory: m["mandatory"] === true,
      notesUrl: typeof m["notes_url"] === "string" ? (m["notes_url"] as string) : null,
      artifacts,
    };
  }

  /**
   * Download one artifact of an update and verify its bytes against the manifest
   * SHA-256, then write it to `destPath`. Returns the chosen artifact. Does NOT
   * apply or execute anything — verification and installation are the host app's
   * responsibility.
   */
  async downloadUpdate(
    info: UpdateInfo,
    destPath: string,
    artifact?: UpdateArtifact,
  ): Promise<UpdateArtifact> {
    this.requireActivated();
    const chosen = artifact ?? pickArtifact(info.artifacts);
    if (!chosen) throw new TalosError("no artifact matches this platform");
    if (!chosen.downloadPath) throw new TalosError("artifact has no download path");

    const url = this.options.serverUrl.replace(/\/+$/, "") + chosen.downloadPath;
    const res = await (globalThis.fetch as typeof fetch)(url, {
      method: "GET",
      headers: {
        "x-talos-product-token": this.options.productToken,
        "x-talos-license-key": this.licenseKey!,
        "x-talos-activation-secret": this.activationSecret!,
        "x-talos-fingerprint": this.fingerprint,
      },
    });
    if (!res.ok) throw new TalosApiError(res.status, undefined);

    // The download channel is untrusted (could stream an unbounded body to
    // exhaust memory before the hash check). Cap the read at the manifest's
    // trusted `size`, then verify the SHA-256 from the signed manifest.
    const bytes = await readCapped(res, chosen.size);
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== chosen.sha256) {
      throw new TalosSignatureError("artifact hash mismatch (tampered or wrong bytes)");
    }
    await writeFile(destPath, bytes);
    return chosen;
  }

  private requireActivated(): void {
    if (!this.activationSecret || !this.licenseKey) {
      throw new TalosError("not activated: call activate() first");
    }
  }

  private post(path: string, body: unknown): Promise<Record<string, unknown>> {
    return this.request("POST", path, body);
  }

  private async request(
    method: string,
    path: string,
    body: unknown,
  ): Promise<Record<string, unknown>> {
    const res = await this.doFetch(this.options.serverUrl.replace(/\/+$/, "") + path, {
      method,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    if (res.status < 200 || res.status >= 300) {
      let errorCode: string | undefined;
      try {
        errorCode = (JSON.parse(text) as { error?: string }).error;
      } catch {
        errorCode = undefined;
      }
      throw new TalosApiError(res.status, errorCode);
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  }
}

function stateFromClaims(
  claims: Record<string, unknown>,
  decision: string,
  isOffline: boolean,
): LicenseState {
  const lic = (claims["lic"] ?? {}) as Record<string, unknown>;
  const features = (lic["features"] ?? {}) as Record<string, unknown>;
  const exp = num(lic["lic_exp"]);
  // Validation carries absolute deadlines; activation carries the same policy
  // as hours beside its `iat`. Prefer the absolute form and derive the other,
  // so both tokens answer "when should I come back?" the same way.
  const iat = num(claims["iat"]) ?? nowSeconds();
  const revalAfter = num(claims["reval_after"]) ?? hoursAfter(iat, lic["reval_h"]);
  const graceUntil = num(claims["grace_until"]) ?? hoursAfter(iat, lic["grace_h"]);
  return new LicenseState(decision, features, exp, isOffline, revalAfter, graceUntil);
}

function hoursAfter(base: number, hours: unknown): number | null {
  const h = num(hours);
  return h === null ? null : base + h * 3600;
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function newNonce(): string {
  return b64urlEncode(randomBytes(16));
}

/**
 * Read a fetch Response body into a Buffer, refusing to buffer more than `cap`
 * bytes (the manifest's trusted size). Guards against an untrusted download host
 * streaming an unbounded body to exhaust memory before the hash check.
 */
async function readCapped(res: Response, cap: number): Promise<Buffer> {
  const contentLength = res.headers.get("content-length");
  if (contentLength && Number(contentLength) > cap) {
    throw new TalosSignatureError("artifact exceeds manifest size");
  }
  const body = res.body;
  if (!body) {
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > cap) throw new TalosSignatureError("artifact exceeds manifest size");
    return buf;
  }
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) {
      await reader.cancel();
      throw new TalosSignatureError("artifact exceeds manifest size");
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function selKey(platform: unknown, arch: unknown, kind: unknown): string {
  return `${String(platform)}/${String(arch)}/${String(kind)}`;
}

/** Best artifact for the current platform (installer preferred), or undefined. */
function pickArtifact(artifacts: UpdateArtifact[]): UpdateArtifact | undefined {
  const map: Record<string, string> = { win32: "windows", darwin: "macos", linux: "linux" };
  const platform = map[os.platform()] ?? os.platform();
  const arch = os.arch();
  const matches = artifacts.filter((a) => a.platform === platform && a.arch === arch);
  return matches.find((a) => a.kind === "installer") ?? matches[0];
}
