import { createHash, randomBytes } from "node:crypto";
import { createReadStream } from "node:fs";
import { open, rename, rm } from "node:fs/promises";
import os from "node:os";
import { type KeyObject } from "node:crypto";

import { TalosApiError, TalosError, TalosSignatureError } from "./errors.js";
import { collectFingerprint, type FingerprintData } from "./fingerprint.js";
import {
  StateStore,
  defaultStatePath,
  hashLicenseKey,
  stateKeyMaterial,
  type StoredBinding,
} from "./state.js";
import { SDK_ID } from "./version.js";
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

/**
 * Fallback check-in cadence, used only until the first heartbeat reports the
 * policy's own. Matches the server's `policies.heartbeat_interval_s` default.
 */
const DEFAULT_HEARTBEAT_SECONDS = 600;

/**
 * What a response has to offer this SDK.
 *
 * `headers` and `body` are optional because a test double need not implement a
 * `ReadableStream`; `arrayBuffer` is not, because the artifact download has to
 * read bytes and an optional method there just moves the failure to run time —
 * which is exactly what this shape is being widened to prevent.
 */
export interface FetchResponseLike {
  status: number;
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
  headers?: { get(name: string): string | null };
  /** A streaming body, when the implementation has one (the global `fetch`
   *  does). Used to enforce the size cap without buffering first. */
  body?: { getReader(): { read(): Promise<{ done: boolean; value?: Uint8Array }>; cancel(): Promise<unknown> } } | null;
}

/** Minimal fetch signature (Node 18+ global fetch, or an injected one). */
export type FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string;
    /**
     * Aborts the request once {@link TalosOptions.httpTimeoutMs} elapses.
     *
     * Optional so an injected `fetch` that predates this field still satisfies
     * the type — but one that ignores the signal has no timeout, and the
     * licensing call it drops is on somebody's launch path.
     */
    signal?: AbortSignal;
  },
) => Promise<FetchResponseLike>;

/**
 * Default cap on a licensing call, in milliseconds.
 *
 * Ten seconds: long enough that a slow network is not mistaken for a dead one,
 * short enough that an application blocked on it still starts. Node's `fetch`
 * has no default at all, which is the state this replaces.
 */
const DEFAULT_HTTP_TIMEOUT_MS = 10_000;

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
  /**
   * The name shown for this seat in the developer's portal. Defaults to
   * `os.hostname()`.
   *
   * Unlike the hostname the SDK folds into the fingerprint, this one is stored
   * and displayed as written — it is what a support agent reads when a customer
   * says "release the one on my old laptop", and without it every seat on a
   * licence is an indistinguishable hash prefix. Pass `""` to send nothing if a
   * machine name would be more identifying than your users expect.
   */
  hostname?: string;
  /**
   * Optional fetch implementation (defaults to the global `fetch`).
   *
   * Used for **every** network call, artifact downloads included. It did not
   * used to be: `downloadUpdate` reached for `globalThis.fetch` directly, so a
   * proxy, a custom CA bundle, request logging or a test double applied to
   * every licensing call and was silently bypassed by the one call that pulls a
   * multi-megabyte binary and is likeliest to need it.
   */
  fetch?: FetchLike;
  /**
   * How long a licensing call may take before it is abandoned, in milliseconds.
   * Default 10000; `0` disables it.
   *
   * Node's `fetch` has **no** default timeout, so before this existed a server
   * that accepted the connection and never answered left `validate()` pending
   * forever — which in a desktop application is a splash screen that never goes
   * away, on the one code path a user cannot skip. Passing a custom `fetch` was
   * the only way to bound it, which is a lot of ceremony for one number.
   *
   * It does **not** apply to `downloadUpdate`. A total-duration cap on a
   * multi-megabyte artifact is not a safeguard, it is a size limit disguised as
   * one: the same 30 seconds that is generous for a licensing call fails every
   * download on a slow connection. The download is bounded by the manifest's
   * signed `size` instead, which is the bound that actually matters there.
   */
  httpTimeoutMs?: number;
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

/** What applying a patch has to produce. */
export interface UpdateDeltaTarget {
  /** The `kind` of the full artifact this rebuilds (`installer`, `archive`, …). */
  kind: string;
  filename: string;
  /** Expected size of the rebuilt file, in bytes (from the signed manifest). */
  size: number;
  /**
   * Expected SHA-256 of the rebuilt file, lowercase hex (from the signed
   * manifest). **Check it after applying** — see {@link verifyAppliedUpdate}.
   * Verifying only the patch leaves whatever comes out of the patcher
   * unverified, which is the whole thing the signed manifest exists to prevent.
   */
  sha256: string;
}

/**
 * A patch that turns one already-installed version into this release, from the
 * signed manifest.
 *
 * Talos hosts and signs patches; it does not produce or apply them. The diff
 * format belongs to whatever applies it (Velopack, Squirrel, MSIX, bsdiff,
 * `zstd --patch-from`), and this SDK deliberately does not run installers.
 */
export interface UpdateDelta {
  platform: string;
  arch: string;
  /** The installed version this patch applies to, exactly as published. */
  from: string;
  /** `release_seq` of the version it applies to (always below this release's). */
  fromSeq: number;
  filename: string;
  /** Expected size of the patch itself, in bytes. */
  size: number;
  /** Expected SHA-256 of the patch itself, lowercase hex. */
  sha256: string;
  target: UpdateDeltaTarget;
  /** Untrusted transport path; the bytes are verified against `sha256`. */
  downloadPath?: string;
}

/** A verified available update (its metadata all comes from the signed manifest). */
export interface UpdateInfo {
  version: string;
  releaseSeq: number;
  mandatory: boolean;
  notesUrl: string | null;
  artifacts: UpdateArtifact[];
  /**
   * Patches this release ships, if any. Never mixed into {@link artifacts}: a
   * patch is not something a host can install, and an SDK that picks "the
   * artifact for this platform" would hand one over as if it were a build.
   */
  deltas: UpdateDelta[];
}

/** Which patch to use, when a release ships more than one. */
export interface DeltaOptions {
  /**
   * The version currently installed. Defaults to `appVersion` from the client
   * options — the same value the update check reports.
   */
  from?: string;
  /**
   * Which shipped file to rebuild, when a release carries patches for several
   * (an installer and a portable archive, say). Defaults to the only one, and
   * is required when there is more than one.
   */
  targetKind?: string;
}

/**
 * How far a download has got, passed to the `onProgress` callback of
 * {@link TalosClient.downloadUpdate} and {@link TalosClient.downloadDelta}.
 *
 * `totalBytes` is the size the **signed manifest** names, not the server's
 * `content-length`. The download host is untrusted, and a bar driven by a header
 * it controls can be parked at 100% while bytes are still arriving. It is also
 * the cap the read is bounded by, so `bytesReceived` never exceeds it.
 */
export interface DownloadProgress {
  /** Bytes verified and written so far. */
  bytesReceived: number;
  /** Total size, in bytes, from the signed manifest. */
  totalBytes: number;
}

/** Called as an artifact download advances. */
export type DownloadProgressCallback = (progress: DownloadProgress) => void;

/**
 * The licence transitions a host can subscribe to with {@link TalosClient.on}.
 *
 * Edges, not levels. `onState` already delivers the verdict on every check-in,
 * and an application that wants "tell me when grace starts" has to diff those
 * itself — getting that right (not re-warning every ten minutes for the whole
 * outage) is exactly the bookkeeping a library should do once instead of every
 * host doing it slightly wrong.
 */
export type TalosEventName =
  | "licenseInvalid"
  | "gracePeriodStarted"
  | "gracePeriodExpired"
  | "clockTamperDetected";

/** Handler for a {@link TalosEventName}; receives the state that was adopted. */
export type LicenseListener = (state: LicenseState) => void;

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

export interface CheckInOptions {
  /** Called after every successful check-in, with the fresh verdict. */
  onState?: (state: LicenseState) => void;
  /**
   * Called when a check-in fails outright — the server answered with an error,
   * or the network is down *and* there is nothing left to fall back on.
   */
  onError?: (error: unknown) => void;
}

export interface CheckForUpdateOptions {
  /** Currently installed version (informational). */
  currentVersion?: string;
  /**
   * Override the anti-downgrade floor for this call.
   *
   * Optional, and normally omitted: the SDK persists the highest `release_seq`
   * it has seen this install running and uses that. Pass one when the host
   * knows something the SDK cannot — a build installed by a package manager, or
   * a first run after adopting the SDK on an already-updated fleet.
   */
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
/**
 * How long an adopted keyset is trusted before a refresh is attempted.
 *
 * The upper bound on how long a revoked signing key keeps being accepted by an
 * install that stays online. A day is the trade: shorter multiplies load on a
 * public endpoint serving a document that changes about once a year, longer
 * widens the window in which a compromised key still works.
 */
const KEYSET_MAX_AGE_SECONDS = 24 * 60 * 60;

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

  /**
   * SHA-256 of the key this machine activated with, or null.
   *
   * The key itself is deliberately not held: after activation the server
   * resolves the licence from the activation secret, so keeping the key would
   * mean a plaintext credential in memory and on disk for the sake of one
   * string comparison in `activate`.
   */
  private licenseKeyHash: string | null = null;
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
  /**
   * The `iat` of the adopted keyset, in unix seconds, or 0 if unknown.
   *
   * Kept so a keyset can go stale. Without it the refresh happens once per
   * process, which is fine for a desktop app that restarts and useless for the
   * process this SDK is most often *in* — a server or an Electron main that runs
   * for weeks. A key revoked in the portal would never reach it.
   */
  private keysetIssuedAt = 0;
  /** The policy's heartbeat cadence, from the last heartbeat's signed claims. */
  private heartbeatInterval: number | null = null;
  private checkInTimer: ReturnType<typeof setTimeout> | null = null;
  /** Bumped on stop so an in-flight tick cannot re-arm a cancelled loop. */
  private checkInGeneration = 0;
  private lease: Lease | null = null;
  private renewTimer: ReturnType<typeof setTimeout> | null = null;
  /** Bumped on release so an in-flight renewal cannot resurrect the seat. */
  private leaseGeneration = 0;
  /** Default instance id for floating leases: one per client object. */
  private readonly instanceId: string = b64urlEncode(randomBytes(9));
  current: LicenseState | null = null;
  private readonly listeners = new Map<TalosEventName, Set<LicenseListener>>();

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
      this.licenseKeyHash = stored.licenseKeyHash;
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
      this.promoteDownloadedRelease();
    }
  }

  /**
   * A release that was downloaded and is now the version running: promote its
   * `release_seq` to the anti-downgrade mark.
   *
   * This is the whole of "the SDK knows what is installed". The SDK downloads
   * and verifies bytes; the host installs them, its own way, usually across a
   * restart — so installation is not an event the SDK can observe. What it can
   * observe is the result, because `appVersion` is the host saying which
   * version it is. When that equals the version whose bytes were fetched, the
   * download became an install.
   *
   * Only forward, and that is the point: yanking a release or lowering its
   * rollout stops it being *offered*, and must not walk an install that already
   * applied it back onto an older build.
   */
  private promoteDownloadedRelease(): void {
    const pending = this.binding?.pendingRelease;
    if (!pending || pending.version !== this.options.appVersion) return;
    const mark = Math.max(this.binding?.releaseSeqHighWater ?? 0, pending.releaseSeq);
    this.persist({ releaseSeqHighWater: mark, pendingRelease: undefined });
  }

  /**
   * The `release_seq` no update may go at or below.
   *
   * The host's explicit value wins when it gives one — it knows things the SDK
   * cannot, such as a build installed by a package manager — and the persisted
   * mark is the default that makes anti-downgrade work for the hosts that give
   * nothing, which is every example and most applications.
   */
  private releaseFloor(explicit?: number): number | undefined {
    return explicit ?? this.binding?.releaseSeqHighWater;
  }

  /**
   * Whether this machine already holds an activation — restored from disk on
   * construction, so this is the startup question: prompt for a licence key, or
   * go straight to {@link validate}?
   */
  get isActivated(): boolean {
    return this.activationSecret !== null;
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
    if (this.keysetLicenseKeys.length > 0 && !this.keysetFromCache && !this.keysetIsStale()) {
      return;
    }
    try {
      await this.refreshKeyset();
    } catch (e) {
      // A refresh that cannot reach the server must not break a client that
      // already has keys it trusts — that would make a network problem look
      // like a licensing failure, which is the one thing the whole grace design
      // exists to avoid. With nothing adopted at all there is no fallback, so
      // the failure is the caller's to see.
      if (this.keysetLicenseKeys.length === 0) throw e;
    }
  }

  /**
   * Whether the adopted keyset is old enough to be worth re-fetching.
   *
   * This is what makes revoking a compromised signing key mean anything to an
   * install: a revoked key is omitted from the keyset, so a client only stops
   * trusting it once it fetches a newer one. Refreshing only on the first call
   * of a process bounds that by "next restart", which for a long-running host is
   * not a bound at all.
   *
   * A day, not an hour: the endpoint is public and unauthenticated, and every
   * install on earth hitting it hourly is a self-inflicted load pattern for a
   * document that changes about once a year. The honest description of the
   * guarantee is in `docs/SECURITY.md` — revocation is bounded, not instant.
   */
  private keysetIsStale(): boolean {
    if (!this.keysetIssuedAt) return true;
    return Date.now() / 1000 - this.keysetIssuedAt > KEYSET_MAX_AGE_SECONDS;
  }

  /** Verify a keyset token against the anchor and adopt its keys. */
  private adoptKeyset(token: unknown): void {
    if (!this.anchorKey || typeof token !== "string") return;
    const claims = verifyKeyset(this.anchorKey, this.options.productToken, token);
    // From the signed claims, not from a local clock reading taken when the
    // fetch happened: a client whose clock is wrong would otherwise decide its
    // keyset is fresh forever, or refetch on every call.
    const iat = claims["iat"];
    this.keysetIssuedAt = typeof iat === "number" ? iat : 0;
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
    if (this.isActivated && this.licenseKeyHash === hashLicenseKey(licenseKey)) {
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
      hostname: this.reportedHostname(),
      os: `${os.type()} ${os.release()}`,
      arch: os.arch(),
      app_version: this.options.appVersion,
      sdk_version: SDK_ID,
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
    // The key is not kept. From here the activation secret identifies both the
    // machine and its licence, so nothing needs the key again until somebody
    // types a different one.
    this.licenseKeyHash = hashLicenseKey(licenseKey);
    this.activationSecret = body["activation_secret"] as string;
    this.machineId = (body["machine_id"] as string) ?? null;
    this.binding = {
      licenseKeyHash: this.licenseKeyHash,
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
    return this.adopt(stateFromClaims(claims, "valid", false));
  }

  /**
   * The heartbeat cadence the server's policy asks for, in seconds, taken from
   * the last heartbeat's **signed** claims — so it cannot be lengthened in
   * transit by anyone wanting a fleet to check in less often.
   *
   * `null` until the first heartbeat of this process.
   */
  get heartbeatIntervalSeconds(): number | null {
    return this.heartbeatInterval;
  }

  /**
   * Subscribe to a licence transition. Returns a function that unsubscribes.
   *
   * ```ts
   * const off = talos.on("gracePeriodStarted", (s) => showOfflineBanner(s.graceUntil));
   * ```
   *
   * Fires from every path that adopts a verdict — `activate`, `validate`,
   * `heartbeat`, and the offline fallback — not only from the background loop,
   * so a host that runs its own timer gets the same transitions. The listener
   * runs synchronously inside that call; a listener that throws is ignored (see
   * {@link emit}).
   */
  on(event: TalosEventName, listener: LicenseListener): () => void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener);
    return () => {
      set.delete(listener);
    };
  }

  /**
   * Adopt a verdict as the current one, announcing the transition it makes.
   *
   * The single funnel every path goes through, which is what makes the events
   * trustworthy: a verdict reached anywhere else would be a transition nobody
   * hears about.
   */
  private adopt(state: LicenseState): LicenseState {
    const event = transitionEvent(this.current, state);
    this.current = state;
    if (event) this.emit(event, state);
    return state;
  }

  private emit(event: TalosEventName, state: LicenseState): void {
    for (const listener of this.listeners.get(event) ?? []) {
      try {
        listener(state);
      } catch {
        // The verdict is already decided, and this is being raised from inside
        // `validate`, whose own catch treats a throw as an unreachable server.
        // A host's broken banner code must not turn a live "revoked" answer
        // into offline grace.
      }
    }
  }

  /**
   * Run the check-ins the server's policy asks for, in the background.
   *
   * Two knobs have existed on the wire since Phase 1 and reached no client:
   * `heartbeat_interval_s` (how often an install reports in — the telemetry
   * rate, and the upper bound on how long a revocation takes to arrive) and
   * `reval_after` (when the entitlement bag and the offline cache should be
   * refreshed). Both are signed. This loop is what makes them a lever the
   * developer can actually pull: change the policy, and deployed apps follow.
   *
   * One timer serves both. Each tick re-validates if the signed `reval_after`
   * has passed, and otherwise sends a heartbeat — which is also what renews the
   * cached verdict that {@link validate} falls back on, so an app that runs
   * this stays inside its grace window without the host writing any scheduling
   * of its own.
   *
   * Opt-in, and idempotent: calling it again replaces the running loop.
   */
  startCheckIns(opts: CheckInOptions = {}): void {
    this.stopCheckIns();
    const generation = ++this.checkInGeneration;
    const tick = async (): Promise<void> => {
      try {
        const due = this.current?.revalidateAfter;
        const state =
          due === null || due === undefined || nowSeconds() >= due
            ? await this.validate()
            : await this.heartbeat();
        if (generation !== this.checkInGeneration) return;
        opts.onState?.(state);
      } catch (e) {
        if (generation !== this.checkInGeneration) return;
        opts.onError?.(e);
      }
      // Re-arm even after a failure: a network outage must not silently end
      // the loop, or the app would never notice the connection coming back.
      if (generation === this.checkInGeneration) schedule();
    };
    const schedule = (): void => {
      const secs = Math.max(60, this.heartbeatInterval ?? DEFAULT_HEARTBEAT_SECONDS);
      this.checkInTimer = setTimeout(() => void tick(), secs * 1000);
      this.checkInTimer.unref?.();
    };
    schedule();
  }

  /** Stop the background check-ins started by {@link startCheckIns}. */
  stopCheckIns(): void {
    this.checkInGeneration += 1;
    if (this.checkInTimer) {
      clearTimeout(this.checkInTimer);
      this.checkInTimer = null;
    }
  }

  /** Drop the machine binding, in memory and on disk. */
  private forgetBinding(): void {
    this.licenseKeyHash = null;
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
        fingerprint: { composite: this.fingerprint, components: this.fp.components },
        activation_secret: this.activationSecret,
        nonce,
        // Sent here as well as on activation and heartbeat, because check-ins
        // are opt-in and this call is not: an application that validates on
        // launch and never calls `startCheckIns` would otherwise show, forever,
        // whatever version it activated on.
        app_version: this.options.appVersion,
        sdk_version: SDK_ID,
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
      return this.adopt(stateFromClaims(claims, decision, false));
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
      return this.adopt(offline);
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
  /**
   * The machine name to report, or `undefined` to report none.
   *
   * An explicit `""` means "do not send": omitting the field leaves whatever
   * the server already holds, because the server coalesces, so sending an empty
   * string would not clear it either — suppression has to happen here.
   */
  private reportedHostname(): string | undefined {
    const h = this.options.hostname ?? os.hostname();
    return h === "" ? undefined : h;
  }

  async heartbeat(): Promise<LicenseState> {
    this.requireActivated();
    await this.ensureKeyset();
    const nonce = newNonce();
    const body = await this.post("/v1/client/heartbeat", {
      product_token: this.options.productToken,
      fingerprint: { composite: this.fingerprint, components: this.fp.components },
      activation_secret: this.activationSecret,
      nonce,
      app_version: this.options.appVersion,
      os: `${os.type()} ${os.release()}`,
      arch: os.arch(),
      sdk_version: SDK_ID,
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
    // The cadence comes from the SIGNED claims, never the response envelope:
    // the whole point of signing it is that nobody in the middle can tell a
    // fleet to check in less often.
    const interval = num(claims["heartbeat_interval_s"]);
    if (interval !== null && interval > 0) this.heartbeatInterval = interval;
    // Every signed server clock we see pushes the high-water mark forward, not
    // just validation's — a heartbeat is the most frequent call there is.
    this.advanceClock(claims);
    this.persist({ timeHighWater: this.binding?.timeHighWater });
    // A heartbeat carries the decision but not the entitlement bag; keep the
    // features from the last activate/validate.
    return this.adopt(
      new LicenseState(
        decision,
        this.current?.features ?? {},
        this.current?.licenseExpiresAt ?? null,
        false,
        this.current?.revalidateAfter ?? null,
        this.current?.graceUntil ?? null,
      ),
    );
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
    if (!this.activationSecret) return;
    await this.request("DELETE", "/v1/client/leases", {
      product_token: this.options.productToken,
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
   * `null` when up to date.
   *
   * Enforces anti-downgrade: a manifest whose `release_seq` is at or below the
   * floor is rejected as no update. The floor is the persisted high-water mark
   * — the highest `release_seq` this install has been seen running — unless
   * {@link CheckForUpdateOptions.currentReleaseSeq} overrides it.
   */
  async checkForUpdate(opts: CheckForUpdateOptions = {}): Promise<UpdateInfo | null> {
    this.requireActivated();
    await this.ensureKeyset();
    const body = await this.post("/v1/client/updates/check", {
      product_token: this.options.productToken,
      fingerprint: { composite: this.fingerprint, components: this.fp.components },
      activation_secret: this.activationSecret,
      current_version: opts.currentVersion ?? this.options.appVersion,
      current_release_seq: this.releaseFloor(opts.currentReleaseSeq),
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
    const floor = this.releaseFloor(opts.currentReleaseSeq);
    if (floor !== undefined && releaseSeq <= floor) {
      // Anti-downgrade, checked here as well as on the server: the server's
      // answer is the one an attacker replaces, and this one is checked against
      // a mark on this machine and a manifest signed by the pinned key.
      return null;
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

    // Patches, keyed by what distinguishes them from each other: the version
    // they apply to and the file they rebuild. A release that supports upgrading
    // from three versions and ships two files carries six.
    const deltaPaths = new Map<string, string>();
    for (const d of asArray(body["deltas"])) {
      const o = d as Record<string, unknown>;
      if (typeof o["download_path"] === "string") {
        deltaPaths.set(
          deltaKey(o["platform"], o["arch"], o["from"], o["target_kind"]),
          o["download_path"],
        );
      }
    }

    const deltas: UpdateDelta[] = asArray(m["deltas"]).map((d) => {
      const o = d as Record<string, unknown>;
      const t = (o["target"] ?? {}) as Record<string, unknown>;
      const platform = String(o["platform"] ?? "");
      const arch = String(o["arch"] ?? "");
      const from = String(o["from"] ?? "");
      const targetKind = String(t["kind"] ?? "");
      return {
        platform,
        arch,
        from,
        fromSeq: typeof o["from_seq"] === "number" ? (o["from_seq"] as number) : 0,
        filename: String(o["filename"] ?? ""),
        size: typeof o["size"] === "number" ? (o["size"] as number) : 0,
        sha256: String(o["sha256"] ?? ""),
        target: {
          kind: targetKind,
          filename: String(t["filename"] ?? ""),
          size: typeof t["size"] === "number" ? (t["size"] as number) : 0,
          sha256: String(t["sha256"] ?? ""),
        },
        downloadPath: deltaPaths.get(deltaKey(platform, arch, from, targetKind)),
      };
    });

    return {
      version: String(m["version"] ?? ""),
      releaseSeq,
      mandatory: m["mandatory"] === true,
      notesUrl: typeof m["notes_url"] === "string" ? (m["notes_url"] as string) : null,
      artifacts,
      deltas,
    };
  }

  /**
   * The patch that upgrades this machine, or `null` if there is none.
   *
   * Matches on the *exact* published version string, not on version ordering: a
   * patch applies to the bytes it was built against, and "close enough" produces
   * a corrupt file rather than an error. So a machine whose installed version is
   * not one the release ships a patch from simply downloads the full build.
   */
  selectDelta(info: UpdateInfo, opts: DeltaOptions = {}): UpdateDelta | null {
    const from = opts.from ?? this.options.appVersion;
    if (!from) return null;
    const { platform, arch } = hostTarget();
    const matches = info.deltas.filter(
      (d) => d.platform === platform && d.arch === arch && d.from === from,
    );
    if (opts.targetKind) return matches.find((d) => d.target.kind === opts.targetKind) ?? null;
    // Ambiguity is refused rather than guessed. Picking one of two patches for
    // an installer and a portable archive would download megabytes and rebuild
    // the file the host was not updating.
    return matches.length === 1 ? matches[0]! : null;
  }

  /**
   * Download a patch and verify its bytes against the manifest's SHA-256, then
   * write it to `destPath`. Returns the patch, whose `target.sha256` is what the
   * rebuilt file must hash to.
   *
   * Does NOT apply it. Applying is the host's job — and so is checking the
   * result, which {@link verifyAppliedUpdate} does. A patch verified on the way
   * in and a result nobody checks is a signed chain that stops one step short of
   * the binary that runs.
   */
  async downloadDelta(
    info: UpdateInfo,
    destPath: string,
    opts: DeltaOptions & { delta?: UpdateDelta; onProgress?: DownloadProgressCallback } = {},
  ): Promise<UpdateDelta> {
    const chosen = opts.delta ?? this.selectDelta(info, opts);
    if (!chosen) throw new TalosError("no patch applies to this install");
    await this.fetchVerified(
      chosen.downloadPath,
      chosen.size,
      chosen.sha256,
      destPath,
      opts.onProgress,
    );
    this.rememberDownloaded(info);
    return chosen;
  }

  /**
   * Download one artifact of an update and verify its bytes against the manifest
   * SHA-256, then write it to `destPath`. Returns the chosen artifact. Does NOT
   * apply or execute anything — verification and installation are the host app's
   * responsibility.
   *
   * `onProgress` is called as the bytes arrive, which is the only way a host can
   * show a bar: an installer takes minutes on a domestic connection, and a
   * promise that says nothing until it settles is indistinguishable from one that
   * has hung. Totals come from the signed manifest — see {@link DownloadProgress}.
   */
  async downloadUpdate(
    info: UpdateInfo,
    destPath: string,
    artifact?: UpdateArtifact,
    onProgress?: DownloadProgressCallback,
  ): Promise<UpdateArtifact> {
    this.requireActivated();
    const chosen = artifact ?? pickArtifact(info.artifacts);
    if (!chosen) throw new TalosError("no artifact matches this platform");
    await this.fetchVerified(chosen.downloadPath, chosen.size, chosen.sha256, destPath, onProgress);
    this.rememberDownloaded(info);
    return chosen;
  }

  /**
   * Note which release's bytes are now on disk, so the next start can tell
   * whether they were installed.
   *
   * Written after the hash check, never before: a download that failed
   * verification is not a release this install is about to be running, and
   * recording it would let a corrupt or substituted file raise the
   * anti-downgrade floor past a good build.
   */
  private rememberDownloaded(info: UpdateInfo): void {
    if (info.releaseSeq <= (this.binding?.releaseSeqHighWater ?? 0)) return;
    this.persist({ pendingRelease: { version: info.version, releaseSeq: info.releaseSeq } });
  }

  /**
   * Fetch one file over the entitled download route and put it at `destPath`
   * only once its bytes match the size and hash the signed manifest names.
   * Shared by full builds and patches, which differ in what they are for and not
   * at all in how their bytes are checked.
   *
   * The bytes go straight to a `.talos-part` file beside the destination, hashed
   * as they arrive, and are renamed into place only once the hash matches. Two
   * things follow. A multi-gigabyte installer is never held in memory — the whole
   * body used to be buffered before it was checked, so the largest artifact a
   * product could ship was bounded by the smallest machine it ran on. And
   * `destPath` never holds unverified bytes, not even briefly: a download that
   * fails leaves whatever was there before rather than a truncated file a host
   * might run.
   */
  private async fetchVerified(
    downloadPath: string | undefined,
    size: number,
    sha256: string,
    destPath: string,
    onProgress?: DownloadProgressCallback,
  ): Promise<void> {
    if (!downloadPath) throw new TalosError("artifact has no download path");
    const url = this.options.serverUrl.replace(/\/+$/, "") + downloadPath;
    const res = await this.doFetch(url, {
      method: "GET",
      headers: {
        "x-talos-product-token": this.options.productToken,
        "x-talos-activation-secret": this.activationSecret!,
        "x-talos-fingerprint": this.fingerprint,
      },
    });
    if (res.status < 200 || res.status >= 300) throw new TalosApiError(res.status, undefined);

    // The download channel is untrusted (could stream an unbounded body to
    // exhaust memory before the hash check). Cap the read at the manifest's
    // trusted `size`, then verify the SHA-256 from the signed manifest.
    const contentLength = res.headers?.get("content-length");
    if (contentLength && Number(contentLength) > size) {
      throw new TalosSignatureError("artifact exceeds manifest size");
    }

    const partPath = destPath + ".talos-part";
    const handle = await open(partPath, "w");
    const hash = createHash("sha256");
    let received = 0;
    let closed = false;
    const take = async (chunk: Uint8Array): Promise<void> => {
      received += chunk.byteLength;
      if (received > size) throw new TalosSignatureError("artifact exceeds manifest size");
      hash.update(chunk);
      await handle.write(chunk);
      onProgress?.({ bytesReceived: received, totalBytes: size });
    };
    try {
      const body = res.body;
      if (body) {
        const reader = body.getReader();
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done || !value) break;
            await take(value);
          }
        } catch (e) {
          await reader.cancel().catch(() => {});
          throw e;
        }
      } else {
        // Nothing to meter, so this one arrives whole. The real `fetch` always
        // has a stream; this is the path an injected implementation takes.
        await take(new Uint8Array(await res.arrayBuffer()));
      }

      if (hash.digest("hex") !== sha256) {
        throw new TalosSignatureError("artifact hash mismatch (tampered or wrong bytes)");
      }
      // Closed before the rename: Windows will not move a file that is open.
      await handle.close();
      closed = true;
      await rename(partPath, destPath);
    } catch (e) {
      if (!closed) await handle.close().catch(() => {});
      // A part file left behind is one the next download has to reason about,
      // and one nobody who finds it in an install directory can.
      await rm(partPath, { force: true }).catch(() => {});
      throw e;
    }
  }

  private requireActivated(): void {
    if (!this.activationSecret) {
      throw new TalosError("not activated: call activate() first");
    }
  }

  private post(path: string, body: unknown): Promise<Record<string, unknown>> {
    return this.request("POST", path, body);
  }

  /**
   * The abort signal for one licensing call, or `undefined` when disabled.
   *
   * A fresh one per request rather than one shared: `AbortSignal.timeout`
   * starts counting when it is created, so a signal made once in the
   * constructor would already have fired by the second call.
   */
  private timeoutSignal(): AbortSignal | undefined {
    const ms = this.options.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
    if (!ms || ms <= 0) return undefined;
    // Present since Node 17.3. Guarded rather than assumed because `fetch` may
    // be injected in a runtime that has one and not the other, and a missing
    // timeout is better than a crash on the launch path.
    return typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(ms) : undefined;
  }

  private async request(
    method: string,
    path: string,
    body: unknown,
  ): Promise<Record<string, unknown>> {
    let res: FetchResponseLike;
    try {
      res = await this.doFetch(this.options.serverUrl.replace(/\/+$/, "") + path, {
        method,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: this.timeoutSignal(),
      });
    } catch (e) {
      // An abort is a network failure, not a licensing verdict, and it has to
      // read as one: `validate` turns a network failure into the grace-period
      // path, and an unrecognised exception type there would take the
      // application down instead of letting it keep running offline.
      if (e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError")) {
        throw new TalosError(
          `request timed out after ${this.options.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS}ms`,
        );
      }
      throw e;
    }
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

/**
 * Which transition, if any, moving from `prev` to `next` amounts to.
 *
 * At most one: the four are mutually exclusive by decision, and a repeat of the
 * verdict already held is not a transition at all — an application offline for a
 * week gets one `gracePeriodStarted`, not one per check-in. A *different* bad
 * verdict does fire again (`expired` after `suspended` is a different thing to
 * tell the user about), which is why this compares the decision and not just
 * validity.
 */
function transitionEvent(prev: LicenseState | null, next: LicenseState): TalosEventName | null {
  if (next.decision === "clock_tampered") {
    return prev?.decision === "clock_tampered" ? null : "clockTamperDetected";
  }
  if (next.decision === "grace_expired") {
    return prev?.decision === "grace_expired" ? null : "gracePeriodExpired";
  }
  if (next.isValid) {
    // Grace begins when a cached verdict is what is keeping the application
    // running, not when the network drops: a failed call that falls back on
    // nothing throws, and never reaches here.
    if (!next.isOffline) return null;
    return prev?.isOffline && prev.isValid ? null : "gracePeriodStarted";
  }
  return prev?.decision === next.decision ? null : "licenseInvalid";
}

function newNonce(): string {
  return b64urlEncode(randomBytes(16));
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function selKey(platform: unknown, arch: unknown, kind: unknown): string {
  return `${String(platform)}/${String(arch)}/${String(kind)}`;
}

function deltaKey(platform: unknown, arch: unknown, from: unknown, targetKind: unknown): string {
  return `${String(platform)}/${String(arch)}/${String(from)}/${String(targetKind)}`;
}

/** The platform and arch names this machine matches artifacts by. */
function hostTarget(): { platform: string; arch: string } {
  const map: Record<string, string> = { win32: "windows", darwin: "macos", linux: "linux" };
  return { platform: map[os.platform()] ?? os.platform(), arch: os.arch() };
}

/** Best artifact for the current platform (installer preferred), or undefined. */
function pickArtifact(artifacts: UpdateArtifact[]): UpdateArtifact | undefined {
  const { platform, arch } = hostTarget();
  const matches = artifacts.filter((a) => a.platform === platform && a.arch === arch);
  return matches.find((a) => a.kind === "installer") ?? matches[0];
}

/**
 * Check that applying a patch produced the file the signed manifest said it
 * would. Throws {@link TalosSignatureError} if not.
 *
 * This is the last link in the chain and the easiest one to leave out. The patch
 * itself was verified on the way in, but a patcher can fail halfway, apply to
 * the wrong base file, or be handed bytes from somewhere else entirely — and
 * every one of those produces a file that nothing has vouched for. Reads the
 * file in chunks, so a multi-gigabyte install is not brought into memory.
 *
 * Needs no licence and no activation: run it from the updater process, after the
 * application it belongs to has exited.
 */
export async function verifyAppliedUpdate(filePath: string, delta: UpdateDelta): Promise<void> {
  const hash = createHash("sha256");
  const stream = createReadStream(filePath);
  await new Promise<void>((resolve, reject) => {
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve());
  });
  const actual = hash.digest("hex");
  if (actual !== delta.target.sha256) {
    throw new TalosSignatureError(
      `applied update does not match the signed manifest: expected ${delta.target.sha256}, got ${actual}`,
    );
  }
}
