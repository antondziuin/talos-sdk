import { createHash, randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import os from "node:os";
import { type KeyObject } from "node:crypto";

import { TalosApiError, TalosError, TalosSignatureError } from "./errors.js";
import { computeFingerprint } from "./fingerprint.js";
import { b64urlEncode, publicKeyFromBase64, verifyManifest, verifyToken } from "./talos-compact.js";

/** Minimal fetch signature (Node 18+ global fetch, or an injected one). */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ status: number; text(): Promise<string> }>;

export interface TalosOptions {
  /** The product's public token (`tpt_…`) from the portal. */
  productToken: string;
  /** The product's Ed25519 public key, base64 (from the portal). */
  publicKey: string;
  /**
   * The product's **release**-signing public key, base64 (from the portal's
   * Integration page). Used to verify update manifests. A key distinct from
   * {@link publicKey}, under separate custody. Falls back to `publicKey` when
   * omitted (for products that sign releases with the license key).
   */
  releasePublicKey?: string;
  /** Base URL of the Talos (or self-hosted) server. */
  serverUrl: string;
  /** Optional app version reported in telemetry/heartbeats. */
  appVersion?: string;
  /** Optional fetch implementation (defaults to the global `fetch`). */
  fetch?: FetchLike;
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
    /** valid | expired | revoked | suspended | deactivated | machine_revoked | invalid. */
    readonly decision: string,
    /** Entitlement bag (server-defined). */
    readonly features: Record<string, unknown>,
    /** Business expiry (unix seconds), or null for perpetual. */
    readonly licenseExpiresAt: number | null,
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
  private readonly publicKey: KeyObject;
  private readonly releaseKey: KeyObject;
  private readonly fingerprint: string;
  private readonly doFetch: FetchLike;

  private licenseKey: string | null = null;
  private activationSecret: string | null = null;
  current: LicenseState | null = null;

  constructor(options: TalosOptions) {
    if (!options.productToken) throw new TalosError("productToken required");
    if (!options.publicKey) throw new TalosError("publicKey required");
    if (!options.serverUrl) throw new TalosError("serverUrl required");
    this.options = options;
    this.publicKey = publicKeyFromBase64(options.publicKey);
    // Manifests verify against the release key; fall back to the license key.
    this.releaseKey = options.releasePublicKey
      ? publicKeyFromBase64(options.releasePublicKey)
      : this.publicKey;
    this.fingerprint = computeFingerprint();
    this.doFetch = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
    if (!this.doFetch) throw new TalosError("no fetch available (need Node 18+ or options.fetch)");
  }

  isFeatureEnabled(name: string): boolean {
    return this.current?.isFeatureEnabled(name) ?? false;
  }

  async activate(licenseKey: string): Promise<LicenseState> {
    const nonce = newNonce();
    const body = await this.post("/v1/client/activate", {
      product_token: this.options.productToken,
      license_key: licenseKey,
      fingerprint: { composite: this.fingerprint, components: {} },
      nonce,
      os: `${os.type()} ${os.release()}`,
      arch: os.arch(),
      app_version: this.options.appVersion,
      sdk_version: "node/0.0.0",
    });

    const claims = verifyToken(
      this.publicKey,
      "activation",
      this.options.productToken,
      nonce,
      body["activation_token"] as string,
    );
    this.licenseKey = licenseKey;
    this.activationSecret = body["activation_secret"] as string;
    this.current = stateFromClaims(claims, "valid");
    return this.current;
  }

  async validate(): Promise<LicenseState> {
    this.requireActivated();
    const nonce = newNonce();
    const body = await this.post("/v1/client/validate", {
      product_token: this.options.productToken,
      license_key: this.licenseKey,
      fingerprint: { composite: this.fingerprint, components: {} },
      activation_secret: this.activationSecret,
      nonce,
    });
    const claims = verifyToken(
      this.publicKey,
      "validation",
      this.options.productToken,
      nonce,
      body["validation_token"] as string,
    );
    const decision = typeof claims["decision"] === "string" ? (claims["decision"] as string) : "invalid";
    this.current = stateFromClaims(claims, decision);
    return this.current;
  }

  async deactivate(): Promise<void> {
    this.requireActivated();
    await this.post("/v1/client/deactivate", {
      product_token: this.options.productToken,
      license_key: this.licenseKey,
      fingerprint: { composite: this.fingerprint, components: {} },
      activation_secret: this.activationSecret,
    });
    this.current = null;
    this.activationSecret = null;
  }

  /**
   * Ask whether a newer release is available. Returns a verified {@link UpdateInfo}
   * (all metadata comes from the manifest signed by the pinned release key), or
   * `null` when up to date. Enforces anti-downgrade: a manifest whose
   * `release_seq` is at or below `currentReleaseSeq` is rejected as no update.
   */
  async checkForUpdate(opts: CheckForUpdateOptions = {}): Promise<UpdateInfo | null> {
    this.requireActivated();
    const body = await this.post("/v1/client/updates/check", {
      product_token: this.options.productToken,
      license_key: this.licenseKey,
      fingerprint: { composite: this.fingerprint, components: {} },
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
    const m = verifyManifest(this.releaseKey, this.options.productToken, manifestToken);
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

  private async post(path: string, body: unknown): Promise<Record<string, unknown>> {
    const res = await this.doFetch(this.options.serverUrl.replace(/\/+$/, "") + path, {
      method: "POST",
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

function stateFromClaims(claims: Record<string, unknown>, decision: string): LicenseState {
  const lic = (claims["lic"] ?? {}) as Record<string, unknown>;
  const features = (lic["features"] ?? {}) as Record<string, unknown>;
  const exp = typeof lic["lic_exp"] === "number" ? (lic["lic_exp"] as number) : null;
  return new LicenseState(decision, features, exp);
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
