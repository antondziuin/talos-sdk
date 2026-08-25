import { randomBytes } from "node:crypto";
import os from "node:os";
import { type KeyObject } from "node:crypto";

import { TalosApiError, TalosError } from "./errors.js";
import { computeFingerprint } from "./fingerprint.js";
import { b64urlEncode, publicKeyFromBase64, verifyToken } from "./talos-compact.js";

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
  /** Base URL of the Talos (or self-hosted) server. */
  serverUrl: string;
  /** Optional app version reported in telemetry/heartbeats. */
  appVersion?: string;
  /** Optional fetch implementation (defaults to the global `fetch`). */
  fetch?: FetchLike;
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
