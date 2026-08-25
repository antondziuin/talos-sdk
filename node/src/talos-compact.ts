import { createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";

import { TalosSignatureError } from "./errors.js";

// DER SubjectPublicKeyInfo prefix for a raw Ed25519 public key.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const CLOCK_SKEW_SECONDS = 60;

/** Wrap a base64-encoded raw 32-byte Ed25519 public key as a KeyObject. */
export function publicKeyFromBase64(b64: string): KeyObject {
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== 32) {
    throw new Error("public key must decode to 32 bytes");
  }
  const der = Buffer.concat([SPKI_PREFIX, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

export function b64urlEncode(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

type Keys = KeyObject | KeyObject[];

/**
 * Parse a Talos-compact token, check scheme/version/`typ`, and verify the
 * signature against ANY of `keys` (a keyset may carry several valid keys during
 * rotation). Returns the decoded claims; the caller checks aud/nonce/exp.
 */
function parseAndVerify(keys: Keys, token: string, expectedTyp: string): Record<string, unknown> {
  const list = Array.isArray(keys) ? keys : [keys];
  const parts = token.split(".");
  if (parts.length !== 5) throw new TalosSignatureError("malformed token");
  if (parts[0] !== "talos") throw new TalosSignatureError("unexpected scheme");
  if (parts[1] !== "1") throw new TalosSignatureError("unsupported wire version");
  if (parts[2] !== expectedTyp) throw new TalosSignatureError("token type mismatch");
  if (list.length === 0) throw new TalosSignatureError("no verification key");

  const lastDot = token.lastIndexOf(".");
  const prefix = Buffer.from(token.slice(0, lastDot), "ascii");
  const sig = b64urlDecode(parts[4]!);
  const ok = list.some((k) => cryptoVerify(null, prefix, k, sig));
  if (!ok) throw new TalosSignatureError("signature verification failed");

  return JSON.parse(b64urlDecode(parts[3]!).toString("utf8")) as Record<string, unknown>;
}

/**
 * Verify a Talos-compact token
 * (`talos.<ver>.<typ>.<b64url(payload)>.<b64url(sig)>`, Ed25519 over the exact
 * ASCII prefix). `keys` may be a single pinned key or a keyset (any of which may
 * have signed it). IGNORES any `kid` and enforces `typ`, `aud`, the echoed
 * nonce, and `nbf`/`exp`.
 */
export function verifyToken(
  keys: Keys,
  expectedTyp: string,
  expectedAud: string,
  expectedNonce: string,
  token: string,
): Record<string, unknown> {
  const claims = parseAndVerify(keys, token, expectedTyp);
  if (claims["aud"] !== expectedAud) throw new TalosSignatureError("audience mismatch");
  if (claims["non"] !== expectedNonce) {
    throw new TalosSignatureError("nonce mismatch (possible replay)");
  }
  const now = Math.floor(Date.now() / 1000);
  const nbf = claims["nbf"];
  if (typeof nbf === "number" && now + CLOCK_SKEW_SECONDS < nbf) {
    throw new TalosSignatureError("token not yet valid");
  }
  const exp = claims["exp"];
  if (typeof exp === "number" && now - CLOCK_SKEW_SECONDS > exp) {
    throw new TalosSignatureError("token expired");
  }
  return claims;
}

/**
 * Verify a signed update **manifest** (`typ=manifest`) against the pinned
 * release key(s). Unlike per-request tokens a manifest is a long-lived, static
 * artifact, so there is no nonce and no short `exp`; instead it carries a
 * `not_before` gate. Enforces scheme/version/`typ`, the signature, `aud`, and
 * `not_before`.
 */
export function verifyManifest(
  releaseKeys: Keys,
  expectedAud: string,
  token: string,
): Record<string, unknown> {
  const claims = parseAndVerify(releaseKeys, token, "manifest");
  if (claims["aud"] !== expectedAud) throw new TalosSignatureError("audience mismatch");
  const notBefore = claims["not_before"];
  if (typeof notBefore === "number") {
    const now = Math.floor(Date.now() / 1000);
    if (now + CLOCK_SKEW_SECONDS < notBefore) {
      throw new TalosSignatureError("manifest not yet released");
    }
  }
  return claims;
}

/**
 * Verify a signed **keyset** (`typ=keyset`) against the pinned anchor key. The
 * keyset lists the product's current, rotatable license/release public keys, so
 * an SDK that pins only the anchor learns the signing keys from it — a rotated
 * key never breaks a deployed app. Enforces scheme/version/`typ`, the anchor
 * signature, and `aud`.
 */
export function verifyKeyset(
  anchorKey: KeyObject,
  expectedAud: string,
  token: string,
): Record<string, unknown> {
  const claims = parseAndVerify(anchorKey, token, "keyset");
  if (claims["aud"] !== expectedAud) throw new TalosSignatureError("audience mismatch");
  return claims;
}
