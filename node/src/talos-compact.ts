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

/**
 * Verify a Talos-compact token
 * (`talos.<ver>.<typ>.<b64url(payload)>.<b64url(sig)>`, Ed25519 over the exact
 * ASCII prefix). Pinned to a single product key; IGNORES any `kid` and enforces
 * `typ`, `aud`, the echoed nonce, and `nbf`/`exp`.
 */
export function verifyToken(
  key: KeyObject,
  expectedTyp: string,
  expectedAud: string,
  expectedNonce: string,
  token: string,
): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 5) throw new TalosSignatureError("malformed token");
  if (parts[0] !== "talos") throw new TalosSignatureError("unexpected scheme");
  if (parts[1] !== "1") throw new TalosSignatureError("unsupported wire version");
  if (parts[2] !== expectedTyp) throw new TalosSignatureError("token type mismatch");

  const lastDot = token.lastIndexOf(".");
  const prefix = Buffer.from(token.slice(0, lastDot), "ascii");
  const sig = b64urlDecode(parts[4]!);
  if (!cryptoVerify(null, prefix, key, sig)) {
    throw new TalosSignatureError("signature verification failed");
  }

  const claims = JSON.parse(b64urlDecode(parts[3]!).toString("utf8")) as Record<string, unknown>;
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
 * release key. Unlike per-request tokens a manifest is a long-lived, static
 * artifact, so there is no nonce to echo and no short `exp`; instead it carries
 * a `not_before` gate. Enforces scheme/version/`typ`, the signature, `aud`, and
 * `not_before`.
 */
export function verifyManifest(
  releaseKey: KeyObject,
  expectedAud: string,
  token: string,
): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 5) throw new TalosSignatureError("malformed manifest");
  if (parts[0] !== "talos") throw new TalosSignatureError("unexpected scheme");
  if (parts[1] !== "1") throw new TalosSignatureError("unsupported wire version");
  if (parts[2] !== "manifest") throw new TalosSignatureError("not a manifest token");

  const lastDot = token.lastIndexOf(".");
  const prefix = Buffer.from(token.slice(0, lastDot), "ascii");
  const sig = b64urlDecode(parts[4]!);
  if (!cryptoVerify(null, prefix, releaseKey, sig)) {
    throw new TalosSignatureError("manifest signature verification failed");
  }

  const claims = JSON.parse(b64urlDecode(parts[3]!).toString("utf8")) as Record<string, unknown>;
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
