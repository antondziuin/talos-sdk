import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";

import { TalosSignatureError } from "../src/errors.js";
import { publicKeyFromBase64, verifyToken } from "../src/talos-compact.js";

function keypair(): { pubB64: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const raw = der.subarray(der.length - 32); // strip the SPKI prefix
  return { pubB64: raw.toString("base64"), privateKey };
}

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function mint(privateKey: KeyObject, typ: string, payload: unknown): string {
  const prefix = `talos.1.${typ}.` + b64url(Buffer.from(JSON.stringify(payload)));
  const sig = cryptoSign(null, Buffer.from(prefix, "ascii"), privateKey);
  return prefix + "." + b64url(sig);
}

function payload(aud: string, non: string) {
  const now = Math.floor(Date.now() / 1000);
  return { aud, non, nbf: now - 10, exp: now + 600 };
}

describe("talos-compact verify", () => {
  it("verifies under the correct key", () => {
    const { pubB64, privateKey } = keypair();
    const token = mint(privateKey, "activation", payload("prod_x", "n1"));
    const claims = verifyToken(publicKeyFromBase64(pubB64), "activation", "prod_x", "n1", token);
    expect(claims["aud"]).toBe("prod_x");
  });

  it("rejects a wrong key", () => {
    const a = keypair();
    const b = keypair();
    const token = mint(a.privateKey, "activation", payload("prod_x", "n1"));
    expect(() =>
      verifyToken(publicKeyFromBase64(b.pubB64), "activation", "prod_x", "n1", token),
    ).toThrow(TalosSignatureError);
  });

  it("rejects typ / aud / nonce mismatch", () => {
    const { pubB64, privateKey } = keypair();
    const key = publicKeyFromBase64(pubB64);
    const token = mint(privateKey, "activation", payload("prod_x", "n1"));
    expect(() => verifyToken(key, "validation", "prod_x", "n1", token)).toThrow();
    expect(() => verifyToken(key, "activation", "prod_y", "n1", token)).toThrow();
    expect(() => verifyToken(key, "activation", "prod_x", "n2", token)).toThrow();
  });

  it("rejects a tampered payload", () => {
    const { pubB64, privateKey } = keypair();
    const key = publicKeyFromBase64(pubB64);
    const token = mint(privateKey, "activation", payload("prod_x", "n1"));
    const parts = token.split(".");
    parts[3] = b64url(Buffer.from(JSON.stringify(payload("prod_x", "n1")))) + "AA";
    expect(() => verifyToken(key, "activation", "prod_x", "n1", parts.join("."))).toThrow(
      TalosSignatureError,
    );
  });
});

/**
 * `nbf`/`exp`, which §4 requires the SDK to check and which nothing tested.
 *
 * The signature is not what these are about: an attacker cannot mint any of
 * these tokens without the pinned key. What they are about is a *server* that
 * emits a token with no expiry, or a client whose clock has run past one. The
 * first is a bug that would otherwise produce a verdict valid forever on every
 * install in the field; the second is the ordinary case this window exists for.
 */
describe("token freshness", () => {
  const now = () => Math.floor(Date.now() / 1000);

  function verify(privateKey: KeyObject, pubB64: string, claims: Record<string, unknown>) {
    const token = mint(privateKey, "validation", { aud: "prod_x", non: "n1", ...claims });
    return () =>
      verifyToken(publicKeyFromBase64(pubB64), "validation", "prod_x", "n1", token);
  }

  it("rejects a token whose exp has passed", () => {
    const { pubB64, privateKey } = keypair();
    expect(verify(privateKey, pubB64, { nbf: now() - 600, exp: now() - 120 })).toThrow(
      TalosSignatureError,
    );
  });

  it("rejects a token that is not valid yet", () => {
    const { pubB64, privateKey } = keypair();
    expect(verify(privateKey, pubB64, { nbf: now() + 600, exp: now() + 1200 })).toThrow(
      TalosSignatureError,
    );
  });

  it("tolerates a minute of clock skew in either direction", () => {
    const { pubB64, privateKey } = keypair();
    // A client 30 seconds fast against a token that has just expired, and one
    // 30 seconds slow against a token that has just started. Both are the
    // ordinary state of an unsynchronised desktop, and refusing them would
    // report a licensing failure for a clock nobody noticed.
    expect(verify(privateKey, pubB64, { nbf: now() - 600, exp: now() - 30 })).not.toThrow();
    expect(verify(privateKey, pubB64, { nbf: now() + 30, exp: now() + 600 })).not.toThrow();
  });

  it("refuses a token that carries no expiry at all", () => {
    const { pubB64, privateKey } = keypair();
    // Signed by the right key, and still refused: a missing `exp` used to read
    // as "no expiry", so one server-side omission would have been a verdict
    // that never went stale on any install that received it.
    expect(verify(privateKey, pubB64, { nbf: now() - 10 })).toThrow(TalosSignatureError);
    expect(verify(privateKey, pubB64, { exp: now() + 600 })).toThrow(TalosSignatureError);
    expect(verify(privateKey, pubB64, { nbf: "soon", exp: "later" })).toThrow(
      TalosSignatureError,
    );
  });
});
