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
