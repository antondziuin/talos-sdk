import { createPrivateKey, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";

import { b64urlEncode } from "./talos-compact.js";

/**
 * The air-gapped exchange, and the identity that makes it possible.
 *
 * Online, a machine proves who it is with the `activation_secret` the server
 * hands back from `activate`. A machine that cannot reach a server never gets
 * one — so it makes its own: an Ed25519 pair at the first offline request,
 * public half in `talos-request.json`, private half never leaving this disk. The
 * file the portal issues is bound to that key as well as to the fingerprint, and
 * anything this machine sends back afterwards is signed by it.
 *
 * The document format deliberately is **not** Talos-compact. That format's `typ`
 * set is the closed list of things the *platform* signs, and putting a machine's
 * key into the same namespace as a product's is exactly the confusion the tag
 * set exists to prevent. What is copied is the part that matters: the payload
 * travels base64url-encoded and is verified as received, never re-serialised, so
 * three implementations cannot disagree about JSON key order and turn that into
 * a signature one of them rejects.
 */

/** Domain tag of `talos-request.json`; also part of what is signed. */
export const REQUEST_DOMAIN = "talos-offline-request";
/** `kind` of the file the portal issues back. */
export const LICENSE_FILE_KIND = "talos-offline-license";
const DOC_VERSION = 1;

/** A machine's own keypair, in the two forms this SDK needs. */
export interface MachineKey {
  /** PKCS#8 DER, base64 — how the private half is kept in the state file. */
  privateKey: string;
  /** The raw 32-byte public key, standard base64 — how it travels. */
  publicKey: string;
}

/** A document this machine signed: what gets written to disk and carried. */
export interface SignedDoc {
  v: number;
  kind: string;
  /** base64url of the payload JSON. */
  req: string;
  /** base64url Ed25519 signature over `"<kind>.1.<req>"`. */
  sig: string;
}

/**
 * Generate the machine's identity.
 *
 * Once per install, at the first offline request. Losing it means the customer
 * repeats the ceremony — which is the honest consequence of an identity that is
 * only ever held in one place, and the reason it lives in the same encrypted
 * state file as everything else this SDK persists.
 */
export function generateMachineKey(): MachineKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKey: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    // The raw key is the last 32 bytes of the SPKI DER; every other Ed25519
    // implementation in this project speaks raw-32, including the server's.
    publicKey: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64"),
  };
}

function privateKeyObject(pkcs8Base64: string): KeyObject {
  return createPrivateKey({
    key: Buffer.from(pkcs8Base64, "base64"),
    format: "der",
    type: "pkcs8",
  });
}

/** The exact ASCII bytes a machine-signed document is signed over. */
export function signedMessage(domain: string, payloadB64: string): string {
  return `${domain}.${DOC_VERSION}.${payloadB64}`;
}

/** Sign a payload object as a machine document. */
export function signMachineDoc(
  key: MachineKey,
  domain: string,
  payload: Record<string, unknown>,
): SignedDoc {
  const req = b64urlEncode(Buffer.from(JSON.stringify(payload), "utf8"));
  const sig = cryptoSign(null, Buffer.from(signedMessage(domain, req), "ascii"), privateKeyObject(key.privateKey));
  return { v: DOC_VERSION, kind: domain, req, sig: b64urlEncode(sig) };
}
