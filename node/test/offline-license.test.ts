import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, createPublicKey, type KeyObject } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { TalosClient, type FetchLike, type TalosOptions } from "../src/client.js";
import { collectFingerprint } from "../src/fingerprint.js";
import {
  LICENSE_FILE_KIND,
  RECEIPT_DOMAIN,
  REQUEST_DOMAIN,
  signedMessage,
} from "../src/offline.js";

/**
 * Air-gapped activation: the machine identity this SDK generates for itself, the
 * request it writes, and the file it is handed back.
 *
 * Distinct from `offline.test.ts`, which is about *grace* — an install that has
 * been online coasting on a cached verdict. Nothing here has ever seen a server,
 * and the assertions that matter are the ones about what still binds a decision
 * to one machine when no server will ever be asked again.
 */

const PRODUCT = "tpt_offline_file_test";
const NOW = (): number => Math.floor(Date.now() / 1000);
const fingerprint = collectFingerprint(PRODUCT).composite;

/** A network that is simply not there — which is the whole point. */
const deadNetwork: FetchLike = () => Promise.reject(new Error("ENOTFOUND"));

function keypair(): { pubB64: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { pubB64: der.subarray(der.length - 32).toString("base64"), privateKey };
}

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function mint(privateKey: KeyObject, typ: string, payload: unknown): string {
  const prefix = `talos.1.${typ}.` + b64url(Buffer.from(JSON.stringify(payload)));
  return prefix + "." + b64url(cryptoSign(null, Buffer.from(prefix, "ascii"), privateKey));
}

function statePath(): string {
  return path.join(mkdtempSync(path.join(os.tmpdir(), "talos-air-")), "state.bin");
}

function client(opts: Partial<TalosOptions> & { statePath: string }): TalosClient {
  return new TalosClient({
    productToken: PRODUCT,
    serverUrl: "http://127.0.0.1:1",
    fetch: deadNetwork,
    ...opts,
  } as TalosOptions);
}

/** The claims the portal signs into a `typ=offline` file. */
function offlineClaims(mpk: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = NOW();
  return {
    aud: PRODUCT,
    typ: "offline",
    sub: "01a07b9c-0000-7000-8000-000000000001",
    iat: now - 60,
    nbf: now - 60,
    exp: now + 90 * 86_400,
    non: "the-nonce-the-request-carried",
    decision: "valid",
    server_time: now - 60,
    fph: fingerprint,
    mpk,
    mid: "m-air-1",
    fid: "f-air-1",
    lic: { features: { pro: true }, lic_exp: null },
    ...over,
  };
}

/** `license.talos`, as the portal hands it back. */
function licenseFile(token: string, keyset?: string): string {
  const file = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-file-")), "license.talos");
  writeFileSync(file, JSON.stringify({ v: 1, kind: LICENSE_FILE_KIND, token, keyset }));
  return file;
}

/** The machine public key out of a request this SDK just wrote. */
function requestPayload(doc: { req: string }): Record<string, unknown> {
  return JSON.parse(b64urlDecode(doc.req).toString("utf8")) as Record<string, unknown>;
}

describe("the offline request", () => {
  it("is signed by the key it names, and carries this machine's fingerprint", () => {
    const doc = client({ statePath: statePath(), publicKey: keypair().pubB64 })
      .createOfflineRequest("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");
    expect(doc.kind).toBe(REQUEST_DOMAIN);

    const payload = requestPayload(doc);
    expect(payload["product_token"]).toBe(PRODUCT);
    expect((payload["fingerprint"] as Record<string, unknown>)["composite"]).toBe(fingerprint);
    expect(payload["license_key"]).toBe("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");

    // The document is self-certifying: the key that signed it is named inside
    // what it signed, which is what makes the request worth anything at all to
    // a portal that has never met this machine.
    const raw = Buffer.from(payload["machine_pubkey"] as string, "base64");
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
    const pub = createPublicKey({ key: der, format: "der", type: "spki" });
    expect(
      cryptoVerify(
        null,
        Buffer.from(signedMessage(REQUEST_DOMAIN, doc.req), "ascii"),
        pub,
        b64urlDecode(doc.sig),
      ),
    ).toBe(true);
  });

  it("keeps one identity across calls and across restarts", () => {
    const file = statePath();
    const pubB64 = keypair().pubB64;
    const first = requestPayload(client({ statePath: file, publicKey: pubB64 }).createOfflineRequest());
    const second = requestPayload(client({ statePath: file, publicKey: pubB64 }).createOfflineRequest());
    // A second identity would mean the file the vendor is about to sign is
    // bound to a key this install has already replaced.
    expect(second["machine_pubkey"]).toBe(first["machine_pubkey"]);
    expect(second["nonce"]).not.toBe(first["nonce"]);
  });
});

describe("loading an offline licence file", () => {
  /** A client that has produced a request, and the key the portal would bind. */
  function requested(over: Partial<TalosOptions> = {}): {
    talos: TalosClient;
    mpk: string;
    file: string;
    licenseKey: KeyObject;
    pubB64: string;
  } {
    const { pubB64, privateKey } = keypair();
    const file = statePath();
    const talos = client({ statePath: file, publicKey: pubB64, ...over });
    const mpk = requestPayload(talos.createOfflineRequest())["machine_pubkey"] as string;
    return { talos, mpk, file, licenseKey: privateKey, pubB64 };
  }

  it("licenses the machine it was issued for, with no network at all", async () => {
    const { talos, mpk, licenseKey } = requested();
    const state = await talos.loadOfflineLicense(
      licenseFile(mint(licenseKey, "offline", offlineClaims(mpk))),
    );
    expect(state.decision).toBe("valid");
    expect(state.isValid).toBe(true);
    expect(state.isOffline).toBe(true);
    expect(state.isFeatureEnabled("pro")).toBe(true);
    // No cadence to return to, and the file's own horizon is what bounds it.
    expect(state.revalidateAfter).toBeNull();
    expect(state.graceUntil).toBeGreaterThan(NOW());
    expect(talos.isActivated).toBe(true);
    expect(talos.currentMachineId).toBe("m-air-1");
  });

  it("survives a restart, and validate() answers from the file", async () => {
    const { talos, mpk, file, licenseKey, pubB64 } = requested();
    await talos.loadOfflineLicense(licenseFile(mint(licenseKey, "offline", offlineClaims(mpk))));

    // A fresh client over the same state: this is every launch after the first,
    // and it must not need the file again or a server that is not there.
    const restarted = client({ statePath: file, publicKey: pubB64 });
    expect(restarted.isActivated).toBe(true);
    const state = await restarted.validate();
    expect(state.decision).toBe("valid");
    expect(state.isOffline).toBe(true);
  });

  it("refuses a file cut for another machine's fingerprint", async () => {
    const { talos, mpk, licenseKey } = requested();
    const state = await talos.loadOfflineLicense(
      licenseFile(
        mint(licenseKey, "offline", offlineClaims(mpk, { fph: "fp2:some-other-machine" })),
      ),
    );
    // The fingerprint is what stops the whole state directory being copied to a
    // second computer, where the machine key would come along with it.
    expect(state.decision).toBe("machine_mismatch");
    expect(state.isValid).toBe(false);
  });

  it("refuses a file cut for another machine's key", async () => {
    const { talos, licenseKey } = requested();
    const somebodyElse = keypair().pubB64;
    const state = await talos.loadOfflineLicense(
      licenseFile(mint(licenseKey, "offline", offlineClaims(somebodyElse))),
    );
    // And the key is what stops the file alone being worth anything: a file
    // lifted off a colleague's laptop names a key this install cannot hold.
    expect(state.decision).toBe("machine_mismatch");
  });

  it("distinguishes the file running out from the licence running out", async () => {
    const { talos, mpk, licenseKey } = requested();
    const expired = await talos.loadOfflineLicense(
      licenseFile(mint(licenseKey, "offline", offlineClaims(mpk, { exp: NOW() - 1 }))),
    );
    expect(expired.decision).toBe("offline_file_expired");

    const { talos: other, mpk: mpk2, licenseKey: key2 } = requested();
    const ended = await other.loadOfflineLicense(
      licenseFile(
        mint(
          key2,
          "offline",
          offlineClaims(mpk2, { lic: { features: {}, lic_exp: NOW() - 1 } }),
        ),
      ),
    );
    // Same symptom for the user, different remedy: a new file versus a renewal.
    expect(ended.decision).toBe("expired");
    expect(ended.licenseExpiresAt).toBeLessThan(NOW());
  });

  it("refuses to outlive its expiry by winding the clock back", async () => {
    const { talos, mpk, licenseKey } = requested();
    // A file issued with a server time a week in the future: the only server
    // clock this install will ever see, and the mark it is held to.
    const state = await talos.loadOfflineLicense(
      licenseFile(
        mint(
          licenseKey,
          "offline",
          offlineClaims(mpk, { iat: NOW() + 7 * 86_400, server_time: NOW() + 7 * 86_400 }),
        ),
      ),
    );
    expect(state.decision).toBe("valid");

    // Now the clock is behind what we have already seen. Nothing has run out —
    // the machine is lying about the time, and saying so is different from
    // reporting a licence problem the user cannot act on.
    const again = await talos.validate();
    expect(again.decision).toBe("clock_tampered");
  });

  it("throws for a file that is not a licence, rather than returning a verdict", async () => {
    const { talos, mpk, pubB64 } = requested();
    const someoneElsesKey = keypair().privateKey;

    // A signature under a key this product does not use.
    await expect(
      talos.loadOfflineLicense(licenseFile(mint(someoneElsesKey, "offline", offlineClaims(mpk)))),
    ).rejects.toThrow(/signature/i);

    // Another product's file. Verdicts are about *this* licence; a file for a
    // different application is a mistake in what was copied, not a decision.
    const { licenseKey } = requested();
    void pubB64;
    await expect(
      talos.loadOfflineLicense(
        licenseFile(mint(licenseKey, "offline", offlineClaims(mpk, { aud: "tpt_another_app" }))),
      ),
    ).rejects.toThrow();

    // Not one of ours at all.
    const junk = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-junk-")), "license.talos");
    writeFileSync(junk, "not json");
    await expect(talos.loadOfflineLicense(junk)).rejects.toThrow(/offline licence file/);
  });

  it("hands the seat back, and drops the licence before the receipt exists", async () => {
    const { talos, mpk, file, licenseKey, pubB64 } = requested();
    await talos.loadOfflineLicense(licenseFile(mint(licenseKey, "offline", offlineClaims(mpk))));

    const receipt = talos.createOfflineDeactivation();
    expect(receipt.kind).toBe(RECEIPT_DOMAIN);
    const payload = requestPayload(receipt);
    expect(payload["fid"]).toBe("f-air-1");
    expect(payload["mid"]).toBe("m-air-1");
    expect(payload["fph"]).toBe(fingerprint);

    // Signed by the same key the file is bound to — which is the only reason a
    // server that has never spoken to this machine can believe it.
    const raw = Buffer.from(mpk, "base64");
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
    expect(
      cryptoVerify(
        null,
        Buffer.from(signedMessage(RECEIPT_DOMAIN, receipt.req), "ascii"),
        createPublicKey({ key: der, format: "der", type: "spki" }),
        b64urlDecode(receipt.sig),
      ),
    ).toBe(true);

    // The licence is gone here, not when the vendor gets round to the upload:
    // an application that writes the file, loses it, or never sends it has
    // still stopped using the seat it is giving up.
    expect(talos.isActivated).toBe(false);
    const restarted = client({ statePath: file, publicKey: pubB64 });
    expect(restarted.isActivated).toBe(false);
    await expect(restarted.validate()).rejects.toThrow(/not activated/);
  });

  it("refuses to write a receipt when there is no offline licence to hand back", async () => {
    const { talos } = requested();
    // A document saying otherwise would be a lie the vendor acts on: a seat
    // freed for an install that is still running.
    expect(() => talos.createOfflineDeactivation()).toThrow(/no offline licence/);
  });

  it("verifies against a keyset carried inside the file, with only the anchor pinned", async () => {
    // The load-bearing case for an air-gapped install: pinning the anchor is
    // what survives key rotation, and an anchor-only client has no licence key
    // at all until it fetches a keyset — from a server it cannot reach. So the
    // file brings one.
    const anchor = keypair();
    const signing = keypair();
    const file = statePath();
    const talos = client({ statePath: file, anchorPublicKey: anchor.pubB64 });
    const mpk = requestPayload(talos.createOfflineRequest())["machine_pubkey"] as string;

    const keyset = mint(anchor.privateKey, "keyset", {
      v: 1,
      typ: "keyset",
      aud: PRODUCT,
      iat: NOW() - 60,
      anchor_kid: "anchor1",
      keys: [{ kid: "k1", purpose: "license", pk: signing.pubB64, status: "active" }],
    });
    const state = await talos.loadOfflineLicense(
      licenseFile(mint(signing.privateKey, "offline", offlineClaims(mpk)), keyset),
    );
    expect(state.decision).toBe("valid");
  });
});
