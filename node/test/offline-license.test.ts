import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, createPublicKey, type KeyObject } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import { TalosClient, type FetchLike, type TalosOptions } from "../src/client.js";
import { collectFingerprint } from "../src/fingerprint.js";
import { StateStore, hashLicenseKey, stateKeyMaterial } from "../src/state.js";
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

function portableClaims(over: Record<string, unknown> = {}): Record<string, unknown> {
  const claims = offlineClaims("");
  delete claims["fph"];
  delete claims["mpk"];
  delete claims["mid"];
  return { ...claims, binding: "portable", perpetual: true, exp: null, ...over };
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

  it("keeps an explicitly perpetual file valid across decades and offline restarts", async () => {
    const fetch = vi.fn(deadNetwork);
    const { talos, mpk, file, licenseKey, pubB64 } = requested({ fetch });
    const state = await talos.loadOfflineLicense(licenseFile(mint(
      licenseKey, "offline", offlineClaims(mpk, { exp: null, perpetual: true }),
    )));
    expect(state.isValid).toBe(true);
    expect(state.graceUntil).toBeNull();
    expect(state.licenseExpiresAt).toBeNull();
    const future = Date.now() + 80 * 365 * 86_400_000;
    const clock = vi.spyOn(Date, "now").mockReturnValue(future);
    try {
      const restarted = client({ statePath: file, publicKey: pubB64, fetch });
      const verdict = await restarted.validate();
      expect(verdict.isValid).toBe(true);
      expect(verdict.isOffline).toBe(true);
      expect(verdict.isFeatureEnabled("pro")).toBe(true);
      expect(verdict.graceUntil).toBeNull();
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      clock.mockRestore();
    }
  });

  it("imports the same portable file on different machines without requests or network", async () => {
    const signing = keypair();
    const anchor = keypair();
    const keyset = mint(anchor.privateKey, "keyset", {
      aud: PRODUCT, iat: NOW() - 60,
      keys: [{ kid: "k1", purpose: "license", pk: signing.pubB64, status: "active" }],
    });
    const file = licenseFile(mint(signing.privateKey, "offline", portableClaims()), keyset);
    const fetch = vi.fn(deadNetwork);
    for (const machine_guid of ["portable-pc-a", "portable-pc-b"]) {
      const options = {
        statePath: statePath(), anchorPublicKey: anchor.pubB64, fetch,
        fingerprintComponents: { machine_guid },
      };
      const talos = client(options);
      expect(talos.isActivated).toBe(false);
      const state = await talos.loadOfflineLicense(file);
      expect(state.isValid && state.isOffline).toBe(true);
      expect(state.graceUntil).toBeNull();
      expect(talos.currentMachineId).toBeNull();
      expect(() => talos.createOfflineDeactivation()).toThrow(/portable.*no bound seat/);
      expect(talos.isActivated).toBe(true);
      const restarted = client(options);
      expect((await restarted.validate()).isValid).toBe(true);
      expect(restarted.isFeatureEnabled("pro")).toBe(true);
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(["portable", "machine"])("switches an existing online activation to a valid %s file", async (binding) => {
    const signing = keypair();
    const path = statePath();
    const fp = collectFingerprint(PRODUCT);
    const store = new StateStore(path, PRODUCT, stateKeyMaterial(fp));
    store.save({
      licenseKeyHash: hashLicenseKey("old-online-key"), activationSecret: "old-online-secret",
      machineId: "old-online-machine", fingerprint: fp.composite, validation: "old-online-cache",
      releaseSeqHighWater: 7,
    });
    const fetch = vi.fn(deadNetwork);
    const options = { statePath: path, publicKey: signing.pubB64, fetch };
    const talos = client(options);
    const claims = binding === "portable" ? portableClaims() : offlineClaims(
      requestPayload(talos.createOfflineRequest())["machine_pubkey"] as string,
      { binding: "machine" },
    );
    expect((await talos.loadOfflineLicense(licenseFile(mint(signing.privateKey, "offline", claims)))).isValid).toBe(true);
    expect((await talos.validate()).isValid).toBe(true);
    expect((await client(options).validate()).isValid).toBe(true);
    const saved = store.load()!;
    expect(saved.activationSecret).toBe("");
    expect(saved.licenseKeyHash).toBe("");
    expect(saved.validation).toBeUndefined();
    expect(saved.releaseSeqHighWater).toBe(7);
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    { binding: undefined }, { binding: "unknown" }, { binding: null },
    { perpetual: undefined }, { perpetual: false }, { perpetual: "true" },
    { exp: undefined }, { exp: "never" }, { exp: NOW() + 86_400 },
    { lic: { features: {}, lic_exp: NOW() + 86_400 } },
    { lic: { features: {} } },
    { fph: null }, { mpk: null }, { mid: null },
    { fid: undefined }, { fid: " " }, { sub: undefined }, { sub: "" },
    { decision: undefined }, { decision: "revoked" },
  ])("rejects malformed portable grants without erasing an online activation: %j", async (over) => {
    const signing = keypair();
    const path = statePath();
    const fp = collectFingerprint(PRODUCT);
    const store = new StateStore(path, PRODUCT, stateKeyMaterial(fp));
    store.save({
      licenseKeyHash: hashLicenseKey("old-online-key"), activationSecret: "old-online-secret",
      machineId: "old-online-machine", fingerprint: fp.composite, validation: "old-online-cache",
    });
    const talos = client({ statePath: path, publicKey: signing.pubB64 });
    const state = await talos.loadOfflineLicense(licenseFile(mint(
      signing.privateKey, "offline", portableClaims(over),
    )));
    expect(state.isValid).toBe(false);
    expect(store.load()?.activationSecret).toBe("old-online-secret");
    expect(store.load()?.validation).toBe("old-online-cache");
    expect(client({ statePath: path, publicKey: signing.pubB64 }).currentMachineId).toBe("old-online-machine");
  });

  it("verifies signature and product before accepting portable binding", async () => {
    const signing = keypair();
    const talos = client({ statePath: statePath(), publicKey: signing.pubB64 });
    const original = mint(signing.privateKey, "offline", offlineClaims("machine-key"));
    const parts = original.split(".");
    parts[3] = b64url(Buffer.from(JSON.stringify(portableClaims())));
    await expect(talos.loadOfflineLicense(licenseFile(parts.join(".")))).rejects.toThrow(/signature/i);
    await expect(talos.loadOfflineLicense(licenseFile(mint(
      signing.privateKey, "offline", portableClaims({ aud: "another-product" }),
    )))).rejects.toThrow(/audience/i);
    expect(talos.isActivated).toBe(false);
  });

  it.each(["activate", "validate", "heartbeat"] as const)(
    "keeps an imported portable file when an older %s request completes",
    async (operation) => {
      for (const status of [200, 403]) {
        const signing = keypair();
        const file = statePath();
        const fp = collectFingerprint(PRODUCT);
        const store = new StateStore(file, PRODUCT, stateKeyMaterial(fp));
        store.save({ licenseKeyHash: hashLicenseKey("old"), activationSecret: "old-secret",
          machineId: "old-machine", fingerprint: fp.composite });
        let entered!: () => void;
        const started = new Promise<void>((resolve) => { entered = resolve; });
        let complete!: (response: Response) => void;
        let nonce: unknown;
        const fetch: FetchLike = async (_url, init) => {
          nonce = JSON.parse(String(init?.body))["nonce"];
          entered();
          return new Promise<Response>((resolve) => { complete = resolve; });
        };
        const options = { statePath: file, publicKey: signing.pubB64, fetch };
        const talos = client(options);
        const pending = operation === "activate" ? talos.activate("new-online-key")
          : operation === "validate" ? talos.validate() : talos.heartbeat();
        await started;
        const portable = licenseFile(mint(signing.privateKey, "offline", portableClaims()));
        expect((await talos.loadOfflineLicense(portable)).isValid).toBe(true);
        const typ = operation === "activate" ? "activation" : operation === "validate" ? "validation" : "heartbeat";
        const response = status === 403 ? { error: "license_revoked" } : {
          [`${typ}_token`]: mint(signing.privateKey, typ, {
            aud: PRODUCT, non: nonce, iat: NOW(), nbf: NOW() - 5, exp: NOW() + 600,
            decision: "revoked", server_time: NOW(), lic: { features: {}, lic_exp: null },
          }), activation_secret: "stale-online-secret", machine_id: "stale-machine",
        };
        complete(new Response(JSON.stringify(response), { status }));
        expect(await pending).toMatchObject({ decision: "valid", isOffline: true });
        expect(talos.current).toMatchObject({ decision: "valid", isOffline: true });
        expect(store.load()?.activationSecret).toBe("");
        expect((await client({ ...options, fetch: deadNetwork }).validate()).isValid).toBe(true);
      }
    },
  );

  it("does not restore a revoked signing key from an older embedded keyset", async () => {
    const anchor = keypair(), old = keypair(), current = keypair();
    const keyset = (signing: typeof old, iat: number): string => mint(anchor.privateKey, "keyset", {
      aud: PRODUCT, iat, keys: [{ purpose: "license", pk: signing.pubB64 }],
    });
    const file = statePath();
    const fp = collectFingerprint(PRODUCT);
    const store = new StateStore(file, PRODUCT, stateKeyMaterial(fp));
    const issuedAt = NOW();
    const currentKeyset = keyset(current, issuedAt);
    store.save({ activationSecret: "online-secret", licenseKeyHash: "old", machineId: "old",
      fingerprint: fp.composite, keyset: currentKeyset });
    const talos = client({ statePath: file, anchorPublicKey: anchor.pubB64 });
    for (const replayedAt of [issuedAt - 1, issuedAt]) {
      await expect(talos.loadOfflineLicense(licenseFile(
        mint(old.privateKey, "offline", portableClaims()), keyset(old, replayedAt),
      ))).rejects.toThrow(/signature/i);
    }
    expect(store.load()?.keyset).toBe(currentKeyset);
    expect((await talos.loadOfflineLicense(licenseFile(
      mint(current.privateKey, "offline", portableClaims()),
    ))).isValid).toBe(true);
    expect(store.load()?.keyset).toBe(currentKeyset);
  });

  it("rolls back an embedded keyset when its offline file is rejected", async () => {
    const anchor = keypair(), current = keypair(), candidate = keypair();
    const keyset = (signing: typeof current, iat: number): string => mint(anchor.privateKey, "keyset", {
      aud: PRODUCT, iat, keys: [{ purpose: "license", pk: signing.pubB64 }],
    });
    const file = statePath();
    const fp = collectFingerprint(PRODUCT);
    const store = new StateStore(file, PRODUCT, stateKeyMaterial(fp));
    const currentKeyset = keyset(current, NOW() - 60);
    store.save({ activationSecret: "online-secret", licenseKeyHash: "old", machineId: "old",
      fingerprint: fp.composite, keyset: currentKeyset });
    const talos = client({ statePath: file, anchorPublicKey: anchor.pubB64 });
    expect((await talos.loadOfflineLicense(licenseFile(
      mint(candidate.privateKey, "offline", portableClaims({ decision: "revoked" })), keyset(candidate, NOW()),
    ))).isValid).toBe(false);
    expect(store.load()?.activationSecret).toBe("online-secret");
    expect((await talos.loadOfflineLicense(licenseFile(
      mint(current.privateKey, "offline", portableClaims()),
    ))).isValid).toBe(true);
    expect(store.load()?.keyset).toBe(currentKeyset);
  });

  it("ignores an older in-flight refresh even when its response has a later keyset", async () => {
    const anchor = keypair(), online = keypair(), portable = keypair(), later = keypair();
    const keyset = (signing: typeof online, iat: number): string => mint(anchor.privateKey, "keyset", {
      aud: PRODUCT, iat, keys: [{ purpose: "license", pk: signing.pubB64 }],
    });
    const file = statePath(), issuedAt = NOW();
    const fp = collectFingerprint(PRODUCT);
    const store = new StateStore(file, PRODUCT, stateKeyMaterial(fp));
    store.save({ activationSecret: "online-secret", licenseKeyHash: "old", machineId: "old",
      fingerprint: fp.composite, keyset: keyset(online, issuedAt - 60) });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    let complete!: (response: Response) => void;
    const fetch: FetchLike = async () => { entered(); return new Promise<Response>((resolve) => { complete = resolve; }); };
    const options = { statePath: file, anchorPublicKey: anchor.pubB64, fetch };
    const talos = client(options);
    const pending = talos.refreshKeyset();
    await started;
    const portableKeyset = keyset(portable, issuedAt);
    expect((await talos.loadOfflineLicense(licenseFile(
      mint(portable.privateKey, "offline", portableClaims()), portableKeyset,
    ))).isValid).toBe(true);
    complete(new Response(JSON.stringify({ keyset: keyset(later, issuedAt + 60) }), { status: 200 }));
    await pending;
    expect((await talos.validate()).isValid).toBe(true);
    expect(store.load()?.keyset).toBe(portableKeyset);
    expect((await client({ ...options, fetch: deadNetwork }).validate()).isValid).toBe(true);
  });

  it.each([
    { exp: null },
    { exp: undefined, perpetual: true },
    { exp: "never", perpetual: true },
    { exp: null, perpetual: "true" },
    { exp: null, perpetual: true, lic: { features: {}, lic_exp: NOW() + 86_400 } },
    { exp: null, perpetual: true, lic: { features: {} } },
    { exp: NOW() - 1, perpetual: true },
  ])("fails closed for an invalid perpetual file: %j", async (over) => {
    const { talos, mpk, licenseKey } = requested();
    const state = await talos.loadOfflineLicense(licenseFile(mint(
      licenseKey, "offline", offlineClaims(mpk, over),
    )));
    expect(state.decision).toBe("offline_file_expired");
    expect(state.isValid).toBe(false);
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
