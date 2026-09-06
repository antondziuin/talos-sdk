import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { TalosClient, type FetchLike, type LicenseState } from "../src/client.js";
import { collectFingerprint } from "../src/fingerprint.js";
import { StateStore, stateKeyMaterial, hashLicenseKey, type StoredBinding } from "../src/state.js";

/**
 * The licence events, which are about edges rather than levels.
 *
 * Everything here was already computable by the host: `startCheckIns` hands it
 * the verdict on every tick, and diffing consecutive verdicts is what tells
 * "grace has begun" from "grace is still on". But every host doing that
 * arithmetic writes the same bug — a warning re-raised every ten minutes for the
 * whole outage, or a banner that never comes down — so the bookkeeping belongs
 * in the SDK, once.
 *
 * So the assertions are about firing *once* on the way in, about the four
 * verdicts not being confused with one another, and about a listener being
 * unable to change the verdict it is being told about.
 */

const PRODUCT = "tpt_events_test";
const NOW = (): number => Math.floor(Date.now() / 1000);
const LICENSE_KEY_HASH = hashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");

function keypair(): { pubB64: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { pubB64: der.subarray(der.length - 32).toString("base64"), privateKey };
}

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function mint(privateKey: KeyObject, typ: string, payload: unknown): string {
  const prefix = `talos.1.${typ}.` + b64url(Buffer.from(JSON.stringify(payload)));
  return prefix + "." + b64url(cryptoSign(null, Buffer.from(prefix, "ascii"), privateKey));
}

const fingerprint = collectFingerprint(PRODUCT).composite;

function validationClaims(over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = NOW();
  return {
    aud: PRODUCT,
    typ: "validation",
    iat: now,
    nbf: now - 60,
    exp: now + 300,
    non: "whatever-the-request-echoed",
    decision: "valid",
    server_time: now,
    reval_after: now + 86_400,
    grace_until: now + 3600,
    fph: fingerprint,
    lic: { features: { pro: true }, lic_exp: null },
    ...over,
  };
}

/** A cached verdict on disk, as a previous run would have left it. */
function seed(
  privateKey: KeyObject,
  over: Record<string, unknown> = {},
  binding: Partial<StoredBinding> = {},
): string {
  const file = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-events-")), "state.bin");
  const fp = collectFingerprint(PRODUCT);
  new StateStore(file, PRODUCT, stateKeyMaterial(fp)).save({
    licenseKeyHash: LICENSE_KEY_HASH,
    activationSecret: "secret",
    machineId: "m1",
    fingerprint,
    // Stale as a fresh proof; that is what makes it a cache.
    validation: mint(privateKey, "validation", validationClaims({ exp: NOW() - 30, ...over })),
    timeHighWater: NOW() - 60,
    ...binding,
  });
  return file;
}

const deadNetwork: FetchLike = () => Promise.reject(new Error("ENOTFOUND"));

/**
 * A live server answering every validate with a signed decision, read afresh
 * each call so one client can be told two different things.
 */
function answering(privateKey: KeyObject, decision: () => string): FetchLike {
  return (_url, init) => {
    const sent = JSON.parse(String(init.body)) as { nonce: string };
    const token = mint(
      privateKey,
      "validation",
      validationClaims({ decision: decision(), non: sent.nonce }),
    );
    return Promise.resolve({
      status: 200,
      text: () => Promise.resolve(JSON.stringify({ validation_token: token })),
      arrayBuffer: () => Promise.reject(new Error("not a download")),
    });
  };
}

function client(pubB64: string, statePath: string, fetchImpl: FetchLike = deadNetwork): TalosClient {
  return new TalosClient({
    productToken: PRODUCT,
    publicKey: pubB64,
    serverUrl: "http://127.0.0.1:1",
    statePath,
    fetch: fetchImpl,
  });
}

describe("licence events", () => {
  it("announces grace once for an outage that lasts all day", async () => {
    const { pubB64, privateKey } = keypair();
    const c = client(pubB64, seed(privateKey));
    const started: LicenseState[] = [];
    const invalid: LicenseState[] = [];
    c.on("gracePeriodStarted", (s) => started.push(s));
    c.on("licenseInvalid", (s) => invalid.push(s));

    await c.validate();
    await c.validate();
    await c.validate();

    // Three check-ins on a dead network, one event. The level is still there
    // for anyone who wants it, on `current`.
    expect(started).toHaveLength(1);
    expect(started[0]!.isOffline).toBe(true);
    expect(started[0]!.isValid).toBe(true);
    expect(invalid).toEqual([]);
    expect(c.current!.isOffline).toBe(true);
  });

  it("tells the end of grace apart from the licence going bad", async () => {
    const { pubB64, privateKey } = keypair();
    const c = client(pubB64, seed(privateKey, { grace_until: NOW() - 1 }));
    const expired: LicenseState[] = [];
    const invalid: LicenseState[] = [];
    c.on("gracePeriodExpired", (s) => expired.push(s));
    c.on("licenseInvalid", (s) => invalid.push(s));

    await c.validate();
    await c.validate();

    // The licence is fine; what ran out is permission to keep believing a
    // cached answer. Reporting that as "your licence is invalid" sends the user
    // to support instead of to their network.
    expect(expired).toHaveLength(1);
    expect(expired[0]!.decision).toBe("grace_expired");
    expect(invalid).toEqual([]);
  });

  it("reports a clock that went backwards as its own thing", async () => {
    const { pubB64, privateKey } = keypair();
    // A high-water mark ahead of the local clock: the machine is lying about
    // the time, which is not a licence problem and must not be announced as one.
    const c = client(pubB64, seed(privateKey, {}, { timeHighWater: NOW() + 7 * 86_400 }));
    const tampered: LicenseState[] = [];
    const invalid: LicenseState[] = [];
    c.on("clockTamperDetected", (s) => tampered.push(s));
    c.on("licenseInvalid", (s) => invalid.push(s));

    await c.validate();
    await c.validate();

    expect(tampered).toHaveLength(1);
    expect(tampered[0]!.decision).toBe("clock_tampered");
    expect(invalid).toEqual([]);
  });

  it("raises invalid once per reason, and again when the reason changes", async () => {
    const { pubB64, privateKey } = keypair();
    let decision = "revoked";
    const c = client(pubB64, seed(privateKey), answering(privateKey, () => decision));
    const seen: string[] = [];
    const off = c.on("licenseInvalid", (s) => seen.push(s.decision));

    expect((await c.validate()).decision).toBe("revoked");
    await c.validate();

    // Same verdict twice is not a transition; a different one is, because "your
    // subscription lapsed" and "this machine was revoked" are different things
    // to put in front of a user.
    expect(seen).toEqual(["revoked"]);

    decision = "expired";
    await c.validate();
    expect(seen).toEqual(["revoked", "expired"]);

    // And the returned unsubscribe actually unsubscribes.
    off();
    decision = "suspended";
    await c.validate();
    expect(seen).toEqual(["revoked", "expired"]);
  });

  it("cannot have the verdict changed by a listener that throws", async () => {
    const { pubB64, privateKey } = keypair();
    const c = client(pubB64, seed(privateKey), answering(privateKey, () => "revoked"));
    c.on("licenseInvalid", () => {
      throw new Error("host bug");
    });

    // The events are emitted from inside `validate`, whose own catch treats a
    // throw as an unreachable server. Letting a listener's exception out would
    // turn a live "revoked" answer into offline grace: the licensing bypass
    // would be a bug in the host's UI code.
    const state = await c.validate();
    expect(state.decision).toBe("revoked");
    expect(state.isOffline).toBe(false);
  });
});
