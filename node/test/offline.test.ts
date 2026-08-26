import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { TalosClient, type FetchLike, type TalosOptions } from "../src/client.js";
import { TalosApiError } from "../src/errors.js";
import { collectFingerprint } from "../src/fingerprint.js";
import { StateStore, stateKeyMaterial, type StoredBinding } from "../src/state.js";

/**
 * The offline path, with no server at all.
 *
 * These assertions are the entire reason `offline_grace_hours` exists as a
 * policy knob, and until now nothing read it: every SDK call was a live round
 * trip that threw on a dead network, so a laptop on a plane lost the licensed
 * application immediately regardless of the configured tolerance.
 */

const PRODUCT = "tpt_offline_test";
const NOW = () => Math.floor(Date.now() / 1000);

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

/** A validation token as the server would have signed it. */
function validationClaims(over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = NOW();
  return {
    aud: PRODUCT,
    typ: "validation",
    iat: now - 60,
    nbf: now - 60,
    exp: now - 30, // deliberately already stale as a *fresh* proof
    non: "whatever-the-request-echoed",
    decision: "valid",
    server_time: now - 60,
    reval_after: now + 86_400,
    grace_until: now + 3600,
    fph: fingerprint,
    lic: { features: { pro: true }, lic_exp: null },
    ...over,
  };
}

function seed(
  privateKey: KeyObject,
  claims: Record<string, unknown>,
  over: Partial<StoredBinding> = {},
): string {
  const file = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-offline-")), "state.bin");
  const fp = collectFingerprint(PRODUCT);
  new StateStore(file, PRODUCT, stateKeyMaterial(fp)).save({
    licenseKey: "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
    activationSecret: "secret",
    machineId: "m1",
    fingerprint,
    validation: mint(privateKey, "validation", claims),
    timeHighWater: NOW() - 60,
    ...over,
  });
  return file;
}

/** A network that is simply not there. */
const deadNetwork: FetchLike = () => Promise.reject(new Error("ENOTFOUND"));

function client(pubB64: string, statePath: string, fetchImpl: FetchLike = deadNetwork): TalosClient {
  const opts: TalosOptions = {
    productToken: PRODUCT,
    publicKey: pubB64,
    serverUrl: "http://127.0.0.1:1",
    statePath,
    fetch: fetchImpl,
  };
  return new TalosClient(opts);
}

describe("offline grace", () => {
  it("honours a cached verdict while the network is down", async () => {
    const { pubB64, privateKey } = keypair();
    const state = await client(pubB64, seed(privateKey, validationClaims())).validate();
    expect(state.decision).toBe("valid");
    expect(state.isValid).toBe(true);
    expect(state.isOffline).toBe(true);
    expect(state.isFeatureEnabled("pro")).toBe(true);
    // The cadence the server signed is surfaced, so the app can schedule.
    expect(state.revalidateAfter).toBeGreaterThan(NOW());
    expect(state.graceUntil).toBeGreaterThan(NOW());
  });

  it("stops honouring it once the grace window closes", async () => {
    const { pubB64, privateKey } = keypair();
    const file = seed(privateKey, validationClaims({ grace_until: NOW() - 1 }));
    const state = await client(pubB64, file).validate();
    expect(state.decision).toBe("grace_expired");
    expect(state.isValid).toBe(false);
    expect(state.isOffline).toBe(true);
  });

  it("refuses to extend grace by winding the clock back", async () => {
    // The high-water mark is a server clock we have already seen, signed. A
    // local clock behind it is not a licence problem, it is a lie about the
    // time — and without this check moving the clock back would renew the
    // grace window indefinitely.
    const { pubB64, privateKey } = keypair();
    const file = seed(privateKey, validationClaims(), {
      timeHighWater: NOW() + 7 * 86_400,
    });
    const state = await client(pubB64, file).validate();
    expect(state.decision).toBe("clock_tampered");
    expect(state.isValid).toBe(false);
  });

  it("does not honour a cache issued for another machine", async () => {
    // Copying the state file to a second computer and pulling the network
    // cable is the cheapest possible attack on offline grace.
    const { pubB64, privateKey } = keypair();
    const file = seed(privateKey, validationClaims({ fph: "fp2:some-other-machine" }));
    await expect(client(pubB64, file).validate()).rejects.toThrow(/ENOTFOUND/);
  });

  it("does not honour a cache signed by the wrong key or edited on disk", async () => {
    const { privateKey } = keypair();
    const other = keypair();
    const file = seed(privateKey, validationClaims());
    // Verified under a key that did not sign it.
    await expect(client(other.pubB64, file).validate()).rejects.toThrow(/ENOTFOUND/);
  });

  it("does not let a cached verdict outlive the licence it was issued under", async () => {
    // Inside the grace window, but the subscription itself has since lapsed.
    // Grace covers an unreachable server, not an expired customer.
    const { pubB64, privateKey } = keypair();
    const file = seed(
      privateKey,
      validationClaims({ lic: { features: { pro: true }, lic_exp: NOW() - 10 } }),
    );
    const state = await client(pubB64, file).validate();
    expect(state.decision).toBe("expired");
    expect(state.isOffline).toBe(true);
  });

  it("never masks an answer from the server", async () => {
    // A status code is a verdict — "revoked", "no such machine", "tenant
    // suspended". Falling back to the cache would turn every negative answer
    // into hours of grace, which is the opposite of what grace is for.
    const { pubB64, privateKey } = keypair();
    const file = seed(privateKey, validationClaims());
    const answers: FetchLike = () =>
      Promise.resolve({
        status: 404,
        text: () => Promise.resolve(JSON.stringify({ error: "machine_not_found" })),
      });
    await expect(client(pubB64, file, answers).validate()).rejects.toBeInstanceOf(TalosApiError);
  });

  it("caches a live verdict, and the cache survives a restart", async () => {
    const { pubB64, privateKey } = keypair();
    // Start from a binding with no cached validation at all.
    const file = seed(privateKey, validationClaims(), { validation: undefined });

    // A server that echoes the nonce the client actually generated.
    const live: FetchLike = (_url, init) => {
      const sent = JSON.parse(init.body) as { nonce: string };
      const token = mint(
        privateKey,
        "validation",
        validationClaims({ non: sent.nonce, exp: NOW() + 600 }),
      );
      return Promise.resolve({
        status: 200,
        text: () => Promise.resolve(JSON.stringify({ validation_token: token })),
      });
    };

    const online = await client(pubB64, file, live).validate();
    expect(online.decision).toBe("valid");
    expect(online.isOffline).toBe(false);

    // Next launch, no network: the verdict just cached is honoured.
    const offline = await client(pubB64, file).validate();
    expect(offline.decision).toBe("valid");
    expect(offline.isOffline).toBe(true);
  });

  it("has nothing to fall back on before the first validation", async () => {
    const { pubB64, privateKey } = keypair();
    const file = seed(privateKey, validationClaims(), { validation: undefined });
    await expect(client(pubB64, file).validate()).rejects.toThrow(/ENOTFOUND/);
  });
});
