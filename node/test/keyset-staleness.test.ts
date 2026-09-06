import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import { TalosClient, type FetchLike } from "../src/client.js";
import { collectFingerprint } from "../src/fingerprint.js";
import { StateStore, stateKeyMaterial, hashLicenseKey } from "../src/state.js";

const LICENSE_KEY_HASH = hashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");

/**
 * A cached keyset goes stale, and that is what makes revoking a key reach an
 * install.
 *
 * A revoked signing key is omitted from the keyset, so a client stops trusting
 * it only once it fetches a newer one. Two triggers, and both earn their place:
 *
 *  - **Once per process, when the adopted keyset came off disk.** Clock-free,
 *    and this codebase does not trust a client's clock anywhere else either.
 *  - **When the adopted keyset is older than a day.** The first trigger alone
 *    bounds propagation by "next restart", which is fine for a desktop app and
 *    no bound at all for the process this SDK is most often in: a service host
 *    or an Electron main that runs for weeks.
 *
 * Every assertion here goes through the public surface. The scenario is the real
 * one: the server answering is signing with the key whose private half leaked,
 * and the question is whether this client still accepts it.
 */

const PRODUCT = "tpt_stale_test";
const NOW = () => Math.floor(Date.now() / 1000);
const DAY = 24 * 60 * 60;

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

/** An anchor-signed keyset naming `keys`, stamped `iat`. */
function keysetToken(
  anchor: KeyObject,
  keys: Array<{ kid: string; pk: string }>,
  iat: number,
): string {
  return mint(anchor, "keyset", {
    v: 1,
    typ: "keyset",
    aud: PRODUCT,
    iat,
    keys: keys.map((k) => ({ kid: k.kid, purpose: "license", pk: k.pk, status: "active" })),
  });
}

/** A state file holding an activated binding and `keyset`, and its path. */
function seed(keyset: string): string {
  const file = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-stale-")), "state.bin");
  const fp = collectFingerprint(PRODUCT);
  new StateStore(file, PRODUCT, stateKeyMaterial(fp)).save({
    licenseKeyHash: LICENSE_KEY_HASH,
    activationSecret: "secret",
    machineId: "m1",
    fingerprint: fp.composite,
    keyset,
    timeHighWater: NOW() - 60,
  });
  return file;
}

/** A server that signs its verdict with `signer` and serves `keyset` on refresh. */
function server(
  signer: KeyObject,
  keyset: string | null,
  count: { fetches: number },
): FetchLike {
  return async (url, init) => {
    const u = String(url);
    if (u.endsWith("/v1/client/keyset")) {
      count.fetches += 1;
      if (keyset === null) throw new Error("offline");
      return new Response(JSON.stringify({ keyset }), { status: 200 });
    }
    if (u.endsWith("/v1/client/validate")) {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(
        JSON.stringify({
          validation_token: mint(signer, "validation", {
            v: 1,
            typ: "validation",
            aud: PRODUCT,
            non: body["nonce"],
            iat: NOW(),
            nbf: NOW() - 5,
            exp: NOW() + 600,
            server_time: NOW(),
            decision: "valid",
            lic: { features: {} },
          }),
        }),
        { status: 200 },
      );
    }
    return new Response("{}", { status: 404 });
  };
}

function client(anchorPublicKey: string, fetchImpl: FetchLike, keyset: string): TalosClient {
  return new TalosClient({
    productToken: PRODUCT,
    anchorPublicKey,
    serverUrl: "https://talos.test",
    fetch: fetchImpl,
    statePath: seed(keyset),
  });
}

describe("keyset staleness", () => {
  it("stops trusting a key once it leaves the keyset", async () => {
    const anchor = keypair();
    const leaked = keypair();
    const current = keypair();
    const both = [
      { kid: "kp_old", pk: leaked.pubB64 },
      { kid: "kp_new", pk: current.pubB64 },
    ];
    const cached = keysetToken(anchor.privateKey, both, NOW() - DAY - 60);

    // The control, which differs from the case below in exactly one way: the
    // server has not revoked anything. Same client, same cached keyset, same
    // signer — so the rejection below is attributable to the revocation and to
    // nothing else about this setup.
    const a = { fetches: 0 };
    const before = client(
      anchor.pubB64,
      server(leaked.privateKey, keysetToken(anchor.privateKey, both, NOW()), a),
      cached,
    );
    await expect(before.validate()).resolves.toMatchObject({ decision: "valid" });
    expect(a.fetches).toBe(1);

    // And now the same thing after the key was revoked in the portal: it is
    // simply absent from what the server serves, so the client no longer holds a
    // key that the leaked private half matches.
    const b = { fetches: 0 };
    const after = client(
      anchor.pubB64,
      server(
        leaked.privateKey,
        keysetToken(anchor.privateKey, [{ kid: "kp_new", pk: current.pubB64 }], NOW()),
        b,
      ),
      cached,
    );
    await expect(
      after.validate(),
      "a revoked key has to stop working without the application being reinstalled",
    ).rejects.toThrow();
    expect(b.fetches).toBe(1);
  });

  it("refetches once a day, and not once a call", async () => {
    // The trigger that matters for a long-running host, and the one the
    // once-per-process refresh hides: a service that started this morning has
    // already used its one refresh, so without a staleness bound a key revoked
    // at noon keeps working until somebody restarts it.
    //
    // The clock is moved rather than waited on. What is being tested is a
    // comparison against the keyset's own signed `iat`, so a fake clock exercises
    // exactly the real code path.
    const anchor = keypair();
    const current = keypair();
    const count = { fetches: 0 };
    let served = keysetToken(anchor.privateKey, [{ kid: "kp_new", pk: current.pubB64 }], NOW());
    const doFetch: FetchLike = async (url, init) =>
      server(current.privateKey, served, count)(url, init);
    const c = client(anchor.pubB64, doFetch, served);

    await c.validate();
    expect(count.fetches, "the first call refreshes what came off disk").toBe(1);
    await c.validate();
    await c.validate();
    expect(
      count.fetches,
      "and then it is a bound, not a poll: every install on earth hitting a public endpoint hourly, for a document that changes about once a year, is a self-inflicted load pattern",
    ).toBe(1);

    // A day later, in the same process.
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date((NOW() + DAY + 60) * 1000));
      served = keysetToken(anchor.privateKey, [{ kid: "kp_new", pk: current.pubB64 }], NOW());
      await c.validate();
      expect(
        count.fetches,
        "a process that has been up for a day must go and look again, or a revocation never reaches it",
      ).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the cached keys when the refresh cannot reach the server", async () => {
    // A network failure must not become a licensing failure. That is the rule
    // the whole grace design rests on, and the refresh path is a new place to
    // break it: a client that already holds keys it trusts must keep working.
    const anchor = keypair();
    const current = keypair();
    const count = { fetches: 0 };
    const c = client(
      anchor.pubB64,
      server(current.privateKey, null, count),
      keysetToken(anchor.privateKey, [{ kid: "kp_new", pk: current.pubB64 }], NOW() - DAY - 60),
    );
    await expect(c.validate()).resolves.toMatchObject({ decision: "valid" });
    expect(count.fetches, "it tried").toBe(1);
  });
});
