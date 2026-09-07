import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { TalosClient, type FetchLike, type FetchResponseLike } from "../src/client.js";
import { collectFingerprint } from "../src/fingerprint.js";
import { StateStore, stateKeyMaterial, hashLicenseKey } from "../src/state.js";

const LICENSE_KEY_HASH = hashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");

/**
 * `options.fetch` has to reach the artifact download too.
 *
 * It is documented as "the fetch implementation" and was wired into every
 * licensing call, while `downloadUpdate` reached for `globalThis.fetch`
 * directly. So a corporate proxy, a custom CA bundle, request logging or a test
 * double applied to activate/validate/heartbeat/update-check and was silently
 * bypassed by the one call that pulls a multi-megabyte binary over the network
 * a proxy exists to cross. On a runtime with no global fetch the failure is
 * worse than silent: every licensing call works, and only the download dies —
 * pointing the developer at the wrong thing entirely.
 */

const PRODUCT = "tpt_download_test";

function keypair(): { pubB64: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { pubB64: der.subarray(der.length - 32).toString("base64"), privateKey };
}

function seededClient(pubB64: string, fetchImpl: FetchLike): TalosClient {
  const file = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-dl-")), "state.bin");
  const fp = collectFingerprint(PRODUCT);
  new StateStore(file, PRODUCT, stateKeyMaterial(fp)).save({
    licenseKeyHash: LICENSE_KEY_HASH,
    activationSecret: "secret",
    machineId: "m1",
    fingerprint: fp.composite,
  });
  return new TalosClient({
    productToken: PRODUCT,
    publicKey: pubB64,
    serverUrl: "http://127.0.0.1:1",
    statePath: file,
    fetch: fetchImpl,
  });
}

function bytesResponse(body: Buffer): FetchResponseLike {
  return {
    status: 200,
    text: () => Promise.resolve(body.toString("utf8")),
    arrayBuffer: () => {
      const out = new ArrayBuffer(body.byteLength);
      new Uint8Array(out).set(body);
      return Promise.resolve(out);
    },
  };
}

/**
 * A body that arrives a few bytes at a time, the way a socket delivers one.
 *
 * `arrayBuffer` rejects: reaching for it means the whole body was pulled into
 * memory, which is the thing the streaming path exists to stop.
 */
function streamResponse(body: Buffer, chunk = 7): FetchResponseLike & { cancelled: () => boolean } {
  let pos = 0;
  let cancelled = false;
  return {
    status: 200,
    text: () => Promise.resolve(body.toString("utf8")),
    arrayBuffer: () => Promise.reject(new Error("the body should have been streamed")),
    body: {
      getReader: () => ({
        read: () => {
          if (pos >= body.length) return Promise.resolve({ done: true });
          const slice = body.subarray(pos, pos + chunk);
          pos += slice.length;
          return Promise.resolve({ done: false, value: new Uint8Array(slice) });
        },
        cancel: () => {
          cancelled = true;
          return Promise.resolve(undefined);
        },
      }),
    },
    cancelled: () => cancelled,
  };
}

describe("downloadUpdate", () => {
  const payload = Buffer.from("an installer, more or less");
  const sha256 = createHash("sha256").update(payload).digest("hex");

  function artifact(over: Record<string, unknown> = {}) {
    return {
      platform: "linux",
      arch: "x64",
      kind: "installer",
      filename: "app.bin",
      size: payload.length,
      sha256,
      downloadPath: "/v1/client/updates/artifacts/a1",
      ...over,
    };
  }

  const info = (a = artifact()) => ({
    version: "1.0.0",
    releaseSeq: 1,
    mandatory: false,
    notesUrl: null,
    artifacts: [a],
    deltas: [],
  });

  it("uses the injected fetch, not the global one", async () => {
    const { pubB64 } = keypair();
    const seen: string[] = [];
    const impl: FetchLike = (url) => {
      seen.push(url);
      return Promise.resolve(bytesResponse(payload));
    };
    const dest = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-dl-out-")), "app.bin");

    await seededClient(pubB64, impl).downloadUpdate(info(), dest, artifact());

    expect(seen).toEqual(["http://127.0.0.1:1/v1/client/updates/artifacts/a1"]);
    expect(readFileSync(dest)).toEqual(payload);
  });

  it("still refuses bytes that do not match the signed manifest", async () => {
    const { pubB64 } = keypair();
    const impl: FetchLike = () => Promise.resolve(bytesResponse(Buffer.from("something else")));
    const dest = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-dl-out-")), "app.bin");

    // The download host is untrusted by design — the hash comes from the
    // manifest the release key signed, and routing the call through a supplied
    // fetch must not become a way around that.
    await expect(
      seededClient(pubB64, impl).downloadUpdate(info(), dest, artifact()),
    ).rejects.toThrow(/hash mismatch/);
  });

  it("refuses a body larger than the manifest says", async () => {
    const { pubB64 } = keypair();
    const huge = Buffer.alloc(payload.length + 1, 7);
    const impl: FetchLike = () => Promise.resolve(bytesResponse(huge));
    const dest = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-dl-out-")), "app.bin");

    await expect(
      seededClient(pubB64, impl).downloadUpdate(info(), dest, artifact()),
    ).rejects.toThrow(/exceeds manifest size/);
  });

  /**
   * The download used to buffer the whole body, hash it, and only then write —
   * correct about the bytes and wrong about everything else. A two-gigabyte
   * installer asked the smallest machine in the field for two gigabytes of RAM,
   * and the host had nothing to show a user for the minutes it took: one
   * promise, no output, indistinguishable from a hang.
   */
  /**
   * A maintenance licence that has run out is not a licence that has failed.
   *
   * `validate` still says valid — the customer keeps the version they bought —
   * and only `/updates/check` refuses, with `updates_not_entitled`. An
   * application that treats that 403 as a licensing error locks a paying
   * customer out of software they own; one that treats it as "no update
   * available" never tells them their maintenance lapsed. Distinguishing it is
   * the point, so the code has to reach the caller.
   */
  it("says why updates were refused, not just that they were", async () => {
    const { pubB64 } = keypair();
    const impl: FetchLike = () =>
      Promise.resolve({
        status: 403,
        text: () => Promise.resolve(JSON.stringify({ error: "updates_not_entitled" })),
        arrayBuffer: () => Promise.reject(new Error("not a download")),
      });

    await expect(seededClient(pubB64, impl).checkForUpdate()).rejects.toMatchObject({
      statusCode: 403,
      errorCode: "updates_not_entitled",
    });
  });

  it("reports progress while the bytes are still arriving", async () => {
    const { pubB64 } = keypair();
    const res = streamResponse(payload);
    const dest = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-dl-out-")), "app.bin");

    const seen: { bytesReceived: number; totalBytes: number }[] = [];
    await seededClient(pubB64, () => Promise.resolve(res)).downloadUpdate(
      info(),
      dest,
      artifact(),
      (p) => seen.push({ ...p }),
    );

    // The point of the change: a report from part-way through. Reporting once
    // at the end satisfies "has an onProgress parameter" and gives a host
    // nothing to draw, so that is what is asserted rather than the count.
    expect(seen.some((p) => p.bytesReceived > 0 && p.bytesReceived < p.totalBytes)).toBe(true);
    // Totals are the signed manifest's; this response carries no content-length.
    expect(seen.every((p) => p.totalBytes === payload.length)).toBe(true);
    expect(seen.map((p) => p.bytesReceived)).toEqual(
      [...seen.map((p) => p.bytesReceived)].sort((a, b) => a - b),
    );
    expect(seen[seen.length - 1]).toEqual({
      bytesReceived: payload.length,
      totalBytes: payload.length,
    });
    expect(readFileSync(dest)).toEqual(payload);
  });

  it("leaves the destination alone when the bytes do not verify", async () => {
    const { pubB64 } = keypair();
    // Exactly as long as the real build, so what refuses it is the hash and not
    // the size cap.
    const wrong = Buffer.from("AN INSTALLER, MORE OR LESS");
    expect(wrong.length).toBe(payload.length);

    const dir = mkdtempSync(path.join(os.tmpdir(), "talos-dl-out-"));
    const dest = path.join(dir, "app.bin");
    const installed = Buffer.from("the build already installed here");
    writeFileSync(dest, installed);

    await expect(
      seededClient(pubB64, () => Promise.resolve(streamResponse(wrong))).downloadUpdate(
        info(),
        dest,
        artifact(),
      ),
    ).rejects.toThrow(/hash mismatch/);

    // Streaming to disk is what makes this worth asserting: the bytes were
    // written before anything vouched for them, and the only reason the host is
    // not now holding an unverified file at the path it is about to run is that
    // they went somewhere else first.
    expect(readFileSync(dest)).toEqual(installed);
    expect(readdirSync(dir)).toEqual(["app.bin"]);
  });

  it("stops reading and leaves nothing behind when the body runs past the manifest size", async () => {
    const { pubB64 } = keypair();
    const res = streamResponse(Buffer.concat([payload, Buffer.from(" and then some")]));
    const dir = mkdtempSync(path.join(os.tmpdir(), "talos-dl-out-"));

    await expect(
      seededClient(pubB64, () => Promise.resolve(res)).downloadUpdate(
        info(),
        path.join(dir, "app.bin"),
        artifact(),
      ),
    ).rejects.toThrow(/exceeds manifest size/);

    // The cap now fires with a part file open and partly written, and with more
    // body still coming that nobody wants.
    expect(res.cancelled()).toBe(true);
    expect(readdirSync(dir)).toEqual([]);
  });
});
