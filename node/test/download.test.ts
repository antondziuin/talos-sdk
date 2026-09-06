import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
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
});
