import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  TalosClient,
  verifyAppliedUpdate,
  type FetchLike,
  type FetchResponseLike,
  type UpdateDelta,
} from "../src/client.js";
import { collectFingerprint } from "../src/fingerprint.js";
import { StateStore, stateKeyMaterial, hashLicenseKey } from "../src/state.js";

const LICENSE_KEY_HASH = hashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");

/**
 * Patches, from the client's side.
 *
 * Two things have to hold and neither is obvious from the wire format alone.
 * A patch must never turn up among the full builds — `downloadUpdate` picks
 * "the artifact for this platform" and hands the file to the host, so a patch in
 * that list is a patch a host tries to run. And the chain of signatures has to
 * reach past the patch to the file it produces: verifying the patch's own bytes
 * says nothing about what comes out of the patcher, which is the thing that
 * actually gets executed.
 */

const PRODUCT = "tpt_delta_test";
// The host names the SDK matches artifacts by. Fixed rather than read from
// `os`, so the test asserts selection and not what machine it happens to run on.
const PLATFORM = { win32: "windows", darwin: "macos", linux: "linux" }[
  os.platform() as string
] ?? os.platform();
const ARCH = os.arch();

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

const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

/** The bytes of the release: one installer, one archive, and patches for both. */
const INSTALLER = Buffer.from("the whole installer, all of it");
const ARCHIVE = Buffer.from("the portable archive");
const PATCH_TO_INSTALLER = Buffer.from("just the diff");
const PATCH_TO_ARCHIVE = Buffer.from("a different diff");

/** A signed manifest for 1.1.0 carrying patches from 1.0.0. */
function manifest(signer: KeyObject): string {
  return mint(signer, "manifest", {
    v: 1,
    typ: "manifest",
    aud: PRODUCT,
    version: "1.1.0",
    release_seq: 42,
    mandatory: false,
    notes_url: null,
    artifacts: [
      {
        platform: PLATFORM,
        arch: ARCH,
        kind: "installer",
        filename: "app-1.1.0.exe",
        size: INSTALLER.length,
        sha256: sha(INSTALLER),
      },
      {
        platform: PLATFORM,
        arch: ARCH,
        kind: "archive",
        filename: "app-1.1.0.zip",
        size: ARCHIVE.length,
        sha256: sha(ARCHIVE),
      },
    ],
    deltas: [
      {
        platform: PLATFORM,
        arch: ARCH,
        from: "1.0.0",
        from_seq: 41,
        filename: "to-installer.patch",
        size: PATCH_TO_INSTALLER.length,
        sha256: sha(PATCH_TO_INSTALLER),
        target: {
          kind: "installer",
          filename: "app-1.1.0.exe",
          size: INSTALLER.length,
          sha256: sha(INSTALLER),
        },
      },
      {
        platform: PLATFORM,
        arch: ARCH,
        from: "1.0.0",
        from_seq: 41,
        filename: "to-archive.patch",
        size: PATCH_TO_ARCHIVE.length,
        sha256: sha(PATCH_TO_ARCHIVE),
        target: {
          kind: "archive",
          filename: "app-1.1.0.zip",
          size: ARCHIVE.length,
          sha256: sha(ARCHIVE),
        },
      },
    ],
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

function jsonResponse(body: unknown): FetchResponseLike {
  return bytesResponse(Buffer.from(JSON.stringify(body)));
}

/**
 * A server that answers the update check with the signed manifest plus the
 * transport routes, and serves each file from its own path.
 */
function server(signer: KeyObject, files: Record<string, Buffer>): FetchLike {
  return (url) => {
    const u = String(url);
    if (u.endsWith("/v1/client/updates/check")) {
      return Promise.resolve(
        jsonResponse({
          update_available: true,
          version: "1.1.0",
          release_seq: 42,
          mandatory: false,
          manifest: manifest(signer),
          artifacts: [
            {
              platform: PLATFORM,
              arch: ARCH,
              kind: "installer",
              artifact_id: "a1",
              download_path: "/v1/client/updates/artifacts/a1",
            },
            {
              platform: PLATFORM,
              arch: ARCH,
              kind: "archive",
              artifact_id: "a2",
              download_path: "/v1/client/updates/artifacts/a2",
            },
          ],
          deltas: [
            {
              platform: PLATFORM,
              arch: ARCH,
              from: "1.0.0",
              target_kind: "installer",
              artifact_id: "d1",
              download_path: "/v1/client/updates/artifacts/d1",
            },
            {
              platform: PLATFORM,
              arch: ARCH,
              from: "1.0.0",
              target_kind: "archive",
              artifact_id: "d2",
              download_path: "/v1/client/updates/artifacts/d2",
            },
          ],
        }),
      );
    }
    const id = u.split("/").pop()!;
    const body = files[id];
    if (!body) return Promise.resolve({ ...bytesResponse(Buffer.alloc(0)), status: 404 });
    return Promise.resolve(bytesResponse(body));
  };
}

function client(pubB64: string, fetchImpl: FetchLike, appVersion?: string): TalosClient {
  const file = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-delta-")), "state.bin");
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
    releasePublicKey: pubB64,
    serverUrl: "http://127.0.0.1:1",
    statePath: file,
    appVersion,
    fetch: fetchImpl,
  });
}

const tmpfile = (name: string) =>
  path.join(mkdtempSync(path.join(os.tmpdir(), "talos-delta-out-")), name);

const FILES = {
  a1: INSTALLER,
  a2: ARCHIVE,
  d1: PATCH_TO_INSTALLER,
  d2: PATCH_TO_ARCHIVE,
};

describe("delta updates", () => {
  it("keeps patches out of the list downloadUpdate picks from", async () => {
    const { pubB64, privateKey } = keypair();
    const info = await client(pubB64, server(privateKey, FILES), "1.0.0").checkForUpdate();

    expect(info).not.toBeNull();
    expect(info!.artifacts.map((a) => a.kind)).toEqual(["installer", "archive"]);
    expect(info!.artifacts.some((a) => a.kind === "delta")).toBe(false);
    expect(info!.deltas).toHaveLength(2);

    // The default pick is still a whole build. A patch here would be handed to
    // the host as if it were an installer, on machines already in the field.
    const dest = tmpfile("app.exe");
    const chosen = await client(pubB64, server(privateKey, FILES), "1.0.0").downloadUpdate(
      info!,
      dest,
    );
    expect(chosen.kind).toBe("installer");
  });

  it("matches a patch on the exact installed version, and nothing else", async () => {
    const { pubB64, privateKey } = keypair();
    const c = client(pubB64, server(privateKey, FILES), "1.0.0");
    const info = (await c.checkForUpdate())!;

    // Two patches from 1.0.0, one per shipped file. Which one is wanted is not
    // something the SDK can infer, so it refuses rather than downloading
    // megabytes to rebuild the file the host was not updating.
    expect(c.selectDelta(info)).toBeNull();
    expect(c.selectDelta(info, { targetKind: "installer" })!.filename).toBe("to-installer.patch");
    expect(c.selectDelta(info, { targetKind: "archive" })!.filename).toBe("to-archive.patch");

    // A version this release ships no patch from gets the full build instead.
    // Deliberately *not* "the nearest older version": a patch applies to the
    // bytes it was built against, and close enough produces a corrupt file
    // rather than an error.
    expect(c.selectDelta(info, { from: "1.0.1", targetKind: "installer" })).toBeNull();
    expect(c.selectDelta(info, { from: "0.9.0", targetKind: "installer" })).toBeNull();
  });

  it("verifies the patch on the way in, and the file it produces on the way out", async () => {
    const { pubB64, privateKey } = keypair();
    const c = client(pubB64, server(privateKey, FILES), "1.0.0");
    const info = (await c.checkForUpdate())!;

    const dest = tmpfile("to-installer.patch");
    const delta = await c.downloadDelta(info, dest, { targetKind: "installer" });
    expect(delta.from).toBe("1.0.0");
    expect(delta.target.sha256).toBe(sha(INSTALLER));
    expect(delta.target.sha256).not.toBe(delta.sha256);

    // Applying is the host's job. Whatever it produces is checked against the
    // manifest, which is the step that keeps the signature reaching the binary
    // that actually runs.
    const applied = tmpfile("app-1.1.0.exe");
    writeFileSync(applied, INSTALLER);
    await expect(verifyAppliedUpdate(applied, delta)).resolves.toBeUndefined();

    // A patcher that stopped halfway, applied to the wrong base, or wrote
    // somebody else's bytes: all of them land here.
    const wrong = tmpfile("half-applied.exe");
    writeFileSync(wrong, INSTALLER.subarray(0, INSTALLER.length - 1));
    await expect(verifyAppliedUpdate(wrong, delta)).rejects.toThrow(
      /does not match the signed manifest/,
    );
  });

  it("refuses patch bytes that do not match the signed manifest", async () => {
    const { pubB64, privateKey } = keypair();
    // Exactly as long as the real patch, so what refuses it is the hash and not
    // the size cap — which would leave the hash check itself unexercised.
    const tampered = { ...FILES, d1: Buffer.from("JUST THE DIFF") };
    expect(tampered.d1.length).toBe(PATCH_TO_INSTALLER.length);
    const c = client(pubB64, server(privateKey, tampered), "1.0.0");
    const info = (await c.checkForUpdate())!;

    // The download route is untrusted exactly like a full artifact's, and a
    // patch is the more attractive thing to swap: it is small, and its output
    // is executable.
    await expect(
      c.downloadDelta(info, tmpfile("bad.patch"), { targetKind: "installer" }),
    ).rejects.toThrow(/hash mismatch/);
  });

  it("has nothing to offer an install whose version was never published", async () => {
    const { pubB64, privateKey } = keypair();
    const c = client(pubB64, server(privateKey, FILES), "0.1.0");
    const info = (await c.checkForUpdate())!;

    expect(c.selectDelta(info, { targetKind: "installer" })).toBeNull();
    await expect(
      c.downloadDelta(info, tmpfile("none.patch"), { targetKind: "installer" }),
    ).rejects.toThrow(/no patch applies/);
  });

  it("reads a manifest with no deltas as one with no deltas", async () => {
    const { pubB64, privateKey } = keypair();
    // Every release published before patches existed looks like this, and there
    // are installs out there that will be offered one.
    const plain: FetchLike = (url) => {
      const u = String(url);
      if (!u.endsWith("/v1/client/updates/check")) return Promise.resolve(bytesResponse(INSTALLER));
      return Promise.resolve(
        jsonResponse({
          update_available: true,
          manifest: mint(privateKey, "manifest", {
            v: 1,
            typ: "manifest",
            aud: PRODUCT,
            version: "1.1.0",
            release_seq: 42,
            artifacts: [
              {
                platform: PLATFORM,
                arch: ARCH,
                kind: "installer",
                filename: "app.exe",
                size: INSTALLER.length,
                sha256: sha(INSTALLER),
              },
            ],
          }),
          artifacts: [],
        }),
      );
    };
    const c = client(pubB64, plain, "1.0.0");
    const info = (await c.checkForUpdate())!;
    expect(info.deltas).toEqual([]);
    expect(c.selectDelta(info)).toBeNull();
  });
});

/** Typed shorthand so a hand-built patch in a test still has to be complete. */
export type _Delta = UpdateDelta;
