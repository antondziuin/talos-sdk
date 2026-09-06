import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { TalosClient, type FetchLike, type FetchResponseLike } from "../src/client.js";
import { collectFingerprint } from "../src/fingerprint.js";
import { StateStore, stateKeyMaterial, hashLicenseKey } from "../src/state.js";

const LICENSE_KEY_HASH = hashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");

/**
 * The anti-downgrade high-water mark, which `docs/SECURITY.md` described for
 * some time before it existed.
 *
 * The rule it states is that yanking a release, or lowering its rollout share,
 * stops the release being *offered* and does not recall it from installs that
 * already applied it — because the SDK will not walk backwards. All of that
 * rested on `currentReleaseSeq`, a number the host had to compute and pass on
 * every call. No example passed it, the SDK stored nothing, and so a client
 * that had installed 1.1.0 and then saw a server offering 1.0.0 — a rollback,
 * a stale replica, or somebody in the middle — took it as an update.
 *
 * The mark has to survive the process to mean anything, so these tests are
 * about what one client writes and the *next* one reads.
 */

const PRODUCT = "tpt_antidowngrade";
const PLATFORM =
  ({ win32: "windows", darwin: "macos", linux: "linux" } as Record<string, string>)[
    os.platform() as string
  ] ?? os.platform();
const ARCH = os.arch();

const BUILD = Buffer.from("the bytes of the build");
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

function keypair(): { pubB64: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { pubB64: der.subarray(der.length - 32).toString("base64"), privateKey };
}

const b64url = (buf: Buffer) =>
  buf.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

function mint(privateKey: KeyObject, typ: string, payload: unknown): string {
  const prefix = `talos.1.${typ}.` + b64url(Buffer.from(JSON.stringify(payload)));
  return prefix + "." + b64url(cryptoSign(null, Buffer.from(prefix, "ascii"), privateKey));
}

function manifest(signer: KeyObject, version: string, releaseSeq: number): string {
  return mint(signer, "manifest", {
    v: 1,
    typ: "manifest",
    aud: PRODUCT,
    version,
    release_seq: releaseSeq,
    mandatory: false,
    notes_url: null,
    artifacts: [
      {
        platform: PLATFORM,
        arch: ARCH,
        kind: "installer",
        filename: `app-${version}.exe`,
        size: BUILD.length,
        sha256: sha(BUILD),
      },
    ],
    deltas: [],
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
 * A server offering one release, and recording what the client claimed to be
 * running — the value the server-side check is made against, and the one that
 * was always `undefined`.
 */
function server(
  signer: KeyObject,
  version: string,
  releaseSeq: number,
  seen: { currentReleaseSeq?: unknown }[],
): FetchLike {
  return (url, init) => {
    const u = String(url);
    if (u.endsWith("/v1/client/updates/check")) {
      const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
      seen.push({ currentReleaseSeq: body["current_release_seq"] });
      return Promise.resolve(
        bytesResponse(
          Buffer.from(
            JSON.stringify({
              update_available: true,
              version,
              release_seq: releaseSeq,
              mandatory: false,
              manifest: manifest(signer, version, releaseSeq),
              artifacts: [
                {
                  platform: PLATFORM,
                  arch: ARCH,
                  kind: "installer",
                  artifact_id: "a1",
                  download_path: "/v1/client/updates/artifacts/a1",
                },
              ],
              deltas: [],
            }),
          ),
        ),
      );
    }
    return Promise.resolve(bytesResponse(BUILD));
  };
}

/** One machine's state file, reused across "restarts". */
function stateFile(): string {
  const file = path.join(mkdtempSync(path.join(os.tmpdir(), "talos-adg-")), "state.bin");
  const fp = collectFingerprint(PRODUCT);
  new StateStore(file, PRODUCT, stateKeyMaterial(fp)).save({
    licenseKeyHash: LICENSE_KEY_HASH,
    activationSecret: "secret",
    machineId: "m1",
    fingerprint: fp.composite,
  });
  return file;
}

function client(file: string, pubB64: string, fetchImpl: FetchLike, appVersion: string) {
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
  path.join(mkdtempSync(path.join(os.tmpdir(), "talos-adg-out-")), name);

describe("anti-downgrade high-water mark", () => {
  it("remembers what it installed, and refuses to go back to an older release", async () => {
    const { pubB64, privateKey } = keypair();
    const file = stateFile();
    const seen: { currentReleaseSeq?: unknown }[] = [];

    // 1.0.0 running, 1.1.0 offered. Nothing is stored yet, so the SDK claims
    // nothing — an install adopting the SDK mid-life must not have its first
    // update refused by a floor it invented.
    const a = client(file, pubB64, server(privateKey, "1.1.0", 42, seen), "1.0.0");
    const info = await a.checkForUpdate();
    expect(info!.releaseSeq).toBe(42);
    expect(seen[0]!.currentReleaseSeq).toBeUndefined();

    // Downloaded and verified. Still not installed: the host writes the bytes
    // somewhere and does its own thing with them, usually after a restart.
    await a.downloadUpdate(info!, tmpfile("app.exe"));

    // A second client on the same machine, still running 1.0.0 — a restart
    // where the update was fetched and not applied. The mark must not move, or
    // a download that was never installed would block the release that was.
    const notYet = client(file, pubB64, server(privateKey, "1.1.0", 42, seen), "1.0.0");
    expect((await notYet.checkForUpdate())!.releaseSeq).toBe(42);
    expect(seen[1]!.currentReleaseSeq).toBeUndefined();

    // Now the host is running 1.1.0: the download became an install, and the
    // SDK can tell because the version it was given matches the one it fetched.
    const rollback = server(privateKey, "1.0.0", 41, seen);
    const after = client(file, pubB64, rollback, "1.1.0");
    expect(await after.checkForUpdate()).toBeNull();
    expect(seen[2]!.currentReleaseSeq).toBe(42);

    // …and the same answer on the next start, from disk rather than from
    // anything this process happened to remember. This is the whole point: a
    // mark that dies with the process protects nothing, because the attack is a
    // server that offers an old build to an application that just started.
    const later = client(file, pubB64, rollback, "1.1.0");
    expect(await later.checkForUpdate()).toBeNull();
    expect(seen[3]!.currentReleaseSeq).toBe(42);
  });

  it("lets the host override the floor it cannot know about", async () => {
    const { pubB64, privateKey } = keypair();
    const seen: { currentReleaseSeq?: unknown }[] = [];
    const c = client(stateFile(), pubB64, server(privateKey, "1.1.0", 42, seen), "1.0.0");

    // A package manager installed 1.2.0 behind the SDK's back. The host knows;
    // the SDK cannot, and says so rather than offering the older build.
    expect(await c.checkForUpdate({ currentReleaseSeq: 50 })).toBeNull();
    expect(seen[0]!.currentReleaseSeq).toBe(50);
  });

  it("does not raise the floor on a download that failed verification", async () => {
    const { pubB64, privateKey } = keypair();
    const file = stateFile();
    const seen: { currentReleaseSeq?: unknown }[] = [];
    // The manifest names the real build; the download serves something else.
    const tampered: FetchLike = (url, init) => {
      const base = server(privateKey, "1.1.0", 42, seen);
      if (String(url).endsWith("/v1/client/updates/check")) return base(url, init);
      return Promise.resolve(bytesResponse(Buffer.from("not the build at all")));
    };
    const a = client(file, pubB64, tampered, "1.0.0");
    const info = (await a.checkForUpdate())!;
    await expect(a.downloadUpdate(info, tmpfile("app.exe"))).rejects.toThrow();

    // Even if the host then reports the version the tampered file claimed to
    // be, nothing was recorded — so the floor did not move past a good build.
    const next = client(file, pubB64, server(privateKey, "1.1.0", 42, seen), "1.1.0");
    expect((await next.checkForUpdate())!.releaseSeq).toBe(42);
  });
});
