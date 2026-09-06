import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { StateStore, defaultStatePath, type StoredBinding, hashLicenseKey } from "../src/index.js";
import { statePathFor } from "../src/state.js";

const LICENSE_KEY_HASH = hashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");

const BINDING: StoredBinding = {
  licenseKeyHash: LICENSE_KEY_HASH,
  activationSecret: "s3cr3t-from-the-server",
  machineId: "01234567-89ab-cdef-0123-456789abcdef",
  fingerprint: "fp2:deadbeef",
};

function tmpFile(): string {
  return path.join(mkdtempSync(path.join(os.tmpdir(), "talos-state-")), "state.bin");
}

describe("state store", () => {
  it("round-trips a binding", () => {
    const p = tmpFile();
    const store = new StateStore(p, "tpt_one", "km");
    expect(store.load()).toBeNull();
    expect(store.save(BINDING)).toBe(true);
    expect(store.load()).toEqual(BINDING);
    store.clear();
    expect(store.load()).toBeNull();
  });

  it("does not write the licence key in the clear", () => {
    const p = tmpFile();
    new StateStore(p, "tpt_one", "km").save(BINDING);
    const raw = readFileSync(p).toString("latin1");
    // Two claims, and the second is newer and stronger. The file is encrypted,
    // so nothing appears in it as typed — but the key is no longer *in* it at
    // all, in any form: after activation the server resolves the licence from
    // the activation secret, so what used to be a plaintext credential on every
    // customer's disk is now a hash with one local use.
    expect(raw).not.toContain("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");
    expect(raw).not.toContain(BINDING.activationSecret);
    expect(JSON.stringify(BINDING)).not.toContain("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");
  });

  it("upgrades a file that still carries the key in it", () => {
    // The installed base. An older SDK wrote `licenseKey`; this one must keep
    // the seat — discarding the binding would charge every existing customer a
    // re-activation for a change made on their behalf — and must stop writing
    // the key at the next save, which is when the plaintext actually disappears.
    const p = tmpFile();
    const store = new StateStore(p, "tpt_one", "km");
    store.save({
      ...BINDING,
      licenseKeyHash: "",
      // The shape an older version persisted.
      licenseKey: "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
    } as StoredBinding & { licenseKey: string });

    const loaded = store.load();
    expect(loaded).not.toBeNull();
    expect(loaded!.licenseKeyHash).toBe(LICENSE_KEY_HASH);
    expect(loaded!.activationSecret).toBe(BINDING.activationSecret);

    store.save(loaded!);
    const again = store.load() as (StoredBinding & { licenseKey?: string }) | null;
    expect(again!.licenseKeyHash).toBe(LICENSE_KEY_HASH);
    expect(again).not.toHaveProperty("licenseKey");
  });

  it("refuses a file belonging to another product", () => {
    // The product token is authenticated as GCM associated data, so a state
    // file cannot be adopted by a different product on the same machine.
    const p = tmpFile();
    new StateStore(p, "tpt_one", "km").save(BINDING);
    expect(new StateStore(p, "tpt_two", "km").load()).toBeNull();
  });

  it("refuses a file from another machine", () => {
    const p = tmpFile();
    new StateStore(p, "tpt_one", "machine-a").save(BINDING);
    expect(new StateStore(p, "tpt_one", "machine-b").load()).toBeNull();
  });

  it("treats a corrupt or truncated file as no activation, never an error", () => {
    // A damaged cache must cost a re-activation, not a launch failure: this
    // runs in the constructor, before the app has shown anything to the user.
    const p = tmpFile();
    const store = new StateStore(p, "tpt_one", "km");
    store.save(BINDING);
    const good = readFileSync(p);

    writeFileSync(p, good.subarray(0, 8)); // truncated
    expect(store.load()).toBeNull();

    writeFileSync(p, Buffer.concat([Buffer.from("XXXX"), good.subarray(4)])); // bad magic
    expect(store.load()).toBeNull();

    const flipped = Buffer.from(good);
    flipped[flipped.length - 1] ^= 0xff; // tampered ciphertext → GCM tag fails
    writeFileSync(p, flipped);
    expect(store.load()).toBeNull();

    writeFileSync(p, Buffer.alloc(0));
    expect(store.load()).toBeNull();
  });

  /**
   * The layouts the C# SDK's `DefaultPathFor` has to agree with, pinned on both
   * sides. The same product on the same machine must not end up with two
   * bindings in two places because two SDKs read the platform differently —
   * which is exactly what happened, on macOS and on Linux, until the C# side
   * stopped asking .NET for "local application data" and started branching.
   */
  it("puts the file where each platform keeps user data", () => {
    // The slot is a hash prefix of the token; read it back rather than restate
    // it, since what is being asserted is the layout around it.
    const slot = path.basename(path.dirname(statePathFor("tpt_one", "linux", "/home/u", {})));

    expect(statePathFor("tpt_one", "win32", "C:\\Users\\u", {})).toBe(
      path.join("C:\\Users\\u", "AppData", "Local", "Talos", slot, "state.bin"),
    );
    expect(statePathFor("tpt_one", "darwin", "/Users/u", {})).toBe(
      path.join("/Users/u", "Library", "Application Support", "Talos", slot, "state.bin"),
    );
    expect(statePathFor("tpt_one", "linux", "/home/u", {})).toBe(
      path.join("/home/u", ".local", "share", "talos", slot, "state.bin"),
    );

    // The environment wins where the platform defines one.
    expect(statePathFor("tpt_one", "linux", "/home/u", { XDG_DATA_HOME: "/data" })).toBe(
      path.join("/data", "talos", slot, "state.bin"),
    );
    expect(statePathFor("tpt_one", "win32", "C:\\Users\\u", { LOCALAPPDATA: "D:\\local" })).toBe(
      path.join("D:\\local", "Talos", slot, "state.bin"),
    );
  });

  it("puts each product in its own slot under the OS user-data directory", () => {
    const a = defaultStatePath("tpt_one");
    const b = defaultStatePath("tpt_two");
    expect(a).not.toEqual(b);
    expect(a.endsWith("state.bin")).toBe(true);
    // The token itself must not appear in the path — the directory is named by
    // a hash of it, so nothing is assumed about its alphabet.
    expect(a).not.toContain("tpt_one");
  });
});
