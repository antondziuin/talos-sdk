import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { StateStore, defaultStatePath, type StoredBinding } from "../src/index.js";

const BINDING: StoredBinding = {
  licenseKey: "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
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
    expect(raw).not.toContain(BINDING.licenseKey);
    expect(raw).not.toContain(BINDING.activationSecret);
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
