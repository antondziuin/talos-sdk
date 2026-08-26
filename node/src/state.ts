import { createCipheriv, createDecipheriv, createHash, hkdfSync } from "node:crypto";
import { randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import os from "node:os";

import type { FingerprintData } from "./fingerprint.js";

/**
 * The machine binding the server hands back at activation, held across process
 * restarts.
 *
 * Without this the binding died with the process and every application start
 * had to call `activate` again — which burns a round trip the protocol was
 * designed to avoid, rotates the activation secret out from under any other
 * running copy, and (because `activate` is the one client route refused for a
 * suspended tenant) turns the platform owner's deliberately graduated
 * suspension into a hard kill switch for the developer's own paying users.
 */
export interface StoredBinding {
  licenseKey: string;
  activationSecret: string;
  machineId: string;
  /**
   * The fingerprint composite at activation time. Informational: it is *not*
   * required to match on restore, because a machine whose hardware drifted is
   * exactly the case the server's fuzzy matcher exists to resolve. Discarding
   * the binding here would re-activate the customer whose disk was replaced —
   * the support ticket the drift budget was built to prevent.
   */
  fingerprint: string;
}

const MAGIC = Buffer.from("TLS1");
const IV_LEN = 12;
const TAG_LEN = 16;
const SALT = Buffer.from("talos-state-v1");

/**
 * Where the binding lives, per product, following each OS's convention.
 *
 * The directory is named by a hash of the product token rather than the token
 * itself: it keeps the path filesystem-safe without assuming anything about the
 * token's alphabet, and two products never collide.
 */
export function defaultStatePath(productToken: string): string {
  const slot = createHash("sha256").update(productToken).digest("hex").slice(0, 16);
  const home = os.homedir();
  switch (os.platform()) {
    case "win32":
      return join(
        process.env["LOCALAPPDATA"] ?? join(home, "AppData", "Local"),
        "Talos",
        slot,
        "state.bin",
      );
    case "darwin":
      return join(home, "Library", "Application Support", "Talos", slot, "state.bin");
    default:
      return join(
        process.env["XDG_DATA_HOME"] ?? join(home, ".local", "share"),
        "talos",
        slot,
        "state.bin",
      );
  }
}

/**
 * Key material for the state file, chosen for **stability** rather than
 * strength: a hardware change must not lock the user out of their own stored
 * licence key. `machine_guid` and `smbios_uuid` survive component swaps;
 * `os_install` survives everything short of a reinstall, which invalidates the
 * other two anyway.
 *
 * These values are already HMAC'd per product by the fingerprint collector, so
 * nothing here reveals an identifier the server does not already hold.
 *
 * Where a host offers none of them the file is obfuscated rather than bound to
 * the machine, and that is the honest description. It matters less than it
 * sounds: the server resolves a machine by fingerprint and demands the
 * activation secret, so a state file copied to a different computer does not
 * validate there. This layer is tamper-evidence and resistance to casual
 * copying — never secrecy from someone who owns the machine.
 */
export function stateKeyMaterial(fp: FingerprintData): string {
  return (
    fp.components["machine_guid"] ??
    fp.components["smbios_uuid"] ??
    fp.components["os_install"] ??
    "talos-unbound"
  );
}

/** Reads and writes one product's machine binding. */
export class StateStore {
  private readonly key: Buffer;

  constructor(
    readonly path: string,
    private readonly productToken: string,
    keyMaterial: string,
  ) {
    this.key = Buffer.from(
      hkdfSync("sha256", Buffer.from(keyMaterial), SALT, Buffer.from(productToken), 32),
    );
  }

  /**
   * Load the binding, or null if there is none.
   *
   * Never throws. A state file that is missing, truncated, from another
   * product, written by a future version, or simply corrupt must degrade to
   * "not activated yet" — the app then activates again. Throwing here would
   * turn a damaged cache into a launch failure.
   */
  load(): StoredBinding | null {
    let raw: Buffer;
    try {
      raw = readFileSync(this.path);
    } catch {
      return null;
    }
    try {
      if (raw.length < MAGIC.length + IV_LEN + TAG_LEN) return null;
      if (!raw.subarray(0, MAGIC.length).equals(MAGIC)) return null;
      const iv = raw.subarray(MAGIC.length, MAGIC.length + IV_LEN);
      const tag = raw.subarray(MAGIC.length + IV_LEN, MAGIC.length + IV_LEN + TAG_LEN);
      const body = raw.subarray(MAGIC.length + IV_LEN + TAG_LEN);
      const d = createDecipheriv("aes-256-gcm", this.key, iv);
      // The product token is authenticated, not just stored: a file belonging
      // to another product cannot be silently adopted.
      d.setAAD(Buffer.from(this.productToken));
      d.setAuthTag(tag);
      const plain = Buffer.concat([d.update(body), d.final()]).toString("utf8");
      const o = JSON.parse(plain) as Record<string, unknown>;
      if (o["v"] !== 1) return null;
      const b: StoredBinding = {
        licenseKey: String(o["licenseKey"] ?? ""),
        activationSecret: String(o["activationSecret"] ?? ""),
        machineId: String(o["machineId"] ?? ""),
        fingerprint: String(o["fingerprint"] ?? ""),
      };
      return b.licenseKey && b.activationSecret ? b : null;
    } catch {
      return null;
    }
  }

  /**
   * Persist the binding. Best-effort by design: a read-only or full disk costs
   * the user a re-activation next launch, and must not fail the activation
   * that just succeeded.
   */
  save(b: StoredBinding): boolean {
    try {
      const plain = Buffer.from(JSON.stringify({ v: 1, ...b }), "utf8");
      const iv = randomBytes(IV_LEN);
      const c = createCipheriv("aes-256-gcm", this.key, iv);
      c.setAAD(Buffer.from(this.productToken));
      const body = Buffer.concat([c.update(plain), c.final()]);
      const out = Buffer.concat([MAGIC, iv, c.getAuthTag(), body]);

      mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
      // Write-then-rename: a crash mid-write leaves the previous binding
      // intact rather than a half file that reads as "never activated".
      const tmp = `${this.path}.tmp`;
      writeFileSync(tmp, out, { mode: 0o600 });
      try {
        chmodSync(tmp, 0o600); // no-op on Windows; explicit on POSIX umasks
      } catch {
        /* ignore */
      }
      renameSync(tmp, this.path);
      return true;
    } catch {
      return false;
    }
  }

  /** Forget the binding (deactivation). */
  clear(): void {
    try {
      rmSync(this.path, { force: true });
    } catch {
      /* ignore */
    }
  }
}
