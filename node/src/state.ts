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
  /**
   * SHA-256 of the licence key as it was typed, hex — **not** the key.
   *
   * The key itself used to live here, so that the next call could send it. It
   * no longer has to: the server resolves a licence from the activation secret,
   * which is the credential these calls authenticate with anyway. What was left
   * was a plaintext licence key in a file on every customer's machine, which is
   * a credential-shaped file and exactly what an infostealer collects.
   *
   * A hash is kept because one thing still needs it: `activate()` called twice
   * with the same key must validate rather than spend a second seat, and that
   * comparison is all the stored value was ever used for. The hash cannot be
   * replayed to the server — the server matches an HMAC under its own pepper —
   * so this is a value with exactly one use and no resale.
   *
   * Hashed as typed, without normalising, because the comparison it replaces
   * was a string equality on the same input: normalising here would change when
   * a re-activation is avoided, which is not what this change is about.
   */
  licenseKeyHash: string;
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
  /**
   * The last anchor-signed keyset token.
   *
   * Cached because an anchor-only client — the pinning that survives key
   * rotation — otherwise has no verification key at all until it can reach the
   * server, which is exactly the situation the offline path exists for. The
   * anchor is compiled into the app, the keyset is signed by it, and the
   * validation token is signed by a key it lists: the whole chain verifies
   * offline against a root the network cannot influence.
   */
  keyset?: string;
  /** The last verified `typ=validation` token — the offline verdict. */
  validation?: string;
  /**
   * The highest server clock ever seen, in unix seconds, taken from a signed
   * claim.
   *
   * This is what makes offline grace bounded. Grace is evaluated against the
   * local clock, which the user controls; with no mark that only moves forward,
   * winding the clock back would renew a 72-hour window indefinitely. A
   * monotonic timer is not a substitute — it resets on reboot and on a VM
   * snapshot restore, which is the case that matters.
   */
  timeHighWater?: number;
  /**
   * The highest `release_seq` this install is known to be running, and the
   * floor `checkForUpdate` refuses to go below.
   *
   * Anti-downgrade only works against a mark that outlives the process, and
   * until this existed there was none: the floor came entirely from
   * `currentReleaseSeq`, which the host had to compute and pass, and which no
   * example passed. `docs/SECURITY.md` described a high-water mark that did not
   * exist, so "yanking a release does not recall it from installs that already
   * applied it" rested on the host having implemented the mark itself.
   */
  releaseSeqHighWater?: number;
  /**
   * A release whose bytes were downloaded and verified but which is not
   * running yet: the version string from its signed manifest, and its
   * `release_seq`.
   *
   * The SDK downloads; the host installs, in its own way, on its own schedule,
   * usually after a restart. So "installed" is not an event the SDK can see —
   * but the *result* is, because the host tells it which version it is on every
   * time a client is constructed. When `appVersion` matches what was downloaded,
   * the download became an install and the mark advances.
   *
   * The alternative was a `markInstalled()` for the host to call, and the whole
   * defect here is a mark that depended on the host doing something nobody
   * documented and no example did.
   */
  pendingRelease?: { version: string; releaseSeq: number };
  /**
   * This machine's own Ed25519 private key (PKCS#8 DER, base64), generated at
   * its first offline request.
   *
   * The air-gapped counterpart of `activationSecret`, and it exists for the same
   * reason that one does: an install has to be able to prove it is the install a
   * decision was made for. It never leaves this file — only the public half
   * travels, inside `talos-request.json` — and losing the file means repeating
   * the ceremony with the vendor, because the identity has exactly one copy by
   * construction.
   */
  machineKey?: string;
  /** The raw public half, standard base64. Checked against the file's `mpk`. */
  machinePublicKey?: string;
  /** The last verified `typ=offline` licence file. */
  offlineToken?: string;
  /**
   * The highest local clock ever seen while running on an offline file, in unix
   * seconds.
   *
   * Deliberately separate from {@link timeHighWater}, which holds *server*
   * times taken from signed claims. An air-gapped install sees exactly one
   * server time in its life — the `iat` of its file — so the server mark stops
   * moving, and nothing would notice a clock wound back to the day after
   * issuance to keep a year-long file alive forever.
   *
   * Mixing the two would be worse than useless: a machine whose clock ran fast
   * would inflate the server mark, and correcting the clock afterwards would
   * then read as tampering on an install that had done nothing wrong.
   *
   * What this bounds is **rollback, not freeze**. A user who stops their clock
   * keeps a file past its expiry; a user who winds it back is told
   * `clock_tampered`. That is the honest limit of enforcing a deadline against
   * a clock its owner controls, and it is the price of offline.
   */
  offlineSeen?: number;
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
  return statePathFor(productToken, os.platform(), os.homedir(), process.env);
}

/**
 * The path, from a host described rather than asked — so the layout on all three
 * platforms is testable from any one of them, and the C# SDK has something to
 * agree with. (Its `DefaultPathFor` is the same three branches; the same product
 * on the same machine must not have two bindings in two places.)
 *
 * Not exported from the package: this exists for the tests on both sides.
 */
export function statePathFor(
  productToken: string,
  platform: string,
  home: string,
  env: Record<string, string | undefined>,
): string {
  const slot = createHash("sha256").update(productToken).digest("hex").slice(0, 16);
  switch (platform) {
    case "win32":
      return join(env["LOCALAPPDATA"] || join(home, "AppData", "Local"), "Talos", slot, "state.bin");
    case "darwin":
      return join(home, "Library", "Application Support", "Talos", slot, "state.bin");
    default:
      // Lower-case, unlike the other two: this is the directory a Linux user's
      // other applications keep company with.
      return join(env["XDG_DATA_HOME"] || join(home, ".local", "share"), "talos", slot, "state.bin");
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

/**
 * SHA-256 of a licence key, hex.
 *
 * Used only to recognise "the same key as last time" without keeping the key.
 * Not a credential and not accepted by anything: the server matches an HMAC
 * computed under a pepper this process has never seen.
 */
export function hashLicenseKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
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
      // An older file carries `licenseKey` in the clear. Upgrade it in place
      // rather than discarding the binding: the customer keeps their seat, and
      // the plaintext key stops existing on disk at the next save — which is
      // the point of the change, and it must not cost anybody a re-activation
      // to get.
      const legacyKey = typeof o["licenseKey"] === "string" ? o["licenseKey"] : "";
      const b: StoredBinding = {
        licenseKeyHash:
          typeof o["licenseKeyHash"] === "string" && o["licenseKeyHash"]
            ? o["licenseKeyHash"]
            : legacyKey
              ? hashLicenseKey(legacyKey)
              : "",
        activationSecret: String(o["activationSecret"] ?? ""),
        machineId: String(o["machineId"] ?? ""),
        fingerprint: String(o["fingerprint"] ?? ""),
      };
      if (typeof o["keyset"] === "string") b.keyset = o["keyset"];
      if (typeof o["validation"] === "string") b.validation = o["validation"];
      if (typeof o["timeHighWater"] === "number") b.timeHighWater = o["timeHighWater"];
      if (typeof o["releaseSeqHighWater"] === "number") {
        b.releaseSeqHighWater = o["releaseSeqHighWater"];
      }
      // Read field by field rather than trusted wholesale: this file is on a
      // disk the user owns, so every value out of it is input. A `pendingRelease`
      // with a string where a number belongs would make the anti-downgrade
      // comparison silently lexicographic.
      const pending = o["pendingRelease"] as Record<string, unknown> | undefined;
      if (
        pending &&
        typeof pending["version"] === "string" &&
        typeof pending["releaseSeq"] === "number"
      ) {
        b.pendingRelease = { version: pending["version"], releaseSeq: pending["releaseSeq"] };
      }
      if (typeof o["machineKey"] === "string") b.machineKey = o["machineKey"];
      if (typeof o["machinePublicKey"] === "string") {
        b.machinePublicKey = o["machinePublicKey"];
      }
      if (typeof o["offlineToken"] === "string") b.offlineToken = o["offlineToken"];
      if (typeof o["offlineSeen"] === "number") b.offlineSeen = o["offlineSeen"];
      // What makes a binding worth keeping is that it holds a licence or the
      // identity behind one. The activation secret is that for an online
      // install; an air-gapped install has none — it was never issued one — and
      // requiring it here would throw away the offline file and the machine key
      // on every start, which is the whole state of an air-gapped install.
      return b.activationSecret || b.offlineToken || b.machineKey ? b : null;
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
