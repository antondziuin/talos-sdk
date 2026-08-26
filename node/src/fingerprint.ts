import { createHash, createHmac } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import os, { type NetworkInterfaceInfo } from "node:os";

/** A machine fingerprint: the composite plus the per-component hashes. */
export interface FingerprintData {
  /** What the server matches on. Derived from {@link components}. */
  composite: string;
  /** `{component_id: hash}` — lets the server tolerate hardware drift. */
  components: Record<string, string>;
}

/**
 * Collect a machine fingerprint.
 *
 * Each component is HMAC'd with a product-scoped key before it leaves the
 * machine, so the server stores hashes and never the underlying identifiers,
 * and the same hardware yields different hashes for different products.
 *
 * **Coverage is thin here, and honestly so.** Node has no hardware access
 * without native modules, and this SDK ships with zero dependencies and never
 * spawns a subprocess. On Linux it can read `/etc/machine-id`, which is enough
 * for the server to recognise a machine across a hardware change. On Windows and
 * macOS it cannot reach anything comparable, so those hosts stay on exact
 * matching: change a NIC and the user re-activates. If your app can do better —
 * Electron with a native module, or a value you already have — pass
 * `fingerprintComponents` in the options and the server will use it. See
 * `docs/FINGERPRINT.md` for the recognised ids and their weights.
 *
 * None of this resists a determined attacker: these values are produced on the
 * client and can be forged. They exist to recognise honest hardware churn.
 */
export function collectFingerprint(
  productToken: string,
  extra?: Record<string, string>,
): FingerprintData {
  const key = createHash("sha256").update("talos-fp|" + productToken).digest();

  const raw: Record<string, string | undefined> = {
    machine_guid: machineGuid(),
    smbios_uuid: readFile("/sys/class/dmi/id/product_uuid"),
    disk_serial: readFile("/sys/class/dmi/id/board_serial"),
    mac_set: macSet(),
    cpu: cpu(),
    mem_bucket: memBucket(),
    os_install: osInstall(),
    hostname: safe(() => os.hostname()),
    ...extra,
  };

  const components: Record<string, string> = {};
  for (const id of Object.keys(raw).sort()) {
    const value = raw[id];
    if (value === undefined || value === null || value.trim() === "") continue;
    // 16 bytes distinguishes components and keeps the request small; this is a
    // matching token, not a secret.
    components[id] = createHmac("sha256", key)
      .update(id + "=" + value.trim())
      .digest("hex")
      .slice(0, 32);
  }

  // The composite is a digest of the hashed components, so a host reporting the
  // same parts always yields the same composite and the server's exact-match
  // fast path keeps working.
  const canonical = Object.entries(components)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
  return {
    composite: "fp2:" + createHash("sha256").update(canonical).digest("hex"),
    components,
  };
}

/** Per-install OS identity; survives hardware changes. Linux only here. */
function machineGuid(): string | undefined {
  return readFile("/etc/machine-id") ?? readFile("/var/lib/dbus/machine-id");
}

/**
 * Sorted physical MACs. Internal interfaces are skipped: loopback and the
 * virtual adapters a VPN raises and drops would otherwise report drift on every
 * connection.
 */
function macSet(): string | undefined {
  return safe(() => {
    const macs = Object.values(os.networkInterfaces())
      .flat()
      .filter((i): i is NetworkInterfaceInfo => Boolean(i) && !i!.internal)
      .map((i) => i.mac)
      .filter((m) => m && m !== "00:00:00:00:00:00")
      .filter((m, i, all) => all.indexOf(m) === i)
      .sort();
    return macs.length === 0 ? undefined : macs.join(",");
  });
}

function cpu(): string | undefined {
  return safe(() => {
    const cpus = os.cpus();
    if (!cpus || cpus.length === 0) return undefined;
    return `${cpus[0].model}|${cpus.length}`;
  });
}

/**
 * Installed RAM rounded down to a power of two GiB. Coarse on purpose: exact
 * byte counts shift when firmware reserves memory, which would look like drift
 * on a machine nobody touched.
 */
function memBucket(): string | undefined {
  return safe(() => {
    const gib = Math.floor(os.totalmem() / 1024 ** 3);
    if (gib < 1) return undefined;
    let bucket = 1;
    while (bucket * 2 <= gib) bucket *= 2;
    return String(bucket);
  });
}

/** Install timestamp, approximated by the OS directory's creation time. */
function osInstall(): string | undefined {
  const path = os.platform() === "win32" ? process.env.SystemRoot ?? "C:\\Windows" : "/etc";
  return safe(() => {
    const birth = statSync(path).birthtimeMs;
    // Filesystems that do not record a birth time report 0 (or the epoch);
    // a constant would be worse than nothing, since every host would agree.
    return birth > 0 ? String(Math.floor(birth / 1000)) : undefined;
  });
}

function readFile(path: string): string | undefined {
  return safe(() => {
    const text = readFileSync(path, "utf8").trim();
    return text.length === 0 ? undefined : text;
  });
}

/**
 * Run a probe, treating any failure as "component unavailable". A missing
 * component costs a little matching weight; an exception escaping into a
 * licensing call would cost the user their session.
 */
function safe<T>(f: () => T | undefined): T | undefined {
  try {
    return f();
  } catch {
    return undefined;
  }
}
