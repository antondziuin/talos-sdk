import { createHash } from "node:crypto";
import os, { type NetworkInterfaceInfo } from "node:os";

/**
 * A stable machine fingerprint (exact-match composite hash). Node has limited
 * hardware access without native modules, so v1 uses hostname + platform/arch +
 * the first physical MAC — weak and spoofable, which is why real anti-abuse
 * signals live server-side. Only the hash is sent.
 */
export function computeFingerprint(): string {
  const macs = Object.values(os.networkInterfaces())
    .flat()
    .filter((i): i is NetworkInterfaceInfo => Boolean(i))
    .map((i) => i.mac)
    .filter((m) => m && m !== "00:00:00:00:00:00")
    .sort();

  const raw = [os.hostname(), os.platform(), os.arch(), macs[0] ?? ""].join("|");
  return "b3:" + createHash("sha256").update("talos-fp " + raw).digest("hex");
}
