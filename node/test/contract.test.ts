import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { TalosClient, TalosError } from "../src/index.js";

/**
 * Cross-language contract test: drives the real Rust `/v1/client` API and
 * verifies the signed tokens with the product's actual public key. Skipped
 * unless `TALOS_CONTRACT=1` and the config env vars are set (see contract.sh).
 */
describe("contract", () => {
  const run = process.env["TALOS_CONTRACT"] === "1";

  (run ? it : it.skip)("activate / validate / deactivate roundtrip", async () => {
    // Pin ONLY the anchor: the demo rotated both signing keys, so the SDK has no
    // direct key and MUST learn the (rotated) license/release keys from the
    // anchor-signed keyset. Verifying at all proves keyset-consume / anti-lock-in.
    const client = new TalosClient({
      productToken: env("TALOS_PRODUCT_TOKEN"),
      anchorPublicKey: env("TALOS_ANCHOR_PUBLIC_KEY"),
      serverUrl: env("TALOS_SERVER_URL"),
      appVersion: "1.0.0",
    });

    const activated = await client.activate(env("TALOS_LICENSE_KEY"));
    expect(activated.isValid).toBe(true);
    expect(client.isFeatureEnabled("pro")).toBe(true);
    expect(client.current?.getEntitlement("seats")).toBe(5);

    // Explicitly refresh the keyset (exercises the standalone endpoint), then
    // validate against the keyset-learned key.
    await client.refreshKeyset();
    const validated = await client.validate();
    expect(validated.decision).toBe("valid");

    const again = await client.validate();
    expect(again.isValid).toBe(true);

    // Updates: check → verified manifest → download → SHA-256 verification.
    const upd = await client.checkForUpdate({ currentVersion: env("TALOS_CURRENT_VERSION") });
    expect(upd).not.toBeNull();
    expect(upd!.version).toBe(env("TALOS_UPDATE_VERSION"));
    expect(upd!.releaseSeq).toBeGreaterThan(0);
    expect(upd!.artifacts.length).toBeGreaterThan(0);

    const dest = path.join(os.tmpdir(), `talos-dl-${process.pid}-${upd!.artifacts[0]!.filename}`);
    const got = await client.downloadUpdate(upd!, dest, upd!.artifacts[0]!);
    expect(got.filename).toBe(upd!.artifacts[0]!.filename);
    const written = await readFile(dest);
    expect(written.length).toBe(got.size);

    // Anti-downgrade: checking with a seq at/above the latest yields no update.
    const none = await client.checkForUpdate({ currentReleaseSeq: upd!.releaseSeq });
    expect(none).toBeNull();

    // Heartbeat: signed decision + the telemetry source for monitoring.
    const beat = await client.heartbeat();
    expect(beat.decision).toBe("valid");

    // Floating seats (the demo policy has max_concurrent_seats = 1).
    const lease = await client.acquireLease({ instanceId: "inst-1", autoRenew: false });
    expect(lease.maxSeats).toBe(1);
    expect(lease.seatsInUse).toBe(1);

    // Re-acquiring the SAME instance renews rather than taking a second seat.
    const renewed = await client.acquireLease({ instanceId: "inst-1", autoRenew: false });
    expect(renewed.seatsInUse).toBe(1);

    // A DIFFERENT instance is refused while the only seat is held.
    await expect(
      client.acquireLease({ instanceId: "inst-2", autoRenew: false }),
    ).rejects.toMatchObject({ statusCode: 409 });

    // Releasing frees the seat for the waiting instance.
    await client.releaseLease();
    const second = await client.acquireLease({ instanceId: "inst-2", autoRenew: false });
    expect(second.seatsInUse).toBe(1);
    await client.releaseLease();

    await client.deactivate();
    await expect(client.validate()).rejects.toBeInstanceOf(TalosError);
  });
});

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} must be set for the contract test`);
  return v;
}
