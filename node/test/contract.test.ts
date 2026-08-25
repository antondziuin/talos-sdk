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
    const client = new TalosClient({
      productToken: env("TALOS_PRODUCT_TOKEN"),
      publicKey: env("TALOS_PUBLIC_KEY"),
      serverUrl: env("TALOS_SERVER_URL"),
      appVersion: "1.0.0",
    });

    const activated = await client.activate(env("TALOS_LICENSE_KEY"));
    expect(activated.isValid).toBe(true);
    expect(client.isFeatureEnabled("pro")).toBe(true);
    expect(client.current?.getEntitlement("seats")).toBe(5);

    const validated = await client.validate();
    expect(validated.decision).toBe("valid");

    const again = await client.validate();
    expect(again.isValid).toBe(true);

    await client.deactivate();
    await expect(client.validate()).rejects.toBeInstanceOf(TalosError);
  });
});

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} must be set for the contract test`);
  return v;
}
