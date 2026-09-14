import { readFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { keccak256, toHex, type Hex } from "viem";
import {
  WalletLicenseClient,
  licenseTypedData,
  type Certificate,
} from "../src/index.js";

it.runIf(!!process.env.TALOS_COORDINATOR_URL)(
  "real coordinator: same device shares a slot; transfer waits for old signed leases",
  async () => {
    const c = JSON.parse(
      readFileSync(
        new URL("../../wallet-contract-vectors.json", import.meta.url),
        "utf8",
      ),
    ).certificate as Certificate;
    const issuer = privateKeyToAccount(("0x" + "01".repeat(32)) as Hex),
      owner = privateKeyToAccount(("0x" + "02".repeat(32)) as Hex);
    const now = Math.floor(Date.now() / 1000);
    c.license.not_before = now - 10;
    c.license.expires_at = now + 3600;
    c.license.license_id = keccak256(toHex(randomUUID()));
    c.signature = await issuer.signTypedData(licenseTypedData(c));
    c.coordinator_url = process.env.TALOS_COORDINATOR_URL!;
    const root = mkdtempSync(join(tmpdir(), "talos-wallet-e2e-"));
    const base = {
      issuer: c.issuer,
      productId: c.license.product_id,
      chainId: c.chain_id,
      contract: c.contract,
    };
    const aOpts = {
      ...base,
      statePath: join(root, "a"),
      fingerprintComponents: { machine_guid: "a" },
    };
    const [a, a2] = await Promise.all([
      WalletLicenseClient.create(aOpts),
      WalletLicenseClient.create(aOpts),
    ]);
    const b = await WalletLicenseClient.create({
      ...base,
      statePath: join(root, "b"),
      fingerprintComponents: { machine_guid: "b" },
    });
    expect(a.deviceKey).toBe(a2.deviceKey);
    for (const client of [a, a2, b]) {
      await client.importCertificate(c);
      await client.acceptDeviceAuthorization(
        await owner.signTypedData(client.createDeviceAuthorization()),
      );
      expect(client.canRun).toBe(false);
    }
    try {
      await Promise.all([a.startSession(), a2.startSession()]);
      expect(a.canRun).toBe(true);
      expect(a2.canRun).toBe(true);
      await expect(b.startSession()).rejects.toThrow("license_in_use");
      await a.stopSession();
      expect(a2.canRun).toBe(true);
      await expect(b.startSession()).rejects.toThrow("license_in_use");
      await a2.stopSession();
      expect(() => a2.requireActiveSession()).toThrow(
        "active_session_required",
      );
      await expect(b.startSession()).rejects.toThrow("license_in_use");
      await new Promise((resolve) => setTimeout(resolve, 62000));
      await b.startSession();
      expect(b.canRun).toBe(true);
      b.notifyResume();
      expect(b.canRun).toBe(false);
    } finally {
      await Promise.all([a.stopSession(), a2.stopSession(), b.stopSession()]);
    }
  },
  90000,
);
