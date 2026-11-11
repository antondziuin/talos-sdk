import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { expect, it } from "vitest";
import { createPublicClient, createWalletClient, keccak256, toHex, http, type Abi, type Address } from "viem";
import { foundry } from "viem/chains";
import { RegistryLicenseClient } from "../src/registry-client.js";
import { type RegistryLicenseManifest } from "../src/registry-protocol.js";

it.runIf(!!process.env.TALOS_REGISTRY_TEST_RPC && !!process.env.TALOS_REGISTRY_TEST_CONTRACT)(
  "local registry: SDK issue, holder binding, renewal, suspend, rights and terminal revocation",
  async () => {
    const rpc = process.env.TALOS_REGISTRY_TEST_RPC!;
    expect(["localhost", "127.0.0.1", "[::1]"]).toContain(new URL(rpc).hostname);
    const publicClient = createPublicClient({ chain: foundry, transport: http(rpc), pollingInterval: 50 });
    expect(await publicClient.getChainId()).toBe(31337);
    const wallet = createWalletClient({ chain: foundry, transport: http(rpc) });
    const [issuer, holder] = await wallet.getAddresses();
    expect(issuer).toBeDefined(); expect(holder).toBeDefined();
    const contract = process.env.TALOS_REGISTRY_TEST_CONTRACT! as Address;
    const artifact = JSON.parse(readFileSync(new URL("../../../contracts/out/TalosLicenseRegistryV1.sol/TalosLicenseRegistryV1.json", import.meta.url), "utf8"));
    const abi = artifact.abi as Abi;
    const product = keccak256(toHex("registry-sdk-test-" + randomUUID()));
    const id = keccak256(toHex(randomUUID()));
    const rights = toHex('{"pro":true}');
    const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const directory = mkdtempSync(join(tmpdir(), "talos-registry-live-"));
    try {
      const options = { chainId: 31337, issuer, productId: product, contract, rpcUrls: [rpc], statePath: join(directory, "state"), fingerprintComponents: { fixture: "registry-live" } };
      const client = await RegistryLicenseClient.create(options);
      const manifest: RegistryLicenseManifest = { v: 1, kind: "talos-registry-license", chain_id: 31337, contract, issuer, product_id: product, license_id: id, holder, entitlements: Buffer.from(rights.slice(2), "hex").toString("base64url") };
      client.importLicense(manifest);
      await expect(client.validate()).rejects.toThrow("license_missing");
      const write = async (functionName: string, args: unknown[]) => {
        const hash = await wallet.writeContract({ account: issuer, address: contract, abi, functionName, args });
        expect((await publicClient.waitForTransactionReceipt({ hash })).status).toBe("success");
      };
      await write("issueLicense", [product, id, holder, 0n, expiry, keccak256(rights)]);
      await expect(client.validate()).rejects.toThrow("device_not_bound");
      const bind = client.createDeviceBinding();
      expect(bind.expectedHolder.toLowerCase()).toBe(holder.toLowerCase());
      const hash = await wallet.sendTransaction({ account: holder, to: bind.to, data: bind.data, value: bind.value });
      expect((await publicClient.waitForTransactionReceipt({ hash })).status).toBe("success");
      expect((await client.requireValidLicense()).revision).toBe(2);
      expect(await client.getEntitlement("pro")).toBe(true);
      const restored = await RegistryLicenseClient.create(options); restored.importLicense(manifest);
      expect(restored.deviceKey).toBe(client.deviceKey);
      expect((await restored.validate()).isValid).toBe(true);
      const other = await RegistryLicenseClient.create({ ...options, statePath: join(directory, "other") }); other.importLicense(manifest);
      await expect(other.validate()).rejects.toThrow("wrong_device");
      await write("renewLicense", [product, id, expiry + 3600n]);
      expect((await client.validate()).expiresAt).toBe(Number(expiry + 3600n));
      await write("suspendLicense", [product, id]);
      await expect(client.validate()).rejects.toThrow("license_suspended");
      await write("resumeLicense", [product, id]);
      expect((await client.validate()).isValid).toBe(true);
      const next = { ...manifest, entitlements: Buffer.from('{"pro":false}').toString("base64url") };
      await write("setEntitlements", [product, id, keccak256(toHex('{"pro":false}'))]);
      await expect(client.validate()).rejects.toThrow("invalid_entitlements_hash");
      client.importLicense(next); expect(await client.getEntitlement("pro")).toBe(false);
      await write("revokeLicense", [product, id]);
      await expect(client.validate()).rejects.toThrow("license_revoked");
      await expect(client.getEntitlement("pro")).rejects.toThrow("license_revoked");
    } finally { rmSync(directory, { recursive: true, force: true }); }
  },
  30000,
);
