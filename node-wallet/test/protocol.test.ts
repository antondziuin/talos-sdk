import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { type Hex } from "viem";
import {
  licenseTypedData,
  deviceTypedData,
  hashTypedData,
  verifyCertificate,
  verifyDevice,
  licenseRef,
  deviceRef,
  type Certificate,
  type DeviceAuthorization,
} from "../src/protocol.js";
const vector = JSON.parse(
  readFileSync(
    new URL("../../wallet-contract-vectors.json", import.meta.url),
    "utf8",
  ),
);
const c = vector.certificate as Certificate,
  d = vector.device as DeviceAuthorization;
const trust = {
  issuer: c.issuer,
  productId: c.license.product_id,
  chainId: c.chain_id,
  contract: c.contract,
};
describe("shared Solidity/Rust/SDK wallet protocol", () => {
  it("matches both typed hashes and namespace identifiers", () => {
    expect(hashTypedData(licenseTypedData(c))).toBe(vector.license_digest);
    expect(hashTypedData(deviceTypedData(c, d))).toBe(vector.device_digest);
    expect(licenseRef(c)).toBe(vector.license_ref);
    expect(deviceRef(d)).toBe(vector.device_ref);
  });
  it("verifies issuer and wallet signatures", async () => {
    expect(await verifyCertificate(c, trust, c.license.not_before)).toEqual({
      pro: true,
    });
    await verifyDevice(c, d);
  });
  it("refuses expiry, tampering, another product and another domain", async () => {
    await expect(
      verifyCertificate(c, trust, c.license.expires_at),
    ).rejects.toThrow();
    await expect(
      verifyCertificate(
        {
          ...c,
          license: { ...c.license, expires_at: c.license.expires_at + 1 },
        },
        trust,
        c.license.not_before,
      ),
    ).rejects.toThrow();
    await expect(
      verifyCertificate(
        c,
        { ...trust, productId: c.license.tenant_id },
        c.license.not_before,
      ),
    ).rejects.toThrow();
    await expect(verifyDevice({ ...c, chain_id: 8453 }, d)).rejects.toThrow();
    await expect(
      verifyDevice(c, { ...d, fingerprint_hash: c.license.tenant_id }),
    ).rejects.toThrow();
  });
  it("renewal retains the wallet consent and the occupied slot", async () => {
    const renewed = {
      ...c,
      license: { ...c.license, expires_at: c.license.expires_at + 300 },
    };
    expect(licenseRef(renewed)).toBe(licenseRef(c));
    await verifyDevice(renewed, d);
  });
  it("accepts a freshly signed Ethereum Sepolia certificate and refuses cross-chain replay", async () => {
    const issuer = privateKeyToAccount(("0x" + "01".repeat(32)) as Hex);
    const sepolia: Certificate = { ...c, chain_id: 11155111 };
    sepolia.signature = await issuer.signTypedData(licenseTypedData(sepolia));
    expect(await verifyCertificate(sepolia, { ...trust, chainId: 11155111 }, c.license.not_before)).toEqual({ pro: true });
    await expect(verifyCertificate(sepolia, trust, c.license.not_before)).rejects.toThrow("invalid_certificate");
    await expect(verifyCertificate({ ...sepolia, chain_id: 84532 }, trust, c.license.not_before)).rejects.toThrow("invalid_issuer_signature");
    await expect(verifyCertificate({ ...sepolia, chain_id: 1 }, { ...trust, chainId: 1 }, c.license.not_before)).rejects.toThrow("invalid_certificate");
  });
});
