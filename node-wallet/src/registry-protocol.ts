import { keccak256, parseAbi, toHex, type Address, type Hex } from "viem";
import { checkHex, type Trust } from "./protocol.js";

/** Public lookup information. The chain, not this file, determines validity. */
export interface RegistryLicenseManifest {
  v: 1;
  kind: "talos-registry-license";
  chain_id: number;
  contract: Address;
  issuer: Address;
  product_id: Hex;
  license_id: Hex;
  holder: Address;
  entitlements: string;
}

export const registryAbi = parseAbi([
  "function registryVersion() view returns (uint256)",
  "function getLicense(address issuer,bytes32 productId,bytes32 licenseId) view returns (address holder,bytes32 deviceKey,uint64 notBefore,uint64 expiresAt,bytes32 entitlementsHash,uint64 revision,uint8 status)",
  "function checkLicense(address issuer,bytes32 productId,bytes32 licenseId,address expectedHolder,bytes32 expectedDeviceKey,bytes32 expectedEntitlementsHash) view returns (bool)",
  "function bindDevice(address issuer,bytes32 productId,bytes32 licenseId,bytes32 deviceKey)",
]);

export class RegistryLicenseError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "RegistryLicenseError";
  }
}

export const registryUuid = (value: unknown): value is string => typeof value === "string"
  && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

export function registryActivationEndpoint(value: string): string {
  try {
    const url = new URL(value);
    if ((url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
      || url.username || url.password || url.search || url.hash) throw new Error();
    return url.toString().replace(/\/$/, "");
  } catch { throw new RegistryLicenseError("invalid_registry_activation_url"); }
}

/** Canonical ASCII domain separation. Every hash/key uses lowercase 0x-prefixed hex. */
export function registryActivationProofText(productToken: string, code: string, deviceKey: Hex, requestId: string): string {
  checkHex(deviceKey, 32);
  if (!registryUuid(requestId)) throw new RegistryLicenseError("invalid_activation_request_id");
  return `talos-registry-activation.1.${keccak256(toHex(productToken))}.${keccak256(toHex(code.trim()))}.${deviceKey.toLowerCase()}.${requestId.toLowerCase()}`;
}

export function registryActivationStatusProofText(productToken: string, activationId: string, deviceKey: Hex): string {
  checkHex(deviceKey, 32);
  if (!registryUuid(activationId)) throw new RegistryLicenseError("invalid_activation_id");
  return `talos-registry-status.1.${keccak256(toHex(productToken))}.${activationId.toLowerCase()}.${deviceKey.toLowerCase()}`;
}

export function registryManifest(
  value: RegistryLicenseManifest | string,
  trust: Trust,
): { manifest: RegistryLicenseManifest; entitlements: Record<string, unknown>; entitlementsHash: Hex } {
  let m: RegistryLicenseManifest;
  try {
    const raw = typeof value === "string" ? value : JSON.stringify(value);
    if (raw.length > 65536) throw new Error();
    m = JSON.parse(raw);
    if (!m || m.v !== 1 || m.kind !== "talos-registry-license") throw new Error();
    if (Object.keys(m).some(key => !["v", "kind", "chain_id", "contract", "issuer", "product_id", "license_id", "holder", "entitlements"].includes(key))) throw new Error();
    for (const address of [m.contract, m.issuer, m.holder]) {
      checkHex(address, 20);
      if (/^0x0+$/.test(address)) throw new Error();
    }
    for (const id of [m.product_id, m.license_id]) {
      checkHex(id, 32);
      if (/^0x0+$/.test(id)) throw new Error();
    }
    if (m.chain_id !== trust.chainId || m.contract.toLowerCase() !== trust.contract.toLowerCase()
      || m.issuer.toLowerCase() !== trust.issuer.toLowerCase()
      || m.product_id.toLowerCase() !== trust.productId.toLowerCase()) throw new Error();
    if (typeof m.entitlements !== "string" || !/^[A-Za-z0-9_-]+$/.test(m.entitlements)) throw new Error();
    const bytes = Buffer.from(m.entitlements, "base64url");
    if (bytes.length > 32768 || bytes.toString("base64url") !== m.entitlements) throw new Error();
    const entitlements: unknown = JSON.parse(bytes.toString("utf8"));
    if (!entitlements || Array.isArray(entitlements) || typeof entitlements !== "object") throw new Error();
    return { manifest: m, entitlements: entitlements as Record<string, unknown>, entitlementsHash: keccak256(toHex(bytes)) };
  } catch {
    throw new RegistryLicenseError("invalid_registry_manifest");
  }
}
