import { createPublicKey, verify } from "node:crypto";
import {
  encodeAbiParameters,
  hashTypedData,
  keccak256,
  recoverTypedDataAddress,
  toHex,
  type Hex,
  type Address,
} from "viem";

export interface Certificate {
  v: 1;
  kind: "talos-wallet-license";
  chain_id: number;
  contract: Address;
  issuer: Address;
  license: {
    tenant_id: Hex;
    product_id: Hex;
    license_id: Hex;
    holder: Address;
    not_before: number;
    expires_at: number;
    entitlements_hash: Hex;
    coordinator_key: Hex;
    max_concurrent_devices: 1;
  };
  entitlements: string;
  signature: Hex;
  coordinator_url: string;
}
export interface DeviceAuthorization {
  device_key: Hex;
  fingerprint_hash: Hex;
  signature: Hex;
}
export interface Trust {
  issuer: Address;
  productId: Hex;
  chainId: number;
  contract: Address;
}
export interface SignedMessage {
  payload: string;
  signature: Hex;
}
export interface Challenge {
  nonce: string;
  license_ref: Hex;
  device_ref: Hex;
  instance_id: string;
  action: string;
  issued_at: number;
  expires_at: number;
}
export interface Lease {
  license_ref: Hex;
  device_ref: Hex;
  instance_id: string;
  nonce: string;
  issued_at: number;
  expires_at: number;
  renew_after_s: number;
}
export const licenseTypes = {
  License: [
    { name: "tenantId", type: "bytes32" },
    { name: "productId", type: "bytes32" },
    { name: "licenseId", type: "bytes32" },
    { name: "holder", type: "address" },
    { name: "notBefore", type: "uint64" },
    { name: "expiresAt", type: "uint64" },
    { name: "entitlementsHash", type: "bytes32" },
    { name: "coordinatorKey", type: "bytes32" },
    { name: "maxConcurrentDevices", type: "uint8" },
  ],
} as const;
export const deviceTypes = {
  DeviceAuthorization: [
    { name: "tenantId", type: "bytes32" },
    { name: "productId", type: "bytes32" },
    { name: "licenseId", type: "bytes32" },
    { name: "issuer", type: "address" },
    { name: "holder", type: "address" },
    { name: "deviceKey", type: "bytes32" },
    { name: "fingerprintHash", type: "bytes32" },
  ],
} as const;
export const domain = (c: Certificate) => ({
  name: "TalosLicenseVerifier",
  version: "1",
  chainId: c.chain_id,
  verifyingContract: c.contract,
});
export function licenseTypedData(c: Certificate) {
  const l = c.license;
  return {
    domain: domain(c),
    types: licenseTypes,
    primaryType: "License" as const,
    message: {
      tenantId: l.tenant_id,
      productId: l.product_id,
      licenseId: l.license_id,
      holder: l.holder,
      notBefore: BigInt(l.not_before),
      expiresAt: BigInt(l.expires_at),
      entitlementsHash: l.entitlements_hash,
      coordinatorKey: l.coordinator_key,
      maxConcurrentDevices: l.max_concurrent_devices,
    },
  };
}
export function deviceTypedData(
  c: Certificate,
  d: Pick<DeviceAuthorization, "device_key" | "fingerprint_hash">,
) {
  return {
    domain: domain(c),
    types: deviceTypes,
    primaryType: "DeviceAuthorization" as const,
    message: {
      tenantId: c.license.tenant_id,
      productId: c.license.product_id,
      licenseId: c.license.license_id,
      issuer: c.issuer,
      holder: c.license.holder,
      deviceKey: d.device_key,
      fingerprintHash: d.fingerprint_hash,
    },
  };
}
export function licenseRef(c: Certificate): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "address" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
      ],
      [
        c.issuer,
        c.license.tenant_id,
        c.license.product_id,
        c.license.license_id,
      ],
    ),
  );
}
export function deviceRef(
  d: Pick<DeviceAuthorization, "device_key" | "fingerprint_hash">,
): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }],
      [d.device_key, d.fingerprint_hash],
    ),
  );
}
export function checkHex(value: unknown, bytes: number): asserts value is Hex {
  if (
    typeof value !== "string" ||
    !new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value)
  )
    throw new Error("invalid_hex");
}
export function canonicalSignature(s: Hex) {
  checkHex(s, 65);
  const n = BigInt("0x" + s.slice(66, 130));
  if (
    !["1b", "1c"].includes(s.slice(-2).toLowerCase()) ||
    n === 0n ||
    n > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n
  )
    throw new Error("noncanonical_signature");
}
export async function verifyCertificate(
  c: Certificate,
  trust: Trust,
  now = Math.floor(Date.now() / 1000),
): Promise<Record<string, unknown>> {
  if (
    !c ||
    c.v !== 1 ||
    c.kind !== "talos-wallet-license" ||
    !c.license ||
    JSON.stringify(c).length > 65536
  )
    throw new Error("invalid_certificate");
  const l = c.license;
  for (const h of [
    l.tenant_id,
    l.product_id,
    l.license_id,
    l.entitlements_hash,
    l.coordinator_key,
  ])
    checkHex(h, 32);
  for (const h of [
    c.issuer,
    c.contract,
    l.holder,
    trust.issuer,
    trust.contract,
  ])
    checkHex(h, 20);
  if (
    c.issuer.toLowerCase() !== trust.issuer.toLowerCase() ||
    c.contract.toLowerCase() !== trust.contract.toLowerCase() ||
    c.chain_id !== trust.chainId ||
    ![8453, 84532, 31337].includes(c.chain_id) ||
    l.product_id.toLowerCase() !== trust.productId.toLowerCase() ||
    /^0x0+$/.test(c.contract) ||
    /^0x0+$/.test(l.holder) ||
    /^0x0+$/.test(l.coordinator_key) ||
    l.max_concurrent_devices !== 1 ||
    !Number.isSafeInteger(l.not_before) ||
    !Number.isSafeInteger(l.expires_at) ||
    l.not_before < 0 ||
    l.expires_at < 0 ||
    now < l.not_before ||
    (l.expires_at !== 0 &&
      (now >= l.expires_at || l.expires_at <= l.not_before))
  )
    throw new Error("invalid_certificate");
  canonicalSignature(c.signature);
  if (
    (
      await recoverTypedDataAddress({
        ...licenseTypedData(c),
        signature: c.signature,
      })
    ).toLowerCase() !== trust.issuer.toLowerCase()
  )
    throw new Error("invalid_issuer_signature");
  const bytes = Buffer.from(c.entitlements, "base64url");
  if (keccak256(toHex(bytes)) !== l.entitlements_hash.toLowerCase())
    throw new Error("invalid_entitlements_hash");
  const ent = JSON.parse(bytes.toString("utf8"));
  if (!ent || Array.isArray(ent) || typeof ent !== "object")
    throw new Error("invalid_entitlements");
  return ent;
}
export async function verifyDevice(
  c: Certificate,
  d: DeviceAuthorization,
): Promise<void> {
  checkHex(d.device_key, 32);
  checkHex(d.fingerprint_hash, 32);
  canonicalSignature(d.signature);
  if (
    /^0x0+$/.test(d.device_key) ||
    (
      await recoverTypedDataAddress({
        ...deviceTypedData(c, d),
        signature: d.signature,
      })
    ).toLowerCase() !== c.license.holder.toLowerCase()
  )
    throw new Error("invalid_wallet_signature");
}
export function verifyMessage<T>(key: Hex, kind: string, m: SignedMessage): T {
  checkHex(key, 32);
  checkHex(m.signature, 64);
  if (typeof m.payload !== "string" || m.payload.length > 65536)
    throw new Error("invalid_message");
  const publicKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(key.slice(2), "hex"),
    ]),
    format: "der",
    type: "spki",
  });
  if (
    !verify(
      null,
      Buffer.from(`talos-wallet.1.${kind}.${m.payload}`),
      publicKey,
      Buffer.from(m.signature.slice(2), "hex"),
    )
  )
    throw new Error("invalid_coordinator_signature");
  return JSON.parse(Buffer.from(m.payload, "base64url").toString("utf8")) as T;
}
export { hashTypedData };
