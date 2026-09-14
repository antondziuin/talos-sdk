import {
  keccak256,
  toHex,
  recoverTypedDataAddress,
  recoverAddress,
  type Address,
  type Hex,
} from "viem";
import {
  domain,
  checkHex,
  canonicalSignature,
  type Certificate,
  type DeviceAuthorization,
  type Trust,
  type SignedMessage,
} from "./protocol.js";
export const DEVICE_VALIDITY_SECONDS = 604800;
export const DEVICE_RENEW_AFTER_SECONDS = 86400;
export interface Enrollment {
  v: 2;
  kind: "talos-wallet-enrollment";
  chain_id: number;
  contract: Address;
  issuer: Address;
  tenant_id: string;
  product_id: string;
  license_id: string;
  holder: Address;
  revision: number;
  issued_at: number;
  renewal_url: string;
  signature: Hex;
}
export interface DeviceCertificate {
  v: 2;
  kind: "talos-device-certificate";
  chain_id: number;
  contract: Address;
  issuer: Address;
  license: {
    tenant_id: Hex;
    product_id: Hex;
    license_id: Hex;
    holder: Address;
    device_key: Hex;
    fingerprint_hash: Hex;
    revision: number;
    not_before: number;
    expires_at: number;
    entitlements_hash: Hex;
  };
  entitlements: string;
  signature: Hex;
}
export const enrollmentTypes = {
  Enrollment: [
    { name: "tenantId", type: "bytes32" },
    { name: "productId", type: "bytes32" },
    { name: "licenseId", type: "bytes32" },
    { name: "holder", type: "address" },
    { name: "revision", type: "uint64" },
    { name: "issuedAt", type: "uint64" },
    { name: "renewalUrlHash", type: "bytes32" },
  ],
} as const;
export const deviceCertificateTypes = {
  DeviceLicense: [
    { name: "tenantId", type: "bytes32" },
    { name: "productId", type: "bytes32" },
    { name: "licenseId", type: "bytes32" },
    { name: "holder", type: "address" },
    { name: "deviceKey", type: "bytes32" },
    { name: "fingerprintHash", type: "bytes32" },
    { name: "revision", type: "uint64" },
    { name: "notBefore", type: "uint64" },
    { name: "expiresAt", type: "uint64" },
    { name: "entitlementsHash", type: "bytes32" },
  ],
} as const;
export function uuidHash(id: string): Hex {
  if (
    typeof id !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)
  )
    throw new Error("invalid_uuid");
  return keccak256(("0x" + id.replaceAll("-", "")) as Hex);
}
/** Hash adapter only; this is not a valid v1 execution permit. */
export function consentContext(e: Enrollment): Certificate {
  const zero = ("0x" + "00".repeat(32)) as Hex;
  return {
    v: 1,
    kind: "talos-wallet-license",
    chain_id: e.chain_id,
    contract: e.contract,
    issuer: e.issuer,
    license: {
      tenant_id: uuidHash(e.tenant_id),
      product_id: uuidHash(e.product_id),
      license_id: uuidHash(e.license_id),
      holder: e.holder,
      not_before: 0,
      expires_at: 0,
      entitlements_hash: zero,
      coordinator_key: zero,
      max_concurrent_devices: 1,
    },
    entitlements: "",
    signature: "0x",
    coordinator_url: "",
  };
}
export function enrollmentTypedData(e: Enrollment) {
  return {
    domain: domain(consentContext(e)),
    types: enrollmentTypes,
    primaryType: "Enrollment" as const,
    message: {
      tenantId: uuidHash(e.tenant_id),
      productId: uuidHash(e.product_id),
      licenseId: uuidHash(e.license_id),
      holder: e.holder,
      revision: BigInt(e.revision),
      issuedAt: BigInt(e.issued_at),
      renewalUrlHash: keccak256(toHex(e.renewal_url)),
    },
  };
}
export function deviceCertificateTypedData(c: DeviceCertificate) {
  const l = c.license;
  return {
    domain: {
      name: "TalosLicenseVerifier",
      version: "1",
      chainId: c.chain_id,
      verifyingContract: c.contract,
    },
    types: deviceCertificateTypes,
    primaryType: "DeviceLicense" as const,
    message: {
      tenantId: l.tenant_id,
      productId: l.product_id,
      licenseId: l.license_id,
      holder: l.holder,
      deviceKey: l.device_key,
      fingerprintHash: l.fingerprint_hash,
      revision: BigInt(l.revision),
      notBefore: BigInt(l.not_before),
      expiresAt: BigInt(l.expires_at),
      entitlementsHash: l.entitlements_hash,
    },
  };
}
export function renewalEndpoint(value: string): string {
  const u = new URL(value);
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (
    (u.protocol !== "https:" && !(u.protocol === "http:" && local)) ||
    u.username ||
    u.password ||
    u.search ||
    u.hash
  )
    throw new Error("invalid_renewal_url");
  return u.toString().replace(/\/$/, "");
}
export async function verifyEnrollment(
  e: Enrollment,
  trust: Trust,
): Promise<void> {
  if (
    !e ||
    e.v !== 2 ||
    e.kind !== "talos-wallet-enrollment" ||
    JSON.stringify(e).length > 16384
  )
    throw new Error("invalid_enrollment");
  for (const a of [
    e.issuer,
    e.contract,
    e.holder,
    trust.issuer,
    trust.contract,
  ])
    checkHex(a, 20);
  if (
    e.issuer.toLowerCase() !== trust.issuer.toLowerCase() ||
    e.chain_id !== trust.chainId ||
    ![8453, 84532, 31337].includes(e.chain_id) ||
    e.contract.toLowerCase() !== trust.contract.toLowerCase() ||
    uuidHash(e.product_id) !== trust.productId.toLowerCase() ||
    /^0x0+$/.test(e.holder) ||
    /^0x0+$/.test(e.contract) ||
    !Number.isSafeInteger(e.revision) ||
    e.revision < 1 ||
    !Number.isSafeInteger(e.issued_at) ||
    e.issued_at < 0
  )
    throw new Error("invalid_enrollment");
  renewalEndpoint(e.renewal_url);
  canonicalSignature(e.signature);
  if (
    (
      await recoverTypedDataAddress({
        ...enrollmentTypedData(e),
        signature: e.signature,
      })
    ).toLowerCase() !== trust.issuer.toLowerCase()
  )
    throw new Error("invalid_issuer_signature");
}
export async function verifyDeviceCertificate(
  c: DeviceCertificate,
  e: Enrollment,
  d: DeviceAuthorization,
  trust: Trust,
  now = Math.floor(Date.now() / 1000),
): Promise<Record<string, unknown>> {
  await verifyEnrollment(e, trust);
  if (
    !c ||
    c.v !== 2 ||
    c.kind !== "talos-device-certificate" ||
    !c.license ||
    JSON.stringify(c).length > 65536
  )
    throw new Error("invalid_device_certificate");
  const l = c.license;
  for (const h of [
    l.tenant_id,
    l.product_id,
    l.license_id,
    l.device_key,
    l.fingerprint_hash,
    l.entitlements_hash,
  ])
    checkHex(h, 32);
  for (const a of [c.issuer, c.contract, l.holder]) checkHex(a, 20);
  if (
    c.issuer.toLowerCase() !== e.issuer.toLowerCase() ||
    c.chain_id !== e.chain_id ||
    c.contract.toLowerCase() !== e.contract.toLowerCase() ||
    l.tenant_id !== uuidHash(e.tenant_id) ||
    l.product_id !== uuidHash(e.product_id) ||
    l.license_id !== uuidHash(e.license_id) ||
    l.holder.toLowerCase() !== e.holder.toLowerCase() ||
    l.device_key !== d.device_key ||
    l.fingerprint_hash !== d.fingerprint_hash ||
    /^0x0+$/.test(l.device_key) ||
    l.revision !== e.revision ||
    !Number.isSafeInteger(l.not_before) ||
    !Number.isSafeInteger(l.expires_at) ||
    l.not_before < 0 ||
    l.not_before > now ||
    l.expires_at <= now ||
    l.expires_at <= l.not_before ||
    l.expires_at - l.not_before > DEVICE_VALIDITY_SECONDS
  )
    throw new Error("invalid_device_certificate");
  canonicalSignature(c.signature);
  if (
    (
      await recoverTypedDataAddress({
        ...deviceCertificateTypedData(c),
        signature: c.signature,
      })
    ).toLowerCase() !== trust.issuer.toLowerCase()
  )
    throw new Error("invalid_issuer_signature");
  const bytes = Buffer.from(c.entitlements, "base64url");
  if (bytes.length > 32768 || keccak256(toHex(bytes)) !== l.entitlements_hash)
    throw new Error("invalid_entitlements_hash");
  const ent = JSON.parse(bytes.toString("utf8"));
  if (!ent || Array.isArray(ent) || typeof ent !== "object")
    throw new Error("invalid_entitlements");
  return ent;
}
export async function verifyRenewalChallenge(
  issuer: Address,
  m: SignedMessage,
): Promise<{
  nonce: string;
  license_ref: Hex;
  device_ref: Hex;
  revision: number;
  issued_at: number;
  expires_at: number;
}> {
  if (typeof m.payload !== "string" || m.payload.length > 4096)
    throw new Error("invalid_challenge");
  canonicalSignature(m.signature);
  if (
    (
      await recoverAddress({
        hash: keccak256(toHex("talos-wallet.2.challenge." + m.payload)),
        signature: m.signature,
      })
    ).toLowerCase() !== issuer.toLowerCase()
  )
    throw new Error("invalid_challenge_signature");
  return JSON.parse(Buffer.from(m.payload, "base64url").toString("utf8"));
}
