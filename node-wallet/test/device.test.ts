import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPublicKey, verify } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { encodeAbiParameters, hashTypedData, keccak256, toHex, type Hex } from "viem";
import { DeviceLicenseClient } from "../src/device-client.js";
import {
  consentContext,
  uuidHash,
  enrollmentTypedData,
  deviceCertificateTypedData,
  verifyEnrollment,
  verifyDeviceCertificate,
  type Enrollment,
  type DeviceCertificate,
} from "../src/device-protocol.js";
import {
  deviceRef,
  licenseRef,
  verifyDevice,
  type DeviceAuthorization,
} from "../src/protocol.js";
const issuer = privateKeyToAccount(("0x" + "01".repeat(32)) as Hex),
  owner = privateKeyToAccount(("0x" + "02".repeat(32)) as Hex);
const vector = JSON.parse(
  readFileSync(
    new URL("../../device-contract-vectors.json", import.meta.url),
    "utf8",
  ),
);
const trust = {
  issuer: issuer.address,
  productId: uuidHash(vector.enrollment.product_id),
  chainId: 84532,
  contract: vector.enrollment.contract,
};
const paths: string[] = [];
const clients: DeviceLicenseClient[] = [];
afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  for (const c of clients.splice(0)) await c.stop();
  for (const p of paths.splice(0)) rmSync(p, { recursive: true, force: true });
});
async function setup(chainId = 84532, contract = vector.enrollment.contract, rpcUrl?: string, certificateTime?: number) {
  const protocolTrust = { ...trust, chainId, contract };
  const directory = mkdtempSync(join(tmpdir(), "talos-device-"));
  paths.push(directory);
  const e: Enrollment = {
    ...vector.enrollment,
    chain_id: chainId,
    contract,
    issued_at: Math.floor(Date.now() / 1000),
  };
  e.signature = await issuer.signTypedData(enrollmentTypedData(e));
  let offline = false,
    bound = "",
    revision = 1,
    revoked = false,
    renewals = 0;
  const http = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (rpcUrl && String(input) === rpcUrl) return globalThis.fetch(input, init);
    if (offline) throw new Error("offline");
    if (revoked) return new Response("{}", { status: 409 });
    const body = JSON.parse(init!.body as string),
      now = Math.floor(Date.now() / 1000);
    if (String(input).endsWith("/challenge")) {
      await verifyEnrollment(body.enrollment, protocolTrust);
      await verifyDevice(consentContext(body.enrollment), body.device);
      const payload = Buffer.from(
        JSON.stringify({
          nonce: "fixture",
          license_ref: licenseRef(consentContext(body.enrollment)),
          device_ref: deviceRef(body.device),
          revision: body.enrollment.revision,
          issued_at: now,
          expires_at: now + 120,
        }),
      ).toString("base64url");
      const signature = await issuer.sign({
        hash: keccak256(toHex("talos-wallet.2.challenge." + payload)),
      });
      return Response.json({ payload, signature });
    }
    const { context, challenge, proof } = body;
    const d = context.device as DeviceAuthorization;
    const key = createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(d.device_key.slice(2), "hex"),
      ]),
      format: "der",
      type: "spki",
    });
    expect(
      verify(
        null,
        Buffer.from("talos-wallet.2.proof." + challenge.payload),
        key,
        Buffer.from(proof.slice(2), "hex"),
      ),
    ).toBe(true);
    if (
      context.enrollment.revision !== revision ||
      (bound && bound !== d.device_key)
    )
      return new Response("{}", { status: 409 });
    bound = d.device_key;
    const c: DeviceCertificate = {
      ...vector.certificate,
      chain_id: chainId,
      contract,
      license: {
        ...vector.certificate.license,
        device_key: d.device_key,
        fingerprint_hash: d.fingerprint_hash,
        revision,
        not_before: certificateTime ?? now,
        expires_at: (certificateTime ?? now) + 604800,
      },
    };
    c.signature = await issuer.signTypedData(deviceCertificateTypedData(c));
    renewals++;
    return Response.json(c);
  });
  const create = async (
    path = join(directory, "state"),
    fingerprint = "one",
  ) => {
    const c = await DeviceLicenseClient.create({
      ...protocolTrust,
      statePath: path,
      fingerprintComponents: { test: fingerprint },
      fetch: http,
    });
    clients.push(c);
    return c;
  };
  const authorize = async (c: DeviceLicenseClient, invitation = e) => {
    await c.importEnrollment(invitation);
    await c.acceptDeviceAuthorization(
      await owner.signTypedData(c.createDeviceAuthorization()),
    );
  };
  return {
    e,
    create,
    authorize,
    http,
    path: join(directory, "state"),
    setOffline: (v: boolean) => (offline = v),
    revoke: () => (revoked = true),
    transfer: async () => {
      bound = "";
      revision++;
      const next = { ...e, revision };
      next.signature = await issuer.signTypedData(enrollmentTypedData(next));
      return next;
    },
    renewals: () => renewals,
  };
}
it("matches the Rust and Solidity device signature vectors and exact expiry", async () => {
  const e = vector.enrollment,
    c = vector.certificate,
    d = vector.device;
  expect(hashTypedData(enrollmentTypedData(e))).toBe(vector.enrollment_digest);
  expect(hashTypedData(deviceCertificateTypedData(c))).toBe(
    vector.certificate_digest,
  );
  expect(
    await verifyDeviceCertificate(c, e, d, trust, c.license.not_before),
  ).toEqual({ pro: true });
  await expect(
    verifyDeviceCertificate(c, e, d, trust, c.license.expires_at),
  ).rejects.toThrow();
  await expect(
    verifyEnrollment({ ...e, renewal_url: "https://attacker.example" }, trust),
  ).rejects.toThrow();
  const tooLong = {
    ...c,
    license: { ...c.license, expires_at: c.license.expires_at + 1 },
  };
  tooLong.signature = await issuer.signTypedData(
    deviceCertificateTypedData(tooLong),
  );
  await expect(
    verifyDeviceCertificate(tooLong, e, d, trust, c.license.not_before),
  ).rejects.toThrow();
});
it("activates and renews on Ethereum Sepolia, preserving pinned trust and RPC chain checks", async () => {
  const s = await setup(11155111),
    c = await s.create();
  await s.authorize(c);
  await c.start();
  expect(c.canRun).toBe(true);
  expect(c.getEntitlement("pro")).toBe(true);
  const expiry = c.expiresAt!;
  vi.spyOn(Date, "now").mockReturnValue(Date.now() + 86400000);
  await c.refresh();
  expect(c.expiresAt).toBeGreaterThan(expiry);
  await expect(verifyEnrollment(s.e, trust)).rejects.toThrow("invalid_enrollment");

  s.http.mockImplementationOnce(async () => Response.json({ jsonrpc: "2.0", id: 1, result: "0xaa36a7" }));
  s.http.mockImplementationOnce(async () => Response.json({ jsonrpc: "2.0", id: 2, result: encodeAbiParameters([{ type: "bool" }], [true]) }));
  await c.stop();
  expect(await c.verifyViaContract("http://127.0.0.1:8545")).toBe(true);
  expect(c.canRun).toBe(false);
  const call = JSON.parse(s.http.mock.calls.at(-1)![1]!.body as string);
  expect(call.method).toBe("eth_call");
  expect(call.params[0].to).toBe(s.e.contract);

  const before = s.http.mock.calls.length;
  s.http.mockImplementationOnce(async () => Response.json({ jsonrpc: "2.0", id: 1, result: "0x1" }));
  await expect(c.verifyViaContract("http://127.0.0.1:8545")).rejects.toThrow("wrong_rpc_chain");
  expect(s.http.mock.calls.length - before).toBe(1);
});
it.each(["issuer", "contract", "product", "mainnet"])("rejects an enrollment outside the application's pinned %s", async (field) => {
  const pinned = { ...trust };
  if (field === "issuer") pinned.issuer = owner.address;
  if (field === "contract") pinned.contract = owner.address;
  if (field === "product") pinned.productId = uuidHash(vector.enrollment.tenant_id);
  if (field === "mainnet") pinned.chainId = 1;
  await expect(verifyEnrollment(vector.enrollment, pinned)).rejects.toThrow("invalid_enrollment");
});
it.each(["future", "revision", "device", "fingerprint", "holder", "entitlements"])("rejects a certificate with a mismatched %s", async (field) => {
  const c: DeviceCertificate = structuredClone(vector.certificate);
  if (field === "future") c.license.not_before++;
  if (field === "revision") c.license.revision++;
  if (field === "device") c.license.device_key = c.license.tenant_id;
  if (field === "fingerprint") c.license.fingerprint_hash = c.license.tenant_id;
  if (field === "holder") c.license.holder = issuer.address;
  if (field === "entitlements") c.entitlements = Buffer.from('{"admin":true}').toString("base64url");
  c.signature = await issuer.signTypedData(deviceCertificateTypedData(c));
  await expect(verifyDeviceCertificate(c, vector.enrollment, vector.device, trust, vector.certificate.license.not_before)).rejects.toThrow();
});
it("rejects owner consent signed by a different wallet", async () => {
  const s = await setup(), c = await s.create();
  await c.importEnrollment(s.e);
  await expect(c.acceptDeviceAuthorization(await issuer.signTypedData(c.createDeviceAuthorization()))).rejects.toThrow("invalid_wallet_signature");
  expect(c.isDeviceAuthorized).toBe(false);
  expect(c.canRun).toBe(false);
});
it("does not overwrite another process's renewed certificate on shutdown", async () => {
  const s = await setup(),
    a = await s.create();
  await s.authorize(a);
  await a.start();
  const b = await s.create();
  await b.start();
  vi.spyOn(Date, "now").mockReturnValue(Date.now() + 86400000);
  await a.refresh();
  const expiry = a.expiresAt;
  await b.stop();
  s.setOffline(true);
  const restored = await s.create();
  await restored.start();
  expect(restored.expiresAt).toBe(expiry);
});
it("does not overwrite a transferred enrollment when an older process stops", async () => {
  const s = await setup(),
    a = await s.create();
  await s.authorize(a);
  await a.start();
  const b = await s.create();
  const e = await s.transfer();
  await s.authorize(b, e);
  await b.start();
  await a.stop();
  const saved = JSON.parse(readFileSync(s.path + ".device.json", "utf8"));
  expect(saved.enrollment.revision).toBe(e.revision);
  expect(saved.certificate.license.revision).toBe(e.revision);
});
it("concurrent starts share the activation result instead of reporting premature success", async () => {
  const s = await setup(),
    c = await s.create();
  await s.authorize(c);
  s.setOffline(true);
  const results = await Promise.allSettled([c.start(), c.start()]);
  expect(results.map((r) => r.status)).toEqual(["rejected", "rejected"]);
  expect(c.canRun).toBe(false);
});
it("requires first activation online, then restarts offline with no network dependency", async () => {
  const s = await setup();
  const c = await s.create();
  await s.authorize(c);
  expect(c.canRun).toBe(false);
  s.setOffline(true);
  await expect(c.start()).rejects.toThrow();
  s.setOffline(false);
  await c.start();
  expect(c.canRun).toBe(true);
  expect(c.getEntitlement("pro")).toBe(true);
  await c.stop();
  s.setOffline(true);
  const restored = await s.create();
  await restored.importEnrollment(s.e);
  await restored.start();
  expect(restored.canRun).toBe(true);
  expect(s.renewals()).toBe(1);
});
it("failed renewal and revocation preserve the existing permit, but never extend its expiry", async () => {
  const s = await setup(),
    c = await s.create();
  await s.authorize(c);
  await c.start();
  const expiry = c.expiresAt!;
  s.revoke();
  await expect(c.refresh()).rejects.toThrow();
  expect(c.canRun).toBe(true);
  expect(c.expiresAt).toBe(expiry);
  vi.spyOn(Date, "now").mockReturnValue(expiry * 1000);
  expect(c.canRun).toBe(false);
  expect(() => c.requireValidCertificate()).toThrow();
});
it("rejects another device; transfer enables it while the old certificate expires naturally", async () => {
  const s = await setup(),
    old = await s.create();
  await s.authorize(old);
  await old.start();
  const next = await s.create(s.path + "-other", "two");
  await s.authorize(next);
  await expect(next.start()).rejects.toThrow();
  const e = await s.transfer();
  await s.authorize(next, e);
  await next.start();
  await expect(old.refresh()).rejects.toThrow();
  expect(old.canRun).toBe(true);
  expect(next.canRun).toBe(true);
});
it("does not accept a copied cache on a changed fingerprint", async () => {
  const s = await setup(),
    c = await s.create();
  await s.authorize(c);
  await c.start();
  await c.stop();
  s.setOffline(true);
  const copied = await s.create(s.path, "other-machine");
  await expect(copied.start()).rejects.toThrow();
  expect(copied.canRun).toBe(false);
});
it("renews automatically after one day and retries after connectivity returns", async () => {
  const s = await setup(),
    c = await s.create();
  await s.authorize(c);
  await c.start();
  const expiry = c.expiresAt!;
  vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
  c.notifyResume();
  s.setOffline(true);
  await vi.advanceTimersByTimeAsync(86401000);
  expect(c.canRun).toBe(true);
  expect(c.expiresAt).toBe(expiry);
  s.setOffline(false);
  c.notifyResume();
  await vi.advanceTimersByTimeAsync(2000);
  expect(c.expiresAt).toBeGreaterThan(expiry);
  expect(s.renewals()).toBe(2);
});
it.runIf(!!process.env.TALOS_WALLET_TEST_RPC && !!process.env.TALOS_WALLET_TEST_CONTRACT)(
  "V2 eth_call verifies an issued device certificate without granting execution after stop",
  async () => {
    const rpc = process.env.TALOS_WALLET_TEST_RPC!;
    // An idle local chain does not mine new timestamps. Sign a fixture valid at
    // the latest block so this read-only check needs no extra transaction.
    const response = await fetch(rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getBlockByNumber", params: ["latest", false] }),
    });
    const block = await response.json();
    expect(response.ok).toBe(true);
    expect(block.error).toBeUndefined();
    const s = await setup(31337, process.env.TALOS_WALLET_TEST_CONTRACT!, rpc, Number.parseInt(block.result.timestamp, 16));
    const c = await s.create();
    await s.authorize(c);
    await c.start();
    expect(await c.verifyViaContract(rpc)).toBe(true);
    await c.stop();
    expect(await c.verifyViaContract(rpc)).toBe(true);
    expect(c.canRun).toBe(false);
  },
);
