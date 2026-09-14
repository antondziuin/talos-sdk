import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPublicKey, verify } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { hashTypedData, keccak256, toHex, type Hex } from "viem";
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
async function setup() {
  const directory = mkdtempSync(join(tmpdir(), "talos-device-"));
  paths.push(directory);
  const e: Enrollment = {
    ...vector.enrollment,
    issued_at: Math.floor(Date.now() / 1000),
  };
  e.signature = await issuer.signTypedData(enrollmentTypedData(e));
  let offline = false,
    bound = "",
    revision = 1,
    revoked = false,
    renewals = 0;
  const http = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (offline) throw new Error("offline");
    if (revoked) return new Response("{}", { status: 409 });
    const body = JSON.parse(init!.body as string),
      now = Math.floor(Date.now() / 1000);
    if (String(input).endsWith("/challenge")) {
      await verifyEnrollment(body.enrollment, trust);
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
      license: {
        ...vector.certificate.license,
        device_key: d.device_key,
        fingerprint_hash: d.fingerprint_hash,
        revision,
        not_before: now,
        expires_at: now + 604800,
      },
    };
    c.signature = await issuer.signTypedData(deviceCertificateTypedData(c));
    renewals++;
    return Response.json(c);
  }) as unknown as typeof fetch;
  const create = async (
    path = join(directory, "state"),
    fingerprint = "one",
  ) => {
    const c = await DeviceLicenseClient.create({
      ...trust,
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
