import { createPrivateKey, sign, randomUUID } from "node:crypto";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { toHex, keccak256, type Hex } from "viem";
import {
  WalletLicenseClient,
  licenseTypedData,
  licenseRef,
  deviceRef,
  type Certificate,
} from "../src/index.js";

async function setup(duration = 60, contract?: Hex) {
  const c = JSON.parse(
    readFileSync(
      new URL("../../wallet-contract-vectors.json", import.meta.url),
      "utf8",
    ),
  ).certificate as Certificate;
  c.license.not_before = Math.floor(Date.now() / 1000) - 10;
  c.license.expires_at = 0;
  c.license.license_id = keccak256(toHex(randomUUID()));
  if (contract) {
    c.chain_id = 31337;
    c.contract = contract;
    c.license.not_before = 0;
  }
  c.signature = await privateKeyToAccount(
    ("0x" + "01".repeat(32)) as Hex,
  ).signTypedData(licenseTypedData(c));
  const coordinator = createPrivateKey({
    key: Buffer.from(
      "302e020100300506032b657004220420" + "03".repeat(32),
      "hex",
    ),
    format: "der",
    type: "pkcs8",
  });
  const state = {
    delay: undefined as undefined | Promise<void>,
    invalid: false,
  };
  function signed(kind: string, value: unknown) {
    const payload = Buffer.from(JSON.stringify(value)).toString("base64url");
    const signature = toHex(
      sign(null, Buffer.from(`talos-wallet.1.${kind}.${payload}`), coordinator),
    );
    return new Response(
      JSON.stringify({
        payload,
        signature: state.invalid ? "0x" + "00".repeat(64) : signature,
      }),
    );
  }
  const fetcher: typeof fetch = async (url, init) => {
    if (String(url) === process.env.TALOS_WALLET_TEST_RPC)
      return fetch(url, init);
    const body = JSON.parse(init!.body as string),
      now = Math.floor(Date.now() / 1000);
    if (String(url).endsWith("/challenge"))
      return signed("challenge", {
        nonce: randomUUID(),
        license_ref: licenseRef(c),
        device_ref: deviceRef(body.device),
        instance_id: body.instance_id,
        action: body.action,
        issued_at: now,
        expires_at: now + 30,
      });
    const ch = JSON.parse(
      Buffer.from(body.challenge.payload, "base64url").toString(),
    );
    const response = signed(
      body.context.action === "release" ? "released" : "lease",
      {
        ...ch,
        issued_at: now,
        expires_at: now + (body.context.action === "release" ? 0 : duration),
        renew_after_s: 20,
      },
    );
    await state.delay;
    return response;
  };
  const client = await WalletLicenseClient.create({
    issuer: c.issuer,
    productId: c.license.product_id,
    chainId: c.chain_id,
    contract: c.contract,
    statePath: join(mkdtempSync(join(tmpdir(), "talos-wallet-unit-")), "state"),
    fetch: fetcher,
  });
  await client.importCertificate(c);
  await client.acceptDeviceAuthorization(
    await privateKeyToAccount(("0x" + "02".repeat(32)) as Hex).signTypedData(
      client.createDeviceAuthorization(),
    ),
  );
  return { client, state };
}

it("enforces expiry synchronously without waiting for the renewal timer", async () => {
  const { client } = await setup(6);
  try {
    await client.startSession();
    expect(client.getEntitlement("pro")).toBe(true);
    await new Promise((r) => setTimeout(r, 1100));
    expect(client.canRun).toBe(false);
    expect(() => client.getEntitlement("pro")).toThrow(
      "active_session_required",
    );
  } finally {
    await client.stopSession();
  }
});
it("never accepts an invalid coordinator signature", async () => {
  const { client, state } = await setup();
  state.invalid = true;
  await expect(client.startSession()).rejects.toThrow();
  expect(client.canRun).toBe(false);
});
it("delayed replies cannot revive a session after resume or extend its lifetime", async () => {
  const { client, state } = await setup(6);
  state.delay = new Promise((r) => setTimeout(r, 1100));
  await expect(client.startSession()).rejects.toThrow(
    "lease_expired_in_transit",
  );
  expect(client.canRun).toBe(false);
  state.delay = new Promise((r) => setTimeout(r, 100));
  const starting = client.startSession();
  await new Promise((r) => setTimeout(r, 30));
  client.notifyResume();
  await expect(starting).rejects.toThrow(
    "session_interrupted_by_clock_or_resume",
  );
  expect(client.canRun).toBe(false);
});
it("stop during acquire cannot revive access, and restart gets a fresh session ID", async () => {
  const { client, state } = await setup();
  state.delay = new Promise((r) => setTimeout(r, 100));
  const starting = client.startSession();
  const failed = expect(starting).rejects.toThrow("session_interrupted");
  await new Promise((r) => setTimeout(r, 30));
  await client.stopSession();
  await failed;
  expect(client.canRun).toBe(false);
  const previous = client.instanceId;
  state.delay = undefined;
  await client.startSession();
  expect(client.instanceId).not.toBe(previous);
  expect(client.canRun).toBe(true);
  await client.stopSession();
});
it.runIf(
  !!process.env.TALOS_WALLET_TEST_RPC &&
    !!process.env.TALOS_WALLET_TEST_CONTRACT,
)(
  "eth_call verifies the deployed contract without granting a session",
  async () => {
    const { client } = await setup(
      60,
      process.env.TALOS_WALLET_TEST_CONTRACT as Hex,
    );
    expect(
      await client.verifyViaContract(process.env.TALOS_WALLET_TEST_RPC!),
    ).toBe(true);
    expect(client.canRun).toBe(false);
  },
);
