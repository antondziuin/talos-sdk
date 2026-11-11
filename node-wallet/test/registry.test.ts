import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { decodeFunctionData, encodeAbiParameters, encodeFunctionResult, keccak256, toHex, type Hex } from "viem";
import { RegistryLicenseClient } from "../src/registry-client.js";
import { registryAbi, type RegistryLicenseManifest } from "../src/registry-protocol.js";

const address = (byte: string) => ("0x" + byte.repeat(20)) as Hex;
const id = (byte: string) => ("0x" + byte.repeat(32)) as Hex;
const zero = id("00");
const trust = { chainId: 11155111, contract: address("05"), issuer: address("01"), productId: id("07") };
const manifest: RegistryLicenseManifest = {
  v: 1, kind: "talos-registry-license", chain_id: trust.chainId,
  contract: trust.contract, issuer: trust.issuer, product_id: trust.productId,
  license_id: id("08"), holder: address("02"), entitlements: Buffer.from('{"pro":true,"seats":2}').toString("base64url"),
};
const directories: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

async function setup(rpcUrls = ["https://rpc-one.example", "https://rpc-two.example"], chainId = trust.chainId) {
  const dir = mkdtempSync(join(tmpdir(), "talos-registry-"));
  directories.push(dir);
  const path = join(dir, "state");
  const state = {
    chain: toHex(chainId), timestamp: Math.floor(Date.now() / 1000) - 2, number: 100n, blockHash: id("aa"),
    latest: new Map<string, bigint[]>(), history: new Map<bigint, { hash: Hex; timestamp: number }>(), latestHash: undefined as Hex | undefined, snapshotReorg: false,
    holder: manifest.holder, deviceKey: zero, notBefore: BigInt(Math.floor(Date.now() / 1000) - 10),
    expiresAt: BigInt(Math.floor(Date.now() / 1000) + 3600), revision: 1n, status: 1,
    hash: keccak256(toHex(Buffer.from(manifest.entitlements, "base64url"))),
    contractCode: "0x6000", version: 1n, valid: true,
    unavailable: new Set<string>(), rpcError: 0, httpStatus: 200,
  };
  const calls: { url: string; method: string; params: unknown[] }[] = [];
  const http = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const { method, params } = JSON.parse(init!.body as string), url = String(input);
    calls.push({ url, method, params });
    if (state.unavailable.has(url)) throw new Error("network down");
    if (state.httpStatus !== 200) return new Response("{}", { status: state.httpStatus });
    if (state.rpcError) return Response.json({ jsonrpc: "2.0", id: 1, error: { code: state.rpcError, message: "fixture" } });
    let result;
    if (method === "eth_chainId") result = state.chain;
    else if (method === "eth_getBlockByNumber") {
      const number = params[0] === "latest" ? state.latest.get(url)?.shift() ?? state.number : BigInt(params[0]);
      const head = state.history.get(number) ?? { hash: state.blockHash, timestamp: state.timestamp };
      result = { number: toHex(number), hash: params[0] === "latest" ? state.latestHash ?? head.hash : head.hash, timestamp: toHex(head.timestamp) };
    }
    else if (method === "eth_getCode") result = state.contractCode;
    else if (method === "eth_call") {
      const { functionName, args } = decodeFunctionData({ abi: registryAbi, data: params[0].data });
      expect(params[0].to).toBe(trust.contract);
      if (functionName === "registryVersion") result = encodeFunctionResult({ abi: registryAbi, functionName, result: state.version });
      else if (functionName === "getLicense") {
        expect(args).toEqual([trust.issuer, trust.productId, manifest.license_id]);
        result = encodeFunctionResult({ abi: registryAbi, functionName, result: [state.holder, state.deviceKey, state.notBefore, state.expiresAt, state.hash, state.revision, state.status] });
      } else if (functionName === "checkLicense") {
        expect(args).toEqual([trust.issuer, trust.productId, manifest.license_id, manifest.holder, state.deviceKey, state.hash]);
        result = encodeAbiParameters([{ type: "bool" }], [state.valid]);
        if (state.snapshotReorg) state.blockHash = id("bb");
      } else throw new Error("unexpected wallet mutation");
    } else throw new Error("unexpected API request");
    return Response.json({ jsonrpc: "2.0", id: 1, result });
  });
  const options = { ...trust, chainId, rpcUrls, statePath: path, fingerprintComponents: { fixture: "one" }, fetch: http };
  const client = await RegistryLicenseClient.create(options);
  state.deviceKey = client.deviceKey;
  client.importLicense({ ...manifest, chain_id: chainId });
  return { client, state, calls, options, path, http };
}

it("creates a holder-wallet binding request and encrypts a stable, fingerprint-bound key", async () => {
  const s = await setup();
  const tx = s.client.createDeviceBinding();
  expect(tx).toMatchObject({ chainId: 11155111, to: trust.contract, expectedHolder: manifest.holder, value: 0n });
  expect(decodeFunctionData({ abi: registryAbi, data: tx.data })).toEqual({ functionName: "bindDevice", args: [trust.issuer, trust.productId, manifest.license_id, s.client.deviceKey] });
  const bytes = readFileSync(s.path);
  expect(bytes.subarray(0, 4).toString()).toBe("TLS1");
  expect(bytes.toString()).not.toContain("machineKey");
  expect((await RegistryLicenseClient.create(s.options)).deviceKey).toBe(s.client.deviceKey);
  expect((await RegistryLicenseClient.create({ ...s.options, fingerprintComponents: { fixture: "other" } })).deviceKey).not.toBe(s.client.deviceKey);
  expect(s.calls).toHaveLength(0);
});

it("reads all contract data at the same fresh block and never caches authorization", async () => {
  const s = await setup();
  const result = await s.client.validate();
  expect(result).toMatchObject({ isValid: true, revision: 1, blockNumber: 100n, expiresAt: Number(s.state.expiresAt), entitlements: { pro: true, seats: 2 } });
  for (const call of s.calls.filter(c => ["eth_getCode", "eth_call"].includes(c.method))) expect(call.params.at(-1)).toBe("0x64");
  expect(await s.client.getEntitlement("pro")).toBe(true);
  expect(await s.client.getEntitlement("constructor")).toBeUndefined();
  s.state.status = 3;
  const before = s.calls.length;
  await expect(s.client.requireValidLicense()).rejects.toThrow("license_revoked");
  expect(s.calls.length).toBeGreaterThan(before);
  expect(s.calls.every(c => c.url === s.options.rpcUrls[0])).toBe(true);
});

it("uses RPC fallback for a transport failure and fails closed when every RPC is unavailable", async () => {
  const s = await setup();
  s.state.unavailable.add(s.options.rpcUrls[0]);
  expect((await s.client.validate()).isValid).toBe(true);
  expect(s.calls.some(c => c.url === s.options.rpcUrls[1])).toBe(true);
  s.state.unavailable.add(s.options.rpcUrls[1]);
  await expect(s.client.validate()).rejects.toThrow("registry_rpc_unavailable");
  await expect(s.client.getEntitlement("pro")).rejects.toThrow("registry_rpc_unavailable");
});

it.each([429, 503])("falls back after transient HTTP %s", async (status) => {
  const s = await setup();
  s.http.mockImplementationOnce(async () => new Response("{}", { status }));
  expect((await s.client.validate()).isValid).toBe(true);
  expect(s.calls.some(c => c.url === s.options.rpcUrls[1])).toBe(true);
});

it("falls back when the response body fails during transfer", async () => {
  const s = await setup();
  const response = new Response();
  vi.spyOn(response, "text").mockRejectedValue(new Error("connection reset"));
  s.http.mockImplementationOnce(async () => response);
  expect((await s.client.validate()).isValid).toBe(true);
  expect(s.calls.some(c => c.url === s.options.rpcUrls[1])).toBe(true);
});

it.each([
  ["missing", "license_missing"], ["suspended", "license_suspended"], ["revoked", "license_revoked"],
  ["expired", "license_expired"], ["future", "license_not_started"], ["unbound", "device_not_bound"],
  ["device", "wrong_device"], ["holder", "wrong_license_holder"], ["entitlements", "invalid_entitlements_hash"],
  ["chain", "wrong_rpc_chain"], ["version", "wrong_registry_version"], ["code", "registry_contract_missing"],
  ["check", "registry_license_rejected"], ["revert", "registry_rpc_rejected"],
])("fails closed on %s without consulting a second provider", async (scenario, error) => {
  const s = await setup();
  switch (scenario) {
    case "missing": s.state.status = 0; break;
    case "suspended": s.state.status = 2; break;
    case "revoked": s.state.status = 3; break;
    case "expired": s.state.expiresAt = BigInt(Math.floor(Date.now() / 1000)); break;
    case "future": s.state.notBefore = BigInt(Math.floor(Date.now() / 1000) + 10); break;
    case "unbound": s.state.deviceKey = zero; break;
    case "device": s.state.deviceKey = id("03"); break;
    case "holder": s.state.holder = address("03"); break;
    case "entitlements": s.state.hash = zero; break;
    case "chain": s.state.chain = "0x1"; break;
    case "version": s.state.version = 2n; break;
    case "code": s.state.contractCode = "0x"; break;
    case "check": s.state.valid = false; break;
    case "revert": s.state.rpcError = 3; break;
  }
  await expect(s.client.validate()).rejects.toThrow(error);
  expect(s.calls.every(c => c.url === s.options.rpcUrls[0])).toBe(true);
});

it("rejects stale blocks, and a previously seen later block cannot be rolled back", async () => {
  const s = await setup();
  s.state.timestamp -= 301;
  await expect(s.client.validate()).rejects.toThrow("stale_rpc_block");
  s.state.timestamp = Math.floor(Date.now() / 1000) - 1;
  await s.client.validate();
  s.state.timestamp--;
  await expect(s.client.validate()).rejects.toThrow("rpc_block_rollback");
});

it("supports perpetual records and observes renewal and changed rights on the next read", async () => {
  const s = await setup();
  s.state.expiresAt = 0n;
  expect((await s.client.validate()).expiresAt).toBeNull();
  s.state.revision++;
  s.state.expiresAt = BigInt(Math.floor(Date.now() / 1000) + 7200);
  expect((await s.client.validate()).revision).toBe(2);
  const next = { ...manifest, entitlements: Buffer.from('{"pro":false}').toString("base64url") };
  s.client.importLicense(next);
  await expect(s.client.validate()).rejects.toThrow("invalid_entitlements_hash");
  s.state.hash = keccak256(toHex(Buffer.from(next.entitlements, "base64url")));
  expect(await s.client.getEntitlement("pro")).toBe(false);
});

it("supports pinned Base Mainnet while rejecting other registry networks", async () => {
  const s = await setup(undefined, 8453);
  expect((await s.client.validate()).isValid).toBe(true);
  expect(() => s.client.importLicense(manifest)).toThrow("invalid_registry_manifest");
  await expect(RegistryLicenseClient.create({ ...s.options, chainId: 1 })).rejects.toThrow("invalid_registry_configuration");
});

it("retries a single provider once for one-block lag without reading a lower license snapshot", async () => {
  const s = await setup(["https://rpc-one.example"]);
  await s.client.validate(); s.calls.length = 0;
  s.state.latest.set(s.options.rpcUrls[0], [99n, 100n]);
  expect((await s.client.validate()).blockNumber).toBe(100n);
  expect(s.calls.filter(c => c.method === "eth_call").every(c => c.params.at(-1) === "0x64")).toBe(true);
  expect(s.calls.filter(c => c.method === "eth_getBlockByNumber" && c.params[0] === "latest")).toHaveLength(2);
});

it("prefers the next pinned RPC to a one-block lagging provider", async () => {
  const s = await setup(); await s.client.validate(); s.calls.length = 0;
  s.state.latest.set(s.options.rpcUrls[0], [99n]);
  expect((await s.client.validate()).blockNumber).toBe(100n);
  expect(s.calls.filter(c => c.method === "eth_call").every(c => c.url === s.options.rpcUrls[1])).toBe(true);
});

it("persists the head of refused revocation and rejects stale active records after restart", async () => {
  const s = await setup(); await s.client.validate();
  s.state.history.set(100n, { hash: s.state.blockHash, timestamp: s.state.timestamp });
  s.state.number = 101n; s.state.blockHash = id("bb"); s.state.status = 3; s.state.revision = 2n;
  await expect(s.client.validate()).rejects.toThrow("license_revoked");
  const restarted = await RegistryLicenseClient.create(s.options); restarted.importLicense(manifest);
  s.state.status = 1; s.state.latest.set(s.options.rpcUrls[0], [100n]); s.state.latest.set(s.options.rpcUrls[1], [100n]);
  await expect(restarted.validate()).rejects.toThrow("rpc_block_lag");
});

it("recovers a canonical reorg at the known height only with a compatible license revision", async () => {
  const s = await setup(); await s.client.validate();
  s.state.blockHash = id("bb"); s.state.timestamp--; s.state.revision = 2n;
  expect((await s.client.validate()).blockHash).toBe(id("bb"));
  expect((await s.client.validate()).revision).toBe(2);
  s.state.blockHash = id("cc"); s.state.revision = 1n;
  await expect(s.client.validate()).rejects.toThrow("registry_reorg_conflict");
});

it("never revives an observed terminal revocation under a reorg, including after restart", async () => {
  const s = await setup(); s.state.status = 3; s.state.revision = 2n;
  await expect(s.client.validate()).rejects.toThrow("license_revoked");
  s.state.blockHash = id("bb"); s.state.status = 1; s.state.revision = 3n;
  const restarted = await RegistryLicenseClient.create(s.options); restarted.importLicense(manifest);
  await expect(restarted.validate()).rejects.toThrow("license_revoked");
});

it("a missing lower-revision record remains an authoritative refusal and advances the head", async () => {
  const s = await setup(); await s.client.validate(); s.calls.length = 0;
  s.state.history.set(100n, { hash: s.state.blockHash, timestamp: s.state.timestamp });
  s.state.number = 101n; s.state.blockHash = id("bb"); s.state.status = 0; s.state.revision = 0n;
  await expect(s.client.validate()).rejects.toThrow("license_missing");
  expect(s.calls.every(c => c.url === s.options.rpcUrls[0])).toBe(true);
  s.state.status = 1; s.state.revision = 1n;
  s.state.latest.set(s.options.rpcUrls[0], [100n]); s.state.latest.set(s.options.rpcUrls[1], [100n]);
  await expect(s.client.validate()).rejects.toThrow("rpc_block_lag");
});

it("rejects a snapshot that changes canonically during the contract reads", async () => {
  const s = await setup(["https://rpc-one.example"]); s.state.snapshotReorg = true;
  await expect(s.client.validate()).rejects.toThrow("rpc_snapshot_reorg");
  s.state.snapshotReorg = false; s.state.blockHash = id("aa");
  expect((await s.client.validate()).blockHash).toBe(id("aa"));
});

it.each(["conflicting header", "higher block with older time"])("rejects inconsistent canonical RPC history: %s", async scenario => {
  const s = await setup(["https://rpc-one.example"]); await s.client.validate(); s.calls.length = 0;
  if (scenario === "conflicting header") s.state.latestHash = id("bb");
  else {
    s.state.history.set(100n, { hash: s.state.blockHash, timestamp: s.state.timestamp });
    s.state.number = 101n; s.state.blockHash = id("bb"); s.state.timestamp--;
  }
  await expect(s.client.validate()).rejects.toThrow(scenario === "conflicting header" ? "rpc_snapshot_reorg" : "rpc_block_rollback");
  expect(s.calls.some(c => c.method === "eth_call")).toBe(false);
});

it.each(["issuer", "product", "contract", "chain", "entitlements"])("rejects a manifest with untrusted %s before any RPC", async (field) => {
  const s = await setup();
  const changed = { ...manifest };
  if (field === "issuer") changed.issuer = address("03");
  if (field === "product") changed.product_id = id("03");
  if (field === "contract") changed.contract = address("03");
  if (field === "chain") changed.chain_id = 1;
  if (field === "entitlements") changed.entitlements = "%%%";
  expect(() => s.client.importLicense(changed)).toThrow("invalid_registry_manifest");
  expect(s.calls).toHaveLength(0);
});
