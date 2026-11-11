import { createPublicKey, verify } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, expect, it, vi } from "vitest";
import { collectFingerprint, StateStore } from "@antondziuin/talos-sdk";
import { decodeFunctionData, encodeFunctionResult, keccak256, toHex, type Hex } from "viem";
import { RegistryLicenseClient, type RegistryActivationProgress } from "../src/registry-client.js";
import { registryAbi, type RegistryLicenseManifest } from "../src/registry-protocol.js";

const addr = (b: string) => ("0x" + b.repeat(20)) as Hex;
const id = (b: string) => ("0x" + b.repeat(32)) as Hex;
const token = "tpt_registry_activation_fixture";
const code = "TEST-CODE-ONLY-NEVER-PERSIST";
const job = "12345678-1234-4234-8234-123456789abc";
const manifest: RegistryLicenseManifest = { v: 1, kind: "talos-registry-license", chain_id: 11155111,
  contract: addr("05"), issuer: addr("01"), product_id: id("07"), license_id: id("08"), holder: addr("01"),
  entitlements: Buffer.from('{"pro":true}').toString("base64url") };
const paths: string[] = [];
afterEach(() => { for (const p of paths.splice(0)) rmSync(p, { recursive: true, force: true }); vi.restoreAllMocks(); });

async function setup() {
  const directory = mkdtempSync(join(tmpdir(), "talos-registry-activate-")); paths.push(directory);
  const blockTimestamp = Math.floor(Date.now() / 1000) - 1;
  const state = { pending: false, failed: false, apiOffline: false, chainStatus: 1, badProof: false, hangClaim: false, hangStatus: false,
    readyOnClaim: false, responseManifest: manifest, error: "", pollError: "", claims: 0, polls: 0, deviceKey: id("00"), acceptedCode: code, jobId: job };
  let releaseClaim: ((response: Response) => void) | undefined, releaseStatus: ((response: Response) => void) | undefined;
  const requests: { url: string; body: Record<string, unknown> }[] = [];
  const response = (ready = false) => Response.json({ status: state.failed ? "failed" : ready ? "ready" : "pending",
    activation_id: state.jobId, manifest: state.failed || !ready ? null : state.responseManifest, error: state.failed ? "fixture_worker_error" : null, retry_after_s: 2 });
  const http = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input), body = JSON.parse(init!.body as string);
    requests.push({ url, body });
    if (url.startsWith("https://activation.example")) {
      if (state.apiOffline) throw new Error("private transport detail must never escape");
      const claim = url.endsWith("/activate");
      if (claim) state.claims++; else state.polls++;
      expect(body.product_token).toBe(token);
      expect(body.device_key).toMatch(/^0x[0-9a-f]{64}$/);
      expect(body.proof).toMatch(/^0x[0-9a-f]{128}$/);
      const text = claim
        ? `talos-registry-activation.1.${keccak256(toHex(token))}.${keccak256(toHex(body.license_key.trim()))}.${body.device_key}.${body.request_id.toLowerCase()}`
        : `talos-registry-status.1.${keccak256(toHex(token))}.${state.jobId}.${body.device_key}`;
      const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(body.device_key.slice(2), "hex")]), format: "der", type: "spki" });
      expect(verify(null, Buffer.from(text), pub, Buffer.from(body.proof.slice(2), "hex"))).toBe(true);
      if (!claim) { expect(body.activation_id).toBe(state.jobId); expect(body).not.toHaveProperty("license_key"); }
      if (state.badProof) return Response.json({ error: "invalid_device_proof" }, { status: 400 });
      const error = state.error || (!claim ? state.pollError : "");
      if (error) return Response.json({ error }, { status: error === "activation_not_found" ? 404 : error === "temporary_unavailable" ? 503 : 409 });
      if (claim && body.license_key !== state.acceptedCode) return Response.json({ error: "license_not_found" }, { status: 404 });
      state.deviceKey = body.device_key;
      if (claim && state.hangClaim) return new Promise(resolve => { releaseClaim = resolve; });
      if (!claim && state.hangStatus) return new Promise(resolve => { releaseStatus = resolve; });
      return response(claim ? state.readyOnClaim : !state.pending);
    }
    expect(url).toBe("https://rpc.example");
    const now = Math.floor(Date.now() / 1000);
    let result;
    if (body.method === "eth_chainId") result = "0xaa36a7";
    else if (body.method === "eth_getBlockByNumber") result = { number: "0x64", timestamp: toHex(blockTimestamp), hash: id("aa") };
    else if (body.method === "eth_getCode") result = "0x6000";
    else if (body.method === "eth_call") {
      const { functionName } = decodeFunctionData({ abi: registryAbi, data: body.params[0].data });
      if (functionName === "registryVersion") result = encodeFunctionResult({ abi: registryAbi, functionName, result: 1n });
      else if (functionName === "getLicense") result = encodeFunctionResult({ abi: registryAbi, functionName,
        result: [manifest.holder, state.deviceKey, BigInt(now - 10), BigInt(now + 3600), keccak256(toHex(Buffer.from(manifest.entitlements, "base64url"))), 2n, state.chainStatus] });
      else if (functionName === "checkLicense") result = encodeFunctionResult({ abi: registryAbi, functionName, result: state.chainStatus === 1 });
      else throw new Error("SDK attempted a wallet transaction");
    } else throw new Error("SDK attempted a non-read-only RPC method");
    return Response.json({ jsonrpc: "2.0", id: 1, result });
  });
  const options = { issuer: manifest.issuer, productId: manifest.product_id, chainId: 11155111, contract: manifest.contract,
    rpcUrls: ["https://rpc.example"], activationUrl: "https://activation.example", productToken: token,
    statePath: join(directory, "state"), fingerprintComponents: { fixture: "activation" }, fetch: http };
  const create = () => RegistryLicenseClient.create(options);
  const client = await create();
  const scope = `wallet-registry:${options.chainId}:${options.contract.toLowerCase()}:${options.issuer.toLowerCase()}:${options.productId.toLowerCase()}`;
  const fp = collectFingerprint(scope, options.fingerprintComponents);
  const store = new StateStore(options.statePath, scope, fp.composite);
  return { client, create, state, requests, store, options, releaseClaim: () => releaseClaim?.(response(true)), releaseStatus: () => releaseStatus?.(response(true)) };
}

it("claims a code with an Ed25519 device proof, persists public state, then uses RPC without Talos", async () => {
  const s = await setup(); const progress: RegistryActivationProgress["status"][] = [];
  const result = await s.client.activate("  " + code + "  ", { onProgress: p => progress.push(p.status) });
  expect(result.isValid).toBe(true); expect(s.state.claims).toBe(1); expect(s.state.polls).toBe(1);
  expect(progress).toEqual(["pending", "validating", "ready"]);
  expect(s.client.isActivated).toBe(true); expect(s.client.hasPendingActivation).toBe(false);
  const saved = s.store.load()!;
  expect(!!saved.registryManifest).toBe(true); expect(saved.registryActivationId).toBeUndefined();
  expect(JSON.stringify(saved).includes(code)).toBe(false);
  expect(JSON.stringify(saved).includes(keccak256(toHex(code)))).toBe(false);
  s.state.apiOffline = true; const before = s.requests.filter(r => r.url.startsWith("https://activation")).length;
  const restored = await s.create(); expect(restored.isActivated).toBe(true); expect(restored.deviceKey).toBe(s.client.deviceKey);
  expect(await restored.getEntitlement("pro")).toBe(true);
  expect((await restored.validate()).isValid).toBe(true);
  expect(s.requests.filter(r => r.url.startsWith("https://activation")).length).toBe(before);
});

it("persists a pending job across timeout and restart, then resumes without transmitting the code again", async () => {
  const s = await setup(); s.state.pending = true;
  await expect(s.client.activate(code, { timeoutMs: 100 })).rejects.toThrow("registry_activation_timeout");
  expect(s.client.isActivated).toBe(false); expect(s.client.hasPendingActivation).toBe(true);
  expect(s.store.load()?.registryActivationId).toBe(job);
  expect(JSON.stringify(s.store.load()).includes(code)).toBe(false);
  const restored = await s.create(); expect(restored.hasPendingActivation).toBe(true); s.state.pending = false;
  expect((await restored.resumeActivation()).isValid).toBe(true);
  expect(s.state.claims).toBe(1);
  expect(s.requests.filter(r => r.url.endsWith("activation-status")).every(r => !("license_key" in r.body))).toBe(true);
});

it("forgets an unknown persisted activation, rethrows its error, then activates a new code after another restart", async () => {
  const s = await setup(); s.state.pending = true; const abort = new AbortController();
  await expect(s.client.activate(code, { signal: abort.signal, onProgress: () => abort.abort() })).rejects.toThrow("registry_activation_aborted");
  expect(s.store.load()?.registryActivationId).toBe(job);
  const resumed = await s.create(); expect(resumed.hasPendingActivation).toBe(true); s.state.error = "activation_not_found";
  await expect(resumed.resumeActivation()).rejects.toMatchObject({ code: "activation_not_found" });
  expect(resumed.hasPendingActivation).toBe(false); expect(resumed.isActivated).toBe(false);
  expect(s.store.load()?.registryActivationId).toBeUndefined(); expect(s.store.load()?.registryManifest).toBeUndefined();
  const restarted = await s.create(); expect(restarted.hasPendingActivation).toBe(false); expect(restarted.deviceKey).toBe(s.client.deviceKey);
  await expect(restarted.resumeActivation()).rejects.toThrow("activation_code_required");
  const replacementCode = "NEW-SYNTHETIC-CODE-ONLY";
  s.state.error = ""; s.state.pending = false; s.state.acceptedCode = replacementCode;
  s.state.jobId = "87654321-4321-4321-8321-cba987654321"; s.state.responseManifest = { ...manifest, license_id: id("09") };
  expect((await restarted.activate(replacementCode)).isValid).toBe(true); expect(s.state.claims).toBe(2);
  const finalRestart = await s.create(); expect(finalRestart.isActivated).toBe(true); expect(finalRestart.hasPendingActivation).toBe(false);
  expect((await finalRestart.requireValidLicense()).isValid).toBe(true);
  expect(s.requests.filter(request => request.url.endsWith("/activate")).map(request => request.body.license_key)).toEqual([code, replacementCode]);
  const saved = JSON.stringify(s.store.load()); expect(saved).not.toContain(code); expect(saved).not.toContain(replacementCode);
});

it("clears a newly saved job when a poll in the same activate call reports it missing", async () => {
  const s = await setup(); s.state.pollError = "activation_not_found";
  await expect(s.client.activate(code)).rejects.toMatchObject({ code: "activation_not_found" });
  expect(s.state.claims).toBe(1); expect(s.state.polls).toBe(1); expect(s.client.hasPendingActivation).toBe(false);
  expect(s.store.load()?.registryActivationId).toBeUndefined(); expect(s.store.load()?.registryManifest).toBeUndefined();
  const restarted = await s.create(); expect(restarted.deviceKey).toBe(s.client.deviceKey); expect(restarted.hasPendingActivation).toBe(false);
  s.state.acceptedCode = "REPLACEMENT-SYNTHETIC-CODE"; s.state.jobId = "87654321-4321-4321-8321-cba987654321"; s.state.pollError = "";
  expect((await restarted.activate(s.state.acceptedCode)).isValid).toBe(true); expect(s.state.claims).toBe(2);
});

it("keeps a newly saved job across a transient poll failure instead of making another claim", async () => {
  const s = await setup(); s.state.pollError = "temporary_unavailable";
  await expect(s.client.activate(code)).rejects.toThrow("registry_activation_http_503");
  expect(s.client.hasPendingActivation).toBe(true); expect(s.store.load()?.registryActivationId).toBe(job);
  s.state.pollError = "";
  expect((await (await s.create()).resumeActivation()).isValid).toBe(true); expect(s.state.claims).toBe(1);
});

it("cancellation preserves a pending job and never uses the abort reason as an error message", async () => {
  const s = await setup(); s.state.pending = true; const controller = new AbortController();
  await expect(s.client.activate(code, { signal: controller.signal, onProgress: () => controller.abort(code) })).rejects.toThrow("registry_activation_aborted");
  expect(s.client.isActivated).toBe(false); expect(s.client.hasPendingActivation).toBe(true);
  s.state.pending = false; expect((await (await s.create()).resumeActivation()).isValid).toBe(true);
  expect(s.state.claims).toBe(1);
});

it("rejects an already aborted call without sending a code", async () => {
  const s = await setup(), controller = new AbortController(); controller.abort(code);
  await expect(s.client.activate(code, { signal: controller.signal })).rejects.toThrow("registry_activation_aborted");
  expect(s.requests).toHaveLength(0);
});

it("a late ready reply after timeout cannot import or persist a manifest", async () => {
  const s = await setup(); s.state.hangClaim = true;
  await expect(s.client.activate(code, { timeoutMs: 25 })).rejects.toThrow("registry_activation_timeout");
  s.releaseClaim(); await new Promise(resolve => setTimeout(resolve, 10));
  expect(s.client.isActivated).toBe(false); expect(s.store.load()?.registryManifest).toBeUndefined();
});

it.each(["wrong-code", "proof", "other-device", "failed"])("fails closed for %s", async scenario => {
  const s = await setup();
  if (scenario === "proof") s.state.badProof = true;
  if (scenario === "other-device") s.state.error = "activation_already_bound";
  if (scenario === "failed") s.state.failed = true;
  const expected = { "wrong-code": "license_not_found", proof: "invalid_device_proof", "other-device": "activation_already_bound", failed: "registry_activation_failed" }[scenario];
  await expect(s.client.activate(scenario === "wrong-code" ? "OTHER-SYNTHETIC-CODE" : code)).rejects.toThrow(expected);
  expect(s.client.isActivated).toBe(false); expect(s.client.hasPendingActivation).toBe(false);
  expect(s.requests.every(r => r.url.startsWith("https://activation.example"))).toBe(true);
});

it("a ready API response cannot override an invalid chain license", async () => {
  const s = await setup(); s.state.chainStatus = 3;
  const progress: string[] = [];
  await expect(s.client.activate(code, { onProgress: p => progress.push(p.status) })).rejects.toThrow("license_revoked");
  expect(progress).not.toContain("ready");
  expect(s.client.isActivated).toBe(false); expect(s.client.hasPendingActivation).toBe(true);
  expect(s.store.load()?.registryManifest).toBeUndefined();
  const restored = await s.create(); expect(restored.isActivated).toBe(false); expect(restored.hasPendingActivation).toBe(true);
  await expect(restored.resumeActivation()).rejects.toThrow("license_revoked");
  expect(s.state.claims).toBe(1);
});

it("a ready job with lagging RPC resumes after restart and commits the manifest only after chain confirmation", async () => {
  const s = await setup(); s.state.chainStatus = 0;
  await expect(s.client.activate(code)).rejects.toThrow("license_missing");
  expect(s.client.isActivated).toBe(false); expect(s.store.load()?.registryManifest).toBeUndefined();
  const restored = await s.create(); expect(restored.hasPendingActivation).toBe(true); expect(restored.isActivated).toBe(false);
  s.state.chainStatus = 1;
  expect((await restored.resumeActivation()).isValid).toBe(true); expect(s.state.claims).toBe(1);
  expect(restored.isActivated).toBe(true); expect(restored.hasPendingActivation).toBe(false);
  s.state.apiOffline = true;
  expect((await (await s.create()).requireValidLicense()).isValid).toBe(true);
});

it("a candidate waiting on RPC is never exposed as the client's imported license", async () => {
  const s = await setup(); let waiting = false, release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const original = s.options.fetch.getMockImplementation()!;
  s.options.fetch.mockImplementation(async (url, init) => {
    const body = JSON.parse(init!.body as string);
    if (String(url) === "https://rpc.example" && body.method === "eth_call"
      && decodeFunctionData({ abi: registryAbi, data: body.params[0].data }).functionName === "getLicense") {
      waiting = true; await gate;
    }
    return original(url, init);
  });
  const work = s.client.activate(code);
  while (!waiting) await new Promise(resolve => setTimeout(resolve, 1));
  expect(s.client.isActivated).toBe(false); expect(s.client.hasPendingActivation).toBe(true);
  expect(s.store.load()?.registryManifest).toBeUndefined();
  await expect(s.client.validate()).rejects.toThrow("registry_manifest_required");
  release(); expect((await work).isValid).toBe(true); expect(s.client.isActivated).toBe(true);
});

it("refuses a ready manifest outside pinned trust and never persists unexpected secret-shaped fields", async () => {
  const s = await setup(); s.state.responseManifest = { ...manifest, issuer: addr("03") };
  await expect(s.client.activate(code)).rejects.toThrow("invalid_registry_manifest");
  expect(s.store.load()?.registryManifest).toBeUndefined();
  s.state.responseManifest = { ...manifest, license_key: code } as RegistryLicenseManifest;
  await expect(s.client.resumeActivation()).rejects.toThrow("invalid_registry_manifest");
  expect(JSON.stringify(s.store.load()).includes(code)).toBe(false);
});

it("tampered cached public manifests never auto-import outside pinned trust", async () => {
  const s = await setup(); await s.client.activate(code);
  const saved = s.store.load()!; saved.registryManifest = JSON.stringify({ ...manifest, contract: addr("03") }); s.store.save(saved);
  const restored = await s.create(); expect(restored.isActivated).toBe(false);
  await expect(restored.validate()).rejects.toThrow("registry_manifest_required");
});

it("concurrent activation calls share one claim and storage result", async () => {
  const s = await setup();
  const results = await Promise.all([s.client.activate(code), s.client.activate(code)]);
  expect(results.every(r => r.isValid)).toBe(true); expect(s.state.claims).toBe(1);
  expect((await s.create()).isActivated).toBe(true);
});

it("an in-flight activation cannot overwrite a later manual import", async () => {
  const s = await setup(); s.state.hangStatus = true;
  const work = s.client.activate(code);
  while (s.state.polls === 0) await new Promise(resolve => setTimeout(resolve, 1));
  s.client.importLicense({ ...manifest, license_id: id("09") }); s.releaseStatus();
  await expect(work).rejects.toThrow("registry_activation_interrupted");
  expect(s.store.load()?.registryManifest).toBeUndefined();
});

it("sanitizes arbitrary API errors and transport details", async () => {
  const s = await setup(); s.state.error = code;
  await expect(s.client.activate(code)).rejects.toThrow("registry_activation_http_409");
  s.state.error = ""; s.state.apiOffline = true;
  await expect(s.client.activate(code)).rejects.toThrow("registry_activation_unavailable");
});

it("gives Base safe publication a ten-minute default without changing explicit caller deadlines", async () => {
  const s = await setup(); s.state.hangClaim = true;
  const client = await RegistryLicenseClient.create({ ...s.options, chainId: 8453 });
  const timer = vi.spyOn(globalThis, "setTimeout");
  const controller = new AbortController();
  const activation = client.activate(code, { signal: controller.signal });
  expect(timer.mock.calls.some(call => call[1] === 600000)).toBe(true);
  controller.abort(); await expect(activation).rejects.toThrow("registry_activation_aborted");
  timer.mockClear();
  const nextController = new AbortController();
  const next = client.activate(code, { timeoutMs: 1234, signal: nextController.signal });
  expect(timer.mock.calls.some(call => call[1] === 1234)).toBe(true);
  nextController.abort(); await expect(next).rejects.toThrow("registry_activation_aborted");
});

it("fails closed on malformed persisted chain observations", async () => {
  const s = await setup(); await s.client.activate(code);
  const saved = s.store.load()!; saved.registryChainState = '{"v":1,"head":{"number":100,"hash":"0x00","timestamp":1},"licenses":{}}'; s.store.save(saved);
  await expect((await s.create()).validate()).rejects.toThrow("invalid_registry_chain_state");
});
