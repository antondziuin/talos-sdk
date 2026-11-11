// Local-only real API + publisher worker + SDK integration. Fixture codes arrive only on stdin.
import { isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { RegistryLicenseClient } from "../dist/index.js";

export async function runActivationWorkerBridge(fixture) {
  const { apiUrl, productToken, trust, rpcUrl, statePath } = fixture;
  for (const endpoint of [apiUrl, rpcUrl]) {
    const url = new URL(endpoint);
    if (!["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) || !["http:", "https:"].includes(url.protocol) || url.username || url.password)
      throw new Error("Only isolated loopback fixtures are permitted.");
  }
  if (trust.chainId !== 31337) throw new Error("Only local chain 31337 is permitted.");
  const chainResponse = await fetch(rpcUrl, { method: "POST", redirect: "error", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }), signal: AbortSignal.timeout(10000) });
  const chain = await chainResponse.json();
  if (!chainResponse.ok || chain.error || BigInt(chain.result) !== 31337n) throw new Error("Local RPC chain mismatch.");
  const repo = fileURLToPath(new URL("../../../", import.meta.url));
  const rel = relative(repo, resolve(statePath));
  if (!(isAbsolute(rel) || rel === ".." || rel.startsWith(`..${sep}`))) throw new Error("Fixture state must stay outside the repository.");
  let disabledApi = false, claims = 0, polls = 0, rpcReads = 0;
  const options = { ...trust, rpcUrls: [rpcUrl], statePath, activationUrl: apiUrl, productToken,
    fetch: (url, request) => {
      const body = JSON.parse(request.body);
      if (url === rpcUrl) {
        if (!["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_call"].includes(body.method)) throw new Error("The SDK must never submit a transaction.");
        rpcReads++;
      } else if (url === apiUrl.replace(/\/$/, "") + "/v1/client/registry/activate") {
        if (disabledApi) throw new Error("Activation service is deliberately unavailable.");
        claims++;
      } else if (url === apiUrl.replace(/\/$/, "") + "/v1/client/registry/activation-status") {
        if (disabledApi || Object.hasOwn(body, "license_key")) throw new Error("Status must use only the device proof.");
        polls++;
      } else throw new Error("Unexpected SDK endpoint.");
      return fetch(url, request);
    },
  };
  const sdk = await RegistryLicenseClient.create(options);
  const progress = [];
  let activated;
  try { activated = await sdk.activate(fixture.licenseKey, { timeoutMs: 60000, onProgress: item => progress.push(item.status) }); }
  finally { fixture.licenseKey = ""; }
  const checks = [];
  const check = (name, value) => { if (!value) throw new Error("Local automatic activation SDK check failed."); checks.push({ name, passed: true }); };
  check("code activation returned after confirmed fresh chain validation", activated.isValid && activated.entitlements.pro === true && progress.at(-1) === "ready");
  check("one device claim arranged automatic publication", claims === 1 && sdk.isActivated && !sdk.hasPendingActivation);
  disabledApi = true;
  const restored = await RegistryLicenseClient.create(options);
  check("encrypted device identity and public manifest survive restart", restored.isActivated && restored.deviceKey === sdk.deviceKey);
  check("fresh runtime validation works with activation service unavailable", (await restored.requireValidLicense()).isValid);
  check("fresh entitlement lookup uses RPC without Talos", await restored.getEntitlement("pro") === true);
  check("SDK uses only direct read-only RPC after activation", rpcReads >= 12 && claims === 1);
  return { chainId: 31337, contract: trust.contract, blockNumber: String(activated.blockNumber), revision: activated.revision,
    checks, activationRequests: claims, statusPolls: polls, transactionsSentBySdk: 0 };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    let input = "";
    for await (const chunk of process.stdin) { input += chunk; if (Buffer.byteLength(input) > 65536) throw new Error("Fixture too large."); }
    console.log(JSON.stringify(await runActivationWorkerBridge(JSON.parse(input))));
  } catch {
    // Do not print fixture inputs, license codes, device keys, URLs or nested provider errors.
    console.error("Local automatic activation SDK bridge failed."); process.exitCode = 1;
  }
}
