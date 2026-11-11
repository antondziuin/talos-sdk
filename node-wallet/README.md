# Talos wallet SDK

Local release preparation: wallet SDK **0.2.0** requires base Node SDK **^0.4.0**.
The published base SDK 0.3.0 does not restore the registry state fields. Build the
local base SDK before this package; package publication is a separate operation.

## Direct on-chain registry

### License code activation

An automatically published policy lets customers enter a license code once.
The SDK signs device proofs with its own encrypted Ed25519 identity; it never
requests a customer wallet, sends an Ethereum transaction, or stores the code.
The publisher's service arranges publication and pays its transaction fees.

```ts
import { RegistryLicenseClient } from '@antondziuin/talos-sdk-wallet';
const client = await RegistryLicenseClient.create({
  issuer: PINNED_ISSUER, productId: PINNED_PRODUCT_ID,
  chainId: 11155111, contract: PINNED_REGISTRY, rpcUrls: [TRUSTED_RPC],
  activationUrl: TRUSTED_TALOS_BASE_URL, productToken: PRODUCT_PUBLIC_TOKEN,
  statePath: DEVICE_STATE_PATH,
});
if (client.isActivated) await client.requireValidLicense();
else if (client.hasPendingActivation) await client.resumeActivation();
else await client.activate(codeEnteredInApplication, {
  timeoutMs: 120000, signal: abortController.signal,
  onProgress: progress => showActivationProgress(progress.status),
});
```

`activate` and `resumeActivation` return only after the service reports ready and
fresh RPC validation succeeds. Progress states are `pending`, `validating`, and
`ready`. Pending activation IDs and public manifests are stored in the encrypted
device state, so a timeout/cancellation can resume without re-entering the code.
`isActivated` means a manifest is present, not that it is currently valid. Check
again before each protected operation. After activation, runtime validation needs
only RPC and keeps working when the activation service is unavailable.

Pin `activationUrl` and `productToken` in the application, alongside the registry
trust anchors. They are not accepted from a customer manifest. Release the updated
base Node SDK together with this wallet SDK so its state loader restores the new
public registry fields. [Runnable code-entry application](../../examples/wallet-license/registry-code.mjs).

Registry mode explicitly supports Base Mainnet (`8453`), Ethereum Sepolia
(`11155111`), and local Anvil (`31337`). Pin a deployed contract and trusted RPCs
for the selected chain; never reuse a Sepolia address on Base. Base publication
waits for the L1 `safe` head, so activation defaults to ten minutes on Base and
two minutes elsewhere. An explicit timeout overrides that default; show pending
progress and resume saved activation after a timeout instead of issuing a new code.
Runtime checks read the latest head for prompt revocations.

The deployed Base `TalosLicenseRegistryV1` is
[`0xf6ea444a6b152ed6c8b63d53a38bb9921ab95c0c`](https://basescan.org/address/0xf6ea444a6b152ed6c8b63d53a38bb9921ab95c0c),
chain `8453` ([deployment transaction](https://basescan.org/tx/0xf95fa58e134f1855cdbc0e1b18cdefdd0752625cdb5689cf4fbdf5be9a077363)).
Issuer and product pins still come from the publisher's integration configuration.

The encrypted device state also records the highest checked block number/hash and
license revision, including authoritative refusals. A provider one block behind
may receive one one-second retry, or the next pinned RPC is tried. Access is never
authorized at a lower head. A changed canonical hash can recover only at the known
height or higher, after a fresh canonical recheck and a nondecreasing license
revision. Conflicting state fails closed (`registry_reorg_conflict`); an observed
terminal revocation cannot become active again through a reorg or restart. RPC
trust and bounded freshness still apply; this is not a consensus or light client.

If a status poll returns `activation_not_found`, the SDK clears only the pending
activation ID and rethrows that error. After restart, the app can ask for a valid
new code using the same encrypted device identity. Temporary service/RPC failures
keep the saved job resumable; they do not trigger another code claim.

### Manual holder binding

`RegistryLicenseClient` checks `TalosLicenseRegistryV1` directly through Ethereum
RPC. Talos prepares a public manifest and unsigned issuer transaction; the issuer
confirms issuance in its wallet and the license holder confirms the device binding.
Runtime validation requires no Talos API, renewal server, or coordinator.

```ts
import { RegistryLicenseClient } from '@antondziuin/talos-sdk-wallet';
const registry = await RegistryLicenseClient.create({
  issuer: PINNED_ISSUER, productId: PINNED_PRODUCT_ID,
  chainId: 11155111, contract: PINNED_REGISTRY,
  rpcUrls: [TRUSTED_SEPOLIA_RPC], statePath: DEVICE_STATE_PATH,
});
registry.importLicense(publicManifest);
// First use: the holder's wallet sends registry.createDeviceBinding();
// wait for its successful receipt before validating.
await registry.requireValidLicense();
if (await registry.getEntitlement<boolean>('pro')) {
  // Perform one bounded protected operation; recheck before releasing its result.
}
```

Pin issuer, product, chain and contract independently of the imported file. Every
validation and entitlement lookup reads fresh chain state, checks the holder,
device key, entitlement hash and expiry, and rejects blocks older than five
minutes. RPC fallback covers transient failures; an authoritative rejection stops
validation. An RPC outage fails closed. There is no offline authorization cache.
Use trusted RPC providers: these reads are not independent blockchain proofs.

One device key is registered per license. The holder can replace it with another
wallet transaction. The SDK stores its generated private device key in the existing
encrypted state format; lost state requires a new binding. Reads use `eth_call`
without transaction gas; issuance, binding, renewal and revocation require gas.
Public manifests and on-chain data must contain no secrets or personal data.
Modified clients and complete key/device clones remain outside software enforcement.

## Seven-day device certificates

Seven-day, issuer-signed device certificates for Node.js 18+ and Electron.
`DeviceLicenseClient` renews through your existing Talos API once a day and retries
when connectivity returns. Valid cached certificates allow offline restarts and
work until expiry. This wallet SDK release requires `@antondziuin/talos-sdk` ^0.4.0.

```ts
import { DeviceLicenseClient } from '@antondziuin/talos-sdk-wallet';
const client = await DeviceLicenseClient.create({
  issuer: PINNED_ISSUER, productId: PINNED_PRODUCT_ID,
  chainId: 8453, contract: PINNED_V2_VERIFIER,
});
await client.importEnrollment(enrollment);
// First use: sign createDeviceAuthorization() with the owner's wallet,
// then acceptDeviceAuthorization(signature).
await client.start();
try {
  client.requireValidCertificate();
  const pro = client.getEntitlement('pro');
  // Check before each protected operation and before releasing its result.
} finally {
  await client.stop();
}
```

Share a persistent statePath across processes on the same device. On connectivity
restoration or wake, call `notifyResume()`. Renewal failures preserve a valid
certificate; they never extend it. A device transfer in the portal stops old
renewals, but the old device can run until its existing certificate expires,
up to 7 days. A copied enrollment alone cannot activate a second device.

Pin trust values in the application. Modified clients and full VM/key/fingerprint
clones are outside the software enforcement boundary. Local checks require no
RPC; optional `verifyViaContract(rpcUrl)` uses a read-only eth_call to V2.

The previous `WalletLicenseClient` remains available for strict coordinator
policies. Package publication and public-chain deployment are separate release steps.

[Full guide](../../docs/WALLET-LICENSES.md) · [Runnable examples](../../examples/wallet-license/)
