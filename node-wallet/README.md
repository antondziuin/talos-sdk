# Talos wallet SDK

Seven-day, issuer-signed device certificates for Node.js 18+ and Electron.
`DeviceLicenseClient` renews through your existing Talos API once a day and retries
when connectivity returns. Valid cached certificates allow offline restarts and
work until expiry. Requires `@antondziuin/talos-sdk` ^0.2.0.

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
