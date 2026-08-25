# @talos/sdk (Node.js)

Online-first client SDK for the Talos licensing platform. Node ≥18, **zero
runtime dependencies** (`node:crypto` Ed25519, built-in `fetch`), dual ESM + CJS.

## Quickstart

```ts
import { TalosClient } from "@talos/sdk";

const talos = new TalosClient({
  productToken: "tpt_…",             // from the portal's Integration page
  publicKey: "base64-ed25519-key",   // pinned at build time
  serverUrl: "https://api.talos.dev",
  appVersion: "1.4.2",
});

const state = await talos.activate(userEnteredLicenseKey);
if (!state.isValid) promptForKey();

if (talos.isFeatureEnabled("pdf-export")) enablePdfMenu();
const seats = Number(talos.current?.getEntitlement("seats") ?? 1);

// Later / periodically:
const check = await talos.validate();   // machine-bound signed decision
```

Every server response is a Talos-compact token signed by the product key and
verified against the pinned `publicKey`, so a fake/MITM server cannot forge an
acceptable answer. The SDK ignores any `kid` and enforces `typ`/`aud`/nonce/
`exp`/`nbf`. In Electron, run this in the **main process** and bridge to the
renderer over IPC.

Anti-tamper honesty: JS is patchable — gate premium value on server-returned
*data* (entitlements/config), not client booleans.

## Tests

- `npm test` runs the client-side verification tests (no server needed).
- The cross-language **contract test** (`test/contract.test.ts`) runs the SDK
  against a live Rust server; see [`../csharp/contract.sh`](../csharp/contract.sh).
