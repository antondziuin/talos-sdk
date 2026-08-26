# @talos/sdk (Node.js)

Online-first client SDK for the Talos licensing platform. Node ≥18, **zero
runtime dependencies** (`node:crypto` Ed25519, built-in `fetch`), dual ESM + CJS.

## Quickstart

```ts
import { TalosClient } from "@talos/sdk";

const talos = new TalosClient({
  productToken: "tpt_…",               // from the portal's Integration page
  anchorPublicKey: "base64-anchor-key", // pin THIS — the rotation-safe root
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
verified against the pinned key, so a fake/MITM server cannot forge an acceptable
answer. The SDK ignores any `kid` and enforces `typ`/`aud`/nonce/`exp`/`nbf`. In
Electron, run this in the **main process** and bridge to the renderer over IPC.

**Key rotation (anti-lock-in).** Pin `anchorPublicKey` — the product's immutable
root. The SDK fetches the anchor-signed *keyset* (delivered with activation, or
`await talos.refreshKeyset()`) and learns the current license/release keys from
it. When you rotate a signing key in the portal, deployed apps keep working with
no reconfiguration. (`publicKey`/`releasePublicKey` are still accepted as direct
pins, but they break on the first rotation — prefer the anchor.)

Anti-tamper honesty: JS is patchable — gate premium value on server-returned
*data* (entitlements/config), not client booleans.

## Floating (concurrent) licenses

```ts
// Policy kind "floating" with max_concurrent_seats = N.
try {
  const lease = await talos.acquireLease({
    onLeaseLost: (why) => showBanner(`Seat lost: ${why}`),
  });
  console.log(`seat ${lease.seatsInUse}/${lease.maxSeats}`);
} catch (e) {
  if (e instanceof TalosApiError && e.statusCode === 409) showBusyDialog();
}

// On clean exit:
await talos.releaseLease();
```

The server arbitrates seats atomically, so two instances can never both take the
last one. The seat auto-renews in the background; a crash needs no cleanup —
the lease simply expires and the seat returns to the pool. Re-acquiring with the
same `instanceId` renews rather than consuming a second seat.

## Updates

```ts
const talos = new TalosClient({
  productToken: "tpt_…",
  publicKey: "…",             // license key (activation/validation tokens)
  releasePublicKey: "…",      // release key (update manifests) — separate custody
  serverUrl: "https://api.talos.dev",
});
await talos.activate(licenseKey);

const upd = await talos.checkForUpdate({ currentVersion: "1.0.0", currentReleaseSeq: 41 });
if (upd) {
  // `upd` is built from a manifest signed by the pinned release key. Metadata
  // (version, sha256, size, filename) is trusted; the download URL is not.
  const dest = `/tmp/${upd.artifacts[0].filename}`;
  await talos.downloadUpdate(upd, dest, upd.artifacts[0]); // verifies SHA-256, does NOT apply
  // Hand `dest` to your installer / electron-updater. Applying is the app's job.
}
```

The manifest carries a monotonic `releaseSeq`; pass your installed high-water
mark as `currentReleaseSeq` and the SDK refuses to surface an older-or-equal
release (**anti-downgrade**). Downloaded bytes are verified against the signed
manifest's SHA-256, so the CDN/mirror serving them is untrusted infrastructure.

## Tests

- `npm test` runs the client-side verification tests (no server needed).
- The cross-language **contract test** (`test/contract.test.ts`) runs the SDK
  against a live Rust server; see [`../csharp/contract.sh`](../csharp/contract.sh).
