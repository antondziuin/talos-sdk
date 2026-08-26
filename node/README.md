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

// The activation is stored on this machine, so the second launch onwards has
// nothing to ask the user for.
const state = talos.isActivated
  ? await talos.validate()              // machine-bound signed decision
  : await talos.activate(userEnteredLicenseKey);
if (!state.isValid) promptForKey();

if (talos.isFeatureEnabled("pdf-export")) enablePdfMenu();
const seats = Number(talos.current?.getEntitlement("seats") ?? 1);
```

## The machine binding is persistent

`activate` binds this machine and the SDK writes that binding to a per-product
file under the OS user-data directory. A `TalosClient` restores it in its
constructor, so `talos.isActivated` answers the startup question — prompt for a
key, or go straight to `validate()` — and the user enters their key once, not
once per launch.

`activate()` is safe to call on every start: when a binding for the same key is
already held it **re-validates** instead of re-activating. That is not just an
optimisation. Re-activating rotates the activation secret, so a second copy of
your app on the same machine would knock the first one out; and `activate` is
the one client route refused while the vendor's own Talos account is suspended,
so re-activating on every launch would take *your* paying users offline over
*your* billing dispute. It falls back to a real activation when the stored
binding is genuinely gone — the seat was released from the portal, or the secret
was rotated elsewhere.

`deactivate()` forgets the binding on disk as well as in memory.

Set `statePath` to choose the file, or `persistState: false` for a process that
should not leave a licence on disk (a test, a short-lived worker) — at the cost
of everything in the paragraph above.

The file is encrypted with a key derived from a stable machine identifier, but
treat that as tamper-evidence and resistance to casual copying, **not** secrecy:
whoever owns the machine can derive the same key. What actually stops a copied
state file is the server — it resolves a machine by fingerprint and demands the
activation secret, so the file does not work on a different computer. A corrupt
or unreadable file is treated as "not activated yet", never as an error: a
damaged cache costs a re-activation, not a failed launch.

## Offline and grace

`validate()` is online-first and offline-tolerant. When the server answers, that
answer wins and is cached. When it cannot be reached, the last verified verdict
is honoured until the policy's `offline_grace_hours` runs out, so a laptop on a
plane keeps working instead of losing the licensed application the moment the
network does.

```ts
const state = await talos.validate();
if (state.isOffline) showBanner("Working offline — checked in " + ago(state.graceUntil));
switch (state.decision) {
  case "valid": break;
  case "grace_expired": requireConnection(); break;   // offline too long
  case "clock_tampered": requireConnection(); break;  // the clock moved back
  default: showLicenceProblem(state.decision);
}
```

What is *not* cached matters as much. **A status code from the server is an
answer** — "revoked", "no such machine", "tenant suspended" — and is never
masked by the cache; falling back there would turn every negative verdict into
hours of grace, which is the opposite of its purpose. Only the absence of an
answer falls back: a dead network, or a reply that fails signature verification
(a garbled or forged response tells you nothing, so it is treated as
unreachable — never as valid).

Four things bound the cached verdict, and each closes a specific hole:

- it is **re-verified under the pinned key** on every use, so editing the state
  file achieves nothing;
- its `fph` claim must be *this* machine, so copying the file to a second
  computer and pulling the network cable does not licence it;
- the licence's own expiry is re-checked, so a cached "valid" cannot outlive
  the subscription it was issued under;
- and a **persistent server-time high-water mark** — the highest signed server
  clock ever seen — is compared against the local clock. Without it, winding the
  system clock back would renew the grace window forever. A monotonic timer is
  not a substitute: it resets on reboot and on a VM snapshot restore, which is
  exactly the case that matters. A clock behind the mark reports
  `clock_tampered`, which is deliberately distinct from `expired` — nothing has
  run out, the machine is lying about the time.

The anchor-signed keyset is cached alongside it, so the whole chain verifies
offline against a root the network cannot influence: the anchor is compiled into
your app, the keyset is signed by it, and the validation token is signed by a key
it lists.

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

## Heartbeats & monitoring

```ts
// Periodically while the app runs (default cadence is policy-driven, ~10 min):
setInterval(() => void talos.heartbeat().catch(() => {}), 10 * 60_000);
```

A heartbeat refreshes this machine's last-seen state, returns the current
**signed** decision (so a revocation reaches the app within one interval), and
feeds the developer portal's monitoring — active installs and version adoption.
It reports only the app version and OS/arch; no IP address is stored.

## Hardware changes

The SDK identifies the machine by a set of component hashes (never the raw
identifiers — each is HMAC'd with a product-scoped key before it is sent). If
the policy uses tolerant matching, a machine that replaces a disk or reinstalls
the OS keeps its seat instead of forcing the user through a re-activation.

**Node's reach is limited.** With no native dependencies and no subprocesses,
this SDK can read a stable machine identity on Linux but not on Windows or
macOS, so those hosts fall back to exact matching: change a NIC and the user
re-activates. If your application can do better — an Electron native module, or
an id you already hold — pass it in and the server will use it:

```ts
const talos = new TalosClient({
  productToken: "tpt_…",
  anchorPublicKey: "…",
  serverUrl: "https://api.talos.dev",
  fingerprintComponents: { machine_guid: myNativeModule.machineId() },
});
```

The value must be stable for the life of the install — one that changes per
launch reports a hardware change on every launch. See
[docs/FINGERPRINT.md](../../docs/FINGERPRINT.md) for the recognised ids, the
per-platform coverage table, and the drift budget that bounds all of this.

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
