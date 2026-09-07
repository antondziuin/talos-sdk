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

## Supplying your own `fetch`

`options.fetch` replaces the global one for **every** network call, artifact
downloads included — so a corporate proxy, a custom CA bundle, request logging
or a test double applies uniformly. It must return `{ status, text(),
arrayBuffer() }`; `headers` and `body` are optional, and when the implementation
provides a streaming `body` the artifact download meters it against the signed
manifest's size instead of buffering first.

## Licensing calls have a deadline

`options.httpTimeoutMs` (default 10000, `0` disables) bounds every licensing
call. Node's `fetch` has none of its own, so without it a server that accepts
the connection and then says nothing leaves `activate()` or `validate()` pending
forever — which in a desktop application is a splash screen that never goes
away, on the one code path a user cannot skip.

A timeout surfaces as a `TalosError`, deliberately: `validate()` treats network
failure as the grace-period case, and an abort arriving as something else would
stop the application instead of letting it keep running offline.

It does **not** cap `downloadUpdate`. A total-duration limit on a
multi-megabyte artifact is a size limit disguised as a safeguard — the same ten
seconds that is generous for a licensing call fails every download on a slow
connection. That one is bounded by the signed manifest's `size`.

An injected `fetch` receives the `signal` and is expected to honour it; one that
ignores it has no timeout.

## The licence key is not kept

After activation the SDK holds no licence key — not in memory, not in the state
file. The server resolves the licence from the per-machine activation secret,
which is what these calls authenticate with anyway, so the key was only a lookup
value travelling beside the credential.

That matters because the state file lives on a disk the user does not solely
control. It is encrypted, but with material any process on that machine can
read; a plaintext licence key in it is a credential-shaped file, and a licence
key works anywhere. A machine-bound secret does not.

What is kept is a SHA-256 of the key, for one thing only: activating twice with
the same key validates instead of spending a second seat. It is accepted by
nothing — the server matches an HMAC under a pepper no client has seen.

A state file written by an older version is upgraded on first read, so nobody
re-activates to get this. And `license_key` is still accepted by every route, so
an application shipped against an older SDK keeps working unchanged.

## The machine binding is persistent

`activate` binds this machine and the SDK writes that binding to a per-product
file under the OS user-data directory. A `TalosClient` restores it in its
constructor, so `talos.isActivated` answers the startup question — prompt for a
key, or go straight to `validate()` — and the user enters their key once, not
once per launch.

That file is `%LOCALAPPDATA%\Talos\<slot>\state.bin` on Windows,
`~/Library/Application Support/Talos/<slot>/state.bin` on macOS,
`$XDG_DATA_HOME/talos/<slot>/state.bin` (or `~/.local/share/...`) on Linux —
where `<slot>` is a hash of the product token, and the same three paths the C#
SDK uses, so one product cannot end up with two bindings in two places.

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

## Heartbeats, monitoring, and cadence

```ts
talos.startCheckIns({
  onState: (s) => updateUi(s),
  onError: (e) => console.warn("check-in failed", e),
});
// On shutdown:
talos.stopCheckIns();
```

One background loop, driven by the **policy** rather than by a number you pick:
each tick re-validates once the signed `reval_after` has passed, and otherwise
sends a heartbeat at the signed `heartbeat_interval_s`. Change the policy in the
portal and deployed apps follow — which is the point, because that interval is
both the telemetry rate and the upper bound on how long a revocation takes to
reach an install. Both values come from the signed claims, never the response
envelope, so nobody in the middle can tell a fleet to check in less often.

Running the loop is also what keeps the offline cache fresh, so an app that
starts it stays inside its grace window without scheduling anything itself.

A heartbeat refreshes this machine's last-seen state, returns the current
**signed** decision, and feeds the developer portal's monitoring — active
installs and version adoption. It reports only the app version and OS/arch; no
IP address is stored. Call `talos.heartbeat()` directly if you would rather own
the schedule; `talos.heartbeatIntervalSeconds` is the policy's answer once the
first one has been sent.

## Events: the transitions, not the level

```ts
talos.on("gracePeriodStarted", (s) => showOfflineBanner(s.graceUntil));
talos.on("gracePeriodExpired", () => requireConnection());
talos.on("licenseInvalid", (s) => showLicenceProblem(s.decision));
talos.on("clockTamperDetected", () => showClockWarning());
talos.on("updateAvailable", (info) => offerUpdate(info.version));
```

Four of them are licence transitions, each raised **once** on the way in and not again while nothing
changes: an application offline for a week gets one `gracePeriodStarted`, not
one per check-in. `licenseInvalid` covers the server's own verdicts (`expired`,
`revoked`, `suspended`, `deactivated`, `machine_revoked`, `invalid`) and fires
again when the *reason* changes, because "your subscription lapsed" and "this
machine was revoked" are different things to put in front of a user. The two
grace verdicts are deliberately not folded into it: what ran out there is
permission to keep believing a cached answer, and reporting it as a licence
problem sends the user to support instead of to their network.

`on` returns a function that unsubscribes. Listeners are called synchronously,
from every path that adopts a verdict — `activate`, `validate`, `heartbeat` and
the offline fallback — so a host running its own timer gets the same
transitions. A listener that throws is ignored: these are raised from inside
`validate`, whose own catch treats a throw as an unreachable server, and a
broken banner must not turn a live "revoked" answer into offline grace.

There is deliberately no "grace ended" or "licence recovered" event. That is a
level, and `onState` (or `talos.current`) already carries it on every check-in;
a second way to learn one fact is a second thing to keep in step.

`updateAvailable` is the odd one out: it carries an `UpdateInfo`, not a licence
state, and it is how an application learns about a release **without asking**.
Subscribing to it makes each heartbeat name your `updateChannel` (`stable`
unless you set one), which is what asks the server whether anything is waiting;
on a yes, the SDK runs a real `checkForUpdate` and hands you what that verified
— the signed manifest and this install's own anti-downgrade floor, never the
hint's word. Nothing is asked for and nothing is spent while no listener is
attached, and each release is announced once however long the user puts off
installing it.

## When updates are refused

A maintenance licence that has run out is **not** a licence that has failed.
`validate()` still returns `valid` — the customer keeps the version they bought,
and their application must keep working — and only the update check refuses:

```ts
try {
  const upd = await talos.checkForUpdate();
  if (upd) offerUpdate(upd);
} catch (e) {
  if (e instanceof TalosApiError && e.errorCode === "updates_not_entitled") {
    // Not a licensing failure. Say what it is and what fixes it.
    showNotice("Your maintenance period has ended. The app keeps working; renew to get updates.");
  } else {
    throw e;
  }
}
```

Both mistakes here cost something. Treating the 403 as a licensing error locks a
paying customer out of software they own. Treating it as "no update available"
never tells them their maintenance lapsed, so they find out when they ask why
they are three versions behind — and nobody renews for a reason they were not
given.

The same code arrives on the artifact download, for the same reason: the gate is
the licence's `updates` entitlement, checked on both routes.

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

const upd = await talos.checkForUpdate();
if (upd) {
  // `upd` is built from a manifest signed by the pinned release key. Metadata
  // (version, sha256, size, filename) is trusted; the download URL is not.
  const dest = `/tmp/${upd.artifacts[0].filename}`;
  await talos.downloadUpdate(upd, dest, upd.artifacts[0], ({ bytesReceived, totalBytes }) => {
    showProgress(bytesReceived / totalBytes); // optional; called as the bytes arrive
  });
  // Hand `dest` to your installer / electron-updater. Applying is the app's job.
}
```

The bytes stream to a `.talos-part` file beside the destination, hashed as they
arrive, and are renamed into place only once the hash matches — so a
multi-gigabyte installer is never held in memory, and a download that fails
verification leaves whatever was at `dest` before rather than a truncated file
your updater might run. `totalBytes` is the signed manifest's size, never the
server's `content-length`: a progress bar the download host can drive can be
parked at 100% while bytes are still arriving.

The manifest carries a monotonic `releaseSeq`, and the SDK refuses to surface a
release at or below the highest one this install has been seen running
(**anti-downgrade**). It keeps that mark itself, in the state file: when
`downloadUpdate` fetches a release, the version is remembered, and the next time
a client is constructed with `appVersion` equal to it the mark moves up. So a
server that offers an older build — a rollback, a stale replica, or somebody in
the middle — is answered with `null` and nothing else is needed from you.

Pass `currentReleaseSeq` only when you know something the SDK cannot: a build
installed by a package manager, or a first run after adopting the SDK on a fleet
that is already updated.

Downloaded bytes are verified against the signed manifest's SHA-256, so the
CDN/mirror serving them is untrusted infrastructure.

## Tests

- `npm test` runs the client-side verification tests (no server needed).
- The cross-language **contract test** (`test/contract.test.ts`) runs the SDK
  against a live Rust server; see [`../csharp/contract.sh`](../csharp/contract.sh).
