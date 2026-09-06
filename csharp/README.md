# Talos.Sdk (C#)

Online-first client SDK for the Talos licensing platform. Multi-targets
`netstandard2.0` (reaches .NET Framework 4.6.2+, Unity, Mono) and `net8.0`.
Ed25519 verification via BouncyCastle (pure managed — no native binaries).

## Quickstart

```csharp
using System.Text.Json;
using Talos.Sdk;

// `using`: the client disposes the HttpClient it created for itself. Supply
// your own via TalosOptions.HttpClient and it is left alone — you own it.
using var talos = new TalosClient(new TalosOptions {
    ProductToken = "tpt_…",              // from the portal's Integration page
    PublicKey    = "base64-ed25519-key", // pinned at build time
    ServerUrl    = "https://api.talos.dev",
    AppVersion   = "1.4.2",
});

// The activation is stored on this machine, so the second launch onwards has
// nothing to ask the user for.
LicenseState state = talos.IsActivated
    ? await talos.ValidateAsync()          // machine-bound signed decision
    : await talos.ActivateAsync(userEnteredLicenseKey);
if (!state.IsValid) { /* prompt for a valid key */ }

if (talos.IsFeatureEnabled("pdf-export")) EnablePdfMenu();
int seats = (int)(talos.Current!.GetEntitlementInt("seats") ?? 1);
string tier = talos.Current!.GetEntitlementString("tier") ?? "standard";
// Anything the SDK did not anticipate — a list, an object — comes back as the
// JsonElement it arrived as, rather than as a TryGetProperty call to write.
JsonElement? modules = talos.Current!.GetEntitlement("modules");
```

## Licensing calls have a deadline

`TalosOptions.HttpTimeoutMs` (default 10000, `0` disables) bounds every
licensing call. `HttpClient`'s own default is 100 seconds, which is a very long
time to hold a splash screen on the one code path a user cannot skip — and
setting `HttpClient.Timeout` instead is not an option when the client is shared,
because it belongs to you and would change every other request your application
makes.

A timeout surfaces as a `TalosException` rather than an
`OperationCanceledException`, deliberately: `ValidateAsync` treats network
failure as the grace-period case, and a cancellation arriving there would stop
the application instead of letting it keep running offline. Your *own*
cancellation still arrives as an `OperationCanceledException` — the two are told
apart by whose token was signalled.

It does **not** cap `DownloadUpdateAsync`, for the same reason it does not in
the Node SDK: a total-duration limit on a multi-megabyte artifact is a size
limit disguised as a safeguard. That one is bounded by the signed manifest's
size.

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

`ActivateAsync` binds this machine and the SDK writes that binding to a
per-product file under the OS user-data directory. A `TalosClient` restores it
in its constructor, so `talos.IsActivated` answers the startup question —
prompt for a key, or go straight to `ValidateAsync()` — and the user enters
their key once, not once per launch.

`ActivateAsync` is safe to call on every start: when a binding for the same key
is already held it **re-validates** instead of re-activating. That is not just
an optimisation. Re-activating rotates the activation secret, so a second copy
of your app on the same machine would knock the first one out; and activate is
the one client route refused while the vendor's own Talos account is suspended,
so re-activating on every launch would take *your* paying users offline over
*your* billing dispute. It falls back to a real activation when the stored
binding is genuinely gone — the seat was released from the portal, or the secret
was rotated elsewhere.

`DeactivateAsync` forgets the binding on disk as well as in memory.

Set `StatePath` to choose the file, or `PersistState = false` for a process that
should not leave a licence on disk (a test, a short-lived worker) — at the cost
of everything above.

The file is encrypted (AES-256-GCM, key derived from a stable machine
identifier), but treat that as tamper-evidence and resistance to casual copying,
**not** secrecy: whoever owns the machine can derive the same key. What actually
stops a copied state file is the server — it resolves a machine by fingerprint
and demands the activation secret, so the file does not work on a different
computer. A corrupt or unreadable file is treated as "not activated yet", never
as an error: a damaged cache costs a re-activation, not a failed launch.

## Offline and grace

`ValidateAsync` is online-first and offline-tolerant. When the server answers,
that answer wins and is cached. When it cannot be reached, the last verified
verdict is honoured until the policy's `offline_grace_hours` runs out, so a
laptop on a plane keeps working instead of losing the licensed application the
moment the network does.

```csharp
LicenseState state = await talos.ValidateAsync();
if (state.IsOffline) ShowBanner("Working offline");
switch (state.Decision)
{
    case "valid": break;
    case "grace_expired": RequireConnection(); break;   // offline too long
    case "clock_tampered": RequireConnection(); break;  // the clock moved back
    default: ShowLicenceProblem(state.Decision); break;
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
- the licence's own expiry is re-checked, so a cached "valid" cannot outlive the
  subscription it was issued under;
- and a **persistent server-time high-water mark** — the highest signed server
  clock ever seen — is compared against the local clock. Without it, winding the
  system clock back would renew the grace window forever. A monotonic timer is
  not a substitute: it resets on reboot and on a VM snapshot restore, which is
  exactly the case that matters. A clock behind the mark reports
  `clock_tampered`, deliberately distinct from `expired` — nothing has run out,
  the machine is lying about the time.

The anchor-signed keyset is cached alongside it, so the whole chain verifies
offline against a root the network cannot influence: the anchor is compiled into
your app, the keyset is signed by it, and the validation token is signed by a key
it lists.

Every server response is a Talos-compact token signed by the product key and
verified against the pinned `PublicKey`, so a fake/MITM server cannot forge an
acceptable answer. The SDK ignores any `kid` in the token and enforces
`typ`/`aud`/nonce/`exp`/`nbf`. Anti-tamper honesty: managed IL is patchable —
gate premium value on server-returned *data* (entitlements/config), not client
booleans, and ship an obfuscator / NativeAOT for release builds.

## Heartbeats, monitoring, and cadence

```csharp
talos.StartCheckIns(
    onState: s => UpdateUi(s),
    onError: e => Log.Warn(e, "check-in failed"));
// On shutdown:
talos.StopCheckIns();
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
IP address is stored. Call `HeartbeatAsync()` directly if you would rather own
the schedule; `HeartbeatIntervalSeconds` is the policy's answer once the first
one has been sent.

## Hardware changes

The SDK identifies the machine by a set of component hashes (never the raw
serials — each is HMAC'd with a product-scoped key before it is sent). If the
policy uses tolerant matching, a machine that replaces a disk or reinstalls the
OS keeps its seat instead of forcing the user through a re-activation.

Collection uses only the BCL and never spawns a subprocess, which bounds what is
readable per platform: Windows and Linux report enough to match on, macOS does
not and falls back to exact matching. Where your app can read more than the BCL
can, supply it:

```csharp
var talos = new TalosClient(new TalosOptions {
    ProductToken = "tpt_…",
    AnchorPublicKey = "…",
    ServerUrl = "https://api.talos.dev",
    ExtraFingerprintComponents = new Dictionary<string, string> {
        ["smbios_uuid"] = MyPlatform.HardwareUuid(),
    },
});
```

The value must be stable for the life of the install. See
[docs/FINGERPRINT.md](../../docs/FINGERPRINT.md) for the recognised ids, the
per-platform coverage table, and the drift budget that bounds all of this.

## Tests

- `dotnet test` runs the client-side verification tests (no server needed).
- The cross-language **contract test** runs the SDK against a live Rust server;
  see [`contract.sh`](contract.sh) (needs Postgres + the built `talos-server`).
