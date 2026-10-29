# Talos.Sdk (C#)

Talos SDK for C# and .NET applications. Activate and validate licenses, read
feature entitlements, manage floating seats, and download signed software
updates. Supports offline grace periods and license files for air-gapped machines.

Targets `netstandard2.0` and `net8.0`. Uses BouncyCastle for managed Ed25519
verification, with no native cryptography binaries.

```sh
dotnet add package Talos.Sdk
```

MIT-licensed.

Wallet licensing is available through `DeviceLicenseClient`: a seven-day device
certificate, offline restarts, and automatic daily renewal through Talos.
Pin issuer/product/network/V2 verifier, import an enrollment, authorize the device
with the owner's wallet, then `StartAsync()` and `RequireValidCertificate()` before
protected work. On restored connectivity call `NotifyResumeAsync()`.
A transfer stops old renewals; the previous device can work until its certificate
expires, up to seven days. `WalletLicenseClient` remains for older coordinator policies.
See [the guide](../../docs/WALLET-LICENSES.md) and [example](../../examples/wallet-csharp/).

## Quickstart

```csharp
using System.Text.Json;
using Talos.Sdk;

// `using`: the client disposes the HttpClient it created for itself. Supply
// your own via TalosOptions.HttpClient and it is left alone — you own it.
using var talos = new TalosClient(new TalosOptions {
    ProductToken = "tpt_…",              // from the portal's Integration page
    PublicKey    = "base64-ed25519-key", // pinned at build time
    ServerUrl    = "https://talos.dziuin.dev", // Talos Cloud, or your self-hosted node
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

`HttpTimeoutMs` does not apply to `DownloadUpdateAsync`. Downloads are bounded
by the signed manifest's size and accept a cancellation token.

## Local diagnostic reports

After a licensing call, `talos.CreateDiagnosticReport()` returns JSON describing
the last decision, offline grace deadline, SDK version and whether an activation
is held. Pass a caught exception to classify it and get a next action:

```csharp
try
{
    await talos.ValidateAsync();
    Console.WriteLine(talos.CreateDiagnosticReport());
}
catch (Exception error)
{
    Console.WriteLine(talos.CreateDiagnosticReport(error));
}
```

The report is a local snapshot: it makes no requests, writes no files and changes
no licensing state. It excludes keys, tokens, server URLs, hardware identifiers,
entitlements and exception messages/stacks. Unknown error codes are replaced with
`api_error`. Serialization supports trimming and NativeAOT. An HTTP error is not
a signed license decision, and an offline result alone cannot identify the
original transport or verification failure.

In the portal, select the same license on **Integration → Connection progress**
to see its devices, recorded validation, seat usage and recent activation refusals.
Use the report for failures that the server cannot see. Do not use it as
authorization; continue to gate access on the SDK's verified license state.

## Downloads stream, and report progress

`DownloadUpdateAsync` and `DownloadDeltaAsync` take an
`IProgress<DownloadProgress>`, and the bytes stream to a `.talos-part` file
beside the destination, hashed as they arrive, renamed into place only once the
hash matches. So a multi-gigabyte installer is never held in memory, a host has
something to draw for the minutes a download takes, and a download that fails
verification leaves whatever was at the destination before rather than a
truncated file an updater might run. `TotalBytes` is the signed manifest's size,
never the server's `Content-Length` — a bar the download host can drive can be
parked at 100% while bytes are still arriving.

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

## Dependency injection

Register `TalosClient` directly with your application's service container:

```csharp
services.AddSingleton(sp => new TalosClient(new TalosOptions { /* … */ }));
```

The service container disposes the client when it shuts down. To isolate
licensing in application tests, wrap the operations you use behind your own
interface.

## Trimming and NativeAOT

The SDK is marked `IsAotCompatible` on `net8.0`, which turns on the trim, AOT
and single-file analyzers over its own code, and CI builds it with
`-warnaserror`. That combination is the point: every request body is a declared
type with a **compile-time** serializer (`[JsonSerializable]` source generation),
and a reflective `JsonSerializer` call coming back is a build error rather than
an application that publishes cleanly and then sends `{}` to `/v1/client/activate`
on a customer's machine. Responses were never reflected over — they are read
field by field through `JsonDocument`.

The `netstandard2.0` build carries the same generated serializers; it simply has
no analyzers, because there is no trimmed publish there to protect.

## The machine binding is persistent

`ActivateAsync` binds this machine and the SDK writes that binding to a
per-product file under the OS user-data directory. A `TalosClient` restores it
in its constructor, so `talos.IsActivated` answers the startup question —
prompt for a key, or go straight to `ValidateAsync()` — and the user enters
their key once, not once per launch.

That file is `%LOCALAPPDATA%\Talos\<slot>\state.bin` on Windows,
`~/Library/Application Support/Talos/<slot>/state.bin` on macOS,
`$XDG_DATA_HOME/talos/<slot>/state.bin` (or `~/.local/share/...`) on Linux —
where `<slot>` is a hash of the product token, and the same three paths the
Node SDK uses, so one product cannot end up with two bindings in two places.

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

## Air-gapped machines

Grace above is for an install that has been online. This is for one that never
will be — an isolated network, no route out at all.

```csharp
// On the machine. Write this out and carry it to your vendor:
File.WriteAllText("talos-request.json", talos.CreateOfflineRequest().ToJson());

// They upload it in the portal and hand you back license.talos:
LicenseState state = await talos.LoadOfflineLicenseAsync("license.talos");
// state.Decision == "valid"
```

The first call generates an **Ed25519 keypair for this machine**, keeps the
private half in the same encrypted state file as everything else, and puts the
public half in the request beside the fingerprint. The file you get back is bound
to both, so a file copied off another machine does not license this one and this
machine's state directory does not license another. Calling it twice reuses the
same identity — only the nonce changes. `ToJson()` goes through the
source-generated serializer, so a trimmed or NativeAOT host writes the real
document rather than an empty envelope with a valid signature over nothing.

Everything is verified locally: the anchor-signed keyset travels inside the file,
so an anchor-only pin still works with no server to fetch one from. The verdict
is kept, so later starts need nothing — `ValidateAsync()` re-checks the stored
file instead of reaching for the network, and `IsActivated` is true.

A **portable** permanent file is issued directly by the vendor. Import it with
`LoadOfflineLicenseAsync("license.talos")` on each computer; no request or
machine key is needed. Its signed `binding: "portable"` explicitly permits use
on different computers. Each computer keeps its own local state; carry the
licence file rather than copying machine-encrypted state. Portable files can be
copied and remain usable indefinitely. `CreateOfflineDeactivation()` refuses
them because they have no bound seat to return.

A valid offline import replaces any existing online activation locally, so
later `ValidateAsync()` calls and restarts use the file without contacting
Talos. Rejected imports preserve the previous stored activation. Keep state
persistence enabled for automatic restore.

For trusted users, a perpetual policy can opt into permanent offline files with
`offline_checkout_max_days: 0`. The issued file has a signed `perpetual: true`
and explicit null file and licence expiries. It needs no renewal or server
connection; `GraceUntil` and `LicenseExpiresAt` are null. Import it using the
same calls above. Older SDK versions reject these files and must be upgraded.

`LoadOfflineLicenseAsync` **throws** only for a file that is not a licence:
unreadable, not one of ours, addressed to another product, or a signature that
does not verify. A file that is one but cannot license this machine comes back as
a verdict you can show the user — `machine_mismatch`, `offline_file_expired` (get
a new file), `expired` (renew the licence), `clock_tampered`.

Retiring the machine? `talos.CreateOfflineDeactivation()` writes a
`talos-deactivation.json` for the vendor to upload, and **drops the licence
before returning it** — so an app that loses the file has still stopped using the
seat. Credited once per file, so a machine restored from a snapshot replaying its
receipt changes nothing.

Two things to know before you offer this to customers. A file **cannot be
recalled** — revoking it in the portal frees the seat so you can issue to a
replacement machine, but the machine holding it keeps working until the file's
own expiry, or indefinitely for a permanent file. Hardware changes to a
machine-bound install are not forgiven offline: the drift matcher lives on the
server, so a replaced disk means `machine_mismatch` and a new request.

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

## Events: the transitions, not the level

```csharp
talos.GracePeriodStarted += (_, s) => ShowOfflineBanner(s.GraceUntil);
talos.GracePeriodExpired += (_, _) => RequireConnection();
talos.LicenseInvalid += (_, s) => ShowLicenceProblem(s.Decision);
talos.ClockTamperDetected += (_, _) => ShowClockWarning();
talos.UpdateAvailable += (_, info) => OfferUpdate(info.Version);
```

Four of them are licence transitions, each raised **once** on the way in and not again while nothing
changes: an application offline for a week gets one `GracePeriodStarted`, not
one per check-in. `LicenseInvalid` covers the server's own verdicts (`expired`,
`revoked`, `suspended`, `deactivated`, `machine_revoked`, `invalid`) and fires
again when the *reason* changes, because "your subscription lapsed" and "this
machine was revoked" are different things to put in front of a user. The two
grace verdicts are deliberately not folded into it: what ran out there is
permission to keep believing a cached answer, and reporting it as a licence
problem sends the user to support instead of to their network.

Handlers run synchronously on the calling thread, from every path that adopts a
verdict — `ActivateAsync`, `ValidateAsync`, `HeartbeatAsync` and the offline
fallback — so a host running its own timer gets the same transitions. A handler
that throws is ignored: these are raised from inside `ValidateAsync`, whose own
catch treats a throw as an unreachable server, and a broken banner must not turn
a live "revoked" answer into offline grace.

There is deliberately no "grace ended" or "licence recovered" event. That is a
level, and `onState` (or `talos.Current`) already carries it on every check-in;
a second way to learn one fact is a second thing to keep in step.

`UpdateAvailable` is the odd one out: it carries an `UpdateInfo`, not a licence
state, and it is how an application learns about a release **without asking**.
Subscribing to it makes each heartbeat name your `UpdateChannel` (`stable`
unless you set one), which is what asks the server whether anything is waiting;
on a yes, the SDK runs a real `CheckForUpdateAsync` and hands you what that
verified — the signed manifest and this install's own anti-downgrade floor,
never the hint's word. Nothing is asked for and nothing is spent while no
handler is attached, and each release is announced once however long the user
puts off installing it.

## When updates are refused

A maintenance licence that has run out is **not** a licence that has failed.
`ValidateAsync` still returns `valid` — the customer keeps the version they
bought, and their application must keep working — and only the update check
refuses:

```csharp
try
{
    UpdateInfo? upd = await talos.CheckForUpdateAsync();
    if (upd is not null) OfferUpdate(upd);
}
catch (TalosApiException e) when (e.Error == "updates_not_entitled")
{
    // Not a licensing failure. Say what it is and what fixes it.
    ShowNotice("Your maintenance period has ended. The app keeps working; renew to get updates.");
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
    ServerUrl = "https://talos.dziuin.dev",
    ExtraFingerprintComponents = new Dictionary<string, string> {
        ["smbios_uuid"] = MyPlatform.HardwareUuid(),
    },
});
```

The value must be stable for the life of the install. The product's fingerprint
policy controls which hardware changes are tolerated.
