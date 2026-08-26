# Talos.Sdk (C#)

Online-first client SDK for the Talos licensing platform. Multi-targets
`netstandard2.0` (reaches .NET Framework 4.6.2+, Unity, Mono) and `net8.0`.
Ed25519 verification via BouncyCastle (pure managed — no native binaries).

## Quickstart

```csharp
using Talos.Sdk;

var talos = new TalosClient(new TalosOptions {
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
```

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

Every server response is a Talos-compact token signed by the product key and
verified against the pinned `PublicKey`, so a fake/MITM server cannot forge an
acceptable answer. The SDK ignores any `kid` in the token and enforces
`typ`/`aud`/nonce/`exp`/`nbf`. Anti-tamper honesty: managed IL is patchable —
gate premium value on server-returned *data* (entitlements/config), not client
booleans, and ship an obfuscator / NativeAOT for release builds.

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
