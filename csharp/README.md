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

var state = await talos.ActivateAsync(userEnteredLicenseKey);
if (!state.IsValid) { /* prompt for a valid key */ }

if (talos.IsFeatureEnabled("pdf-export")) EnablePdfMenu();
int seats = (int)(talos.Current!.GetEntitlementInt("seats") ?? 1);

// Later / periodically:
var check = await talos.ValidateAsync();   // machine-bound signed decision
```

Every server response is a Talos-compact token signed by the product key and
verified against the pinned `PublicKey`, so a fake/MITM server cannot forge an
acceptable answer. The SDK ignores any `kid` in the token and enforces
`typ`/`aud`/nonce/`exp`/`nbf`. Anti-tamper honesty: managed IL is patchable —
gate premium value on server-returned *data* (entitlements/config), not client
booleans, and ship an obfuscator / NativeAOT for release builds.

## Tests

- `dotnet test` runs the client-side verification tests (no server needed).
- The cross-language **contract test** runs the SDK against a live Rust server;
  see [`contract.sh`](contract.sh) (needs Postgres + the built `talos-server`).
