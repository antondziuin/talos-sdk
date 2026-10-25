# Talos SDKs

Talos SDKs add license activation, validation, feature entitlements, and signed
software updates to your application. All three packages support machine-bound
licenses, offline grace periods, air-gapped activation, and floating seats.

## Packages

| Package | Applications | Requirements |
|---|---|---|
| `Talos.Sdk` | C# / .NET applications | `netstandard2.0` or `net8.0`; managed Ed25519 verification via BouncyCastle |
| `@antondziuin/talos-sdk` | Node.js and Electron applications | Node.js 18 or later; ESM and CommonJS; no runtime dependencies |
| `talos-sdk` (crates.io) | Rust applications | Rust 1.85 or later; blocking API; `ed25519-dalek`, rustls via `ureq` (replaceable) |

## Installation

```sh
dotnet add package Talos.Sdk
npm install @antondziuin/talos-sdk
cargo add talos-sdk
```

## Integration

Configure the SDK with your Talos server URL, product token, and pinned anchor
public key from the product's Integration page. Activate with the customer's
license key, then validate the saved activation on later launches. Background
check-ins keep the license state current according to the product's policy.

The SDK verifies signed licensing responses and update manifests with Ed25519.
Offline validation uses the last verified decision within the configured grace
period; air-gapped machines use a separately issued offline license file.

## Activation metadata

Every SDK hashes fingerprint components with a product-scoped key before sending
them. They also report the following descriptive fields for the activation:

| Field | Default | Purpose |
|---|---|---|
| `hostname` | `os.hostname()` / `Environment.MachineName` / the OS hostname | Identifies the machine in the portal. Sent as plain text; set `hostname` (Node.js, Rust) or `Hostname` (.NET) to `""` to omit it. |
| `app_version` | Unset | Your application's version, configured with `appVersion` (Node.js), `AppVersion` (.NET) or `app_version` (Rust). |
| `sdk_version` | Installed SDK version | Reports SDK version adoption on activation and heartbeat. |

The server keeps the last value it was given for each, so an SDK that omits one
leaves the previous value alone rather than blanking it.

## License

All SDK packages are MIT-licensed.
