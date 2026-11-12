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

Configure the SDK with the server URL — `https://talos.dziuin.dev` for Talos
Cloud, or your self-hosted node's address — and the product token and pinned
anchor public key from the product's Integration page. Activate with the customer's
license key, then validate the saved activation on later launches. Background
check-ins keep the license state current according to the product's policy.

The SDK verifies signed licensing responses and update manifests with Ed25519.
Offline validation uses the last verified decision within the configured grace
period; air-gapped machines use a separately issued offline license file.

Local release preparation pairs `@antondziuin/talos-sdk` **0.4.0** with
`@antondziuin/talos-sdk-wallet` **0.2.0** (peer requirement **^0.4.0**).
These changes prepare source and packages locally; they do not publish them.
Older published base SDK 0.3.0 drops the registry persistence fields on load.

## Direct on-chain registry

Registry clients explicitly allow Base Mainnet 8453, Sepolia 11155111 and local
Anvil 31337 with separately pinned contract/issuer/product/RPC configuration.
They persist a block/revision floor, retry provider lag without granting stale
access, recheck canonical history on reorgs, and retain observed revocation.
Base activation defaults to ten minutes while waiting for L1 safe publication.

Node/Electron's `@antondziuin/talos-sdk-wallet`, C#'s `Talos.Sdk` and Rust's
`talos-sdk` 0.3.0 with `features = ["registry"]` expose
`RegistryLicenseClient` for `TalosLicenseRegistryV1`. This mode reads licensing
state directly through trusted Ethereum RPC, with no Talos runtime API,
coordinator, or renewal service. It is separate from ordinary Talos activation
and seven-day `DeviceLicenseClient` certificates. Rust's feature is optional;
existing classic clients keep their default dependencies and HTTP seam.

Import a public manifest, have the holder's wallet confirm the generated device
binding transaction, then call `requireValidLicense()` / `RequireValidLicenseAsync()`
before each protected operation. Every check reads fresh state; RPC outages deny
access and there is no offline authorization cache. Pin issuer, product, chain and
registry address independently of the file. Issuance, binding, renewal and
revocation require wallet transactions; client patching and full device-key
cloning are not prevented. Examples: [Node registry](node-wallet/README.md),
[C# registry](csharp/README.md), [Rust registry](rust/README.md#direct-on-chain-registry-optional).

Automatically published policies also support a customer code-entry flow through
`activate(code)` / `ActivateAsync(code)` / Rust `activate(&code)`. The activation service arranges and pays
for publication; the SDK uses an Ed25519 device proof, not a customer Ethereum
wallet. Pending jobs resume after restart without resending a code. Once ready,
runtime checks use direct RPC, with no ongoing Talos dependency. Configure trusted
`activationUrl` / `ActivationUrl` and `productToken` / `ProductToken` separately from
the customer manifest. [Runnable Node application](../examples/wallet-license/README.md).

The publisher fetches public policy fields from the authenticated portal endpoint
`GET /v1/portal/products/{product}/wallet-registry-policies/{policy}/integration`.
It returns `issuer`, `product_id`, `chain_id`, `contract`, `product_token` and
`automatic_activation`; code-entry requires the last field to be `true`.
The application supplies its trusted activation base URL and client RPC endpoints
separately. SDKs append the activation/status paths to that base URL themselves.
Public client settings never include publisher credentials or the worker's private
RPC token. See the [configuration field table](rust/README.md#publisher-integration-configuration)
and [client RPC availability guidance](rust/README.md#client-rpc-availability).

Rust SDK 0.3.1 adds [transactional code replacement](rust/README.md#switching-to-another-license-code)
without resetting device identity, and [signed public updates](rust/README.md#signed-updates-for-registry-applications)
without classic activation. Registry policy creation supports license-lifetime
updates or a separate paid maintenance period. Public update delivery is an
explicit product opt-in; the SDK checks the signed release date against the
on-chain update rights, including for manually installed builds. Node/C# Registry
licensing remains supported; these new updater APIs are currently Rust-specific.

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
