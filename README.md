# Talos SDKs

Client SDKs that developers embed in their products.

- `csharp/` — **`Talos.Sdk`** (NuGet). Multi-target `netstandard2.0;net8.0`,
  Ed25519 via BouncyCastle (pure managed). Phase 1.
- `node/` — **`@talos/sdk`** (npm). Node ≥18, zero prod dependencies
  (`node:crypto` Ed25519), dual ESM/CJS. Phase 2.

Both are thin online-first clients over the same wire protocol: activate →
validate (signed decision + nonce echo) → heartbeat → deactivate, with pinned
per-product Ed25519 verification of every Talos-compact token. See plan §9.

## What a seat reports about itself

Alongside the fingerprint — whose components are HMAC'd, so raw identifiers
never leave the machine — both SDKs send three plain, descriptive fields the
developer's portal shows against the seat:

| Field | Default | Why it is not the fingerprint's hostname |
|---|---|---|
| `hostname` | `os.hostname()` / `Environment.MachineName` | Stored and displayed as written. It is what a support agent reads when a customer says "release the one on my old laptop"; without it every seat on a licence is a hash prefix. Set the `hostname` option to `""` to send nothing. |
| `app_version` | unset (`appVersion` option) | Your product's version, for the adoption dashboard. |
| `sdk_version` | this SDK's own package version | Answers "how many installs are still on the old client?" — sent on heartbeat as well as activation, because activation happens once per install and the answer has to stay current. |

The server keeps the last value it was given for each, so an SDK that omits one
leaves the previous value alone rather than blanking it.
