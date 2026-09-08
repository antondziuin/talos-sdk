# Talos SDKs

Client SDKs that developers embed in their products. **MIT licensed** — the
platform they talk to is not, and the split is deliberate: a library you compile
into your own application should not be something your legal review has to read.

```sh
dotnet add package Talos.Sdk
npm install @antondziuin/talos-sdk
```

## Where this code lives

The public repository you are probably reading this in is a **mirror**. The SDKs
are developed in the Talos monorepo, which is private, because that is where
they are tested against a real server: the cross-language contract harness
drives the actual Rust API and verifies real signed tokens, and the frozen wire
vectors in `contract-vectors.json` are generated there and verified here, in C#
and in Node, against bytes that predate all three implementations.

The mirror carries the real history of these files — `git subtree split`, not a
squashed export — and exists because npm attests provenance only against a
public repository. Publishing from here is what makes the attestation, the
package pages' repository links and SourceLink point at code anyone can read.

Pull requests are welcome and land in the monorepo, so they arrive back here on
the next release rather than as a merge commit.

- `csharp/` — **`Talos.Sdk`** (NuGet). Multi-target `netstandard2.0;net8.0`,
  Ed25519 via BouncyCastle (pure managed). Phase 1.
- `node/` — **`@antondziuin/talos-sdk`** (npm). Node ≥18, zero prod dependencies
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
