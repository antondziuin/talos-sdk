# Talos SDKs

Client SDKs that developers embed in their products.

- `csharp/` — **`Talos.Sdk`** (NuGet). Multi-target `netstandard2.0;net8.0`,
  Ed25519 via BouncyCastle (pure managed). Phase 1.
- `node/` — **`@talos/sdk`** (npm). Node ≥18, zero prod dependencies
  (`node:crypto` Ed25519), dual ESM/CJS. Phase 2.

Both are thin online-first clients over the same wire protocol: activate →
validate (signed decision + nonce echo) → heartbeat → deactivate, with pinned
per-product Ed25519 verification of every Talos-compact token. See plan §9.
