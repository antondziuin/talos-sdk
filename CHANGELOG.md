# SDK releases

## Rust 0.3.3

- `RegistryLicenseClient::export_portable_license` and
  `import_portable_license`: carry one activated Registry license to any
  computer as a file. No Talos request is made on import or afterwards; every
  copy still validates against the registry over RPC, so an on-chain revocation
  or expiry stops all of them.
- `RegistryLicenseClient::report_launch`: an optional, signed launch report for
  per-license computer and launch counts. It never affects access and needs a
  Talos server that serves `/v1/client/registry/checkin`; against an older
  server it fails with `registry_checkin_unavailable`.

A portable file is a bearer credential with no device limit. Node.js and .NET
do not have these calls yet.

## Node.js 0.3.0 · .NET 0.3.0 · Rust 0.2.0

- Import perpetual portable offline files on any computer through the existing
  offline-license APIs, without generating a machine request.
- Require an explicitly signed portable grant, the correct product and
  perpetual expiry claims. Existing machine-bound files retain hardware checks.
- Switch a valid offline import away from an existing online activation and
  stop its lease renewals. Rejected imports retain the stored activation.
- Prevent delayed online responses from overwriting an imported offline grant.
- Preserve newer trusted keysets when importing older files, and restore trust
  state when an import fails.

Portable files require a Talos server with portable issuance support. They have
no device or concurrent-use limit and cannot be remotely recalled. Older SDKs
reject portable files; applications must update before importing them.
