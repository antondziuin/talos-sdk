# SDK releases

## Rust 0.4.0

- Code recovery for Registry policies that name an activator contract. A client
  opened with `RegistryLicenseClient::with_code(options, code)` derives its
  device key from the customer's code, and `activate(code)` restores an already
  published license from the registry over RPC with no Talos request. The first
  activation of a code still goes through Talos.
- `RegistryLicenseClient::replace_with_code` switches an installation to another
  code and keeps the current license until the new one verifies.
- `RegistryLicenseOptions::activator`: the `TalosLicenseActivatorV1` address
  from the publisher's integration settings. A new public field, which is why
  this is 0.4.0 and not a patch release: code that lists every field of
  `RegistryLicenseOptions` must add it. Options built with
  `..Default::default()` are unaffected.
- With `activator` set, `activate` on a client opened with `new` returns
  `registry_code_identity_required`, and `replace_license` returns
  `registry_code_replacement_required`. The server enforces the same rule: under
  such a policy it accepts only the key derived from the code and answers any
  other with `registry_code_identity_required`, so no license is ever published
  that its own code cannot restore.

Under such a policy the code is a bearer credential with no device limit, and
entitlements are published on chain as plain text. It needs a Talos server with
migration 0064 and a deployed activator contract. Node.js and .NET do not derive
the key from a code yet, so they cannot activate under such a policy: the server
refuses their random key. Use a policy without an activator for those
applications.

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
