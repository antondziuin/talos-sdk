# SDK releases

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
