/// This SDK's own version, as reported to the server on activate, validate and
/// heartbeat.
///
/// Read from the manifest at compile time, so it cannot go stale the way a
/// hand-maintained literal does — and the column it fills is how a developer
/// answers "who is still on the old client?".
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The wire form: language tag plus version, e.g. `rust/0.1.0`.
pub(crate) fn sdk_id() -> String {
    format!("rust/{SDK_VERSION}")
}
