use std::fmt;
use std::sync::Arc;

use serde_json::{Map, Value};

/// A licence verdict.
///
/// The server's own verdicts, plus four only a client can reach: two for
/// offline grace and two for an air-gapped licence file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Decision {
    /// Licensed.
    Valid,
    /// The licence's own term ended.
    Expired,
    /// Revoked by the vendor. Permanent.
    Revoked,
    /// Suspended by the vendor.
    Suspended,
    /// This machine's seat was released.
    Deactivated,
    /// This machine was revoked.
    MachineRevoked,
    /// Anything the server judged unusable without a more specific reason.
    Invalid,
    /// Offline for longer than the policy's grace window. Not a licence
    /// problem: what ran out is permission to keep believing a cached answer.
    GraceExpired,
    /// The system clock moved back behind a signed server time already seen.
    ClockTampered,
    /// An offline licence file issued for a different machine.
    MachineMismatch,
    /// An offline licence file past its own horizon: ask for a new file.
    OfflineFileExpired,
    /// A verdict this SDK version does not know, kept as sent.
    Other(String),
}

impl Decision {
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "valid" => Decision::Valid,
            "expired" => Decision::Expired,
            "revoked" => Decision::Revoked,
            "suspended" => Decision::Suspended,
            "deactivated" => Decision::Deactivated,
            "machine_revoked" => Decision::MachineRevoked,
            "invalid" => Decision::Invalid,
            "grace_expired" => Decision::GraceExpired,
            "clock_tampered" => Decision::ClockTampered,
            "machine_mismatch" => Decision::MachineMismatch,
            "offline_file_expired" => Decision::OfflineFileExpired,
            other => Decision::Other(other.to_string()),
        }
    }

    /// The wire spelling: `valid`, `grace_expired`, ….
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Decision::Valid => "valid",
            Decision::Expired => "expired",
            Decision::Revoked => "revoked",
            Decision::Suspended => "suspended",
            Decision::Deactivated => "deactivated",
            Decision::MachineRevoked => "machine_revoked",
            Decision::Invalid => "invalid",
            Decision::GraceExpired => "grace_expired",
            Decision::ClockTampered => "clock_tampered",
            Decision::MachineMismatch => "machine_mismatch",
            Decision::OfflineFileExpired => "offline_file_expired",
            Decision::Other(s) => s,
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The current, cryptographically verified licence verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct LicenseState {
    /// The verdict.
    pub decision: Decision,
    /// The entitlement bag, as the server signed it.
    pub features: Map<String, Value>,
    /// Business expiry (unix seconds), or `None` for perpetual.
    pub license_expires_at: Option<i64>,
    /// True when this verdict came from the local cache rather than a live
    /// server — honoured on trust, inside the window the policy allows.
    pub is_offline: bool,
    /// Unix seconds after which the app should validate again. Server-chosen,
    /// carried in a signed claim.
    pub revalidate_after: Option<i64>,
    /// Unix seconds until which this verdict may be honoured offline.
    pub grace_until: Option<i64>,
}

impl LicenseState {
    pub(crate) fn bare(decision: Decision, is_offline: bool) -> Self {
        LicenseState {
            decision,
            features: Map::new(),
            license_expires_at: None,
            is_offline,
            revalidate_after: None,
            grace_until: None,
        }
    }

    /// Whether the verdict is [`Decision::Valid`].
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.decision == Decision::Valid
    }

    /// Whether an entitlement is on: `true`, a non-zero number, or a non-empty
    /// string.
    #[must_use]
    pub fn is_feature_enabled(&self, name: &str) -> bool {
        match self.features.get(name) {
            Some(Value::Bool(b)) => *b,
            Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
            Some(Value::String(s)) => !s.is_empty(),
            _ => false,
        }
    }

    /// One entitlement, as the server sent it.
    #[must_use]
    pub fn entitlement(&self, name: &str) -> Option<&Value> {
        self.features.get(name)
    }

    /// One entitlement as an integer, when it is one.
    #[must_use]
    pub fn entitlement_i64(&self, name: &str) -> Option<i64> {
        self.features.get(name).and_then(Value::as_i64)
    }
}

/// One downloadable artifact of an update. Everything but `download_path` comes
/// from the signed manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateArtifact {
    /// `windows`, `macos`, `linux`, ….
    pub platform: String,
    /// `x64`, `arm64`, ….
    pub arch: String,
    /// `installer`, `archive`, ….
    pub kind: String,
    /// The file's name as published.
    pub filename: String,
    /// Expected size in bytes.
    pub size: u64,
    /// Expected SHA-256, lowercase hex.
    pub sha256: String,
    /// Untrusted transport path; the bytes are verified against `sha256`.
    pub download_path: Option<String>,
}

/// What applying a patch has to produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateDeltaTarget {
    /// The `kind` of the full artifact this rebuilds.
    pub kind: String,
    /// The rebuilt file's name.
    pub filename: String,
    /// Expected size of the rebuilt file, in bytes.
    pub size: u64,
    /// Expected SHA-256 of the rebuilt file. **Check it after applying** — see
    /// [`verify_applied_update`](crate::verify_applied_update).
    pub sha256: String,
}

/// A patch from one installed version to this release. Talos hosts and signs
/// patches; it neither produces nor applies them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateDelta {
    /// `windows`, `macos`, `linux`, ….
    pub platform: String,
    /// `x64`, `arm64`, ….
    pub arch: String,
    /// The installed version this patch applies to, exactly as published.
    pub from: String,
    /// `release_seq` of that version.
    pub from_seq: i64,
    /// The patch file's name.
    pub filename: String,
    /// Expected size of the patch itself.
    pub size: u64,
    /// Expected SHA-256 of the patch itself.
    pub sha256: String,
    /// What applying it must produce.
    pub target: UpdateDeltaTarget,
    /// Untrusted transport path.
    pub download_path: Option<String>,
}

/// A verified available update. All metadata comes from the signed manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateInfo {
    /// The release's version string.
    pub version: String,
    /// Monotonic release number; what anti-downgrade compares.
    pub release_seq: i64,
    /// Whether the vendor marked it mandatory.
    pub mandatory: bool,
    /// Release notes, if published.
    pub notes_url: Option<String>,
    /// Full builds.
    pub artifacts: Vec<UpdateArtifact>,
    /// Patches. Never mixed into `artifacts`: a patch is not something a host
    /// can install.
    pub deltas: Vec<UpdateDelta>,
}

/// How far a download has got. `total_bytes` is the **signed** size, never the
/// server's `content-length`: a bar the download host can drive can be parked
/// at 100% while bytes are still arriving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadProgress {
    /// Bytes verified and written so far.
    pub bytes_received: u64,
    /// Total size from the signed manifest.
    pub total_bytes: u64,
}

/// A held floating seat. Renew before `expires_at` or it is reclaimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Server-side lease id (from the signed token).
    pub id: String,
    /// This process's instance id.
    pub instance_id: String,
    /// Unix seconds when the seat is reclaimed unless renewed.
    pub expires_at: i64,
    /// Renew after this many seconds.
    pub renew_after_seconds: i64,
    /// Seats taken, from the signed claims.
    pub seats_in_use: i64,
    /// The policy's cap, from the signed claims.
    pub max_seats: i64,
}

/// Which event a listener is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventKind {
    /// The licence stopped being usable; the payload says why.
    LicenseInvalid,
    /// Running on a cached verdict because the server could not be reached.
    GracePeriodStarted,
    /// The offline window closed.
    GracePeriodExpired,
    /// The clock moved back behind a signed server time already seen.
    ClockTamperDetected,
    /// A newer release is waiting, noticed by a heartbeat.
    UpdateAvailable,
}

/// A transition, delivered to the listeners of its [`EventKind`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum TalosEvent {
    /// See [`EventKind::LicenseInvalid`].
    LicenseInvalid(LicenseState),
    /// See [`EventKind::GracePeriodStarted`].
    GracePeriodStarted(LicenseState),
    /// See [`EventKind::GracePeriodExpired`].
    GracePeriodExpired(LicenseState),
    /// See [`EventKind::ClockTamperDetected`].
    ClockTamperDetected(LicenseState),
    /// See [`EventKind::UpdateAvailable`].
    UpdateAvailable(UpdateInfo),
}

impl TalosEvent {
    /// The kind this event is delivered under.
    #[must_use]
    pub fn kind(&self) -> EventKind {
        match self {
            TalosEvent::LicenseInvalid(_) => EventKind::LicenseInvalid,
            TalosEvent::GracePeriodStarted(_) => EventKind::GracePeriodStarted,
            TalosEvent::GracePeriodExpired(_) => EventKind::GracePeriodExpired,
            TalosEvent::ClockTamperDetected(_) => EventKind::ClockTamperDetected,
            TalosEvent::UpdateAvailable(_) => EventKind::UpdateAvailable,
        }
    }

    /// The licence state, for every event but `UpdateAvailable`.
    #[must_use]
    pub fn state(&self) -> Option<&LicenseState> {
        match self {
            TalosEvent::LicenseInvalid(s)
            | TalosEvent::GracePeriodStarted(s)
            | TalosEvent::GracePeriodExpired(s)
            | TalosEvent::ClockTamperDetected(s) => Some(s),
            TalosEvent::UpdateAvailable(_) => None,
        }
    }
}

pub(crate) type StateCallback = Arc<dyn Fn(&LicenseState) + Send + Sync>;
pub(crate) type ErrorCallback = Arc<dyn Fn(&crate::Error) + Send + Sync>;
pub(crate) type LostCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// Callbacks for [`TalosClient::start_check_ins`](crate::TalosClient::start_check_ins).
///
/// Both run on the check-in thread. A UI application marshals to its own
/// thread from there.
#[derive(Clone, Default)]
pub struct CheckInOptions {
    pub(crate) on_state: Option<StateCallback>,
    pub(crate) on_error: Option<ErrorCallback>,
}

impl CheckInOptions {
    /// No callbacks: the loop still runs, and events still fire.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Called after every successful check-in, with the fresh verdict.
    #[must_use]
    pub fn on_state(mut self, f: impl Fn(&LicenseState) + Send + Sync + 'static) -> Self {
        self.on_state = Some(Arc::new(f));
        self
    }

    /// Called when a check-in fails outright — the server answered with an
    /// error, or the network is down *and* there is nothing to fall back on.
    #[must_use]
    pub fn on_error(mut self, f: impl Fn(&crate::Error) + Send + Sync + 'static) -> Self {
        self.on_error = Some(Arc::new(f));
        self
    }
}

impl fmt::Debug for CheckInOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckInOptions")
            .field("on_state", &self.on_state.is_some())
            .field("on_error", &self.on_error.is_some())
            .finish()
    }
}

/// Options for [`TalosClient::acquire_lease`](crate::TalosClient::acquire_lease).
///
/// ```
/// # use talos_sdk::AcquireLeaseOptions;
/// let options = AcquireLeaseOptions::new()
///     .instance_id("render-worker-1")
///     .on_lease_lost(|why| eprintln!("seat lost: {why}"));
/// ```
#[derive(Clone)]
pub struct AcquireLeaseOptions {
    pub(crate) instance_id: Option<String>,
    pub(crate) auto_renew: bool,
    pub(crate) on_lease_lost: Option<LostCallback>,
}

impl Default for AcquireLeaseOptions {
    fn default() -> Self {
        AcquireLeaseOptions {
            instance_id: None,
            auto_renew: true,
            on_lease_lost: None,
        }
    }
}

impl AcquireLeaseOptions {
    /// A random per-client instance id, renewed in the background.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Identifies this running process. Re-acquiring with the same value renews
    /// instead of taking a second seat. Defaults to a random per-client id.
    #[must_use]
    pub fn instance_id(mut self, id: impl Into<String>) -> Self {
        self.instance_id = Some(id.into());
        self
    }

    /// Renew in the background (default `true`). Call
    /// [`release_lease`](crate::TalosClient::release_lease) to stop.
    #[must_use]
    pub fn auto_renew(mut self, on: bool) -> Self {
        self.auto_renew = on;
        self
    }

    /// Called on the renewal thread if a renewal fails and the seat is lost.
    #[must_use]
    pub fn on_lease_lost(mut self, f: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.on_lease_lost = Some(Arc::new(f));
        self
    }
}

impl fmt::Debug for AcquireLeaseOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcquireLeaseOptions")
            .field("instance_id", &self.instance_id)
            .field("auto_renew", &self.auto_renew)
            .field("on_lease_lost", &self.on_lease_lost.is_some())
            .finish()
    }
}

/// Options for [`TalosClient::check_for_update`](crate::TalosClient::check_for_update).
#[derive(Debug, Clone, Default)]
pub struct CheckForUpdateOptions {
    /// Currently installed version (informational). Defaults to `app_version`.
    pub current_version: Option<String>,
    /// Override the anti-downgrade floor for this call. Normally omitted: the
    /// SDK persists the highest `release_seq` it has seen this install running.
    /// Pass one only when you know something it cannot — a build installed by a
    /// package manager, or a first run on an already-updated fleet.
    pub current_release_seq: Option<i64>,
    /// Update channel; defaults to the client's `update_channel`, else `stable`.
    pub channel: Option<String>,
}

/// Which patch to use, when a release ships more than one.
#[derive(Debug, Clone, Default)]
pub struct DeltaOptions {
    /// The version installed. Defaults to `app_version`.
    pub from: Option<String>,
    /// Which shipped file to rebuild, when the release patches several.
    /// Required when there is more than one.
    pub target_kind: Option<String>,
}
