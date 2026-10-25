//! Talos SDK for Rust applications.
//!
//! Activate and validate licences, read feature entitlements, hold floating
//! seats, and download signed software updates — with offline grace periods
//! and licence files for air-gapped machines.
//!
//! ```no_run
//! use talos_sdk::{Decision, TalosClient, TalosOptions};
//!
//! let talos = TalosClient::new(TalosOptions {
//!     product_token: "tpt_…".into(),               // from the portal's Integration page
//!     anchor_public_key: Some("base64-anchor-key".into()), // pin THIS — the rotation-safe root
//!     server_url: "https://talos.dziuin.dev".into(),
//!     app_version: Some(env!("CARGO_PKG_VERSION").into()),
//!     ..Default::default()
//! })?;
//!
//! // The activation is stored on this machine, so the second launch onwards
//! // has nothing to ask the user for.
//! # let user_entered_license_key = "";
//! let state = if talos.is_activated() {
//!     talos.validate()?
//! } else {
//!     talos.activate(user_entered_license_key)?
//! };
//! match state.decision {
//!     Decision::Valid => {}
//!     Decision::GraceExpired | Decision::ClockTampered => { /* require a connection */ }
//!     _ => { /* show the licence problem */ }
//! }
//!
//! if talos.is_feature_enabled("pdf-export") { /* enable the menu */ }
//! let seats = state.entitlement_i64("seats").unwrap_or(1);
//! # let _ = seats;
//! # Ok::<(), talos_sdk::Error>(())
//! ```
//!
//! Every server response is a Talos-compact token signed by the product key and
//! verified against the pinned key, so a fake or intercepting server cannot
//! forge an acceptable answer. Calls block; from async code run them on a
//! blocking thread.
//!
//! Anti-tamper honesty: a binary is patchable. Gate premium value on
//! server-returned *data* (entitlements, configuration), not on client
//! booleans.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod client;
pub mod compact;
mod diagnostics;
mod error;
mod fingerprint;
mod host;
mod offline;
mod state;
pub mod transport;
mod types;
mod version;

#[cfg(test)]
mod tests;

pub use client::{verify_applied_update, Subscription, TalosClient, TalosOptions};
pub use error::{Error, Result};
pub use fingerprint::{collect_fingerprint, FingerprintData};
pub use offline::{signed_message, SignedDoc, LICENSE_FILE_KIND, RECEIPT_DOMAIN, REQUEST_DOMAIN};
pub use state::{default_state_path, hash_license_key};
pub use transport::{HttpRequest, HttpResponse, Transport};
pub use types::{
    AcquireLeaseOptions, CheckForUpdateOptions, CheckInOptions, Decision, DeltaOptions,
    DownloadProgress, EventKind, Lease, LicenseState, TalosEvent, UpdateArtifact, UpdateDelta,
    UpdateDeltaTarget, UpdateInfo,
};
pub use version::SDK_VERSION;
