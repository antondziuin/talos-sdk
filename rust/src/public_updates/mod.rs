//! Public signed release checks and verified downloads, without a classic activation.
//!
//! A publisher must explicitly enable public updates for the product. This client
//! never grants a license; the registry-aware methods check a supplied registry
//! license before and after update operations.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::compact::{unix_now, verify_keyset, verify_manifest_at, PublicKey};
use crate::fingerprint::{collect_fingerprint, hex};
use crate::registry::{RegistryLicenseClient, RegistryLicenseError};
use crate::state::{
    create_private_dir, default_state_path, state_key_material, StateStore, StoredBinding,
};
use crate::{
    CheckForUpdateOptions, DownloadProgress, Error, HttpRequest, HttpResponse, Result, Transport,
    UpdateArtifact, UpdateInfo,
};

const MAX_JSON: usize = 1_048_576;
const MAX_SAFE: i64 = 9_007_199_254_740_991;
const CLOCK_SKEW: i64 = 60;

/// Trusted application settings for a public signed update channel.
#[derive(Clone)]
pub struct PublicUpdateOptions {
    /// Public product token, from the publisher's integration settings.
    pub product_token: String,
    /// Trusted registry product bytes32, required by registry-aware methods.
    /// Plain public release clients may leave this unset.
    pub registry_product_id: Option<String>,
    /// Pinned standard-base64 Ed25519 anchor key for this product.
    pub anchor_public_key: String,
    /// Trusted HTTPS Talos origin/base URL, without `/v1/client/...`.
    pub server_url: String,
    /// Version of the running application, used to recognize completed installs.
    pub app_version: Option<String>,
    /// Release channel; defaults to `stable`.
    pub update_channel: Option<String>,
    /// Separate encrypted update state. Never point this at licensing state.
    pub state_path: Option<PathBuf>,
    /// Stable platform fingerprint overrides, used only to protect local state.
    pub fingerprint_components: BTreeMap<String, String>,
    /// Custom blocking transport, with deadlines covering response body reads.
    /// API requests must return redirects rather than follow them.
    pub transport: Option<Arc<dyn Transport>>,
    /// Per-HTTP request timeout; defaults to ten seconds, positive and at most a minute.
    pub http_timeout: Duration,
    /// Overall default download budget; defaults to five minutes, at most one hour.
    pub download_timeout: Duration,
    /// Maximum accepted signed artifact size; defaults to two GiB.
    pub max_artifact_bytes: u64,
}

impl Default for PublicUpdateOptions {
    fn default() -> Self {
        Self {
            product_token: String::new(),
            registry_product_id: None,
            anchor_public_key: String::new(),
            server_url: "https://talos.dziuin.dev".into(),
            app_version: None,
            update_channel: None,
            state_path: None,
            fingerprint_components: BTreeMap::new(),
            transport: None,
            http_timeout: Duration::from_secs(10),
            download_timeout: Duration::from_secs(300),
            max_artifact_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Cooperative cancellation for an update check or download.
#[derive(Clone, Default)]
pub struct PublicUpdateCancellationToken(Arc<AtomicBool>);

impl PublicUpdateCancellationToken {
    /// Create an uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Cancel operations using this token. In-flight transport calls must honor their timeout.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Optional overall deadline and cancellation for one operation.
#[derive(Clone, Default)]
pub struct PublicUpdateRequestOptions {
    /// Positive overall budget, at most one hour; `None` uses the operation default.
    pub timeout: Option<Duration>,
    /// Cancellation shared with the application's update UI.
    pub cancellation: Option<PublicUpdateCancellationToken>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u8,
    keyset: Option<String>,
    keyset_iat: i64,
    keyset_conflict: bool,
    installed_seq: i64,
    installed_version: Option<String>,
    observations: BTreeMap<String, Observation>,
    downloaded: BTreeMap<String, i64>,
    running_releases: BTreeMap<String, RunningRelease>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunningRelease {
    manifest: String,
    release_seq: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    seq: i64,
    manifest_hash: String,
}

#[derive(Clone)]
struct Offer {
    info: UpdateInfo,
    manifest: String,
    channel: String,
    product_id: String,
    published_at: u64,
    cutoff: Option<u64>,
}

struct Inner {
    options: PublicUpdateOptions,
    anchor: PublicKey,
    base: String,
    channel: String,
    transport: Arc<dyn Transport>,
    path: PathBuf,
    store: StateStore,
    fingerprint: String,
    operation: Mutex<()>,
    offer: Mutex<Option<Offer>>,
}

/// Blocking, cloneable public update client. It does not require or create a classic activation.
#[derive(Clone)]
pub struct PublicUpdateClient(Arc<Inner>);

impl PublicUpdateClient {
    /// Validate trusted settings and load or create independent encrypted update state.
    pub fn new(options: PublicUpdateOptions) -> Result<Self> {
        if options.product_token.is_empty()
            || options.product_token.len() > 256
            || !options
                .product_token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
            || options.http_timeout.is_zero()
            || options.http_timeout > Duration::from_secs(60)
            || options.download_timeout.is_zero()
            || options.download_timeout > Duration::from_secs(3600)
            || options.max_artifact_bytes == 0
            || options
                .registry_product_id
                .as_deref()
                .is_some_and(|id| !product_hash(id))
        {
            return Err(Error::usage("invalid_public_update_configuration"));
        }
        let anchor = PublicKey::from_base64(&options.anchor_public_key)?;
        let base = crate::registry::validate_endpoint(&options.server_url, true)
            .map_err(|_| Error::usage("invalid_public_update_url"))?;
        let channel = options
            .update_channel
            .clone()
            .unwrap_or_else(|| "stable".into());
        validate_channel(&channel)?;
        let scope = format!("public-updates:{}", options.product_token);
        let fp = collect_fingerprint(&scope, &options.fingerprint_components);
        let path = options
            .state_path
            .clone()
            .unwrap_or_else(|| default_state_path(&scope));
        let path = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        };
        let transport = match &options.transport {
            Some(t) => t.clone(),
            None => {
                #[cfg(feature = "ureq")]
                {
                    Arc::new(crate::transport::UreqTransport::without_redirects())
                        as Arc<dyn Transport>
                }
                #[cfg(not(feature = "ureq"))]
                {
                    return Err(Error::usage("public_update_transport_required"));
                }
            }
        };
        let store = StateStore::new(path.clone(), &scope, &state_key_material(&fp));
        let client = Self(Arc::new(Inner {
            options,
            anchor,
            base,
            channel,
            transport,
            path,
            store,
            fingerprint: fp.composite,
            operation: Mutex::new(()),
            offer: Mutex::new(None),
        }));
        let budget = Budget::new(
            Duration::from_secs(10),
            &PublicUpdateRequestOptions::default(),
        )?;
        client.0.with_state(&budget, |state| client.0.save(state))?;
        Ok(client)
    }

    /// Check a public channel. All returned metadata comes from a verified signed manifest.
    /// This method grants no license and does not implement maintenance eligibility.
    pub fn check_for_update(&self, options: CheckForUpdateOptions) -> Result<Option<UpdateInfo>> {
        self.check_with_options(options, &PublicUpdateRequestOptions::default())
    }

    /// Check a public channel with an overall timeout and cooperative cancellation.
    pub fn check_with_options(
        &self,
        options: CheckForUpdateOptions,
        request: &PublicUpdateRequestOptions,
    ) -> Result<Option<UpdateInfo>> {
        self.check_bounded(options, request, None)
    }

    fn check_bounded(
        &self,
        options: CheckForUpdateOptions,
        request: &PublicUpdateRequestOptions,
        cutoff: Option<u64>,
    ) -> Result<Option<UpdateInfo>> {
        let budget = Budget::new(self.0.options.http_timeout * 3, request)?;
        self.0.with_state(&budget, |state| {
            let channel = options.channel.as_deref().unwrap_or(&self.0.channel);
            validate_channel(channel)?;
            let explicit = options.current_release_seq.unwrap_or(0);
            if !(0..=MAX_SAFE).contains(&explicit) {
                return Err(Error::usage("invalid_release_sequence"));
            }
            state.installed_seq = state.installed_seq.max(explicit);
            remember_version(state, self.0.options.app_version.as_deref());
            remember_version(state, options.current_version.as_deref());
            promote_downloaded(
                state,
                options
                    .current_version
                    .as_deref()
                    .or(self.0.options.app_version.as_deref()),
            );
            let current_version = state
                .installed_version
                .as_deref()
                .and_then(comparable_version);
            if current_version.is_none() && state.installed_seq == 0 {
                return Err(Error::usage("current_update_version_or_sequence_required"));
            }
            let keys = self.0.refresh_keys(state, &budget)?;
            let current = current_version.as_ref().map(ToString::to_string);
            let body = self.0.post(
                "/v1/client/public-updates/check",
                json!({
                    "product_token": self.0.options.product_token, "current_version": current,
                    "current_release_seq": state.installed_seq, "channel": channel,
                    "published_before": cutoff,
                }),
                &budget,
            )?;
            match body.get("update_available").and_then(Value::as_bool) {
                Some(false) => {
                    self.0.save(state)?;
                    return Ok(None);
                }
                Some(true) => {}
                None => return Err(invalid()),
            }
            let manifest = body
                .get("manifest")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            let mut offer = self.0.parse_offer(&keys, manifest, channel, &body)?;
            offer.cutoff = cutoff;
            if cutoff.is_some_and(|until| offer.published_at > until) {
                return Err(Error::signature("update_outside_maintenance_window"));
            }
            self.0.cache_running_release(state, &offer)?;
            let candidate = comparable_version(&offer.info.version);
            if candidate.is_none() && (current_version.is_some() || state.installed_seq == 0) {
                return Err(Error::signature("unorderable_update_version"));
            }
            if let (Some(running), Some(candidate)) = (current_version, candidate) {
                if candidate.cmp_precedence(&running) != std::cmp::Ordering::Greater {
                    if candidate == running {
                        state.installed_seq = state.installed_seq.max(offer.info.release_seq);
                    }
                    self.0.save(state)?;
                    return Ok(None);
                }
            }
            observe(state, &offer)?;
            self.0.save(state)?;
            if offer.info.release_seq <= state.installed_seq {
                return Ok(None);
            }
            *lock(&self.0.offer)? = Some(offer.clone());
            Ok(Some(offer.info))
        })
    }

    /// Check a public channel for a freshly valid registry license and its signed update policy.
    /// A network/update failure must not be turned into a license revocation by the host.
    pub fn check_for_registry_update(
        &self,
        registry: &RegistryLicenseClient,
        options: CheckForUpdateOptions,
    ) -> Result<Option<UpdateInfo>> {
        self.check_for_registry_update_with_options(
            registry,
            options,
            &PublicUpdateRequestOptions::default(),
        )
    }

    /// Registry-aware check with cancellation/deadline options for the update requests.
    pub fn check_for_registry_update_with_options(
        &self,
        registry: &RegistryLicenseClient,
        options: CheckForUpdateOptions,
        request: &PublicUpdateRequestOptions,
    ) -> Result<Option<UpdateInfo>> {
        let before = self.authorize_running_release(registry, request)?;
        let cutoff = before.update_publication_cutoff().map_err(registry_error)?;
        let info = self.check_bounded(options, request, cutoff)?;
        let license = registry.require_valid_license().map_err(registry_error)?;
        license
            .update_publication_cutoff()
            .map_err(registry_error)?;
        if let Some(info) = &info {
            let offer = self.0.offer_for(info)?;
            bind_registry(registry, &offer)?;
            license
                .require_update_entitlement(offer.published_at)
                .map_err(registry_error)?;
            let budget = Budget::new(self.0.options.http_timeout, request)?;
            self.0.with_state(&budget, |state| {
                self.0.verify_latest_authority(state, &offer)
            })?;
        }
        Ok(info)
    }

    /// Download a verified offer into a new destination, checking signed size and SHA-256.
    /// Matches the classic client's argument order. This method never installs anything.
    /// Existing destinations are preserved; choose a new private staging path for each download.
    pub fn download_update(
        &self,
        info: &UpdateInfo,
        dest: impl AsRef<Path>,
        artifact: Option<&UpdateArtifact>,
        on_progress: Option<&mut dyn FnMut(DownloadProgress)>,
    ) -> Result<UpdateArtifact> {
        self.download_with_options(
            info,
            dest,
            artifact,
            on_progress,
            &PublicUpdateRequestOptions::default(),
        )
    }

    /// Download with an overall deadline and cooperative cancellation.
    /// Progress runs on the calling thread; do not re-enter this client's update methods.
    pub fn download_with_options(
        &self,
        info: &UpdateInfo,
        dest: impl AsRef<Path>,
        artifact: Option<&UpdateArtifact>,
        on_progress: Option<&mut dyn FnMut(DownloadProgress)>,
        request: &PublicUpdateRequestOptions,
    ) -> Result<UpdateArtifact> {
        self.download_checked(info, dest.as_ref(), artifact, on_progress, request, None)
    }

    fn download_checked(
        &self,
        info: &UpdateInfo,
        dest: &Path,
        artifact: Option<&UpdateArtifact>,
        mut on_progress: Option<&mut dyn FnMut(DownloadProgress)>,
        request: &PublicUpdateRequestOptions,
        expected: Option<&Offer>,
    ) -> Result<UpdateArtifact> {
        let budget = Budget::new(self.0.options.download_timeout, request)?;
        self.0.with_state(&budget, |state| {
            let offer = self.0.offer_for(info)?;
            if expected.is_some_and(|prior| {
                prior.manifest != offer.manifest
                    || prior.channel != offer.channel
                    || prior.cutoff != offer.cutoff
            }) {
                return Err(Error::signature("public_update_offer_changed"));
            }
            let keys = self.0.refresh_keys(state, &budget)?;
            let signed = self
                .0
                .verify_offer(&keys, &offer.manifest, &offer.channel)?;
            if signed.info.version != offer.info.version
                || signed.info.release_seq != offer.info.release_seq
            {
                return Err(invalid());
            }
            observe(state, &offer)?;
            if info.release_seq <= state.installed_seq {
                return Err(Error::signature("public_update_rollback"));
            }
            if let Some(running) = state
                .installed_version
                .as_deref()
                .and_then(comparable_version)
            {
                if comparable_version(&info.version).is_none_or(|candidate| {
                    candidate.cmp_precedence(&running) != std::cmp::Ordering::Greater
                }) {
                    return Err(Error::signature("public_update_version_rollback"));
                }
            }
            let chosen = match artifact {
                Some(a) => a.clone(),
                None => info
                    .artifacts
                    .iter()
                    .find(|a| {
                        a.platform == crate::host::platform()
                            && a.arch == crate::host::arch()
                            && a.kind == "installer"
                    })
                    .or_else(|| {
                        info.artifacts.iter().find(|a| {
                            a.platform == crate::host::platform()
                                && a.arch == crate::host::arch()
                                && a.kind == "archive"
                        })
                    })
                    .cloned()
                    .ok_or_else(|| Error::usage("no_matching_update_artifact"))?,
            };
            if !offer.info.artifacts.contains(&chosen) {
                return Err(Error::signature("unverified_update_artifact"));
            }
            let path = chosen
                .download_path
                .as_deref()
                .ok_or_else(|| Error::usage("artifact_has_no_download_path"))?;
            self.0.validate_download_path(path, &offer.channel)?;
            if dest.try_exists()? {
                return Err(Error::usage("public_update_destination_exists"));
            }
            let mut part = Part::create(dest)?;
            let response = self.0.send("GET", path, None, &budget, true)?;
            if response.content_length.is_some_and(|n| n != chosen.size) {
                return Err(Error::signature("artifact_size_mismatch"));
            }
            let mut body = response.body.take(chosen.size.saturating_add(1));
            let mut digest = Sha256::new();
            let mut received = 0u64;
            let mut buf = [0u8; 64 * 1024];
            loop {
                budget.remaining()?;
                let n = body.read(&mut buf).map_err(|_| unavailable())?;
                budget.remaining()?;
                if n == 0 {
                    break;
                }
                received = received.checked_add(n as u64).ok_or_else(invalid)?;
                if received > chosen.size {
                    return Err(Error::signature("artifact_size_mismatch"));
                }
                part.file.write_all(&buf[..n])?;
                digest.update(&buf[..n]);
                if let Some(progress) = &mut on_progress {
                    progress(DownloadProgress {
                        bytes_received: received,
                        total_bytes: chosen.size,
                    });
                }
            }
            if received != chosen.size || hex(&digest.finalize()) != chosen.sha256 {
                return Err(Error::signature("artifact_hash_mismatch"));
            }
            budget.remaining()?;
            part.file.sync_all()?;
            // Linking is atomic and never replaces an existing destination, even if
            // another process created it after the check above. The part is adjacent.
            std::fs::hard_link(&part.path, dest)?;
            if !state.downloaded.contains_key(&info.version) && state.downloaded.len() >= 64 {
                return Err(Error::usage("public_update_history_limit"));
            }
            state
                .downloaded
                .entry(info.version.clone())
                .and_modify(|seq| *seq = (*seq).max(info.release_seq))
                .or_insert(info.release_seq);
            self.0.save(state)?;
            Ok(chosen)
        })
    }

    /// Download only while the registry license remains valid and entitled to this release.
    /// The caller must honor the result before applying the verified staged file.
    pub fn download_registry_update(
        &self,
        registry: &RegistryLicenseClient,
        info: &UpdateInfo,
        dest: impl AsRef<Path>,
        artifact: Option<&UpdateArtifact>,
        on_progress: Option<&mut dyn FnMut(DownloadProgress)>,
    ) -> Result<UpdateArtifact> {
        self.download_registry_update_with_options(
            registry,
            info,
            dest,
            artifact,
            on_progress,
            &PublicUpdateRequestOptions::default(),
        )
    }

    /// Registry-aware download with deadline/cancellation for update HTTP requests.
    /// Registry reads retain the supplied registry client's own request bounds.
    pub fn download_registry_update_with_options(
        &self,
        registry: &RegistryLicenseClient,
        info: &UpdateInfo,
        dest: impl AsRef<Path>,
        artifact: Option<&UpdateArtifact>,
        on_progress: Option<&mut dyn FnMut(DownloadProgress)>,
        request: &PublicUpdateRequestOptions,
    ) -> Result<UpdateArtifact> {
        if request
            .cancellation
            .as_ref()
            .is_some_and(PublicUpdateCancellationToken::is_cancelled)
        {
            return Err(Error::usage("public_update_cancelled"));
        }
        self.authorize_running_release(registry, request)?;
        let offer = self.0.offer_for(info)?;
        bind_registry(registry, &offer)?;
        registry
            .require_valid_license()
            .map_err(registry_error)?
            .require_update_entitlement(offer.published_at)
            .map_err(registry_error)?;
        let chosen = self.download_checked(
            info,
            dest.as_ref(),
            artifact,
            on_progress,
            request,
            Some(&offer),
        )?;
        registry
            .require_valid_license()
            .map_err(registry_error)?
            .require_update_entitlement(offer.published_at)
            .map_err(registry_error)?;
        let budget = Budget::new(self.0.options.http_timeout, request)?;
        self.0.with_state(&budget, |state| {
            self.0.verify_latest_authority(state, &offer)
        })?;
        Ok(chosen)
    }
}

impl PublicUpdateClient {
    /// Require this running build to be covered by the supplied registry license.
    /// Lifetime policies need only fresh registry RPC. Maintenance policies also
    /// verify this exact build's signed publication date. Verified build metadata
    /// is cached independently, so later launches do not depend on Talos HTTP.
    /// Call after a license change and before allowing use of a paid build;
    /// ordinary `require_valid_license()` alone does not enforce a build cutoff.
    pub fn require_running_release_entitlement(
        &self,
        registry: &RegistryLicenseClient,
    ) -> Result<()> {
        self.require_running_release_entitlement_with_options(
            registry,
            &PublicUpdateRequestOptions::default(),
        )
    }

    /// Running-build check with timeout/cancellation for a first metadata resolution.
    /// Legacy `updates: false` restricts update operations, not an already covered build.
    pub fn require_running_release_entitlement_with_options(
        &self,
        registry: &RegistryLicenseClient,
        request: &PublicUpdateRequestOptions,
    ) -> Result<()> {
        self.authorize_running_release(registry, request)
            .map(|_| ())
    }

    fn authorize_running_release(
        &self,
        registry: &RegistryLicenseClient,
        request: &PublicUpdateRequestOptions,
    ) -> Result<crate::registry::RegistryLicenseState> {
        self.bind_registry_configuration(registry)?;
        let budget = Budget::new(self.0.options.http_timeout * 3, request)?;
        budget.remaining()?;
        let before = registry.require_valid_license().map_err(registry_error)?;
        let Some(until) = before
            .maintenance_publication_cutoff()
            .map_err(registry_error)?
        else {
            self.0.with_state(&budget, |state| {
                remember_version(state, self.0.options.app_version.as_deref());
                promote_downloaded(state, self.0.options.app_version.as_deref());
                self.0.save(state)
            })?;
            return Ok(before);
        };
        let version = self
            .0
            .options
            .app_version
            .as_deref()
            .filter(|v| !v.is_empty() && v.len() <= 4096)
            .ok_or_else(|| Error::usage("running_app_version_required"))?;
        let channel = &self.0.channel;
        let offer = self.0.with_state(&budget, |state| {
            let cache_key = running_key(channel, version);
            if let Some(cached) = state.running_releases.get(&cache_key) {
                if state.keyset_conflict { return Err(Error::signature("public_update_keyset_conflict")); }
                let latest = state.keyset.as_deref().ok_or_else(invalid_state)?;
                let claims = verify_keyset(&self.0.anchor, &self.0.options.product_token, latest)?;
                let keys = release_keys(&claims)?;
                let offer = self.0.verify_offer(&keys, &cached.manifest, channel)?;
                if offer.info.version != version { return Err(invalid_state()); }
                return Ok(offer);
            }
            let keys = self.0.refresh_keys(state, &budget)?;
            let body = self.0.post("/v1/client/public-updates/resolve", json!({
                "product_token": self.0.options.product_token, "version": version, "channel": channel,
            }), &budget)?;
            if body.get("update_available").and_then(Value::as_bool) != Some(true) { return Err(invalid()); }
            let manifest = body.get("manifest").and_then(Value::as_str).ok_or_else(invalid)?;
            let offer = self.0.parse_offer(&keys, manifest, channel, &body)?;
            if offer.info.version != version { return Err(Error::signature("running_release_version_mismatch")); }
            bind_registry(registry, &offer)?;
            self.0.cache_running_release(state, &offer)?;
            self.0.save(state)?;
            Ok(offer)
        })?;
        bind_registry(registry, &offer)?;
        if offer.published_at > until {
            return Err(not_entitled());
        }
        let after = registry.require_valid_license().map_err(registry_error)?;
        if after
            .maintenance_publication_cutoff()
            .map_err(registry_error)?
            .is_some_and(|cutoff| offer.published_at > cutoff)
        {
            return Err(not_entitled());
        }
        self.0.with_state(&budget, |state| {
            self.0.verify_latest_authority(state, &offer)?;
            remember_version(state, Some(version));
            state.installed_seq = state.installed_seq.max(offer.info.release_seq);
            promote_downloaded(state, Some(version));
            self.0.save(state)
        })?;
        Ok(after)
    }

    fn bind_registry_configuration(&self, registry: &RegistryLicenseClient) -> Result<()> {
        let expected = self
            .0
            .options
            .registry_product_id
            .as_deref()
            .ok_or_else(|| Error::usage("registry_update_product_required"))?;
        if !expected.eq_ignore_ascii_case(registry.registry_product_id()) {
            return Err(Error::signature("registry_update_product_mismatch"));
        }
        Ok(())
    }
}

impl Inner {
    fn with_state<T>(
        &self,
        budget: &Budget,
        operation: impl FnOnce(&mut Saved) -> Result<T>,
    ) -> Result<T> {
        let _operation = loop {
            budget.remaining()?;
            match self.operation.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::Poisoned(_)) => return Err(invalid()),
                Err(TryLockError::WouldBlock) => budget.wait()?,
            }
        };
        let parent = self
            .path
            .parent()
            .ok_or_else(|| Error::usage("invalid_public_update_state_path"))?;
        if !parent.exists() {
            create_private_dir(parent)?;
        }
        let mut lock_path = self.path.as_os_str().to_owned();
        lock_path.push(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(PathBuf::from(lock_path))?;
        let _file = FileLock::acquire(file, budget)?;
        let mut state = if self.path.try_exists()? {
            let binding = self.store.load().ok_or_else(invalid_state)?;
            let raw = binding.public_update_state.ok_or_else(invalid_state)?;
            if raw.len() > MAX_JSON {
                return Err(invalid_state());
            }
            let saved: Saved = serde_json::from_str(&raw).map_err(|_| invalid_state())?;
            if saved.version != 1
                || [saved.keyset_iat, saved.installed_seq]
                    .iter()
                    .any(|n| !(0..=MAX_SAFE).contains(n))
                || saved.observations.len() > 64
                || saved.observations.values().any(|o| {
                    !(1..=MAX_SAFE).contains(&o.seq)
                        || o.manifest_hash.len() != 64
                        || !o.manifest_hash.bytes().all(|b| b.is_ascii_hexdigit())
                })
                || saved.downloaded.len() > 64
                || saved.downloaded.iter().any(|(version, seq)| {
                    version.is_empty() || version.len() > 4096 || !(1..=MAX_SAFE).contains(seq)
                })
                || saved
                    .installed_version
                    .as_deref()
                    .is_some_and(|v| comparable_version(v).is_none())
                || saved.running_releases.len() > 64
                || saved.running_releases.iter().any(|(key, cached)| {
                    key.len() > 4300
                        || cached.manifest.len() > MAX_JSON
                        || !(1..=MAX_SAFE).contains(&cached.release_seq)
                })
            {
                return Err(invalid_state());
            }
            if let Some(token) = &saved.keyset {
                let claims = verify_keyset(&self.anchor, &self.options.product_token, token)?;
                if positive(&claims, "iat")? != saved.keyset_iat {
                    return Err(invalid_state());
                }
            } else if saved.keyset_iat != 0 || saved.keyset_conflict {
                return Err(invalid_state());
            }
            saved
        } else {
            Saved {
                version: 1,
                ..Saved::default()
            }
        };
        if unix_now().saturating_add(CLOCK_SKEW) < state.keyset_iat {
            return Err(Error::signature("public_update_clock_rollback"));
        }
        budget.remaining()?;
        operation(&mut state)
    }

    fn save(&self, state: &mut Saved) -> Result<()> {
        self.trim_running_releases(state, None)?;
        let mut binding = StoredBinding::empty(&self.fingerprint);
        binding.public_update_state =
            Some(serde_json::to_string(state).map_err(|_| invalid_state())?);
        if binding
            .public_update_state
            .as_ref()
            .is_some_and(|raw| raw.len() > MAX_JSON)
        {
            return Err(Error::usage("public_update_history_limit"));
        }
        if !self.store.save(&binding) {
            return Err(Error::usage("public_update_state_unavailable"));
        }
        Ok(())
    }

    fn cache_running_release(&self, state: &mut Saved, offer: &Offer) -> Result<()> {
        let key = running_key(&offer.channel, &offer.info.version);
        state.running_releases.insert(
            key.clone(),
            RunningRelease {
                manifest: offer.manifest.clone(),
                release_seq: offer.info.release_seq,
            },
        );
        self.trim_running_releases(state, Some(&key))?;
        Ok(())
    }

    fn trim_running_releases(&self, state: &mut Saved, incoming: Option<&str>) -> Result<()> {
        let running = self
            .options
            .app_version
            .as_ref()
            .map(|v| running_key(&self.channel, v));
        loop {
            let size = serde_json::to_vec(state)
                .map_err(|_| invalid_state())?
                .len();
            if state.running_releases.len() <= 64 && size <= MAX_JSON {
                return Ok(());
            }
            let victim = state
                .running_releases
                .iter()
                .filter(|(key, _)| running.as_ref() != Some(key) && incoming != Some(key.as_str()))
                .min_by_key(|(_, proof)| proof.release_seq)
                .map(|(key, _)| key.clone())
                .ok_or_else(|| Error::usage("public_update_history_limit"))?;
            state.running_releases.remove(&victim);
        }
    }

    fn verify_latest_authority(&self, state: &Saved, offer: &Offer) -> Result<()> {
        if state.keyset_conflict {
            return Err(Error::signature("public_update_keyset_conflict"));
        }
        let token = state.keyset.as_deref().ok_or_else(invalid_state)?;
        let claims = verify_keyset(&self.anchor, &self.options.product_token, token)?;
        self.verify_offer(&release_keys(&claims)?, &offer.manifest, &offer.channel)?;
        Ok(())
    }

    fn send(
        &self,
        method: &'static str,
        path: &str,
        body: Option<Value>,
        budget: &Budget,
        download: bool,
    ) -> Result<HttpResponse> {
        let remaining = budget.remaining()?;
        let response = self
            .transport
            .send(HttpRequest {
                method,
                url: format!("{}{path}", self.base),
                headers: vec![("content-type", "application/json".into())],
                body: body
                    .map(|v| serde_json::to_vec(&v))
                    .transpose()
                    .map_err(|_| invalid())?,
                timeout: Some(if download {
                    remaining
                } else {
                    remaining.min(self.options.http_timeout)
                }),
            })
            .map_err(|_| unavailable())?;
        budget.remaining()?;
        if !(200..300).contains(&response.status) {
            let status = response.status;
            let mut raw = Vec::new();
            let _ = response.body.take(8193).read_to_end(&mut raw);
            budget.remaining()?;
            let parsed = (raw.len() <= 8192)
                .then(|| serde_json::from_slice::<Value>(&raw).ok())
                .flatten();
            let code = match parsed
                .as_ref()
                .and_then(|v| v.get("error"))
                .and_then(Value::as_str)
            {
                Some("public_updates_disabled") => "public_updates_disabled",
                Some("public_release_not_found") => "public_release_not_found",
                Some("artifact_not_found") => "artifact_not_found",
                Some("product_not_found") => "product_not_found",
                Some("invalid_channel") => "invalid_channel",
                Some("invalid_published_before") => "invalid_published_before",
                Some("updates_not_entitled") => "updates_not_entitled",
                Some("node_degraded") => "node_degraded",
                Some("node_killed") => "node_killed",
                Some("tenant_suspended") => "tenant_suspended",
                _ => "public_update_request_failed",
            };
            return Err(Error::Api {
                status,
                code: Some(code.into()),
            });
        }
        Ok(response)
    }

    fn post(&self, path: &str, body: Value, budget: &Budget) -> Result<Value> {
        let response = self.send("POST", path, Some(body), budget, false)?;
        if response.content_length.is_some_and(|n| n > MAX_JSON as u64) {
            return Err(invalid());
        }
        let mut raw = Vec::new();
        response
            .body
            .take((MAX_JSON + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(|_| unavailable())?;
        budget.remaining()?;
        if raw.len() > MAX_JSON {
            return Err(invalid());
        }
        serde_json::from_slice(&raw).map_err(|_| invalid())
    }

    fn refresh_keys(&self, state: &mut Saved, budget: &Budget) -> Result<Vec<PublicKey>> {
        let body = self.post(
            "/v1/client/keyset",
            json!({ "product_token": self.options.product_token }),
            budget,
        )?;
        let token = body
            .get("keyset")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let claims = verify_keyset(&self.anchor, &self.options.product_token, token)?;
        let iat = positive(&claims, "iat")?;
        if iat > unix_now().saturating_add(CLOCK_SKEW) {
            return Err(Error::signature("invalid_keyset_time"));
        }
        if iat < state.keyset_iat {
            return Err(Error::signature("public_update_keyset_rollback"));
        }
        if iat == state.keyset_iat
            && (state.keyset_conflict || state.keyset.as_deref().is_some_and(|old| old != token))
        {
            // A second-granularity timestamp cannot order two different signed
            // keysets. Persist that ambiguity, including on failed operations:
            // replaying the predecessor after restart must not revive a key.
            state.keyset = Some(token.into());
            state.keyset_conflict = true;
            self.save(state)?;
            return Err(Error::signature("public_update_keyset_conflict"));
        }
        let keys = release_keys(&claims);
        state.keyset = Some(token.into());
        state.keyset_iat = iat;
        state.keyset_conflict = false;
        // Persist revocation observations even when the new keyset contains no
        // release key. A later replay must not resurrect its predecessor.
        self.save(state)?;
        keys
    }

    fn verify_offer(&self, keys: &[PublicKey], manifest: &str, channel: &str) -> Result<Offer> {
        let claims = verify_manifest_at(keys, &self.options.product_token, manifest, unix_now())?;
        if claims.get("v").and_then(Value::as_i64) != Some(1)
            || claims.get("typ").and_then(Value::as_str) != Some("manifest")
            || claims.get("channel").and_then(Value::as_str) != Some(channel)
        {
            return Err(invalid());
        }
        let version = text(&claims, "version")?;
        let release_seq = positive(&claims, "release_seq")?;
        let mut published_at = positive(&claims, "iat")?;
        for field in ["published_at", "not_before"] {
            if let Some(value) = claims.get(field).filter(|v| !v.is_null()) {
                let n = value
                    .as_i64()
                    .filter(|n| (0..=MAX_SAFE).contains(n))
                    .ok_or_else(invalid)?;
                published_at = published_at.max(n);
            }
        }
        if published_at > unix_now().saturating_add(CLOCK_SKEW) {
            return Err(Error::signature("manifest_not_yet_published"));
        }
        let product_id = text(&claims, "product_id")?;
        if !uuid_hex(&product_id) {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let artifacts = claims
            .get("artifacts")
            .and_then(Value::as_array)
            .filter(|v| !v.is_empty() && v.len() <= 128)
            .ok_or_else(invalid)?;
        let mut parsed = Vec::new();
        for item in artifacts {
            let item = item.as_object().ok_or_else(invalid)?;
            let platform = text(item, "platform")?;
            let arch = text(item, "arch")?;
            let kind = text(item, "kind")?;
            if kind == "delta" || !seen.insert((platform.clone(), arch.clone(), kind.clone())) {
                return Err(invalid());
            }
            let filename = text(item, "filename")?;
            if filename.contains(['/', '\\', ':']) || matches!(filename.as_str(), "." | "..") {
                return Err(invalid());
            }
            let size = item
                .get("size")
                .and_then(Value::as_u64)
                .filter(|n| {
                    *n > 0 && *n <= self.options.max_artifact_bytes && *n <= MAX_SAFE as u64
                })
                .ok_or_else(invalid)?;
            let sha256 = text(item, "sha256")?;
            if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid());
            }
            parsed.push(UpdateArtifact {
                platform,
                arch,
                kind,
                filename,
                size,
                sha256: sha256.to_ascii_lowercase(),
                download_path: None,
            });
        }
        let mandatory = claims
            .get("mandatory")
            .and_then(Value::as_bool)
            .ok_or_else(invalid)?;
        let notes_url = match claims.get("notes_url") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.len() <= 4096 => Some(s.clone()),
            _ => return Err(invalid()),
        };
        Ok(Offer {
            info: UpdateInfo {
                version,
                release_seq,
                mandatory,
                notes_url,
                artifacts: parsed,
                deltas: Vec::new(),
            },
            manifest: manifest.into(),
            channel: channel.into(),
            product_id,
            published_at: published_at as u64,
            cutoff: None,
        })
    }

    fn parse_offer(
        &self,
        keys: &[PublicKey],
        manifest: &str,
        channel: &str,
        body: &Value,
    ) -> Result<Offer> {
        let mut offer = self.verify_offer(keys, manifest, channel)?;
        let refs = body
            .get("artifacts")
            .and_then(Value::as_array)
            .filter(|r| r.len() <= 128)
            .ok_or_else(invalid)?;
        let mut seen = BTreeSet::new();
        for r in refs {
            let r = r.as_object().ok_or_else(invalid)?;
            let platform = text(r, "platform")?;
            let arch = text(r, "arch")?;
            let kind = text(r, "kind")?;
            if !seen.insert((platform.clone(), arch.clone(), kind.clone())) {
                return Err(invalid());
            }
            let artifact_id = text(r, "artifact_id")?;
            if !uuid_any(&artifact_id) {
                return Err(invalid());
            }
            let path = text(r, "download_path")?;
            self.validate_download_path(&path, channel)?;
            let expected = download_path(&self.options.product_token, channel, &artifact_id);
            if path != expected {
                return Err(invalid());
            }
            let artifact = offer
                .info
                .artifacts
                .iter_mut()
                .find(|a| a.platform == platform && a.arch == arch && a.kind == kind)
                .ok_or_else(invalid)?;
            artifact.download_path = Some(path);
        }
        Ok(offer)
    }

    fn validate_download_path(&self, path: &str, channel: &str) -> Result<()> {
        let rest = path
            .strip_prefix("/v1/client/public-updates/artifacts/")
            .ok_or_else(invalid)?;
        let (id, _) = rest.split_once('?').ok_or_else(invalid)?;
        if !uuid_any(id) || path != download_path(&self.options.product_token, channel, id) {
            return Err(invalid());
        }
        Ok(())
    }

    fn offer_for(&self, info: &UpdateInfo) -> Result<Offer> {
        lock(&self.offer)?
            .as_ref()
            .filter(|o| o.info == *info)
            .cloned()
            .ok_or_else(|| Error::signature("unverified_public_update_offer"))
    }
}

fn bind_registry(registry: &RegistryLicenseClient, offer: &Offer) -> Result<()> {
    let raw = offer.product_id.replace('-', "");
    let bytes = (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).map_err(|_| invalid()))
        .collect::<Result<Vec<_>>>()?;
    let hash = format!("0x{}", hex(&Keccak256::digest(bytes)));
    if !registry.registry_product_id().eq_ignore_ascii_case(&hash) {
        return Err(Error::signature("registry_update_product_mismatch"));
    }
    Ok(())
}

fn registry_error(error: RegistryLicenseError) -> Error {
    Error::Api {
        status: if error.is_transient() { 503 } else { 403 },
        code: Some(error.code().into()),
    }
}

fn release_keys(claims: &serde_json::Map<String, Value>) -> Result<Vec<PublicKey>> {
    let entries = claims
        .get("keys")
        .and_then(Value::as_array)
        .filter(|v| v.len() <= 128)
        .ok_or_else(invalid)?;
    let mut keys = Vec::new();
    for entry in entries {
        if entry.get("purpose").and_then(Value::as_str) == Some("release")
            && matches!(
                entry.get("status").and_then(Value::as_str),
                Some("active" | "retired")
            )
        {
            keys.push(PublicKey::from_base64(
                entry
                    .get("pk")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid)?,
            )?);
        }
    }
    if keys.is_empty() {
        return Err(Error::signature("no_release_verification_key"));
    }
    Ok(keys)
}

fn running_key(channel: &str, version: &str) -> String {
    format!("{}:{channel}{version}", channel.len())
}
fn not_entitled() -> Error {
    Error::Api {
        status: 403,
        code: Some("updates_not_entitled".into()),
    }
}

fn comparable_version(value: &str) -> Option<semver::Version> {
    let value = value.trim();
    if value.len() > 4096 {
        return None;
    }
    let value = value
        .strip_prefix('v')
        .or_else(|| value.strip_prefix('V'))
        .unwrap_or(value);
    if let Ok(version) = semver::Version::parse(value) {
        return Some(version);
    }
    // The server also accepts a missing minor/patch. Normalize that spelling,
    // then let semver own the version grammar and precedence comparison.
    let end = value.find(['-', '+']).unwrap_or(value.len());
    let (core, suffix) = value.split_at(end);
    let normalized = match core.split('.').count() {
        1 => format!("{core}.0.0{suffix}"),
        2 => format!("{core}.0{suffix}"),
        _ => return None,
    };
    semver::Version::parse(&normalized).ok()
}

fn remember_version(state: &mut Saved, value: Option<&str>) {
    let Some(candidate) = value.and_then(comparable_version) else {
        return;
    };
    if state
        .installed_version
        .as_deref()
        .and_then(comparable_version)
        .is_none_or(|old| candidate.cmp_precedence(&old) == std::cmp::Ordering::Greater)
    {
        state.installed_version = Some(candidate.to_string());
    }
}

fn promote_downloaded(state: &mut Saved, version: Option<&str>) {
    if let Some(seq) = version.and_then(|version| state.downloaded.get(version)) {
        state.installed_seq = state.installed_seq.max(*seq);
    }
    state.downloaded.retain(|_, seq| *seq > state.installed_seq);
}

fn product_hash(value: &str) -> bool {
    value.strip_prefix("0x").is_some_and(|s| {
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) && s.bytes().any(|b| b != b'0')
    })
}

fn observe(state: &mut Saved, offer: &Offer) -> Result<()> {
    let digest = hex(&Sha256::digest(offer.manifest.as_bytes()));
    let domain = format!(
        "{}:{}",
        offer.channel,
        offer.cutoff.map_or_else(|| "all".into(), |n| n.to_string())
    );
    if let Some(old) = state.observations.get(&domain) {
        if offer.info.release_seq < old.seq
            || (offer.info.release_seq == old.seq && old.manifest_hash != digest)
        {
            return Err(Error::signature("public_update_rollback"));
        }
    } else if state.observations.len() >= 64 {
        return Err(Error::usage("public_update_history_limit"));
    }
    state.observations.insert(
        domain,
        Observation {
            seq: offer.info.release_seq,
            manifest_hash: digest,
        },
    );
    Ok(())
}

fn positive(claims: &serde_json::Map<String, Value>, field: &str) -> Result<i64> {
    claims
        .get(field)
        .and_then(Value::as_i64)
        .filter(|n| (1..=MAX_SAFE).contains(n))
        .ok_or_else(invalid)
}
fn text(claims: &serde_json::Map<String, Value>, field: &str) -> Result<String> {
    claims
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(invalid)
}
fn validate_channel(channel: &str) -> Result<()> {
    if channel.is_empty() || channel.len() > 100 || channel.chars().any(char::is_control) {
        return Err(Error::usage("invalid_update_channel"));
    }
    Ok(())
}
fn uuid_hex(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn uuid_canonical(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn uuid_any(s: &str) -> bool {
    uuid_hex(s) || uuid_canonical(s)
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"*-._".contains(&b) {
                (b as char).to_string()
            } else if b == b' ' {
                "+".into()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
fn download_path(token: &str, channel: &str, id: &str) -> String {
    format!(
        "/v1/client/public-updates/artifacts/{id}?product_token={}&channel={}",
        encode(token),
        encode(channel)
    )
}
fn invalid() -> Error {
    Error::signature("invalid_public_update_response")
}
fn invalid_state() -> Error {
    Error::signature("invalid_public_update_state")
}
fn unavailable() -> Error {
    Error::Network("public_update_unavailable".into())
}
fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    m.lock().map_err(|_| invalid_state())
}

struct Budget {
    deadline: Instant,
    cancellation: Option<PublicUpdateCancellationToken>,
}
impl Budget {
    fn new(default: Duration, options: &PublicUpdateRequestOptions) -> Result<Self> {
        let timeout = options.timeout.unwrap_or(default);
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err(Error::usage("invalid_public_update_timeout"));
        }
        Ok(Self {
            deadline: Instant::now() + timeout,
            cancellation: options.cancellation.clone(),
        })
    }
    fn remaining(&self) -> Result<Duration> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(PublicUpdateCancellationToken::is_cancelled)
        {
            return Err(Error::usage("public_update_cancelled"));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| Error::Network("public_update_timeout".into()))
    }
    fn wait(&self) -> Result<()> {
        std::thread::sleep(self.remaining()?.min(Duration::from_millis(5)));
        self.remaining().map(|_| ())
    }
}

struct FileLock(File);
impl FileLock {
    fn acquire(file: File, budget: &Budget) -> Result<Self> {
        loop {
            budget.remaining()?;
            match FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok(Self(file)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => budget.wait()?,
                Err(e) => return Err(e.into()),
            }
        }
    }
}
impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

struct Part {
    path: PathBuf,
    file: File,
}
impl Part {
    fn create(dest: &Path) -> Result<Self> {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| Error::usage("public_update_random_unavailable"))?;
        let mut path = dest.as_os_str().to_owned();
        path.push(format!(".{}.talos-part", hex(&random)));
        let path = PathBuf::from(path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        Ok(Self { path, file })
    }
}
impl Drop for Part {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests;
