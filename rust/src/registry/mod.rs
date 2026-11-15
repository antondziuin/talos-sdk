//! Walletless code activation and fresh license checks against a pinned EVM registry.
//! Calls block: run them on a worker thread. A cached manifest never grants access.

mod activation;
mod chain;
mod protocol;

use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::{
    state::{create_private_dir, state_key_material, StateStore, StoredBinding},
    transport::{HttpRequest, HttpResponse, Transport},
};
use activation::{ActivationEndpoint, ActivationResponse, ActivationStatus};
pub(crate) use protocol::validate_endpoint;
use protocol::ParsedManifest;
pub use protocol::{RegistryLicenseManifest, RegistryTrust};

/// A sanitized registry failure. Error text never contains codes, keys or RPC credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryLicenseError {
    code: &'static str,
    transient: bool,
}

impl RegistryLicenseError {
    pub(super) fn new(code: &'static str) -> Self {
        Self {
            code,
            transient: false,
        }
    }
    pub(super) fn transient(code: &'static str) -> Self {
        Self {
            code,
            transient: true,
        }
    }
    /// Stable machine-readable reason, such as `license_expired` or `wrong_device`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }
    /// Whether another pinned RPC provider may be tried for this observation.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        self.transient
    }
}

impl fmt::Display for RegistryLicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for RegistryLicenseError {}
pub(super) type RegistryError = RegistryLicenseError;
/// Result returned by the registry client; independent of classic Talos offline grace.
pub type RegistryResult<T> = std::result::Result<T, RegistryLicenseError>;

/// Immutable application configuration. Never load trust pins from a customer's license file.
#[derive(Clone)]
pub struct RegistryLicenseOptions {
    /// Publisher namespace address, 0x-prefixed 20-byte hex.
    pub issuer: String,
    /// Product namespace: Keccak-256 of the product UUID's 16 bytes.
    pub product_id: String,
    /// Base (8453), Sepolia (11155111), or local Anvil (31337).
    pub chain_id: u64,
    /// The deployed TalosLicenseRegistryV1 address.
    pub contract: String,
    /// One to five trusted HTTPS RPC URLs; loopback HTTP is allowed for tests.
    pub rpc_urls: Vec<String>,
    /// Separate encrypted device state; defaults to a registry-specific scope.
    pub state_path: Option<PathBuf>,
    /// Stable components merged over the platform probes, as in `TalosOptions`.
    pub fingerprint_components: BTreeMap<String, String>,
    /// Custom blocking transport. It must honor timeouts and never follow redirects.
    pub transport: Option<Arc<dyn Transport>>,
    /// Trusted Talos HTTPS API origin/base path, required for activation by code.
    pub activation_url: Option<String>,
    /// Public product token, required with `activation_url`.
    pub product_token: Option<String>,
    /// Per-request timeout, capped at ten seconds; zero is refused.
    pub http_timeout: Duration,
}

impl Default for RegistryLicenseOptions {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            product_id: String::new(),
            chain_id: 11155111,
            contract: String::new(),
            rpc_urls: Vec::new(),
            state_path: None,
            fingerprint_components: BTreeMap::new(),
            transport: None,
            activation_url: None,
            product_token: None,
            http_timeout: Duration::from_secs(10),
        }
    }
}

/// Cooperative cancellation for activation, polling and waits. An in-flight
/// custom transport must also honor the request timeout.
#[derive(Clone, Default)]
pub struct RegistryCancellationToken(Arc<AtomicBool>);
impl RegistryCancellationToken {
    /// Create an uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Cancel all operations sharing this token.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Stage reported to the application, without a license code or private identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryActivationStatus {
    /// Publication is still queued or awaiting confirmation.
    Pending,
    /// The server reports publication; independent RPC checks are running.
    Validating,
    /// A fresh chain observation authorizes the device.
    Ready,
}

/// Progress for a resumable activation.
#[derive(Debug, Clone)]
pub struct RegistryActivationProgress {
    /// Current stage.
    pub status: RegistryActivationStatus,
    /// Public activation job UUID.
    pub activation_id: String,
    /// Suggested delay before another status poll.
    pub retry_after_seconds: u64,
}

/// Deadline and optional application notifications for activation.
#[derive(Clone, Default)]
pub struct RegistryActivationOptions {
    /// Overall budget: default ten minutes on Base, two minutes elsewhere;
    /// explicit values must be positive and at most ten minutes.
    pub timeout: Option<Duration>,
    /// Cooperative cancellation, also checked during polling sleeps and locks.
    pub cancellation: Option<RegistryCancellationToken>,
    /// Short notification callback. Run blocking SDK work outside the UI thread;
    /// callbacks must not re-enter activation. Callback panics are isolated.
    pub on_progress: Option<Arc<dyn Fn(RegistryActivationProgress) + Send + Sync>>,
}

/// A fresh observation, not an offline permit. Recheck before protected work.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryLicenseState {
    /// Entitlements whose exact bytes hash matches the current chain record.
    pub entitlements: Map<String, Value>,
    /// Expiry in Unix seconds; `None` means perpetual.
    pub expires_at: Option<u64>,
    /// Earliest permitted time, Unix seconds.
    pub not_before: u64,
    /// Current on-chain revision.
    pub revision: u64,
    /// Block used for every part of this check.
    pub block_number: u64,
    /// Canonical hash of that block.
    pub block_hash: String,
    /// Monotonic local observation time, Unix seconds.
    pub checked_at: u64,
}

impl RegistryLicenseState {
    /// True only for a boolean `true` entitlement; never coerces other types.
    #[must_use]
    pub fn entitlement_bool(&self, name: &str) -> bool {
        self.entitlements.get(name).and_then(Value::as_bool) == Some(true)
    }
    /// Read an integer entitlement without coercion.
    #[must_use]
    pub fn entitlement_i64(&self, name: &str) -> Option<i64> {
        self.entitlements.get(name).and_then(Value::as_i64)
    }

    /// Authorize an update whose publication timestamp came from an independently
    /// verified, product-pinned signed release manifest. Never pass a timestamp
    /// supplied by a customer or copied from unsigned release-list metadata.
    /// Maintenance limits update eligibility, not the runtime license's validity.
    pub fn require_update_entitlement(&self, release_timestamp: u64) -> RegistryResult<()> {
        const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
        if release_timestamp == 0 || release_timestamp > MAX_SAFE_INTEGER {
            return Err(RegistryError::new("invalid_release_timestamp"));
        }
        match self.update_publication_cutoff()? {
            Some(until) if release_timestamp > until => {
                Err(RegistryError::new("updates_not_entitled"))
            }
            _ => Ok(()),
        }
    }

    /// Latest eligible signed publication time, or no publication cutoff for
    /// license-mode/legacy grants. This is a discovery hint, not authorization:
    /// verify the offered release and recheck this license before downloading.
    pub fn update_publication_cutoff(&self) -> RegistryResult<Option<u64>> {
        match self.entitlements.get("updates") {
            Some(Value::Bool(false)) => {
                return Err(RegistryError::new("updates_not_entitled"));
            }
            None | Some(Value::Bool(true)) => {}
            Some(_) => return Err(RegistryError::new("invalid_update_entitlement")),
        }
        self.maintenance_publication_cutoff()
    }

    /// Maintenance window for a verified running build's signed publication
    /// time. Unlike update discovery, this ignores the legacy `updates: false`
    /// switch: disabling new downloads must not disable an already paid build.
    /// The caller must still check the runtime license and signed build identity.
    pub fn maintenance_publication_cutoff(&self) -> RegistryResult<Option<u64>> {
        const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
        let Some(policy) = self.entitlements.get("talos_updates") else {
            return Ok(None); // Existing registry grants predate update metadata.
        };
        let policy = policy
            .as_object()
            .ok_or_else(|| RegistryError::new("invalid_update_entitlement"))?;
        match policy.get("mode").and_then(Value::as_str) {
            Some("license") if policy.len() == 1 => Ok(None),
            Some("maintenance") if policy.len() == 2 => {
                let until = policy
                    .get("until")
                    .and_then(Value::as_u64)
                    .filter(|n| *n > 0 && *n <= MAX_SAFE_INTEGER)
                    .ok_or_else(|| RegistryError::new("invalid_update_entitlement"))?;
                Ok(Some(until))
            }
            _ => Err(RegistryError::new("invalid_update_entitlement")),
        }
    }
}

struct Clock {
    high: Duration,
    anchor: Instant,
}
impl Clock {
    fn now(&mut self) -> u64 {
        let instant = Instant::now();
        self.high = self
            .high
            .saturating_add(instant.duration_since(self.anchor))
            .max(Duration::from_secs(wall_time()));
        self.anchor = instant;
        self.high.as_secs()
    }
}
fn wall_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|e| e.into_inner())
}

struct LimitedTransport {
    inner: Arc<dyn Transport>,
    timeout: Duration,
}
impl Transport for LimitedTransport {
    fn send(&self, mut request: HttpRequest) -> Result<HttpResponse, String> {
        request.timeout = Some(request.timeout.unwrap_or(self.timeout).min(self.timeout));
        self.inner.send(request)
    }
}
struct ScopedTransport<'a> {
    inner: &'a dyn Transport,
    budget: &'a Budget,
}
impl Transport for ScopedTransport<'_> {
    fn send(&self, mut request: HttpRequest) -> Result<HttpResponse, String> {
        let remaining = self
            .budget
            .remaining()
            .map_err(|_| "registry_activation_unavailable".to_owned())?;
        request.timeout = Some(request.timeout.unwrap_or(remaining).min(remaining));
        self.inner.send(request)
    }
}

struct Inner {
    options: RegistryLicenseOptions,
    trust: RegistryTrust,
    transport: Arc<dyn Transport>,
    endpoint: Option<ActivationEndpoint>,
    store: StateStore,
    path: PathBuf,
    key: SigningKey,
    device_key: String,
    manifest: Mutex<Option<ParsedManifest>>,
    clock: Mutex<Clock>,
    generation: AtomicU64,
}

/// A persistent device identity and a direct registry reader. Clone handles share
/// state. No Ethereum wallet, transaction signing or transaction sending is used.
#[derive(Clone)]
pub struct RegistryLicenseClient(Arc<Inner>);

impl fmt::Debug for RegistryLicenseClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistryLicenseClient")
            .field("chain_id", &self.0.trust.chain_id)
            .finish_non_exhaustive()
    }
}

impl RegistryLicenseClient {
    /// Validate configuration and restore/create this installation's encrypted
    /// device identity. An unwritable state file is a refusal, not best-effort.
    pub fn new(mut options: RegistryLicenseOptions) -> RegistryResult<Self> {
        let trust = RegistryTrust {
            chain_id: options.chain_id,
            contract: options.contract.to_ascii_lowercase(),
            issuer: options.issuer.to_ascii_lowercase(),
            product_id: options.product_id.to_ascii_lowercase(),
        };
        protocol::validate_trust(&trust)?;
        if options.rpc_urls.is_empty()
            || options.rpc_urls.len() > 5
            || options.http_timeout.is_zero()
        {
            return Err(RegistryError::new("invalid_registry_configuration"));
        }
        for rpc in &options.rpc_urls {
            protocol::validate_endpoint(rpc, false)?;
        }
        let endpoint = match (&options.activation_url, &options.product_token) {
            (Some(url), Some(token)) => Some(ActivationEndpoint::new(url, token)?),
            (None, None) => None,
            _ => return Err(RegistryError::new("invalid_registry_configuration")),
        };
        let transport = match options.transport.take() {
            Some(transport) => transport,
            None => default_transport()?,
        };
        let transport: Arc<dyn Transport> = Arc::new(LimitedTransport {
            inner: transport,
            timeout: options.http_timeout.min(Duration::from_secs(10)),
        });
        let (store, path, composite) = state_location(&options, &trust)?;
        let _guard = FileLock::acquire(&lock_path(&path, ".lock"), None)?;
        let mut binding = match store.load() {
            Some(binding) => binding,
            None if path.exists() => return Err(RegistryError::new("invalid_device_state")),
            None => StoredBinding::empty(&composite),
        };
        if binding.machine_key.is_none()
            && (binding.registry_activation_id.is_some()
                || binding.registry_manifest.is_some()
                || binding.registry_replacement_id.is_some())
        {
            return Err(RegistryError::new("device_key_missing"));
        }
        let key = if binding.machine_key.is_some() {
            stored_key(&binding)?
        } else {
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(&mut *seed)
                .map_err(|_| RegistryError::new("device_key_generation_failed"))?;
            let key = SigningKey::from_bytes(&seed);
            binding.machine_key = Some(STANDARD.encode(seed.as_slice()));
            binding.machine_public_key = Some(STANDARD.encode(key.verifying_key().as_bytes()));
            if !store.save(&binding) {
                return Err(RegistryError::new("device_key_not_saved"));
            }
            key
        };
        if let Some(id) = &binding.registry_activation_id {
            if !protocol::registry_uuid(id) {
                return Err(RegistryError::new("invalid_registry_activation_state"));
            }
        }
        if binding.registry_activation_id.is_some() && binding.registry_manifest.is_some() {
            return Err(RegistryError::new("registry_activation_state_conflict"));
        }
        if let Some(id) = &binding.registry_replacement_id {
            if !protocol::registry_uuid(id) {
                return Err(RegistryError::new("invalid_registry_activation_state"));
            }
            if binding.registry_manifest.is_none() || binding.registry_activation_id.is_some() {
                return Err(RegistryError::new("registry_activation_state_conflict"));
            }
        }
        let manifest = binding
            .registry_manifest
            .as_deref()
            .map(|raw| protocol::parse_manifest(raw, &trust))
            .transpose()?;
        chain::parse_chain_state(binding.registry_chain_state.as_deref())?;
        let high = wall_time()
            .max(binding.time_high_water.max(0) as u64)
            .max(binding.offline_seen.max(0) as u64);
        let device_key = protocol::hex(key.verifying_key().as_bytes());
        Ok(Self(Arc::new(Inner {
            options,
            trust,
            transport,
            endpoint,
            store,
            path,
            key,
            device_key,
            manifest: Mutex::new(manifest),
            clock: Mutex::new(Clock {
                high: Duration::from_secs(high),
                anchor: Instant::now(),
            }),
            generation: AtomicU64::new(0),
        })))
    }

    /// Public Ed25519 device key. It is not an Ethereum account or private key.
    #[must_use]
    pub fn device_key(&self) -> &str {
        &self.0.device_key
    }
    pub(crate) fn registry_product_id(&self) -> &str {
        &self.0.trust.product_id
    }
    /// A manifest is loaded. This alone is never permission to use the application.
    #[must_use]
    pub fn is_activated(&self) -> bool {
        lock(&self.0.manifest).is_some()
    }
    /// Whether the retained state contains a job that can be resumed without a code.
    #[must_use]
    pub fn has_pending_activation(&self) -> bool {
        self.with_binding(|binding| Ok(binding.registry_activation_id.is_some()))
            .unwrap_or(false)
    }
    /// A replacement is retained separately from the current license. Check this
    /// before prompting for a further code, and call `resume_replacement`.
    #[must_use]
    pub fn has_pending_replacement(&self) -> bool {
        self.with_binding(|binding| Ok(binding.registry_replacement_id.is_some()))
            .unwrap_or(false)
    }
    /// Import public lookup information. It grants no access and is not persisted
    /// as an activation; `require_valid_license` must independently check RPC.
    pub fn import_license(&self, raw: &str) -> RegistryResult<()> {
        let parsed = protocol::parse_manifest(raw, &self.0.trust)?;
        let mut manifest = lock(&self.0.manifest);
        *manifest = Some(parsed);
        self.0.generation.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    /// Export this activated license as a portable file: the public manifest
    /// together with the secret half of the key the registry record is bound to.
    ///
    /// The registry binds a license to one key, not to one computer. A file
    /// carrying that key therefore validates on any machine, with no Talos
    /// server involved — each one still reads the registry over RPC, so a
    /// revocation or expiry on chain stops every copy at once.
    ///
    /// **The file is a bearer credential.** Whoever holds it can run the
    /// application; there is no device limit. Call this only for licenses that
    /// are meant to be unrestricted, and never log or upload the result. A
    /// fresh valid observation is required first: an invalid license is not
    /// exported.
    pub fn export_portable_license(&self) -> RegistryResult<String> {
        self.validate()?;
        let (manifest, secret) = self.with_binding(|binding| {
            if binding.registry_activation_id.is_some() || binding.registry_replacement_id.is_some()
            {
                return Err(RegistryError::new("registry_activation_state_conflict"));
            }
            let manifest = binding
                .registry_manifest
                .clone()
                .ok_or_else(|| RegistryError::new("registry_license_not_activated"))?;
            let secret = Zeroizing::new(
                binding
                    .machine_key
                    .clone()
                    .ok_or_else(|| RegistryError::new("device_key_missing"))?,
            );
            Ok((manifest, secret))
        })?;
        let mut file = Map::new();
        file.insert("v".into(), Value::from(1));
        file.insert("kind".into(), Value::from(PORTABLE_KIND));
        file.insert("manifest".into(), Value::from(manifest));
        file.insert("device_secret".into(), Value::from(secret.as_str()));
        Ok(Value::Object(file).to_string())
    }

    /// Install a portable license file on this machine and open a client for it.
    ///
    /// No Talos request is made, now or later. The file's key and manifest are
    /// written into this installation's own encrypted state, after which the
    /// client behaves exactly as if it had been activated here. Importing
    /// grants nothing by itself: `require_valid_license` must still succeed
    /// against the registry.
    ///
    /// An installation that already holds a different license, or has an
    /// activation in progress, is refused rather than overwritten. Importing
    /// the same file again is a no-op.
    pub fn import_portable_license(
        options: RegistryLicenseOptions,
        raw: &str,
    ) -> RegistryResult<Self> {
        let invalid = || RegistryError::new("invalid_portable_license");
        let trust = RegistryTrust {
            chain_id: options.chain_id,
            contract: options.contract.to_ascii_lowercase(),
            issuer: options.issuer.to_ascii_lowercase(),
            product_id: options.product_id.to_ascii_lowercase(),
        };
        protocol::validate_trust(&trust)?;
        if raw.len() > 131_072 {
            return Err(invalid());
        }
        let file: Value = serde_json::from_str(raw).map_err(|_| invalid())?;
        if file.get("v").and_then(Value::as_u64) != Some(1)
            || file.get("kind").and_then(Value::as_str) != Some(PORTABLE_KIND)
        {
            return Err(invalid());
        }
        let manifest = file
            .get("manifest")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let secret = Zeroizing::new(
            file.get("device_secret")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?
                .to_owned(),
        );
        // The pins come from the application, never from the file: a manifest
        // for another issuer, product, chain or contract is refused here.
        let parsed = protocol::parse_manifest(manifest, &trust)?;
        let seed = Zeroizing::new(STANDARD.decode(secret.as_str()).map_err(|_| invalid())?);
        let seed: &[u8; 32] = seed.as_slice().try_into().map_err(|_| invalid())?;
        if STANDARD.encode(seed) != *secret {
            return Err(invalid());
        }
        let public = STANDARD.encode(SigningKey::from_bytes(seed).verifying_key().as_bytes());

        let (store, path, composite) = state_location(&options, &trust)?;
        {
            let _guard = FileLock::acquire(&lock_path(&path, ".lock"), None)?;
            let mut binding = match store.load() {
                Some(binding) => binding,
                None if path.exists() => return Err(RegistryError::new("invalid_device_state")),
                None => StoredBinding::empty(&composite),
            };
            if binding.registry_activation_id.is_some() || binding.registry_replacement_id.is_some()
            {
                return Err(RegistryError::new("registry_activation_state_conflict"));
            }
            if let Some(current) = &binding.registry_manifest {
                let current = protocol::parse_manifest(current, &trust)?;
                if current.manifest != parsed.manifest
                    || binding.machine_public_key.as_deref() != Some(public.as_str())
                {
                    return Err(RegistryError::new("registry_already_activated"));
                }
            } else {
                // A key generated here and never bound to anything is replaced;
                // nothing on chain refers to it.
                binding.machine_key = Some(secret.as_str().to_owned());
                binding.machine_public_key = Some(public);
                binding.registry_manifest = Some(manifest.to_owned());
                binding.registry_chain_state = None;
                if !store.save(&binding) {
                    return Err(RegistryError::new("device_state_not_saved"));
                }
            }
        }
        Self::new(options)
    }

    /// Tell the publisher's Talos server that this installation started.
    ///
    /// Advisory in both directions: it feeds the publisher's per-license
    /// install and launch counts, and it is **never** a condition of access —
    /// call it after `require_valid_license`, ignore its error, and do not
    /// retry in a loop. Offline, or with Talos down, it fails with
    /// `registry_checkin_unavailable` and the license keeps working.
    ///
    /// Sent: the public license identifier, a product-scoped digest of this
    /// machine's fingerprint, the OS and architecture, and `app_version`. No
    /// host name, user name or raw hardware identifier.
    pub fn report_launch(&self, app_version: Option<&str>) -> RegistryResult<()> {
        let endpoint = self
            .0
            .endpoint
            .as_ref()
            .ok_or_else(|| RegistryError::new("registry_activation_not_configured"))?;
        let (candidate, _) = self.snapshot()?;
        let scope = format!(
            "wallet-registry:{}:{}:{}:{}",
            self.0.trust.chain_id,
            self.0.trust.contract,
            self.0.trust.issuer,
            self.0.trust.product_id
        );
        let fp = crate::collect_fingerprint(&scope, &self.0.options.fingerprint_components);
        let install_id = protocol::keccak_hex(fp.composite.as_bytes())[2..].to_owned();
        endpoint.checkin(
            self.0.transport.as_ref(),
            &self.0.key,
            &candidate.manifest.license_id,
            &install_id,
            wall_time(),
            app_version,
            Duration::from_secs(5),
        )
    }

    /// Read fresh canonical state; an authoritative refusal never tries another
    /// provider, and a cache is never used as offline permission.
    pub fn validate(&self) -> RegistryResult<RegistryLicenseState> {
        self.validate_with(self.0.transport.as_ref(), None)
    }
    /// Require a fresh valid observation before a protected operation.
    pub fn require_valid_license(&self) -> RegistryResult<RegistryLicenseState> {
        self.validate()
    }
    /// Claim a code, or resume retained work, using the network-specific default deadline.
    pub fn activate(&self, code: &str) -> RegistryResult<RegistryLicenseState> {
        self.activate_with_options(code, &RegistryActivationOptions::default())
    }
    /// Resume a retained activation without reading or storing the original code.
    pub fn resume_activation(&self) -> RegistryResult<RegistryLicenseState> {
        self.resume_with_options(&RegistryActivationOptions::default())
    }
    /// Resume with an application deadline, cancellation and progress notifications.
    pub fn resume_with_options(
        &self,
        options: &RegistryActivationOptions,
    ) -> RegistryResult<RegistryLicenseState> {
        self.activate_with_options("", options)
    }

    /// Explicitly replace a completed code activation, preserving the device
    /// identity and the current license until a new grant passes fresh RPC checks.
    /// A retained replacement must be resumed or explicitly discarded first;
    /// a different code is never silently ignored or substituted for that job.
    pub fn replace_license(&self, code: &str) -> RegistryResult<RegistryLicenseState> {
        self.replace_with_options(code, &RegistryActivationOptions::default())
    }

    /// Replace with the same deadlines, cancellation and progress options as
    /// initial activation. Invalid codes and interrupted polling keep the old
    /// manifest. Once publication is claimed, only its public job ID is retained.
    pub fn replace_with_options(
        &self,
        code: &str,
        options: &RegistryActivationOptions,
    ) -> RegistryResult<RegistryLicenseState> {
        self.replace_inner(Some(code), options)
    }

    /// Resume the retained replacement without asking for or storing its code.
    /// The current license can still be checked independently while it is pending.
    pub fn resume_replacement(&self) -> RegistryResult<RegistryLicenseState> {
        self.resume_replacement_with_options(&RegistryActivationOptions::default())
    }

    /// Resume replacement with a bounded deadline and cooperative cancellation.
    pub fn resume_replacement_with_options(
        &self,
        options: &RegistryActivationOptions,
    ) -> RegistryResult<RegistryLicenseState> {
        self.replace_inner(None, options)
    }

    /// Forget only the local pending replacement handle after an explicit user
    /// decision. This does NOT cancel server publication, refund gas, revoke or
    /// unbind a license, or reset identity/history. Cancel and join an in-flight
    /// SDK replacement first; this call serializes with it across processes.
    /// Never invoke this automatically for timeouts or RPC/service failures.
    pub fn discard_pending_replacement(&self) -> RegistryResult<()> {
        let budget = self.activation_budget(&RegistryActivationOptions::default())?;
        let _guard =
            FileLock::acquire(&lock_path(&self.0.path, ".activation.lock"), Some(&budget))?;
        self.restore_manifest(Some(&budget))?;
        let (expected, generation) = self.snapshot()?;
        self.with_binding_budget(Some(&budget), |binding| {
            self.assert_active(&budget, generation)?;
            self.check_replacement_base(binding, &expected)?;
            binding.registry_replacement_id = None;
            self.save_binding(binding)
        })
    }

    fn activation_budget(&self, options: &RegistryActivationOptions) -> RegistryResult<Budget> {
        let timeout =
            options
                .timeout
                .unwrap_or(Duration::from_secs(if self.0.trust.chain_id == 8453 {
                    600
                } else {
                    120
                }));
        if timeout.is_zero() || timeout > Duration::from_secs(600) {
            return Err(RegistryError::new("invalid_registry_activation_timeout"));
        }
        Ok(Budget {
            deadline: Instant::now() + timeout,
            cancellation: options.cancellation.clone(),
        })
    }

    fn replace_inner(
        &self,
        code: Option<&str>,
        options: &RegistryActivationOptions,
    ) -> RegistryResult<RegistryLicenseState> {
        let budget = self.activation_budget(options)?;
        budget.remaining()?;
        let _guard =
            FileLock::acquire(&lock_path(&self.0.path, ".activation.lock"), Some(&budget))?;
        self.restore_manifest(Some(&budget))?;
        let (expected, generation) = self.snapshot()?;
        let endpoint = self
            .0
            .endpoint
            .as_ref()
            .ok_or_else(|| RegistryError::new("registry_activation_not_configured"))?;
        let pending = self.with_binding_budget(Some(&budget), |binding| {
            self.assert_active(&budget, generation)?;
            self.check_replacement_base(binding, &expected)?;
            Ok(binding.registry_replacement_id.clone())
        })?;
        let scoped = ScopedTransport {
            inner: self.0.transport.as_ref(),
            budget: &budget,
        };
        let mut response = match (code, pending) {
            (Some(_), Some(_)) => {
                return Err(RegistryError::new("registry_replacement_pending"));
            }
            (None, None) => return Err(RegistryError::new("registry_replacement_not_pending")),
            (None, Some(id)) => {
                self.poll_replacement(endpoint, &scoped, &id, &budget, &expected, generation)?
            }
            (Some(code), None) => {
                let result = endpoint.activate(
                    &scoped,
                    &self.0.key,
                    code,
                    &request_uuid()?,
                    budget.remaining()?,
                );
                budget.remaining()?;
                result?
            }
        };
        loop {
            self.assert_active(&budget, generation)?;
            let failed = matches!(response.status, ActivationStatus::Failed);
            self.save_replacement(
                &response.activation_id,
                failed,
                &budget,
                &expected,
                generation,
            )?;
            match response.status {
                ActivationStatus::Failed => {
                    return Err(RegistryError::new("registry_activation_failed"));
                }
                ActivationStatus::Pending => {
                    notify(
                        options,
                        RegistryActivationStatus::Pending,
                        &response.activation_id,
                        response.retry_after_s,
                    );
                    budget.sleep(Duration::from_secs(response.retry_after_s.max(1)))?;
                    response = self.poll_replacement(
                        endpoint,
                        &scoped,
                        &response.activation_id,
                        &budget,
                        &expected,
                        generation,
                    )?;
                }
                ActivationStatus::Ready => {
                    let raw =
                        serde_json::to_string(response.manifest.as_ref().ok_or_else(|| {
                            RegistryError::new("invalid_registry_activation_response")
                        })?)
                        .map_err(|_| RegistryError::new("invalid_registry_manifest"))?;
                    let candidate = protocol::parse_manifest(&raw, &self.0.trust)?;
                    notify(
                        options,
                        RegistryActivationStatus::Validating,
                        &response.activation_id,
                        0,
                    );
                    let check =
                        self.validate_candidate(&candidate, generation, &scoped, Some(&budget));
                    self.assert_active(&budget, generation)?;
                    let license = check?;
                    self.commit_replacement(
                        candidate,
                        &raw,
                        &response.activation_id,
                        &budget,
                        &expected,
                        generation,
                    )?;
                    // Commit is the linearization point: a later cancellation
                    // cannot undo a successfully verified, durably saved swap.
                    notify(
                        options,
                        RegistryActivationStatus::Ready,
                        &response.activation_id,
                        0,
                    );
                    return Ok(license);
                }
            }
        }
    }

    fn check_replacement_base(
        &self,
        binding: &StoredBinding,
        expected: &ParsedManifest,
    ) -> RegistryResult<()> {
        let stored = binding
            .registry_manifest
            .as_deref()
            .ok_or_else(|| RegistryError::new("registry_replacement_state_conflict"))?;
        if binding.registry_activation_id.is_some()
            || protocol::parse_manifest(stored, &self.0.trust)?.manifest != expected.manifest
        {
            return Err(RegistryError::new("registry_replacement_state_conflict"));
        }
        Ok(())
    }

    fn save_replacement(
        &self,
        id: &str,
        failed: bool,
        budget: &Budget,
        expected: &ParsedManifest,
        generation: u64,
    ) -> RegistryResult<()> {
        self.with_binding_budget(Some(budget), |binding| {
            self.assert_active(budget, generation)?;
            self.check_replacement_base(binding, expected)?;
            if binding
                .registry_replacement_id
                .as_deref()
                .is_some_and(|saved| saved != id)
            {
                return Err(RegistryError::new("registry_replacement_state_conflict"));
            }
            binding.registry_replacement_id = (!failed).then(|| id.to_owned());
            self.save_binding(binding)
        })
    }

    fn poll_replacement(
        &self,
        endpoint: &ActivationEndpoint,
        transport: &dyn Transport,
        id: &str,
        budget: &Budget,
        expected: &ParsedManifest,
        generation: u64,
    ) -> RegistryResult<ActivationResponse> {
        self.assert_active(budget, generation)?;
        let result = endpoint.poll(transport, &self.0.key, id, budget.remaining()?);
        self.assert_active(budget, generation)?;
        if result
            .as_ref()
            .is_err_and(|error| error.code() == "activation_not_found")
        {
            self.save_replacement(id, true, budget, expected, generation)?;
        }
        result
    }

    fn commit_replacement(
        &self,
        candidate: ParsedManifest,
        raw: &str,
        id: &str,
        budget: &Budget,
        expected: &ParsedManifest,
        generation: u64,
    ) -> RegistryResult<()> {
        // Same lock order as initial activation: manifest -> persisted state.
        let mut manifest = lock(&self.0.manifest);
        self.assert_active(budget, generation)?;
        if manifest.as_ref().map(|m| &m.manifest) != Some(&expected.manifest) {
            return Err(RegistryError::new("registry_replacement_state_conflict"));
        }
        self.with_binding_budget(Some(budget), |binding| {
            self.assert_active(budget, generation)?;
            self.check_replacement_base(binding, expected)?;
            if binding.registry_replacement_id.as_deref() != Some(id) {
                return Err(RegistryError::new("registry_replacement_state_conflict"));
            }
            binding.registry_manifest = Some(raw.to_owned());
            binding.registry_replacement_id = None;
            self.save_binding(binding)
        })?;
        *manifest = Some(candidate);
        self.0.generation.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Activate with bounded polling. Ready API responses must pass fresh RPC
    /// checks before their manifest is saved. The code is never retained.
    pub fn activate_with_options(
        &self,
        code: &str,
        options: &RegistryActivationOptions,
    ) -> RegistryResult<RegistryLicenseState> {
        let budget = self.activation_budget(options)?;
        budget.remaining()?;
        // Separate from short state locks: one first activation per profile,
        // including across processes. Closing/crashing releases the OS lock.
        let _activation_guard =
            FileLock::acquire(&lock_path(&self.0.path, ".activation.lock"), Some(&budget))?;
        self.restore_manifest(Some(&budget))?;
        let scoped = ScopedTransport {
            inner: self.0.transport.as_ref(),
            budget: &budget,
        };
        let (existing, mut generation) = self.optional_snapshot();
        if let Some(existing) = existing {
            let result = self.validate_candidate(&existing, generation, &scoped, Some(&budget));
            budget.remaining()?;
            return result;
        }
        let endpoint = self
            .0
            .endpoint
            .as_ref()
            .ok_or_else(|| RegistryError::new("registry_activation_not_configured"))?;
        let pending =
            self.with_binding_budget(Some(&budget), |b| Ok(b.registry_activation_id.clone()))?;
        let mut response = match pending {
            Some(id) => self.poll(endpoint, &scoped, &id, &budget, generation)?,
            None => {
                self.assert_active(&budget, generation)?;
                let result = endpoint.activate(
                    &scoped,
                    &self.0.key,
                    code,
                    &request_uuid()?,
                    budget.remaining()?,
                );
                budget.remaining()?;
                result?
            }
        };
        loop {
            self.assert_active(&budget, generation)?;
            let retained =
                self.with_binding_budget(Some(&budget), |b| Ok(b.registry_activation_id.clone()))?;
            if retained
                .as_deref()
                .is_some_and(|id| id != response.activation_id)
            {
                return Err(RegistryError::new("invalid_registry_activation_response"));
            }
            match response.status {
                ActivationStatus::Failed => {
                    self.save_activation(&response.activation_id, None, true, &budget, generation)?;
                    return Err(RegistryError::new("registry_activation_failed"));
                }
                ActivationStatus::Ready => {
                    let raw =
                        serde_json::to_string(response.manifest.as_ref().ok_or_else(|| {
                            RegistryError::new("invalid_registry_activation_response")
                        })?)
                        .map_err(|_| RegistryError::new("invalid_registry_manifest"))?;
                    let candidate = protocol::parse_manifest(&raw, &self.0.trust)?;
                    self.save_activation(
                        &response.activation_id,
                        None,
                        false,
                        &budget,
                        generation,
                    )?;
                    notify(
                        options,
                        RegistryActivationStatus::Validating,
                        &response.activation_id,
                        0,
                    );
                    let check =
                        self.validate_candidate(&candidate, generation, &scoped, Some(&budget));
                    self.assert_active(&budget, generation)?;
                    check?;
                    generation = self.commit_ready(
                        candidate,
                        &raw,
                        &response.activation_id,
                        &budget,
                        generation,
                    )?;
                    let result = self.validate_with(&scoped, Some(&budget));
                    self.assert_active(&budget, generation)?;
                    let result = result?;
                    notify(
                        options,
                        RegistryActivationStatus::Ready,
                        &response.activation_id,
                        0,
                    );
                    return Ok(result);
                }
                ActivationStatus::Pending => {
                    self.save_activation(
                        &response.activation_id,
                        None,
                        false,
                        &budget,
                        generation,
                    )?;
                    notify(
                        options,
                        RegistryActivationStatus::Pending,
                        &response.activation_id,
                        response.retry_after_s,
                    );
                    budget.sleep(Duration::from_secs(response.retry_after_s.max(1)))?;
                    response = self.poll(
                        endpoint,
                        &scoped,
                        &response.activation_id,
                        &budget,
                        generation,
                    )?;
                }
            }
        }
    }

    fn now(&self) -> u64 {
        lock(&self.0.clock).now()
    }
    fn snapshot(&self) -> RegistryResult<(ParsedManifest, u64)> {
        let (candidate, generation) = self.optional_snapshot();
        Ok((
            candidate.ok_or_else(|| RegistryError::new("registry_manifest_required"))?,
            generation,
        ))
    }
    fn optional_snapshot(&self) -> (Option<ParsedManifest>, u64) {
        let manifest = lock(&self.0.manifest);
        (manifest.clone(), self.0.generation.load(Ordering::Acquire))
    }
    fn validate_with(
        &self,
        transport: &dyn Transport,
        budget: Option<&Budget>,
    ) -> RegistryResult<RegistryLicenseState> {
        let (candidate, generation) = self.snapshot()?;
        self.validate_candidate(&candidate, generation, transport, budget)
    }
    fn commit_ready(
        &self,
        candidate: ParsedManifest,
        raw: &str,
        id: &str,
        budget: &Budget,
        generation: u64,
    ) -> RegistryResult<u64> {
        // Lock order is manifest -> state; state operations never lock manifest.
        // A concurrent import cannot be overwritten by this delayed publication.
        let mut manifest = lock(&self.0.manifest);
        self.assert_active(budget, generation)?;
        if manifest.is_some() {
            return Err(RegistryError::new("registry_activation_interrupted"));
        }
        self.save_activation(id, Some(raw), false, budget, generation)?;
        *manifest = Some(candidate);
        Ok(self.0.generation.fetch_add(1, Ordering::AcqRel) + 1)
    }
    fn assert_active(&self, budget: &Budget, generation: u64) -> RegistryResult<()> {
        budget.remaining()?;
        if self.0.generation.load(Ordering::Acquire) != generation {
            return Err(RegistryError::new("registry_activation_interrupted"));
        }
        Ok(())
    }
    fn poll(
        &self,
        endpoint: &ActivationEndpoint,
        transport: &dyn Transport,
        id: &str,
        budget: &Budget,
        generation: u64,
    ) -> RegistryResult<ActivationResponse> {
        self.assert_active(budget, generation)?;
        let response = endpoint.poll(transport, &self.0.key, id, budget.remaining()?);
        self.assert_active(budget, generation)?;
        if response
            .as_ref()
            .is_err_and(|error| error.code() == "activation_not_found")
        {
            self.save_activation(id, None, true, budget, generation)?;
        }
        response
    }
    fn restore_manifest(&self, budget: Option<&Budget>) -> RegistryResult<()> {
        if lock(&self.0.manifest).is_none() {
            let raw = self.with_binding_budget(budget, |b| Ok(b.registry_manifest.clone()))?;
            if let Some(raw) = raw {
                let parsed = protocol::parse_manifest(&raw, &self.0.trust)?;
                let mut manifest = lock(&self.0.manifest);
                if manifest.is_none() {
                    *manifest = Some(parsed);
                    self.0.generation.fetch_add(1, Ordering::AcqRel);
                }
            }
        }
        Ok(())
    }
    fn with_binding<T>(
        &self,
        action: impl FnOnce(&mut StoredBinding) -> RegistryResult<T>,
    ) -> RegistryResult<T> {
        self.with_binding_budget(None, action)
    }
    fn with_binding_budget<T>(
        &self,
        budget: Option<&Budget>,
        action: impl FnOnce(&mut StoredBinding) -> RegistryResult<T>,
    ) -> RegistryResult<T> {
        let _guard = FileLock::acquire(&lock_path(&self.0.path, ".lock"), budget)?;
        if let Some(budget) = budget {
            budget.remaining()?;
        }
        let mut binding = self
            .0
            .store
            .load()
            .ok_or_else(|| RegistryError::new("device_key_missing"))?;
        let stored = stored_key(&binding)?;
        if stored.verifying_key() != self.0.key.verifying_key() {
            return Err(RegistryError::new("device_key_missing"));
        }
        action(&mut binding)
    }
    fn save_binding(&self, binding: &StoredBinding) -> RegistryResult<()> {
        if !self.0.store.save(binding) {
            return Err(RegistryError::new("device_state_not_saved"));
        }
        Ok(())
    }
    fn save_activation(
        &self,
        id: &str,
        manifest: Option<&str>,
        failed: bool,
        budget: &Budget,
        generation: u64,
    ) -> RegistryResult<()> {
        self.with_binding_budget(Some(budget), |binding| {
            self.assert_active(budget, generation)?;
            if binding
                .registry_activation_id
                .as_deref()
                .is_some_and(|old| old != id)
            {
                return Err(RegistryError::new("registry_activation_state_conflict"));
            }
            if let Some(raw) = manifest {
                if let Some(old) = &binding.registry_manifest {
                    let old = protocol::parse_manifest(old, &self.0.trust)?;
                    let new = protocol::parse_manifest(raw, &self.0.trust)?;
                    if old.manifest != new.manifest {
                        return Err(RegistryError::new("registry_activation_state_conflict"));
                    }
                }
                binding.registry_manifest = Some(raw.to_owned());
                binding.registry_activation_id = None;
            } else if failed {
                binding.registry_activation_id = None;
            } else {
                if binding.registry_manifest.is_some() {
                    return Err(RegistryError::new("registry_activation_state_conflict"));
                }
                binding.registry_activation_id = Some(id.to_owned());
            }
            self.save_binding(binding)
        })
    }
    fn validate_candidate(
        &self,
        candidate: &ParsedManifest,
        generation: u64,
        transport: &dyn Transport,
        budget: Option<&Budget>,
    ) -> RegistryResult<RegistryLicenseState> {
        let (initial, high, persisted_manifest) = self.with_binding_budget(budget, |binding| {
            Ok((
                chain::parse_chain_state(binding.registry_chain_state.as_deref())?,
                binding.time_high_water.max(0) as u64,
                binding.registry_manifest.clone(),
            ))
        })?;
        let observation = chain::read_chain(
            transport,
            &self.0.options.rpc_urls,
            &chain::ReadInput {
                trust: &self.0.trust,
                parsed: candidate,
                device_key: &self.0.device_key,
                prior_state: initial.as_ref(),
                time_high_water: high,
            },
            || self.now(),
            |duration| match budget {
                Some(budget) => budget.sleep(duration),
                None => {
                    std::thread::sleep(duration);
                    Ok(())
                }
            },
        )?;
        let terminal = self.with_binding_budget(budget, |binding| {
            if self.0.generation.load(Ordering::Acquire) != generation {
                return Err(RegistryError::new("license_changed_during_validation"));
            }
            if binding.registry_manifest != persisted_manifest {
                return Err(RegistryError::new("license_changed_during_validation"));
            }
            let seen = chain::parse_chain_state(binding.registry_chain_state.as_deref())?;
            let (merged, terminal) = chain::merge_observation(
                seen.as_ref(),
                initial.as_ref(),
                &observation,
                &candidate.manifest.license_id,
            )?;
            binding.registry_chain_state = Some(
                serde_json::to_string(&merged)
                    .map_err(|_| RegistryError::new("invalid_registry_chain_state"))?,
            );
            binding.time_high_water = binding
                .time_high_water
                .max(observation.head.timestamp as i64);
            binding.offline_seen = binding.offline_seen.max(self.now() as i64);
            self.save_binding(binding)?;
            Ok(terminal)
        })?;
        if terminal {
            return Err(RegistryError::new("license_revoked"));
        }
        if let Some(reason) = observation.refusal {
            return Err(RegistryError::new(reason));
        }
        let checked_at = self.now().max(observation.checked_at);
        if self.0.generation.load(Ordering::Acquire) != generation {
            return Err(RegistryError::new("license_changed_during_validation"));
        }
        if observation.record.expires_at != 0 && observation.record.expires_at <= checked_at {
            return Err(RegistryError::new("license_expired"));
        }
        if observation.head.timestamp.saturating_add(300) < checked_at {
            return Err(RegistryError::transient("stale_rpc_block"));
        }
        Ok(RegistryLicenseState {
            entitlements: candidate.entitlements.clone(),
            expires_at: (observation.record.expires_at != 0)
                .then_some(observation.record.expires_at),
            not_before: observation.record.not_before,
            revision: observation.record.revision,
            block_number: observation
                .head
                .number
                .parse()
                .map_err(|_| RegistryError::new("invalid_registry_chain_state"))?,
            block_hash: observation.head.hash,
            checked_at,
        })
    }
}

struct Budget {
    deadline: Instant,
    cancellation: Option<RegistryCancellationToken>,
}
impl Budget {
    fn remaining(&self) -> RegistryResult<Duration> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(RegistryCancellationToken::is_cancelled)
        {
            return Err(RegistryError::new("registry_activation_aborted"));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| RegistryError::new("registry_activation_timeout"))
    }
    fn sleep(&self, duration: Duration) -> RegistryResult<()> {
        let until = Instant::now() + duration;
        while Instant::now() < until {
            let remaining = self.remaining()?;
            std::thread::sleep(
                remaining
                    .min(until.saturating_duration_since(Instant::now()))
                    .min(Duration::from_millis(50)),
            );
        }
        self.remaining().map(|_| ())
    }
}
fn notify(
    options: &RegistryActivationOptions,
    status: RegistryActivationStatus,
    id: &str,
    retry: u64,
) {
    if let Some(callback) = &options.on_progress {
        let progress = RegistryActivationProgress {
            status,
            activation_id: id.to_owned(),
            retry_after_seconds: retry,
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(progress)));
    }
}
const PORTABLE_KIND: &str = "talos-registry-portable-license";

/// Where this installation keeps its registry state, and the key it is sealed
/// under. One definition, because the portable import must write exactly the
/// file `RegistryLicenseClient::new` will read.
fn state_location(
    options: &RegistryLicenseOptions,
    trust: &RegistryTrust,
) -> RegistryResult<(StateStore, PathBuf, String)> {
    let scope = format!(
        "wallet-registry:{}:{}:{}:{}",
        trust.chain_id, trust.contract, trust.issuer, trust.product_id
    );
    let fp = crate::collect_fingerprint(&scope, &options.fingerprint_components);
    let path = options
        .state_path
        .clone()
        .unwrap_or_else(|| crate::default_state_path(&scope));
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|_| RegistryError::new("invalid_registry_state_path"))?
            .join(path)
    };
    let store = StateStore::new(path.clone(), &scope, &state_key_material(&fp));
    Ok((store, path, fp.composite))
}
fn stored_key(binding: &StoredBinding) -> RegistryResult<SigningKey> {
    let encoded = binding
        .machine_key
        .as_ref()
        .ok_or_else(|| RegistryError::new("device_key_missing"))?;
    let bytes = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| RegistryError::new("invalid_device_key"))?,
    );
    if bytes.len() != 32 || STANDARD.encode(&*bytes) != *encoded {
        return Err(RegistryError::new("invalid_device_key"));
    }
    let seed: &[u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| RegistryError::new("invalid_device_key"))?;
    let key = SigningKey::from_bytes(seed);
    if binding.machine_public_key.as_deref()
        != Some(STANDARD.encode(key.verifying_key().as_bytes()).as_str())
    {
        return Err(RegistryError::new("invalid_device_key"));
    }
    Ok(key)
}
fn request_uuid() -> RegistryResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| RegistryError::new("registry_request_id_unavailable"))?;
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    let hex = protocol::hex(&bytes);
    let h = &hex[2..];
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
fn lock_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}
struct FileLock(File);
impl FileLock {
    fn acquire(path: &Path, budget: Option<&Budget>) -> RegistryResult<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        create_private_dir(parent).map_err(|_| RegistryError::new("device_state_not_saved"))?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|_| RegistryError::new("device_state_locked"))?;
        let until = Instant::now() + Duration::from_secs(35);
        loop {
            if let Some(budget) = budget {
                budget.remaining()?;
            }
            match FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok(Self(file)),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {}
                Err(_) => return Err(RegistryError::new("device_state_locked")),
            }
            if budget.is_none() && Instant::now() >= until {
                return Err(RegistryError::new("device_state_locked"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}
#[cfg(feature = "ureq")]
fn default_transport() -> RegistryResult<Arc<dyn Transport>> {
    Ok(Arc::new(
        crate::transport::UreqTransport::without_redirects(),
    ))
}
#[cfg(not(feature = "ureq"))]
fn default_transport() -> RegistryResult<Arc<dyn Transport>> {
    Err(RegistryError::new("registry_transport_required"))
}

#[cfg(test)]
mod tests;
