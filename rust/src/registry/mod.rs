//! Walletless code activation and fresh license checks against a pinned EVM registry.
//! Calls block: run them on a worker thread. A cached manifest never grants access.
//!
//! One thing may stand in for a fresh check, and only when the publisher asked for
//! it: an offline allowance stamped into the license itself (`talos_offline`), which
//! lets the last valid observation stand for a stated number of days while no RPC
//! provider can be reached. See [`RegistryLicenseState::offline_until`].

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
    /// The deployed TalosLicenseActivatorV1 address, from the publisher's integration
    /// settings, when the policy issues licenses that can be recovered from their code.
    /// With it, a client opened through [`RegistryLicenseClient::with_code`] restores an
    /// already activated license from the registry alone, with no Talos request.
    pub activator: Option<String>,
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
            activator: None,
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
    /// Public activation job UUID; empty when a license is restored from the registry
    /// by its code, which involves no activation job.
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

/// A fresh observation — or, where the license grants an offline allowance and no
/// RPC provider could be reached, the last one. Recheck before protected work.
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
    /// Monotonic local observation time, Unix seconds. When [`Self::offline_until`]
    /// is set, the time of the last fresh observation this state repeats.
    pub checked_at: u64,
    /// `None` for a state read from the chain just now.
    ///
    /// `Some(deadline)` when no RPC provider could be reached and the license's
    /// own offline allowance let the last valid observation stand: every other
    /// field then describes that observation, and `deadline` is the Unix second
    /// at which the allowance runs out — the earlier of the allowance and the
    /// license's expiry. After it, validation fails with
    /// `offline_period_expired` until a fresh check succeeds.
    ///
    /// The allowance is a term the publisher stamped into the license, so it is
    /// covered by the entitlement hash the registry holds; a refusal read from
    /// the chain — revoked, expired, another device — ends it at once.
    pub offline_until: Option<u64>,
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

    /// Days this license may run on its last valid observation when no RPC
    /// provider can be reached, as stamped by the publisher's policy; `None`
    /// when every check needs the network. A malformed term grants nothing.
    #[must_use]
    pub fn offline_allowance_days(&self) -> Option<u32> {
        offline_allowance_days(&self.entitlements)
    }

    /// Whether this state repeats the last fresh observation under the
    /// license's offline allowance instead of reading the chain just now.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.offline_until.is_some()
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

/// The offline term of a license: `{"talos_offline": {"days": N}}`, `N` a whole
/// number from 1 to 36500. Anything else — a string, a fraction, an extra key —
/// is read as no allowance, never as a generous one.
fn offline_allowance_days(entitlements: &Map<String, Value>) -> Option<u32> {
    let term = entitlements.get("talos_offline")?.as_object()?;
    if term.len() != 1 {
        return None;
    }
    let days = term.get("days")?.as_u64()?;
    (1..=36_500).contains(&days).then_some(days as u32)
}

/// The last fresh, valid observation of one license, kept in the encrypted
/// device state. It names the license and the exact entitlement bytes it was
/// made for, so it cannot be carried over to another license or another
/// revision of the terms.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OfflineBasis {
    license_id: String,
    entitlements_hash: String,
    checked_at: u64,
    expires_at: u64,
    not_before: u64,
    revision: u64,
    block_number: u64,
    block_hash: String,
}
impl OfflineBasis {
    fn to_json(&self) -> String {
        serde_json::json!({
            "v": 1, "licenseId": self.license_id, "entitlementsHash": self.entitlements_hash,
            "checkedAt": self.checked_at, "expiresAt": self.expires_at,
            "notBefore": self.not_before, "revision": self.revision,
            "blockNumber": self.block_number, "blockHash": self.block_hash,
        })
        .to_string()
    }
    /// Field by field: the file is on a disk the user owns.
    fn parse(raw: Option<&str>) -> Option<Self> {
        let value: Value = serde_json::from_str(raw?).ok()?;
        let fields = value.as_object()?;
        if fields.get("v").and_then(Value::as_u64) != Some(1) {
            return None;
        }
        let text = |key: &str| fields.get(key).and_then(Value::as_str).map(str::to_owned);
        let number = |key: &str| fields.get(key).and_then(Value::as_u64);
        Some(Self {
            license_id: text("licenseId")?,
            entitlements_hash: text("entitlementsHash")?,
            checked_at: number("checkedAt")?,
            expires_at: number("expiresAt")?,
            not_before: number("notBefore")?,
            revision: number("revision")?,
            block_number: number("blockNumber")?,
            block_hash: text("blockHash")?,
        })
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
    activator: Option<String>,
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
        let trust = trust_of(&options)?;
        let activator = options
            .activator
            .as_deref()
            .map(|address| protocol::nonzero_hex(address, 20))
            .transpose()
            .map_err(|_| RegistryError::new("invalid_registry_configuration"))?;
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
            activator,
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
        let trust = trust_of(&options)?;
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
                binding.registry_offline = None;
                if !store.save(&binding) {
                    return Err(RegistryError::new("device_state_not_saved"));
                }
            }
        }
        Self::new(options)
    }

    /// Open a client whose device identity is derived from the customer's license code.
    ///
    /// This is how an application uses a policy with code recovery. The key a license is
    /// bound to is computed from the code instead of being generated at random, so the
    /// same code produces the same key on a reinstalled system or another computer. Call
    /// `activate(code)` on the result: a first activation goes through Talos once, and
    /// every later one, anywhere, is rebuilt from the registry over RPC with no Talos
    /// request, provided `activator` is set in the options.
    ///
    /// **The code is then a bearer credential.** Whoever knows it can run the application
    /// on any number of computers for as long as the license stands, and only an on-chain
    /// revocation stops them. Use this only with policies meant to work that way.
    ///
    /// Neither the code nor anything that reveals it is stored; the derived key is kept in
    /// this installation's encrypted state like any device key. An installation that
    /// already holds a license under a different key is refused with
    /// `registry_already_activated` rather than overwritten: use
    /// [`replace_with_code`](Self::replace_with_code) to change codes.
    pub fn with_code(options: RegistryLicenseOptions, code: &str) -> RegistryResult<Self> {
        let trust = trust_of(&options)?;
        let identity = protocol::code_identity(&trust, code)?;
        let public = STANDARD.encode(
            SigningKey::from_bytes(&identity.seed)
                .verifying_key()
                .as_bytes(),
        );
        let (store, path, composite) = state_location(&options, &trust)?;
        {
            let _guard = FileLock::acquire(&lock_path(&path, ".lock"), None)?;
            let mut binding = match store.load() {
                Some(binding) => binding,
                None if path.exists() => return Err(RegistryError::new("invalid_device_state")),
                None => StoredBinding::empty(&composite),
            };
            let same = binding.machine_public_key.as_deref() == Some(public.as_str());
            if binding.registry_manifest.is_some()
                || binding.registry_activation_id.is_some()
                || binding.registry_replacement_id.is_some()
            {
                if !same {
                    return Err(RegistryError::new("registry_already_activated"));
                }
            } else if !same {
                // A key generated here and never bound to anything is replaced; nothing on
                // chain refers to it.
                binding.machine_key = Some(STANDARD.encode(identity.seed.as_slice()));
                binding.machine_public_key = Some(public);
                binding.registry_chain_state = None;
                binding.registry_offline = None;
                if !store.save(&binding) {
                    return Err(RegistryError::new("device_state_not_saved"));
                }
            }
        }
        Self::new(options)
    }

    /// Switch this installation to another code on a policy with code recovery, keeping
    /// the current license in force until the new one has passed a fresh registry check.
    ///
    /// A recoverable license is bound to a key derived from its code, so a new code means
    /// a new key; [`replace_license`](Self::replace_license), which keeps the key, cannot
    /// do this and refuses when `activator` is configured. The new code is activated in a
    /// side file next to the state file and swapped in only on success. An interrupted
    /// call can simply be repeated with the same code and resumes the same activation.
    ///
    /// Returns a new client. Handles opened before the swap hold the old key and fail
    /// with `device_key_missing`; drop them and use the returned one.
    pub fn replace_with_code(
        options: RegistryLicenseOptions,
        code: &str,
        activation: &RegistryActivationOptions,
    ) -> RegistryResult<(Self, RegistryLicenseState)> {
        let trust = trust_of(&options)?;
        let identity = protocol::code_identity(&trust, code)?;
        let public = STANDARD.encode(
            SigningKey::from_bytes(&identity.seed)
                .verifying_key()
                .as_bytes(),
        );
        let (store, path, _) = state_location(&options, &trust)?;
        let current = {
            let _guard = FileLock::acquire(&lock_path(&path, ".lock"), None)?;
            match store.load() {
                Some(binding) => Some(binding),
                None if path.exists() => return Err(RegistryError::new("invalid_device_state")),
                None => None,
            }
        };
        let occupied = current.as_ref().is_some_and(|binding| {
            binding.registry_manifest.is_some()
                || binding.registry_activation_id.is_some()
                || binding.registry_replacement_id.is_some()
        });
        let same = current
            .as_ref()
            .is_some_and(|binding| binding.machine_public_key.as_deref() == Some(public.as_str()));
        if !occupied || same {
            // Nothing to preserve, or the same code again: an ordinary activation.
            let client = Self::with_code(options, code)?;
            let license = client.activate_with_options(code, activation)?;
            return Ok((client, license));
        }
        let next_path = lock_path(&path, ".next");
        let mut side = options.clone();
        side.state_path = Some(next_path.clone());
        let (side_store, _, _) = state_location(&side, &trust)?;
        {
            // A side file left by a different code belongs to an abandoned attempt.
            let _guard = FileLock::acquire(&lock_path(&next_path, ".lock"), None)?;
            let stale = match side_store.load() {
                Some(binding) => binding.machine_public_key.as_deref() != Some(public.as_str()),
                None => next_path.exists(),
            };
            if stale && std::fs::remove_file(&next_path).is_err() {
                return Err(RegistryError::new("device_state_not_saved"));
            }
        }
        let license = Self::with_code(side, code)?.activate_with_options(code, activation)?;
        {
            let _activation = FileLock::acquire(&lock_path(&path, ".activation.lock"), None)?;
            let _state = FileLock::acquire(&lock_path(&path, ".lock"), None)?;
            let _next = FileLock::acquire(&lock_path(&next_path, ".lock"), None)?;
            let mut next = side_store
                .load()
                .filter(|binding| {
                    binding.registry_manifest.is_some()
                        && binding.machine_public_key.as_deref() == Some(public.as_str())
                })
                .ok_or_else(|| RegistryError::new("device_state_not_saved"))?;
            // The clock high-water marks and chain observations belong to this
            // computer/chain, not just to one license: preserve terminal revocations
            // and the highest observed head across code replacements.
            if let Some(old) = store.load() {
                next.time_high_water = next.time_high_water.max(old.time_high_water);
                next.offline_seen = next.offline_seen.max(old.offline_seen);
                let old_chain = chain::parse_chain_state(old.registry_chain_state.as_deref())?;
                let next_chain = chain::parse_chain_state(next.registry_chain_state.as_deref())?;
                if let Some(merged) = merge_chain_states(old_chain, next_chain)? {
                    next.registry_chain_state = Some(
                        serde_json::to_string(&merged)
                            .map_err(|_| RegistryError::new("invalid_registry_chain_state"))?,
                    );
                }
            }
            if !store.save(&next) {
                return Err(RegistryError::new("device_state_not_saved"));
            }
            let _ = std::fs::remove_file(&next_path);
        }
        Ok((Self::new(options)?, license))
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
    /// provider.
    ///
    /// A cache is never offline permission by itself. The one exception is a term
    /// of the license: if the publisher's policy stamped an offline allowance
    /// into it and no RPC provider can be reached, the last valid observation
    /// stands until that allowance runs out, and the returned state says so in
    /// [`RegistryLicenseState::offline_until`]. A license without the term keeps
    /// failing with the transient RPC error, as before.
    pub fn validate(&self) -> RegistryResult<RegistryLicenseState> {
        match self.validate_with(self.0.transport.as_ref(), None) {
            Ok(state) => Ok(state),
            Err(error) if error.is_transient() => self.offline_state(error),
            Err(error) => {
                // The chain, or this device's own state, said no. Whatever was
                // observed before is no longer something to fall back on.
                self.forget_offline_basis();
                Err(error)
            }
        }
    }
    /// Require a valid license before a protected operation: a fresh observation,
    /// or the last one while the license's own offline allowance lasts.
    pub fn require_valid_license(&self) -> RegistryResult<RegistryLicenseState> {
        self.validate()
    }
    /// Require a state read from the chain just now, ignoring any offline
    /// allowance. For the operations a publisher never wants to run on a
    /// remembered answer.
    pub fn require_fresh_license(&self) -> RegistryResult<RegistryLicenseState> {
        self.validate_with(self.0.transport.as_ref(), None)
    }

    /// Let the last valid observation stand, if the license allows it and it has
    /// not run out. `cause` is the transient failure that brought us here, and is
    /// what the caller gets back when there is nothing to stand on.
    fn offline_state(&self, cause: RegistryError) -> RegistryResult<RegistryLicenseState> {
        let (candidate, _) = self.snapshot()?;
        let Some(days) = offline_allowance_days(&candidate.entitlements) else {
            return Err(cause);
        };
        self.with_binding_budget(None, |binding| {
            let Some(basis) = OfflineBasis::parse(binding.registry_offline.as_deref()) else {
                return Err(cause.clone());
            };
            // Never let a cached offline basis override a terminally revoked
            // license or a newer on-chain revision already recorded in chain state.
            if let Some(seen) = chain::parse_chain_state(binding.registry_chain_state.as_deref())? {
                if let Some(obs) = seen.licenses.get(&candidate.manifest.license_id) {
                    if obs.revoked {
                        return Err(RegistryError::new("license_revoked"));
                    }
                    if obs.revision > basis.revision {
                        return Err(cause.clone());
                    }
                }
            }
            // The same license, under the same terms, that was observed.
            if basis.license_id != candidate.manifest.license_id
                || basis.entitlements_hash != candidate.entitlements_hash
            {
                return Err(cause.clone());
            }
            // The highest time this device has ever seen, not the wall clock: a
            // clock set back must not buy the period again.
            let now = self
                .now()
                .max(binding.time_high_water.max(0) as u64)
                .max(binding.offline_seen.max(0) as u64)
                .max(basis.checked_at);
            // This moment is written down whatever the answer is, so a restart
            // with an earlier wall clock still starts from here — including
            // after a refusal, or running out could be undone by winding back.
            let advanced = now as i64 > binding.offline_seen;
            binding.offline_seen = binding.offline_seen.max(now as i64);
            let verdict = (|| {
                if basis.not_before > now {
                    return Err(cause.clone());
                }
                if basis.expires_at != 0 && basis.expires_at <= now {
                    return Err(RegistryError::new("license_expired"));
                }
                let allowance = basis
                    .checked_at
                    .saturating_add(u64::from(days).saturating_mul(86_400));
                if allowance <= now {
                    return Err(RegistryError::new("offline_period_expired"));
                }
                Ok(RegistryLicenseState {
                    entitlements: candidate.entitlements.clone(),
                    expires_at: (basis.expires_at != 0).then_some(basis.expires_at),
                    not_before: basis.not_before,
                    revision: basis.revision,
                    block_number: basis.block_number,
                    block_hash: basis.block_hash.clone(),
                    checked_at: basis.checked_at,
                    offline_until: Some(match basis.expires_at {
                        0 => allowance,
                        expires_at => allowance.min(expires_at),
                    }),
                })
            })();
            if advanced {
                let saved = self.save_binding(binding);
                // Access is granted only on a record that was actually written.
                if verdict.is_ok() {
                    saved?;
                }
            }
            verdict
        })
    }

    /// Drop the remembered observation. Best effort: a state that cannot be
    /// written keeps what it had, and the refusal that brought us here is
    /// returned to the caller either way.
    fn forget_offline_basis(&self) {
        let _ = self.with_binding_budget(None, |binding| {
            if binding.registry_offline.take().is_some() {
                self.save_binding(binding)?;
            }
            Ok(())
        });
    }

    #[cfg(test)]
    pub(super) fn skip_time(&self, seconds: u64) {
        let mut clock = lock(&self.0.clock);
        clock.high = clock.high.saturating_add(Duration::from_secs(seconds));
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
        if code.is_some() && self.0.activator.is_some() {
            // A recoverable license is bound to a key derived from its code. Replacing the
            // manifest under the current key would produce one its own code cannot recover.
            return Err(RegistryError::new("registry_code_replacement_required"));
        }
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
                        &license,
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
        license: &RegistryLicenseState,
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
        let offline_basis = offline_allowance_days(&candidate.entitlements).map(|_| OfflineBasis {
            license_id: candidate.manifest.license_id.clone(),
            entitlements_hash: candidate.entitlements_hash.clone(),
            checked_at: license.checked_at,
            expires_at: license.expires_at.unwrap_or(0),
            not_before: license.not_before,
            revision: license.revision,
            block_number: license.block_number,
            block_hash: license.block_hash.clone(),
        });
        self.with_binding_budget(Some(budget), |binding| {
            self.assert_active(budget, generation)?;
            self.check_replacement_base(binding, expected)?;
            if binding.registry_replacement_id.as_deref() != Some(id) {
                return Err(RegistryError::new("registry_replacement_state_conflict"));
            }
            binding.registry_manifest = Some(raw.to_owned());
            binding.registry_replacement_id = None;
            binding.registry_offline = offline_basis.as_ref().map(OfflineBasis::to_json);
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
        let pending =
            self.with_binding_budget(Some(&budget), |b| Ok(b.registry_activation_id.clone()))?;
        if pending.is_none() {
            // A license already published under this code is rebuilt from the registry;
            // Talos is asked only when there is nothing on chain to recover.
            if let Some(license) =
                self.recover_from_chain(code, options, &scoped, &budget, generation)?
            {
                return Ok(license);
            }
        }
        let endpoint = self
            .0
            .endpoint
            .as_ref()
            .ok_or_else(|| RegistryError::new("registry_activation_not_configured"))?;
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

    /// With an activator configured, look for a license already published under `code` and
    /// install it from chain data alone. `None` sends the caller on to the activation
    /// service: no activator, no code, or nothing recoverable on chain.
    fn recover_from_chain(
        &self,
        code: &str,
        options: &RegistryActivationOptions,
        transport: &dyn Transport,
        budget: &Budget,
        generation: u64,
    ) -> RegistryResult<Option<RegistryLicenseState>> {
        let Some(activator) = self.0.activator.as_deref() else {
            return Ok(None);
        };
        if code.trim().is_empty() {
            return Ok(None);
        }
        let identity = protocol::code_identity(&self.0.trust, code)?;
        if SigningKey::from_bytes(&identity.seed).verifying_key() != self.0.key.verifying_key() {
            // This client holds a random key. Activating with it would bind the license to a
            // key its own code cannot reproduce, which is the one thing this mode promises.
            return Err(RegistryError::new("registry_code_identity_required"));
        }
        self.assert_active(budget, generation)?;
        let found = chain::recover_manifest(
            transport,
            &self.0.options.rpc_urls,
            &chain::RecoveryInput {
                trust: &self.0.trust,
                activator,
                license_id: &identity.license_id,
                device_key: &self.0.device_key,
            },
            || self.now(),
        );
        self.assert_active(budget, generation)?;
        let Some(manifest) = found? else {
            return Ok(None);
        };
        let raw = serde_json::to_string(&manifest)
            .map_err(|_| RegistryError::new("invalid_registry_manifest"))?;
        let candidate = protocol::parse_manifest(&raw, &self.0.trust)?;
        // No activation job exists for a license read straight from the registry.
        notify(options, RegistryActivationStatus::Validating, "", 0);
        let check = self.validate_candidate(&candidate, generation, transport, Some(budget));
        self.assert_active(budget, generation)?;
        check?;
        let generation = {
            // Same lock order as `commit_ready`: manifest, then persisted state.
            let mut manifest = lock(&self.0.manifest);
            self.assert_active(budget, generation)?;
            if manifest.is_some() {
                return Err(RegistryError::new("registry_activation_interrupted"));
            }
            self.with_binding_budget(Some(budget), |binding| {
                self.assert_active(budget, generation)?;
                if binding.registry_activation_id.is_some() || binding.registry_manifest.is_some() {
                    return Err(RegistryError::new("registry_activation_state_conflict"));
                }
                binding.registry_manifest = Some(raw.clone());
                self.save_binding(binding)
            })?;
            *manifest = Some(candidate);
            self.0.generation.fetch_add(1, Ordering::AcqRel) + 1
        };
        let result = self.validate_with(transport, Some(budget));
        self.assert_active(budget, generation)?;
        let result = result?;
        notify(options, RegistryActivationStatus::Ready, "", 0);
        Ok(Some(result))
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
            if terminal || observation.refusal.is_some() {
                binding.registry_offline = None;
            }
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
        let state = RegistryLicenseState {
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
            offline_until: None,
        };
        // What an offline allowance is measured from. Kept only for the license
        // this device actually holds — a candidate still being activated or
        // replaced has not earned it — and only when the license has the term,
        // so a license without one leaves nothing behind to be reinterpreted.
        let basis = offline_allowance_days(&candidate.entitlements).map(|_| OfflineBasis {
            license_id: candidate.manifest.license_id.clone(),
            entitlements_hash: candidate.entitlements_hash.clone(),
            checked_at: state.checked_at,
            expires_at: observation.record.expires_at,
            not_before: state.not_before,
            revision: state.revision,
            block_number: state.block_number,
            block_hash: state.block_hash.clone(),
        });
        // Only when the license just observed is the one this client holds.
        // Validating a candidate — an activation or a replacement in progress —
        // must neither grant it a basis nor take the held license's away. Read
        // before the state lock: the order is manifest, then state.
        let held = lock(&self.0.manifest).as_ref().is_some_and(|held| {
            held.manifest.license_id == candidate.manifest.license_id
                && held.entitlements_hash == candidate.entitlements_hash
        });
        self.with_binding_budget(budget, |binding| {
            if self.0.generation.load(Ordering::Acquire) != generation {
                return Err(RegistryError::new("license_changed_during_validation"));
            }
            let next = basis.as_ref().map(OfflineBasis::to_json);
            if held && binding.registry_offline != next {
                binding.registry_offline = next;
                self.save_binding(binding)?;
            }
            Ok(())
        })?;
        Ok(state)
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
fn merge_chain_states(
    old: Option<chain::RegistryChainState>,
    next: Option<chain::RegistryChainState>,
) -> RegistryResult<Option<chain::RegistryChainState>> {
    match (old, next) {
        (None, None) => Ok(None),
        (Some(state), None) | (None, Some(state)) => Ok(Some(state)),
        (Some(old), Some(next)) => {
            let old_num = old
                .head
                .number
                .parse::<u64>()
                .map_err(|_| RegistryError::new("invalid_registry_chain_state"))?;
            let next_num = next
                .head
                .number
                .parse::<u64>()
                .map_err(|_| RegistryError::new("invalid_registry_chain_state"))?;
            let head = if next_num > old_num
                || (next_num == old_num && next.head.timestamp >= old.head.timestamp)
            {
                next.head
            } else {
                old.head
            };
            let mut licenses = old.licenses;
            for (id, obs) in next.licenses {
                licenses
                    .entry(id)
                    .and_modify(|e| {
                        e.revision = e.revision.max(obs.revision);
                        e.revoked |= obs.revoked;
                    })
                    .or_insert(obs);
            }
            if licenses.len() > 64 {
                return Err(RegistryError::new("invalid_registry_chain_state"));
            }
            Ok(Some(chain::RegistryChainState {
                v: 1,
                head,
                licenses,
            }))
        }
    }
}

const PORTABLE_KIND: &str = "talos-registry-portable-license";

/// The application's pins in canonical form, validated.
fn trust_of(options: &RegistryLicenseOptions) -> RegistryResult<RegistryTrust> {
    let trust = RegistryTrust {
        chain_id: options.chain_id,
        contract: options.contract.to_ascii_lowercase(),
        issuer: options.issuer.to_ascii_lowercase(),
        product_id: options.product_id.to_ascii_lowercase(),
    };
    protocol::validate_trust(&trust)?;
    Ok(trust)
}

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
