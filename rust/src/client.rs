use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::Duration;

use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::compact::{
    number, unix_now, verify_cached_token_at, verify_keyset, verify_manifest_at, verify_token_at,
    Claims, PublicKey, B64URL, CLOCK_SKEW_SECONDS,
};
use crate::diagnostics::diagnostic_report;
use crate::error::{Error, Result};
use crate::fingerprint::{collect_fingerprint, hex, FingerprintData};
use crate::host;
use crate::offline::{
    generate_machine_key, sign_machine_doc, MachineKey, SignedDoc, LICENSE_FILE_KIND,
    RECEIPT_DOMAIN, REQUEST_DOMAIN,
};
use crate::state::{
    default_state_path, hash_license_key, state_key_material, StateStore, StoredBinding,
};
use crate::transport::{HttpRequest, Transport};
use crate::types::{
    AcquireLeaseOptions, CheckForUpdateOptions, CheckInOptions, Decision, DeltaOptions,
    DownloadProgress, EventKind, Lease, LicenseState, TalosEvent, UpdateArtifact, UpdateDelta,
    UpdateDeltaTarget, UpdateInfo,
};
use crate::version::sdk_id;

/// Fallback check-in cadence, used only until the first heartbeat reports the
/// policy's own. Matches the server's `policies.heartbeat_interval_s` default.
const DEFAULT_HEARTBEAT_SECONDS: i64 = 600;

/// How long an adopted keyset is trusted before a refresh is attempted: the
/// upper bound on how long a revoked signing key keeps being accepted by an
/// install that stays online. A day, because the endpoint is public and the
/// document changes about once a year.
const KEYSET_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;

/// Default cap on a licensing call. Long enough that a slow network is not
/// mistaken for a dead one, short enough that an application blocked on it
/// still starts.
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The most a licensing response may be. Real ones are a few kilobytes; a
/// server streaming more is not one to keep reading from.
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// How a [`TalosClient`] is configured.
///
/// ```no_run
/// use talos_sdk::{TalosClient, TalosOptions};
///
/// let talos = TalosClient::new(TalosOptions {
///     product_token: "tpt_…".into(),
///     anchor_public_key: Some("base64-anchor-key".into()),
///     server_url: "https://talos.dziuin.dev".into(),
///     app_version: Some(env!("CARGO_PKG_VERSION").into()),
///     ..Default::default()
/// })?;
/// # Ok::<(), talos_sdk::Error>(())
/// ```
#[derive(Clone)]
pub struct TalosOptions {
    /// The product's public token (`tpt_…`) from the portal.
    pub product_token: String,
    /// Base URL of the Talos (or self-hosted) server.
    pub server_url: String,
    /// The product's **anchor** public key, base64 — the rotation-safe root.
    /// The SDK fetches the anchor-signed keyset and learns the current licence
    /// and release keys from it, so rotating a signing key never breaks a
    /// deployed app. Pin this.
    pub anchor_public_key: Option<String>,
    /// A direct pin of the licence-signing key. Works, and breaks on the first
    /// rotation; prefer the anchor. Optional when the anchor is set.
    pub public_key: Option<String>,
    /// A direct pin of the release-signing key, for update manifests. Falls
    /// back to `public_key`.
    pub release_public_key: Option<String>,
    /// Your application's version, reported on activation, validation and
    /// heartbeat, and the default for update checks and patch selection.
    pub app_version: Option<String>,
    /// The name shown for this seat in the portal. Defaults to the machine's
    /// hostname; `Some("")` sends nothing.
    pub hostname: Option<String>,
    /// The update channel this install follows; `stable` when unset.
    pub update_channel: Option<String>,
    /// How long a licensing call may take. Default 10 s; `Duration::ZERO`
    /// disables it. Not applied to artifact downloads, which are bounded by the
    /// signed manifest's size instead.
    pub http_timeout: Duration,
    /// Extra fingerprint components merged over the collected ones, hashed
    /// like any other (e.g. `smbios_uuid` read by your own code).
    pub fingerprint_components: BTreeMap<String, String>,
    /// Where to keep this machine's binding. Defaults to
    /// [`default_state_path`](crate::default_state_path).
    pub state_path: Option<PathBuf>,
    /// Persist the binding (default `true`). Off only for a process that must
    /// not leave a licence on disk — every start then activates again.
    pub persist_state: bool,
    /// Your own HTTP client for every call, downloads included. Defaults to the
    /// built-in one (feature `ureq`).
    pub transport: Option<Arc<dyn Transport>>,
}

impl Default for TalosOptions {
    fn default() -> Self {
        TalosOptions {
            product_token: String::new(),
            server_url: String::new(),
            anchor_public_key: None,
            public_key: None,
            release_public_key: None,
            app_version: None,
            hostname: None,
            update_channel: None,
            http_timeout: DEFAULT_HTTP_TIMEOUT,
            fingerprint_components: BTreeMap::new(),
            state_path: None,
            persist_state: true,
            transport: None,
        }
    }
}

impl std::fmt::Debug for TalosOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TalosOptions")
            .field("product_token", &self.product_token)
            .field("server_url", &self.server_url)
            .field("anchor_public_key", &self.anchor_public_key)
            .field("app_version", &self.app_version)
            .field("update_channel", &self.update_channel)
            .field("http_timeout", &self.http_timeout)
            .field("state_path", &self.state_path)
            .field("persist_state", &self.persist_state)
            .field("transport", &self.transport.as_ref().map(|_| "custom"))
            .finish_non_exhaustive()
    }
}

/// A listener registration. Call [`unsubscribe`](Self::unsubscribe) to remove
/// it; dropping it leaves the listener in place.
#[derive(Debug)]
pub struct Subscription {
    id: u64,
    listeners: Weak<Mutex<Listeners>>,
}

impl Subscription {
    /// Remove the listener.
    pub fn unsubscribe(self) {
        if let Some(l) = self.listeners.upgrade() {
            lock(&l).entries.retain(|e| e.0 != self.id);
        }
    }
}

type Listener = Arc<dyn Fn(&TalosEvent) + Send + Sync>;

#[derive(Default)]
struct Listeners {
    next: u64,
    entries: Vec<(u64, EventKind, Listener)>,
}

impl std::fmt::Debug for Listeners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Listeners({})", self.entries.len())
    }
}

/// A cancellable sleep shared with one background thread. Bumping the
/// generation wakes the sleeper and tells it it has been replaced.
#[derive(Default)]
struct Ticker {
    generation: Mutex<u64>,
    wake: Condvar,
}

impl Ticker {
    fn bump(&self) -> u64 {
        let mut g = lock(&self.generation);
        *g += 1;
        self.wake.notify_all();
        *g
    }

    fn current(&self) -> u64 {
        *lock(&self.generation)
    }

    /// Sleep for `d` unless replaced first. True if still current afterwards.
    fn sleep(&self, generation: u64, d: Duration) -> bool {
        let g = lock(&self.generation);
        let (g, _) = self
            .wake
            .wait_timeout_while(g, d, |g| *g == generation)
            .unwrap_or_else(|e| e.into_inner());
        *g == generation
    }
}

/// Everything about the client that changes.
#[derive(Default)]
struct Mutable {
    keyset_license_keys: Vec<PublicKey>,
    keyset_release_keys: Vec<PublicKey>,
    /// True while the adopted keyset came off disk: one refresh per process
    /// upgrades it, but a client that cannot reach the server keeps verifying
    /// with what it already trusts.
    keyset_from_cache: bool,
    /// The adopted keyset's signed `iat`, so it can go stale in a process that
    /// runs for weeks — and so an older one is never adopted over it.
    keyset_issued_at: i64,
    /// The adopted keyset token itself, which is what gets persisted.
    keyset_token: Option<String>,
    license_key_hash: Option<String>,
    activation_secret: Option<String>,
    machine_id: Option<String>,
    binding: Option<StoredBinding>,
    heartbeat_interval: Option<i64>,
    lease: Option<Lease>,
    /// Bumped on release so an in-flight renewal cannot resurrect the seat.
    lease_generation: u64,
    current: Option<LicenseState>,
    /// The newest release already announced.
    announced_release_seq: i64,
}

pub(crate) struct Inner {
    product_token: String,
    server_url: String,
    app_version: Option<String>,
    hostname: Option<String>,
    update_channel: Option<String>,
    http_timeout: Duration,
    anchor: Option<PublicKey>,
    public_key: Option<PublicKey>,
    release_key: Option<PublicKey>,
    fp: FingerprintData,
    transport: Arc<dyn Transport>,
    store: Option<StateStore>,
    instance_id: String,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
    m: Mutex<Mutable>,
    listeners: Arc<Mutex<Listeners>>,
    check_ins: Arc<Ticker>,
    renewals: Arc<Ticker>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Wake both background threads so they notice the client is gone
        // rather than sleeping out their interval first.
        self.check_ins.bump();
        self.renewals.bump();
    }
}

/// The Talos client: one per product, for the life of the process.
///
/// Every trust decision is a signed token verified against the pinned key, so a
/// fake or intercepting server cannot forge an acceptable answer. Calls block;
/// from async code, run them on a blocking thread (`spawn_blocking`).
///
/// Cloning is cheap and yields a handle to the same client — the same binding,
/// the same listeners, the same background loops.
#[derive(Clone)]
pub struct TalosClient {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for TalosClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TalosClient")
            .field("product_token", &self.inner.product_token)
            .field("activated", &self.is_activated())
            .finish_non_exhaustive()
    }
}

impl TalosClient {
    /// Build a client, restoring this machine's binding from disk.
    ///
    /// Synchronous and offline: a client constructed at startup already
    /// answers [`is_activated`](Self::is_activated), so the application knows
    /// whether to ask for a licence key before anything touches the network.
    pub fn new(options: TalosOptions) -> Result<Self> {
        Self::with_clock(options, Box::new(unix_now))
    }

    pub(crate) fn with_clock(
        options: TalosOptions,
        clock: Box<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self> {
        if options.product_token.is_empty() {
            return Err(Error::usage("product_token required"));
        }
        if options.server_url.is_empty() {
            return Err(Error::usage("server_url required"));
        }
        let nonempty = |s: &Option<String>| {
            s.as_deref()
                .filter(|s| !s.is_empty())
                .map(PublicKey::from_base64)
        };
        let anchor = nonempty(&options.anchor_public_key).transpose()?;
        let public_key = nonempty(&options.public_key).transpose()?;
        if anchor.is_none() && public_key.is_none() {
            return Err(Error::usage("anchor_public_key or public_key required"));
        }
        // The direct release pin falls back to the licence pin; a keyset
        // overrides both.
        let release_key = nonempty(&options.release_public_key)
            .transpose()?
            .or(public_key);
        let transport = match options.transport {
            Some(t) => t,
            None => default_transport()?,
        };
        let fp = collect_fingerprint(&options.product_token, &options.fingerprint_components);
        let store = options.persist_state.then(|| {
            StateStore::new(
                options
                    .state_path
                    .clone()
                    .unwrap_or_else(|| default_state_path(&options.product_token)),
                &options.product_token,
                &state_key_material(&fp),
            )
        });
        let mut instance = [0u8; 9];
        getrandom::getrandom(&mut instance)
            .map_err(|e| Error::usage(format!("no randomness available: {e}")))?;

        let inner = Inner {
            product_token: options.product_token,
            server_url: options.server_url.trim_end_matches('/').to_string(),
            app_version: options.app_version.filter(|v| !v.is_empty()),
            hostname: options.hostname,
            update_channel: options.update_channel.filter(|c| !c.is_empty()),
            http_timeout: options.http_timeout,
            anchor,
            public_key,
            release_key,
            fp,
            transport,
            store,
            instance_id: B64URL.encode(instance),
            clock,
            m: Mutex::new(Mutable::default()),
            listeners: Arc::new(Mutex::new(Listeners::default())),
            check_ins: Arc::new(Ticker::default()),
            renewals: Arc::new(Ticker::default()),
        };
        inner.restore();
        Ok(TalosClient {
            inner: Arc::new(inner),
        })
    }

    /// Whether this install holds a licence for this machine — an online
    /// activation **or** a loaded air-gapped licence file. The startup
    /// question: ask for a licence key, or go straight to
    /// [`validate`](Self::validate)?
    #[must_use]
    pub fn is_activated(&self) -> bool {
        let m = lock(&self.inner.m);
        m.activation_secret.is_some()
            || m.binding
                .as_ref()
                .is_some_and(|b| b.offline_token.is_some())
    }

    /// The server's id for this machine, once activated.
    #[must_use]
    pub fn machine_id(&self) -> Option<String> {
        lock(&self.inner.m).machine_id.clone()
    }

    /// The last verdict adopted, from any path.
    #[must_use]
    pub fn current(&self) -> Option<LicenseState> {
        lock(&self.inner.m).current.clone()
    }

    /// Whether the current verdict carries an enabled entitlement.
    #[must_use]
    pub fn is_feature_enabled(&self, name: &str) -> bool {
        lock(&self.inner.m)
            .current
            .as_ref()
            .is_some_and(|s| s.is_feature_enabled(name))
    }

    /// The policy's heartbeat cadence from the last heartbeat's **signed**
    /// claims, or `None` before the first one.
    #[must_use]
    pub fn heartbeat_interval_seconds(&self) -> Option<i64> {
        lock(&self.inner.m).heartbeat_interval
    }

    /// The floating seat currently held, if any.
    #[must_use]
    pub fn current_lease(&self) -> Option<Lease> {
        lock(&self.inner.m).lease.clone()
    }

    /// This machine's fingerprint, as sent to the server.
    #[must_use]
    pub fn fingerprint(&self) -> &FingerprintData {
        &self.inner.fp
    }

    /// A local JSON support report without credentials, identifiers or error
    /// text. Pass a caught error to classify it. Makes no requests and changes
    /// nothing; never use it as authorisation.
    #[must_use]
    pub fn create_diagnostic_report(&self, error: Option<&Error>) -> String {
        let current = self.current();
        diagnostic_report(
            self.is_activated(),
            self.inner.anchor.is_some(),
            current.as_ref(),
            error,
        )
    }

    /// Fetch and verify the anchor-signed keyset and adopt its keys. Called
    /// automatically when needed; call it after a rotation to pick the new keys
    /// up at once. A no-op without an anchor pin.
    pub fn refresh_keyset(&self) -> Result<()> {
        self.inner.refresh_keyset()
    }

    /// Ensure this machine is activated on `license_key` and return the
    /// verified state. Safe to call on every start.
    ///
    /// When a binding for the same key is already held this **re-validates**
    /// instead: the activation secret is not rotated (so a second copy of the
    /// app is not knocked out), no seat is touched, and — because activation is
    /// the one client route refused for a suspended tenant — your users keep
    /// working through a dispute over your own Talos account. It falls back to a
    /// real activation when the stored binding is gone.
    pub fn activate(&self, license_key: &str) -> Result<LicenseState> {
        self.inner.activate(license_key)
    }

    /// Validate the held activation: online first, offline-tolerant.
    ///
    /// When the server answers, that answer wins and is cached. When it cannot
    /// be reached — or answers with something that fails verification — the
    /// last verified verdict is honoured until the policy's grace runs out, and
    /// the state says `is_offline`. An HTTP status is an answer and is never
    /// masked by the cache.
    pub fn validate(&self) -> Result<LicenseState> {
        self.inner.validate()
    }

    /// Release this machine's seat and forget the binding, on disk too.
    pub fn deactivate(&self) -> Result<()> {
        self.inner.deactivate()
    }

    /// Report in: refreshes last-seen, feeds the portal's monitoring, and
    /// returns the current **signed** decision.
    pub fn heartbeat(&self) -> Result<LicenseState> {
        self.inner.heartbeat()
    }

    /// Run the check-ins the server's policy asks for, on a background thread.
    ///
    /// Each tick re-validates once the signed `reval_after` has passed and
    /// otherwise heartbeats at the signed `heartbeat_interval_s`, so changing
    /// the policy in the portal changes what deployed apps do. Calling it again
    /// replaces the running loop. The thread ends with
    /// [`stop_check_ins`](Self::stop_check_ins) or when the last client handle
    /// is dropped.
    pub fn start_check_ins(&self, options: CheckInOptions) {
        let generation = self.inner.check_ins.bump();
        let ticker = Arc::clone(&self.inner.check_ins);
        let weak = Arc::downgrade(&self.inner);
        std::thread::Builder::new()
            .name("talos-check-ins".into())
            .spawn(move || loop {
                let secs = match weak.upgrade() {
                    Some(inner) => lock(&inner.m)
                        .heartbeat_interval
                        .unwrap_or(DEFAULT_HEARTBEAT_SECONDS)
                        .max(60),
                    None => return,
                };
                if !ticker.sleep(generation, Duration::from_secs(secs as u64)) {
                    return;
                }
                let Some(inner) = weak.upgrade() else { return };
                let due = lock(&inner.m)
                    .current
                    .as_ref()
                    .and_then(|s| s.revalidate_after);
                let result = match due {
                    Some(due) if (inner.clock)() < due => inner.heartbeat(),
                    _ => inner.validate(),
                };
                if ticker.current() != generation {
                    return;
                }
                // Re-armed after a failure too: an outage must not silently end
                // the loop, or the app would never notice the network coming
                // back.
                let _ = catch_unwind(AssertUnwindSafe(|| match &result {
                    Ok(state) => {
                        if let Some(f) = &options.on_state {
                            f(state);
                        }
                    }
                    Err(e) => {
                        if let Some(f) = &options.on_error {
                            f(e);
                        }
                    }
                }));
            })
            .expect("spawning the check-in thread");
    }

    /// Stop the loop started by [`start_check_ins`](Self::start_check_ins).
    pub fn stop_check_ins(&self) {
        self.inner.check_ins.bump();
    }

    /// Subscribe to a transition.
    ///
    /// The four licence events are edges, not levels: each fires **once** on
    /// the way in — an app offline for a week gets one `GracePeriodStarted` —
    /// and `LicenseInvalid` fires again when the *reason* changes. They fire
    /// from every path that adopts a verdict (`activate`, `validate`,
    /// `heartbeat`, the offline fallback), synchronously, on the calling
    /// thread. A listener that panics is ignored: these are raised from inside
    /// `validate`, and a broken banner must not turn a live "revoked" into
    /// offline grace.
    ///
    /// Subscribing to [`EventKind::UpdateAvailable`] is what makes heartbeats
    /// ask the server whether a release is waiting; the payload is what a real
    /// [`check_for_update`](Self::check_for_update) verified.
    pub fn on(
        &self,
        kind: EventKind,
        listener: impl Fn(&TalosEvent) + Send + Sync + 'static,
    ) -> Subscription {
        let mut l = lock(&self.inner.listeners);
        l.next += 1;
        let id = l.next;
        l.entries.push((id, kind, Arc::new(listener)));
        Subscription {
            id,
            listeners: Arc::downgrade(&self.inner.listeners),
        }
    }

    /// Acquire a floating seat. The server arbitrates the cap atomically, so
    /// this either returns a seat or fails with `Error::Api { status: 409,
    /// code: Some("seat_limit_reached") }`.
    ///
    /// By default the seat is renewed on a background thread at the
    /// server-chosen interval. Always [`release_lease`](Self::release_lease) on
    /// a clean exit; a crash simply lets the seat expire.
    pub fn acquire_lease(&self, options: AcquireLeaseOptions) -> Result<Lease> {
        let instance_id = options
            .instance_id
            .clone()
            .unwrap_or_else(|| self.inner.instance_id.clone());
        let (lease, adopted) = self.inner.acquire_lease(&instance_id, None)?;
        if let (true, Some(lease_generation)) = (options.auto_renew, adopted) {
            self.schedule_renewals(instance_id, options, lease_generation);
        }
        Ok(lease)
    }

    /// Renew the seat adopted under `lease_generation` until it is released.
    ///
    /// The generation is the one the seat was adopted under, not one read here:
    /// a `release_lease` landing between the adoption and this call must stop
    /// the loop before it takes a seat, not be mistaken for the starting state.
    pub(crate) fn schedule_renewals(
        &self,
        instance_id: String,
        options: AcquireLeaseOptions,
        lease_generation: u64,
    ) {
        let generation = self.inner.renewals.bump();
        if lock(&self.inner.m).lease_generation != lease_generation {
            return;
        }
        let ticker = Arc::clone(&self.inner.renewals);
        let weak = Arc::downgrade(&self.inner);
        std::thread::Builder::new()
            .name("talos-lease-renewal".into())
            .spawn(move || loop {
                let delay = match weak.upgrade() {
                    Some(inner) => lock(&inner.m)
                        .lease
                        .as_ref()
                        .map_or(200, |l| l.renew_after_seconds)
                        .max(1),
                    None => return,
                };
                if !ticker.sleep(generation, Duration::from_secs(delay as u64)) {
                    return;
                }
                let Some(inner) = weak.upgrade() else { return };
                // Checked before asking for a seat as well as after: a release
                // during the sleep must not cost a seat it would then hand back.
                if lock(&inner.m).lease_generation != lease_generation {
                    return;
                }
                // Adopted only under this loop's generation, so a release while
                // the renewal is in flight hands the seat straight back.
                let result = inner.acquire_lease(&instance_id, Some(lease_generation));
                let mut m = lock(&inner.m);
                // Released (or re-acquired) while the renewal was in flight:
                // neither re-adopt nor report a loss nobody is holding.
                if m.lease_generation != lease_generation || ticker.current() != generation {
                    return;
                }
                match result {
                    Ok((_, Some(_))) => {}
                    Ok((_, None)) => return,
                    Err(e) => {
                        m.lease = None;
                        drop(m);
                        if let Some(f) = &options.on_lease_lost {
                            let reason = e.to_string();
                            let _ = catch_unwind(AssertUnwindSafe(|| f(&reason)));
                        }
                        return;
                    }
                }
            })
            .expect("spawning the lease renewal thread");
    }

    /// Release the floating seat and stop renewing it.
    pub fn release_lease(&self) -> Result<()> {
        // The generation moves FIRST, so a renewal already in flight sees it is
        // stale and neither re-adopts the seat nor re-arms.
        let lease = {
            let mut m = lock(&self.inner.m);
            m.lease_generation += 1;
            m.lease.take()
        };
        self.inner.renewals.bump();
        match lease {
            Some(lease) => self.inner.release_instance(&lease.instance_id),
            None => Ok(()),
        }
    }

    /// Ask whether a newer release is available. Returns a verified
    /// [`UpdateInfo`] — every field from the manifest signed by the release key
    /// — or `None` when up to date.
    ///
    /// Anti-downgrade: a release at or below the highest one this install has
    /// been seen running is answered with `None`, whatever the server says.
    ///
    /// An expired maintenance licence is `Error::Api { status: 403, code:
    /// Some("updates_not_entitled") }` here while `validate` stays valid: the
    /// customer keeps the version they bought. Say so, rather than treating it
    /// as a licensing failure or as "no update".
    pub fn check_for_update(&self, options: CheckForUpdateOptions) -> Result<Option<UpdateInfo>> {
        self.inner.check_for_update(&options)
    }

    /// The patch that upgrades this machine, or `None`. Matches the *exact*
    /// published version string — a patch applies to the bytes it was built
    /// against — and refuses to guess between several.
    #[must_use]
    pub fn select_delta(&self, info: &UpdateInfo, options: &DeltaOptions) -> Option<UpdateDelta> {
        let from = options
            .from
            .as_deref()
            .or(self.inner.app_version.as_deref())?;
        let matches: Vec<&UpdateDelta> = info
            .deltas
            .iter()
            .filter(|d| d.platform == host::platform() && d.arch == host::arch() && d.from == from)
            .collect();
        if let Some(kind) = &options.target_kind {
            return matches
                .into_iter()
                .find(|d| &d.target.kind == kind)
                .cloned();
        }
        match matches.as_slice() {
            [only] => Some((*only).clone()),
            _ => None,
        }
    }

    /// Download one artifact and put it at `dest` only once its bytes match the
    /// signed size and SHA-256. Defaults to this platform's installer. Does NOT
    /// install anything; that is the host application's job.
    ///
    /// The bytes stream to a `.talos-part` file beside `dest`, hashed as they
    /// arrive, so an installer is never held in memory and a failed download
    /// leaves whatever was at `dest` before.
    pub fn download_update(
        &self,
        info: &UpdateInfo,
        dest: impl AsRef<Path>,
        artifact: Option<&UpdateArtifact>,
        on_progress: Option<&mut dyn FnMut(DownloadProgress)>,
    ) -> Result<UpdateArtifact> {
        let chosen = match artifact {
            Some(a) => a.clone(),
            None => pick_artifact(&info.artifacts)
                .ok_or_else(|| Error::usage("no artifact matches this platform"))?,
        };
        self.inner.fetch_verified(
            chosen.download_path.as_deref(),
            chosen.size,
            &chosen.sha256,
            dest.as_ref(),
            on_progress,
        )?;
        self.inner.remember_downloaded(info);
        Ok(chosen)
    }

    /// Download a patch, verified like a full build. Returns it; its
    /// `target.sha256` is what the rebuilt file must hash to — check with
    /// [`verify_applied_update`] after applying.
    pub fn download_delta(
        &self,
        info: &UpdateInfo,
        dest: impl AsRef<Path>,
        delta: Option<&UpdateDelta>,
        options: &DeltaOptions,
        on_progress: Option<&mut dyn FnMut(DownloadProgress)>,
    ) -> Result<UpdateDelta> {
        let chosen = match delta {
            Some(d) => d.clone(),
            None => self
                .select_delta(info, options)
                .ok_or_else(|| Error::usage("no patch applies to this install"))?,
        };
        self.inner.fetch_verified(
            chosen.download_path.as_deref(),
            chosen.size,
            &chosen.sha256,
            dest.as_ref(),
            on_progress,
        )?;
        self.inner.remember_downloaded(info);
        Ok(chosen)
    }

    /// The request an air-gapped machine hands to its vendor. Write
    /// [`SignedDoc::to_json_pretty`] to `talos-request.json`; the vendor uploads
    /// it and returns a `license.talos` for
    /// [`load_offline_license`](Self::load_offline_license).
    ///
    /// The first call generates this machine's Ed25519 identity and keeps it in
    /// the state file; later calls reuse it. `license_key`, when given, lets the
    /// portal catch issuing against the wrong licence.
    pub fn create_offline_request(&self, license_key: Option<&str>) -> Result<SignedDoc> {
        self.inner.create_offline_request(license_key)
    }

    /// Adopt an air-gapped licence file, verified entirely locally.
    ///
    /// Fails only for a file that is not a licence — unreadable, not ours,
    /// another product's, a broken signature. A licence that cannot license this
    /// machine comes back as a verdict to show the user: `MachineMismatch`,
    /// `OfflineFileExpired`, `Expired`, `ClockTampered`.
    pub fn load_offline_license(&self, file: &[u8]) -> Result<LicenseState> {
        self.inner.load_offline_license(file)
    }

    /// [`load_offline_license`](Self::load_offline_license) from a path.
    pub fn load_offline_license_file(&self, path: impl AsRef<Path>) -> Result<LicenseState> {
        let bytes = std::fs::read(path)?;
        self.inner.load_offline_license(&bytes)
    }

    /// Hand this machine's air-gapped seat back: write the result to
    /// `talos-deactivation.json` for the vendor. **The licence is dropped
    /// before this returns**, so an app that loses the file has still stopped
    /// using the seat.
    pub fn create_offline_deactivation(&self) -> Result<SignedDoc> {
        self.inner.create_offline_deactivation()
    }
}

impl Inner {
    fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Restore the binding saved by an earlier process.
    fn restore(&self) {
        let Some(stored) = self.store.as_ref().and_then(StateStore::load) else {
            return;
        };
        let mut m = lock(&self.m);
        let nonempty = |s: &str| (!s.is_empty()).then(|| s.to_string());
        m.license_key_hash = nonempty(&stored.license_key_hash);
        m.activation_secret = nonempty(&stored.activation_secret);
        m.machine_id = nonempty(&stored.machine_id);
        // Adopt the cached keyset before anything asks for a verification key:
        // without it an anchor-only client cannot verify a cached decision, and
        // the offline path is unreachable exactly when it is needed.
        if let Some(keyset) = stored.keyset.clone() {
            if let Ok(true) = self.adopt_keyset(&mut m, &Value::String(keyset)) {
                m.keyset_from_cache = !m.keyset_license_keys.is_empty();
            }
        }
        m.binding = Some(stored);
        self.promote_downloaded_release(&mut m);
    }

    /// A downloaded release that is now the version running moves the
    /// anti-downgrade mark up. Installing happens outside the SDK; what it can
    /// see is the result, because `app_version` says which version is running.
    /// Only forward: a yanked release must not walk an install back.
    fn promote_downloaded_release(&self, m: &mut Mutable) {
        let Some(b) = m.binding.as_mut() else { return };
        let (Some(pending), Some(running)) =
            (b.pending_version.as_deref(), self.app_version.as_deref())
        else {
            return;
        };
        if pending != running {
            return;
        }
        b.release_seq_high_water = b.release_seq_high_water.max(b.pending_release_seq);
        b.pending_version = None;
        b.pending_release_seq = 0;
        self.save(m);
    }

    fn save(&self, m: &Mutable) {
        if let (Some(store), Some(b)) = (&self.store, &m.binding) {
            store.save(b);
        }
    }

    /// Change the binding and write it back. In memory even when nothing is
    /// persisted, so an in-process offline fallback still has its cache.
    fn persist(&self, m: &mut Mutable, f: impl FnOnce(&mut StoredBinding)) {
        if let Some(b) = m.binding.as_mut() {
            f(b);
            self.save(m);
        }
    }

    fn forget_binding(&self) {
        let mut m = lock(&self.m);
        m.license_key_hash = None;
        m.activation_secret = None;
        m.machine_id = None;
        m.current = None;
        m.binding = None;
        drop(m);
        if let Some(store) = &self.store {
            store.clear();
        }
    }

    /// Advance the server-time high-water mark from a signed claim. Only ever
    /// forward: this is what keeps offline grace bounded when the user owns the
    /// clock.
    fn advance_clock(m: &mut Mutable, claims: &Claims) {
        let Some(seen) = number(claims.get("server_time")).or_else(|| number(claims.get("iat")))
        else {
            return;
        };
        if let Some(b) = m.binding.as_mut() {
            if seen > b.time_high_water {
                b.time_high_water = seen;
            }
        }
    }

    fn binding_base(&self, m: &Mutable) -> StoredBinding {
        m.binding
            .clone()
            .unwrap_or_else(|| StoredBinding::empty(&self.fp.composite))
    }

    fn fingerprint_json(&self) -> Value {
        json!({ "composite": self.fp.composite, "components": self.fp.components })
    }

    /// The machine name to report, or `None` for none: an explicit `""`
    /// suppresses it, because omitting the field is the only way to leave the
    /// server's value alone.
    fn reported_hostname(&self) -> Option<String> {
        match &self.hostname {
            Some(h) if h.is_empty() => None,
            Some(h) => Some(h.clone()),
            None => host::hostname(),
        }
    }

    fn channel(&self) -> String {
        self.update_channel
            .clone()
            .unwrap_or_else(|| "stable".to_string())
    }

    fn require_activated(&self) -> Result<String> {
        lock(&self.m)
            .activation_secret
            .clone()
            .ok_or(Error::NotActivated)
    }

    /// A live answer that names a machine must name this one.
    ///
    /// The server echoes the composite it was asked about into every token it
    /// signs, so an honest answer always matches. One that does not was asked
    /// about another machine — a relay pairing this client's nonce with
    /// somebody else's activation — and says nothing about this one. A token
    /// without the claim is accepted, for a server older than it.
    fn check_machine(&self, fph: Option<&Value>) -> Result<()> {
        match fph.and_then(Value::as_str) {
            Some(fph) if fph != self.fp.composite => {
                Err(Error::signature("token was issued for another machine"))
            }
            _ => Ok(()),
        }
    }

    // ---- keys ----------------------------------------------------------------

    /// Verify a keyset against the anchor and adopt its keys. Returns whether
    /// it was adopted.
    ///
    /// A keyset older than the one already held is ignored rather than
    /// adopted. The server signs a keyset with the time it is asked for one, so
    /// an older one can only be a recording — and a recording from before a key
    /// was revoked is exactly how a revoked key would come back, on every
    /// refresh, for as long as somebody kept replaying it. The allowance is for
    /// two replicas' clocks, not for anything an attacker could use.
    fn adopt_keyset(&self, m: &mut Mutable, token: &Value) -> Result<bool> {
        let (Some(anchor), Some(token)) = (&self.anchor, token.as_str()) else {
            return Ok(false);
        };
        let claims = verify_keyset(anchor, &self.product_token, token)?;
        // From the signed claims, not a local reading: a wrong clock would
        // otherwise call its keyset fresh forever, or stale on every call.
        let issued_at = number(claims.get("iat")).unwrap_or(0);
        if issued_at + CLOCK_SKEW_SECONDS < m.keyset_issued_at {
            return Ok(false);
        }
        let mut license = Vec::new();
        let mut release = Vec::new();
        for entry in claims
            .get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(pk) = entry.get("pk").and_then(Value::as_str) else {
                continue;
            };
            let Ok(key) = PublicKey::from_base64(pk) else {
                continue;
            };
            match entry.get("purpose").and_then(Value::as_str) {
                Some("license") => license.push(key),
                Some("release") => release.push(key),
                _ => {}
            }
        }
        m.keyset_issued_at = issued_at;
        m.keyset_license_keys = license;
        m.keyset_release_keys = release;
        m.keyset_token = Some(token.to_string());
        Ok(true)
    }

    fn refresh_keyset(&self) -> Result<()> {
        if self.anchor.is_none() {
            return Ok(());
        }
        let body = self.post(
            "/v1/client/keyset",
            json!({ "product_token": self.product_token }),
        )?;
        let keyset = body.get("keyset").cloned().unwrap_or(Value::Null);
        let mut m = lock(&self.m);
        let adopted = self.adopt_keyset(&mut m, &keyset)?;
        m.keyset_from_cache = false;
        if adopted {
            let token = m.keyset_token.clone();
            self.persist(&mut m, |b| b.keyset = token);
        }
        Ok(())
    }

    /// Make sure a verification key exists before a response has to be
    /// verified, refreshing a cached or stale keyset when the server is there.
    fn ensure_keyset(&self) -> Result<()> {
        if self.anchor.is_none() {
            return Ok(());
        }
        {
            let m = lock(&self.m);
            let stale =
                m.keyset_issued_at == 0 || self.now() - m.keyset_issued_at > KEYSET_MAX_AGE_SECONDS;
            if !m.keyset_license_keys.is_empty() && !m.keyset_from_cache && !stale {
                return Ok(());
            }
        }
        match self.refresh_keyset() {
            Ok(()) => Ok(()),
            // A refresh that cannot reach the server must not break a client
            // that already holds keys it trusts — that would make a network
            // problem look like a licensing failure.
            Err(_) if !lock(&self.m).keyset_license_keys.is_empty() => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn license_keys(&self, m: &Mutable) -> Result<Vec<PublicKey>> {
        if !m.keyset_license_keys.is_empty() {
            return Ok(m.keyset_license_keys.clone());
        }
        self.public_key
            .map(|k| vec![k])
            .ok_or_else(|| Error::signature("no license verification key (keyset unavailable)"))
    }

    fn release_keys(&self, m: &Mutable) -> Result<Vec<PublicKey>> {
        if !m.keyset_release_keys.is_empty() {
            return Ok(m.keyset_release_keys.clone());
        }
        self.release_key
            .map(|k| vec![k])
            .ok_or_else(|| Error::signature("no release verification key (keyset unavailable)"))
    }

    // ---- verdicts ------------------------------------------------------------

    /// Adopt a verdict as the current one and announce the transition it makes.
    /// The single funnel every path goes through, which is what makes the
    /// events trustworthy.
    fn adopt(&self, state: LicenseState) -> LicenseState {
        let event = {
            let mut m = lock(&self.m);
            let event = transition_event(m.current.as_ref(), &state);
            m.current = Some(state.clone());
            event
        };
        if let Some(kind) = event {
            let payload = match kind {
                EventKind::LicenseInvalid => TalosEvent::LicenseInvalid(state.clone()),
                EventKind::GracePeriodStarted => TalosEvent::GracePeriodStarted(state.clone()),
                EventKind::GracePeriodExpired => TalosEvent::GracePeriodExpired(state.clone()),
                _ => TalosEvent::ClockTamperDetected(state.clone()),
            };
            self.emit(&payload);
        }
        state
    }

    fn emit(&self, event: &TalosEvent) {
        let kind = event.kind();
        let listeners: Vec<Listener> = lock(&self.listeners)
            .entries
            .iter()
            .filter(|e| e.1 == kind)
            .map(|e| Arc::clone(&e.2))
            .collect();
        for listener in listeners {
            // The verdict is already decided. A host's broken banner code must
            // not unwind out of `validate` and turn a live answer into grace.
            let _ = catch_unwind(AssertUnwindSafe(|| listener(event)));
        }
    }

    fn has_listener(&self, kind: EventKind) -> bool {
        lock(&self.listeners).entries.iter().any(|e| e.1 == kind)
    }

    fn state_from_claims(
        &self,
        claims: &Claims,
        decision: Decision,
        is_offline: bool,
    ) -> LicenseState {
        let empty = Map::new();
        let lic = claims
            .get("lic")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        let features = lic
            .get("features")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        // Validation carries absolute deadlines; activation carries the same
        // policy as hours beside its `iat`. Prefer the absolute form.
        let iat = number(claims.get("iat")).unwrap_or_else(|| self.now());
        let hours_after = |k: &str| number(lic.get(k)).map(|h| iat + h * 3600);
        LicenseState {
            decision,
            features,
            license_expires_at: number(lic.get("lic_exp")),
            is_offline,
            revalidate_after: number(claims.get("reval_after")).or_else(|| hours_after("reval_h")),
            grace_until: number(claims.get("grace_until")).or_else(|| hours_after("grace_h")),
        }
    }

    // ---- the licensing calls -------------------------------------------------

    fn activate(&self, license_key: &str) -> Result<LicenseState> {
        let key_hash = hash_license_key(license_key);
        let same_key = lock(&self.m).license_key_hash.as_deref() == Some(key_hash.as_str());
        if same_key && self.require_activated().is_ok() {
            match self.validate() {
                // `deactivated` means the seat was released, and taking it again
                // is what re-activating is for. Every other verdict is the
                // server's answer.
                Ok(state) if state.decision != Decision::Deactivated => return Ok(state),
                Ok(_) => {}
                // 401: the secret was rotated elsewhere. 404: the machine is
                // gone. Anything else is a real failure, not a reason to spend
                // a seat.
                Err(Error::Api {
                    status: 401 | 404, ..
                }) => {}
                Err(e) => return Err(e),
            }
            self.forget_binding();
        }

        let nonce = new_nonce();
        let body = self.post(
            "/v1/client/activate",
            json!({
                "product_token": self.product_token,
                "license_key": license_key,
                "fingerprint": self.fingerprint_json(),
                "nonce": nonce,
                "hostname": self.reported_hostname(),
                "os": host::os_description(),
                "arch": host::arch(),
                "app_version": self.app_version,
                "sdk_version": sdk_id(),
            }),
        )?;

        let mut m = lock(&self.m);
        // Adopt the keyset delivered with activation first, so a rotated key
        // verifies the activation token.
        let keyset = body.get("keyset").cloned().unwrap_or(Value::Null);
        if self.adopt_keyset(&mut m, &keyset)? {
            m.keyset_from_cache = false;
        }
        let claims = verify_token_at(
            &self.license_keys(&m)?,
            "activation",
            &self.product_token,
            &nonce,
            str_field(&body, "activation_token"),
            self.now(),
        )?;
        // Activation names the machine inside `lic`; the others at the top.
        self.check_machine(claims.get("lic").and_then(|lic| lic.get("fph")))?;
        let secret = str_field(&body, "activation_secret").to_string();
        if secret.is_empty() {
            return Err(Error::InvalidResponse(
                "activation returned no activation_secret".into(),
            ));
        }
        let machine_id = body
            .get("machine_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let previous = m.binding.take();
        let keyset = m
            .keyset_token
            .clone()
            .or_else(|| previous.as_ref().and_then(|p| p.keyset.clone()));
        m.license_key_hash = Some(key_hash.clone());
        m.activation_secret = Some(secret.clone());
        m.machine_id = machine_id.clone();
        m.binding = Some(StoredBinding {
            license_key_hash: key_hash,
            activation_secret: secret,
            machine_id: machine_id.unwrap_or_default(),
            fingerprint: self.fp.composite.clone(),
            // A fresh activation invalidates any cached verdict for the old
            // binding; what survives is per product or per install, not per
            // binding: the keyset, the clock mark, the anti-downgrade mark and
            // this machine's own offline identity. The offline *file* does not —
            // a live activation supersedes it.
            keyset,
            time_high_water: previous.as_ref().map_or(0, |p| p.time_high_water),
            release_seq_high_water: previous.as_ref().map_or(0, |p| p.release_seq_high_water),
            pending_version: previous.as_ref().and_then(|p| p.pending_version.clone()),
            pending_release_seq: previous.as_ref().map_or(0, |p| p.pending_release_seq),
            machine_key: previous.as_ref().and_then(|p| p.machine_key.clone()),
            machine_public_key: previous.as_ref().and_then(|p| p.machine_public_key.clone()),
            offline_seen: previous.as_ref().map_or(0, |p| p.offline_seen),
            ..StoredBinding::default()
        });
        Self::advance_clock(&mut m, &claims);
        self.save(&m);
        drop(m);
        Ok(self.adopt(self.state_from_claims(&claims, Decision::Valid, false)))
    }

    fn validate(&self) -> Result<LicenseState> {
        // An air-gapped install has no server to ask and no secret to ask with:
        // its file is the verdict, re-checked here because the clock and the
        // calendar are exactly what may have changed.
        let offline_token = {
            let m = lock(&self.m);
            match (
                &m.activation_secret,
                m.binding.as_ref().and_then(|b| b.offline_token.clone()),
            ) {
                (None, Some(token)) => Some(token),
                _ => None,
            }
        };
        if let Some(token) = offline_token {
            return self.adopt_offline_token(&token);
        }
        let secret = self.require_activated()?;
        match self.validate_online(&secret) {
            Ok(state) => Ok(state),
            // An HTTP status is an answer. Falling back here would turn every
            // negative verdict into hours of grace.
            Err(e @ Error::Api { .. }) => Err(e),
            // Only the absence of an answer falls back: a dead network, or a
            // reply that fails verification — which tells us nothing, and so is
            // treated as unreachable, never as valid.
            Err(e) => match self.offline_decision() {
                Some(state) => Ok(self.adopt(state)),
                None => Err(e),
            },
        }
    }

    fn validate_online(&self, secret: &str) -> Result<LicenseState> {
        self.ensure_keyset()?;
        let nonce = new_nonce();
        let body = self.post(
            "/v1/client/validate",
            json!({
                "product_token": self.product_token,
                "fingerprint": self.fingerprint_json(),
                "activation_secret": secret,
                "nonce": nonce,
                // Here as well as on activation and heartbeat, because check-ins
                // are opt-in and this call is not.
                "app_version": self.app_version,
                "sdk_version": sdk_id(),
            }),
        )?;
        let token = str_field(&body, "validation_token").to_string();
        let mut m = lock(&self.m);
        let claims = verify_token_at(
            &self.license_keys(&m)?,
            "validation",
            &self.product_token,
            &nonce,
            &token,
            self.now(),
        )?;
        self.check_machine(claims.get("fph"))?;
        let decision = decision_of(&claims);
        Self::advance_clock(&mut m, &claims);
        self.persist(&mut m, |b| b.validation = Some(token));
        drop(m);
        Ok(self.adopt(self.state_from_claims(&claims, decision, false)))
    }

    /// The verdict from the local cache, or `None` when nothing is usable.
    ///
    /// Every check is load-bearing: the token is re-verified under the pinned
    /// key (an edited cache is worthless), `fph` must be this machine (a copied
    /// state file licenses nothing), `grace_until` bounds how long a verdict may
    /// outlive its issuance, the licence's own expiry still applies, and the
    /// clock is checked against a mark that only moves forward.
    fn offline_decision(&self) -> Option<LicenseState> {
        let m = lock(&self.m);
        let b = m.binding.as_ref()?;
        let token = b.validation.clone()?;
        let now = self.now();
        if b.time_high_water > 0 && now + CLOCK_SKEW_SECONDS < b.time_high_water {
            // Distinct from "expired": nothing has run out, the machine is
            // lying about the time.
            return Some(LicenseState::bare(Decision::ClockTampered, true));
        }
        let claims = verify_cached_token_at(
            &self.license_keys(&m).ok()?,
            "validation",
            &self.product_token,
            &token,
            now,
        )
        .ok()?;
        drop(m);
        if claims.get("fph").and_then(Value::as_str) != Some(self.fp.composite.as_str()) {
            return None;
        }
        let grace_until = number(claims.get("grace_until"));
        let mut cached = self.state_from_claims(&claims, decision_of(&claims), true);
        cached.grace_until = grace_until;
        if grace_until.is_none_or(|g| now > g) {
            cached.decision = Decision::GraceExpired;
        } else if cached.license_expires_at.is_some_and(|exp| now > exp) {
            cached.decision = Decision::Expired;
        }
        Some(cached)
    }

    fn deactivate(&self) -> Result<()> {
        let secret = self.require_activated()?;
        self.post(
            "/v1/client/deactivate",
            json!({
                "product_token": self.product_token,
                "fingerprint": self.fingerprint_json(),
                "activation_secret": secret,
            }),
        )?;
        self.forget_binding();
        Ok(())
    }

    fn heartbeat(&self) -> Result<LicenseState> {
        let secret = self.require_activated()?;
        self.ensure_keyset()?;
        let nonce = new_nonce();
        let wants_update = self.has_listener(EventKind::UpdateAvailable);
        let body = self.post(
            "/v1/client/heartbeat",
            json!({
                "product_token": self.product_token,
                "fingerprint": self.fingerprint_json(),
                "activation_secret": secret,
                "nonce": nonce,
                "app_version": self.app_version,
                "os": host::os_description(),
                "arch": host::arch(),
                "sdk_version": sdk_id(),
                // Naming the channel is what asks for the update hint, and it
                // costs the server two queries — so only when somebody listens.
                "update_channel": wants_update.then(|| self.channel()),
            }),
        )?;
        let mut m = lock(&self.m);
        let claims = verify_token_at(
            &self.license_keys(&m)?,
            "heartbeat",
            &self.product_token,
            &nonce,
            str_field(&body, "heartbeat_token"),
            self.now(),
        )?;
        self.check_machine(claims.get("fph"))?;
        // The cadence comes from the SIGNED claims, never the envelope: nobody
        // in the middle gets to tell a fleet to check in less often.
        if let Some(interval) = number(claims.get("heartbeat_interval_s")).filter(|i| *i > 0) {
            m.heartbeat_interval = Some(interval);
        }
        // Every signed server clock pushes the mark forward, not only
        // validation's — a heartbeat is the most frequent call there is.
        Self::advance_clock(&mut m, &claims);
        self.save(&m);
        // A heartbeat carries the decision but not the entitlement bag; keep
        // the rest of the last activate/validate.
        let previous = m.current.clone();
        drop(m);
        let state = self.adopt(LicenseState {
            decision: decision_of(&claims),
            is_offline: false,
            ..previous.unwrap_or_else(|| LicenseState::bare(Decision::Valid, false))
        });
        self.announce_update(&claims);
        Ok(state)
    }

    /// Act on the heartbeat's signed `upd` hint: confirm it with a real update
    /// check and announce a release not announced yet. A failing check is
    /// swallowed — the heartbeat it rode in on has already succeeded.
    fn announce_update(&self, claims: &Claims) {
        if !self.has_listener(EventKind::UpdateAvailable)
            || claims.get("upd") != Some(&Value::Bool(true))
        {
            return;
        }
        let Ok(Some(info)) = self.check_for_update(&CheckForUpdateOptions::default()) else {
            return;
        };
        {
            let mut m = lock(&self.m);
            if info.release_seq <= m.announced_release_seq {
                return;
            }
            m.announced_release_seq = info.release_seq;
        }
        self.emit(&TalosEvent::UpdateAvailable(info));
    }

    // ---- floating seats ------------------------------------------------------

    /// Take (or renew) a seat. Returns the lease and, when it was adopted as
    /// the current one, the lease generation it was adopted under.
    ///
    /// `generation` is the one the caller is acting for — a renewal loop's —
    /// or `None` to take the current one. A release since then means the seat
    /// just taken is handed straight back rather than adopted.
    pub(crate) fn acquire_lease(
        &self,
        instance_id: &str,
        generation: Option<u64>,
    ) -> Result<(Lease, Option<u64>)> {
        let secret = self.require_activated()?;
        self.ensure_keyset()?;
        let generation = generation.unwrap_or_else(|| lock(&self.m).lease_generation);
        let nonce = new_nonce();
        let body = self.post(
            "/v1/client/leases",
            json!({
                "product_token": self.product_token,
                "fingerprint": self.fingerprint_json(),
                "activation_secret": secret,
                "instance_id": instance_id,
                "nonce": nonce,
            }),
        )?;
        let claims = {
            let m = lock(&self.m);
            verify_token_at(
                &self.license_keys(&m)?,
                "lease",
                &self.product_token,
                &nonce,
                str_field(&body, "lease_token"),
                self.now(),
            )?
        };
        // The signed grant must be for the instance and machine that asked, or
        // a server could hand every process one shared seat's token.
        if claims.get("inst").and_then(Value::as_str) != Some(instance_id)
            || claims.get("fph").and_then(Value::as_str) != Some(self.fp.composite.as_str())
        {
            return Err(Error::signature("lease token does not match this instance"));
        }
        // Seat facts come from the signed claims. The renewal budget is derived
        // from the token's own clock, so a wrong local clock cannot collapse
        // the renew loop; the envelope's hint is accepted only inside it.
        let expires_at = number(claims.get("exp")).unwrap_or(0);
        let server_now = number(claims.get("server_time")).unwrap_or_else(|| self.now());
        let budget = (expires_at - server_now).max(1);
        let hinted = number(body.get("renew_after_s")).unwrap_or(0);
        let lease = Lease {
            id: claims.get("lease").map(value_string).unwrap_or_default(),
            instance_id: instance_id.to_string(),
            expires_at,
            renew_after_seconds: if hinted > 0 && hinted <= budget {
                hinted
            } else {
                (budget / 3).max(1)
            },
            seats_in_use: number(claims.get("seats_in_use")).unwrap_or(0),
            max_seats: number(claims.get("max_seats")).unwrap_or(0),
        };
        let mut m = lock(&self.m);
        if m.lease_generation != generation {
            drop(m);
            let _ = self.release_instance(instance_id);
            return Ok((lease, None));
        }
        m.lease = Some(lease.clone());
        Ok((lease, Some(generation)))
    }

    fn release_instance(&self, instance_id: &str) -> Result<()> {
        let Some(secret) = lock(&self.m).activation_secret.clone() else {
            return Ok(());
        };
        self.request(
            "DELETE",
            "/v1/client/leases",
            json!({
                "product_token": self.product_token,
                "fingerprint": self.fingerprint_json(),
                "activation_secret": secret,
                "instance_id": instance_id,
            }),
        )?;
        Ok(())
    }

    // ---- updates -------------------------------------------------------------

    /// The `release_seq` no update may go at or below: the host's explicit
    /// value when given, else the persisted mark.
    fn release_floor(&self, explicit: Option<i64>) -> Option<i64> {
        explicit.or_else(|| {
            lock(&self.m)
                .binding
                .as_ref()
                .map(|b| b.release_seq_high_water)
                .filter(|seq| *seq > 0)
        })
    }

    fn check_for_update(&self, options: &CheckForUpdateOptions) -> Result<Option<UpdateInfo>> {
        let secret = self.require_activated()?;
        self.ensure_keyset()?;
        let floor = self.release_floor(options.current_release_seq);
        let body = self.post(
            "/v1/client/updates/check",
            json!({
                "product_token": self.product_token,
                "fingerprint": self.fingerprint_json(),
                "activation_secret": secret,
                "current_version": options.current_version.clone().or_else(|| self.app_version.clone()),
                "current_release_seq": floor,
                "channel": options.channel.clone().unwrap_or_else(|| self.channel()),
            }),
        )?;
        if body.get("update_available") != Some(&Value::Bool(true)) {
            return Ok(None);
        }
        let Some(manifest) = body.get("manifest").and_then(Value::as_str) else {
            return Err(Error::signature("update available but no manifest"));
        };
        // Trust only the signed manifest for version, seq and artifact facts.
        let m = {
            let st = lock(&self.m);
            verify_manifest_at(
                &self.release_keys(&st)?,
                &self.product_token,
                manifest,
                self.now(),
            )?
        };
        let release_seq = number(m.get("release_seq")).unwrap_or(0);
        if floor.is_some_and(|floor| release_seq <= floor) {
            // Checked here as well as on the server: the server's answer is the
            // one an attacker replaces.
            return Ok(None);
        }

        // The untrusted transport maps: which path serves which signed file.
        let mut downloads = HashMap::new();
        for d in array(body.get("artifacts")) {
            if let Some(path) = d.get("download_path").and_then(Value::as_str) {
                downloads.insert(key3(d, "platform", "arch", "kind"), path.to_string());
            }
        }
        let mut delta_paths = HashMap::new();
        for d in array(body.get("deltas")) {
            if let Some(path) = d.get("download_path").and_then(Value::as_str) {
                let key = format!(
                    "{}/{}",
                    key3(d, "platform", "arch", "from"),
                    text(d.get("target_kind"))
                );
                delta_paths.insert(key, path.to_string());
            }
        }

        let artifacts = array(m.get("artifacts"))
            .map(|a| {
                let mut artifact = UpdateArtifact {
                    platform: text(a.get("platform")),
                    arch: text(a.get("arch")),
                    kind: text(a.get("kind")),
                    filename: text(a.get("filename")),
                    size: a.get("size").and_then(Value::as_u64).unwrap_or(0),
                    sha256: text(a.get("sha256")),
                    download_path: None,
                };
                artifact.download_path =
                    downloads.get(&key3(a, "platform", "arch", "kind")).cloned();
                artifact
            })
            .collect();
        let deltas = array(m.get("deltas"))
            .map(|d| {
                let empty = Value::Object(Map::new());
                let t = d.get("target").unwrap_or(&empty);
                let target = UpdateDeltaTarget {
                    kind: text(t.get("kind")),
                    filename: text(t.get("filename")),
                    size: t.get("size").and_then(Value::as_u64).unwrap_or(0),
                    sha256: text(t.get("sha256")),
                };
                let key = format!("{}/{}", key3(d, "platform", "arch", "from"), target.kind);
                UpdateDelta {
                    platform: text(d.get("platform")),
                    arch: text(d.get("arch")),
                    from: text(d.get("from")),
                    from_seq: number(d.get("from_seq")).unwrap_or(0),
                    filename: text(d.get("filename")),
                    size: d.get("size").and_then(Value::as_u64).unwrap_or(0),
                    sha256: text(d.get("sha256")),
                    download_path: delta_paths.get(&key).cloned(),
                    target,
                }
            })
            .collect();

        Ok(Some(UpdateInfo {
            version: text(m.get("version")),
            release_seq,
            mandatory: m.get("mandatory") == Some(&Value::Bool(true)),
            notes_url: m
                .get("notes_url")
                .and_then(Value::as_str)
                .map(str::to_string),
            artifacts,
            deltas,
        }))
    }

    /// Note which release's bytes are on disk, so the next start can tell
    /// whether they were installed. Written after the hash check, never before:
    /// a corrupt or substituted file must not raise the floor past a good build.
    fn remember_downloaded(&self, info: &UpdateInfo) {
        let mut m = lock(&self.m);
        if info.release_seq <= m.binding.as_ref().map_or(0, |b| b.release_seq_high_water) {
            return;
        }
        let (version, seq) = (info.version.clone(), info.release_seq);
        self.persist(&mut m, |b| {
            b.pending_version = Some(version);
            b.pending_release_seq = seq;
        });
    }

    /// Fetch one file over the entitled download route and put it at `dest`
    /// only once its bytes match the signed size and hash.
    fn fetch_verified(
        &self,
        download_path: Option<&str>,
        size: u64,
        sha256: &str,
        dest: &Path,
        mut on_progress: Option<&mut dyn FnMut(DownloadProgress)>,
    ) -> Result<()> {
        let secret = self.require_activated()?;
        let path = download_path.ok_or_else(|| Error::usage("artifact has no download path"))?;
        let response = self
            .transport
            .send(HttpRequest {
                method: "GET",
                url: format!("{}{path}", self.server_url),
                headers: vec![
                    ("x-talos-product-token", self.product_token.clone()),
                    ("x-talos-activation-secret", secret),
                    ("x-talos-fingerprint", self.fp.composite.clone()),
                ],
                body: None,
                timeout: None,
            })
            .map_err(Error::Network)?;
        if !(200..300).contains(&response.status) {
            return Err(Error::Api {
                status: response.status,
                code: None,
            });
        }
        // The download host is untrusted and could stream an unbounded body.
        // The read is capped at the signed size whatever the header says.
        if response.content_length.is_some_and(|len| len > size) {
            return Err(Error::signature("artifact exceeds manifest size"));
        }

        let mut part = dest.as_os_str().to_owned();
        part.push(".talos-part");
        let part = PathBuf::from(part);
        let result = (|| -> Result<()> {
            let mut file = std::fs::File::create(&part)?;
            let mut hash = Sha256::new();
            let mut body = response.body;
            let mut buf = vec![0u8; 64 * 1024];
            let mut received = 0u64;
            loop {
                let n = body
                    .read(&mut buf)
                    .map_err(|e| Error::Network(e.to_string()))?;
                if n == 0 {
                    break;
                }
                received += n as u64;
                if received > size {
                    return Err(Error::signature("artifact exceeds manifest size"));
                }
                hash.update(&buf[..n]);
                file.write_all(&buf[..n])?;
                if let Some(f) = on_progress.as_mut() {
                    f(DownloadProgress {
                        bytes_received: received,
                        total_bytes: size,
                    });
                }
            }
            if hex(&hash.finalize()) != sha256.to_ascii_lowercase() {
                return Err(Error::signature(
                    "artifact hash mismatch (tampered or wrong bytes)",
                ));
            }
            file.sync_all()?;
            // Closed before the rename: Windows will not move an open file.
            drop(file);
            std::fs::rename(&part, dest)?;
            Ok(())
        })();
        if result.is_err() {
            // A part file left behind is one nobody who finds it can reason about.
            let _ = std::fs::remove_file(&part);
        }
        result
    }

    // ---- air-gapped ------------------------------------------------------------

    fn machine_key(&self, m: &mut Mutable) -> Result<MachineKey> {
        if let Some(b) = &m.binding {
            if let (Some(seed), Some(public_key)) = (&b.machine_key, &b.machine_public_key) {
                return Ok(MachineKey {
                    seed: seed.clone(),
                    public_key: public_key.clone(),
                });
            }
        }
        let key = generate_machine_key()?;
        let mut b = self.binding_base(m);
        b.machine_key = Some(key.seed.clone());
        b.machine_public_key = Some(key.public_key.clone());
        m.binding = Some(b);
        self.save(m);
        Ok(key)
    }

    fn create_offline_request(&self, license_key: Option<&str>) -> Result<SignedDoc> {
        let key = self.machine_key(&mut lock(&self.m))?;
        let payload = without_nulls(json!({
            "product_token": self.product_token,
            "license_key": license_key,
            "fingerprint": self.fingerprint_json(),
            "machine_pubkey": key.public_key,
            "nonce": new_nonce(),
            "hostname": self.reported_hostname(),
            "os": host::os_description(),
            "arch": host::arch(),
            "app_version": self.app_version,
            "sdk_version": sdk_id(),
            "created_at": self.now(),
        }));
        sign_machine_doc(&key.seed, REQUEST_DOMAIN, &payload)
    }

    fn load_offline_license(&self, file: &[u8]) -> Result<LicenseState> {
        let not_a_licence = || Error::usage("not a Talos offline licence file");
        let doc: Value = serde_json::from_slice(file).map_err(|_| not_a_licence())?;
        if doc.get("kind").and_then(Value::as_str) != Some(LICENSE_FILE_KIND) {
            return Err(not_a_licence());
        }
        let token = doc
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(not_a_licence)?;
        // The keyset travels inside the file because an air-gapped machine has
        // nowhere to fetch one. Adopted only if the pinned anchor signed it,
        // and only if it is not older than the one already held — an old file
        // must not bring back a key revoked since.
        if let Some(keyset) = doc.get("keyset").filter(|k| k.is_string()) {
            self.adopt_keyset(&mut lock(&self.m), keyset)?;
        }
        self.adopt_offline_token(token)
    }

    /// Verify the offline file against this machine and this clock, and adopt
    /// the verdict. Runs on load and on every `validate`.
    fn adopt_offline_token(&self, token: &str) -> Result<LicenseState> {
        let now = self.now();
        let mut m = lock(&self.m);
        // The nonce belonged to a request that may be weeks old — the server
        // is what needed it. `exp` is a verdict rather than an error, below.
        let claims = verify_cached_token_at(
            &self.license_keys(&m)?,
            "offline",
            &self.product_token,
            token,
            now,
        )?;

        // Both halves, exactly: the fingerprint stops the whole state directory
        // being copied to another computer, and the key stops the file alone
        // being worth anything.
        let mpk = claims.get("mpk").and_then(Value::as_str);
        let ours = m
            .binding
            .as_ref()
            .and_then(|b| b.machine_public_key.as_deref());
        if mpk.is_none()
            || mpk != ours
            || claims.get("fph").and_then(Value::as_str) != Some(self.fp.composite.as_str())
        {
            drop(m);
            return Ok(self.adopt(LicenseState::bare(Decision::MachineMismatch, true)));
        }

        // Two lower bounds on "now" this install has observed: one signed by
        // the server, one its own. A clock behind either has moved backwards.
        let (high_water, seen) = m
            .binding
            .as_ref()
            .map_or((0, 0), |b| (b.time_high_water, b.offline_seen));
        let mark = high_water.max(seen);
        if mark > 0 && now + CLOCK_SKEW_SECONDS < mark {
            drop(m);
            return Ok(self.adopt(LicenseState::bare(Decision::ClockTampered, true)));
        }

        let empty = Map::new();
        let lic = claims
            .get("lic")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        let features = lic
            .get("features")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let lic_exp = number(lic.get("lic_exp"));
        let exp = number(claims.get("exp"));

        // Kept even when today's answer is "expired": the file is this
        // machine's, and the app can say which file it is holding.
        if let Some(mid) = claims.get("mid").and_then(Value::as_str) {
            m.machine_id = Some(mid.to_string());
        }
        let mut b = self.binding_base(&m);
        if let Some(mid) = &m.machine_id {
            b.machine_id = mid.clone();
        }
        b.offline_token = Some(token.to_string());
        b.offline_seen = b.offline_seen.max(now);
        if let Some(k) = m.keyset_token.clone() {
            b.keyset = Some(k);
        }
        m.binding = Some(b);
        Self::advance_clock(&mut m, &claims);
        self.save(&m);
        drop(m);

        // The file's own horizon is the whole enforcement: no server will ever
        // be asked again. Distinct from `Expired`, which is the licence ending —
        // a new file versus a renewal.
        let decision = if exp.is_none_or(|e| now > e) {
            Decision::OfflineFileExpired
        } else if lic_exp.is_some_and(|e| now > e) {
            Decision::Expired
        } else {
            Decision::Valid
        };
        Ok(self.adopt(LicenseState {
            decision,
            features,
            license_expires_at: lic_exp,
            is_offline: true,
            revalidate_after: None,
            grace_until: exp,
        }))
    }

    fn create_offline_deactivation(&self) -> Result<SignedDoc> {
        let mut m = lock(&self.m);
        let (token, seed) = match m.binding.as_ref() {
            Some(b) => match (&b.offline_token, &b.machine_key, &b.machine_public_key) {
                (Some(t), Some(k), Some(_)) => (t.clone(), k.clone()),
                _ => return Err(Error::usage("no offline licence to hand back")),
            },
            None => return Err(Error::usage("no offline licence to hand back")),
        };
        // Read what the file says about itself before dropping it: the receipt
        // names the file and the machine.
        let claims = self
            .license_keys(&m)
            .and_then(|keys| {
                verify_cached_token_at(&keys, "offline", &self.product_token, &token, self.now())
            })
            .map_err(|_| Error::usage("the stored offline licence no longer verifies"))?;

        // Dropped first. The order is the point.
        if let Some(b) = m.binding.as_mut() {
            b.offline_token = None;
        }
        m.current = None;
        self.save(&m);
        drop(m);

        sign_machine_doc(
            &seed,
            RECEIPT_DOMAIN,
            &without_nulls(json!({
                "fid": claims.get("fid"),
                "mid": claims.get("mid"),
                "fph": self.fp.composite,
                "local_time": self.now(),
            })),
        )
    }

    // ---- HTTP ------------------------------------------------------------------

    fn post(&self, path: &str, body: Value) -> Result<Map<String, Value>> {
        self.request("POST", path, body)
    }

    fn request(&self, method: &'static str, path: &str, body: Value) -> Result<Map<String, Value>> {
        let body =
            serde_json::to_vec(&without_nulls(body)).expect("a JSON value always serialises");
        let response = self
            .transport
            .send(HttpRequest {
                method,
                url: format!("{}{path}", self.server_url),
                headers: vec![("content-type", "application/json".to_string())],
                body: Some(body),
                timeout: (!self.http_timeout.is_zero()).then_some(self.http_timeout),
            })
            // A timeout is a network failure, not a verdict, and must read as
            // one: `validate` turns it into the grace-period path.
            .map_err(Error::Network)?;
        let status = response.status;
        let mut text = Vec::new();
        response
            .body
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut text)
            .map_err(|e| Error::Network(e.to_string()))?;
        if !(200..300).contains(&status) {
            let code = serde_json::from_slice::<Value>(&text)
                .ok()
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string));
            // Every refusal Talos makes carries its reason as JSON — including
            // a self-hosted node's `503 node_degraded`, which is meant to stop
            // validation. A 5xx without one is the gateway in front of a
            // server that is down: Cloudflare's 52x page, IIS's 502.3, an
            // nginx 504. That is the absence of an answer, and the case grace
            // exists for, not a verdict that should take the app down.
            if status >= 500 && code.is_none() {
                return Err(Error::Network(format!(
                    "HTTP {status} from something other than the licensing server"
                )));
            }
            return Err(Error::Api { status, code });
        }
        if text.iter().all(u8::is_ascii_whitespace) {
            return Ok(Map::new());
        }
        match serde_json::from_slice::<Value>(&text) {
            Ok(Value::Object(o)) => Ok(o),
            _ => Err(Error::InvalidResponse(
                "the response is not a JSON object".into(),
            )),
        }
    }
}

/// Check that applying a patch produced the file the signed manifest said it
/// would. The patch was verified on the way in; this is the last link, and the
/// easiest to leave out — a patcher can fail halfway or apply to the wrong base,
/// and the result is a file nothing has vouched for. Streams the file; needs no
/// licence and no network.
pub fn verify_applied_update(path: impl AsRef<Path>, delta: &UpdateDelta) -> Result<()> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    let actual = hex(&hash.finalize());
    if actual != delta.target.sha256.to_ascii_lowercase() {
        return Err(Error::signature(format!(
            "applied update does not match the signed manifest: expected {}, got {actual}",
            delta.target.sha256
        )));
    }
    Ok(())
}

/// Which transition, if any, moving from `prev` to `next` amounts to. At most
/// one, and a repeat of the verdict already held is none at all.
fn transition_event(prev: Option<&LicenseState>, next: &LicenseState) -> Option<EventKind> {
    let prev_decision = prev.map(|p| &p.decision);
    match next.decision {
        Decision::ClockTampered => (prev_decision != Some(&Decision::ClockTampered))
            .then_some(EventKind::ClockTamperDetected),
        Decision::GraceExpired => (prev_decision != Some(&Decision::GraceExpired))
            .then_some(EventKind::GracePeriodExpired),
        Decision::Valid => {
            // Grace begins when a cached verdict is what keeps the app running,
            // not when the network drops: a failed call with nothing to fall
            // back on never reaches here.
            if !next.is_offline {
                return None;
            }
            let already = prev.is_some_and(|p| p.is_offline && p.is_valid());
            (!already).then_some(EventKind::GracePeriodStarted)
        }
        _ => (prev_decision != Some(&next.decision)).then_some(EventKind::LicenseInvalid),
    }
}

fn pick_artifact(artifacts: &[UpdateArtifact]) -> Option<UpdateArtifact> {
    let matches: Vec<&UpdateArtifact> = artifacts
        .iter()
        .filter(|a| a.platform == host::platform() && a.arch == host::arch())
        .collect();
    matches
        .iter()
        .find(|a| a.kind == "installer")
        .or(matches.first())
        .map(|a| (*a).clone())
}

fn decision_of(claims: &Claims) -> Decision {
    Decision::parse(
        claims
            .get("decision")
            .and_then(Value::as_str)
            .unwrap_or("invalid"),
    )
}

fn str_field<'a>(o: &'a Map<String, Value>, key: &str) -> &'a str {
    o.get(key).and_then(Value::as_str).unwrap_or("")
}

fn text(v: Option<&Value>) -> String {
    v.map(value_string).unwrap_or_default()
}

fn value_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn array(v: Option<&Value>) -> impl Iterator<Item = &Value> {
    v.and_then(Value::as_array).into_iter().flatten()
}

fn key3(o: &Value, a: &str, b: &str, c: &str) -> String {
    format!("{}/{}/{}", text(o.get(a)), text(o.get(b)), text(o.get(c)))
}

/// Drop top-level nulls, as JSON.stringify drops `undefined`: an absent field
/// leaves the server's stored value alone, where a null might not.
fn without_nulls(v: Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(o.into_iter().filter(|(_, v)| !v.is_null()).collect()),
        other => other,
    }
}

fn new_nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("the OS random source is available");
    B64URL.encode(bytes)
}

/// Lock, recovering from poisoning: a panic elsewhere must not take licensing
/// down with it, and every critical section here leaves the state consistent.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(feature = "ureq")]
fn default_transport() -> Result<Arc<dyn Transport>> {
    Ok(Arc::new(crate::transport::UreqTransport::new()))
}

#[cfg(not(feature = "ureq"))]
fn default_transport() -> Result<Arc<dyn Transport>> {
    Err(Error::usage(
        "no HTTP transport: enable the `ureq` feature or set TalosOptions::transport",
    ))
}
