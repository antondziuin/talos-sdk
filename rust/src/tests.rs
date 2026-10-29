//! The client against a stand-in server that signs real tokens.
//!
//! The stand-in mints Talos-compact tokens with keys generated here and echoes
//! the client's nonce, so every path below runs the same verification a live
//! answer does. What it adds over a live server is control: the network can
//! drop, the clock can move, and an answer can be altered on the way back.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::compact::{B64, B64URL};
use crate::fingerprint::hex;
use crate::transport::{HttpRequest, HttpResponse, Transport};
use crate::*;

const TOKEN: &str = "tpt_rust_unit";
const T0: i64 = 1_800_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(k: &SigningKey) -> String {
    B64.encode(k.verifying_key().as_bytes())
}

fn mint(k: &SigningKey, typ: &str, claims: &Value) -> String {
    let prefix = format!(
        "talos.1.{typ}.{}",
        B64URL.encode(serde_json::to_vec(claims).unwrap())
    );
    let sig = k.sign(prefix.as_bytes());
    format!("{prefix}.{}", B64URL.encode(sig.to_bytes()))
}

/// What the stand-in serves for an update.
#[derive(Clone)]
struct Release {
    version: String,
    seq: i64,
    bytes: Vec<u8>,
    /// Served instead of `bytes`, to model a substituted download.
    served: Option<Vec<u8>>,
}

struct State {
    online: bool,
    decision: String,
    /// A status to answer every licensing call with.
    refuse: Option<(u16, &'static str)>,
    /// Rewrites the body of each answer, as a meddling proxy would.
    alter: Option<Box<dyn Fn(String) -> String + Send>>,
    calls: Vec<String>,
    heartbeat_interval: i64,
    upd: bool,
    release: Option<Release>,
    lease_owner: Option<String>,
    /// Signs leases for another instance than the one asking.
    lease_wrong_instance: bool,
    /// Names another machine in every token, as a relay would get them.
    fph_override: Option<String>,
    /// Answers every licensing call with this status and an HTML page, as a
    /// gateway in front of a dead server does.
    gateway: Option<u16>,
    /// Served instead of the current keyset, as a recording would be.
    keyset_replay: Option<String>,
    renew_after: i64,
    grace_hours: i64,
    lic_exp: Option<i64>,
}

struct Server {
    clock: Arc<AtomicI64>,
    anchor: SigningKey,
    license: SigningKey,
    release: SigningKey,
    state: Mutex<State>,
}

impl Server {
    fn new(clock: Arc<AtomicI64>) -> Arc<Self> {
        Arc::new(Server {
            clock,
            anchor: key(1),
            license: key(2),
            release: key(3),
            state: Mutex::new(State {
                online: true,
                decision: "valid".into(),
                refuse: None,
                alter: None,
                calls: Vec::new(),
                heartbeat_interval: 900,
                upd: false,
                release: None,
                lease_owner: None,
                lease_wrong_instance: false,
                fph_override: None,
                gateway: None,
                keyset_replay: None,
                renew_after: 200,
                grace_hours: 72,
                lic_exp: None,
            }),
        })
    }

    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    fn calls(&self, path: &str) -> usize {
        self.with(|s| s.calls.iter().filter(|c| c.as_str() == path).count())
    }

    fn keyset(&self) -> String {
        mint(
            &self.anchor,
            "keyset",
            &json!({
                "v": 1, "typ": "keyset", "aud": TOKEN, "iat": self.now(),
                "keys": [
                    {"kid": "k1", "pk": pk(&self.license), "purpose": "license", "status": "active"},
                    {"kid": "r1", "pk": pk(&self.release), "purpose": "release", "status": "active"},
                ],
            }),
        )
    }

    fn base(&self, typ: &str, req: &Value) -> serde_json::Map<String, Value> {
        let now = self.now();
        let mut c = serde_json::Map::new();
        c.insert("v".into(), json!(1));
        c.insert("typ".into(), json!(typ));
        c.insert("aud".into(), json!(TOKEN));
        c.insert("iat".into(), json!(now));
        c.insert("nbf".into(), json!(now));
        c.insert("exp".into(), json!(now + 300));
        c.insert("non".into(), req["nonce"].clone());
        c.insert("fph".into(), self.fph(req));
        c
    }

    fn fph(&self, req: &Value) -> Value {
        self.with(|s| s.fph_override.clone())
            .map_or_else(|| req["fingerprint"]["composite"].clone(), Value::from)
    }

    /// An anchor-signed keyset listing only `license`, issued at `iat`.
    fn keyset_at(&self, iat: i64, license: &SigningKey) -> String {
        mint(
            &self.anchor,
            "keyset",
            &json!({
                "v": 1, "typ": "keyset", "aud": TOKEN, "iat": iat,
                "keys": [{"kid": "old", "pk": pk(license), "purpose": "license", "status": "active"}],
            }),
        )
    }

    fn answer(&self, path: &str, req: &Value) -> (u16, Value) {
        let (decision, interval, upd, grace_hours, lic_exp) = self.with(|s| {
            (
                s.decision.clone(),
                s.heartbeat_interval,
                s.upd,
                s.grace_hours,
                s.lic_exp,
            )
        });
        let now = self.now();
        match path {
            "/v1/client/keyset" => {
                let keyset = self
                    .with(|s| s.keyset_replay.clone())
                    .unwrap_or_else(|| self.keyset());
                (200, json!({ "keyset": keyset }))
            }
            "/v1/client/activate" => {
                let mut c = self.base("activation", req);
                c.insert(
                    "lic".into(),
                    json!({"features": {"pro": true, "seats": 5}, "lic_exp": lic_exp, "grace_h": grace_hours, "reval_h": 24, "fph": self.fph(req)}),
                );
                (
                    200,
                    json!({
                        "activation_token": mint(&self.license, "activation", &Value::Object(c)),
                        "activation_secret": "secret-1",
                        "machine_id": "machine-1",
                        "keyset": self.keyset(),
                    }),
                )
            }
            "/v1/client/validate" => {
                let mut c = self.base("validation", req);
                c.insert("decision".into(), json!(decision));
                c.insert("server_time".into(), json!(now));
                c.insert("reval_after".into(), json!(now + 24 * 3600));
                c.insert("grace_until".into(), json!(now + grace_hours * 3600));
                c.insert(
                    "lic".into(),
                    json!({"features": {"pro": true, "seats": 5}, "lic_exp": lic_exp}),
                );
                (
                    200,
                    json!({"validation_token": mint(&self.license, "validation", &Value::Object(c))}),
                )
            }
            "/v1/client/heartbeat" => {
                let mut c = self.base("heartbeat", req);
                c.insert("decision".into(), json!(decision));
                c.insert("server_time".into(), json!(now));
                c.insert("heartbeat_interval_s".into(), json!(interval));
                if upd && req.get("update_channel").is_some() {
                    c.insert("upd".into(), json!(true));
                }
                // The envelope says something else on purpose: only the signed
                // claim may set the cadence.
                (
                    200,
                    json!({"heartbeat_token": mint(&self.license, "heartbeat", &Value::Object(c)), "heartbeat_interval_s": 1}),
                )
            }
            "/v1/client/deactivate" => (200, json!({})),
            "/v1/client/leases" => {
                let inst = req["instance_id"].as_str().unwrap_or("").to_string();
                let wrong = self.with(|s| s.lease_wrong_instance);
                let taken = self.with(|s| match &s.lease_owner {
                    Some(owner) if *owner != inst => true,
                    _ => {
                        s.lease_owner = Some(inst.clone());
                        false
                    }
                });
                if taken {
                    return (409, json!({"error": "seat_limit_reached"}));
                }
                let mut c = self.base("lease", req);
                c.insert(
                    "inst".into(),
                    json!(if wrong { "someone-else" } else { inst.as_str() }),
                );
                c.insert("lease".into(), json!("lease-1"));
                c.insert("server_time".into(), json!(now));
                c.insert("exp".into(), json!(now + 600));
                c.insert("seats_in_use".into(), json!(1));
                c.insert("max_seats".into(), json!(1));
                (
                    200,
                    json!({"lease_token": mint(&self.license, "lease", &Value::Object(c)), "renew_after_s": self.with(|s| s.renew_after)}),
                )
            }
            "/v1/client/updates/check" => {
                let Some(r) = self.with(|s| s.release.clone()) else {
                    return (200, json!({"update_available": false}));
                };
                let manifest = mint(
                    &self.release,
                    "manifest",
                    &json!({
                        "v": 1, "typ": "manifest", "aud": TOKEN, "version": r.version, "release_seq": r.seq,
                        "mandatory": false, "notes_url": null, "not_before": null,
                        "artifacts": [{
                            "platform": host::platform(), "arch": host::arch(), "kind": "installer",
                            "filename": "app.bin", "size": r.bytes.len(), "sha256": hex(&Sha256::digest(&r.bytes)),
                        }],
                        "deltas": [],
                    }),
                );
                (
                    200,
                    json!({
                        "update_available": true,
                        "manifest": manifest,
                        "artifacts": [{"platform": host::platform(), "arch": host::arch(), "kind": "installer", "download_path": "/dl/app.bin"}],
                    }),
                )
            }
            _ => (404, json!({"error": "not_found"})),
        }
    }

    /// Issue an air-gapped licence file for a request document, as the portal
    /// does after verifying the machine's signature.
    fn issue_offline(
        &self,
        request: &SignedDoc,
        horizon: i64,
        fph_override: Option<&str>,
    ) -> Vec<u8> {
        self.issue_offline_with(request, horizon, fph_override, |_| {})
    }

    fn issue_offline_with(
        &self,
        request: &SignedDoc,
        horizon: i64,
        fph_override: Option<&str>,
        tweak: impl FnOnce(&mut Value),
    ) -> Vec<u8> {
        let payload: Value = serde_json::from_slice(&B64URL.decode(&request.req).unwrap()).unwrap();
        let now = self.now();
        let mut claims = json!({
            "v": 1, "typ": "offline", "aud": TOKEN, "iat": now, "nbf": now, "exp": now + horizon,
            "server_time": now, "decision": "valid", "fid": "file-1", "mid": "machine-air",
            "fph": fph_override.map_or(payload["fingerprint"]["composite"].clone(), |f| json!(f)),
            "mpk": payload["machine_pubkey"],
            "lic": {"features": {"pro": true}, "lic_exp": null},
        });
        tweak(&mut claims);
        let token = mint(&self.license, "offline", &claims);
        serde_json::to_vec(
            &json!({"kind": LICENSE_FILE_KIND, "token": token, "keyset": self.keyset()}),
        )
        .unwrap()
    }

    fn issue_portable(&self, tweak: impl FnOnce(&mut Value)) -> Vec<u8> {
        let now = self.now();
        let mut claims = json!({
            "v": 1, "typ": "offline", "aud": TOKEN, "iat": now, "nbf": now,
            "exp": null, "perpetual": true, "binding": "portable",
            "server_time": now, "decision": "valid", "fid": "portable-file-1",
            "sub": "portable-licence-1", "lic": {"features": {"pro": true}, "lic_exp": null},
        });
        tweak(&mut claims);
        serde_json::to_vec(&json!({
            "kind": LICENSE_FILE_KIND,
            "token": mint(&self.license, "offline", &claims),
            "keyset": self.keyset(),
        }))
        .unwrap()
    }
}

impl Transport for Server {
    fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, String> {
        let path = request
            .url
            .trim_start_matches("http://talos.test")
            .to_string();
        let online = self.with(|s| {
            s.calls.push(path.clone());
            s.online
        });
        if !online {
            return Err("connection refused".into());
        }
        if request.method == "GET" {
            let r = self
                .with(|s| s.release.clone())
                .expect("a release to download");
            return Ok(HttpResponse::from_bytes(200, r.served.unwrap_or(r.bytes)));
        }
        if let Some(status) = self.with(|s| s.gateway) {
            return Ok(HttpResponse::from_bytes(
                status,
                "<html><body>502 Bad Gateway</body></html>",
            ));
        }
        if let Some((status, code)) = self.with(|s| s.refuse) {
            return Ok(HttpResponse::from_bytes(
                status,
                json!({"error": code}).to_string(),
            ));
        }
        let req: Value = serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).unwrap();
        let (status, body) = self.answer(&path, &req);
        let mut body = body.to_string();
        if let Some(alter) = &self.state.lock().unwrap().alter {
            body = alter(body);
        }
        Ok(HttpResponse::from_bytes(status, body))
    }
}

struct Fixture {
    server: Arc<Server>,
    clock: Arc<AtomicI64>,
    state_path: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let clock = Arc::new(AtomicI64::new(T0));
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        Fixture {
            server: Server::new(Arc::clone(&clock)),
            clock,
            state_path: std::env::temp_dir()
                .join(format!("talos-rust-unit-{}", hex(&nonce)))
                .join("state.bin"),
        }
    }

    fn options(&self) -> TalosOptions {
        TalosOptions {
            product_token: TOKEN.into(),
            server_url: "http://talos.test/".into(),
            anchor_public_key: Some(pk(&self.server.anchor)),
            app_version: Some("1.0.0".into()),
            state_path: Some(self.state_path.clone()),
            transport: Some(Arc::clone(&self.server) as Arc<dyn Transport>),
            ..Default::default()
        }
    }

    fn client(&self) -> TalosClient {
        self.client_with(self.options())
    }

    fn client_with(&self, options: TalosOptions) -> TalosClient {
        let clock = Arc::clone(&self.clock);
        TalosClient::with_clock(options, Box::new(move || clock.load(Ordering::SeqCst))).unwrap()
    }

    fn advance(&self, secs: i64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }

    fn offline(&self, offline: bool) {
        self.server.with(|s| s.online = !offline);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(dir) = self.state_path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn recorder(client: &TalosClient, kind: EventKind) -> Arc<Mutex<Vec<TalosEvent>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let _ = client.on(kind, move |e| sink.lock().unwrap().push(e.clone()));
    seen
}

#[test]
fn an_anchor_only_client_activates_through_the_keyset_and_keeps_the_binding() {
    let f = Fixture::new();
    let talos = f.client();
    assert!(!talos.is_activated());

    let state = talos.activate("KEY-1").unwrap();
    assert!(state.is_valid());
    assert!(!state.is_offline);
    assert!(talos.is_feature_enabled("pro"));
    assert_eq!(state.entitlement_i64("seats"), Some(5));
    assert_eq!(
        state.grace_until,
        Some(T0 + 72 * 3600),
        "activation's grace_h is read beside its iat"
    );
    assert_eq!(talos.machine_id().as_deref(), Some("machine-1"));

    // The next launch: nothing to ask the user for.
    let restarted = f.client();
    assert!(restarted.is_activated());
    assert_eq!(restarted.machine_id().as_deref(), Some("machine-1"));
    assert_eq!(restarted.validate().unwrap().decision, Decision::Valid);
}

#[test]
fn activating_again_with_the_same_key_validates_instead() {
    let f = Fixture::new();
    f.client().activate("KEY-1").unwrap();
    let again = f.client();
    assert!(again.activate("KEY-1").unwrap().is_valid());
    assert_eq!(
        f.server.calls("/v1/client/activate"),
        1,
        "a second activation would rotate the secret"
    );

    // A different key is a real activation.
    again.activate("KEY-2").unwrap();
    assert_eq!(f.server.calls("/v1/client/activate"), 2);
}

#[test]
fn the_licence_key_is_not_kept_on_disk() {
    let f = Fixture::new();
    f.client().activate("SECRET-LICENCE-KEY").unwrap();
    let raw = std::fs::read(&f.state_path).unwrap();
    assert!(!raw.windows(18).any(|w| w == b"SECRET-LICENCE-KEY"));
    assert!(raw.starts_with(b"TLS1"));
}

#[test]
fn a_dead_network_falls_back_to_the_cached_verdict_once() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    talos.validate().unwrap();
    let started = recorder(&talos, EventKind::GracePeriodStarted);

    f.offline(true);
    f.advance(3600);
    let state = talos.validate().unwrap();
    assert!(state.is_valid());
    assert!(state.is_offline);
    assert_eq!(state.features["pro"], json!(true));
    talos.validate().unwrap();
    assert_eq!(
        started.lock().unwrap().len(),
        1,
        "a transition, not a level"
    );

    // And from a cold start, with no network at all: the cached keyset is
    // what verifies the cached verdict.
    let cold = f.client();
    let state = cold.validate().unwrap();
    assert!(state.is_valid() && state.is_offline);
}

#[test]
fn an_answer_from_the_server_is_never_masked_by_the_cache() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    talos.validate().unwrap();
    f.server.with(|s| s.refuse = Some((403, "license_revoked")));
    let err = talos.validate().unwrap_err();
    assert_eq!(err.status(), Some(403));
    assert_eq!(err.code(), Some("license_revoked"));
}

#[test]
fn a_negative_signed_verdict_is_announced_once_per_reason() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    let invalid = recorder(&talos, EventKind::LicenseInvalid);
    f.server.with(|s| s.decision = "suspended".into());
    assert_eq!(talos.validate().unwrap().decision, Decision::Suspended);
    talos.heartbeat().unwrap();
    f.server.with(|s| s.decision = "expired".into());
    talos.validate().unwrap();
    let seen = invalid.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].state().unwrap().decision, Decision::Expired);
}

#[test]
fn grace_runs_out() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    talos.validate().unwrap();
    let expired = recorder(&talos, EventKind::GracePeriodExpired);
    f.offline(true);
    f.advance(73 * 3600);
    assert_eq!(talos.validate().unwrap().decision, Decision::GraceExpired);
    assert_eq!(expired.lock().unwrap().len(), 1);
}

#[test]
fn a_clock_wound_back_is_tampering_not_expiry() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    f.advance(10 * 3600);
    talos.validate().unwrap();
    let tamper = recorder(&talos, EventKind::ClockTamperDetected);
    f.offline(true);
    f.advance(-5 * 3600);
    assert_eq!(talos.validate().unwrap().decision, Decision::ClockTampered);
    assert_eq!(tamper.lock().unwrap().len(), 1);
}

#[test]
fn an_altered_answer_counts_as_silence_and_never_as_valid() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();

    // With no cached verdict there is nothing to fall back on: the signature
    // failure is what the caller sees.
    f.server.with(|s| {
        s.alter = Some(Box::new(|body: String| {
            let v: Value = serde_json::from_str(&body).unwrap();
            let Some(t) = v.get("validation_token").and_then(Value::as_str) else {
                return body;
            };
            let (head, sig) = t.rsplit_once('.').unwrap();
            let flipped = if sig.starts_with('A') { "B" } else { "A" };
            json!({"validation_token": format!("{head}.{flipped}{}", &sig[1..])}).to_string()
        }))
    });
    assert!(matches!(talos.validate(), Err(Error::Signature(_))));

    // With one, the forged answer reads as an unreachable server.
    f.server.with(|s| s.alter = None);
    talos.validate().unwrap();
    f.server.with(|s| {
        s.alter = Some(Box::new(|body: String| {
            body.replace(
                "\"validation_token\":\"talos.1.validation.",
                "\"validation_token\":\"talos.1.validation.x",
            )
        }))
    });
    let state = talos.validate().unwrap();
    assert!(
        state.is_offline,
        "a forged answer must not land as a live verdict"
    );
}

#[test]
fn a_replayed_answer_is_refused_by_its_nonce() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    assert!(!talos.validate().unwrap().is_offline);
    let captured: Arc<Mutex<Option<String>>> = Arc::default();
    let tape = Arc::clone(&captured);
    f.server.with(|s| {
        s.alter = Some(Box::new(move |body: String| {
            tape.lock().unwrap().get_or_insert(body).clone()
        }))
    });
    talos.validate().unwrap();
    let replayed = talos.validate().unwrap();
    assert!(replayed.is_offline);
}

#[test]
fn a_state_file_copied_to_another_machine_licenses_nothing_offline() {
    let f = Fixture::new();
    f.client().activate("KEY-1").unwrap();
    f.client().validate().unwrap();
    f.offline(true);
    // Same file, same product, a machine that reports different hardware. The
    // file still decrypts — the stable id it is keyed by did not change — but
    // the cached verdict names the other machine's fingerprint.
    let mut options = f.options();
    options
        .fingerprint_components
        .insert("cpu".into(), "a different machine".into());
    let other = f.client_with(options);
    assert!(other.is_activated());
    assert!(matches!(other.validate(), Err(Error::Network(_))));
}

#[test]
fn the_heartbeat_cadence_comes_from_the_signed_claims() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    assert_eq!(talos.heartbeat_interval_seconds(), None);
    let state = talos.heartbeat().unwrap();
    assert!(state.is_valid());
    assert_eq!(
        state.features["pro"],
        json!(true),
        "a heartbeat keeps the last entitlement bag"
    );
    assert_eq!(talos.heartbeat_interval_seconds(), Some(900));
}

#[test]
fn a_heartbeat_hint_announces_a_release_once() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    f.server.with(|s| {
        s.upd = true;
        s.release = Some(Release {
            version: "1.1.0".into(),
            seq: 5,
            bytes: b"build".to_vec(),
            served: None,
        });
    });
    talos.heartbeat().unwrap();
    assert_eq!(
        f.server.calls("/v1/client/updates/check"),
        0,
        "nobody asked, so nothing is checked"
    );

    let updates = recorder(&talos, EventKind::UpdateAvailable);
    talos.heartbeat().unwrap();
    talos.heartbeat().unwrap();
    let seen = updates.lock().unwrap();
    assert_eq!(seen.len(), 1);
    match &seen[0] {
        TalosEvent::UpdateAvailable(info) => assert_eq!(info.version, "1.1.0"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn a_listener_that_panics_does_not_change_the_verdict() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    let _ = talos.on(EventKind::LicenseInvalid, |_| panic!("broken banner"));
    f.server.with(|s| s.decision = "revoked".into());
    assert_eq!(talos.validate().unwrap().decision, Decision::Revoked);
}

#[test]
fn unsubscribing_stops_delivery() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    let seen = Arc::new(Mutex::new(0));
    let sink = Arc::clone(&seen);
    let sub = talos.on(EventKind::LicenseInvalid, move |_| {
        *sink.lock().unwrap() += 1
    });
    sub.unsubscribe();
    f.server.with(|s| s.decision = "revoked".into());
    talos.validate().unwrap();
    assert_eq!(*seen.lock().unwrap(), 0);
}

#[test]
fn updates_are_verified_downloaded_and_never_downgraded() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    assert_eq!(
        talos
            .check_for_update(CheckForUpdateOptions::default())
            .unwrap(),
        None
    );

    let bytes = b"the new build".to_vec();
    f.server.with(|s| {
        s.release = Some(Release {
            version: "1.1.0".into(),
            seq: 5,
            bytes: bytes.clone(),
            served: None,
        })
    });
    let info = talos
        .check_for_update(CheckForUpdateOptions::default())
        .unwrap()
        .unwrap();
    assert_eq!((info.version.as_str(), info.release_seq), ("1.1.0", 5));

    let dir = f.state_path.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("app.bin");
    let mut progress = Vec::new();
    let mut on_progress = |p: DownloadProgress| progress.push(p);
    let got = talos
        .download_update(&info, &dest, None, Some(&mut on_progress))
        .unwrap();
    assert_eq!(got.filename, "app.bin");
    assert_eq!(std::fs::read(&dest).unwrap(), bytes);
    assert_eq!(progress.last().unwrap().total_bytes, bytes.len() as u64);

    // A substituted download leaves what was there, and no part file.
    f.server
        .with(|s| s.release.as_mut().unwrap().served = Some(b"the evil build".to_vec()));
    let err = talos.download_update(&info, &dest, None, None).unwrap_err();
    assert!(matches!(err, Error::Signature(_)), "{err}");
    assert_eq!(std::fs::read(&dest).unwrap(), bytes);
    assert!(!dir.join("app.bin.talos-part").exists());

    // An oversized one is cut off at the signed size.
    f.server
        .with(|s| s.release.as_mut().unwrap().served = Some(vec![0u8; 1000]));
    assert!(matches!(
        talos.download_update(&info, &dest, None, None),
        Err(Error::Signature(_))
    ));

    // The next start runs 1.1.0: the mark moves up, and 1.1.0 is no update.
    let mut options = f.options();
    options.app_version = Some("1.1.0".into());
    let updated = f.client_with(options);
    assert_eq!(
        updated
            .check_for_update(CheckForUpdateOptions::default())
            .unwrap(),
        None
    );
    // A rollback offered later is refused too.
    f.server.with(|s| {
        s.release = Some(Release {
            version: "1.0.5".into(),
            seq: 4,
            bytes: b"old".to_vec(),
            served: None,
        })
    });
    assert_eq!(
        updated
            .check_for_update(CheckForUpdateOptions::default())
            .unwrap(),
        None
    );
}

#[test]
fn an_applied_patch_is_checked_against_the_manifest() {
    let f = Fixture::new();
    let dir = f.state_path.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("rebuilt.bin");
    std::fs::write(&file, b"rebuilt").unwrap();
    let delta = UpdateDelta {
        platform: "linux".into(),
        arch: "x64".into(),
        from: "1.0.0".into(),
        from_seq: 1,
        filename: "p".into(),
        size: 1,
        sha256: String::new(),
        target: UpdateDeltaTarget {
            kind: "installer".into(),
            filename: "rebuilt.bin".into(),
            size: 7,
            sha256: hex(&Sha256::digest(b"rebuilt")),
        },
        download_path: None,
    };
    verify_applied_update(&file, &delta).unwrap();
    std::fs::write(&file, b"half-applied").unwrap();
    assert!(matches!(
        verify_applied_update(&file, &delta),
        Err(Error::Signature(_))
    ));
}

#[test]
fn a_floating_seat_is_signed_for_this_instance() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    let lease = talos
        .acquire_lease(
            AcquireLeaseOptions::new()
                .instance_id("inst-1")
                .auto_renew(false),
        )
        .unwrap();
    assert_eq!((lease.seats_in_use, lease.max_seats), (1, 1));
    assert_eq!(lease.renew_after_seconds, 200);
    assert_eq!(talos.current_lease(), Some(lease));

    let busy = talos
        .acquire_lease(
            AcquireLeaseOptions::new()
                .instance_id("inst-2")
                .auto_renew(false),
        )
        .unwrap_err();
    assert_eq!(busy.code(), Some("seat_limit_reached"));

    talos.release_lease().unwrap();
    assert_eq!(talos.current_lease(), None);

    f.server.with(|s| {
        s.lease_owner = None;
        s.lease_wrong_instance = true;
    });
    assert!(matches!(
        talos.acquire_lease(AcquireLeaseOptions::new().auto_renew(false)),
        Err(Error::Signature(_))
    ));
}

#[test]
fn an_air_gapped_machine_licenses_itself_from_a_file() {
    let f = Fixture::new();
    f.offline(true);
    let talos = f.client();
    let request = talos.create_offline_request(None).unwrap();
    assert_eq!(request.kind, REQUEST_DOMAIN);
    // Twice is one identity.
    let again = talos.create_offline_request(None).unwrap();
    let pubkey = |d: &SignedDoc| {
        let v: Value = serde_json::from_slice(&B64URL.decode(&d.req).unwrap()).unwrap();
        v["machine_pubkey"].as_str().unwrap().to_string()
    };
    assert_eq!(pubkey(&request), pubkey(&again));

    let file = f.server.issue_offline(&request, 30 * 86400, None);
    let state = talos.load_offline_license(&file).unwrap();
    assert!(state.is_valid() && state.is_offline);
    assert!(talos.is_activated());

    // A later start needs nothing.
    let restarted = f.client();
    assert!(restarted.is_activated());
    assert!(restarted.validate().unwrap().is_valid());

    // Ten days of use, then a clock wound back five: the install's own mark
    // is what notices, since an air-gapped machine sees one server time ever.
    f.advance(10 * 86400);
    assert!(restarted.validate().unwrap().is_valid());
    f.advance(-5 * 86400);
    assert_eq!(
        restarted.validate().unwrap().decision,
        Decision::ClockTampered
    );

    // The file's horizon is the whole enforcement.
    f.advance(26 * 86400);
    assert_eq!(
        restarted.validate().unwrap().decision,
        Decision::OfflineFileExpired
    );

    // Handing the seat back drops the licence before the receipt exists.
    let receipt = restarted.create_offline_deactivation().unwrap();
    assert_eq!(receipt.kind, RECEIPT_DOMAIN);
    assert!(!restarted.is_activated());
    assert!(!f.client().is_activated());
    assert!(restarted.create_offline_deactivation().is_err());
}

#[test]
fn perpetual_offline_files_survive_decades_and_restarts_without_network() {
    let f = Fixture::new();
    f.offline(true);
    let talos = f.client();
    let request = talos.create_offline_request(None).unwrap();
    let file = f.server.issue_offline_with(&request, 86400, None, |c| {
        c["exp"] = Value::Null;
        c["perpetual"] = json!(true);
    });
    let state = talos.load_offline_license(&file).unwrap();
    assert!(state.is_valid() && state.is_offline);
    assert_eq!(state.grace_until, None);
    assert_eq!(state.license_expires_at, None);

    f.advance(80 * 365 * 86400);
    let restarted = f.client();
    let state = restarted.validate().unwrap();
    assert!(state.is_valid() && state.is_offline);
    assert_eq!(state.grace_until, None);
    assert!(state.is_feature_enabled("pro"));
    assert!(f.server.with(|s| s.calls.is_empty()));
}

#[test]
fn invalid_perpetual_offline_files_fail_closed() {
    for problem in [
        "missing_flag",
        "missing_exp",
        "malformed_exp",
        "malformed_flag",
        "business_expiry",
        "missing_business_expiry",
        "bounded_expired",
    ] {
        let f = Fixture::new();
        let talos = f.client();
        let request = talos.create_offline_request(None).unwrap();
        let file = f.server.issue_offline_with(&request, 86400, None, |c| {
            c["exp"] = Value::Null;
            c["perpetual"] = json!(true);
            match problem {
                "missing_flag" => {
                    c.as_object_mut().unwrap().remove("perpetual");
                }
                "missing_exp" => {
                    c.as_object_mut().unwrap().remove("exp");
                }
                "malformed_exp" => c["exp"] = json!("never"),
                "malformed_flag" => c["perpetual"] = json!("true"),
                "business_expiry" => c["lic"]["lic_exp"] = json!(T0 + 86400),
                "missing_business_expiry" => {
                    c["lic"].as_object_mut().unwrap().remove("lic_exp");
                }
                "bounded_expired" => c["exp"] = json!(T0 - 1),
                _ => unreachable!(),
            }
        });
        assert_eq!(
            talos.load_offline_license(&file).unwrap().decision,
            Decision::OfflineFileExpired,
            "{problem}"
        );
    }
}

#[test]
fn portable_offline_file_works_on_different_machines_without_requests() {
    let first = Fixture::new();
    let second = Fixture::new();
    first.offline(true);
    second.offline(true);
    let file = first.server.issue_portable(|_| {});
    for (f, machine) in [(&first, "hardware-a"), (&second, "hardware-b")] {
        let mut options = f.options();
        options
            .fingerprint_components
            .insert("machine_guid".into(), machine.into());
        options
            .fingerprint_components
            .insert("hostname".into(), machine.into());
        let talos = f.client_with(options.clone());
        let state = talos.load_offline_license(&file).unwrap();
        assert!(state.is_valid() && state.is_offline);
        assert_eq!(state.grace_until, None);
        assert_eq!(talos.machine_id(), None);
        assert!(talos.is_activated());
        assert!(matches!(talos.create_offline_deactivation(),
            Err(Error::Usage(message)) if message.contains("portable")));

        f.advance(80 * 365 * 86400);
        let restarted = f.client_with(options);
        let state = restarted.validate().unwrap();
        assert!(state.is_valid() && state.is_offline);
        assert!(state.is_feature_enabled("pro"));
        assert!(f.server.with(|s| s.calls.is_empty()));
    }
}

#[test]
fn valid_offline_import_replaces_an_online_activation_durably() {
    for portable in [true, false] {
        let f = Fixture::new();
        let talos = f.client();
        assert!(talos.activate("KEY-1").unwrap().is_valid());
        talos
            .acquire_lease(AcquireLeaseOptions::new().auto_renew(false))
            .unwrap();
        assert!(talos.current_lease().is_some());
        let file = if portable {
            f.server.issue_portable(|_| {})
        } else {
            let request = talos.create_offline_request(None).unwrap();
            f.server.issue_offline(&request, 86400, None)
        };
        let calls = f.server.with(|s| s.calls.len());
        assert!(talos.load_offline_license(&file).unwrap().is_valid());
        assert!(talos.current_lease().is_none());
        f.offline(true);
        assert!(talos.validate().unwrap().is_valid());
        assert!(f.client().validate().unwrap().is_valid());
        assert_eq!(f.server.with(|s| s.calls.len()), calls);
        if portable {
            assert_eq!(f.client().machine_id(), None);
        }
    }
}

#[test]
fn invalid_portable_import_preserves_existing_online_activation() {
    let f = Fixture::new();
    let talos = f.client();
    assert!(talos.activate("KEY-1").unwrap().is_valid());
    let before = std::fs::read(&f.state_path).unwrap();
    let file = f.server.issue_portable(|c| c["perpetual"] = json!(false));
    assert!(!talos.load_offline_license(&file).unwrap().is_valid());
    assert_eq!(std::fs::read(&f.state_path).unwrap(), before);
    assert!(f.client().validate().unwrap().is_valid());
    assert_eq!(f.server.calls("/v1/client/validate"), 1);
}

#[test]
fn in_flight_online_responses_cannot_replace_an_imported_offline_file() {
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
    use std::time::Duration;

    struct PausedResponse {
        server: Arc<Server>,
        path: &'static str,
        gate: Mutex<Option<(SyncSender<()>, Receiver<()>)>>,
        fail: bool,
    }
    impl Transport for PausedResponse {
        fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, String> {
            let pause = request.url.ends_with(self.path);
            let response = self.server.send(request);
            if pause {
                if let Some((entered, release)) = self.gate.lock().unwrap().take() {
                    entered.send(()).unwrap();
                    release.recv_timeout(Duration::from_secs(5)).unwrap();
                    if self.fail {
                        return Err("delayed connection failure".into());
                    }
                }
            }
            response
        }
    }

    for path in [
        "/v1/client/activate",
        "/v1/client/validate",
        "/v1/client/heartbeat",
        "/v1/client/deactivate",
        "/v1/client/keyset",
    ] {
        for fail in [false, true] {
            let f = Fixture::new();
            f.client().activate("KEY-1").unwrap();
            if path == "/v1/client/keyset" {
                f.advance(3600);
                let replacement = f.server.keyset_at(T0 + 7200, &key(9));
                f.server.with(|s| s.keyset_replay = Some(replacement));
            }
            let (entered_tx, entered_rx) = sync_channel(1);
            let (release_tx, release_rx) = sync_channel(1);
            let mut options = f.options();
            options.transport = Some(Arc::new(PausedResponse {
                server: Arc::clone(&f.server),
                path,
                gate: Mutex::new(Some((entered_tx, release_rx))),
                fail,
            }));
            let talos = f.client_with(options);
            f.server.with(|s| s.decision = "revoked".into());
            let request_client = talos.clone();
            let pending = std::thread::spawn(move || match path {
                "/v1/client/activate" => request_client.activate("KEY-2").map(Some),
                "/v1/client/validate" => request_client.validate().map(Some),
                "/v1/client/keyset" => request_client.validate().map(Some),
                "/v1/client/heartbeat" => request_client.heartbeat().map(Some),
                _ => request_client.deactivate().map(|_| None),
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let file = f.server.issue_portable(|_| {});
            let state = talos.load_offline_license(&file).unwrap();
            assert!(state.is_valid() && state.is_offline);
            let before = std::fs::read(&f.state_path).unwrap();
            release_tx.send(()).unwrap();
            if let Some(state) = pending.join().unwrap().unwrap() {
                assert!(state.is_valid() && state.is_offline, "{path}: fail={fail}");
            }
            assert!(talos.current().unwrap().is_valid());
            assert!(talos.current().unwrap().is_offline);
            assert_eq!(std::fs::read(&f.state_path).unwrap(), before, "{path}");
            f.offline(true);
            assert!(f.client().validate().unwrap().is_valid());
        }
    }
}

#[test]
fn rejected_offline_import_does_not_replace_trusted_keys() {
    for problem in ["signature", "contract", "older_keyset"] {
        let f = Fixture::new();
        let talos = f.client();
        talos.activate("KEY-1").unwrap();
        f.advance(3600);
        let mut file: Value = serde_json::from_slice(&f.server.issue_portable(|_| {})).unwrap();
        // A real anchor-signed keyset from a different key rotation accompanies
        // an invalid file. It must not poison the held activation's trust.
        let issued = if problem == "older_keyset" {
            T0 - 3600
        } else {
            T0 + 3600
        };
        file["keyset"] = json!(f.server.keyset_at(issued, &key(9)));
        if problem != "signature" {
            let parts: Vec<_> = file["token"].as_str().unwrap().split('.').collect();
            let mut claims: Value =
                serde_json::from_slice(&B64URL.decode(parts[3]).unwrap()).unwrap();
            if problem == "contract" {
                claims["perpetual"] = json!(false);
            }
            file["token"] = json!(mint(&key(9), "offline", &claims));
        }
        let before = std::fs::read(&f.state_path).unwrap();
        let result = talos.load_offline_license(&serde_json::to_vec(&file).unwrap());
        if problem == "contract" {
            assert!(!result.unwrap().is_valid());
        } else {
            assert!(matches!(result, Err(Error::Signature(_))));
        }
        assert_eq!(std::fs::read(&f.state_path).unwrap(), before, "{problem}");
        let state = talos.validate().unwrap();
        assert!(state.is_valid() && !state.is_offline, "{problem}");
    }
}

#[test]
fn malformed_portable_contracts_fail_closed() {
    for problem in [
        "missing_binding",
        "unknown_binding",
        "null_binding",
        "false_perpetual",
        "string_perpetual",
        "missing_decision",
        "revoked_decision",
        "missing_exp",
        "finite_exp",
        "missing_lic_exp",
        "finite_lic_exp",
        "null_fph",
        "null_mpk",
        "null_mid",
        "missing_fid",
        "empty_fid",
        "missing_sub",
        "empty_sub",
    ] {
        let f = Fixture::new();
        let file = f.server.issue_portable(|c| match problem {
            "missing_binding" => {
                c.as_object_mut().unwrap().remove("binding");
            }
            "unknown_binding" => c["binding"] = json!("anything"),
            "null_binding" => c["binding"] = Value::Null,
            "false_perpetual" => c["perpetual"] = json!(false),
            "string_perpetual" => c["perpetual"] = json!("true"),
            "missing_decision" => {
                c.as_object_mut().unwrap().remove("decision");
            }
            "revoked_decision" => c["decision"] = json!("revoked"),
            "missing_exp" => {
                c.as_object_mut().unwrap().remove("exp");
            }
            "finite_exp" => c["exp"] = json!(T0 + 86400),
            "missing_lic_exp" => {
                c["lic"].as_object_mut().unwrap().remove("lic_exp");
            }
            "finite_lic_exp" => c["lic"]["lic_exp"] = json!(T0 + 86400),
            "null_fph" => c["fph"] = Value::Null,
            "null_mpk" => c["mpk"] = Value::Null,
            "null_mid" => c["mid"] = Value::Null,
            "missing_fid" => {
                c.as_object_mut().unwrap().remove("fid");
            }
            "empty_fid" => c["fid"] = json!(" "),
            "missing_sub" => {
                c.as_object_mut().unwrap().remove("sub");
            }
            "empty_sub" => c["sub"] = json!(""),
            _ => unreachable!(),
        });
        assert!(
            !f.client().load_offline_license(&file).unwrap().is_valid(),
            "{problem}"
        );
    }
}

#[test]
fn portable_import_verifies_signature_and_product_before_binding() {
    let f = Fixture::new();
    let wrong_product = f
        .server
        .issue_portable(|c| c["aud"] = json!("another-product"));
    assert!(matches!(
        f.client().load_offline_license(&wrong_product),
        Err(Error::Signature(_))
    ));

    let mut file: Value = serde_json::from_slice(&f.server.issue_portable(|_| {})).unwrap();
    let parts: Vec<_> = file["token"]
        .as_str()
        .unwrap()
        .split('.')
        .map(str::to_string)
        .collect();
    let mut claims: Value = serde_json::from_slice(&B64URL.decode(&parts[3]).unwrap()).unwrap();
    claims["binding"] = json!("machine");
    file["token"] = json!(format!(
        "{}.{}.{}.{}.{}",
        parts[0],
        parts[1],
        parts[2],
        B64URL.encode(serde_json::to_vec(&claims).unwrap()),
        parts[4]
    ));
    assert!(matches!(
        f.client()
            .load_offline_license(&serde_json::to_vec(&file).unwrap()),
        Err(Error::Signature(_))
    ));
}

#[test]
fn machine_offline_files_accept_only_known_bindings() {
    for (binding, valid) in [
        (json!("machine"), true),
        (json!("unknown"), false),
        (Value::Null, false),
    ] {
        let f = Fixture::new();
        let talos = f.client();
        let request = talos.create_offline_request(None).unwrap();
        let file = f
            .server
            .issue_offline_with(&request, 86400, None, |c| c["binding"] = binding);
        assert_eq!(talos.load_offline_license(&file).unwrap().is_valid(), valid);
    }
}

#[test]
fn another_machines_licence_file_is_a_verdict_not_an_error() {
    let f = Fixture::new();
    let talos = f.client();
    let request = talos.create_offline_request(None).unwrap();
    let file = f
        .server
        .issue_offline(&request, 86400, Some("fp2:someone-else"));
    assert_eq!(
        talos.load_offline_license(&file).unwrap().decision,
        Decision::MachineMismatch
    );
    assert!(matches!(
        talos.load_offline_license(b"{\"kind\":\"x\"}"),
        Err(Error::Usage(_))
    ));
}

#[test]
fn deactivation_forgets_the_binding_on_disk() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    talos.deactivate().unwrap();
    assert!(!talos.is_activated());
    assert!(matches!(talos.validate(), Err(Error::NotActivated)));
    assert!(!f.client().is_activated());
}

#[test]
fn a_dead_network_with_nothing_cached_is_an_error_not_a_verdict() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    f.offline(true);
    assert!(matches!(talos.validate(), Err(Error::Network(_))));
    let report: Value =
        serde_json::from_str(&talos.create_diagnostic_report(talos.validate().err().as_ref()))
            .unwrap();
    assert_eq!(report["error_code"], "client_error");
    assert!(!report.to_string().contains("secret-1"));
}

#[test]
fn without_persistence_nothing_reaches_the_disk() {
    let f = Fixture::new();
    let mut options = f.options();
    options.persist_state = false;
    let talos = f.client_with(options);
    talos.activate("KEY-1").unwrap();
    talos.validate().unwrap();
    assert!(!f.state_path.exists());
    // The in-process cache still carries the offline fallback.
    f.offline(true);
    assert!(talos.validate().unwrap().is_offline);
}

#[test]
fn a_gateway_page_in_front_of_a_dead_server_is_not_an_answer() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    talos.validate().unwrap();

    // Cloudflare's 52x, IIS's 502.3: no Talos answer, so the cached verdict.
    f.server.with(|s| s.gateway = Some(502));
    let state = talos.validate().unwrap();
    assert!(state.is_valid() && state.is_offline);

    // A self-hosted node's own refusal is an answer, and stops validation.
    f.server.with(|s| {
        s.gateway = None;
        s.refuse = Some((503, "node_degraded"));
    });
    assert_eq!(talos.validate().unwrap_err().code(), Some("node_degraded"));
}

#[test]
fn an_answer_about_another_machine_is_no_answer_about_this_one() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    talos.validate().unwrap();

    // A relay pairing this client's nonce with somebody else's activation gets
    // a genuine token naming that other machine.
    f.server
        .with(|s| s.fph_override = Some("fp2:somebody-else".into()));
    assert!(
        talos.validate().unwrap().is_offline,
        "it must not land as a live verdict"
    );
    assert!(matches!(talos.heartbeat(), Err(Error::Signature(_))));

    let fresh = Fixture::new();
    fresh
        .server
        .with(|s| s.fph_override = Some("fp2:somebody-else".into()));
    assert!(matches!(
        fresh.client().activate("KEY-1"),
        Err(Error::Signature(_))
    ));
}

#[test]
fn a_replayed_older_keyset_does_not_bring_a_revoked_key_back() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();

    // Two days on, the held keyset is stale and the next call refreshes it —
    // and gets a recording from before the activation, listing a key the
    // product no longer uses. Adopting it would make every live answer fail.
    f.advance(2 * 86400);
    let replay = f.server.keyset_at(T0 - 3600, &key(9));
    f.server.with(|s| s.keyset_replay = Some(replay));
    let state = talos.validate().unwrap();
    assert!(state.is_valid());
    assert!(
        !state.is_offline,
        "the keys already held still verify the live answer"
    );

    // And it is not what the next start trusts either.
    f.offline(true);
    let restarted = f.client();
    let cached = restarted.validate().unwrap();
    assert!(cached.is_valid() && cached.is_offline);
}

#[test]
fn a_conflicting_keyset_cannot_rollback_trust_within_clock_skew_or_the_same_second() {
    for older_by in [0, 1] {
        let f = Fixture::new();
        let talos = f.client();
        talos.activate("KEY-1").unwrap();
        let conflicting = f.server.keyset_at(T0 - older_by, &key(9));
        let mut file: Value = serde_json::from_slice(&f.server.issue_portable(|_| {})).unwrap();
        let parts: Vec<_> = file["token"].as_str().unwrap().split('.').collect();
        let claims: Value = serde_json::from_slice(&B64URL.decode(parts[3]).unwrap()).unwrap();
        file["token"] = json!(mint(&key(9), "offline", &claims));
        file["keyset"] = json!(conflicting);
        assert!(
            matches!(
                talos.load_offline_license(&serde_json::to_vec(&file).unwrap()),
                Err(Error::Signature(_))
            ),
            "older_by={older_by}"
        );
        assert!(talos.validate().unwrap().is_valid());
    }
}

#[test]
fn a_release_before_renewals_start_stops_them_before_they_take_a_seat() {
    let f = Fixture::new();
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    let opts = AcquireLeaseOptions::new()
        .instance_id("inst-1")
        .auto_renew(false);
    let (_, adopted) = talos.inner.acquire_lease("inst-1", None).unwrap();
    let generation = adopted.expect("adopted");
    talos.release_lease().unwrap();
    let before = f.server.calls("/v1/client/leases");
    // The window the race lived in: renewals scheduled for a generation the
    // release has already moved past.
    talos.schedule_renewals("inst-1".into(), opts, generation);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert_eq!(f.server.calls("/v1/client/leases"), before);
    assert_eq!(talos.current_lease(), None);
}

#[test]
fn a_held_seat_is_renewed_in_the_background_until_released() {
    let f = Fixture::new();
    f.server.with(|s| s.renew_after = 1);
    let talos = f.client();
    talos.activate("KEY-1").unwrap();
    talos
        .acquire_lease(AcquireLeaseOptions::new().instance_id("inst-1"))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let renewed = f.server.calls("/v1/client/leases");
    assert!(renewed >= 2, "renewed {renewed} times");
    talos.release_lease().unwrap();
    // The release's own DELETE goes to the same path; count from after it.
    let released = f.server.calls("/v1/client/leases");
    assert_eq!(released, renewed + 1);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert_eq!(
        f.server.calls("/v1/client/leases"),
        released,
        "no renewal after the release"
    );
    assert_eq!(talos.current_lease(), None);
}
