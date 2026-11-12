//! Signed public update protocol regression tests.

use super::*;
use crate::compact::{B64, B64URL};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

const TOKEN: &str = "tpt_public_update_test";
const PRODUCT: &str = "01a175263e5c73b2aa5fd477985877a1";
const ARTIFACT: &str = "01a175263e5c73b2aa5fd477985877a2";
const BYTES: &[u8] = b"synthetic signed archive bytes; never executed";
const ORIGIN: &str = "https://updates.example/proxy";

fn test_product_id() -> String {
    let raw = (0..PRODUCT.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&PRODUCT[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    format!("0x{}", hex(&Keccak256::digest(raw)))
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn pk(k: &SigningKey) -> String {
    B64.encode(k.verifying_key().as_bytes())
}
fn mint(k: &SigningKey, typ: &str, value: &Value) -> String {
    let prefix = format!(
        "talos.1.{typ}.{}",
        B64URL.encode(serde_json::to_vec(value).unwrap())
    );
    format!(
        "{prefix}.{}",
        B64URL.encode(k.sign(prefix.as_bytes()).to_bytes())
    )
}

struct Fixture {
    root: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).unwrap();
        let path = root.join(format!("talos-public-update-unit-{}", hex(&random)));
        std::fs::create_dir(&path).unwrap();
        Self { root, path }
    }
    fn state(&self) -> PathBuf {
        self.path.join("updates.dat")
    }
    fn dest(&self) -> PathBuf {
        self.path.join("archive.zip")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self.path.canonicalize().unwrap();
        assert!(path.starts_with(&self.root));
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("talos-public-update-unit-"));
        std::fs::remove_dir_all(path).unwrap();
    }
}

struct Settings {
    seq: i64,
    version: String,
    channel: String,
    keyset_iat: i64,
    manifest: Option<String>,
    keyset: Option<String>,
    body: Option<Value>,
    bytes: Vec<u8>,
    content_length: Option<u64>,
    status: Option<u16>,
    calls: Vec<HttpRequest>,
    registry_device: String,
    registry_rights: Value,
    registry_status: u64,
    rpc_checks: usize,
    after_second_rpc_check: Option<Arc<dyn Fn() + Send + Sync>>,
}

struct Server {
    anchor: SigningKey,
    release: SigningKey,
    settings: Mutex<Settings>,
}
impl Server {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            anchor: key(41),
            release: key(42),
            settings: Mutex::new(Settings {
                seq: 2,
                version: "1.1.0".into(),
                channel: "stable".into(),
                keyset_iat: unix_now(),
                manifest: None,
                keyset: None,
                body: None,
                bytes: BYTES.into(),
                content_length: Some(BYTES.len() as u64),
                status: None,
                calls: vec![],
                registry_device: format!("0x{}", "00".repeat(32)),
                registry_rights: json!({"pro":true}),
                registry_status: 1,
                rpc_checks: 0,
                after_second_rpc_check: None,
            }),
        })
    }
    fn configure(&self, f: impl FnOnce(&mut Settings)) {
        f(&mut self.settings.lock().unwrap());
    }
    fn claims(&self) -> Value {
        let s = self.settings.lock().unwrap();
        json!({
            "v":1,"typ":"manifest","iss":"01a175263e5c73b2aa5fd477985877aa","aud":TOKEN,
            "sub":"01a175263e5c73b2aa5fd477985877ab","product_id":PRODUCT,
            "iat":s.keyset_iat,"published_at":s.keyset_iat,"not_before":null,
            "version":s.version,"release_seq":s.seq,"channel":s.channel,"mandatory":false,"notes_url":null,
            "artifacts":[{"platform":"windows","arch":"x64","kind":"archive","filename":"viewer.zip",
                "size":BYTES.len(),"sha256":hex(&Sha256::digest(BYTES))}]
        })
    }
    fn keyset(&self, iat: i64, keys: Value) -> String {
        mint(
            &self.anchor,
            "keyset",
            &json!({"v":1,"typ":"keyset","aud":TOKEN,"iat":iat,"keys":keys}),
        )
    }
    fn client(self: &Arc<Self>, fixture: &Fixture) -> PublicUpdateClient {
        PublicUpdateClient::new(self.options(fixture)).unwrap()
    }
    fn options(self: &Arc<Self>, fixture: &Fixture) -> PublicUpdateOptions {
        PublicUpdateOptions {
            product_token: TOKEN.into(),
            registry_product_id: Some(test_product_id()),
            anchor_public_key: pk(&self.anchor),
            server_url: ORIGIN.into(),
            app_version: Some("1.0.0".into()),
            state_path: Some(fixture.state()),
            transport: Some(self.clone()),
            fingerprint_components: BTreeMap::from([(
                "machine_guid".into(),
                "synthetic-public-update-machine".into(),
            )]),
            ..Default::default()
        }
    }
    fn gets(&self) -> usize {
        self.settings
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|r| r.method == "GET")
            .count()
    }
}
impl Transport for Server {
    fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, String> {
        if request.url == "https://registry-rpc.example" {
            let body: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
            let mut s = self.settings.lock().unwrap();
            let number = |n: u64| format!("{n:064x}");
            let result = match body["method"].as_str().unwrap() {
                "eth_chainId" => json!("0x7a69"),
                "eth_getBlockByNumber" => {
                    json!({"number":"0x64","hash":format!("0x{}","77".repeat(32)),"timestamp":format!("0x{:x}",s.keyset_iat)})
                }
                "eth_getCode" => json!(include_str!("../registry/test-runtime.hex").trim()),
                "eth_call" => {
                    let data = body["params"][0]["data"].as_str().unwrap();
                    let selector = |signature: &str| {
                        format!(
                            "0x{}",
                            hex(&Keccak256::digest(signature.as_bytes()))[..8].to_owned()
                        )
                    };
                    if data.starts_with(&selector("registryVersion()")) {
                        json!(format!("0x{}", number(1)))
                    } else if data.starts_with(&selector("getLicense(address,bytes32,bytes32)")) {
                        let rights = serde_json::to_vec(&s.registry_rights).unwrap();
                        json!(format!(
                            "0x{}{}{}{}{}{}{}",
                            format!("{}{}", "0".repeat(24), "11".repeat(20)),
                            &s.registry_device[2..],
                            number(0),
                            number(0),
                            hex(&Keccak256::digest(rights)),
                            number(1),
                            number(s.registry_status)
                        ))
                    } else {
                        s.rpc_checks += 1;
                        json!(format!("0x{}", number(1)))
                    }
                }
                method => panic!("unexpected fixture RPC {method}"),
            };
            s.calls.push(request);
            let hook = if s.rpc_checks == 2 {
                s.after_second_rpc_check.take()
            } else {
                None
            };
            drop(s);
            if let Some(hook) = hook {
                hook();
            }
            return Ok(HttpResponse::from_bytes(
                200,
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":result})).unwrap(),
            ));
        }
        let path = request
            .url
            .strip_prefix(ORIGIN)
            .expect("fixed update origin/base path")
            .to_owned();
        let claims = self.claims();
        let mut s = self.settings.lock().unwrap();
        assert!(request.timeout.is_some_and(|d| !d.is_zero()));
        assert!(request
            .headers
            .iter()
            .all(|(k, _)| !k.contains("activation") && !k.contains("fingerprint")));
        s.calls.push(request);
        if let Some(status) = s.status {
            return Ok(HttpResponse::from_bytes(
                status,
                b"{\"error\":\"internal\"}".to_vec(),
            ));
        }
        if path == "/v1/client/keyset" {
            let token = s.keyset.clone().unwrap_or_else(|| {
                self.keyset(
                    s.keyset_iat,
                    json!([
                        {"purpose":"release","status":"active","pk":pk(&self.release)}
                    ]),
                )
            });
            Ok(HttpResponse::from_bytes(
                200,
                serde_json::to_vec(&json!({"keyset":token})).unwrap(),
            ))
        } else if path == "/v1/client/public-updates/check"
            || path == "/v1/client/public-updates/resolve"
        {
            let mut manifest = s
                .manifest
                .clone()
                .unwrap_or_else(|| mint(&self.release, "manifest", &claims));
            if path.ends_with("/resolve") {
                let request: Value =
                    serde_json::from_slice(s.calls.last().unwrap().body.as_ref().unwrap()).unwrap();
                let payload = manifest.split('.').nth(3).unwrap();
                let mut resolved: Value =
                    serde_json::from_slice(&B64URL.decode(payload).unwrap()).unwrap();
                resolved["version"] = request["version"].clone();
                if request["version"] == "1.0.0" {
                    resolved["release_seq"] = json!(1);
                    resolved["iat"] = json!(s.keyset_iat - 200);
                    resolved["published_at"] = json!(s.keyset_iat - 200);
                }
                manifest = mint(&self.release, "manifest", &resolved);
            }
            let body=s.body.clone().unwrap_or_else(||json!({"update_available":true,"manifest":manifest,
                // These envelope facts deliberately disagree with signed claims.
                "version":"EVIL","release_seq":999999,"mandatory":true,
                "artifacts":[{"platform":"windows","arch":"x64","kind":"archive","artifact_id":ARTIFACT,
                    "download_path":download_path(TOKEN,&s.channel,ARTIFACT)}]
            }));
            Ok(HttpResponse::from_bytes(
                200,
                serde_json::to_vec(&body).unwrap(),
            ))
        } else if path.starts_with("/v1/client/public-updates/artifacts/") {
            Ok(HttpResponse {
                status: 200,
                content_length: s.content_length,
                body: Box::new(std::io::Cursor::new(s.bytes.clone())),
            })
        } else {
            panic!("unexpected public update path {path}");
        }
    }
}

fn offer(client: &PublicUpdateClient) -> UpdateInfo {
    client
        .check_for_update(Default::default())
        .unwrap()
        .unwrap()
}

#[test]
fn public_check_download_and_restart_need_no_classic_activation() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    let info = offer(&client);
    assert_eq!(info.version, "1.1.0");
    assert_eq!(info.release_seq, 2);
    assert!(!info.mandatory);
    let artifact = &info.artifacts[0];
    let mut progress = vec![];
    let chosen = client
        .download_update(
            &info,
            f.dest(),
            Some(artifact),
            Some(&mut |p| progress.push(p)),
        )
        .unwrap();
    assert_eq!(&chosen, artifact);
    assert_eq!(std::fs::read(f.dest()).unwrap(), BYTES);
    assert_eq!(progress.last().unwrap().bytes_received, BYTES.len() as u64);
    let mut options = server.options(&f);
    options.app_version = Some("1.1.0".into());
    let restarted = PublicUpdateClient::new(options).unwrap();
    assert!(restarted
        .check_for_update(Default::default())
        .unwrap()
        .is_none());
    assert!(std::fs::read(f.state()).unwrap().starts_with(b"TLS1"));
    let s = server.settings.lock().unwrap();
    for request in &s.calls {
        let body = request.body.as_deref().unwrap_or_default();
        assert!(!String::from_utf8_lossy(body).contains("license_key"));
        assert!(!request.url.contains("/client/activate"));
    }
}

#[test]
fn forged_signed_metadata_and_wrong_anchor_or_channel_never_offer_an_update() {
    for case in 0..6 {
        let f = Fixture::new();
        let server = Server::new();
        let mut claims = server.claims();
        match case {
            0 => claims["aud"] = json!("another_product"),
            1 => claims["channel"] = json!("beta"),
            2 => claims["release_seq"] = json!(2.5),
            3 => claims["not_before"] = json!(unix_now() + 3600),
            4 => claims["artifacts"][0]["filename"] = json!("../escape.zip"),
            5 => {}
            _ => unreachable!(),
        }
        let signing = if case == 5 { key(99) } else { key(42) };
        server.configure(|s| s.manifest = Some(mint(&signing, "manifest", &claims)));
        assert!(
            server
                .client(&f)
                .check_for_update(Default::default())
                .is_err(),
            "case {case}"
        );
        assert_eq!(server.gets(), 0);
    }
    let f = Fixture::new();
    let server = Server::new();
    let mut opts = server.options(&f);
    opts.anchor_public_key = pk(&key(99));
    assert!(PublicUpdateClient::new(opts)
        .unwrap()
        .check_for_update(Default::default())
        .is_err());
}

#[test]
fn manifest_replay_is_rejected_after_restart_and_explicit_floor_cannot_lower_it() {
    let f = Fixture::new();
    let server = Server::new();
    server.configure(|s| {
        s.seq = 10;
        s.version = "2.0.0".into();
    });
    let client = server.client(&f);
    assert_eq!(offer(&client).release_seq, 10);
    drop(client);
    server.configure(|s| {
        s.seq = 9;
        s.version = "1.9.0".into();
    });
    let client = server.client(&f);
    assert!(client
        .check_for_update(CheckForUpdateOptions {
            current_release_seq: Some(0),
            ..Default::default()
        })
        .is_err());
}

#[test]
fn maintenance_uses_its_own_observation_domain_and_signed_publication_cutoff() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    server.configure(|s| {
        s.seq = 20;
        s.version = "2.0.0".into();
    });
    assert_eq!(offer(&client).release_seq, 20);
    server.configure(|s| {
        s.seq = 12;
        s.version = "1.2.0".into();
    });
    let cutoff = unix_now() as u64 + 10;
    let info = client
        .check_bounded(Default::default(), &Default::default(), Some(cutoff))
        .unwrap()
        .unwrap();
    assert_eq!(info.release_seq, 12);
    let body: Value = serde_json::from_slice(
        server
            .settings
            .lock()
            .unwrap()
            .calls
            .iter()
            .find(|r| {
                r.url.ends_with("/public-updates/check")
                    && serde_json::from_slice::<Value>(r.body.as_ref().unwrap()).unwrap()
                        ["published_before"]
                        == json!(cutoff)
            })
            .unwrap()
            .body
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["published_before"], cutoff);
    let mut claims = server.claims();
    claims["published_at"] = json!(cutoff + 1);
    server.configure(|s| s.manifest = Some(mint(&server.release, "manifest", &claims)));
    assert!(client
        .check_bounded(Default::default(), &Default::default(), Some(cutoff))
        .is_err());
}

#[test]
fn observed_key_revocation_survives_failure_and_prevents_old_keyset_replay() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    let info = offer(&client);
    let old = server.keyset(
        unix_now(),
        json!([{"purpose":"release","status":"active","pk":pk(&server.release)}]),
    );
    let revoked = server.keyset(unix_now() + 1, json!([]));
    server.configure(|s| s.keyset = Some(revoked));
    assert!(client
        .download_update(&info, f.dest(), Some(&info.artifacts[0]), None)
        .is_err());
    assert_eq!(server.gets(), 0);
    server.configure(|s| s.keyset = Some(old));
    let restarted = server.client(&f);
    assert!(restarted.check_for_update(Default::default()).is_err());
}

#[test]
fn a_same_second_revocation_conflict_survives_restart_and_cannot_resurrect_keys() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    let info = offer(&client);
    let iat = server.settings.lock().unwrap().keyset_iat;
    let old = server.keyset(
        iat,
        json!([{"purpose":"release","status":"active","pk":pk(&server.release)}]),
    );
    let revoked = server.keyset(iat, json!([]));
    server.configure(|s| s.keyset = Some(revoked.clone()));
    assert!(client
        .download_update(&info, f.dest(), Some(&info.artifacts[0]), None)
        .is_err());
    assert_eq!(server.gets(), 0);
    drop(client);
    let restarted = server.client(&f);
    // Neither ambiguous same-second token may authorize an update.
    server.configure(|s| s.keyset = Some(old));
    assert!(restarted.check_for_update(Default::default()).is_err());
    server.configure(|s| s.keyset = Some(revoked));
    assert!(restarted.check_for_update(Default::default()).is_err());
    // A later anchor-signed keyset resolves the ambiguity, without the old key.
    let later = server.keyset(iat + 1, json!([]));
    server.configure(|s| s.keyset = Some(later));
    assert!(restarted.check_for_update(Default::default()).is_err());
    assert_eq!(server.gets(), 0);
}

#[test]
fn unsigned_paths_and_fabricated_update_info_cannot_start_a_download() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    let info = offer(&client);
    let mut fake = info.clone();
    fake.release_seq += 1;
    assert!(client
        .download_update(&fake, f.dest(), Some(&fake.artifacts[0]), None)
        .is_err());
    let mut artifact = info.artifacts[0].clone();
    artifact.download_path = Some("https://evil.example/file".into());
    assert!(client
        .download_update(&info, f.dest(), Some(&artifact), None)
        .is_err());
    assert_eq!(server.gets(), 0);
    let manifest = mint(&server.release, "manifest", &server.claims());
    server.configure(|s|s.body=Some(json!({"update_available":true,"manifest":manifest,
        "artifacts":[{"platform":"windows","arch":"x64","kind":"archive","artifact_id":ARTIFACT,"download_path":"//evil.example/file"}]
    })));
    assert!(client.check_for_update(Default::default()).is_err());
}

#[test]
fn corrupt_or_oversized_streams_leave_no_destination_and_no_partial_files() {
    for case in 0..3 {
        let f = Fixture::new();
        let server = Server::new();
        let client = server.client(&f);
        let info = offer(&client);
        server.configure(|s| match case {
            0 => s.bytes[0] ^= 1,
            1 => {
                s.bytes.push(0);
                s.content_length = None;
            }
            2 => {
                s.bytes.pop();
                s.content_length = None;
            }
            _ => unreachable!(),
        });
        assert!(client
            .download_update(&info, f.dest(), Some(&info.artifacts[0]), None)
            .is_err());
        assert!(!f.dest().exists());
        assert!(!std::fs::read_dir(&f.path).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".talos-part")));
    }
}

#[test]
fn cancellation_during_streaming_preserves_activation_and_allows_a_retry() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    let info = offer(&client);
    let cancel = PublicUpdateCancellationToken::new();
    let options = PublicUpdateRequestOptions {
        cancellation: Some(cancel.clone()),
        ..Default::default()
    };
    assert!(client
        .download_with_options(
            &info,
            f.dest(),
            Some(&info.artifacts[0]),
            Some(&mut |_| cancel.cancel()),
            &options
        )
        .is_err());
    assert!(!f.dest().exists());
    client
        .download_update(&info, f.dest(), Some(&info.artifacts[0]), None)
        .unwrap();
    assert_eq!(std::fs::read(f.dest()).unwrap(), BYTES);
    let existing = f.path.join("existing.zip");
    std::fs::write(&existing, b"keep existing").unwrap();
    assert!(client
        .download_update(&info, &existing, Some(&info.artifacts[0]), None)
        .is_err());
    assert_eq!(std::fs::read(existing).unwrap(), b"keep existing");
}

#[test]
fn state_corruption_and_failed_persistence_fail_closed() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    let mut temporary = f.state().as_os_str().to_owned();
    temporary.push(".tmp");
    std::fs::create_dir(PathBuf::from(temporary)).unwrap();
    assert!(client.check_for_update(Default::default()).is_err());
    std::fs::write(f.state(), b"corrupt encrypted state").unwrap();
    assert!(PublicUpdateClient::new(server.options(&f)).is_err());
}

#[test]
fn transport_failure_is_an_error_not_an_up_to_date_response() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    server.configure(|s| s.status = Some(503));
    assert!(matches!(
        client.check_for_update(Default::default()),
        Err(Error::Api { status: 503, .. })
    ));
    server.configure(|s| s.status = None);
    assert!(client
        .check_for_update(Default::default())
        .unwrap()
        .is_some());
}

#[test]
fn registry_product_binding_and_scheduled_publication_time_are_verified() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    let info = offer(&client);
    let mut offer = client.0.offer_for(&info).unwrap();
    let bytes = (0..PRODUCT.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&PRODUCT[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let product_id = format!("0x{}", hex(&Keccak256::digest(bytes)));
    let make_registry = |id: String, file: &str| {
        RegistryLicenseClient::new(crate::registry::RegistryLicenseOptions {
            issuer: format!("0x{}", "11".repeat(20)),
            product_id: id,
            chain_id: 31337,
            contract: format!("0x{}", "22".repeat(20)),
            rpc_urls: vec!["https://unused-rpc.example".into()],
            state_path: Some(f.path.join(file)),
            transport: Some(server.clone()),
            ..Default::default()
        })
        .unwrap()
    };
    let registry = make_registry(product_id, "registry.dat");
    assert!(bind_registry(&registry, &offer).is_ok());
    let wrong = make_registry(format!("0x{}", "33".repeat(32)), "other-registry.dat");
    assert!(bind_registry(&wrong, &offer).is_err());
    let mut claims = server.claims();
    claims["not_before"] = json!(unix_now() + 30);
    offer = client
        .0
        .verify_offer(
            &[PublicKey::from_base64(&pk(&server.release)).unwrap()],
            &mint(&server.release, "manifest", &claims),
            "stable",
        )
        .unwrap();
    assert_eq!(offer.published_at, (unix_now() + 30) as u64);
}

#[test]
fn form_encoded_channels_and_uuid_formats_match_the_server_contract() {
    let f = Fixture::new();
    let server = Server::new();
    server.configure(|s| s.channel = "release candidate~".into());
    let client = server.client(&f);
    let info = client
        .check_for_update(CheckForUpdateOptions {
            channel: Some("release candidate~".into()),
            ..Default::default()
        })
        .unwrap()
        .unwrap();
    assert!(info.artifacts[0]
        .download_path
        .as_deref()
        .unwrap()
        .contains("channel=release+candidate%7E"));
    client
        .download_update(&info, f.dest(), Some(&info.artifacts[0]), None)
        .unwrap();
}

#[test]
fn another_paid_window_download_does_not_forget_the_release_actually_installed() {
    let f = Fixture::new();
    let server = Server::new();
    let first = server.client(&f);
    let second = server.client(&f);
    server.configure(|s| {
        s.seq = 21;
        s.version = "2.1.0".into();
    });
    let newer = offer(&first);
    first
        .download_update(
            &newer,
            f.path.join("newer.zip"),
            Some(&newer.artifacts[0]),
            None,
        )
        .unwrap();
    server.configure(|s| {
        s.seq = 20;
        s.version = "2.0.0".into();
    });
    let older = second
        .check_bounded(
            Default::default(),
            &Default::default(),
            Some(unix_now() as u64 + 10),
        )
        .unwrap()
        .unwrap();
    second
        .download_update(
            &older,
            f.path.join("older.zip"),
            Some(&older.artifacts[0]),
            None,
        )
        .unwrap();
    let mut options = server.options(&f);
    options.app_version = Some("2.1.0".into());
    let restarted = PublicUpdateClient::new(options).unwrap();
    let budget = Budget::new(Duration::from_secs(1), &Default::default()).unwrap();
    restarted.check_for_update(Default::default()).unwrap();
    let floor = restarted
        .0
        .with_state(&budget, |state| Ok(state.installed_seq))
        .unwrap();
    assert_eq!(floor, 21);
}

#[test]
fn signed_old_versions_are_not_updates_even_with_a_higher_publication_sequence() {
    for (running, candidate, newer) in [
        ("2.0.0", "1.2.0", false),
        ("1.0.0", "1.0.0-rc.1", false),
        ("1.0.0-rc.2", "1.0.0-rc.10", true),
        ("v1.2", "1.2.1", true),
        ("1.2.0+build.9", "1.2.0+build.10", false),
    ] {
        let f = Fixture::new();
        let server = Server::new();
        server.configure(|s| {
            s.version = candidate.into();
            s.seq = 100;
        });
        let mut options = server.options(&f);
        options.app_version = Some(running.into());
        let client = PublicUpdateClient::new(options).unwrap();
        assert_eq!(
            client
                .check_for_update(Default::default())
                .unwrap()
                .is_some(),
            newer,
            "{candidate} over {running}"
        );
    }
    let f = Fixture::new();
    let server = Server::new();
    server.configure(|s| s.version = "nightly".into());
    let mut options = server.options(&f);
    options.app_version = Some("nightly".into());
    let client = PublicUpdateClient::new(options).unwrap();
    assert!(client.check_for_update(Default::default()).is_err());
    assert!(server.settings.lock().unwrap().calls.is_empty());
    assert!(client
        .check_for_update(CheckForUpdateOptions {
            current_release_seq: Some(1),
            ..Default::default()
        })
        .unwrap()
        .is_some());
}

#[test]
fn a_newer_running_version_in_another_process_blocks_a_stale_download() {
    let f = Fixture::new();
    let server = Server::new();
    let stale = server.client(&f);
    let info = offer(&stale);
    let mut options = server.options(&f);
    options.app_version = Some("2.0.0".into());
    let newer = PublicUpdateClient::new(options).unwrap();
    newer.check_for_update(Default::default()).unwrap();
    assert!(stale
        .download_update(&info, f.dest(), Some(&info.artifacts[0]), None)
        .is_err());
    assert_eq!(server.gets(), 0);
}

#[test]
fn a_changed_private_offer_cannot_replace_the_manifest_used_for_registry_eligibility() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    let info = offer(&client);
    let expected = client.0.offer_for(&info).unwrap();
    let mut claims = server.claims();
    claims["published_at"] = json!(unix_now() + 1);
    server.configure(|s| s.manifest = Some(mint(&server.release, "manifest", &claims)));
    let same_info = client
        .check_bounded(
            Default::default(),
            &Default::default(),
            Some(unix_now() as u64 + 100),
        )
        .unwrap()
        .unwrap();
    assert_eq!(info, same_info);
    assert!(client
        .download_checked(
            &info,
            &f.dest(),
            Some(&info.artifacts[0]),
            None,
            &Default::default(),
            Some(&expected)
        )
        .is_err());
    assert_eq!(server.gets(), 0);
}

fn registry(fixture: &Fixture, server: &Arc<Server>, rights: Value) -> RegistryLicenseClient {
    let raw = (0..PRODUCT.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&PRODUCT[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let product_id = format!("0x{}", hex(&Keccak256::digest(raw)));
    let issuer = format!("0x{}", "11".repeat(20));
    let contract = format!("0x{}", "22".repeat(20));
    let client = RegistryLicenseClient::new(crate::registry::RegistryLicenseOptions {
        issuer: issuer.clone(),
        contract: contract.clone(),
        product_id: product_id.clone(),
        chain_id: 31337,
        state_path: Some(fixture.path.join("registry.dat")),
        rpc_urls: vec!["https://registry-rpc.example".into()],
        transport: Some(server.clone()),
        ..Default::default()
    })
    .unwrap();
    server.configure(|s| {
        s.registry_device = client.device_key().into();
        s.registry_rights = rights.clone();
    });
    client
        .import_license(
            &serde_json::to_string(&crate::registry::RegistryLicenseManifest {
                v: 1,
                kind: "talos-registry-license".into(),
                chain_id: 31337,
                contract,
                issuer: issuer.clone(),
                product_id,
                license_id: format!("0x{}", "44".repeat(32)),
                holder: issuer,
                entitlements: B64URL.encode(serde_json::to_vec(&rights).unwrap()),
            })
            .unwrap(),
        )
        .unwrap();
    client
}

#[test]
fn a_paid_old_build_keeps_running_without_talos_but_a_manual_new_build_is_not_covered() {
    let f = Fixture::new();
    let server = Server::new();
    let now = unix_now();
    let registry = registry(
        &f,
        &server,
        json!({"pro":true,"updates":false,"talos_updates":{"mode":"maintenance","until":now-100}}),
    );
    let mut claims = server.claims();
    claims["iat"] = json!(now - 200);
    claims["published_at"] = json!(now - 200);
    server.configure(|s| s.manifest = Some(mint(&server.release, "manifest", &claims)));
    let mut opts = server.options(&f);
    opts.app_version = Some("1.1.0".into());
    let current = PublicUpdateClient::new(opts.clone()).unwrap();
    current
        .require_running_release_entitlement(&registry)
        .unwrap();
    // Already paid old builds remain runnable even when updates:false and the
    // maintenance period is over. Only new update operations are refused.
    assert!(current
        .check_for_registry_update(&registry, Default::default())
        .is_err());
    let before = server
        .settings
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|r| r.url.starts_with(ORIGIN))
        .count();
    server.configure(|s| s.status = Some(503));
    let restarted = PublicUpdateClient::new(opts).unwrap();
    restarted
        .require_running_release_entitlement(&registry)
        .unwrap();
    assert_eq!(
        before,
        server
            .settings
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|r| r.url.starts_with(ORIGIN))
            .count()
    );
    // Manually installing a newer public binary must still enforce its signed
    // publication cutoff; it must not bypass maintenance by avoiding the updater.
    server.configure(|s| {
        s.status = None;
        s.version = "1.2.0".into();
        s.manifest = None;
    });
    let mut newer = server.options(&f);
    newer.app_version = Some("1.2.0".into());
    let newer = PublicUpdateClient::new(newer).unwrap();
    let error = newer
        .require_running_release_entitlement(&registry)
        .unwrap_err();
    assert_eq!(error.code(), Some("updates_not_entitled"));
    server.configure(|s| s.status = Some(503));
    assert_eq!(
        newer
            .require_running_release_entitlement(&registry)
            .unwrap_err()
            .code(),
        Some("updates_not_entitled")
    );
}

#[test]
fn lifetime_running_builds_need_only_registry_rpc_and_missing_paid_metadata_fails_closed() {
    for paid in [false, true] {
        let f = Fixture::new();
        let server = Server::new();
        let rights = if paid {
            json!({"pro":true,"talos_updates":{"mode":"maintenance","until":unix_now()+3600}})
        } else {
            json!({"pro":true,"updates":false,"talos_updates":{"mode":"license"}})
        };
        let registry = registry(&f, &server, rights);
        let mut opts = server.options(&f);
        opts.app_version = Some("1.1.0".into());
        let client = PublicUpdateClient::new(opts).unwrap();
        server.configure(|s| s.status = Some(503));
        assert_eq!(
            client
                .require_running_release_entitlement(&registry)
                .is_ok(),
            !paid
        );
        let api = server
            .settings
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|r| r.url.starts_with(ORIGIN))
            .count();
        assert_eq!(api, usize::from(paid));
    }
}

#[test]
fn registry_aware_checks_use_paid_cutoff_and_recheck_revocation_after_download() {
    let f = Fixture::new();
    let server = Server::new();
    let now = unix_now();
    let registry = registry(
        &f,
        &server,
        json!({"pro":true,"talos_updates":{"mode":"maintenance","until":now-100}}),
    );
    let client = server.client(&f);
    // The transport deliberately ignores published_before: the SDK must check
    // signed publication dates independently of the server's selection.
    assert!(client
        .check_for_registry_update(&registry, Default::default())
        .is_err());
    let mut claims = server.claims();
    claims["iat"] = json!(now - 200);
    claims["published_at"] = json!(now - 200);
    server.configure(|s| s.manifest = Some(mint(&server.release, "manifest", &claims)));
    let info = client
        .check_for_registry_update(&registry, Default::default())
        .unwrap()
        .unwrap();
    let result = client.download_registry_update(
        &registry,
        &info,
        f.dest(),
        Some(&info.artifacts[0]),
        Some(&mut |_| server.configure(|s| s.registry_status = 3)),
    );
    assert_eq!(result.unwrap_err().code(), Some("license_revoked"));
}

#[test]
fn an_archive_only_release_is_selected_by_default_for_the_running_platform() {
    let f = Fixture::new();
    let server = Server::new();
    let client = server.client(&f);
    let mut claims = server.claims();
    claims["artifacts"][0]["platform"] = json!(crate::host::platform());
    claims["artifacts"][0]["arch"] = json!(crate::host::arch());
    let manifest = mint(&server.release, "manifest", &claims);
    server.configure(|s|s.body=Some(json!({"update_available":true,"manifest":manifest,"artifacts":[{
        "platform":crate::host::platform(),"arch":crate::host::arch(),"kind":"archive","artifact_id":ARTIFACT,
        "download_path":download_path(TOKEN,"stable",ARTIFACT)
    }]})));
    let info = offer(&client);
    assert_eq!(
        client
            .download_update(&info, f.dest(), None, None)
            .unwrap()
            .kind,
        "archive"
    );
}

#[test]
fn cached_running_metadata_cannot_resurrect_a_known_revoked_or_ambiguous_key() {
    for same_second in [false, true] {
        let f = Fixture::new();
        let server = Server::new();
        let now = unix_now();
        let registry = registry(
            &f,
            &server,
            json!({"pro":true,"talos_updates":{"mode":"maintenance","until":now-100}}),
        );
        let mut claims = server.claims();
        claims["iat"] = json!(now - 200);
        claims["published_at"] = json!(now - 200);
        server.configure(|s| s.manifest = Some(mint(&server.release, "manifest", &claims)));
        let mut options = server.options(&f);
        options.app_version = Some("1.1.0".into());
        let client = PublicUpdateClient::new(options.clone()).unwrap();
        client
            .require_running_release_entitlement(&registry)
            .unwrap();
        let iat = server.settings.lock().unwrap().keyset_iat;
        let revoked = server.keyset(iat + i64::from(!same_second), json!([]));
        server.configure(|s| s.keyset = Some(revoked));
        assert!(client.check_for_update(Default::default()).is_err());
        let calls = server
            .settings
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|r| r.url.starts_with(ORIGIN))
            .count();
        server.configure(|s| s.status = Some(503));
        let restarted = PublicUpdateClient::new(options).unwrap();
        assert!(restarted
            .require_running_release_entitlement(&registry)
            .is_err());
        assert_eq!(
            calls,
            server
                .settings
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|r| r.url.starts_with(ORIGIN))
                .count()
        );
    }
}

#[test]
fn registry_runtime_helpers_require_the_configured_product_even_for_lifetime_policies() {
    for configured in [None, Some(format!("0x{}", "33".repeat(32)))] {
        let f = Fixture::new();
        let server = Server::new();
        let registry = registry(
            &f,
            &server,
            json!({"pro":true,"talos_updates":{"mode":"license"}}),
        );
        let mut options = server.options(&f);
        options.registry_product_id = configured;
        let client = PublicUpdateClient::new(options).unwrap();
        assert!(client
            .require_running_release_entitlement(&registry)
            .is_err());
        assert!(server.settings.lock().unwrap().calls.is_empty());
    }
}

#[test]
fn an_unpaid_manual_build_does_not_poison_the_paid_builds_update_floor() {
    let f = Fixture::new();
    let server = Server::new();
    let now = unix_now();
    let registry = registry(
        &f,
        &server,
        json!({"pro":true,"talos_updates":{"mode":"maintenance","until":now-100}}),
    );
    let old = server.client(&f);
    old.require_running_release_entitlement(&registry).unwrap();
    server.configure(|s| {
        s.version = "3.0.0".into();
        s.seq = 30;
    });
    // Public archives remain public. Downloading an unpaid build must not make
    // it the licensed installed floor merely because its version is launched.
    let unpaid = offer(&old);
    old.download_update(
        &unpaid,
        f.path.join("unpaid.zip"),
        Some(&unpaid.artifacts[0]),
        None,
    )
    .unwrap();
    let mut options = server.options(&f);
    options.app_version = Some("3.0.0".into());
    let manual = PublicUpdateClient::new(options).unwrap();
    assert_eq!(
        manual
            .require_running_release_entitlement(&registry)
            .unwrap_err()
            .code(),
        Some("updates_not_entitled")
    );
    server.configure(|s| {
        s.version = "1.2.0".into();
        s.seq = 12;
    });
    let mut claims = server.claims();
    claims["iat"] = json!(now - 200);
    claims["published_at"] = json!(now - 200);
    server.configure(|s| s.manifest = Some(mint(&server.release, "manifest", &claims)));
    let restored = server.client(&f);
    let eligible = restored
        .check_for_registry_update(&registry, Default::default())
        .unwrap()
        .unwrap();
    assert_eq!(eligible.version, "1.2.0");
    let budget = Budget::new(Duration::from_secs(1), &Default::default()).unwrap();
    restored
        .0
        .with_state(&budget, |state| {
            assert_eq!(state.installed_seq, 1);
            assert_eq!(state.installed_version.as_deref(), Some("1.0.0"));
            Ok(())
        })
        .unwrap();
}

#[test]
fn more_than_sixty_four_releases_keep_updates_working_and_preserve_the_running_paid_proof() {
    let f = Fixture::new();
    let server = Server::new();
    let now = unix_now();
    let registry = registry(
        &f,
        &server,
        json!({"pro":true,"talos_updates":{"mode":"maintenance","until":now+3600}}),
    );
    let client = server.client(&f);
    client
        .require_running_release_entitlement(&registry)
        .unwrap();
    for n in 0..66 {
        server.configure(|s| {
            s.version = format!("2.{n}.0");
            s.seq = 2 + n;
        });
        assert_eq!(offer(&client).version, format!("2.{n}.0"));
    }
    let budget = Budget::new(Duration::from_secs(1), &Default::default()).unwrap();
    client
        .0
        .with_state(&budget, |state| {
            assert!(state.running_releases.len() <= 64);
            assert!(state
                .running_releases
                .contains_key(&running_key("stable", "1.0.0")));
            assert!(state
                .running_releases
                .contains_key(&running_key("stable", "2.65.0")));
            assert_eq!(state.installed_seq, 1);
            Ok(())
        })
        .unwrap();
    server.configure(|s| s.status = Some(503));
    server
        .client(&f)
        .require_running_release_entitlement(&registry)
        .unwrap();
}

#[test]
fn a_new_revocation_observed_during_the_final_registry_read_wins_over_cached_authority() {
    let f = Fixture::new();
    let server = Server::new();
    let now = unix_now();
    let registry = registry(
        &f,
        &server,
        json!({"pro":true,"talos_updates":{"mode":"maintenance","until":now+3600}}),
    );
    let mut options = server.options(&f);
    options.app_version = Some("1.1.0".into());
    let client = PublicUpdateClient::new(options).unwrap();
    let changed = client.clone();
    let rpc = server.clone();
    let revoked = server.keyset(now + 1, json!([]));
    server.configure(|s| {
        s.after_second_rpc_check = Some(Arc::new(move || {
            rpc.configure(|s| s.keyset = Some(revoked.clone()));
            assert!(changed.check_for_update(Default::default()).is_err());
        }))
    });
    assert!(client
        .require_running_release_entitlement(&registry)
        .is_err());
    assert_eq!(server.gets(), 0);
}

#[test]
fn an_old_unorderable_version_cannot_bypass_a_known_running_version_using_a_stale_sequence() {
    let f = Fixture::new();
    let server = Server::new();
    server.configure(|s| {
        s.version = "1.0.0-beta.01".into();
        s.seq = 2;
    });
    let mut options = server.options(&f);
    options.app_version = Some("2.0.0".into());
    let client = PublicUpdateClient::new(options).unwrap();
    assert!(client
        .check_for_update(CheckForUpdateOptions {
            current_release_seq: Some(1),
            ..Default::default()
        })
        .is_err());
}
