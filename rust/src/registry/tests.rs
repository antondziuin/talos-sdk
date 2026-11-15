//! End-to-end SDK fixtures. Every HTTP response is synthetic; no real code or transaction.

use super::*;
use std::{collections::VecDeque, sync::Barrier};

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::json;

const API: &str = "https://publisher.example";
const RPC_A: &str = "https://rpc-a.example";
const RPC_B: &str = "https://rpc-b.example";
const TOKEN: &str = "tpt_registry_client_fixture";
const JOB: &str = "11111111-1111-4111-8111-111111111111";
const FIRST_CODE: &str = "SYNTHETIC-FIRST-CODE";
const SECOND_CODE: &str = "SYNTHETIC-SECOND-CODE";
const REPLACEMENT_JOB: &str = "22222222-2222-4222-8222-222222222222";

fn address(byte: &str) -> String {
    format!("0x{}", byte.repeat(20))
}
fn word(byte: &str) -> String {
    format!("0x{}", byte.repeat(32))
}
fn uint(value: u64) -> String {
    format!("{value:064x}")
}
fn selector(signature: &str) -> String {
    protocol::keccak_hex(signature.as_bytes())[..10].into()
}
fn address_word(value: &str) -> String {
    format!("{}{}", "0".repeat(24), &value[2..])
}

struct Profile(PathBuf);
impl Profile {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "talos-rust-registry-{}",
            &protocol::hex(&random)[2..]
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn state(&self) -> PathBuf {
        self.0.join("state.dat")
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        // This exact newly-created test root is the only recursive cleanup target.
        assert_eq!(self.0.parent(), Some(std::env::temp_dir().as_path()));
        assert!(self
            .0
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("talos-rust-registry-"));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
enum Reply {
    Pending,
    Ready,
    MissingJob,
    WrongCode,
    Failed,
    Unavailable,
}
#[derive(Clone)]
struct LicenseRecord {
    device: String,
    holder: String,
    rights_hash: String,
    not_before: u64,
    expires: u64,
    revision: u64,
    status: u64,
}
struct Model {
    activation: VecDeque<Reply>,
    polling: VecDeque<Reply>,
    api_offline: bool,
    api_calls: usize,
    activation_posts: usize,
    status_posts: usize,
    rpc_calls: usize,
    rpc_b_calls: usize,
    code_hashes: Vec<String>,
    devices: Vec<String>,
    device: String,
    holder: String,
    rights_hash: String,
    entitlements_json: Vec<u8>,
    runtime: String,
    chain: u64,
    version: u64,
    head: u64,
    timestamp: u64,
    not_before: u64,
    expires: u64,
    revision: u64,
    status: u64,
    check: bool,
    fail_primary: bool,
    bad_manifest: Option<&'static str>,
    block_state_write: Option<PathBuf>,
    manifest_license_id: String,
    job: String,
    records: BTreeMap<String, LicenseRecord>,
    checkins: Vec<Value>,
}
struct Server(Mutex<Model>);
impl Server {
    fn new() -> Arc<Self> {
        let now = wall_time();
        Arc::new(Self(Mutex::new(Model {
            activation: VecDeque::new(),
            polling: VecDeque::new(),
            api_offline: false,
            api_calls: 0,
            activation_posts: 0,
            status_posts: 0,
            rpc_calls: 0,
            rpc_b_calls: 0,
            code_hashes: Vec::new(),
            devices: Vec::new(),
            device: word("00"),
            holder: address("22"),
            rights_hash: protocol::keccak_hex(br#"{"pro":true,"seats":3}"#),
            entitlements_json: br#"{"pro":true,"seats":3}"#.to_vec(),
            runtime: include_str!("test-runtime.hex").trim().to_owned(),
            chain: 8453,
            version: 1,
            head: 100,
            timestamp: now,
            not_before: now.saturating_sub(1),
            expires: 0,
            revision: 2,
            status: 1,
            check: true,
            fail_primary: false,
            bad_manifest: None,
            block_state_write: None,
            manifest_license_id: word("44"),
            job: JOB.into(),
            records: BTreeMap::new(),
            checkins: Vec::new(),
        })))
    }
    fn with(&self, action: impl FnOnce(&mut Model)) {
        action(&mut lock(&self.0));
    }
    fn manifest(model: &Model) -> Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut value = json!({"v":1,"kind":"talos-registry-license","chain_id":8453,"contract":address("11"),
            "issuer":address("22"),"product_id":word("33"),"license_id":model.manifest_license_id,"holder":address("22"),
            "entitlements":URL_SAFE_NO_PAD.encode(&model.entitlements_json)});
        if let Some(field) = model.bad_manifest {
            value[field] = match field {
                "chain_id" => json!(11155111),
                "product_id" => json!(word("55")),
                _ => json!(address("55")),
            };
        }
        value
    }
    fn reply(model: &Model, reply: Reply) -> HttpResponse {
        let (status, body) = match reply {
            Reply::Pending => (
                200,
                json!({"status":"pending","activation_id":model.job,"manifest":null,"error":null,"retry_after_s":0}),
            ),
            Reply::Ready => (
                200,
                json!({"status":"ready","activation_id":model.job,"manifest":Self::manifest(model),"error":null,"retry_after_s":0}),
            ),
            Reply::MissingJob => (404, json!({"error":"activation_not_found"})),
            Reply::WrongCode => (404, json!({"error":"license_not_found"})),
            Reply::Failed => (
                200,
                json!({"status":"failed","activation_id":model.job,"manifest":null,"error":"synthetic_worker_failure","retry_after_s":0}),
            ),
            Reply::Unavailable => (503, json!({"error":"registry_activation_unavailable"})),
        };
        HttpResponse::from_bytes(status, body.to_string())
    }
    fn record(model: &Model, id: &str) -> LicenseRecord {
        if let Some(record) = model.records.get(id) {
            return record.clone();
        }
        assert_eq!(id, word("44"));
        LicenseRecord {
            device: model.device.clone(),
            holder: model.holder.clone(),
            rights_hash: model.rights_hash.clone(),
            not_before: model.not_before,
            expires: model.expires,
            revision: model.revision,
            status: model.status,
        }
    }
}
fn verify_proof(body: &Value, status: bool) {
    let bytes = protocol::decode_hex(body["device_key"].as_str().unwrap()).unwrap();
    let key = VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap();
    let bytes = protocol::decode_hex(body["proof"].as_str().unwrap()).unwrap();
    let signature = Signature::from_slice(&bytes).unwrap();
    let message = if status {
        assert!(body.get("license_key").is_none());
        protocol::status_proof_text(
            TOKEN,
            body["activation_id"].as_str().unwrap(),
            body["device_key"].as_str().unwrap(),
        )
        .unwrap()
    } else {
        protocol::activation_proof_text(
            TOKEN,
            body["license_key"].as_str().unwrap(),
            body["device_key"].as_str().unwrap(),
            body["request_id"].as_str().unwrap(),
        )
        .unwrap()
    };
    key.verify_strict(message.as_bytes(), &signature).unwrap();
}
impl Transport for Server {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        assert_eq!(request.method, "POST");
        assert!(request
            .timeout
            .is_some_and(|timeout| timeout > Duration::ZERO && timeout <= Duration::from_secs(10)));
        let body: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
        let mut model = lock(&self.0);
        if request.url.starts_with(API) {
            model.api_calls += 1;
            if model.api_offline {
                return Err("SYNTHETIC_HTTP_CREDENTIAL_MUST_NOT_ESCAPE".into());
            }
            assert_eq!(body["product_token"], TOKEN);
            if request.url.ends_with("/activate") {
                verify_proof(&body, false);
                model.activation_posts += 1;
                model.code_hashes.push(protocol::keccak_hex(
                    body["license_key"].as_str().unwrap().as_bytes(),
                ));
                let device = body["device_key"].as_str().unwrap().to_owned();
                model.devices.push(device.clone());
                model.device = device;
                let reply = model.activation.pop_front().unwrap_or(Reply::Ready);
                return Ok(Self::reply(&model, reply));
            }
            if request.url.ends_with("/checkin") {
                let device = body["device_key"].as_str().unwrap();
                let message = protocol::checkin_proof_text(
                    TOKEN,
                    body["license_id"].as_str().unwrap(),
                    device,
                    body["install_id"].as_str().unwrap(),
                    body["timestamp"].as_u64().unwrap(),
                )
                .unwrap();
                let key = VerifyingKey::from_bytes(
                    protocol::decode_hex(device)
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .unwrap(),
                )
                .unwrap();
                let proof = protocol::decode_hex(body["proof"].as_str().unwrap()).unwrap();
                key.verify_strict(message.as_bytes(), &Signature::from_slice(&proof).unwrap())
                    .unwrap();
                model.checkins.push(body);
                return Ok(HttpResponse::from_bytes(204, Vec::new()));
            }
            assert!(request.url.ends_with("/activation-status"));
            verify_proof(&body, true);
            model.status_posts += 1;
            let reply = model.polling.pop_front().unwrap_or(Reply::Ready);
            return Ok(Self::reply(&model, reply));
        }
        assert!(
            [RPC_A, RPC_B].contains(&request.url.as_str()),
            "unexpected endpoint"
        );
        model.rpc_calls += 1;
        if request.url == RPC_B {
            model.rpc_b_calls += 1;
        }
        if request.url == RPC_A && model.fail_primary {
            return Err("synthetic_rpc_unavailable".into());
        }
        let result = match body["method"].as_str().unwrap() {
            "eth_chainId" => json!(format!("0x{:x}", model.chain)),
            "eth_getBlockByNumber" => {
                let tag = body["params"][0].as_str().unwrap();
                let number = if tag == "latest" {
                    model.head
                } else {
                    u64::from_str_radix(&tag[2..], 16).unwrap()
                };
                json!({"number":format!("0x{number:x}"),"hash":format!("0x{number:064x}"),"timestamp":format!("0x{:x}",model.timestamp)})
            }
            "eth_getCode" => {
                assert_eq!(body["params"][0], address("11"));
                assert_eq!(body["params"][1], format!("0x{:x}", model.head));
                json!(model.runtime)
            }
            "eth_call" => {
                assert_eq!(body["params"][0]["to"], address("11"));
                assert_eq!(body["params"][1], format!("0x{:x}", model.head));
                let data = body["params"][0]["data"].as_str().unwrap();
                if data == selector("registryVersion()") {
                    json!(format!("0x{}", uint(model.version)))
                } else if data.starts_with(&selector("getLicense(address,bytes32,bytes32)")) {
                    let id = format!("0x{}", &data[138..202]);
                    let record = Self::record(&model, &id);
                    assert_eq!(
                        data,
                        format!(
                            "{}{}{}{}",
                            selector("getLicense(address,bytes32,bytes32)"),
                            address_word(&address("22")),
                            &word("33")[2..],
                            &id[2..]
                        )
                    );
                    json!(format!(
                        "0x{}{}{}{}{}{}{}",
                        address_word(&record.holder),
                        &record.device[2..],
                        uint(record.not_before),
                        uint(record.expires),
                        &record.rights_hash[2..],
                        uint(record.revision),
                        uint(record.status)
                    ))
                } else {
                    let id = format!("0x{}", &data[138..202]);
                    Self::record(&model, &id);
                    assert_eq!(
                        data,
                        format!(
                            "{}{}{}{}{}{}{}",
                            selector(
                                "checkLicense(address,bytes32,bytes32,address,bytes32,bytes32)"
                            ),
                            address_word(&address("22")),
                            &word("33")[2..],
                            &id[2..],
                            address_word(&address("22")),
                            &model.device[2..],
                            &protocol::keccak_hex(&model.entitlements_json)[2..]
                        )
                    );
                    if let Some(path) = model.block_state_write.take() {
                        std::fs::create_dir(path).unwrap();
                    }
                    json!(format!("0x{}", uint(u64::from(model.check))))
                }
            }
            _ => panic!("SDK attempted a mutating or unsupported RPC method"),
        };
        Ok(HttpResponse::from_bytes(
            200,
            json!({"jsonrpc":"2.0","id":1,"result":result}).to_string(),
        ))
    }
}
fn options(profile: &Profile, server: Arc<Server>) -> RegistryLicenseOptions {
    RegistryLicenseOptions {
        issuer: address("22"),
        product_id: word("33"),
        chain_id: 8453,
        contract: address("11"),
        rpc_urls: vec![RPC_A.into(), RPC_B.into()],
        state_path: Some(profile.state()),
        fingerprint_components: [
            "machine_guid",
            "smbios_uuid",
            "disk_serial",
            "mac_set",
            "cpu",
            "mem_bucket",
            "os_install",
            "hostname",
        ]
        .into_iter()
        .map(|id| (id.to_owned(), format!("registry-test:{id}")))
        .collect(),
        transport: Some(server),
        activation_url: Some(API.into()),
        product_token: Some(TOKEN.into()),
        ..Default::default()
    }
}
fn short() -> RegistryActivationOptions {
    RegistryActivationOptions {
        timeout: Some(Duration::from_millis(250)),
        ..Default::default()
    }
}
fn imported(profile: &Profile, server: Arc<Server>) -> RegistryLicenseClient {
    let client = RegistryLicenseClient::new(options(profile, server.clone())).unwrap();
    server.with(|model| model.device = client.device_key().into());
    client
        .import_license(&Server::manifest(&lock(&server.0)).to_string())
        .unwrap();
    client
}

#[path = "replacement_tests.rs"]
mod replacement;

#[test]
fn activation_requires_real_rpc_then_persists_and_restart_uses_rpc_without_talos() {
    let profile = Profile::new();
    let server = Server::new();
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    let device = client.device_key().to_owned();
    let stages = Arc::new(Mutex::new(Vec::new()));
    let progress = stages.clone();
    let result = client
        .activate_with_options(
            FIRST_CODE,
            &RegistryActivationOptions {
                on_progress: Some(Arc::new(move |event| lock(&progress).push(event.status))),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(result.entitlement_bool("pro"));
    assert_eq!(result.entitlement_i64("seats"), Some(3));
    assert_eq!(result.expires_at, None);
    assert!(client.is_activated());
    assert!(!client.has_pending_activation());
    assert_eq!(
        *lock(&stages),
        vec![
            RegistryActivationStatus::Validating,
            RegistryActivationStatus::Ready
        ]
    );
    let encrypted = std::fs::read(profile.state()).unwrap();
    assert!(!encrypted
        .windows(FIRST_CODE.len())
        .any(|window| window == FIRST_CODE.as_bytes()));
    assert!(!String::from_utf8_lossy(&encrypted).contains("registry_manifest"));
    drop(client);
    let (api_before, rpc_before) = {
        let model = lock(&server.0);
        (model.api_calls, model.rpc_calls)
    };
    server.with(|model| model.api_offline = true);
    let restarted = RegistryLicenseClient::new(opts).unwrap();
    assert_eq!(restarted.device_key(), device);
    assert!(restarted.is_activated());
    assert!(restarted
        .require_valid_license()
        .unwrap()
        .entitlement_bool("pro"));
    let model = lock(&server.0);
    assert_eq!(model.api_calls, api_before);
    assert!(model.rpc_calls > rpc_before);
    assert_eq!(model.activation_posts, 1);
}

#[test]
fn portable_file_validates_on_another_machine_through_rpc_alone_and_never_calls_talos() {
    let first = Profile::new();
    let server = Server::new();
    let origin = RegistryLicenseClient::new(options(&first, server.clone())).unwrap();
    assert_eq!(
        origin.export_portable_license().unwrap_err().code(),
        "registry_manifest_required",
        "nothing to export before activation"
    );
    origin.activate(FIRST_CODE).unwrap();
    let file = origin.export_portable_license().unwrap();
    assert!(!file.contains(FIRST_CODE), "the code is never in the file");

    // A different computer: its own profile, its own hardware, and no Talos.
    let other_machine = |profile: &Profile| {
        let mut opts = options(profile, server.clone());
        for value in opts.fingerprint_components.values_mut() {
            value.push_str(":another-computer");
        }
        opts
    };
    let (api_before, posts_before) = {
        let model = lock(&server.0);
        (model.api_calls, model.activation_posts)
    };
    server.with(|model| model.api_offline = true);
    let second = Profile::new();
    let copy =
        RegistryLicenseClient::import_portable_license(other_machine(&second), &file).unwrap();
    assert_eq!(copy.device_key(), origin.device_key());
    assert!(copy.is_activated());
    assert!(copy
        .require_valid_license()
        .unwrap()
        .entitlement_bool("pro"));
    // The same file again is a no-op, and the state survives a restart.
    drop(copy);
    let again =
        RegistryLicenseClient::import_portable_license(other_machine(&second), &file).unwrap();
    assert!(again.require_valid_license().is_ok());
    {
        let model = lock(&server.0);
        assert_eq!(model.api_calls, api_before, "no Talos request on the copy");
        assert_eq!(model.activation_posts, posts_before);
    }

    // The registry stays the authority: revoking the record stops every copy.
    server.with(|model| model.status = 3);
    assert!(again.require_valid_license().is_err());
    assert!(origin.require_valid_license().is_err());
    assert!(
        origin.export_portable_license().is_err(),
        "an invalid license is not exported"
    );

    // A file is never trusted for its pins, and a damaged one is refused.
    let third = Profile::new();
    let mut foreign = other_machine(&third);
    foreign.issuer = address("77");
    assert!(RegistryLicenseClient::import_portable_license(foreign, &file).is_err());
    assert_eq!(
        RegistryLicenseClient::import_portable_license(
            other_machine(&third),
            &file.replace("talos-registry-portable-license", "talos-registry-license"),
        )
        .unwrap_err()
        .code(),
        "invalid_portable_license"
    );
    assert!(!third.state().exists(), "a refused file writes nothing");
}

#[test]
fn launch_report_is_signed_names_the_install_and_never_decides_access() {
    let first = Profile::new();
    let server = Server::new();
    let origin = RegistryLicenseClient::new(options(&first, server.clone())).unwrap();
    assert!(origin.report_launch(None).is_err(), "nothing to report yet");
    origin.activate(FIRST_CODE).unwrap();
    origin.report_launch(Some("1.2.3")).unwrap();
    origin.report_launch(Some("1.2.3")).unwrap();

    // The same portable key on another computer reports as a different install.
    let second = Profile::new();
    let mut opts = options(&second, server.clone());
    for value in opts.fingerprint_components.values_mut() {
        value.push_str(":another-computer");
    }
    let copy = RegistryLicenseClient::import_portable_license(
        opts,
        &origin.export_portable_license().unwrap(),
    )
    .unwrap();
    copy.report_launch(None).unwrap();
    {
        let model = lock(&server.0);
        let reports = &model.checkins;
        assert_eq!(reports.len(), 3);
        assert_eq!(reports[0]["license_id"], word("44"));
        assert_eq!(reports[0]["app_version"], "1.2.3");
        assert!(reports[2]["app_version"].is_null());
        assert_eq!(reports[0]["install_id"], reports[1]["install_id"]);
        assert_ne!(reports[0]["install_id"], reports[2]["install_id"]);
        assert_eq!(reports[0]["device_key"], reports[2]["device_key"]);
        assert_eq!(reports[0]["install_id"].as_str().unwrap().len(), 64);
    }

    // Talos unreachable: the report fails and the license still validates.
    server.with(|model| model.api_offline = true);
    assert_eq!(
        copy.report_launch(None).unwrap_err().code(),
        "registry_checkin_unavailable"
    );
    assert!(copy.require_valid_license().is_ok());
}

#[test]
fn pending_timeout_retains_id_and_resumes_after_restart_without_another_code_claim() {
    let profile = Profile::new();
    let server = Server::new();
    server.with(|m| m.activation.push_back(Reply::Pending));
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    let device = client.device_key().to_owned();
    assert_eq!(
        client
            .activate_with_options(FIRST_CODE, &short())
            .unwrap_err()
            .code(),
        "registry_activation_timeout"
    );
    assert!(!client.is_activated());
    assert!(client.has_pending_activation());
    drop(client);
    let client = RegistryLicenseClient::new(opts).unwrap();
    assert_eq!(client.device_key(), device);
    assert!(client.has_pending_activation());
    assert!(client.resume_activation().unwrap().entitlement_bool("pro"));
    let model = lock(&server.0);
    assert_eq!(model.activation_posts, 1);
    assert_eq!(model.status_posts, 1);
}

#[test]
fn unknown_saved_job_clears_only_pending_id_and_new_code_works_with_the_same_device() {
    let profile = Profile::new();
    let server = Server::new();
    server.with(|m| {
        m.activation.push_back(Reply::Pending);
        m.polling.push_back(Reply::MissingJob);
    });
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    let device = client.device_key().to_owned();
    assert_eq!(
        client
            .activate_with_options(FIRST_CODE, &short())
            .unwrap_err()
            .code(),
        "registry_activation_timeout"
    );
    drop(client);
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    assert_eq!(
        client.resume_activation().unwrap_err().code(),
        "activation_not_found"
    );
    assert!(!client.has_pending_activation());
    assert!(!client.is_activated());
    drop(client);
    let client = RegistryLicenseClient::new(opts).unwrap();
    assert_eq!(client.device_key(), device);
    assert!(!client.has_pending_activation());
    assert!(client
        .activate(SECOND_CODE)
        .unwrap()
        .entitlement_bool("pro"));
    let model = lock(&server.0);
    assert_eq!(model.activation_posts, 2);
    assert_eq!(model.devices, vec![device.clone(), device]);
    assert_ne!(model.code_hashes[0], model.code_hashes[1]);
}

#[test]
fn unknown_job_from_the_same_claim_poll_loop_is_cleared_before_a_restart_and_new_code() {
    let profile = Profile::new();
    let server = Server::new();
    server.with(|m| {
        m.activation.push_back(Reply::Pending);
        m.polling.push_back(Reply::MissingJob);
    });
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    let device = client.device_key().to_owned();
    assert_eq!(
        client.activate(FIRST_CODE).unwrap_err().code(),
        "activation_not_found"
    );
    assert!(!client.has_pending_activation());
    drop(client);
    let client = RegistryLicenseClient::new(opts).unwrap();
    assert_eq!(client.device_key(), device);
    assert!(client.activate(SECOND_CODE).is_ok());
    assert_eq!(lock(&server.0).activation_posts, 2);
}

#[test]
fn transient_poll_failure_keeps_the_job_and_invalid_code_does_not_create_a_pending_id() {
    let profile = Profile::new();
    let server = Server::new();
    server.with(|m| {
        m.activation.push_back(Reply::WrongCode);
        m.activation.push_back(Reply::Pending);
        m.polling.push_back(Reply::Unavailable);
    });
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    assert!(client.optional_snapshot().0.is_none());
    assert_eq!(
        client.activate(FIRST_CODE).unwrap_err().code(),
        "license_not_found"
    );
    assert!(!client.has_pending_activation());
    assert_eq!(
        client
            .activate_with_options(FIRST_CODE, &short())
            .unwrap_err()
            .code(),
        "registry_activation_timeout"
    );
    assert_eq!(
        client.resume_activation().unwrap_err().code(),
        "registry_activation_unavailable"
    );
    assert!(client.has_pending_activation());
    assert!(client.resume_activation().is_ok());
    assert_eq!(lock(&server.0).activation_posts, 2);
}

#[test]
fn ready_claim_cannot_activate_a_missing_expired_revoked_or_other_device_record() {
    for (status, device, expiry, expected) in [
        (0, None, 0, "license_missing"),
        (3, None, 0, "license_revoked"),
        (1, Some(word("55")), 0, "wrong_device"),
        (1, Some(word("00")), 0, "device_not_bound"),
        (1, None, 1, "license_expired"),
    ] {
        let profile = Profile::new();
        let server = Server::new();
        let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
        server.with(|m| {
            m.status = status;
            m.expires = expiry;
        });
        // A public imported manifest exercises the same fresh authorization path with a chosen device record.
        server.with(|m| m.device = device.unwrap_or_else(|| client.device_key().into()));
        client
            .import_license(&Server::manifest(&lock(&server.0)).to_string())
            .unwrap();
        assert_eq!(client.require_valid_license().unwrap_err().code(), expected);
    }
    let profile = Profile::new();
    let server = Server::new();
    server.with(|m| m.status = 0);
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    assert_eq!(
        client.activate(FIRST_CODE).unwrap_err().code(),
        "license_missing"
    );
    assert!(!client.is_activated());
    assert!(client.has_pending_activation());
    drop(client);
    let restarted = RegistryLicenseClient::new(opts).unwrap();
    assert!(
        !restarted.is_activated(),
        "an unconfirmed ready claim must not be restored as a manifest"
    );
    assert!(restarted.has_pending_activation());
    server.with(|m| m.status = 1);
    assert!(restarted.resume_activation().is_ok());
    assert_eq!(lock(&server.0).activation_posts, 1);
}

#[test]
fn cancellation_after_ready_claim_cannot_commit_or_expose_an_unchecked_manifest() {
    let profile = Profile::new();
    let server = Server::new();
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    let observer = client.clone();
    let token = RegistryCancellationToken::new();
    let cancel = token.clone();
    let options = RegistryActivationOptions {
        cancellation: Some(token),
        on_progress: Some(Arc::new(move |event| {
            if event.status == RegistryActivationStatus::Validating {
                assert!(!observer.is_activated());
                assert_eq!(
                    observer.validate().unwrap_err().code(),
                    "registry_manifest_required"
                );
                cancel.cancel();
            }
        })),
        ..Default::default()
    };
    assert_eq!(
        client
            .activate_with_options(FIRST_CODE, &options)
            .unwrap_err()
            .code(),
        "registry_activation_aborted"
    );
    assert!(!client.is_activated());
    assert!(client.has_pending_activation());
    assert_eq!(lock(&server.0).rpc_calls, 0);
    drop(options);
    drop(client);
    let restarted = RegistryLicenseClient::new(opts).unwrap();
    assert!(!restarted.is_activated());
    assert!(restarted.has_pending_activation());
    assert!(restarted.resume_activation().is_ok());
    assert_eq!(lock(&server.0).activation_posts, 1);
}

#[test]
fn manifest_pins_runtime_version_holder_rights_and_contract_check_are_enforced() {
    for field in ["issuer", "product_id", "contract", "chain_id"] {
        let profile = Profile::new();
        let server = Server::new();
        server.with(|m| m.bad_manifest = Some(field));
        let client = RegistryLicenseClient::new(options(&profile, server)).unwrap();
        assert_eq!(
            client.activate(FIRST_CODE).unwrap_err().code(),
            "invalid_registry_manifest"
        );
        assert!(!client.is_activated());
    }
    for (variant, expected) in [
        (0, "wrong_registry_runtime"),
        (1, "wrong_registry_version"),
        (2, "wrong_license_holder"),
        (3, "invalid_entitlements_hash"),
        (4, "registry_license_rejected"),
        (5, "wrong_rpc_chain"),
        (6, "license_not_started"),
        (7, "license_suspended"),
    ] {
        let profile = Profile::new();
        let server = Server::new();
        let client = imported(&profile, server.clone());
        server.with(|m| match variant {
            0 => m.runtime = "0x6000".into(),
            1 => m.version = 2,
            2 => m.holder = address("55"),
            3 => m.rights_hash = word("55"),
            4 => m.check = false,
            5 => m.chain = 11155111,
            6 => m.not_before = m.timestamp + 30,
            _ => m.status = 2,
        });
        assert_eq!(client.require_valid_license().unwrap_err().code(), expected);
    }
}

#[test]
fn newer_revocation_and_head_floors_survive_restarts_and_cannot_be_revived_by_a_stale_provider() {
    let profile = Profile::new();
    let server = Server::new();
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    client.activate(FIRST_CODE).unwrap();
    server.with(|m| {
        m.head = 102;
        m.revision = 3;
        m.status = 3;
    });
    assert_eq!(client.validate().unwrap_err().code(), "license_revoked");
    drop(client);
    let client = RegistryLicenseClient::new(opts).unwrap();
    server.with(|m| {
        m.head = 100;
        m.revision = 2;
        m.status = 1;
    });
    assert_eq!(client.validate().unwrap_err().code(), "rpc_block_lag");
    server.with(|m| {
        m.head = 103;
        m.revision = 4;
    });
    assert_eq!(client.validate().unwrap_err().code(), "license_revoked");
}

#[test]
fn rpc_fallback_is_allowed_for_network_failure_but_never_for_authoritative_revocation() {
    let profile = Profile::new();
    let server = Server::new();
    let client = imported(&profile, server.clone());
    server.with(|m| m.fail_primary = true);
    assert!(client.validate().is_ok());
    assert!(lock(&server.0).rpc_b_calls > 0);
    server.with(|m| {
        m.fail_primary = false;
        m.rpc_b_calls = 0;
        m.status = 3;
        m.revision = 3;
    });
    assert_eq!(client.validate().unwrap_err().code(), "license_revoked");
    assert_eq!(lock(&server.0).rpc_b_calls, 0);
}

#[test]
fn cancellation_and_deadlines_refuse_before_transport_and_pending_cancellation_is_resumable() {
    let profile = Profile::new();
    let server = Server::new();
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    let token = RegistryCancellationToken::new();
    token.cancel();
    assert_eq!(
        client
            .activate_with_options(
                FIRST_CODE,
                &RegistryActivationOptions {
                    cancellation: Some(token),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .code(),
        "registry_activation_aborted"
    );
    for timeout in [Duration::ZERO, Duration::from_secs(601)] {
        assert_eq!(
            client
                .activate_with_options(
                    FIRST_CODE,
                    &RegistryActivationOptions {
                        timeout: Some(timeout),
                        ..Default::default()
                    }
                )
                .unwrap_err()
                .code(),
            "invalid_registry_activation_timeout"
        );
    }
    assert_eq!(lock(&server.0).api_calls, 0);
    server.with(|m| m.activation.push_back(Reply::Pending));
    let token = RegistryCancellationToken::new();
    let cancel = token.clone();
    let opts = RegistryActivationOptions {
        cancellation: Some(token),
        on_progress: Some(Arc::new(move |event| {
            if event.status == RegistryActivationStatus::Pending {
                cancel.cancel();
            }
        })),
        ..Default::default()
    };
    assert_eq!(
        client
            .activate_with_options(FIRST_CODE, &opts)
            .unwrap_err()
            .code(),
        "registry_activation_aborted"
    );
    assert!(client.has_pending_activation());
    assert!(!client.is_activated());
    assert!(client.resume_activation().is_ok());
}

#[test]
fn unreadable_state_or_failure_to_persist_a_valid_observation_never_grants_access() {
    let profile = Profile::new();
    let server = Server::new();
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    server.with(|m| m.block_state_write = Some(lock_path(&profile.state(), ".tmp")));
    assert_eq!(
        client.activate(FIRST_CODE).unwrap_err().code(),
        "device_state_not_saved"
    );
    assert!(!client.is_activated());
    assert!(client.has_pending_activation());
    std::fs::remove_dir(lock_path(&profile.state(), ".tmp")).unwrap();
    drop(client);
    let mut bytes = std::fs::read(profile.state()).unwrap();
    bytes[20] ^= 1;
    std::fs::write(profile.state(), bytes).unwrap();
    assert_eq!(
        RegistryLicenseClient::new(opts).unwrap_err().code(),
        "invalid_device_state"
    );
}

#[test]
fn parallel_clients_sharing_a_profile_create_only_one_activation_claim() {
    let profile = Profile::new();
    let server = Server::new();
    let opts = options(&profile, server.clone());
    let first = RegistryLicenseClient::new(opts.clone()).unwrap();
    let second = RegistryLicenseClient::new(opts).unwrap();
    assert_eq!(first.device_key(), second.device_key());
    let barrier = Arc::new(Barrier::new(3));
    let a = barrier.clone();
    let b = barrier.clone();
    let first = std::thread::spawn(move || {
        a.wait();
        first.activate(FIRST_CODE)
    });
    let second = std::thread::spawn(move || {
        b.wait();
        second.activate(FIRST_CODE)
    });
    barrier.wait();
    assert!(first.join().unwrap().is_ok());
    assert!(second.join().unwrap().is_ok());
    assert_eq!(lock(&server.0).activation_posts, 1);
}

#[test]
fn terminal_worker_failure_forgets_the_pending_id_and_keeps_the_device() {
    let profile = Profile::new();
    let server = Server::new();
    server.with(|m| m.activation.push_back(Reply::Failed));
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    let device = client.device_key().to_owned();
    assert_eq!(
        client.activate(FIRST_CODE).unwrap_err().code(),
        "registry_activation_failed"
    );
    assert!(!client.has_pending_activation());
    assert_eq!(client.device_key(), device);
    assert!(client.activate(SECOND_CODE).is_ok());
}

#[test]
fn contended_state_lock_respects_short_activation_timeout_and_cancellation() {
    use std::sync::mpsc;

    for cancelled in [false, true] {
        let profile = Profile::new();
        let server = Server::new();
        let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
        let token = RegistryCancellationToken::new();
        let state_lock = FileLock::acquire(&lock_path(&profile.state(), ".lock"), None).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = client.clone();
        let cancellation = token.clone();
        let started = Instant::now();
        let handle = std::thread::spawn(move || {
            entered_tx.send(()).unwrap();
            let result = worker.activate_with_options(
                FIRST_CODE,
                &RegistryActivationOptions {
                    timeout: Some(if cancelled {
                        Duration::from_secs(5)
                    } else {
                        Duration::from_millis(25)
                    }),
                    cancellation: Some(cancellation),
                    ..Default::default()
                },
            );
            finished_tx.send(result).unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        if cancelled {
            std::thread::sleep(Duration::from_millis(20));
            token.cancel();
        }
        // Release the held lock even when a regression fails this deadline, so no worker is stranded.
        let result = finished_rx.recv_timeout(Duration::from_millis(800));
        drop(state_lock);
        handle.join().unwrap();
        let error = result
            .expect("activation ignored its deadline while waiting for state lock")
            .unwrap_err();
        assert_eq!(
            error.code(),
            if cancelled {
                "registry_activation_aborted"
            } else {
                "registry_activation_timeout"
            }
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!client.is_activated());
        assert!(!client.has_pending_activation());
        assert_eq!(lock(&server.0).api_calls, 0);
        assert_eq!(lock(&server.0).rpc_calls, 0);
    }
}

#[test]
fn stale_ready_commit_cannot_replace_a_new_import_or_clear_its_retained_job() {
    let profile = Profile::new();
    let server = Server::new();
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    let budget = Budget {
        deadline: Instant::now() + Duration::from_secs(3),
        cancellation: None,
    };
    let stale_generation = client.0.generation.load(Ordering::Acquire);
    let old_raw = Server::manifest(&lock(&server.0)).to_string();
    let old_candidate = protocol::parse_manifest(&old_raw, &client.0.trust).unwrap();
    client
        .save_activation(JOB, None, false, &budget, stale_generation)
        .unwrap();
    let mut newer = Server::manifest(&lock(&server.0));
    newer["license_id"] = json!(word("55"));
    client.import_license(&newer.to_string()).unwrap();
    let (before, generation) = client.snapshot().unwrap();
    assert_eq!(before.manifest.license_id, word("55"));
    assert!(generation > stale_generation);
    assert_eq!(
        client
            .commit_ready(old_candidate, &old_raw, JOB, &budget, stale_generation)
            .unwrap_err()
            .code(),
        "registry_activation_interrupted"
    );
    let (after, after_generation) = client.snapshot().unwrap();
    assert_eq!(after.manifest, before.manifest);
    assert_eq!(after_generation, generation);
    client
        .with_binding(|binding| {
            assert_eq!(binding.registry_activation_id.as_deref(), Some(JOB));
            assert!(binding.registry_manifest.is_none());
            Ok(())
        })
        .unwrap();
    assert_eq!(lock(&server.0).api_calls, 0);
    assert_eq!(lock(&server.0).rpc_calls, 0);
}

#[test]
fn concurrent_snapshot_keeps_each_manifest_paired_with_its_generation() {
    let profile = Profile::new();
    let server = Server::new();
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    let first = Server::manifest(&lock(&server.0));
    let mut second = first.clone();
    second["license_id"] = json!(word("55"));
    let (first, second) = (first.to_string(), second.to_string());
    client.import_license(&first).unwrap(); // Generation one is the first lookup.
    let done = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(3));
    let mut readers = Vec::new();
    for _ in 0..2 {
        let reader = client.clone();
        let done = done.clone();
        let barrier = barrier.clone();
        readers.push(std::thread::spawn(move || {
            barrier.wait();
            let mut observations = 0;
            while !done.load(Ordering::Acquire) || observations < 2000 {
                let (candidate, generation) = reader.snapshot().unwrap();
                assert_eq!(
                    candidate.manifest.license_id,
                    if generation % 2 == 0 {
                        word("55")
                    } else {
                        word("44")
                    }
                );
                observations += 1;
            }
            observations
        }));
    }
    barrier.wait();
    for index in 0..1000 {
        client
            .import_license(if index % 2 == 0 { &second } else { &first })
            .unwrap();
        std::thread::yield_now();
    }
    done.store(true, Ordering::Release);
    for reader in readers {
        assert!(reader.join().unwrap() >= 2000);
    }
}

#[cfg(feature = "ureq")]
#[test]
fn built_in_registry_transport_does_not_follow_a_loopback_redirect_with_the_code() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    let profile = Profile::new();
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    origin.set_nonblocking(true).unwrap();
    target.set_nonblocking(true).unwrap();
    let origin_url = format!("http://{}", origin.local_addr().unwrap());
    let target_url = format!("http://{}/must-not-receive", target.local_addr().unwrap());
    let responder = std::thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match origin.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("synthetic loopback origin did not accept: {error}"),
            }
        };
        // Accepted sockets inherit nonblocking mode on Windows. A read before
        // the client writes must wait instead of racing with WouldBlock.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
            assert!(bytes.len() <= 16_384);
            if let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..header_end]).to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:").map(str::trim))
                    .unwrap()
                    .parse()
                    .unwrap();
                if bytes.len() >= header_end + 4 + length {
                    break;
                }
            }
        }
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("POST /v1/client/registry/activate "));
        assert!(text.contains(FIRST_CODE));
        let body = "{\"error\":\"synthetic_redirect\"}";
        write!(stream, "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    });
    let mut opts = options(&profile, Server::new());
    opts.activation_url = Some(origin_url);
    opts.rpc_urls = vec![format!("http://{}", target.local_addr().unwrap())];
    opts.transport = None; // Exercise RegistryLicenseClient's real default factory.
    let client = RegistryLicenseClient::new(opts).unwrap();
    let error = client
        .activate_with_options(
            FIRST_CODE,
            &RegistryActivationOptions {
                timeout: Some(Duration::from_secs(3)),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(error.code(), "registry_activation_http_error");
    responder.join().unwrap();
    assert!(
        matches!(target.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "redirect target received an unexpected connection"
    );
    assert!(!client.is_activated());
    assert!(!client.has_pending_activation());
}
