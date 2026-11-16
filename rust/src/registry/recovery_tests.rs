//! Licenses recoverable from their code: the same code yields the same key and the same
//! registry record anywhere, and a published license is rebuilt with no Talos request.
use super::*;

fn activator() -> String {
    address("77")
}
fn trust() -> RegistryTrust {
    RegistryTrust {
        chain_id: 8453,
        contract: address("11"),
        issuer: address("22"),
        product_id: word("33"),
    }
}
/// The registry identifier and public device key a code determines.
fn identity(code: &str) -> (String, String) {
    let identity = protocol::code_identity(&trust(), code).unwrap();
    let key = SigningKey::from_bytes(&identity.seed);
    (
        identity.license_id,
        protocol::hex(key.verifying_key().as_bytes()),
    )
}
fn recoverable(profile: &Profile, server: Arc<Server>) -> RegistryLicenseOptions {
    RegistryLicenseOptions {
        activator: Some(activator()),
        ..options(profile, server)
    }
}
/// A different computer: its own state file and its own hardware.
fn elsewhere(profile: &Profile, server: Arc<Server>) -> RegistryLicenseOptions {
    let mut opts = recoverable(profile, server);
    for value in opts.fingerprint_components.values_mut() {
        value.push_str(":another-computer");
    }
    opts
}
/// The activation service behaves as it does for a policy with an activator: it publishes
/// `code`'s license under the code-derived identifier, held by the activator.
fn policy(server: &Server, code: &str) {
    let (license_id, _) = identity(code);
    server.with(|m| {
        m.manifest_license_id = license_id;
        m.manifest_holder = activator();
        m.unknown_is_missing = true;
        m.publish_on_activate = true;
    });
}
/// A license already activated somewhere else under `code`.
fn on_chain(server: &Server, code: &str) -> String {
    let (license_id, device) = identity(code);
    server.with(|m| {
        let rights_hash = protocol::keccak_hex(&m.entitlements_json);
        m.published
            .insert(rights_hash.clone(), m.entitlements_json.clone());
        m.records.insert(
            license_id.clone(),
            LicenseRecord {
                device,
                holder: activator(),
                rights_hash,
                not_before: m.not_before,
                expires: 0,
                revision: 2,
                status: 1,
            },
        );
        m.unknown_is_missing = true;
    });
    license_id
}
fn saved(client: &RegistryLicenseClient) -> StoredBinding {
    client.with_binding(|b| Ok(b.clone())).unwrap()
}
fn license_id_of(client: &RegistryLicenseClient) -> String {
    protocol::parse_manifest(&saved(client).registry_manifest.unwrap(), &client.0.trust)
        .unwrap()
        .manifest
        .license_id
}
fn calls(server: &Server) -> (usize, usize) {
    let model = lock(&server.0);
    (model.api_calls, model.rpc_calls)
}

#[test]
fn a_code_activated_once_restores_on_another_computer_from_the_registry_alone() {
    let server = Server::new();
    policy(&server, FIRST_CODE);
    let (license_id, device) = identity(FIRST_CODE);

    // First activation: nothing is on chain yet, so Talos publishes the license.
    let first = Profile::new();
    let origin =
        RegistryLicenseClient::with_code(recoverable(&first, server.clone()), FIRST_CODE).unwrap();
    assert_eq!(origin.device_key(), device, "the key comes from the code");
    assert!(!origin.is_activated());
    assert!(origin.activate(FIRST_CODE).unwrap().entitlement_bool("pro"));
    {
        let model = lock(&server.0);
        assert_eq!(model.activation_posts, 1);
        assert_eq!(model.devices, vec![device.clone()]);
    }
    assert_eq!(license_id_of(&origin), license_id);
    let encrypted = std::fs::read(first.state()).unwrap();
    for secret in [FIRST_CODE.as_bytes(), b"SYNTHET1CF1RSTC0DE"] {
        assert!(
            !encrypted.windows(secret.len()).any(|w| w == secret),
            "the code is never stored"
        );
    }

    // A reinstalled system or another computer: only the code, and no Talos at all.
    server.with(|m| m.api_offline = true);
    let (api_before, _) = calls(&server);
    let second = Profile::new();
    let copy = RegistryLicenseClient::with_code(
        elsewhere(&second, server.clone()),
        " synthetic first code\n",
    )
    .unwrap();
    assert_eq!(copy.device_key(), device);
    assert!(!copy.is_activated());
    let stages = Arc::new(Mutex::new(Vec::new()));
    let progress = stages.clone();
    let restored = copy
        .activate_with_options(
            "synthetic_first_code",
            &RegistryActivationOptions {
                on_progress: Some(Arc::new(move |event| {
                    lock(&progress).push((event.status, event.activation_id))
                })),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(restored.entitlement_bool("pro"));
    assert_eq!(restored.entitlement_i64("seats"), Some(3));
    assert_eq!(
        *lock(&stages),
        vec![
            (RegistryActivationStatus::Validating, String::new()),
            (RegistryActivationStatus::Ready, String::new())
        ]
    );
    assert_eq!(
        protocol::parse_manifest(&saved(&copy).registry_manifest.unwrap(), &copy.0.trust)
            .unwrap()
            .manifest,
        protocol::parse_manifest(&saved(&origin).registry_manifest.unwrap(), &origin.0.trust)
            .unwrap()
            .manifest,
        "the manifest rebuilt from chain data is the one Talos handed out"
    );
    drop(copy);
    let restarted = RegistryLicenseClient::new(elsewhere(&second, server.clone())).unwrap();
    assert!(restarted.is_activated());
    assert!(restarted.require_valid_license().is_ok());
    assert_eq!(
        calls(&server).0,
        api_before,
        "no Talos request on the second computer"
    );

    // The registry stays the authority for every computer the code was typed on.
    server.with(|m| {
        m.head += 1;
        let record = m.records.get_mut(&license_id).unwrap();
        record.status = 3;
        record.revision = 3;
    });
    for client in [&restarted, &origin] {
        assert_eq!(
            client.require_valid_license().unwrap_err().code(),
            "license_revoked"
        );
    }
}

#[test]
fn recoverable_policies_require_the_code_derived_key_and_never_overwrite_another_license() {
    let server = Server::new();
    policy(&server, FIRST_CODE);
    let profile = Profile::new();

    // A client holding a random key would bind the license to something its code cannot
    // reproduce. It is refused before any request leaves the machine.
    let random = RegistryLicenseClient::new(recoverable(&profile, server.clone())).unwrap();
    let before = calls(&server);
    assert_eq!(
        random.activate(FIRST_CODE).unwrap_err().code(),
        "registry_code_identity_required"
    );
    assert_eq!(calls(&server), before);
    let unused = random.device_key().to_owned();
    drop(random);

    // The never-bound random key is replaced by the derived one.
    let client =
        RegistryLicenseClient::with_code(recoverable(&profile, server.clone()), FIRST_CODE)
            .unwrap();
    assert_ne!(client.device_key(), unused);
    assert_eq!(client.device_key(), identity(FIRST_CODE).1);
    client.activate(FIRST_CODE).unwrap();

    // The same code again is a no-op; a different code never silently replaces a license.
    let again = RegistryLicenseClient::with_code(recoverable(&profile, server.clone()), FIRST_CODE)
        .unwrap();
    assert!(again.is_activated());
    assert_eq!(
        RegistryLicenseClient::with_code(recoverable(&profile, server.clone()), SECOND_CODE)
            .unwrap_err()
            .code(),
        "registry_already_activated"
    );
    assert_eq!(license_id_of(&again), identity(FIRST_CODE).0);
    // Keeping the key while changing the license would make the new one unrecoverable.
    let before = calls(&server);
    assert_eq!(
        client.replace_license(SECOND_CODE).unwrap_err().code(),
        "registry_code_replacement_required"
    );
    assert_eq!(calls(&server), before);

    let fresh = Profile::new();
    assert_eq!(
        RegistryLicenseClient::with_code(recoverable(&fresh, server.clone()), " - ")
            .unwrap_err()
            .code(),
        "activation_code_required"
    );
    assert!(!fresh.state().exists(), "a refused code writes nothing");
    for bad in ["0x1234", &address("00"), "not-an-address"] {
        let mut opts = recoverable(&fresh, server.clone());
        opts.activator = Some(bad.into());
        assert_eq!(
            RegistryLicenseClient::new(opts).unwrap_err().code(),
            "invalid_registry_configuration"
        );
    }
}

#[test]
fn the_activation_service_is_asked_only_when_the_registry_holds_nothing_for_this_key() {
    // Each case leaves a record the code's key cannot claim from chain data alone.
    for case in ["another key", "another holder", "bytes not published"] {
        let server = Server::new();
        policy(&server, FIRST_CODE);
        let license_id = on_chain(&server, FIRST_CODE);
        server.with(|m| {
            let record = m.records.get_mut(&license_id).unwrap();
            match case {
                // Activated by an installation that generated a random key.
                "another key" => record.device = word("ab"),
                "another holder" => record.holder = address("22"),
                _ => m.published.clear(),
            }
            m.activation.push_back(Reply::Unavailable);
        });
        let profile = Profile::new();
        let client =
            RegistryLicenseClient::with_code(recoverable(&profile, server.clone()), FIRST_CODE)
                .unwrap();
        assert_eq!(
            client.activate(FIRST_CODE).unwrap_err().code(),
            "registry_activation_unavailable",
            "{case}"
        );
        assert_eq!(lock(&server.0).activation_posts, 1, "{case}");
        assert!(!client.is_activated(), "{case}");
    }
    // Without an activation service configured there is nowhere to fall back to.
    let server = Server::new();
    policy(&server, FIRST_CODE);
    let profile = Profile::new();
    let mut opts = recoverable(&profile, server.clone());
    opts.activation_url = None;
    opts.product_token = None;
    let client = RegistryLicenseClient::with_code(opts.clone(), FIRST_CODE).unwrap();
    assert_eq!(
        client.activate(FIRST_CODE).unwrap_err().code(),
        "registry_activation_not_configured"
    );
    // ...and none is needed once the license is on chain.
    on_chain(&server, FIRST_CODE);
    assert!(client.activate(FIRST_CODE).unwrap().entitlement_bool("pro"));
    assert_eq!(calls(&server).0, 0);
}

#[test]
fn a_wrong_or_missing_activator_contract_is_refused_before_any_activation_request() {
    let registry_runtime = include_str!("test-runtime.hex").trim().to_owned();
    for (runtime, expected) in [
        ("0x".to_owned(), "registry_activator_missing"),
        (registry_runtime, "wrong_registry_activator"),
    ] {
        let server = Server::new();
        policy(&server, FIRST_CODE);
        on_chain(&server, FIRST_CODE);
        server.with(|m| m.activator_runtime = runtime);
        let profile = Profile::new();
        let client =
            RegistryLicenseClient::with_code(recoverable(&profile, server.clone()), FIRST_CODE)
                .unwrap();
        assert_eq!(client.activate(FIRST_CODE).unwrap_err().code(), expected);
        assert_eq!(calls(&server).0, 0, "{expected}");
        assert!(!client.is_activated());
    }
}

#[test]
fn a_recoverable_license_that_is_no_longer_valid_reports_why_and_is_not_installed() {
    for (expected, change) in [
        ("license_revoked", 3u64),
        ("license_suspended", 2),
        ("license_expired", 1),
    ] {
        let server = Server::new();
        policy(&server, FIRST_CODE);
        let license_id = on_chain(&server, FIRST_CODE);
        server.with(|m| {
            let record = m.records.get_mut(&license_id).unwrap();
            record.status = change;
            if expected == "license_expired" {
                record.expires = m.timestamp - 5;
                record.not_before = m.timestamp - 50;
            }
        });
        let profile = Profile::new();
        let client =
            RegistryLicenseClient::with_code(recoverable(&profile, server.clone()), FIRST_CODE)
                .unwrap();
        assert_eq!(client.activate(FIRST_CODE).unwrap_err().code(), expected);
        assert!(!client.is_activated(), "{expected}");
        assert!(saved(&client).registry_manifest.is_none(), "{expected}");
        assert_eq!(calls(&server).0, 0, "the registry already answered");
    }
}

#[test]
fn changing_codes_keeps_the_old_license_until_the_new_one_verifies_then_swaps_the_key() {
    let server = Server::new();
    policy(&server, FIRST_CODE);
    let profile = Profile::new();
    let opts = recoverable(&profile, server.clone());
    let old = RegistryLicenseClient::with_code(opts.clone(), FIRST_CODE).unwrap();
    old.activate(FIRST_CODE).unwrap();
    let (first_id, first_device) = identity(FIRST_CODE);
    let (second_id, second_device) = identity(SECOND_CODE);
    let side = lock_path(&profile.state(), ".next");

    // The new code is not on chain and Talos is unreachable: nothing changes.
    server.with(|m| m.api_offline = true);
    assert_eq!(
        RegistryLicenseClient::replace_with_code(opts.clone(), SECOND_CODE, &short())
            .unwrap_err()
            .code(),
        "registry_activation_unavailable"
    );
    assert!(old.require_valid_license().is_ok());
    assert_eq!(license_id_of(&old), first_id);
    assert_eq!(old.device_key(), first_device);

    // A side file left by an abandoned attempt with some other code is not reused.
    assert!(side.exists());
    assert_eq!(
        RegistryLicenseClient::replace_with_code(opts.clone(), "SYNTHETIC-THIRD-CODE", &short())
            .unwrap_err()
            .code(),
        "registry_activation_unavailable"
    );

    // The new code was activated on another computer earlier: the swap needs no Talos.
    on_chain(&server, SECOND_CODE);
    let high_water = saved(&old).time_high_water;
    let (current, license) =
        RegistryLicenseClient::replace_with_code(opts.clone(), SECOND_CODE, &short()).unwrap();
    assert!(license.entitlement_bool("pro"));
    assert_eq!(current.device_key(), second_device);
    assert_eq!(license_id_of(&current), second_id);
    assert!(saved(&current).time_high_water >= high_water);
    assert!(!side.exists(), "the side file is consumed by the swap");
    assert_eq!(lock(&server.0).activation_posts, 1, "only the first code");
    // Handles opened before the swap hold the old key.
    assert_eq!(
        old.require_valid_license().unwrap_err().code(),
        "device_key_missing"
    );
    drop(current);
    let restarted = RegistryLicenseClient::new(opts.clone()).unwrap();
    assert_eq!(restarted.device_key(), second_device);
    assert!(restarted.require_valid_license().is_ok());
    drop(restarted);

    // The same code again is an ordinary validation, and the old code still exists on
    // chain for whoever holds it.
    let (again, _) = RegistryLicenseClient::replace_with_code(opts, SECOND_CODE, &short()).unwrap();
    assert_eq!(again.device_key(), second_device);
    let other = Profile::new();
    let first_again =
        RegistryLicenseClient::with_code(elsewhere(&other, server.clone()), FIRST_CODE).unwrap();
    assert!(first_again.activate(FIRST_CODE).is_ok());
}
