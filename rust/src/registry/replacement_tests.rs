//! Replacement fixtures keep the old grant and the new grant distinct.
use super::*;

fn saved(client: &RegistryLicenseClient) -> StoredBinding {
    client.with_binding(|b| Ok(b.clone())).unwrap()
}

fn prepare_replacement(server: &Server, client: &RegistryLicenseClient) {
    server.with(|m| {
        m.records.insert(
            word("55"),
            LicenseRecord {
                device: client.device_key().into(),
                holder: address("22"),
                rights_hash: m.rights_hash.clone(),
                not_before: m.not_before,
                expires: 0,
                revision: 1,
                status: 1,
            },
        );
        m.manifest_license_id = word("55");
        m.job = REPLACEMENT_JOB.into();
    });
}

fn assert_current(client: &RegistryLicenseClient, byte: &str) {
    let current = saved(client).registry_manifest.unwrap();
    assert_eq!(
        protocol::parse_manifest(&current, &client.0.trust)
            .unwrap()
            .manifest
            .license_id,
        word(byte)
    );
}

#[test]
fn replacing_revoked_license_preserves_identity_history_and_verified_new_grant_after_restart() {
    let profile = Profile::new();
    let server = Server::new();
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    client.activate(FIRST_CODE).unwrap();
    let old_manifest = saved(&client).registry_manifest.unwrap();
    server.with(|m| {
        m.head += 1;
        m.revision = 3;
        m.status = 3;
    });
    assert_eq!(client.validate().unwrap_err().code(), "license_revoked");
    let previous = saved(&client);
    prepare_replacement(&server, &client);
    let new_license = client.replace_license(SECOND_CODE).unwrap();
    assert!(new_license.entitlement_bool("pro"));
    assert_eq!(new_license.revision, 1);
    assert_current(&client, "55");
    let current = saved(&client);
    assert_eq!(current.machine_key, previous.machine_key);
    assert_eq!(current.machine_public_key, previous.machine_public_key);
    assert!(current.time_high_water >= previous.time_high_water);
    let history = chain::parse_chain_state(current.registry_chain_state.as_deref())
        .unwrap()
        .unwrap();
    assert!(history.licenses[&word("44")].revoked);
    assert_eq!(history.licenses[&word("44")].revision, 3);
    assert_eq!(history.licenses[&word("55")].revision, 1);
    assert!(!client.has_pending_replacement());
    assert!(current.registry_activation_id.is_none());
    assert!(current.license_key_hash.is_empty());
    drop(client);
    server.with(|m| m.api_offline = true);
    let restored = RegistryLicenseClient::new(opts).unwrap();
    assert_current(&restored, "55");
    assert!(restored.validate().unwrap().entitlement_bool("pro"));
    assert_eq!(saved(&restored).machine_key, previous.machine_key);
    // Even an apparently active higher revision cannot revive a terminal ID.
    server.with(|m| {
        m.head += 1;
        m.status = 1;
        m.revision += 1;
    });
    restored.import_license(&old_manifest).unwrap();
    assert_eq!(restored.validate().unwrap_err().code(), "license_revoked");
    let model = lock(&server.0);
    assert_eq!(model.activation_posts, 2);
    assert_eq!(model.devices[0], model.devices[1]);
}

#[test]
fn expired_license_can_be_renewed_or_explicitly_replaced_without_rekeying() {
    let profile = Profile::new();
    let server = Server::new();
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    client.activate(FIRST_CODE).unwrap();
    let identity = saved(&client).machine_key;
    server.with(|m| m.expires = wall_time() - 1);
    assert_eq!(client.validate().unwrap_err().code(), "license_expired");
    server.with(|m| {
        m.revision += 1;
        m.expires = wall_time() + 100;
    });
    assert!(client.validate().is_ok(), "renewal requires no state reset");
    server.with(|m| m.expires = wall_time() - 1);
    prepare_replacement(&server, &client);
    assert!(client.replace_license(SECOND_CODE).is_ok());
    assert_eq!(saved(&client).machine_key, identity);
    assert_current(&client, "55");
}

#[test]
fn invalid_new_code_preserves_the_old_working_license_and_never_stores_the_code() {
    let profile = Profile::new();
    let server = Server::new();
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    client.activate(FIRST_CODE).unwrap();
    let original = saved(&client);
    server.with(|m| m.activation.push_back(Reply::WrongCode));
    assert_eq!(
        client.replace_license(SECOND_CODE).unwrap_err().code(),
        "license_not_found"
    );
    assert_current(&client, "44");
    assert!(client.validate().unwrap().entitlement_bool("pro"));
    let retained = saved(&client);
    assert_eq!(retained.machine_key, original.machine_key);
    assert_eq!(retained.registry_manifest, original.registry_manifest);
    assert!(retained.registry_replacement_id.is_none());
    assert!(retained.license_key_hash.is_empty());
    assert!(!retained.registry_manifest.unwrap().contains(SECOND_CODE));
}

#[test]
fn pending_replacement_keeps_old_license_and_resumes_after_restart_without_new_code() {
    let profile = Profile::new();
    let server = Server::new();
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    client.activate(FIRST_CODE).unwrap();
    let identity = client.device_key().to_owned();
    prepare_replacement(&server, &client);
    server.with(|m| m.activation.push_back(Reply::Pending));
    assert_eq!(
        client
            .replace_with_options(SECOND_CODE, &short())
            .unwrap_err()
            .code(),
        "registry_activation_timeout"
    );
    assert!(client.is_activated());
    assert!(client.has_pending_replacement());
    assert!(!client.has_pending_activation());
    assert_current(&client, "44");
    assert!(client.validate().is_ok());
    let before = lock(&server.0).activation_posts;
    assert_eq!(
        client
            .replace_license("SYNTHETIC-THIRD-CODE")
            .unwrap_err()
            .code(),
        "registry_replacement_pending"
    );
    assert_eq!(lock(&server.0).activation_posts, before);
    drop(client);
    let restored = RegistryLicenseClient::new(opts).unwrap();
    assert_eq!(restored.device_key(), identity);
    assert!(restored.has_pending_replacement());
    assert_current(&restored, "44");
    assert!(restored.resume_replacement().is_ok());
    assert_current(&restored, "55");
    assert!(!restored.has_pending_replacement());
    assert_eq!(lock(&server.0).activation_posts, before);
}

#[test]
fn cancelled_pending_replacement_is_retained_until_explicit_local_discard() {
    let profile = Profile::new();
    let server = Server::new();
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    client.activate(FIRST_CODE).unwrap();
    let original = saved(&client);
    prepare_replacement(&server, &client);
    server.with(|m| m.activation.push_back(Reply::Pending));
    let token = RegistryCancellationToken::new();
    let cancel = token.clone();
    assert_eq!(
        client
            .replace_with_options(
                SECOND_CODE,
                &RegistryActivationOptions {
                    cancellation: Some(token),
                    on_progress: Some(Arc::new(move |_| cancel.cancel())),
                    ..Default::default()
                },
            )
            .unwrap_err()
            .code(),
        "registry_activation_aborted"
    );
    assert!(client.has_pending_replacement());
    assert!(client.validate().is_ok());
    let api_calls = lock(&server.0).api_calls;
    client.discard_pending_replacement().unwrap();
    assert!(!client.has_pending_replacement());
    assert_eq!(
        lock(&server.0).api_calls,
        api_calls,
        "discard is local only"
    );
    assert_eq!(saved(&client).machine_key, original.machine_key);
    assert_eq!(saved(&client).registry_manifest, original.registry_manifest);
    assert!(saved(&client).registry_chain_state.is_some());
    assert!(client.replace_license(SECOND_CODE).is_ok());
}

#[test]
fn missing_replacement_job_clears_only_its_id_and_preserves_current_license() {
    let profile = Profile::new();
    let server = Server::new();
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    client.activate(FIRST_CODE).unwrap();
    prepare_replacement(&server, &client);
    server.with(|m| m.activation.push_back(Reply::Pending));
    client
        .replace_with_options(SECOND_CODE, &short())
        .unwrap_err();
    let original = saved(&client);
    server.with(|m| m.polling.push_back(Reply::MissingJob));
    assert_eq!(
        client.resume_replacement().unwrap_err().code(),
        "activation_not_found"
    );
    let retained = saved(&client);
    assert!(retained.registry_replacement_id.is_none());
    assert_eq!(retained.registry_manifest, original.registry_manifest);
    assert_eq!(retained.machine_key, original.machine_key);
    assert!(client.validate().is_ok());
}

#[test]
fn ready_replacement_does_not_replace_current_license_when_rpc_rejects_new_grant() {
    for (status, expected) in [(0, "license_missing"), (3, "license_revoked")] {
        let profile = Profile::new();
        let server = Server::new();
        let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
        client.activate(FIRST_CODE).unwrap();
        prepare_replacement(&server, &client);
        server.with(|m| m.records.get_mut(&word("55")).unwrap().status = status);
        assert_eq!(
            client.replace_license(SECOND_CODE).unwrap_err().code(),
            expected
        );
        assert_current(&client, "44");
        assert!(client.has_pending_replacement());
        assert!(client.validate().is_ok());
    }
}

#[test]
fn stale_independent_client_cannot_claim_or_clear_another_completed_replacement() {
    let profile = Profile::new();
    let server = Server::new();
    let opts = options(&profile, server.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    client.activate(FIRST_CODE).unwrap();
    let stale = RegistryLicenseClient::new(opts).unwrap();
    prepare_replacement(&server, &client);
    client.replace_license(SECOND_CODE).unwrap();
    let api_before = lock(&server.0).activation_posts;
    assert_eq!(
        stale
            .replace_license("SYNTHETIC-THIRD-CODE")
            .unwrap_err()
            .code(),
        "registry_replacement_state_conflict"
    );
    assert_eq!(
        stale.discard_pending_replacement().unwrap_err().code(),
        "registry_replacement_state_conflict"
    );
    assert_eq!(lock(&server.0).activation_posts, api_before);
    assert_current(&client, "55");
}

struct GatedOldRead {
    server: Arc<Server>,
    armed: AtomicBool,
    entered: std::sync::mpsc::SyncSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}
impl Transport for GatedOldRead {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let body: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
        let data = body["params"][0]["data"].as_str().unwrap_or("");
        if data.starts_with(&selector("getLicense(address,bytes32,bytes32)"))
            && data.ends_with(&word("44")[2..])
            && self.armed.swap(false, Ordering::AcqRel)
        {
            self.entered.send(()).map_err(|_| "test_gate_closed")?;
            lock(&self.release)
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| "test_gate_timeout")?;
        }
        self.server.send(request)
    }
}

#[test]
fn in_flight_validation_from_another_client_cannot_commit_over_a_replacement() {
    let profile = Profile::new();
    let server = Server::new();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let gate = Arc::new(GatedOldRead {
        server: server.clone(),
        armed: AtomicBool::new(false),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let mut opts = options(&profile, server.clone());
    opts.transport = Some(gate.clone());
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    client.activate(FIRST_CODE).unwrap();
    let independent = RegistryLicenseClient::new(opts).unwrap();
    prepare_replacement(&server, &client);
    gate.armed.store(true, Ordering::Release);
    let reader = std::thread::spawn(move || independent.validate());
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let swapped = client.replace_license(SECOND_CODE);
    release_tx.send(()).unwrap();
    swapped.unwrap();
    assert_eq!(
        reader.join().unwrap().unwrap_err().code(),
        "license_changed_during_validation"
    );
    assert_current(&client, "55");
    assert!(client.validate().unwrap().entitlement_bool("pro"));
}

#[test]
fn replacement_durability_failure_keeps_old_manifest_and_pending_job_for_retry() {
    let profile = Profile::new();
    let server = Server::new();
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    client.activate(FIRST_CODE).unwrap();
    prepare_replacement(&server, &client);
    let blocker = lock_path(&profile.state(), ".tmp");
    server.with(|m| m.block_state_write = Some(blocker.clone()));
    assert_eq!(
        client.replace_license(SECOND_CODE).unwrap_err().code(),
        "device_state_not_saved"
    );
    assert_current(&client, "44");
    assert!(client.has_pending_replacement());
    std::fs::remove_dir(blocker).unwrap(); // Exact empty fixture directory only.
    assert!(client.validate().is_ok());
    assert!(client.resume_replacement().is_ok());
    assert_current(&client, "55");
}

#[test]
fn replacement_rpc_outage_keeps_current_binding_and_can_resume_after_recovery() {
    let profile = Profile::new();
    let server = Server::new();
    let mut opts = options(&profile, server.clone());
    opts.rpc_urls = vec![RPC_A.into()];
    let client = RegistryLicenseClient::new(opts).unwrap();
    client.activate(FIRST_CODE).unwrap();
    let previous = saved(&client);
    prepare_replacement(&server, &client);
    server.with(|m| m.fail_primary = true);
    assert!(client
        .replace_license(SECOND_CODE)
        .unwrap_err()
        .is_transient());
    assert_current(&client, "44");
    assert!(client.has_pending_replacement());
    assert_eq!(saved(&client).machine_key, previous.machine_key);
    assert!(
        client.validate().unwrap_err().is_transient(),
        "outage grants no offline access"
    );
    server.with(|m| m.fail_primary = false);
    assert!(client.validate().is_ok());
    assert!(client.resume_replacement().is_ok());
    assert_current(&client, "55");
}

#[test]
fn cancellation_before_replacement_validation_keeps_the_verified_old_manifest() {
    let profile = Profile::new();
    let server = Server::new();
    let client = RegistryLicenseClient::new(options(&profile, server.clone())).unwrap();
    client.activate(FIRST_CODE).unwrap();
    prepare_replacement(&server, &client);
    let token = RegistryCancellationToken::new();
    let cancel = token.clone();
    assert_eq!(
        client
            .replace_with_options(
                SECOND_CODE,
                &RegistryActivationOptions {
                    cancellation: Some(token),
                    on_progress: Some(Arc::new(move |stage| {
                        if stage.status == RegistryActivationStatus::Validating {
                            cancel.cancel();
                        }
                    })),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .code(),
        "registry_activation_aborted"
    );
    assert_current(&client, "44");
    assert!(client.has_pending_replacement());
    assert!(client.validate().is_ok());
    assert!(client.resume_replacement().is_ok());
    assert_current(&client, "55");
}

fn update_state(entitlements: Value) -> RegistryLicenseState {
    RegistryLicenseState {
        entitlements: entitlements.as_object().unwrap().clone(),
        expires_at: None,
        not_before: 1,
        revision: 1,
        block_number: 100,
        block_hash: word("aa"),
        checked_at: wall_time(),
    }
}

#[test]
fn update_entitlements_preserve_legacy_rules_and_fail_closed_on_malformed_metadata() {
    assert_eq!(
        update_state(json!({})).update_publication_cutoff().unwrap(),
        None
    );
    assert_eq!(
        update_state(json!({"talos_updates":{"mode":"license"}}))
            .update_publication_cutoff()
            .unwrap(),
        None
    );
    assert!(update_state(json!({}))
        .require_update_entitlement(1)
        .is_ok());
    assert!(update_state(json!({"updates":true}))
        .require_update_entitlement(1)
        .is_ok());
    assert_eq!(
        update_state(json!({"updates":false,"talos_updates":{"mode":"license"}}))
            .require_update_entitlement(1)
            .unwrap_err()
            .code(),
        "updates_not_entitled"
    );
    assert_eq!(
        update_state(json!({"updates":false}))
            .maintenance_publication_cutoff()
            .unwrap(),
        None
    );
    let old_build =
        update_state(json!({"updates":false,"talos_updates":{"mode":"maintenance","until":100}}));
    assert_eq!(
        old_build.maintenance_publication_cutoff().unwrap(),
        Some(100)
    );
    assert_eq!(
        old_build.update_publication_cutoff().unwrap_err().code(),
        "updates_not_entitled"
    );
    for entitlements in [
        json!({"updates":"yes"}),
        json!({"talos_updates":null}),
        json!({"talos_updates":{"mode":"unknown"}}),
        json!({"talos_updates":{"mode":"license","until":1}}),
        json!({"talos_updates":{"mode":"maintenance","until":0}}),
        json!({"talos_updates":{"mode":"maintenance","until":-1}}),
        json!({"talos_updates":{"mode":"maintenance","until":1.5}}),
        json!({"talos_updates":{"mode":"maintenance","until":9007199254740992u64}}),
    ] {
        assert_eq!(
            update_state(entitlements)
                .require_update_entitlement(1)
                .unwrap_err()
                .code(),
            "invalid_update_entitlement"
        );
    }
    let state = update_state(json!({"talos_updates":{"mode":"maintenance","until":100}}));
    assert_eq!(state.update_publication_cutoff().unwrap(), Some(100));
    assert!(state.require_update_entitlement(99).is_ok());
    assert!(state.require_update_entitlement(100).is_ok());
    assert_eq!(
        state.require_update_entitlement(101).unwrap_err().code(),
        "updates_not_entitled"
    );
    assert_eq!(
        state.require_update_entitlement(0).unwrap_err().code(),
        "invalid_release_timestamp"
    );
}

#[test]
fn maintenance_end_refuses_new_updates_without_expiring_the_runtime_license() {
    let profile = Profile::new();
    let server = Server::new();
    server.with(|m| {
        m.entitlements_json =
            br#"{"pro":true,"talos_updates":{"mode":"maintenance","until":1}}"#.to_vec();
        m.rights_hash = protocol::keccak_hex(&m.entitlements_json);
    });
    let client = RegistryLicenseClient::new(options(&profile, server)).unwrap();
    let state = client.activate(FIRST_CODE).unwrap();
    assert_eq!(state.expires_at, None);
    assert_eq!(
        state.require_update_entitlement(2).unwrap_err().code(),
        "updates_not_entitled"
    );
    assert!(state.require_update_entitlement(1).is_ok());
    assert!(client.validate().unwrap().entitlement_bool("pro"));
}
