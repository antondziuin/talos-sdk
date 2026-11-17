//! The offline allowance: a term of the license, measured from the last valid
//! observation, and nothing a file or a clock can extend.
use super::*;

const DAY: u64 = 86_400;

/// Issue the fixture license with the given entitlement text, as a policy with
/// that offline term would stamp it.
fn with_terms(server: &Server, entitlements: &str) {
    server.with(|m| {
        m.entitlements_json = entitlements.as_bytes().to_vec();
        m.rights_hash = protocol::keccak_hex(entitlements.as_bytes());
    });
}

fn allowing(days: u64) -> String {
    format!(r#"{{"pro":true,"talos_offline":{{"days":{days}}}}}"#)
}

fn unplug(server: &Server) {
    server.with(|m| m.rpc_offline = true);
}

/// Bring the network back with a chain that has moved on by `seconds`, so its
/// head is fresh against a client whose clock was moved the same way.
fn reconnect(server: &Server, seconds: u64) {
    server.with(|m| {
        m.rpc_offline = false;
        m.block_times.insert(m.head, m.timestamp);
        m.timestamp += seconds;
        m.head += 1 + seconds / 2;
    });
}

fn stored(client: &RegistryLicenseClient) -> StoredBinding {
    client.with_binding(|b| Ok(b.clone())).unwrap()
}

#[test]
fn a_license_without_the_term_is_refused_the_moment_no_provider_answers() {
    let profile = Profile::new();
    let server = Server::new();
    let client = imported(&profile, server.clone());
    let fresh = client.validate().unwrap();
    assert_eq!(fresh.offline_allowance_days(), None);
    assert_eq!(fresh.offline_until, None);
    // Nothing is kept that a later, more generous reading could reinterpret.
    assert!(stored(&client).registry_offline.is_none());

    unplug(&server);
    let refused = client.validate().unwrap_err();
    assert_eq!(refused.code(), "registry_rpc_unavailable");
    assert!(refused.is_transient());
    assert_eq!(
        client.require_valid_license().unwrap_err().code(),
        "registry_rpc_unavailable"
    );
}

#[test]
fn the_last_valid_check_stands_for_the_stated_days_and_not_a_second_longer() {
    // Any whole number of days: the publisher picks it, the SDK does not round it.
    for days in [1, 7, 45, 400] {
        let profile = Profile::new();
        let server = Server::new();
        with_terms(&server, &allowing(days));
        let client = imported(&profile, server.clone());

        let fresh = client.validate().unwrap();
        assert_eq!(fresh.offline_allowance_days(), Some(days as u32));
        assert!(!fresh.is_offline());

        unplug(&server);
        let offline = client.require_valid_license().unwrap();
        assert!(offline.is_offline());
        assert_eq!(
            offline.offline_until,
            Some(fresh.checked_at + days * DAY),
            "{days} days from the last fresh check"
        );
        // It repeats the observation it stands on, entitlements included.
        assert_eq!(offline.checked_at, fresh.checked_at);
        assert_eq!(offline.revision, fresh.revision);
        assert_eq!(offline.block_hash, fresh.block_hash);
        assert!(offline.entitlement_bool("pro"));
        // A caller that wants the chain's answer and nothing else still gets a refusal.
        assert!(client.require_fresh_license().unwrap_err().is_transient());

        client.skip_time(days * DAY - 120);
        assert!(
            client.validate().unwrap().is_offline(),
            "{days} days: still inside"
        );
        client.skip_time(240);
        let expired = client.validate().unwrap_err();
        assert_eq!(expired.code(), "offline_period_expired", "{days} days");
        assert!(!expired.is_transient());

        // A fresh check starts the period again from its own time.
        reconnect(&server, days * DAY + 120);
        let renewed = client.validate().unwrap();
        assert_eq!(renewed.offline_until, None);
        assert!(renewed.checked_at >= fresh.checked_at + days * DAY);
        unplug(&server);
        assert_eq!(
            client.validate().unwrap().offline_until,
            Some(renewed.checked_at + days * DAY)
        );
    }
}

#[test]
fn time_already_spent_offline_survives_a_restart_and_a_clock_set_back() {
    let profile = Profile::new();
    let server = Server::new();
    with_terms(&server, &allowing(7));
    let opts = options(&profile, server.clone());
    // Activated by code, so the license itself is in the device state and a
    // new process finds it there.
    let client = RegistryLicenseClient::new(opts.clone()).unwrap();
    let fresh = client.activate(FIRST_CODE).unwrap();
    assert_eq!(fresh.offline_allowance_days(), Some(7));
    unplug(&server);

    // Three days in, used offline once: that moment is written down.
    client.skip_time(3 * DAY);
    assert!(client.validate().unwrap().is_offline());
    drop(client);

    // A new process reads the real wall clock, which is three days "earlier".
    // It must start from the recorded time, not from the clock on the wall.
    let restarted = RegistryLicenseClient::new(opts.clone()).unwrap();
    let again = restarted.validate().unwrap();
    assert_eq!(again.offline_until, Some(fresh.checked_at + 7 * DAY));
    restarted.skip_time(4 * DAY + 60);
    assert_eq!(
        restarted.validate().unwrap_err().code(),
        "offline_period_expired"
    );
    drop(restarted);

    // And once it has run out, restarting does not bring it back.
    let later = RegistryLicenseClient::new(opts).unwrap();
    assert_eq!(
        later.validate().unwrap_err().code(),
        "offline_period_expired"
    );
}

#[test]
fn the_allowance_never_outlives_the_license_itself() {
    let profile = Profile::new();
    let server = Server::new();
    with_terms(&server, &allowing(30));
    let expires = wall_time() + 2 * DAY;
    server.with(|m| m.expires = expires);
    let client = imported(&profile, server.clone());
    assert_eq!(client.validate().unwrap().expires_at, Some(expires));

    unplug(&server);
    let offline = client.validate().unwrap();
    assert_eq!(
        offline.offline_until,
        Some(expires),
        "the earlier of the two"
    );
    assert_eq!(offline.expires_at, Some(expires));

    client.skip_time(2 * DAY + 60);
    let refused = client.validate().unwrap_err();
    assert_eq!(refused.code(), "license_expired");
    assert!(!refused.is_transient());
}

#[test]
fn a_refusal_read_from_the_chain_ends_the_allowance_at_once() {
    let profile = Profile::new();
    let server = Server::new();
    with_terms(&server, &allowing(30));
    let client = imported(&profile, server.clone());
    client.validate().unwrap();
    assert!(stored(&client).registry_offline.is_some());

    // The publisher revokes; the device hears it once.
    server.with(|m| {
        m.head += 1;
        m.revision = 3;
        m.status = 3;
    });
    assert_eq!(client.validate().unwrap_err().code(), "license_revoked");
    assert!(stored(&client).registry_offline.is_none());

    // Pulling the cable afterwards buys nothing.
    unplug(&server);
    assert!(client.validate().is_err());
    assert!(client.require_valid_license().is_err());
    drop(client);
    let restarted = RegistryLicenseClient::new(options(&profile, server)).unwrap();
    assert!(restarted.validate().is_err());
}

#[test]
fn a_malformed_term_grants_nothing() {
    for terms in [
        r#"{"pro":true,"talos_offline":{"days":0}}"#,
        r#"{"pro":true,"talos_offline":{"days":36501}}"#,
        r#"{"pro":true,"talos_offline":{"days":-7}}"#,
        r#"{"pro":true,"talos_offline":{"days":"7"}}"#,
        r#"{"pro":true,"talos_offline":{"days":1.5}}"#,
        r#"{"pro":true,"talos_offline":{"days":7,"hours":12}}"#,
        r#"{"pro":true,"talos_offline":{}}"#,
        r#"{"pro":true,"talos_offline":7}"#,
        r#"{"pro":true,"talos_offline":true}"#,
        r#"{"pro":true,"offline_days":7}"#,
    ] {
        let profile = Profile::new();
        let server = Server::new();
        with_terms(&server, terms);
        let client = imported(&profile, server.clone());
        let fresh = client.validate().unwrap();
        assert_eq!(fresh.offline_allowance_days(), None, "{terms}");
        assert!(stored(&client).registry_offline.is_none(), "{terms}");
        unplug(&server);
        assert!(client.validate().unwrap_err().is_transient(), "{terms}");
    }
}

#[test]
fn a_basis_for_another_license_or_other_terms_grants_nothing() {
    let profile = Profile::new();
    let server = Server::new();
    with_terms(&server, &allowing(30));
    let client = imported(&profile, server.clone());
    client.validate().unwrap();
    let genuine = stored(&client).registry_offline.unwrap();
    unplug(&server);
    assert!(client.validate().unwrap().is_offline());

    let rewrite = |change: &dyn Fn(&mut Value)| {
        let mut basis: Value = serde_json::from_str(&genuine).unwrap();
        change(&mut basis);
        client
            .with_binding(|b| {
                b.registry_offline = Some(basis.to_string());
                client.save_binding(b)
            })
            .unwrap();
    };
    rewrite(&|basis| basis["licenseId"] = json!(word("55")));
    assert!(client.validate().unwrap_err().is_transient());
    rewrite(&|basis| basis["entitlementsHash"] = json!(word("66")));
    assert!(client.validate().unwrap_err().is_transient());
    rewrite(&|basis| basis["v"] = json!(2));
    assert!(client.validate().unwrap_err().is_transient());
    rewrite(&|basis| {
        basis.as_object_mut().unwrap().remove("checkedAt");
    });
    assert!(client.validate().unwrap_err().is_transient());

    client
        .with_binding(|b| {
            b.registry_offline = Some("not json".into());
            client.save_binding(b)
        })
        .unwrap();
    assert!(client.validate().unwrap_err().is_transient());

    // The genuine one, restored, works again: it was the edits that were refused.
    rewrite(&|_| {});
    assert!(client.validate().unwrap().is_offline());
}

#[test]
fn a_license_never_checked_on_this_device_has_nothing_to_stand_on() {
    let profile = Profile::new();
    let server = Server::new();
    with_terms(&server, &allowing(30));
    let client = imported(&profile, server.clone());
    // Imported, but offline before its first successful check.
    unplug(&server);
    let refused = client.validate().unwrap_err();
    assert!(refused.is_transient());
    assert!(stored(&client).registry_offline.is_none());
}
