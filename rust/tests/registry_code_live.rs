//! Opt-in bridge for the server's end-to-end test of code recovery. It is driven by a real
//! Talos API, a real publisher worker and a local chain that the harness started; alone it
//! does nothing. No transaction is ever sent from here: the SDK only reads the chain.
#![cfg(all(feature = "registry", feature = "ureq"))]

use std::{collections::BTreeMap, path::Path};

use serde_json::{json, Value};
use talos_sdk::{RegistryLicenseClient, RegistryLicenseOptions};

fn fingerprint(machine: &str) -> BTreeMap<String, String> {
    [
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
    .map(|id| (id.to_owned(), format!("code-bridge:{machine}:{id}")))
    .collect()
}

fn text(fixture: &Value, name: &str) -> String {
    fixture[name]
        .as_str()
        .unwrap_or_else(|| panic!("fixture field {name}"))
        .to_owned()
}

/// One computer. `talos` decides whether this computer can reach the activation service
/// at all: without it the SDK has no URL to send a request to.
fn computer(fixture: &Value, machine: &str, talos: bool) -> RegistryLicenseOptions {
    RegistryLicenseOptions {
        issuer: text(fixture, "issuer"),
        product_id: text(fixture, "product_id"),
        chain_id: fixture["chain_id"].as_u64().unwrap(),
        contract: text(fixture, "contract"),
        rpc_urls: vec![text(fixture, "rpc_url")],
        state_path: Some(Path::new(&text(fixture, "state_dir")).join(format!("{machine}.state"))),
        fingerprint_components: fingerprint(machine),
        activation_url: talos.then(|| text(fixture, "api_url")),
        product_token: talos.then(|| text(fixture, "product_token")),
        activator: Some(text(fixture, "activator")),
        ..Default::default()
    }
}

#[test]
fn a_code_activated_through_talos_is_restored_elsewhere_from_the_chain_alone() {
    let Ok(path) = std::env::var("TALOS_REGISTRY_CODE_BRIDGE") else {
        eprintln!("skipping: run by the server's registry_code_recovery_flow test");
        return;
    };
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let code = text(&fixture, "license_key");

    // A client with a random key must not create an activation its code cannot recover.
    let random = RegistryLicenseClient::new(computer(&fixture, "random", true)).unwrap();
    assert_eq!(
        random.activate(&code).unwrap_err().code(),
        "registry_code_identity_required"
    );

    // The same mistake in an application built without the activator address. That SDK
    // cannot know the policy is recoverable, so the server is what refuses the random key,
    // before anything is queued or published.
    let mut unaware = computer(&fixture, "unaware", true);
    unaware.activator = None;
    let unaware = RegistryLicenseClient::new(unaware).unwrap();
    assert_eq!(
        unaware.activate(&code).unwrap_err().code(),
        "registry_code_identity_required"
    );

    // First computer: nothing is on chain, so Talos publishes the license.
    let first = RegistryLicenseClient::with_code(computer(&fixture, "first", true), &code).unwrap();
    let device = first.device_key().to_owned();
    let license = first.activate(&code).unwrap();
    assert!(license.entitlement_bool("pro"));
    assert_eq!(license.entitlement_i64("seats"), Some(7));

    // Second computer: the same code typed in lower case without dashes, and no
    // activation service configured at all. Everything comes from the registry.
    let typed = code.replace('-', "").to_ascii_lowercase();
    let second =
        RegistryLicenseClient::with_code(computer(&fixture, "second", false), &typed).unwrap();
    assert_eq!(second.device_key(), device);
    assert!(!second.is_activated());
    let restored = second.activate(&typed).unwrap();
    assert_eq!(restored.entitlements, license.entitlements);
    assert_eq!(restored.revision, license.revision);
    assert_eq!(restored.expires_at, license.expires_at);
    drop(second);
    let restarted = RegistryLicenseClient::new(computer(&fixture, "second", false)).unwrap();
    assert!(restarted.is_activated());
    let checked = restarted.require_valid_license().unwrap();

    // A wrong code derives a key and an identifier nothing on chain answers to, and this
    // computer has nowhere else to ask.
    let wrong =
        RegistryLicenseClient::with_code(computer(&fixture, "third", false), "WRONG-CODE-0000")
            .unwrap();
    assert_eq!(
        wrong.activate("WRONG-CODE-0000").unwrap_err().code(),
        "registry_activation_not_configured"
    );

    println!(
        "TALOS_CODE_BRIDGE={}",
        json!({
            "device_key": device,
            "revision": checked.revision,
            "block_number": checked.block_number,
            "expires_at": checked.expires_at,
            "second_computer_talos_requests": 0,
        })
    );
}
