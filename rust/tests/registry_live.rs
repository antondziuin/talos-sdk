//! Opt-in read-only protocol smoke against a configured publisher and registry.
//! The only activation request uses a freshly randomized INVALID synthetic code.
//! It cannot create a real license or send an Ethereum transaction.
#![cfg(all(feature = "registry", feature = "ureq"))]

use std::{collections::BTreeMap, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;
use talos_sdk::{RegistryLicenseClient, RegistryLicenseOptions};

struct Profile(PathBuf);
impl Profile {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).unwrap();
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let root = std::env::temp_dir().join(format!("talos-registry-live-{suffix}"));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        let root = self.0.canonicalize().unwrap();
        let temporary = std::env::temp_dir().canonicalize().unwrap();
        assert_eq!(root.parent(), Some(temporary.as_path()));
        assert!(root
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("talos-registry-live-"));
        let _ = std::fs::remove_dir_all(root);
    }
}

fn required(name: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| panic!("{name} is required for the opt-in smoke"))
}

#[test]
fn real_rpc_refuses_unissued_manifest_and_real_api_refuses_synthetic_invalid_code() {
    if std::env::var("TALOS_REGISTRY_LIVE").as_deref() != Ok("1") {
        eprintln!("skipping: set TALOS_REGISTRY_LIVE=1 and the public smoke configuration");
        return;
    }
    let profile = Profile::new();
    let issuer = required("TALOS_REGISTRY_SMOKE_ISSUER");
    let contract = required("TALOS_REGISTRY_SMOKE_CONTRACT");
    let product = required("TALOS_REGISTRY_SMOKE_PRODUCT_ID");
    let chain: u64 = required("TALOS_REGISTRY_SMOKE_CHAIN_ID").parse().unwrap();
    let fingerprint: BTreeMap<_, _> = [
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
    .map(|id| (id.to_owned(), "SYNTHETIC-RUST-REGISTRY-SMOKE".to_owned()))
    .collect();
    let client = RegistryLicenseClient::new(RegistryLicenseOptions {
        issuer: issuer.clone(),
        contract: contract.clone(),
        product_id: product.clone(),
        chain_id: chain,
        rpc_urls: vec![required("TALOS_REGISTRY_SMOKE_RPC")],
        activation_url: Some(required("TALOS_REGISTRY_SMOKE_API")),
        product_token: Some(required("TALOS_REGISTRY_SMOKE_PRODUCT_TOKEN")),
        state_path: Some(profile.0.join("state.bin")),
        fingerprint_components: fingerprint,
        ..Default::default()
    })
    .unwrap();
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).unwrap();
    let random_hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let invalid = format!("SYNTHETIC-INVALID-{random_hex}");
    let error = client.activate(&invalid).unwrap_err();
    assert_eq!(error.code(), "license_not_found");
    assert!(!client.is_activated());
    assert!(!client.has_pending_activation());
    let manifest = json!({
        "v":1,"kind":"talos-registry-license","chain_id":chain,"contract":contract,
        "issuer":issuer,"product_id":product,"license_id":format!("0x{random_hex}"),
        "holder":issuer,"entitlements":URL_SAFE_NO_PAD.encode(b"{\"pro\":true}")
    });
    client.import_license(&manifest.to_string()).unwrap();
    assert_eq!(
        client.require_valid_license().unwrap_err().code(),
        "license_missing"
    );
}
