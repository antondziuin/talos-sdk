//! The frozen wire vectors, verified by this SDK.
//!
//! Every other verification test here mints a token with a key it generated
//! moments earlier — the SDK agreeing with itself, which it would keep doing if
//! the format changed on both sides at once. This one reads
//! `sdks/contract-vectors.json`: fixed keys and tokens signed by the Rust
//! server's own code and committed to the repository, so drift shows up as four
//! implementations disagreeing with bytes that predate all of them.

use base64::Engine;
use serde_json::Value;
use talos_sdk::compact::{verify_keyset, verify_manifest, verify_token, Claims, PublicKey};
use talos_sdk::{signed_message, REQUEST_DOMAIN};

const VECTORS: &str = include_str!("../../contract-vectors.json");

fn doc() -> Value {
    serde_json::from_str(VECTORS).expect("contract-vectors.json parses")
}

fn key(doc: &Value, name: &str) -> PublicKey {
    PublicKey::from_base64(doc["keys"][name].as_str().unwrap()).unwrap()
}

/// Verify one vector through the entry point the client uses for its class.
fn verify_with(doc: &Value, v: &Value, k: &PublicKey) -> talos_sdk::Result<Claims> {
    let aud = doc["aud"].as_str().unwrap();
    let token = v["token"].as_str().unwrap();
    match v["typ"].as_str().unwrap() {
        "keyset" => verify_keyset(k, aud, token),
        "manifest" => verify_manifest(std::slice::from_ref(k), aud, token),
        typ => verify_token(
            std::slice::from_ref(k),
            typ,
            aud,
            doc["nonce"].as_str().unwrap(),
            token,
        ),
    }
}

fn named<'a>(doc: &'a Value, name: &str) -> &'a Value {
    doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
}

#[test]
fn every_committed_vector_verifies_under_the_key_it_names() {
    let doc = doc();
    let vectors = doc["vectors"].as_array().unwrap();
    for v in vectors {
        let claims = verify_with(&doc, v, &key(&doc, v["key"].as_str().unwrap()))
            .unwrap_or_else(|e| panic!("{}: {e}", v["name"]));
        assert_eq!(claims["typ"], v["typ"], "{}", v["name"]);
        assert_eq!(claims["aud"], doc["aud"], "{}", v["name"]);
    }
    // A file that failed to load must not read as passing vectors.
    assert_eq!(vectors.len(), 7);
}

#[test]
fn no_vector_verifies_under_a_key_it_does_not_name() {
    let doc = doc();
    for v in doc["vectors"].as_array().unwrap() {
        for other in ["license", "anchor", "release"] {
            if v["key"] == other {
                continue;
            }
            assert!(
                verify_with(&doc, v, &key(&doc, other)).is_err(),
                "{} under {other}",
                v["name"]
            );
        }
    }
}

#[test]
fn every_negative_vector_is_refused() {
    let doc = doc();
    let negative = doc["negative"].as_array().unwrap();
    for v in negative {
        assert!(
            verify_with(&doc, v, &key(&doc, v["key"].as_str().unwrap())).is_err(),
            "{}",
            v["name"]
        );
    }
    assert_eq!(negative.len(), 5);
}

#[test]
fn a_machine_document_is_signed_over_the_same_message_as_the_server_builds() {
    // The one document that goes the other way: signed here, verified by the
    // portal. A typo in the domain or version on one side produces a request
    // that side signs happily and the vendor's portal refuses.
    let doc = doc();
    let md = &doc["machine_doc"];
    assert_eq!(md["domain"], REQUEST_DOMAIN);
    let message = signed_message(
        md["domain"].as_str().unwrap(),
        md["payload_b64"].as_str().unwrap(),
    );
    assert_eq!(message, md["signed_message"].as_str().unwrap());

    let raw: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(md["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sig: [u8; 64] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(md["sig"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&raw).unwrap();
    assert!(vk
        .verify_strict(
            message.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&sig)
        )
        .is_ok());
}

/// The claims an application reads, by name. The signature checks above would
/// still pass if a claim were renamed on both sides at once.
#[test]
fn the_claims_an_application_reads_are_where_they_have_always_been() {
    let doc = doc();
    let license = key(&doc, "license");

    let act = verify_with(&doc, named(&doc, "activation"), &license).unwrap();
    assert_eq!(act["lic"]["features"]["pro"], true);
    assert_eq!(act["lic"]["features"]["seats"], 5);
    assert_eq!(act["lic"]["grace_h"], 72);
    assert_eq!(act["lic"]["reval_h"], 24);
    assert!(act["lic"]["lic_exp"].is_null());

    let val = verify_with(&doc, named(&doc, "validation"), &license).unwrap();
    assert_eq!(val["decision"], "valid");
    assert!(val["grace_until"].as_i64().unwrap() > val["server_time"].as_i64().unwrap());

    let beat = verify_with(&doc, named(&doc, "heartbeat"), &license).unwrap();
    assert_eq!(beat["heartbeat_interval_s"], 3600);
    assert_eq!(beat["upd"], true);

    let lease = verify_with(&doc, named(&doc, "lease"), &license).unwrap();
    assert_eq!(lease["max_seats"], 3);
    assert_eq!(lease["seats_in_use"], 1);
    assert_eq!(lease["inst"], "inst-1");

    // How an anchor-only application learns the licence key. If this moves, a
    // rotation stops reaching the field and every install fails at once.
    let keyset = verify_with(&doc, named(&doc, "keyset"), &key(&doc, "anchor")).unwrap();
    assert!(keyset["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["purpose"] == "license"
            && k["status"] == "active"
            && k["pk"] == doc["keys"]["license"]));

    let man = verify_with(&doc, named(&doc, "manifest"), &key(&doc, "release")).unwrap();
    assert_eq!(man["version"], "1.2.0");
    assert_eq!(man["release_seq"], 7);
    assert_eq!(man["artifacts"][0]["filename"], "notes-1.2.0-x64.exe");
    assert_eq!(man["artifacts"][0]["sha256"].as_str().unwrap().len(), 64);
}
