//! Cross-language contract test: drives the real `/v1/client` API and verifies
//! the signed tokens with the product's actual keys.
//!
//! Runs only with `TALOS_CONTRACT=1` and the configuration `sdks/csharp/contract.sh`
//! exports, which builds a demo product and starts the server. Without it every
//! case returns early and says so — this cannot run in the public mirror, where
//! the server is not available.

#![cfg(feature = "ureq")]

use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use talos_sdk::transport::UreqTransport;
use talos_sdk::{
    AcquireLeaseOptions, CheckForUpdateOptions, Decision, Error, EventKind, HttpRequest,
    HttpResponse, TalosClient, TalosEvent, TalosOptions, Transport,
};

/// One case at a time. They share a licence and, being one process, one
/// machine fingerprint — a real activation in one rotates the activation secret
/// another is holding, which would fail it for a reason nothing here tests.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn enabled() -> bool {
    let on = std::env::var("TALOS_CONTRACT").as_deref() == Ok("1");
    if !on {
        eprintln!("skipping: TALOS_CONTRACT is not set (run sdks/csharp/contract.sh)");
    }
    on
}

fn env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!("{name} must be set for the contract test"),
    }
}

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("talos-rust-contract-{}-{name}", std::process::id()))
}

fn options(state: &str) -> TalosOptions {
    // Pin ONLY the anchor: the demo rotated both signing keys, so verifying at
    // all proves the client learned them from the anchor-signed keyset.
    TalosOptions {
        product_token: env("TALOS_PRODUCT_TOKEN"),
        anchor_public_key: Some(env("TALOS_ANCHOR_PUBLIC_KEY")),
        server_url: env("TALOS_SERVER_URL"),
        app_version: Some("1.0.0".into()),
        state_path: Some(temp(state).join("state.bin")),
        ..Default::default()
    }
}

#[test]
fn activate_validate_update_lease_deactivate() {
    if !enabled() {
        return;
    }
    let _serial = serial();
    let opts = options("roundtrip");
    let _ = std::fs::remove_dir_all(temp("roundtrip"));
    let client = TalosClient::new(opts.clone()).unwrap();
    assert!(!client.is_activated());

    let activated = client.activate(&env("TALOS_LICENSE_KEY")).unwrap();
    assert!(activated.is_valid());
    assert!(client.is_feature_enabled("pro"));
    assert_eq!(activated.entitlement_i64("seats"), Some(5));

    client.refresh_keyset().unwrap();
    assert_eq!(client.validate().unwrap().decision, Decision::Valid);

    // The next launch: a client that never calls activate.
    let restarted = TalosClient::new(opts.clone()).unwrap();
    assert!(restarted.is_activated());
    assert_eq!(restarted.machine_id(), client.machine_id());
    assert_eq!(restarted.validate().unwrap().decision, Decision::Valid);

    // activate() on an existing binding re-validates. The proof is the FIRST
    // client: a real activation would have rotated the secret it holds.
    assert_eq!(
        restarted
            .activate(&env("TALOS_LICENSE_KEY"))
            .unwrap()
            .decision,
        Decision::Valid
    );
    assert_eq!(client.validate().unwrap().decision, Decision::Valid);

    // Updates: check → verified manifest → download → SHA-256.
    let upd = client
        .check_for_update(CheckForUpdateOptions {
            current_version: Some(env("TALOS_CURRENT_VERSION")),
            ..Default::default()
        })
        .unwrap()
        .expect("the demo publishes an update");
    assert_eq!(upd.version, env("TALOS_UPDATE_VERSION"));
    assert!(upd.release_seq > 0);
    let artifact = upd.artifacts.first().expect("an artifact").clone();
    let dest = temp(&format!("dl-{}", artifact.filename));
    let got = client
        .download_update(&upd, &dest, Some(&artifact), None)
        .unwrap();
    assert_eq!(std::fs::metadata(&dest).unwrap().len(), got.size);
    let _ = std::fs::remove_file(&dest);

    // Anti-downgrade: a floor at the latest yields nothing.
    let none = client
        .check_for_update(CheckForUpdateOptions {
            current_release_seq: Some(upd.release_seq),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(none, None);

    // A heartbeat with a listener carries the update hint — two routes and a
    // signed claim the server only sets when asked.
    let announced = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&announced);
    let _ = client.on(EventKind::UpdateAvailable, move |e| {
        if let TalosEvent::UpdateAvailable(info) = e {
            sink.lock().unwrap().push(info.version.clone());
        }
    });
    assert_eq!(client.heartbeat().unwrap().decision, Decision::Valid);
    assert_eq!(
        *announced.lock().unwrap(),
        vec![env("TALOS_UPDATE_VERSION")]
    );

    // Floating seats: the demo policy has max_concurrent_seats = 1.
    let lease = |inst: &str| {
        client.acquire_lease(
            AcquireLeaseOptions::new()
                .instance_id(inst)
                .auto_renew(false),
        )
    };
    let first = lease("inst-1").unwrap();
    assert_eq!((first.max_seats, first.seats_in_use), (1, 1));
    assert_eq!(
        lease("inst-1").unwrap().seats_in_use,
        1,
        "the same instance renews"
    );
    assert_eq!(lease("inst-2").unwrap_err().status(), Some(409));
    client.release_lease().unwrap();
    assert_eq!(lease("inst-2").unwrap().seats_in_use, 1);
    client.release_lease().unwrap();

    client.deactivate().unwrap();
    assert!(matches!(client.validate(), Err(Error::NotActivated)));
    assert!(!TalosClient::new(opts).unwrap().is_activated());
    let _ = std::fs::remove_dir_all(temp("roundtrip"));
}

/// The real transport with a seam where a hostile network would be: the
/// request reaches the real server, and only the answer is altered.
type Alter = Box<dyn Fn(String) -> String + Send>;

struct Meddler {
    real: UreqTransport,
    alter: Mutex<Option<Alter>>,
}

impl Transport for Meddler {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let mut response = self.real.send(request)?;
        let mut body = String::new();
        response
            .body
            .read_to_string(&mut body)
            .map_err(|e| e.to_string())?;
        if let Some(alter) = self.alter.lock().unwrap().as_ref() {
            body = alter(body);
        }
        Ok(HttpResponse::from_bytes(response.status, body))
    }
}

fn meddled(state: &str) -> (TalosClient, Arc<Meddler>) {
    let meddler = Arc::new(Meddler {
        real: UreqTransport::new(),
        alter: Mutex::new(None),
    });
    let _ = std::fs::remove_dir_all(temp(state));
    let mut opts = options(state);
    opts.transport = Some(Arc::clone(&meddler) as Arc<dyn Transport>);
    (TalosClient::new(opts).unwrap(), meddler)
}

/// Flip one character of the signature of every token in a body.
fn flip_signatures(body: String) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body.as_str();
    while let Some(start) = rest.find("talos.1.") {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail.find('"').unwrap_or(tail.len());
        let token = &tail[..end];
        let (head, sig) = token.rsplit_once('.').unwrap();
        let flipped = if sig.starts_with('A') { 'B' } else { 'A' };
        out.push_str(&format!("{head}.{flipped}{}", &sig[1..]));
        rest = &tail[end..];
    }
    out.push_str(rest);
    assert_ne!(
        out, body,
        "nothing was altered, so the test would prove nothing"
    );
    out
}

#[test]
fn a_real_answer_changed_on_the_way_back_is_refused() {
    if !enabled() {
        return;
    }
    let _serial = serial();
    let (client, meddler) = meddled("meddled");
    assert!(client
        .activate(&env("TALOS_LICENSE_KEY"))
        .unwrap()
        .is_valid());
    *meddler.alter.lock().unwrap() = Some(Box::new(flip_signatures));
    // No cached verdict yet, so the refusal is what the caller sees.
    assert!(matches!(client.validate(), Err(Error::Signature(_))));
    let _ = std::fs::remove_dir_all(temp("meddled"));
}

#[test]
fn a_real_answer_replayed_for_a_later_request_does_not_land_as_live() {
    if !enabled() {
        return;
    }
    let _serial = serial();
    let (client, meddler) = meddled("replayed");
    assert!(client
        .activate(&env("TALOS_LICENSE_KEY"))
        .unwrap()
        .is_valid());
    assert!(!client.validate().unwrap().is_offline);

    let tape: Arc<Mutex<Option<String>>> = Arc::default();
    let recording = Arc::clone(&tape);
    *meddler.alter.lock().unwrap() = Some(Box::new(move |body| {
        recording.lock().unwrap().get_or_insert(body).clone()
    }));
    client.validate().unwrap(); // records; answers its own nonce
    assert!(
        client.validate().unwrap().is_offline,
        "a replayed answer must not count as a live verdict"
    );
    let _ = std::fs::remove_dir_all(temp("replayed"));
}
