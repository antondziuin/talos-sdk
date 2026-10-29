# talos-sdk (Rust)

Talos SDK for Rust applications. Activate and validate licenses, read feature
entitlements, manage floating seats, and download signed software updates.
Supports offline grace periods and license files for air-gapped machines.

Requires Rust 1.85 or later. The API is blocking; from async code, call it on a
blocking thread (`tokio::task::spawn_blocking`). Ed25519 verification uses
`ed25519-dalek`, and HTTP goes through `ureq` with rustls — or through your own
[`Transport`](#supplying-your-own-transport).

```sh
cargo add talos-sdk
```

MIT-licensed.

## Quickstart

```rust
use talos_sdk::{Decision, TalosClient, TalosOptions};

let talos = TalosClient::new(TalosOptions {
    product_token: "tpt_…".into(),                        // from the portal's Integration page
    anchor_public_key: Some("base64-anchor-key".into()),  // pin THIS — the rotation-safe root
    server_url: "https://talos.dziuin.dev".into(),           // Talos Cloud, or your self-hosted node
    app_version: Some(env!("CARGO_PKG_VERSION").into()),
    ..Default::default()
})?;

// The activation is stored on this machine, so the second launch onwards has
// nothing to ask the user for.
let state = if talos.is_activated() {
    talos.validate()?                      // machine-bound signed decision
} else {
    talos.activate(&user_entered_license_key)?
};
if !state.is_valid() {
    prompt_for_key();
}

if talos.is_feature_enabled("pdf-export") {
    enable_pdf_menu();
}
let seats = state.entitlement_i64("seats").unwrap_or(1);
```

`TalosClient` is `Clone + Send + Sync`; clones are handles to the same client.
Create one per product and share it.

## Errors

`talos_sdk::Error` separates the server's answers from the absence of one:

| Variant | Meaning |
|---|---|
| `Api { status, code }` | The server answered with an error status — `activation_limit_reached`, `seat_limit_reached`, `updates_not_entitled`, … (`e.code()`). Never masked by the offline cache. |
| `Signature(_)` | A response failed verification against the pinned key. Treated as silence, never as valid. |
| `Network(_)` | No answer: no route, TLS failure, the licensing deadline passed, or a gateway's 5xx page (no Talos reason in it) in front of a server that is down. |
| `NotActivated` | The call needs an activation first. |
| `Usage(_)`, `Io(_)`, `InvalidResponse(_)` | Configuration, local files, or a 2xx body that is not JSON. |

## Local diagnostic reports

`talos.create_diagnostic_report(None)` — or `Some(&error)` after a failed call —
returns JSON describing the last decision, the offline grace deadline, the SDK
version and whether an activation is held, with a suggested next action. It
makes no requests, writes nothing, and excludes keys, tokens, server URLs,
machine identifiers, entitlements and error text. Do not use it as
authorisation.

## Licensing calls have a deadline

`TalosOptions::http_timeout` (default 10 s, `Duration::ZERO` disables) bounds
every licensing call, so a server that accepts the connection and then says
nothing cannot hold your splash screen forever. A timeout is `Error::Network`
on purpose: `validate()` treats a network failure as the grace-period case.

It does **not** cap `download_update`, which is bounded by the signed manifest's
`size` instead — a total-duration limit on a multi-megabyte artifact is a size
limit disguised as a safeguard.

## Supplying your own transport

`TalosOptions::transport` replaces the HTTP client for **every** call, artifact
downloads included — a corporate proxy, a custom CA bundle, request logging or a
test double applies uniformly. Implement `talos_sdk::Transport`; return `Err`
only when there is no response at all, and a 4xx/5xx as an `Ok` with that
status. `talos_sdk::transport::UreqTransport` is the built-in one, public so you
can wrap it. Build with `default-features = false` to drop `ureq` entirely.

## The licence key is not kept

After activation the SDK holds no licence key — not in memory, not in the state
file. The server resolves the licence from the per-machine activation secret.
What is kept is a SHA-256 of the key, for one thing only: activating twice with
the same key validates instead of spending a second seat.

## The machine binding is persistent

`activate` binds this machine and writes that binding to a per-product file —
the same paths the C# and Node SDKs use:

- Windows: `%LOCALAPPDATA%\Talos\<slot>\state.bin`
- macOS: `~/Library/Application Support/Talos/<slot>/state.bin`
- Linux: `$XDG_DATA_HOME/talos/<slot>/state.bin` (or `~/.local/share/…`)

`TalosClient::new` restores it, so `is_activated()` answers the startup
question. `activate()` is safe to call on every start: with a binding for the
same key it **re-validates** instead of re-activating — which does not rotate the
activation secret (a second copy of your app is not knocked out) and keeps
working while your own Talos account is suspended, since activation is the one
client route refused then. `deactivate()` forgets the binding on disk too.

Set `state_path` to choose the file, or `persist_state: false` for a process
that should not leave a licence on disk. Directories the SDK creates are private
(0700, the file 0600); one that already exists — say `/var/lib/myapp` — keeps the
permissions you gave it. The file is AES-256-GCM under a key
derived from a stable machine identifier: tamper-evidence and resistance to
casual copying, **not** secrecy. What stops a copied file is the server, which
resolves a machine by fingerprint and demands the activation secret. A corrupt
file reads as "not activated yet", never as an error.

## Offline and grace

`validate()` is online-first and offline-tolerant. When the server answers, that
answer wins and is cached. When it cannot be reached, the last verified verdict
is honoured until the policy's `offline_grace_hours` runs out:

```rust
let state = talos.validate()?;
if state.is_offline {
    show_banner("Working offline");
}
match state.decision {
    Decision::Valid => {}
    Decision::GraceExpired => require_connection(),  // offline too long
    Decision::ClockTampered => require_connection(), // the clock moved back
    other => show_licence_problem(&other),
}
```

**An answer from the server is never masked by the cache** — "revoked", "no
such machine", a self-hosted node's `503 node_degraded`. Only the absence of one
falls back: a dead network, a gateway's error page in front of a server that is
down (a 5xx carrying no Talos reason — Cloudflare's 52x, IIS's 502.3), or a reply
that fails signature verification or names another machine's fingerprint. The
cached verdict is re-verified under the
pinned key on every use, must name *this* machine's fingerprint, cannot outlive
the licence's own expiry, and is compared against a persistent high-water mark
of signed server time, so winding the clock back reports `ClockTampered`
instead of renewing grace forever.

**Key rotation.** Pin `anchor_public_key`. The SDK learns the current licence
and release keys from the anchor-signed keyset (cached alongside the binding, so
the whole chain verifies offline), and rotating a signing key in the portal
needs no new build. A keyset older than the one already held is ignored, so a
recording from before a key was revoked cannot bring that key back.
`public_key` / `release_public_key` still work as direct pins, and break on the
first rotation.

## Air-gapped machines

```rust
// On the machine. Write this out and carry it to your vendor:
std::fs::write("talos-request.json", talos.create_offline_request(None)?.to_json_pretty())?;

// They upload it in the portal and hand you back license.talos:
let state = talos.load_offline_license_file("license.talos")?;
```

The first request generates an Ed25519 identity for this machine, kept in the
state file; the returned file is bound to it and to the fingerprint. Everything
is verified locally — the keyset travels inside the file — and later starts need
nothing: `validate()` re-checks the stored file and `is_activated()` is true.

For trusted users, a perpetual policy can opt into permanent offline files with
`offline_checkout_max_days: 0`. The signed file carries `perpetual: true` and
explicit null file and licence expiries. It needs no renewal or connection;
`grace_until` and `license_expires_at` are `None`. Import it using the same calls
above. Older SDK versions reject these files and must be upgraded. Permanent
files cannot be recalled, and hardware changes still require a new request.

`load_offline_license` fails only for a file that is not a licence. One that
cannot license this machine comes back as a verdict: `MachineMismatch`,
`OfflineFileExpired` (get a new file), `Expired` (renew), `ClockTampered`.
`create_offline_deactivation()` writes the receipt that returns the seat, and
drops the licence before returning it.

## Heartbeats and check-ins

```rust
use talos_sdk::CheckInOptions;

talos.start_check_ins(
    CheckInOptions::new()
        .on_state(|s| update_ui(s))
        .on_error(|e| eprintln!("check-in failed: {e}")),
);
// On shutdown:
talos.stop_check_ins();
```

One background thread, driven by the **policy**: each tick re-validates once the
signed `reval_after` has passed and otherwise heartbeats at the signed
`heartbeat_interval_s`. Both come from signed claims, never the envelope. The
callbacks run on that thread; marshal to your UI thread from there. The loop
ends with `stop_check_ins()` or when the last client handle is dropped.

## Events: the transitions, not the level

```rust
use talos_sdk::{EventKind, TalosEvent};

talos.on(EventKind::GracePeriodStarted, |e| show_offline_banner(e.state()));
talos.on(EventKind::LicenseInvalid, |e| show_licence_problem(e.state()));
talos.on(EventKind::UpdateAvailable, |e| {
    if let TalosEvent::UpdateAvailable(info) = e {
        offer_update(&info.version);
    }
});
```

Licence events fire **once** on the way in, from every path that adopts a
verdict, synchronously on the calling thread. `LicenseInvalid` fires again when
the reason changes. A listener that panics is ignored. `on` returns a
`Subscription`; call `.unsubscribe()` to remove it.

Subscribing to `UpdateAvailable` makes heartbeats ask the server whether a
release is waiting; the payload is what a real `check_for_update` verified, and
each release is announced once.

## When updates are refused

A maintenance licence that has run out is **not** a licence that has failed.
`validate()` stays valid and only the update check refuses:

```rust
match talos.check_for_update(Default::default()) {
    Ok(Some(update)) => offer_update(&update.version),
    Ok(None) => {}
    Err(e) if e.code() == Some("updates_not_entitled") => {
        show_notice("Your maintenance period has ended. The app keeps working; renew to get updates.");
    }
    Err(e) => return Err(e.into()),
}
```

## Floating (concurrent) licenses

```rust
use talos_sdk::AcquireLeaseOptions;

match talos.acquire_lease(AcquireLeaseOptions::new().on_lease_lost(|why| eprintln!("seat lost: {why}"))) {
    Ok(lease) => println!("seat {}/{}", lease.seats_in_use, lease.max_seats),
    Err(e) if e.status() == Some(409) => show_busy_dialog(),
    Err(e) => return Err(e.into()),
}
// On clean exit:
talos.release_lease()?;
```

The server arbitrates seats atomically. The seat renews on a background thread;
a crash needs no cleanup — the lease expires and the seat returns to the pool.

## Updates

```rust
if let Some(update) = talos.check_for_update(Default::default())? {
    // Built from a manifest signed by the release key. Metadata is trusted;
    // the download URL is not.
    let dest = std::env::temp_dir().join(&update.artifacts[0].filename);
    talos.download_update(&update, &dest, None, Some(&mut |p| {
        show_progress(p.bytes_received as f64 / p.total_bytes as f64);
    }))?;
    // Hand `dest` to your installer. Applying is the app's job.
}
```

The bytes stream to a `.talos-part` file beside the destination, hashed as they
arrive, and are renamed into place only once the SHA-256 matches — a failed
download leaves whatever was at `dest` before. `total_bytes` is the signed size,
never the server's `content-length`.

The manifest carries a monotonic `release_seq`, and the SDK refuses a release at
or below the highest one this install has been seen running (anti-downgrade).
It keeps that mark in the state file: once `download_update` has fetched a
release, the next client constructed with `app_version` equal to it moves the
mark up.

Patches: `select_delta` / `download_delta` fetch a signed patch for the exact
installed version, and `talos_sdk::verify_applied_update` checks the rebuilt
file against the manifest after your patcher runs.

## Hardware changes

The SDK identifies the machine by component hashes — each raw value HMAC'd with
a product-scoped key before it is sent. Without subprocesses, it reads:

| Component | Windows | Linux | macOS |
|---|:--:|:--:|:--:|
| `machine_guid` | registry `MachineGuid` | `/etc/machine-id` | — |
| `smbios_uuid` | — | root only | — |
| `disk_serial` | system volume serial | root only | — |
| `mac_set` | physical adapters | interfaces with a device | `en*` |
| `cpu`, `mem_bucket`, `hostname` | ✅ | ✅ | ✅ |
| `os_install` | registry `InstallDate` | `/etc` birth time | `/etc` birth time |

If your application can read more — say, the macOS hardware UUID through IOKit —
pass it and the server will use it:

```rust
let mut options = TalosOptions::default();
options.fingerprint_components.insert("smbios_uuid".into(), my_hardware_uuid());
```

The value must be stable for the life of the install.

Anti-tamper honesty: a binary is patchable. Gate premium value on
server-returned *data* (entitlements, configuration), not on client booleans.
