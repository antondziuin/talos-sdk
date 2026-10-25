//! The machine binding, held across process restarts.
//!
//! Without it every application start would have to call `activate` again —
//! which burns a round trip the protocol exists to avoid, rotates the activation
//! secret out from under any other running copy, and (because `activate` is the
//! one client route refused for a suspended tenant) turns a vendor's billing
//! dispute into an outage for their paying users.
//!
//! The file is AES-256-GCM under a key derived from a stable machine identifier,
//! with the product token as associated data. Treat that as tamper-evidence and
//! resistance to casual copying, **not** secrecy: whoever owns the machine can
//! derive the same key. What actually stops a copied state file is the server,
//! which resolves a machine by fingerprint and demands the activation secret.

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::fingerprint::{hex, FingerprintData};

const MAGIC: &[u8] = b"TLS1";
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SALT: &[u8] = b"talos-state-v1";

/// Everything persisted for one product on this machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StoredBinding {
    /// SHA-256 of the licence key as typed, hex — **not** the key.
    ///
    /// After activation the server resolves the licence from the activation
    /// secret, so the key itself would only be a plaintext credential on a disk
    /// the user does not solely control. The hash has exactly one use: calling
    /// `activate` twice with the same key validates instead of spending a
    /// second seat. Nothing accepts it — the server matches an HMAC under a
    /// pepper no client has seen.
    pub license_key_hash: String,
    pub activation_secret: String,
    pub machine_id: String,
    /// The composite at activation time. Informational: a machine whose
    /// hardware drifted is exactly what the server's matcher resolves, so it is
    /// not required to match on restore.
    pub fingerprint: String,
    /// The last anchor-signed keyset token, so an anchor-only client can verify
    /// a cached verdict with no network.
    pub keyset: Option<String>,
    /// The last verified `typ=validation` token — the offline verdict.
    pub validation: Option<String>,
    /// The highest signed server clock ever seen, unix seconds. What keeps
    /// offline grace bounded when the user owns the clock.
    pub time_high_water: i64,
    /// The highest `release_seq` this install is known to be running: the
    /// anti-downgrade floor.
    pub release_seq_high_water: i64,
    /// A release downloaded and verified but not yet running.
    pub pending_version: Option<String>,
    pub pending_release_seq: i64,
    /// This machine's own Ed25519 seed (raw 32 bytes, base64), generated at its
    /// first offline request. Never leaves this file.
    pub machine_key: Option<String>,
    /// Its public half, raw 32 bytes, standard base64.
    pub machine_public_key: Option<String>,
    /// The last verified `typ=offline` licence file.
    pub offline_token: Option<String>,
    /// The highest **local** clock seen while running on an offline file.
    /// Separate from `time_high_water` on purpose: an air-gapped install sees
    /// one server time in its life, and mixing the two would make a corrected
    /// fast clock read as tampering.
    pub offline_seen: i64,
}

impl StoredBinding {
    /// An empty binding to build on, for an install that has stored nothing.
    pub(crate) fn empty(fingerprint: &str) -> Self {
        StoredBinding {
            fingerprint: fingerprint.to_string(),
            ..Default::default()
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "v": 1,
            "licenseKeyHash": self.license_key_hash,
            "activationSecret": self.activation_secret,
            "machineId": self.machine_id,
            "fingerprint": self.fingerprint,
            "keyset": self.keyset,
            "validation": self.validation,
            "timeHighWater": self.time_high_water,
            "releaseSeqHighWater": self.release_seq_high_water,
            "pendingVersion": self.pending_version,
            "pendingReleaseSeq": self.pending_release_seq,
            "machineKey": self.machine_key,
            "machinePublicKey": self.machine_public_key,
            "offlineToken": self.offline_token,
            "offlineSeen": self.offline_seen,
        })
    }

    /// Read field by field rather than trusted wholesale: the file is on a disk
    /// the user owns, so every value in it is input.
    fn from_json(o: &Map<String, Value>) -> Option<Self> {
        if o.get("v").and_then(Value::as_i64) != Some(1) {
            return None;
        }
        let s = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let opt = |k: &str| {
            o.get(k)
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        let n = |k: &str| o.get(k).and_then(Value::as_i64).unwrap_or(0);
        Some(StoredBinding {
            license_key_hash: s("licenseKeyHash"),
            activation_secret: s("activationSecret"),
            machine_id: s("machineId"),
            fingerprint: s("fingerprint"),
            keyset: opt("keyset"),
            validation: opt("validation"),
            time_high_water: n("timeHighWater"),
            release_seq_high_water: n("releaseSeqHighWater"),
            pending_version: opt("pendingVersion"),
            pending_release_seq: n("pendingReleaseSeq"),
            machine_key: opt("machineKey"),
            machine_public_key: opt("machinePublicKey"),
            offline_token: opt("offlineToken"),
            offline_seen: n("offlineSeen"),
        })
    }
}

/// Where the binding lives by default, per product, following each OS's
/// convention — the same three paths the C# and Node SDKs use:
///
/// - Windows: `%LOCALAPPDATA%\Talos\<slot>\state.bin`
/// - macOS: `~/Library/Application Support/Talos/<slot>/state.bin`
/// - Linux: `$XDG_DATA_HOME/talos/<slot>/state.bin` (or `~/.local/share/…`)
///
/// `<slot>` is the first 16 hex characters of SHA-256 of the product token:
/// filesystem-safe whatever the token's alphabet, and two products never
/// collide.
#[must_use]
pub fn default_state_path(product_token: &str) -> PathBuf {
    // `home_dir` rather than `$HOME`: a daemon started by a systemd system unit
    // or `env -i` has no `HOME`, and the account database still knows where
    // its home is — which is what Node's `os.homedir()` and .NET's profile
    // lookup consult too. Without it the binding would land in a temp
    // directory that tmpfiles or a reboot empties. Deprecated on some
    // toolchains for a Windows quirk fixed in 1.85, which is this crate's MSRV.
    #[allow(deprecated)]
    let home = std::env::home_dir()
        .filter(|p| !p.as_os_str().is_empty())
        // A host with no home at all, even in the account database (a
        // locked-down container), still has to put the file somewhere.
        .unwrap_or_else(std::env::temp_dir);
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    state_path_for(
        product_token,
        std::env::consts::OS,
        &home,
        env("LOCALAPPDATA"),
        env("XDG_DATA_HOME"),
    )
}

/// The path, from a host described rather than asked, so all three layouts are
/// testable from any one platform.
pub(crate) fn state_path_for(
    product_token: &str,
    os: &str,
    home: &Path,
    local_app_data: Option<PathBuf>,
    xdg_data_home: Option<PathBuf>,
) -> PathBuf {
    let slot = &hex(&Sha256::digest(product_token.as_bytes()))[..16];
    match os {
        "windows" => local_app_data
            .unwrap_or_else(|| home.join("AppData").join("Local"))
            .join("Talos")
            .join(slot)
            .join("state.bin"),
        "macos" => home
            .join("Library")
            .join("Application Support")
            .join("Talos")
            .join(slot)
            .join("state.bin"),
        // Lower-case, unlike the other two: this is the directory a Linux
        // user's other applications keep company with.
        _ => xdg_data_home
            .unwrap_or_else(|| home.join(".local").join("share"))
            .join("talos")
            .join(slot)
            .join("state.bin"),
    }
}

/// SHA-256 of a licence key, hex. Recognises "the same key as last time"
/// without keeping the key; accepted by nothing.
#[must_use]
pub fn hash_license_key(key: &str) -> String {
    hex(&Sha256::digest(key.as_bytes()))
}

/// Key material for the state file, chosen for **stability** rather than
/// strength: a hardware change must not lock the user out of their own binding.
/// `machine_guid` and `smbios_uuid` survive component swaps; `os_install`
/// survives everything short of a reinstall. These are already HMAC'd per
/// product, so nothing here reveals an identifier the server does not hold.
pub(crate) fn state_key_material(fp: &FingerprintData) -> String {
    ["machine_guid", "smbios_uuid", "os_install"]
        .iter()
        .find_map(|id| fp.components.get(*id).filter(|v| !v.is_empty()).cloned())
        .unwrap_or_else(|| "talos-unbound".to_string())
}

/// Reads and writes one product's binding.
pub(crate) struct StateStore {
    path: PathBuf,
    key: [u8; 32],
    aad: Vec<u8>,
}

impl StateStore {
    pub(crate) fn new(path: PathBuf, product_token: &str, key_material: &str) -> Self {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(SALT), key_material.as_bytes())
            .expand(product_token.as_bytes(), &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 length");
        StateStore {
            path,
            key,
            aad: product_token.as_bytes().to_vec(),
        }
    }

    /// The binding, or `None` if there is none.
    ///
    /// Never fails. A file that is missing, truncated, from another product,
    /// written by a future version or simply corrupt degrades to "not activated
    /// yet": a damaged cache costs a re-activation, not a failed launch.
    pub(crate) fn load(&self) -> Option<StoredBinding> {
        let raw = std::fs::read(&self.path).ok()?;
        if raw.len() < MAGIC.len() + IV_LEN + TAG_LEN || &raw[..MAGIC.len()] != MAGIC {
            return None;
        }
        let iv = &raw[MAGIC.len()..MAGIC.len() + IV_LEN];
        let sealed = &raw[MAGIC.len() + IV_LEN..];
        let cipher = Aes256Gcm::new_from_slice(&self.key).ok()?;
        // The product token is authenticated, not just stored: a file
        // belonging to another product cannot be silently adopted.
        let plain = cipher
            .decrypt(
                Nonce::from_slice(iv),
                Payload {
                    msg: sealed,
                    aad: &self.aad,
                },
            )
            .ok()?;
        let Value::Object(o) = serde_json::from_slice::<Value>(&plain).ok()? else {
            return None;
        };
        let b = StoredBinding::from_json(&o)?;
        // Worth keeping only if it holds a licence or the identity behind one.
        // An air-gapped install has no activation secret — it was never issued
        // one — and requiring it would throw away its file and its key.
        (!b.activation_secret.is_empty() || b.offline_token.is_some() || b.machine_key.is_some())
            .then_some(b)
    }

    /// Persist the binding. Best-effort by design: a read-only or full disk
    /// costs a re-activation next launch, and must not fail the activation that
    /// just succeeded.
    pub(crate) fn save(&self, b: &StoredBinding) -> bool {
        self.try_save(b).is_some()
    }

    fn try_save(&self, b: &StoredBinding) -> Option<()> {
        let plain = serde_json::to_vec(&b.to_json()).ok()?;
        let mut iv = [0u8; IV_LEN];
        getrandom::getrandom(&mut iv).ok()?;
        let cipher = Aes256Gcm::new_from_slice(&self.key).ok()?;
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: &plain,
                    aad: &self.aad,
                },
            )
            .ok()?;
        let mut out = Vec::with_capacity(MAGIC.len() + IV_LEN + sealed.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&sealed);

        let dir = self.path.parent()?;
        create_private_dir(dir).ok()?;
        // Write-then-rename: a crash mid-write leaves the previous binding
        // intact rather than a half file that reads as "never activated".
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        // A leftover from a crash is removed, and the new one is created
        // exclusively: `O_EXCL` does not follow a symlink somebody planted at
        // that name, so a privileged process writing here cannot be steered
        // into overwriting a file elsewhere. A link planted between the two
        // steps fails the save, which is best-effort anyway.
        let _ = std::fs::remove_file(&tmp);
        if write_private(&tmp, &out).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return None;
        }
        if std::fs::rename(&tmp, &self.path).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return None;
        }
        Some(())
    }

    /// Forget the binding (deactivation).
    pub(crate) fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Create the state directory, private to this user — but only the parts that
/// do not exist yet. A directory that is already there was somebody's choice
/// (`state_path = /var/lib/myapp/license.bin`), and tightening `/var/lib`
/// itself to 0700 because a licence file lives under it would break every
/// other service that passes through it.
#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        std::env::temp_dir()
            .join(format!("talos-rust-{name}-{}", hex(&nonce)))
            .join("state.bin")
    }

    #[test]
    fn a_binding_survives_a_round_trip() {
        let path = temp_path("roundtrip");
        let store = StateStore::new(path.clone(), "tpt_a", "material");
        let b = StoredBinding {
            license_key_hash: hash_license_key("KEY"),
            activation_secret: "sec".into(),
            machine_id: "m1".into(),
            time_high_water: 1_767_225_600,
            pending_version: Some("1.2.0".into()),
            pending_release_seq: 7,
            ..StoredBinding::empty("fp2:x")
        };
        assert!(store.save(&b));
        assert_eq!(store.load(), Some(b));
        store.clear();
        assert_eq!(store.load(), None);
    }

    #[test]
    fn another_products_file_reads_as_nothing() {
        let path = temp_path("aad");
        let b = StoredBinding {
            activation_secret: "sec".into(),
            ..StoredBinding::empty("fp2:x")
        };
        assert!(StateStore::new(path.clone(), "tpt_a", "material").save(&b));
        assert_eq!(
            StateStore::new(path.clone(), "tpt_b", "material").load(),
            None
        );
        assert_eq!(
            StateStore::new(path.clone(), "tpt_a", "other-machine").load(),
            None
        );
        StateStore::new(path, "tpt_a", "material").clear();
    }

    #[test]
    fn a_damaged_file_reads_as_nothing() {
        let path = temp_path("damaged");
        let store = StateStore::new(path.clone(), "tpt_a", "material");
        let b = StoredBinding {
            activation_secret: "sec".into(),
            ..StoredBinding::empty("fp2:x")
        };
        assert!(store.save(&b));
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(store.load(), None);
        std::fs::write(&path, b"TLS1").unwrap();
        assert_eq!(store.load(), None);
        store.clear();
    }

    #[test]
    fn a_binding_holding_nothing_is_not_kept() {
        let path = temp_path("empty");
        let store = StateStore::new(path, "tpt_a", "material");
        assert!(store.save(&StoredBinding::empty("fp2:x")));
        assert_eq!(store.load(), None);
        store.clear();
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_already_exists_keeps_its_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("perms");
        let dir = path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let store = StateStore::new(path.clone(), "tpt_a", "material");
        let b = StoredBinding {
            activation_secret: "sec".into(),
            ..StoredBinding::empty("fp2:x")
        };
        assert!(store.save(&b));
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "a directory the host chose is not ours to tighten"
        );
        let file = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_at_the_temporary_name_is_not_followed() {
        let path = temp_path("symlink");
        let dir = path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("state.bin.tmp")).unwrap();
        let store = StateStore::new(path.clone(), "tpt_a", "material");
        let b = StoredBinding {
            activation_secret: "sec".into(),
            ..StoredBinding::empty("fp2:x")
        };
        assert!(store.save(&b));
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert_eq!(store.load(), Some(b));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_three_layouts_match_the_other_sdks() {
        let token = "tpt_layout";
        let slot = &hex(&Sha256::digest(token.as_bytes()))[..16];
        let home = Path::new("/home/u");
        assert_eq!(
            state_path_for(
                token,
                "windows",
                home,
                Some(PathBuf::from("C:/Users/u/AppData/Local")),
                None
            ),
            PathBuf::from("C:/Users/u/AppData/Local")
                .join("Talos")
                .join(slot)
                .join("state.bin"),
        );
        assert_eq!(
            state_path_for(token, "macos", home, None, None),
            home.join("Library/Application Support/Talos")
                .join(slot)
                .join("state.bin"),
        );
        assert_eq!(
            state_path_for(token, "linux", home, None, None),
            home.join(".local/share/talos").join(slot).join("state.bin"),
        );
        assert_eq!(
            state_path_for(token, "linux", home, None, Some(PathBuf::from("/xdg"))),
            PathBuf::from("/xdg/talos").join(slot).join("state.bin"),
        );
    }
}
