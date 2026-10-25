use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::host;

/// A machine fingerprint: the composite the server matches on, plus the
/// per-component hashes that let it tolerate hardware drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintData {
    /// `fp2:<sha256 hex>`, derived from [`components`](Self::components).
    pub composite: String,
    /// `{component_id: hash}`, sorted by id.
    pub components: BTreeMap<String, String>,
}

/// Collect this machine's fingerprint for a product.
///
/// Every component is HMAC'd with a product-scoped key before it leaves the
/// machine, so the server stores hashes and never the underlying serials — and
/// the same hardware yields different hashes for different products. A
/// component that cannot be read is absent: never an error, never a fabricated
/// value.
///
/// `extra` is merged over what was collected, for an application that can read
/// more than this SDK can (see `docs/FINGERPRINT.md` for the recognised ids and
/// their weights). A supplied value must be stable for the life of the install.
///
/// None of this resists a determined attacker: the values are produced on the
/// client and can be forged. It exists to recognise honest hardware churn.
#[must_use]
pub fn collect_fingerprint(
    product_token: &str,
    extra: &BTreeMap<String, String>,
) -> FingerprintData {
    let raw = host::collect();
    let mut values = BTreeMap::new();
    let mut add = |id: &str, value: Option<String>| {
        if let Some(v) = value {
            values.insert(id.to_string(), v);
        }
    };
    add("machine_guid", raw.machine_guid);
    add("smbios_uuid", raw.smbios_uuid);
    add("disk_serial", raw.disk_serial);
    add("mac_set", raw.mac_set);
    add("cpu", raw.cpu);
    add("mem_bucket", raw.mem_bucket);
    add("os_install", raw.os_install);
    add("hostname", raw.hostname);
    for (id, value) in extra {
        values.insert(id.clone(), value.clone());
    }
    fingerprint_from(product_token, &values)
}

/// Hash raw component values into a fingerprint. Split out so the derivation —
/// which has to agree with the other SDKs' bit for bit — is testable without
/// the host.
pub(crate) fn fingerprint_from(
    product_token: &str,
    raw: &BTreeMap<String, String>,
) -> FingerprintData {
    let key = Sha256::digest(format!("talos-fp|{product_token}").as_bytes());
    let mut components = BTreeMap::new();
    for (id, value) in raw {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC takes any key length");
        mac.update(format!("{id}={value}").as_bytes());
        // 16 bytes distinguishes components and keeps the request small; this
        // is a matching token, not a secret.
        let digest = hex(&mac.finalize().into_bytes());
        components.insert(id.clone(), digest[..32].to_string());
    }
    // The composite is a digest of the hashed components, so a host reporting
    // the same parts always yields the same composite and the server's
    // exact-match fast path keeps working.
    let canonical = components
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");
    FingerprintData {
        composite: format!("fp2:{}", hex(&Sha256::digest(canonical.as_bytes()))),
        components,
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_derivation_matches_the_other_sdks() {
        // Same inputs as every SDK's own derivation: key = SHA-256("talos-fp|" +
        // token), component = first 32 hex of HMAC(key, "id=value"), composite =
        // SHA-256 over sorted "id=hash" lines. A change here moves every Rust
        // install onto a new composite, which the exact matcher reads as a new
        // machine and charges a seat for.
        let raw = BTreeMap::from([
            ("machine_guid".to_string(), " 0f3c9b2e ".to_string()),
            ("hostname".to_string(), "build-01".to_string()),
            ("cpu".to_string(), "   ".to_string()),
        ]);
        let fp = fingerprint_from("tpt_test", &raw);

        let key = Sha256::digest(b"talos-fp|tpt_test");
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(b"machine_guid=0f3c9b2e");
        let guid = hex(&mac.finalize().into_bytes())[..32].to_string();

        assert_eq!(fp.components.get("machine_guid"), Some(&guid));
        assert!(
            !fp.components.contains_key("cpu"),
            "a blank value is not a component"
        );
        let canonical = format!(
            "hostname={}\nmachine_guid={guid}",
            fp.components["hostname"]
        );
        assert_eq!(
            fp.composite,
            format!("fp2:{}", hex(&Sha256::digest(canonical.as_bytes())))
        );
    }

    #[test]
    fn different_products_see_different_hashes_for_the_same_machine() {
        let raw = BTreeMap::from([("machine_guid".to_string(), "same".to_string())]);
        assert_ne!(
            fingerprint_from("tpt_a", &raw),
            fingerprint_from("tpt_b", &raw)
        );
    }

    #[test]
    fn this_host_yields_a_composite() {
        let fp = collect_fingerprint("tpt_test", &BTreeMap::new());
        assert!(fp.composite.starts_with("fp2:"));
        assert_eq!(fp.composite.len(), 4 + 64);
    }
}
