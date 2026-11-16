//! Registry wire formats, trust pins and device-proof domain separation.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http::Uri;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use super::RegistryError;

/// Trusted application configuration. Never obtain these pins from a license file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryTrust {
    /// Base Mainnet (8453), Sepolia (11155111), or local Anvil (31337).
    pub chain_id: u64,
    /// Shared registry contract address, as 0x-prefixed 20-byte hex.
    pub contract: String,
    /// Product publisher address, as 0x-prefixed 20-byte hex.
    pub issuer: String,
    /// Product namespace, as 0x-prefixed 32-byte hex.
    pub product_id: String,
}

/// Public lookup information. Importing it is not a license validity decision.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryLicenseManifest {
    /// Wire format version, currently one.
    pub v: u8,
    /// The literal `talos-registry-license`.
    pub kind: String,
    /// Pinned EVM network ID.
    pub chain_id: u64,
    /// Registry contract address.
    pub contract: String,
    /// Publisher namespace address.
    pub issuer: String,
    /// Product namespace hash.
    pub product_id: String,
    /// Public license identifier hash, never the activation code.
    pub license_id: String,
    /// Holder authorized to enroll the device; managed activation uses the issuer.
    pub holder: String,
    /// Unpadded base64url-encoded UTF-8 entitlement object.
    pub entitlements: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedManifest {
    pub manifest: RegistryLicenseManifest,
    pub entitlements: Map<String, Value>,
    pub entitlements_hash: String,
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

pub(crate) fn keccak_hex(bytes: &[u8]) -> String {
    hex(&Keccak256::digest(bytes))
}

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, RegistryError> {
    let body = value
        .strip_prefix("0x")
        .filter(|s| s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| RegistryError::new("invalid_registry_hex"))?;
    body.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => unreachable!(),
            };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

pub(crate) fn fixed_hex(value: &str, length: usize) -> Result<String, RegistryError> {
    if value.len() != 2 + length * 2 || decode_hex(value)?.len() != length {
        return Err(RegistryError::new("invalid_registry_hex"));
    }
    Ok(value.to_ascii_lowercase())
}

pub(crate) fn nonzero_hex(value: &str, length: usize) -> Result<String, RegistryError> {
    let value = fixed_hex(value, length)?;
    if value.as_bytes()[2..].iter().all(|b| *b == b'0') {
        return Err(RegistryError::new("invalid_registry_hex"));
    }
    Ok(value)
}

pub(crate) fn validate_trust(trust: &RegistryTrust) -> Result<(), RegistryError> {
    if ![8453, 11155111, 31337].contains(&trust.chain_id)
        || nonzero_hex(&trust.contract, 20).is_err()
        || nonzero_hex(&trust.issuer, 20).is_err()
        || nonzero_hex(&trust.product_id, 32).is_err()
    {
        return Err(RegistryError::new("invalid_registry_configuration"));
    }
    Ok(())
}

pub(crate) fn validate_endpoint(value: &str, activation: bool) -> Result<String, RegistryError> {
    let code = if activation {
        "invalid_registry_activation_url"
    } else {
        "invalid_registry_configuration"
    };
    if !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || value.contains(['#', '\\'])
    {
        return Err(RegistryError::new(code));
    }
    let parsed: Uri = value.parse().map_err(|_| RegistryError::new(code))?;
    let authority = parsed.authority().ok_or_else(|| RegistryError::new(code))?;
    let host = authority.host();
    if host.is_empty() || authority.as_str().contains('@') {
        return Err(RegistryError::new(code));
    }
    let suffix = authority
        .as_str()
        .strip_prefix(host)
        .ok_or_else(|| RegistryError::new(code))?;
    if !suffix.is_empty() {
        let port = suffix
            .strip_prefix(':')
            .ok_or_else(|| RegistryError::new(code))?;
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            return Err(RegistryError::new(code));
        }
    }
    let ip = if host.starts_with('[') {
        let ipv6 = host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|s| s.parse::<std::net::Ipv6Addr>().ok())
            .ok_or_else(|| RegistryError::new(code))?;
        Some(std::net::IpAddr::V6(ipv6))
    } else {
        host.parse::<std::net::IpAddr>().ok()
    };
    let loopback = host.eq_ignore_ascii_case("localhost")
        || ip == Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        || ip == Some(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
    let scheme = parsed
        .scheme_str()
        .ok_or_else(|| RegistryError::new(code))?;
    if !(scheme.eq_ignore_ascii_case("https") || (scheme.eq_ignore_ascii_case("http") && loopback))
        || (activation && parsed.query().is_some())
    {
        return Err(RegistryError::new(code));
    }
    let normalized = parsed.to_string();
    Ok(if activation {
        normalized
            .strip_suffix('/')
            .unwrap_or(&normalized)
            .to_owned()
    } else {
        normalized
    })
}

pub(crate) fn registry_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

pub(crate) fn activation_proof_text(
    product_token: &str,
    code: &str,
    device_key: &str,
    request_id: &str,
) -> Result<String, RegistryError> {
    let device = fixed_hex(device_key, 32)?;
    if !registry_uuid(request_id) {
        return Err(RegistryError::new("invalid_activation_request_id"));
    }
    Ok(format!(
        "talos-registry-activation.1.{}.{}.{}.{}",
        keccak_hex(product_token.as_bytes()),
        keccak_hex(code.trim().as_bytes()),
        device,
        request_id.to_ascii_lowercase()
    ))
}

pub(crate) fn status_proof_text(
    product_token: &str,
    activation_id: &str,
    device_key: &str,
) -> Result<String, RegistryError> {
    let device = fixed_hex(device_key, 32)?;
    if !registry_uuid(activation_id) {
        return Err(RegistryError::new("invalid_activation_id"));
    }
    Ok(format!(
        "talos-registry-status.1.{}.{}.{}",
        keccak_hex(product_token.as_bytes()),
        activation_id.to_ascii_lowercase(),
        device
    ))
}

pub(crate) fn checkin_proof_text(
    product_token: &str,
    license_id: &str,
    device_key: &str,
    install_id: &str,
    timestamp: u64,
) -> Result<String, RegistryError> {
    Ok(format!(
        "talos-registry-checkin.1.{}.{}.{}.{}.{}",
        keccak_hex(product_token.as_bytes()),
        fixed_hex(license_id, 32)?,
        fixed_hex(device_key, 32)?,
        install_id,
        timestamp
    ))
}

/// The form of a license code the Talos server hashes: ASCII letters and digits only,
/// upper case, with the look-alike Crockford characters folded (I, L → 1; O → 0). A code
/// typed with or without its dashes, in either case, therefore names the same license.
pub(crate) fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        })
        .collect()
}

/// What a recoverable license's code determines on its own: where the record lives in the
/// registry, and the device key that record is bound to.
pub(crate) struct CodeIdentity {
    /// Public registry identifier, 0x-prefixed 32-byte hex.
    pub license_id: String,
    /// Ed25519 seed. Secret: whoever has it can run the application.
    pub seed: Zeroizing<[u8; 32]>,
}

/// Derive the identity of a recoverable license from its code and the application's pins.
///
/// Both values hang off one root so that neither reveals the other, and the root binds the
/// chain, registry, issuer and product: the same code under another product is unrelated.
/// The server computes the identifier the same way, and the public key too, so that it can
/// refuse to bind a recoverable license to any other key. A code carries 120 random bits,
/// so the public identifier and key do not help anyone guess it.
pub(crate) fn code_identity(
    trust: &RegistryTrust,
    code: &str,
) -> Result<CodeIdentity, RegistryError> {
    validate_trust(trust)?;
    let normalized = Zeroizing::new(normalize_code(code));
    if normalized.is_empty() || normalized.len() > 256 {
        return Err(RegistryError::new("activation_code_required"));
    }
    let mut input = Zeroizing::new(b"talos-registry-code-v1\0".to_vec());
    input.extend_from_slice(&[0; 24]);
    input.extend_from_slice(&trust.chain_id.to_be_bytes());
    for pin in [&trust.contract, &trust.issuer, &trust.product_id] {
        input.extend_from_slice(&decode_hex(pin)?);
    }
    input.extend_from_slice(normalized.as_bytes());
    let root = Zeroizing::new(<[u8; 32]>::from(Keccak256::digest(&*input)));
    let derive = |label: &[u8]| {
        let mut hasher = Keccak256::new();
        hasher.update(label);
        hasher.update(root.as_slice());
        <[u8; 32]>::from(hasher.finalize())
    };
    Ok(CodeIdentity {
        license_id: hex(&derive(b"talos-registry-code-license-v1")),
        seed: Zeroizing::new(derive(b"talos-registry-code-device-v1")),
    })
}

pub(crate) fn parse_manifest(
    raw: &str,
    trust: &RegistryTrust,
) -> Result<ParsedManifest, RegistryError> {
    let parse = || -> Result<ParsedManifest, RegistryError> {
        validate_trust(trust)?;
        if raw.len() > 65_536 {
            return Err(RegistryError::new("invalid_registry_manifest"));
        }
        let mut manifest: RegistryLicenseManifest = serde_json::from_str(raw)
            .map_err(|_| RegistryError::new("invalid_registry_manifest"))?;
        manifest.contract = nonzero_hex(&manifest.contract, 20)?;
        manifest.issuer = nonzero_hex(&manifest.issuer, 20)?;
        manifest.holder = nonzero_hex(&manifest.holder, 20)?;
        manifest.product_id = nonzero_hex(&manifest.product_id, 32)?;
        manifest.license_id = nonzero_hex(&manifest.license_id, 32)?;
        if manifest.v != 1
            || manifest.kind != "talos-registry-license"
            || manifest.chain_id != trust.chain_id
            || !manifest.contract.eq_ignore_ascii_case(&trust.contract)
            || !manifest.issuer.eq_ignore_ascii_case(&trust.issuer)
            || !manifest.product_id.eq_ignore_ascii_case(&trust.product_id)
            || manifest.entitlements.is_empty()
        {
            return Err(RegistryError::new("invalid_registry_manifest"));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&manifest.entitlements)
            .map_err(|_| RegistryError::new("invalid_registry_manifest"))?;
        if bytes.len() > 32_768 || URL_SAFE_NO_PAD.encode(&bytes) != manifest.entitlements {
            return Err(RegistryError::new("invalid_registry_manifest"));
        }
        let entitlements: Value = serde_json::from_slice(&bytes)
            .map_err(|_| RegistryError::new("invalid_registry_manifest"))?;
        let entitlements = entitlements
            .as_object()
            .cloned()
            .ok_or_else(|| RegistryError::new("invalid_registry_manifest"))?;
        Ok(ParsedManifest {
            manifest,
            entitlements,
            entitlements_hash: keccak_hex(&bytes),
        })
    };
    parse().map_err(|_| RegistryError::new("invalid_registry_manifest"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (RegistryTrust, Value) {
        let trust = RegistryTrust {
            chain_id: 8453,
            contract: format!("0x{}", "11".repeat(20)),
            issuer: format!("0x{}", "22".repeat(20)),
            product_id: format!("0x{}", "33".repeat(32)),
        };
        let manifest = json!({"v":1,"kind":"talos-registry-license","chain_id":trust.chain_id,"contract":trust.contract,
            "issuer":trust.issuer,"product_id":trust.product_id,"license_id":format!("0x{}","44".repeat(32)),"holder":trust.issuer,
            "entitlements":URL_SAFE_NO_PAD.encode(br#"{"pro":true,"seats":2}"#)});
        (trust, manifest)
    }

    #[test]
    fn manifest_pins_exact_bytes_and_entitlement_object() {
        let (trust, value) = fixture();
        let parsed = parse_manifest(&value.to_string(), &trust).unwrap();
        assert_eq!(parsed.entitlements["pro"], true);
        assert_eq!(parsed.entitlements["seats"], 2);
        assert_eq!(
            parsed.entitlements_hash,
            keccak_hex(br#"{"pro":true,"seats":2}"#)
        );
        for field in ["contract", "issuer", "product_id", "license_id", "holder"] {
            let mut bad = value.clone();
            bad[field] = Value::String(format!(
                "0x{}",
                "00".repeat(if ["contract", "issuer", "holder"].contains(&field) {
                    20
                } else {
                    32
                })
            ));
            assert_eq!(
                parse_manifest(&bad.to_string(), &trust).unwrap_err().code(),
                "invalid_registry_manifest"
            );
        }
        for field in ["contract", "issuer", "product_id"] {
            let mut bad = value.clone();
            bad[field] = Value::String(format!(
                "0x{}",
                "55".repeat(if field == "product_id" { 32 } else { 20 })
            ));
            assert!(parse_manifest(&bad.to_string(), &trust).is_err());
        }
        let mut bad = value.clone();
        bad["chain_id"] = json!(11155111);
        assert!(parse_manifest(&bad.to_string(), &trust).is_err());
        let mut bad = value.clone();
        bad["extra"] = json!(true);
        assert!(parse_manifest(&bad.to_string(), &trust).is_err());
    }

    #[test]
    fn entitlements_are_strict_unpadded_base64url_utf8_bounded_json_object() {
        let (trust, value) = fixture();
        for encoded in ["e30=", "e31", "W10", "bnVsbA", "_w", ""] {
            let mut bad = value.clone();
            bad["entitlements"] = json!(encoded);
            assert!(
                parse_manifest(&bad.to_string(), &trust).is_err(),
                "accepted {encoded}"
            );
        }
        let mut bad = value.clone();
        bad["entitlements"] = json!(URL_SAFE_NO_PAD.encode(vec![b' '; 32_769]));
        assert!(parse_manifest(&bad.to_string(), &trust).is_err());
        assert!(parse_manifest(&" ".repeat(65_537), &trust).is_err());
    }

    #[test]
    fn activation_proofs_match_frozen_node_domain_vectors() {
        let key = format!("0x{}", "AB".repeat(32));
        let id = "ABCDEF01-2345-6789-ABCD-EF0123456789";
        let token_hash = keccak_hex(b"tpt_fixture");
        let code_hash = keccak_hex(b"TEST-CODE");
        assert_eq!(
            token_hash,
            "0xcc8ad00ea86101e119eeff60c7daabf483d3a8cd075fe4ce75f473e6ebd682e4"
        );
        assert_eq!(
            code_hash,
            "0x8bb59bdde50169bcd6f16f656bb598a1ba9600a7a7fb2625ea38cde78d25b1a5"
        );
        assert_eq!(
            activation_proof_text("tpt_fixture", " \tTEST-CODE\n", &key, id).unwrap(),
            format!(
                "talos-registry-activation.1.{token_hash}.{code_hash}.{}.{}",
                key.to_ascii_lowercase(),
                id.to_ascii_lowercase()
            )
        );
        assert_eq!(
            status_proof_text("tpt_fixture", id, &key).unwrap(),
            format!(
                "talos-registry-status.1.{token_hash}.{}.{}",
                id.to_ascii_lowercase(),
                key.to_ascii_lowercase()
            )
        );
        assert!(!registry_uuid("abcdef01-2345-6789-abcd-ef012345678"));
        assert!(activation_proof_text("tpt_fixture", "TEST-CODE", &key, "bad-id").is_err());
    }

    #[test]
    fn code_identity_matches_independent_node_vector_and_ignores_how_the_code_is_typed() {
        let (trust, _) = fixture();
        let identity = code_identity(&trust, "0123456789ABCDEFGHJKMNPQR").unwrap();
        // Computed with viem's keccak256 and Node's Ed25519; the server derives the same
        // identifier in `talos_wallet::registry::code_license_id`.
        assert_eq!(
            identity.license_id,
            "0xdce9ae5ad263079c0f4134e75a51932bcf0970c14aaf6351cd8da992aae67944"
        );
        assert_eq!(
            hex(&*identity.seed),
            "0x827207622bc29125e0ae0c512683a6665a025fe90561d6652904bad141b73cbc"
        );
        assert_eq!(
            hex(ed25519_dalek::SigningKey::from_bytes(&identity.seed)
                .verifying_key()
                .as_bytes()),
            "0x5402ca53f9f96eb225b57d8da35993dcd294b6df98ae525690a1f1585a31971b"
        );
        for typed in [
            "01234-56789-ABCDE-FGHJK-MNPQR",
            " o1234-56789-abcde-fghjk-mnpqr\n",
            "0I234 56789 ABCDE FGHJK MNPQR",
            "0L23456789abcdefghjkmnpqr",
        ] {
            let same = code_identity(&trust, typed).unwrap();
            assert_eq!(same.license_id, identity.license_id, "{typed}");
            assert_eq!(*same.seed, *identity.seed, "{typed}");
        }
        assert_eq!(normalize_code("ab-IL-o0"), "AB1100");
        let other_code = code_identity(&trust, "0123456789ABCDEFGHJKMNPQS").unwrap();
        assert_ne!(other_code.license_id, identity.license_id);
        assert_ne!(*other_code.seed, *identity.seed);
        for change in 0..4 {
            let mut other = trust.clone();
            match change {
                0 => other.chain_id = 11155111,
                1 => other.contract = format!("0x{}", "12".repeat(20)),
                2 => other.issuer = format!("0x{}", "23".repeat(20)),
                _ => other.product_id = format!("0x{}", "34".repeat(32)),
            }
            let moved = code_identity(&other, "0123456789ABCDEFGHJKMNPQR").unwrap();
            assert_ne!(moved.license_id, identity.license_id);
            assert_ne!(*moved.seed, *identity.seed);
        }
        for empty in ["", " - - ", "\u{2014}"] {
            assert_eq!(
                code_identity(&trust, empty).err().unwrap().code(),
                "activation_code_required"
            );
        }
        assert!(code_identity(&trust, &"A".repeat(257)).is_err());
    }

    #[test]
    fn endpoints_allow_only_https_or_exact_loopback_and_separate_activation_query_rules() {
        for endpoint in [
            "https://rpc.example/path?key=private",
            "http://localhost:8545/",
            "http://127.0.0.1:8545/",
            "http://[::1]:8545/",
        ] {
            assert!(validate_endpoint(endpoint, false).is_ok());
        }
        for endpoint in [
            "http://remote.example/",
            "https://user:secret@rpc.example/",
            "https://rpc.example/#fragment",
            "file:///tmp/key",
            "https://rpc.example:65536/",
            "https://rpc.example:abc/",
            "https://rpc.example:/",
            "https://[not-ip]/",
            "https://rpc.example/with space",
            "https://rpc.example/\nkey",
            "https://rpc.example\\@elsewhere.example/",
            "https://приватний.example/",
            "http://127.0.0.2:8545/",
            "http://localhost.evil.example:8545/",
            "/relative/path",
        ] {
            assert!(validate_endpoint(endpoint, false).is_err());
        }
        assert!(validate_endpoint("https://rpc.example/?key=secret", true).is_err());
        assert_eq!(
            validate_endpoint("https://activation.example/base/", true).unwrap(),
            "https://activation.example/base"
        );
        assert!(validate_endpoint("http://[0:0:0:0:0:0:0:1]:65535/", false).is_ok());
    }
}
