//! Talos-compact token verification.
//!
//! Every answer the server gives is a token of the form
//! `talos.<ver>.<typ>.<b64url(claims)>.<b64url(sig)>`, Ed25519-signed over the
//! exact ASCII prefix before the last dot. Verifying that prefix as received —
//! never a re-serialisation of the claims — is what keeps three implementations
//! from disagreeing about JSON key order and turning that into a rejected
//! signature.
//!
//! These functions IGNORE any `kid`: the key comes from the pin or the
//! anchor-signed keyset, never from the token naming one.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// Tolerance for a slow or slightly-off clock, in seconds. Forgiving about
/// drift while still catching a clock that has been moved.
pub(crate) const CLOCK_SKEW_SECONDS: i64 = 60;

/// base64url, unpadded on the way out and indifferent to padding on the way in.
pub(crate) const B64URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Standard base64, padded on the way out — how keys travel.
pub(crate) const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Decoded token claims.
pub type Claims = Map<String, Value>;

/// A pinned Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub(crate) VerifyingKey);

impl PublicKey {
    /// A key from its standard-base64 raw 32 bytes — the form the portal's
    /// Integration page shows.
    pub fn from_base64(b64: &str) -> Result<Self> {
        let raw = B64
            .decode(b64.trim())
            .map_err(|_| Error::usage("public key is not valid base64"))?;
        let raw: [u8; 32] = raw
            .try_into()
            .map_err(|_| Error::usage("public key must decode to 32 bytes"))?;
        VerifyingKey::from_bytes(&raw)
            .map(PublicKey)
            .map_err(|_| Error::usage("public key is not a valid Ed25519 point"))
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", B64.encode(self.0.as_bytes()))
    }
}

/// Parse a token, check scheme/version/`typ`, and verify the signature against
/// ANY of `keys` (a keyset may carry several valid keys during rotation).
fn parse_and_verify(keys: &[PublicKey], token: &str, expected_typ: &str) -> Result<Claims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 {
        return Err(Error::signature("malformed token"));
    }
    if parts[0] != "talos" {
        return Err(Error::signature("unexpected scheme"));
    }
    if parts[1] != "1" {
        return Err(Error::signature("unsupported wire version"));
    }
    if parts[2] != expected_typ {
        return Err(Error::signature("token type mismatch"));
    }
    if keys.is_empty() {
        return Err(Error::signature("no verification key"));
    }

    let last_dot = token.rfind('.').expect("five segments have four dots");
    let prefix = &token.as_bytes()[..last_dot];
    let sig = B64URL
        .decode(parts[4])
        .map_err(|_| Error::signature("signature is not base64url"))?;
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| Error::signature("signature has the wrong length"))?;
    let sig = Signature::from_bytes(&sig);
    if !keys.iter().any(|k| k.0.verify_strict(prefix, &sig).is_ok()) {
        return Err(Error::signature("signature verification failed"));
    }

    let payload = B64URL
        .decode(parts[3])
        .map_err(|_| Error::signature("claims are not base64url"))?;
    match serde_json::from_slice::<Value>(&payload) {
        Ok(Value::Object(claims)) => Ok(claims),
        _ => Err(Error::signature("claims are not a JSON object")),
    }
}

fn check_aud(claims: &Claims, expected_aud: &str) -> Result<()> {
    if claims.get("aud").and_then(Value::as_str) != Some(expected_aud) {
        return Err(Error::signature("audience mismatch"));
    }
    Ok(())
}

/// Verify a per-request token: signature, `typ`, `aud`, the echoed nonce, and
/// `nbf`/`exp` — both of which are required, not "checked if present".
///
/// Every live token the server mints carries both, so a token without them did
/// not come from a server that knows what it is doing, and treating a missing
/// `exp` as "no expiry" would turn one server-side omission into a verdict
/// valid forever on every install in the field.
pub fn verify_token(
    keys: &[PublicKey],
    expected_typ: &str,
    expected_aud: &str,
    expected_nonce: &str,
    token: &str,
) -> Result<Claims> {
    verify_token_at(
        keys,
        expected_typ,
        expected_aud,
        expected_nonce,
        token,
        unix_now(),
    )
}

pub(crate) fn verify_token_at(
    keys: &[PublicKey],
    expected_typ: &str,
    expected_aud: &str,
    expected_nonce: &str,
    token: &str,
    now: i64,
) -> Result<Claims> {
    let claims = parse_and_verify(keys, token, expected_typ)?;
    check_aud(&claims, expected_aud)?;
    if claims.get("non").and_then(Value::as_str) != Some(expected_nonce) {
        return Err(Error::signature("nonce mismatch (possible replay)"));
    }
    let nbf = number(claims.get("nbf")).ok_or_else(|| Error::signature("token has no nbf"))?;
    if now + CLOCK_SKEW_SECONDS < nbf {
        return Err(Error::signature("token not yet valid"));
    }
    let exp = number(claims.get("exp")).ok_or_else(|| Error::signature("token has no exp"))?;
    if now - CLOCK_SKEW_SECONDS > exp {
        return Err(Error::signature("token expired"));
    }
    Ok(claims)
}

/// Verify a token restored from the local cache, for use while offline.
///
/// The nonce and `exp` deliberately do not apply: the nonce belonged to the
/// request that fetched the token, and `exp` is the short window in which it
/// counts as *fresh* — a cached decision is by definition used after that. What
/// bounds offline use is the `grace_until` claim, enforced by the caller,
/// together with the persisted server-time high-water mark.
pub fn verify_cached_token(
    keys: &[PublicKey],
    expected_typ: &str,
    expected_aud: &str,
    token: &str,
) -> Result<Claims> {
    verify_cached_token_at(keys, expected_typ, expected_aud, token, unix_now())
}

pub(crate) fn verify_cached_token_at(
    keys: &[PublicKey],
    expected_typ: &str,
    expected_aud: &str,
    token: &str,
    now: i64,
) -> Result<Claims> {
    let claims = parse_and_verify(keys, token, expected_typ)?;
    check_aud(&claims, expected_aud)?;
    if let Some(nbf) = number(claims.get("nbf")) {
        if now + CLOCK_SKEW_SECONDS < nbf {
            return Err(Error::signature("cached token not yet valid"));
        }
    }
    Ok(claims)
}

/// Verify a signed update manifest (`typ=manifest`) against the release key(s).
///
/// A manifest is a long-lived artifact, so there is no nonce and no short
/// `exp`; it carries a `not_before` gate instead.
pub fn verify_manifest(
    release_keys: &[PublicKey],
    expected_aud: &str,
    token: &str,
) -> Result<Claims> {
    verify_manifest_at(release_keys, expected_aud, token, unix_now())
}

pub(crate) fn verify_manifest_at(
    release_keys: &[PublicKey],
    expected_aud: &str,
    token: &str,
    now: i64,
) -> Result<Claims> {
    let claims = parse_and_verify(release_keys, token, "manifest")?;
    check_aud(&claims, expected_aud)?;
    if let Some(not_before) = number(claims.get("not_before")) {
        if now + CLOCK_SKEW_SECONDS < not_before {
            return Err(Error::signature("manifest not yet released"));
        }
    }
    Ok(claims)
}

/// Verify a signed keyset (`typ=keyset`) against the pinned anchor.
///
/// The keyset lists the product's current, rotatable license and release keys,
/// so a client that pins only the anchor learns the signing keys from it — and a
/// rotated key never breaks a deployed application.
pub fn verify_keyset(anchor: &PublicKey, expected_aud: &str, token: &str) -> Result<Claims> {
    let claims = parse_and_verify(std::slice::from_ref(anchor), token, "keyset")?;
    check_aud(&claims, expected_aud)?;
    Ok(claims)
}

/// A finite JSON number as whole seconds, or `None`.
pub(crate) fn number(v: Option<&Value>) -> Option<i64> {
    let v = v?;
    v.as_i64()
        .or_else(|| v.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
