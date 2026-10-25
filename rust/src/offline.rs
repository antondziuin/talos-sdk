//! The air-gapped exchange, and the identity that makes it possible.
//!
//! Online, a machine proves who it is with the activation secret `activate`
//! hands back. A machine that cannot reach a server never gets one, so it makes
//! its own: an Ed25519 pair at its first offline request, the public half in
//! `talos-request.json`, the private half never leaving the state file. The
//! licence file the portal issues is bound to that key as well as to the
//! fingerprint, and anything the machine sends back is signed by it.
//!
//! The document format is deliberately **not** Talos-compact — that format's
//! `typ` set is the closed list of things the *platform* signs. What is copied is
//! the part that matters: the payload travels base64url-encoded and is verified
//! as received, never re-serialised.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::compact::{B64, B64URL};
use crate::error::{Error, Result};

/// Domain tag of `talos-request.json`; also part of what is signed.
pub const REQUEST_DOMAIN: &str = "talos-offline-request";

/// Domain tag of `talos-deactivation.json`, the document that hands a seat
/// back. Inside the signed bytes so a captured request is never a valid
/// receipt.
pub const RECEIPT_DOMAIN: &str = "talos-offline-deactivation";

/// `kind` of the licence file the portal issues back.
pub const LICENSE_FILE_KIND: &str = "talos-offline-license";

const DOC_VERSION: u32 = 1;

/// A document this machine signed: what gets written to disk and carried to the
/// vendor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDoc {
    /// Format version, `1`.
    pub v: u32,
    /// The domain tag: [`REQUEST_DOMAIN`] or [`RECEIPT_DOMAIN`].
    pub kind: String,
    /// base64url of the payload JSON.
    pub req: String,
    /// base64url Ed25519 signature over `"<kind>.1.<req>"`.
    pub sig: String,
}

impl SignedDoc {
    /// Pretty JSON, ready to write to `talos-request.json` or
    /// `talos-deactivation.json`.
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("a SignedDoc always serialises")
    }
}

/// The machine's identity: seed and public key, both standard base64.
pub(crate) struct MachineKey {
    pub seed: String,
    pub public_key: String,
}

pub(crate) fn generate_machine_key() -> Result<MachineKey> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| Error::usage(format!("no randomness available: {e}")))?;
    let key = SigningKey::from_bytes(&seed);
    Ok(MachineKey {
        seed: B64.encode(seed),
        public_key: B64.encode(key.verifying_key().as_bytes()),
    })
}

/// The exact ASCII bytes a machine document is signed over.
#[must_use]
pub fn signed_message(domain: &str, payload_b64: &str) -> String {
    format!("{domain}.{DOC_VERSION}.{payload_b64}")
}

pub(crate) fn sign_machine_doc(seed_b64: &str, domain: &str, payload: &Value) -> Result<SignedDoc> {
    let seed: [u8; 32] = B64
        .decode(seed_b64)
        .ok()
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::usage("the stored machine key is damaged"))?;
    let key = SigningKey::from_bytes(&seed);
    let req = B64URL.encode(serde_json::to_vec(payload).expect("a JSON value always serialises"));
    let sig = key.sign(signed_message(domain, &req).as_bytes());
    Ok(SignedDoc {
        v: DOC_VERSION,
        kind: domain.to_string(),
        req,
        sig: B64URL.encode(sig.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn a_document_verifies_under_the_machine_key_and_names_its_domain() {
        let key = generate_machine_key().unwrap();
        let doc = sign_machine_doc(
            &key.seed,
            REQUEST_DOMAIN,
            &serde_json::json!({"nonce": "n"}),
        )
        .unwrap();
        assert_eq!(doc.kind, REQUEST_DOMAIN);

        let pk: [u8; 32] = B64.decode(&key.public_key).unwrap().try_into().unwrap();
        let sig: [u8; 64] = B64URL.decode(&doc.sig).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let msg = signed_message(REQUEST_DOMAIN, &doc.req);
        assert!(vk
            .verify(msg.as_bytes(), &Signature::from_bytes(&sig))
            .is_ok());
        // The domain is inside the signed bytes, so a request is not a receipt.
        let other = signed_message(RECEIPT_DOMAIN, &doc.req);
        assert!(vk
            .verify(other.as_bytes(), &Signature::from_bytes(&sig))
            .is_err());
    }
}
