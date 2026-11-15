//! The code-activation wire protocol. This module never grants a license or persists a code.
//! A ready response still needs pinned-manifest and fresh on-chain validation by the caller.

use std::{io::Read, time::Duration};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use super::{
    protocol::{
        activation_proof_text, hex, registry_uuid, status_proof_text, validate_endpoint,
        RegistryLicenseManifest,
    },
    RegistryError, RegistryResult,
};
use crate::transport::{HttpRequest, Transport};

const MAX_RESPONSE_BYTES: u64 = 65_536;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// A publication claim from the activation API, never an authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActivationStatus {
    Pending,
    Ready,
    Failed,
}

/// Validated response shape. Remote diagnostic text is intentionally not retained.
#[derive(Debug, Clone)]
pub(super) struct ActivationResponse {
    pub status: ActivationStatus,
    pub activation_id: String,
    pub manifest: Option<RegistryLicenseManifest>,
    pub retry_after_s: u64,
}

/// Trusted application activation settings, independent of customer-supplied files.
#[derive(Clone)]
pub(super) struct ActivationEndpoint {
    endpoint: String,
    product_token: String,
}

impl ActivationEndpoint {
    pub fn new(endpoint: &str, product_token: &str) -> RegistryResult<Self> {
        if product_token.is_empty() || product_token.len() > 256 {
            return Err(RegistryError::new("invalid_registry_configuration"));
        }
        Ok(Self {
            endpoint: validate_endpoint(endpoint, true)?,
            product_token: product_token.to_owned(),
        })
    }

    /// Claim a code once. The caller owns the deadline, request UUID and encrypted device key.
    pub fn activate(
        &self,
        transport: &dyn Transport,
        key: &SigningKey,
        code: &str,
        request_id: &str,
        timeout: Duration,
    ) -> RegistryResult<ActivationResponse> {
        let code = code.trim();
        if code.is_empty() || code.len() > 512 {
            return Err(RegistryError::new("activation_code_required"));
        }
        let device = hex(key.verifying_key().as_bytes());
        let request_id = canonical_id(request_id)?;
        let message = activation_proof_text(&self.product_token, code, &device, &request_id)?;
        self.post(
            transport,
            "activate",
            json!({
                "product_token": self.product_token,
                "license_key": code,
                "device_key": device,
                "request_id": request_id,
                "proof": hex(&key.sign(message.as_bytes()).to_bytes()),
            }),
            timeout,
        )
    }

    /// Poll using only a device signature and public identifiers, never the original code.
    /// `activation_not_found` is returned intact so the caller can clear only the pending ID.
    pub fn poll(
        &self,
        transport: &dyn Transport,
        key: &SigningKey,
        activation_id: &str,
        timeout: Duration,
    ) -> RegistryResult<ActivationResponse> {
        let device = hex(key.verifying_key().as_bytes());
        let activation_id = canonical_id(activation_id)?;
        let message = status_proof_text(&self.product_token, &activation_id, &device)?;
        let response = self.post(
            transport,
            "activation-status",
            json!({
                "product_token": self.product_token,
                "activation_id": activation_id,
                "device_key": device,
                "proof": hex(&key.sign(message.as_bytes()).to_bytes()),
            }),
            timeout,
        )?;
        if response.activation_id != activation_id {
            return Err(invalid_response());
        }
        Ok(response)
    }

    /// Report a launch. The response carries nothing; only delivery matters.
    #[allow(clippy::too_many_arguments)]
    pub fn checkin(
        &self,
        transport: &dyn Transport,
        key: &SigningKey,
        license_id: &str,
        install_id: &str,
        timestamp: u64,
        app_version: Option<&str>,
        timeout: Duration,
    ) -> RegistryResult<()> {
        let unavailable = || RegistryError::new("registry_checkin_unavailable");
        let device = hex(key.verifying_key().as_bytes());
        let message = super::protocol::checkin_proof_text(
            &self.product_token,
            license_id,
            &device,
            install_id,
            timestamp,
        )?;
        let body = serde_json::to_vec(&json!({
            "product_token": self.product_token,
            "license_id": license_id,
            "device_key": device,
            "install_id": install_id,
            "timestamp": timestamp,
            "platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            "app_version": app_version,
            "proof": hex(&key.sign(message.as_bytes()).to_bytes()),
        }))
        .map_err(|_| unavailable())?;
        let response = transport
            .send(HttpRequest {
                method: "POST",
                url: format!("{}/v1/client/registry/checkin", self.endpoint),
                headers: vec![("content-type", "application/json".into())],
                body: Some(body),
                timeout: Some(timeout.min(HTTP_TIMEOUT)),
            })
            .map_err(|_| unavailable())?;
        if response.status == 204 {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    fn post(
        &self,
        transport: &dyn Transport,
        path: &str,
        body: Value,
        timeout: Duration,
    ) -> RegistryResult<ActivationResponse> {
        if timeout.is_zero() {
            return Err(RegistryError::new("registry_activation_timeout"));
        }
        let body = serde_json::to_vec(&body).map_err(|_| invalid_response())?;
        let response = transport
            .send(HttpRequest {
                method: "POST",
                url: format!("{}/v1/client/registry/{path}", self.endpoint),
                headers: vec![("content-type", "application/json".into())],
                body: Some(body),
                timeout: Some(timeout.min(HTTP_TIMEOUT)),
            })
            // Transport messages may include the URL, request body, or raw code. Never expose them.
            .map_err(|_| RegistryError::new("registry_activation_unavailable"))?;
        if response
            .content_length
            .is_some_and(|len| len > MAX_RESPONSE_BYTES)
        {
            return Err(invalid_response());
        }
        let status = response.status;
        let mut bytes = Vec::new();
        response
            .body
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RegistryError::new("registry_activation_unavailable"))?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(invalid_response());
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid_response())?;
        if !(200..300).contains(&status) {
            return Err(api_error(status, &value));
        }
        parse_response(value)
    }
}

fn api_error(status: u16, body: &Value) -> RegistryError {
    let code = body.get("error").and_then(Value::as_str);
    let known = [
        "license_not_found",
        "activation_already_bound",
        "automatic_activation_not_enabled",
        "invalid_registry_activation",
        "invalid_device_proof",
        "activation_not_found",
        "license_inactive",
        "tenant_closed",
        "registry_activation_unavailable",
        "registry_base_activation_disabled",
        "rate_limited",
    ];
    match known.into_iter().find(|known| Some(*known) == code) {
        Some(code) => RegistryError::new(code),
        None => RegistryError::new(match status {
            400 => "registry_activation_http_400",
            401 => "registry_activation_http_401",
            403 => "registry_activation_http_403",
            404 => "registry_activation_http_404",
            409 => "registry_activation_http_409",
            422 => "registry_activation_http_422",
            429 => "registry_activation_http_429",
            500 => "registry_activation_http_500",
            502 => "registry_activation_http_502",
            503 => "registry_activation_http_503",
            504 => "registry_activation_http_504",
            _ => "registry_activation_http_error",
        }),
    }
}

fn parse_response(value: Value) -> RegistryResult<ActivationResponse> {
    let object = value.as_object().ok_or_else(invalid_response)?;
    let fields = [
        "status",
        "activation_id",
        "manifest",
        "error",
        "retry_after_s",
    ];
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(invalid_response());
    }
    let status = match object["status"].as_str() {
        Some("pending") => ActivationStatus::Pending,
        Some("ready") => ActivationStatus::Ready,
        Some("failed") => ActivationStatus::Failed,
        _ => return Err(invalid_response()),
    };
    let activation_id = canonical_id(
        object["activation_id"]
            .as_str()
            .ok_or_else(invalid_response)?,
    )
    .map_err(|_| invalid_response())?;
    let retry_after_s = object["retry_after_s"]
        .as_u64()
        .filter(|seconds| *seconds <= 60)
        .ok_or_else(invalid_response)?;
    if !object["error"].is_null() && !object["error"].is_string() {
        return Err(invalid_response());
    }
    let manifest = if status == ActivationStatus::Ready {
        if !object["error"].is_null() {
            return Err(invalid_response());
        }
        Some(serde_json::from_value(object["manifest"].clone()).map_err(|_| invalid_response())?)
    } else {
        if !object["manifest"].is_null() {
            return Err(invalid_response());
        }
        None
    };
    Ok(ActivationResponse {
        status,
        activation_id,
        manifest,
        retry_after_s,
    })
}

fn canonical_id(value: &str) -> RegistryResult<String> {
    if !registry_uuid(value) {
        return Err(RegistryError::new("invalid_activation_request_id"));
    }
    Ok(value.to_ascii_lowercase())
}

fn invalid_response() -> RegistryError {
    RegistryError::new("invalid_registry_activation_response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    use ed25519_dalek::Signature;

    use crate::transport::HttpResponse;

    const TOKEN: &str = "tpt_activation_wire_fixture";
    const CODE: &str = "SYNTHETIC-CODE-ONLY";
    const REQUEST: &str = "11111111-1111-4111-8111-111111111111";
    const ACTIVATION: &str = "22222222-2222-4222-8222-222222222222";
    const PRIVATE_TEXT: &str = "SYNTHETIC_REQUEST_VALUE_MUST_NOT_ESCAPE";

    enum Reply {
        Bytes(u16, Vec<u8>, Option<u64>),
        Network,
        BrokenBody,
    }
    struct Fake {
        requests: Mutex<Vec<HttpRequest>>,
        replies: Mutex<VecDeque<Reply>>,
    }
    impl Fake {
        fn new(replies: Vec<Reply>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                replies: Mutex::new(replies.into()),
            }
        }
        fn json(status: u16, value: Value) -> Self {
            Self::new(vec![Reply::Bytes(
                status,
                serde_json::to_vec(&value).unwrap(),
                None,
            )])
        }
        fn body(&self, index: usize) -> Value {
            serde_json::from_slice(self.requests.lock().unwrap()[index].body.as_ref().unwrap())
                .unwrap()
        }
    }
    impl Transport for Fake {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            self.requests.lock().unwrap().push(request);
            match self.replies.lock().unwrap().pop_front() {
                Some(Reply::Bytes(status, body, content_length)) => Ok(HttpResponse {
                    status,
                    content_length,
                    body: Box::new(std::io::Cursor::new(body)),
                }),
                Some(Reply::BrokenBody) => {
                    struct Broken;
                    impl Read for Broken {
                        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                            Err(std::io::Error::other(PRIVATE_TEXT))
                        }
                    }
                    Ok(HttpResponse {
                        status: 200,
                        content_length: None,
                        body: Box::new(Broken),
                    })
                }
                _ => Err(PRIVATE_TEXT.into()),
            }
        }
    }
    fn pending() -> Value {
        json!({"status":"pending","activation_id":ACTIVATION,"manifest":null,"error":null,"retry_after_s":2})
    }
    fn endpoint() -> ActivationEndpoint {
        ActivationEndpoint::new("https://publisher.example/", TOKEN).unwrap()
    }
    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }
    fn activate(fake: &Fake) -> RegistryResult<ActivationResponse> {
        endpoint().activate(fake, &key(), CODE, REQUEST, Duration::from_secs(50))
    }
    fn signature(body: &Value) -> Signature {
        let bytes = super::super::protocol::decode_hex(body["proof"].as_str().unwrap()).unwrap();
        Signature::from_slice(&bytes).unwrap()
    }

    #[test]
    fn initial_claim_matches_independent_node_proof_vector_and_trims_only_the_code() {
        let fake = Fake::json(200, pending());
        let response = endpoint()
            .activate(
                &fake,
                &key(),
                &format!("  {CODE}\t"),
                REQUEST,
                Duration::from_secs(50),
            )
            .unwrap();
        assert_eq!(response.status, ActivationStatus::Pending);
        assert_eq!(response.activation_id, ACTIVATION);
        assert_eq!(response.retry_after_s, 2);
        assert!(response.manifest.is_none());
        let body = fake.body(0);
        assert_eq!(body["license_key"], CODE);
        assert_eq!(body["product_token"], TOKEN);
        assert_eq!(body["request_id"], REQUEST);
        let expected = "talos-registry-activation.1.0x067a6cc704f681bc047fa78dacefa7dae92ff47c2a225a5e1e7b46d336f3f633.0xd284e0b070ed1c16382dd3b45711b047f6a47370e234ee75f1263f093ee37b42.0xea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c.11111111-1111-4111-8111-111111111111";
        key()
            .verifying_key()
            .verify_strict(expected.as_bytes(), &signature(&body))
            .unwrap();
        let requests = fake.requests.lock().unwrap();
        assert_eq!(
            requests[0].url,
            "https://publisher.example/v1/client/registry/activate"
        );
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].timeout, Some(Duration::from_secs(10)));
    }

    #[test]
    fn polling_has_independent_domain_and_no_code_and_checks_the_returned_job_id() {
        let fake = Fake::json(200, pending());
        endpoint()
            .poll(&fake, &key(), ACTIVATION, Duration::from_millis(31))
            .unwrap();
        let body = fake.body(0);
        assert!(body.get("license_key").is_none());
        assert!(body.get("request_id").is_none());
        assert_eq!(body["activation_id"], ACTIVATION);
        let expected = "talos-registry-status.1.0x067a6cc704f681bc047fa78dacefa7dae92ff47c2a225a5e1e7b46d336f3f633.22222222-2222-4222-8222-222222222222.0xea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
        key()
            .verifying_key()
            .verify_strict(expected.as_bytes(), &signature(&body))
            .unwrap();
        assert_eq!(
            fake.requests.lock().unwrap()[0].timeout,
            Some(Duration::from_millis(31))
        );
        assert!(fake.requests.lock().unwrap()[0]
            .url
            .ends_with("/activation-status"));
        let mut wrong = pending();
        wrong["activation_id"] = json!(REQUEST);
        let fake = Fake::json(200, wrong);
        assert!(endpoint()
            .poll(&fake, &key(), ACTIVATION, HTTP_TIMEOUT)
            .unwrap_err()
            .to_string()
            .contains("invalid_registry_activation_response"));
    }

    #[test]
    fn unknown_jobs_preserve_the_clear_pending_signal_and_other_errors_are_safe() {
        for code in [
            "activation_not_found",
            "license_not_found",
            "activation_already_bound",
            "registry_base_activation_disabled",
        ] {
            let fake = Fake::json(404, json!({"error":code,"details":PRIVATE_TEXT}));
            let error = endpoint()
                .poll(&fake, &key(), ACTIVATION, HTTP_TIMEOUT)
                .unwrap_err();
            assert!(error.to_string().contains(code));
            assert!(!format!("{error:?} {error}").contains(PRIVATE_TEXT));
        }
        let fake = Fake::json(503, json!({"error":PRIVATE_TEXT}));
        let error = activate(&fake).unwrap_err();
        assert!(error.to_string().contains("registry_activation_http_503"));
        assert!(!format!("{error:?} {error}").contains(PRIVATE_TEXT));
        for reply in [Reply::Network, Reply::BrokenBody] {
            let error = activate(&Fake::new(vec![reply])).unwrap_err();
            assert!(error
                .to_string()
                .contains("registry_activation_unavailable"));
            assert!(!format!("{error:?} {error}").contains(PRIVATE_TEXT));
        }
    }

    #[test]
    fn all_response_fields_and_pending_manifest_secrecy_are_checked() {
        let mut variants = Vec::new();
        for field in [
            "status",
            "activation_id",
            "manifest",
            "error",
            "retry_after_s",
        ] {
            let mut value = pending();
            value.as_object_mut().unwrap().remove(field);
            variants.push(value);
        }
        for (field, value) in [
            ("status", json!("unknown")),
            ("activation_id", json!("not-a-uuid")),
            ("manifest", json!({"leaked":"pending"})),
            ("error", json!({"raw":PRIVATE_TEXT})),
            ("retry_after_s", json!(-1)),
            ("retry_after_s", json!(61)),
            ("retry_after_s", json!(1.5)),
            ("extra", json!(true)),
        ] {
            let mut candidate = pending();
            candidate[field] = value;
            variants.push(candidate);
        }
        for value in variants {
            let error = activate(&Fake::json(200, value)).unwrap_err();
            assert!(error
                .to_string()
                .contains("invalid_registry_activation_response"));
            assert!(!error.to_string().contains(PRIVATE_TEXT));
        }
        let mut failure = pending();
        failure["status"] = json!("failed");
        failure["error"] = json!(PRIVATE_TEXT);
        let response = activate(&Fake::json(200, failure)).unwrap();
        assert_eq!(response.status, ActivationStatus::Failed);
        assert!(!format!("{response:?}").contains(PRIVATE_TEXT));
    }

    #[test]
    fn ready_is_only_a_typed_claim_and_remote_error_text_is_never_kept() {
        let mut response = pending();
        response["status"] = json!("ready");
        assert!(activate(&Fake::json(200, response.clone())).is_err());
        response["manifest"] = json!({
            "v":1,"kind":"talos-registry-license","chain_id":8453,
            "contract":format!("0x{}","11".repeat(20)),"issuer":format!("0x{}","22".repeat(20)),
            "product_id":format!("0x{}","33".repeat(32)),"license_id":format!("0x{}","44".repeat(32)),
            "holder":format!("0x{}","22".repeat(20)),"entitlements":"eyJwcm8iOnRydWV9"
        });
        let claim = activate(&Fake::json(200, response.clone())).unwrap();
        assert_eq!(claim.status, ActivationStatus::Ready);
        assert!(claim.manifest.is_some());
        response["error"] = json!(PRIVATE_TEXT);
        let error = activate(&Fake::json(200, response)).unwrap_err();
        assert!(!error.to_string().contains(PRIVATE_TEXT));
    }

    #[test]
    fn response_size_and_parse_failures_are_bounded_and_redacted() {
        for reply in [
            Reply::Bytes(200, b"{}".to_vec(), Some(MAX_RESPONSE_BYTES + 1)),
            Reply::Bytes(200, vec![b' '; MAX_RESPONSE_BYTES as usize + 1], None),
            Reply::Bytes(200, PRIVATE_TEXT.as_bytes().to_vec(), None),
        ] {
            let error = activate(&Fake::new(vec![reply])).unwrap_err();
            assert!(error
                .to_string()
                .contains("invalid_registry_activation_response"));
            assert!(!error.to_string().contains(PRIVATE_TEXT));
        }
    }

    #[test]
    fn invalid_configuration_inputs_and_exhausted_deadline_never_reach_transport() {
        for url in [
            "http://external.example",
            "https://publisher.example/?token=private",
            "https://user:pass@publisher.example",
            "https://publisher.example/#fragment",
        ] {
            assert!(ActivationEndpoint::new(url, TOKEN).is_err());
        }
        assert!(ActivationEndpoint::new("https://publisher.example", "").is_err());
        assert!(ActivationEndpoint::new("http://127.0.0.1:18081", TOKEN).is_ok());
        let fake = Fake::new(Vec::new());
        for code in ["", "   "] {
            assert!(endpoint()
                .activate(&fake, &key(), code, REQUEST, HTTP_TIMEOUT)
                .is_err());
        }
        assert!(endpoint()
            .activate(&fake, &key(), CODE, "invalid", HTTP_TIMEOUT)
            .is_err());
        assert!(endpoint()
            .poll(&fake, &key(), "invalid", HTTP_TIMEOUT)
            .is_err());
        assert!(endpoint()
            .activate(&fake, &key(), CODE, REQUEST, Duration::ZERO)
            .is_err());
        assert!(fake.requests.lock().unwrap().is_empty());
    }
}
