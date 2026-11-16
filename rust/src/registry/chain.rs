//! Fresh, pinned, read-only registry snapshots and monotonic observation merging.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::transport::{HttpRequest, Transport};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use super::protocol::{
    decode_hex, fixed_hex, hex, keccak_hex, validate_endpoint, validate_trust, ParsedManifest,
    RegistryLicenseManifest, RegistryTrust,
};
use super::RegistryError;

const MAX_SAFE: u64 = 9_007_199_254_740_991;
const RUNTIME_HASH: &str = "0xa87a5b6815e052c3833968b93d7bac89fce3fe4406ddc5b6a3dab930820f64bb";
/// TalosLicenseActivatorV1: same compiler settings, non-upgradeable, ownerless, no immutables.
const ACTIVATOR_RUNTIME_HASH: &str =
    "0x8b0141e57fe37f1360a476111d893cc258cdba407d097e6c21107ce5e236f916";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryHead {
    pub number: String,
    pub hash: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryObservation {
    pub revision: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryChainState {
    pub v: u8,
    pub head: RegistryHead,
    pub licenses: BTreeMap<String, RegistryObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegistryRecord {
    pub holder: String,
    pub device_key: String,
    pub not_before: u64,
    pub expires_at: u64,
    pub entitlements_hash: String,
    pub revision: u64,
    pub status: u8,
}

pub(crate) struct ReadInput<'a> {
    pub trust: &'a RegistryTrust,
    pub parsed: &'a ParsedManifest,
    pub device_key: &'a str,
    pub prior_state: Option<&'a RegistryChainState>,
    pub time_high_water: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ReadObservation {
    pub head: RegistryHead,
    pub record: RegistryRecord,
    pub refusal: Option<&'static str>,
    pub reorg: bool,
    pub checked_at: u64,
}

#[derive(Debug, Clone)]
struct Block {
    number: u64,
    timestamp: u64,
    hash: String,
    tag: String,
}

impl Block {
    fn head(&self) -> RegistryHead {
        RegistryHead {
            number: self.number.to_string(),
            hash: self.hash.clone(),
            timestamp: self.timestamp,
        }
    }
}

fn invalid() -> RegistryError {
    RegistryError::new("invalid_registry_rpc_response")
}

fn decimal(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    value.parse::<u64>().ok().filter(|n| *n <= MAX_SAFE)
}

fn quantity(value: &Value) -> Result<u64, RegistryError> {
    let raw = value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or_else(invalid)?;
    if raw.is_empty()
        || raw.len() > 14
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    u64::from_str_radix(raw, 16)
        .ok()
        .filter(|n| *n <= MAX_SAFE)
        .ok_or_else(invalid)
}

fn block(value: &Value) -> Result<Block, RegistryError> {
    Ok(Block {
        number: quantity(&value["number"])?,
        timestamp: quantity(&value["timestamp"])?,
        hash: fixed_hex(value["hash"].as_str().ok_or_else(invalid)?, 32).map_err(|_| invalid())?,
        tag: value["number"].as_str().ok_or_else(invalid)?.to_owned(),
    })
}

pub(crate) fn same_head(a: &RegistryHead, b: &RegistryHead) -> bool {
    a.number == b.number && a.hash.eq_ignore_ascii_case(&b.hash) && a.timestamp == b.timestamp
}

pub(crate) fn parse_chain_state(
    raw: Option<&str>,
) -> Result<Option<RegistryChainState>, RegistryError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let parse = || -> Option<RegistryChainState> {
        if raw.len() > 32_768 {
            return None;
        }
        let mut state: RegistryChainState = serde_json::from_str(raw).ok()?;
        if state.v != 1
            || decimal(&state.head.number).is_none()
            || state.head.timestamp > MAX_SAFE
            || state.licenses.len() > 64
        {
            return None;
        }
        state.head.hash = fixed_hex(&state.head.hash, 32).ok()?;
        for (id, observation) in &state.licenses {
            if fixed_hex(id, 32).ok().as_deref() != Some(id.as_str())
                || observation.revision > MAX_SAFE
            {
                return None;
            }
        }
        Some(state)
    };
    parse()
        .map(Some)
        .ok_or_else(|| RegistryError::new("invalid_registry_chain_state"))
}

pub(crate) fn merge_observation(
    current: Option<&RegistryChainState>,
    initial: Option<&RegistryChainState>,
    observation: &ReadObservation,
    license_id: &str,
) -> Result<(RegistryChainState, bool), RegistryError> {
    let id =
        fixed_hex(license_id, 32).map_err(|_| RegistryError::new("invalid_registry_manifest"))?;
    if let Some(seen) = current {
        if decimal(&observation.head.number).ok_or_else(invalid)?
            < decimal(&seen.head.number).ok_or_else(invalid)?
        {
            return Err(RegistryError::transient("rpc_block_lag"));
        }
        if !same_head(&seen.head, &observation.head)
            && initial.is_none_or(|s| !same_head(&seen.head, &s.head))
        {
            return Err(RegistryError::transient("rpc_head_changed"));
        }
    }
    let mut licenses = current.map(|s| s.licenses.clone()).unwrap_or_default();
    let prior = licenses.get(&id);
    if observation.refusal.is_none()
        && prior.is_some_and(|p| observation.record.revision < p.revision)
    {
        return Err(if observation.reorg {
            RegistryError::new("registry_reorg_conflict")
        } else {
            RegistryError::transient("rpc_state_rollback")
        });
    }
    if prior.is_none() && licenses.len() >= 64 {
        return Err(RegistryError::new("registry_observation_limit"));
    }
    let terminal = observation.record.status == 3 || prior.is_some_and(|p| p.revoked);
    let revision = observation
        .record
        .revision
        .max(prior.map_or(0, |p| p.revision));
    licenses.insert(
        id,
        RegistryObservation {
            revision,
            revoked: terminal,
        },
    );
    Ok((
        RegistryChainState {
            v: 1,
            head: observation.head.clone(),
            licenses,
        },
        terminal,
    ))
}

struct Rpc<'a> {
    transport: &'a dyn Transport,
    url: &'a str,
}

impl Rpc<'_> {
    fn call(&self, method: &'static str, params: Value) -> Result<Value, RegistryError> {
        if ![
            "eth_chainId",
            "eth_getBlockByNumber",
            "eth_getCode",
            "eth_call",
        ]
        .contains(&method)
        {
            return Err(invalid());
        }
        let response = self
            .transport
            .send(HttpRequest {
                method: "POST",
                url: self.url.to_owned(),
                headers: vec![("content-type", "application/json".into())],
                body: Some(
                    serde_json::to_vec(
                        &json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
                    )
                    .map_err(|_| invalid())?,
                ),
                timeout: Some(Duration::from_secs(10)),
            })
            .map_err(|_| RegistryError::transient("registry_rpc_unavailable"))?;
        if !(200..300).contains(&response.status) {
            return Err(
                // Authentication and quota failures belong to this RPC provider,
                // not to the on-chain license. Another independently pinned
                // provider must still perform every verification from scratch.
                if [401, 403, 408, 429].contains(&response.status) || response.status >= 500 {
                    RegistryError::transient("registry_rpc_unavailable")
                } else {
                    RegistryError::new("registry_rpc_rejected")
                },
            );
        }
        if response.content_length.is_some_and(|n| n > 1_048_576) {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        response
            .body
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| RegistryError::transient("registry_rpc_unavailable"))?;
        if bytes.len() > 1_048_576 {
            return Err(invalid());
        }
        let envelope: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if !envelope.is_object()
            || envelope["jsonrpc"] != "2.0"
            || envelope["id"].as_u64() != Some(1)
        {
            return Err(invalid());
        }
        if let Some(error) = envelope
            .get("error")
            .filter(|e| !e.is_null() && **e != Value::Bool(false))
        {
            return Err(
                if [-32005, -32002, -32603].contains(&error["code"].as_i64().unwrap_or(0)) {
                    RegistryError::transient("registry_rpc_unavailable")
                } else {
                    RegistryError::new("registry_rpc_rejected")
                },
            );
        }
        envelope.get("result").cloned().ok_or_else(invalid)
    }

    fn call_contract(
        &self,
        contract: &str,
        tag: &str,
        data: String,
    ) -> Result<Vec<u8>, RegistryError> {
        let result = self.call("eth_call", json!([{"to":contract,"data":data},tag]))?;
        decode_hex(result.as_str().ok_or_else(invalid)?).map_err(|_| invalid())
    }
}

fn selector(signature: &str) -> String {
    keccak_hex(signature.as_bytes())[..10].to_owned()
}

fn address_word(address: &str) -> Result<String, RegistryError> {
    let address = fixed_hex(address, 20).map_err(|_| invalid())?;
    Ok(format!("{}{}", "0".repeat(24), &address[2..]))
}

fn uint_word(word: &[u8], width: usize) -> Result<u64, RegistryError> {
    if word.len() != 32 || word[..32 - width].iter().any(|b| *b != 0) {
        return Err(RegistryError::new("invalid_registry_record"));
    }
    let value = word[32 - width..]
        .iter()
        .fold(0u64, |n, b| (n << 8) | u64::from(*b));
    if value > MAX_SAFE {
        return Err(RegistryError::new("invalid_registry_record"));
    }
    Ok(value)
}

fn record(bytes: &[u8]) -> Result<RegistryRecord, RegistryError> {
    if bytes.len() != 224 || bytes[..12].iter().any(|b| *b != 0) {
        return Err(RegistryError::new("invalid_registry_record"));
    }
    let words: Vec<_> = bytes.chunks_exact(32).collect();
    let record = RegistryRecord {
        holder: hex(&words[0][12..]),
        device_key: hex(words[1]),
        not_before: uint_word(words[2], 8)?,
        expires_at: uint_word(words[3], 8)?,
        entitlements_hash: hex(words[4]),
        revision: uint_word(words[5], 8)?,
        status: uint_word(words[6], 1)? as u8,
    };
    if record.status > 3 || (record.status != 0 && record.revision == 0) {
        return Err(RegistryError::new("invalid_registry_record"));
    }
    Ok(record)
}

fn boolean(bytes: &[u8]) -> Result<bool, RegistryError> {
    if bytes.len() != 32 || bytes[..31].iter().any(|b| *b != 0) || bytes[31] > 1 {
        return Err(invalid());
    }
    Ok(bytes[31] == 1)
}

/// The exact runtime code and version of a pinned contract at `tag`.
fn verify_runtime(
    rpc: &Rpc<'_>,
    contract: &str,
    tag: &str,
    runtime_hash: &str,
    version: &str,
    codes: [&'static str; 3],
) -> Result<(), RegistryError> {
    let [missing, wrong_runtime, wrong_version] = codes;
    let code = rpc.call("eth_getCode", json!([contract, tag]))?;
    let code = decode_hex(code.as_str().ok_or_else(|| RegistryError::new(missing))?)
        .map_err(|_| RegistryError::new(missing))?;
    if code.is_empty() {
        return Err(RegistryError::new(missing));
    }
    if keccak_hex(&code) != runtime_hash {
        return Err(RegistryError::new(wrong_runtime));
    }
    let reported = rpc.call_contract(contract, tag, selector(version))?;
    if reported.len() != 32 || reported[..31].iter().any(|b| *b != 0) || reported[31] != 1 {
        return Err(RegistryError::new(wrong_version));
    }
    Ok(())
}

fn verify_registry(rpc: &Rpc<'_>, contract: &str, tag: &str) -> Result<(), RegistryError> {
    verify_runtime(
        rpc,
        contract,
        tag,
        RUNTIME_HASH,
        "registryVersion()",
        [
            "registry_contract_missing",
            "wrong_registry_runtime",
            "wrong_registry_version",
        ],
    )
}

/// ABI-decodes a returned `bytes` value: an offset word, a length word, then padded data.
fn abi_bytes(bytes: &[u8]) -> Result<Vec<u8>, RegistryError> {
    if bytes.len() < 64 || bytes.len() % 32 != 0 || uint_word(&bytes[..32], 8).ok() != Some(32) {
        return Err(invalid());
    }
    let length = uint_word(&bytes[32..64], 8).map_err(|_| invalid())? as usize;
    let room = bytes.len() - 64;
    if length > room || room - length >= 32 || length > 32_768 {
        return Err(invalid());
    }
    Ok(bytes[64..64 + length].to_vec())
}

/// What an application knows about a recoverable license before it has a manifest.
pub(crate) struct RecoveryInput<'a> {
    pub trust: &'a RegistryTrust,
    /// Pinned `TalosLicenseActivatorV1` address.
    pub activator: &'a str,
    /// Identifier derived from the code.
    pub license_id: &'a str,
    /// Public device key derived from the same code.
    pub device_key: &'a str,
}

fn recover_url(
    rpc: &Rpc<'_>,
    input: &RecoveryInput<'_>,
    now: &mut impl FnMut() -> u64,
) -> Result<Option<RegistryLicenseManifest>, RegistryError> {
    if quantity(&rpc.call("eth_chainId", json!([]))?)? != input.trust.chain_id {
        return Err(RegistryError::new("wrong_rpc_chain"));
    }
    let latest = block(&rpc.call("eth_getBlockByNumber", json!(["latest", false]))?)?;
    let time = now();
    if latest.timestamp < time.saturating_sub(300) || latest.timestamp > time.saturating_add(30) {
        return Err(RegistryError::transient("stale_rpc_block"));
    }
    verify_registry(rpc, &input.trust.contract, &latest.tag)?;
    verify_runtime(
        rpc,
        input.activator,
        &latest.tag,
        ACTIVATOR_RUNTIME_HASH,
        "activatorVersion()",
        [
            "registry_activator_missing",
            "wrong_registry_activator",
            "wrong_registry_activator",
        ],
    )?;
    let calldata = format!(
        "{}{}{}{}",
        selector("getLicense(address,bytes32,bytes32)"),
        address_word(&input.trust.issuer)?,
        &input.trust.product_id[2..],
        &input.license_id[2..]
    );
    let record = record(&rpc.call_contract(&input.trust.contract, &latest.tag, calldata)?)?;
    // Nothing published under this code yet, or a record this code's key cannot claim: an
    // installation activated before recovery existed, or a binding still in flight. Neither
    // is an error; the caller falls back to the activation service.
    if record.status == 0
        || !record.holder.eq_ignore_ascii_case(input.activator)
        || !record.device_key.eq_ignore_ascii_case(input.device_key)
    {
        return Ok(None);
    }
    let published = abi_bytes(&rpc.call_contract(
        input.activator,
        &latest.tag,
        format!(
            "{}{}",
            selector("getEntitlements(bytes32)"),
            &record.entitlements_hash[2..]
        ),
    )?)?;
    // The activator is a plain store; the registry record is what makes these bytes true.
    if published.is_empty() || keccak_hex(&published) != record.entitlements_hash {
        return Ok(None);
    }
    let canonical = rpc.call("eth_getBlockByNumber", json!([latest.tag, false]))?;
    if canonical.is_null() || !same_head(&latest.head(), &block(&canonical)?.head()) {
        return Err(RegistryError::transient("rpc_snapshot_reorg"));
    }
    Ok(Some(RegistryLicenseManifest {
        v: 1,
        kind: "talos-registry-license".into(),
        chain_id: input.trust.chain_id,
        contract: input.trust.contract.clone(),
        issuer: input.trust.issuer.clone(),
        product_id: input.trust.product_id.clone(),
        license_id: input.license_id.to_ascii_lowercase(),
        holder: input.activator.to_ascii_lowercase(),
        entitlements: URL_SAFE_NO_PAD.encode(&published),
    }))
}

/// Rebuild the public manifest of a recoverable license from chain data alone: the record
/// the code names, and the entitlement text its activator published. `None` means there is
/// nothing here for this code and key to recover. Like any manifest, the result grants
/// nothing by itself; the caller validates it against the registry before keeping it.
pub(crate) fn recover_manifest(
    transport: &dyn Transport,
    rpc_urls: &[String],
    input: &RecoveryInput<'_>,
    mut now: impl FnMut() -> u64,
) -> Result<Option<RegistryLicenseManifest>, RegistryError> {
    validate_trust(input.trust)?;
    fixed_hex(input.activator, 20)
        .map_err(|_| RegistryError::new("invalid_registry_configuration"))?;
    fixed_hex(input.license_id, 32).map_err(|_| RegistryError::new("invalid_registry_manifest"))?;
    fixed_hex(input.device_key, 32).map_err(|_| RegistryError::new("invalid_device_key"))?;
    if rpc_urls.is_empty() || rpc_urls.len() > 5 {
        return Err(RegistryError::new("invalid_registry_configuration"));
    }
    let mut transient = RegistryError::transient("registry_rpc_unavailable");
    for url in rpc_urls {
        validate_endpoint(url, false)?;
        match recover_url(&Rpc { transport, url }, input, &mut now) {
            Ok(found) => return Ok(found),
            Err(error) if error.is_transient() => transient = error,
            Err(error) => return Err(error),
        }
    }
    Err(transient)
}

fn read_url(
    rpc: &Rpc<'_>,
    input: &ReadInput<'_>,
    providers: usize,
    now: &mut impl FnMut() -> u64,
    wait: &mut impl FnMut(Duration) -> Result<(), RegistryError>,
) -> Result<ReadObservation, RegistryError> {
    if quantity(&rpc.call("eth_chainId", json!([]))?)? != input.trust.chain_id {
        return Err(RegistryError::new("wrong_rpc_chain"));
    }
    let mut latest = block(&rpc.call("eth_getBlockByNumber", json!(["latest", false]))?)?;
    let mut reorg = false;
    if let Some(initial) = input.prior_state {
        let highest = decimal(&initial.head.number)
            .ok_or_else(|| RegistryError::new("invalid_registry_chain_state"))?;
        if latest.number < highest {
            if highest - latest.number != 1 {
                return Err(RegistryError::transient("rpc_block_lag"));
            }
            let anchor = rpc.call(
                "eth_getBlockByNumber",
                json!([format!("0x{highest:x}"), false]),
            )?;
            if anchor.is_null() || !same_head(&initial.head, &block(&anchor)?.head()) {
                return Err(RegistryError::transient("rpc_block_lag"));
            }
            if providers > 1 {
                return Err(RegistryError::transient("rpc_block_lag"));
            }
            wait(Duration::from_secs(1))?;
            latest = block(&rpc.call("eth_getBlockByNumber", json!(["latest", false]))?)?;
            if latest.number < highest {
                return Err(RegistryError::transient("rpc_block_lag"));
            }
        }
        let anchor = rpc.call(
            "eth_getBlockByNumber",
            json!([format!("0x{highest:x}"), false]),
        )?;
        if anchor.is_null() {
            return Err(RegistryError::transient("rpc_canonicality_unavailable"));
        }
        let canonical = block(&anchor)?;
        if canonical.number != highest {
            return Err(RegistryError::transient("rpc_canonicality_unavailable"));
        }
        if latest.number == highest && !same_head(&latest.head(), &canonical.head()) {
            return Err(RegistryError::transient("rpc_snapshot_reorg"));
        }
        reorg = !canonical.hash.eq_ignore_ascii_case(&initial.head.hash);
        if !reorg
            && (canonical.timestamp != initial.head.timestamp
                || latest.timestamp < canonical.timestamp)
        {
            return Err(RegistryError::transient("rpc_block_rollback"));
        }
    } else if latest.timestamp < input.time_high_water {
        return Err(RegistryError::transient("rpc_block_rollback"));
    }
    let time = now();
    if latest.timestamp < time.saturating_sub(300) || latest.timestamp > time.saturating_add(30) {
        return Err(RegistryError::transient("stale_rpc_block"));
    }
    verify_registry(rpc, &input.trust.contract, &latest.tag)?;
    let m = &input.parsed.manifest;
    let calldata = format!(
        "{}{}{}{}",
        selector("getLicense(address,bytes32,bytes32)"),
        address_word(&input.trust.issuer)?,
        &input.trust.product_id[2..],
        &m.license_id[2..]
    );
    let record = record(&rpc.call_contract(&input.trust.contract, &latest.tag, calldata)?)?;
    let current = now();
    let zero = format!("0x{}", "0".repeat(64));
    let mut refusal = if record.status != 1 {
        [
            Some("license_missing"),
            None,
            Some("license_suspended"),
            Some("license_revoked"),
        ][record.status as usize]
    } else if !record.holder.eq_ignore_ascii_case(&m.holder) {
        Some("wrong_license_holder")
    } else if record.device_key == zero {
        Some("device_not_bound")
    } else if !record.device_key.eq_ignore_ascii_case(input.device_key) {
        Some("wrong_device")
    } else if !record
        .entitlements_hash
        .eq_ignore_ascii_case(&input.parsed.entitlements_hash)
    {
        Some("invalid_entitlements_hash")
    } else if record.not_before > latest.timestamp || record.not_before > current {
        Some("license_not_started")
    } else if record.expires_at != 0
        && (record.expires_at <= latest.timestamp
            || record.expires_at <= current
            || record.expires_at <= record.not_before)
    {
        Some("license_expired")
    } else {
        None
    };
    if refusal.is_none() {
        let calldata = format!(
            "{}{}{}{}{}{}{}",
            selector("checkLicense(address,bytes32,bytes32,address,bytes32,bytes32)"),
            address_word(&input.trust.issuer)?,
            &input.trust.product_id[2..],
            &m.license_id[2..],
            address_word(&m.holder)?,
            &input.device_key[2..],
            &input.parsed.entitlements_hash[2..]
        );
        if !boolean(&rpc.call_contract(&input.trust.contract, &latest.tag, calldata)?)? {
            refusal = Some("registry_license_rejected");
        }
    }
    let canonical = rpc.call("eth_getBlockByNumber", json!([latest.tag, false]))?;
    if canonical.is_null() || !same_head(&latest.head(), &block(&canonical)?.head()) {
        return Err(RegistryError::transient("rpc_snapshot_reorg"));
    }
    if refusal.is_none() {
        if let Some(prior) = input
            .prior_state
            .and_then(|s| s.licenses.get(&m.license_id.to_ascii_lowercase()))
        {
            if record.revision < prior.revision {
                return Err(if reorg {
                    RegistryError::new("registry_reorg_conflict")
                } else {
                    RegistryError::transient("rpc_state_rollback")
                });
            }
        }
    }
    let checked_at = now();
    if refusal.is_none() && record.expires_at != 0 && record.expires_at <= checked_at {
        refusal = Some("license_expired");
    }
    if latest.timestamp < checked_at.saturating_sub(300) {
        return Err(RegistryError::transient("stale_rpc_block"));
    }
    Ok(ReadObservation {
        head: latest.head(),
        record,
        refusal,
        reorg,
        checked_at,
    })
}

pub(crate) fn read_chain(
    transport: &dyn Transport,
    rpc_urls: &[String],
    input: &ReadInput<'_>,
    mut now: impl FnMut() -> u64,
    mut wait: impl FnMut(Duration) -> Result<(), RegistryError>,
) -> Result<ReadObservation, RegistryError> {
    validate_trust(input.trust)?;
    fixed_hex(input.device_key, 32).map_err(|_| RegistryError::new("invalid_device_key"))?;
    if rpc_urls.is_empty() || rpc_urls.len() > 5 {
        return Err(RegistryError::new("invalid_registry_configuration"));
    }
    for url in rpc_urls {
        validate_endpoint(url, false)?;
    }
    let mut transient = RegistryError::transient("registry_rpc_unavailable");
    for url in rpc_urls {
        match read_url(
            &Rpc { transport, url },
            input,
            rpc_urls.len(),
            &mut now,
            &mut wait,
        ) {
            Ok(observation) => return Ok(observation),
            Err(error) if error.is_transient() => transient = error,
            Err(error) => return Err(error),
        }
    }
    Err(transient)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::HttpResponse;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct MockTransport {
        replies: Mutex<VecDeque<Result<HttpResponse, String>>>,
        sent: Mutex<Vec<HttpRequest>>,
    }
    impl MockTransport {
        fn new(replies: Vec<Result<HttpResponse, String>>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                sent: Mutex::new(Vec::new()),
            }
        }
    }
    impl Transport for MockTransport {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            self.sent.lock().unwrap().push(request);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected RPC")
        }
    }
    fn response(result: Value) -> Result<HttpResponse, String> {
        Ok(HttpResponse::from_bytes(
            200,
            json!({"jsonrpc":"2.0","id":1,"result":result}).to_string(),
        ))
    }
    fn head(number: u64) -> RegistryHead {
        RegistryHead {
            number: number.to_string(),
            hash: format!("0x{number:064x}"),
            timestamp: 1000 + number,
        }
    }
    fn observed(revision: u64, status: u8) -> ReadObservation {
        ReadObservation {
            head: head(101),
            record: RegistryRecord {
                holder: format!("0x{}", "11".repeat(20)),
                device_key: format!("0x{}", "22".repeat(32)),
                not_before: 900,
                expires_at: 0,
                entitlements_hash: format!("0x{}", "33".repeat(32)),
                revision,
                status,
            },
            refusal: None,
            reorg: false,
            checked_at: 1101,
        }
    }
    fn prior(revision: u64, revoked: bool) -> RegistryChainState {
        RegistryChainState {
            v: 1,
            head: head(100),
            licenses: BTreeMap::from([(
                format!("0x{:064x}", 1),
                RegistryObservation { revision, revoked },
            )]),
        }
    }
    fn raw_record() -> Vec<u8> {
        let mut bytes = vec![0; 224];
        bytes[12..32].fill(0x11);
        bytes[32..64].fill(0x22);
        bytes[128..160].fill(0x33);
        bytes[95] = 1;
        bytes[191] = 2;
        bytes[223] = 1;
        bytes
    }
    fn fixture() -> (RegistryTrust, ParsedManifest, String) {
        let trust = RegistryTrust {
            chain_id: 8453,
            contract: format!("0x{}", "11".repeat(20)),
            issuer: format!("0x{}", "22".repeat(20)),
            product_id: format!("0x{}", "33".repeat(32)),
        };
        let manifest = super::super::protocol::parse_manifest(&json!({"v":1,"kind":"talos-registry-license","chain_id":8453,
            "contract":trust.contract,"issuer":trust.issuer,"product_id":trust.product_id,"license_id":format!("0x{:064x}",1),"holder":trust.issuer,"entitlements":"e30"}).to_string(),&trust).unwrap();
        (trust, manifest, format!("0x{}", "44".repeat(32)))
    }

    #[test]
    fn record_decoding_requires_exact_abi_width_padding_and_safe_timestamps() {
        let good = raw_record();
        let decoded = record(&good).unwrap();
        assert_eq!(decoded.status, 1);
        assert_eq!(decoded.revision, 2);
        assert_eq!(decoded.not_before, 1);
        for bad in [good[..223].to_vec(), [good.clone(), vec![0; 32]].concat()] {
            assert!(record(&bad).is_err());
        }
        for index in [0, 64, 96, 160, 192] {
            let mut bad = good.clone();
            bad[index] = 1;
            assert!(record(&bad).is_err(), "dirty high word at {index}");
        }
        let mut bad = good.clone();
        bad[184..192].copy_from_slice(&(MAX_SAFE + 1).to_be_bytes());
        assert!(record(&bad).is_err());
        let mut bad = good.clone();
        bad[223] = 4;
        assert!(record(&bad).is_err());
        let mut bad = good;
        bad[191] = 0;
        assert!(record(&bad).is_err());
        let mut bool_word = vec![0; 32];
        assert!(!boolean(&bool_word).unwrap());
        bool_word[31] = 1;
        assert!(boolean(&bool_word).unwrap());
        bool_word[31] = 2;
        assert!(boolean(&bool_word).is_err());
    }

    #[test]
    fn chain_cache_is_strict_bounded_and_canonical() {
        let state = prior(2, false);
        let encoded = serde_json::to_string(&state).unwrap();
        assert_eq!(
            parse_chain_state(Some(&encoded)).unwrap(),
            Some(state.clone())
        );
        assert_eq!(parse_chain_state(None).unwrap(), None);
        let mut value = serde_json::to_value(state).unwrap();
        value["head"]["number"] = json!("0100");
        assert!(parse_chain_state(Some(&value.to_string())).is_err());
        value["head"]["number"] = json!("100");
        value["head"]["timestamp"] = json!(MAX_SAFE + 1);
        assert!(parse_chain_state(Some(&value.to_string())).is_err());
        assert!(parse_chain_state(Some(&" ".repeat(32_769))).is_err());
    }

    #[test]
    fn revisions_cannot_rollback_and_revocation_remains_terminal_across_reorgs() {
        let state = prior(9, false);
        let mut next = observed(8, 1);
        let id = format!("0x{:064x}", 1);
        let error = merge_observation(Some(&state), Some(&state), &next, &id).unwrap_err();
        assert_eq!(error.code(), "rpc_state_rollback");
        assert!(error.is_transient());
        next.reorg = true;
        assert_eq!(
            merge_observation(Some(&state), Some(&state), &next, &id)
                .unwrap_err()
                .code(),
            "registry_reorg_conflict"
        );
        next = observed(10, 3);
        next.refusal = Some("license_revoked");
        let (revoked, terminal) =
            merge_observation(Some(&state), Some(&state), &next, &id).unwrap();
        assert!(terminal);
        next = observed(11, 1);
        next.head = head(102);
        next.reorg = true;
        let (still_revoked, terminal) =
            merge_observation(Some(&revoked), Some(&revoked), &next, &id).unwrap();
        assert!(terminal);
        assert!(still_revoked.licenses[&id].revoked);
        assert_eq!(still_revoked.licenses[&id].revision, 11);
    }

    #[test]
    fn concurrent_heads_and_license_observation_limit_fail_closed() {
        let initial = prior(2, false);
        let mut current = initial.clone();
        let next = observed(3, 1);
        let id = format!("0x{:064x}", 1);
        current.head = head(102);
        assert_eq!(
            merge_observation(Some(&current), Some(&initial), &next, &id)
                .unwrap_err()
                .code(),
            "rpc_block_lag"
        );
        current.head = head(100);
        current.head.hash = format!("0x{}", "ab".repeat(32));
        assert_eq!(
            merge_observation(Some(&current), Some(&initial), &next, &id)
                .unwrap_err()
                .code(),
            "rpc_head_changed"
        );
        current = initial.clone();
        current.licenses = (0..64)
            .map(|n| {
                (
                    format!("0x{n:064x}"),
                    RegistryObservation {
                        revision: 1,
                        revoked: false,
                    },
                )
            })
            .collect();
        assert_eq!(
            merge_observation(
                Some(&current),
                Some(&current),
                &next,
                &format!("0x{:064x}", 100)
            )
            .unwrap_err()
            .code(),
            "registry_observation_limit"
        );
        assert!(merge_observation(Some(&current), Some(&current), &next, &id).is_ok());
    }

    #[test]
    fn rpc_errors_are_redacted_and_only_transient_codes_allow_failover() {
        let transport = MockTransport::new(vec![Err("https://rpc.example/SECRET".into())]);
        let rpc = Rpc {
            transport: &transport,
            url: "https://rpc.example/SECRET",
        };
        let error = rpc.call("eth_chainId", json!([])).unwrap_err();
        assert_eq!(error.code(), "registry_rpc_unavailable");
        assert!(error.is_transient());
        let transport = MockTransport::new(vec![Ok(HttpResponse::from_bytes(
            200,
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"SECRET"}}).to_string(),
        ))]);
        assert!(Rpc {
            transport: &transport,
            url: "https://rpc.example/"
        }
        .call("eth_chainId", json!([]))
        .unwrap_err()
        .is_transient());
        let transport = MockTransport::new(vec![Ok(HttpResponse::from_bytes(400, "SECRET"))]);
        assert!(!Rpc {
            transport: &transport,
            url: "https://rpc.example/"
        }
        .call("eth_chainId", json!([]))
        .unwrap_err()
        .is_transient());
        let transport = MockTransport::new(vec![]);
        assert!(Rpc {
            transport: &transport,
            url: "https://rpc.example/"
        }
        .call("eth_sendRawTransaction", json!(["0x"]))
        .is_err());
        assert!(transport.sent.lock().unwrap().is_empty());
    }

    fn snapshot_replies(
        parsed: &ParsedManifest,
        device: &str,
        status: u8,
    ) -> Vec<Result<HttpResponse, String>> {
        let block = json!({"number":"0x64","timestamp":"0x44c","hash":head(100).hash});
        let mut record = raw_record();
        record[12..32].copy_from_slice(&decode_hex(&parsed.manifest.holder).unwrap());
        record[32..64].copy_from_slice(&decode_hex(device).unwrap());
        record[128..160].copy_from_slice(&decode_hex(&parsed.entitlements_hash).unwrap());
        record[223] = status;
        let mut replies = vec![
            response(json!("0x2105")),
            response(block.clone()),
            response(json!(include_str!("test-runtime.hex").trim())),
            response(json!(format!("0x{:064x}", 1))),
            response(json!(hex(&record))),
        ];
        if status == 1 {
            replies.push(response(json!(format!("0x{:064x}", 1))));
        }
        replies.push(response(block));
        replies
    }

    #[test]
    fn revoked_rpc_keys_fail_over_to_a_fully_verified_independent_snapshot() {
        let (trust, parsed, device) = fixture();
        let input = ReadInput {
            trust: &trust,
            parsed: &parsed,
            device_key: &device,
            prior_state: None,
            time_high_water: 0,
        };
        let urls = vec![
            "https://first.example/EXPOSED_PROVIDER_KEY".into(),
            "https://second.example/".into(),
        ];
        for status in [401, 403] {
            let mut replies = vec![Ok(HttpResponse::from_bytes(
                status,
                "PRIVATE_PROVIDER_MESSAGE",
            ))];
            replies.extend(snapshot_replies(&parsed, &device, 1));
            let transport = MockTransport::new(replies);
            let observation = read_chain(&transport, &urls, &input, || 1100, |_| Ok(())).unwrap();
            assert!(observation.refusal.is_none());
            assert_eq!(observation.record.device_key, device);
            let sent = transport.sent.lock().unwrap();
            assert_eq!(sent.len(), 8);
            assert_eq!(sent[0].url, urls[0]);
            assert!(sent[1..].iter().all(|request| request.url == urls[1]));
        }
        let transport = MockTransport::new(vec![
            Ok(HttpResponse::from_bytes(401, "PRIVATE_PROVIDER_MESSAGE")),
            Ok(HttpResponse::from_bytes(403, "PRIVATE_PROVIDER_MESSAGE")),
        ]);
        let error = read_chain(&transport, &urls, &input, || 1100, |_| Ok(())).unwrap_err();
        assert_eq!(error.to_string(), "registry_rpc_unavailable");
        assert!(error.is_transient());
    }

    #[test]
    fn an_authoritative_license_revocation_never_tries_a_permissive_backup() {
        let (trust, parsed, device) = fixture();
        let input = ReadInput {
            trust: &trust,
            parsed: &parsed,
            device_key: &device,
            prior_state: None,
            time_high_water: 0,
        };
        let urls = vec![
            "https://first.example/".into(),
            "https://second.example/".into(),
        ];
        let transport = MockTransport::new(snapshot_replies(&parsed, &device, 3));
        let observation = read_chain(&transport, &urls, &input, || 1100, |_| Ok(())).unwrap();
        assert_eq!(observation.refusal, Some("license_revoked"));
        assert!(transport
            .sent
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.url == urls[0]));
    }

    #[test]
    fn reader_fails_over_network_failure_but_never_an_authoritative_wrong_chain() {
        let (trust, parsed, device) = fixture();
        let input = ReadInput {
            trust: &trust,
            parsed: &parsed,
            device_key: &device,
            prior_state: None,
            time_high_water: 0,
        };
        let urls = vec![
            "https://first.example/".into(),
            "https://second.example/".into(),
        ];
        let transport = MockTransport::new(vec![
            Err("unavailable SECRET".into()),
            response(json!("0x1")),
        ]);
        assert_eq!(
            read_chain(&transport, &urls, &input, || 1100, |_| Ok(()))
                .unwrap_err()
                .code(),
            "wrong_rpc_chain"
        );
        let sent = transport.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].url, urls[1]);
        drop(sent);
        let transport = MockTransport::new(vec![response(json!("0x1")), response(json!("0x2105"))]);
        assert_eq!(
            read_chain(&transport, &urls, &input, || 1100, |_| Ok(()))
                .unwrap_err()
                .code(),
            "wrong_rpc_chain"
        );
        assert_eq!(transport.sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn one_block_lag_wait_honors_activation_timeout_and_cancellation_before_retry() {
        let (trust, parsed, device) = fixture();
        let initial = prior(2, false);
        let input = ReadInput {
            trust: &trust,
            parsed: &parsed,
            device_key: &device,
            prior_state: Some(&initial),
            time_high_water: 0,
        };
        for code in ["registry_activation_timeout", "registry_activation_aborted"] {
            let transport = MockTransport::new(vec![
                response(json!("0x2105")),
                response(json!({"number":"0x63","timestamp":"0x44b","hash":head(99).hash})),
                response(json!({"number":"0x64","timestamp":"0x44c","hash":initial.head.hash})),
            ]);
            let mut waits = Vec::new();
            let error = read_chain(
                &transport,
                &["https://rpc.example/".into()],
                &input,
                || 1100,
                |duration| {
                    waits.push(duration);
                    Err(RegistryError::new(code))
                },
            )
            .unwrap_err();
            assert_eq!(error.code(), code);
            assert_eq!(waits, vec![Duration::from_secs(1)]);
            assert_eq!(transport.sent.lock().unwrap().len(), 3);
        }
    }

    #[test]
    fn rpc_envelopes_and_body_size_are_strict_before_any_authorization() {
        for body in [
            json!({"jsonrpc":"2.0","id":2,"result":"0x2105"}).to_string(),
            json!({"jsonrpc":"2.0","id":1}).to_string(),
            "not JSON SECRET".to_owned(),
        ] {
            let transport = MockTransport::new(vec![Ok(HttpResponse::from_bytes(200, body))]);
            let error = Rpc {
                transport: &transport,
                url: "https://rpc.example/SECRET",
            }
            .call("eth_chainId", json!([]))
            .unwrap_err();
            assert_eq!(error.code(), "invalid_registry_rpc_response");
            assert!(!error.is_transient());
        }
        let transport = MockTransport::new(vec![Ok(HttpResponse::from_bytes(
            200,
            vec![b' '; 1_048_577],
        ))]);
        assert_eq!(
            Rpc {
                transport: &transport,
                url: "https://rpc.example/SECRET"
            }
            .call("eth_chainId", json!([]))
            .unwrap_err()
            .code(),
            "invalid_registry_rpc_response"
        );
    }
}
