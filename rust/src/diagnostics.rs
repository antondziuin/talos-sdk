use serde_json::json;

use crate::compact::unix_now;
use crate::error::Error;
use crate::types::LicenseState;
use crate::version::sdk_id;

const DECISIONS: &[&str] = &[
    "valid",
    "expired",
    "revoked",
    "suspended",
    "deactivated",
    "machine_revoked",
    "invalid",
    "grace_expired",
    "clock_tampered",
];

const ERROR_CODES: &[&str] = &[
    "product_not_found",
    "license_not_found",
    "license_expired",
    "license_revoked",
    "license_suspended",
    "machine_revoked",
    "activation_limit_reached",
    "seat_limit_reached",
    "deactivation_limit_reached",
    "tenant_suspended",
    "tenant_closed",
    "invalid_activation_secret",
    "rate_limited",
];

fn advice(key: &str) -> Option<&'static str> {
    Some(match key {
        "signature_verification_failed" => {
            "Check the pinned anchor, product configuration and system time. Keep signature verification enabled."
        }
        "activation_limit_reached" => {
            "Open the license's devices in the portal. Release an unused device or review its activation limit."
        }
        "seat_limit_reached" => "Close an unused app session or review the concurrent seat limit.",
        "license_expired" | "expired" => "Renew the license in the portal, then validate again.",
        "license_revoked" | "revoked" => "Revocation is permanent. Ask the vendor for a replacement license.",
        "license_suspended" => "Ask the vendor to review the suspension before activating a new device.",
        "suspended" => "Ask the vendor to review the suspension.",
        "machine_revoked" => "Ask the vendor to review this device in the portal.",
        "grace_expired" => {
            "Reconnect to the configured Talos server and validate. Do not extend the local grace deadline."
        }
        "clock_tampered" => "Correct the system clock and validate online.",
        "client_error" => {
            "Check connectivity, server configuration and local state access. The exception text is intentionally excluded."
        }
        _ => return None,
    })
}

/// An allowlisted local snapshot. Never serialise options, errors or bindings
/// wholesale: every field here is one somebody decided was safe to paste into a
/// support ticket.
pub(crate) fn diagnostic_report(
    activated: bool,
    anchor_pinned: bool,
    state: Option<&LicenseState>,
    error: Option<&Error>,
) -> String {
    let code: Option<&str> = match error {
        Some(Error::Api { code, .. }) => Some(
            code.as_deref()
                .filter(|c| ERROR_CODES.contains(c))
                .unwrap_or("api_error"),
        ),
        Some(Error::Signature(_)) => Some("signature_verification_failed"),
        Some(_) => Some("client_error"),
        None => None,
    };
    let decision: Option<&str> = state.map(|s| {
        let d = s.decision.as_str();
        DECISIONS
            .iter()
            .copied()
            .find(|known| *known == d)
            .unwrap_or("unknown")
    });
    let action = code
        .or(decision)
        .and_then(advice)
        .unwrap_or(if code.is_some() {
            "Review the licensing call and configuration with the vendor. HTTP errors are not signed license decisions."
        } else if state.is_some_and(|s| s.is_offline) {
            "The last decision was offline. Check connectivity and validate online; this snapshot cannot identify the transport failure."
        } else if !activated {
            "Activate with a license key, then validate the saved activation."
        } else if decision == Some("valid") {
            "The last licensing call returned valid. Check the portal for this device's recorded validation."
        } else {
            "Run a licensing check and generate a new report. Ask the vendor to review an invalid decision."
        });
    let http_status = error
        .and_then(Error::status)
        .filter(|s| (100..=599).contains(s));
    serde_json::to_string_pretty(&json!({
        "schema_version": 1,
        "sdk": sdk_id(),
        "generated_at": unix_now(),
        "activated": activated,
        "anchor_pinned": anchor_pinned,
        "decision": decision,
        "is_offline": state.map(|s| s.is_offline),
        "license_expires_at": state.and_then(|s| s.license_expires_at),
        "grace_until": state.and_then(|s| s.grace_until),
        "error_code": code,
        "http_status": http_status,
        "next_action": action,
    }))
    .expect("a JSON value always serialises")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Decision;

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn an_unknown_error_code_is_not_repeated() {
        let e = Error::Api {
            status: 418,
            code: Some("customer-name-in-here".into()),
        };
        let r = parse(&diagnostic_report(true, true, None, Some(&e)));
        assert_eq!(r["error_code"], "api_error");
        assert_eq!(r["http_status"], 418);
        assert!(!r.to_string().contains("customer-name"));
    }

    #[test]
    fn error_text_never_reaches_the_report() {
        let e = Error::Network("connect to secret-host.internal failed".into());
        let r = diagnostic_report(true, false, None, Some(&e));
        assert!(!r.contains("secret-host"));
        assert_eq!(parse(&r)["error_code"], "client_error");
    }

    #[test]
    fn an_offline_valid_state_says_so() {
        let s = LicenseState {
            grace_until: Some(42),
            ..LicenseState::bare(Decision::Valid, true)
        };
        let r = parse(&diagnostic_report(true, true, Some(&s), None));
        assert_eq!(r["decision"], "valid");
        assert_eq!(r["is_offline"], true);
        assert_eq!(r["grace_until"], 42);
        assert!(r["next_action"]
            .as_str()
            .unwrap()
            .starts_with("The last decision was offline"));
        assert!(r["sdk"].as_str().unwrap().starts_with("rust/"));
    }
}
