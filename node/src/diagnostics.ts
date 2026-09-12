import { TalosApiError, TalosSignatureError } from "./errors.js";
import type { LicenseState } from "./client.js";
import { SDK_ID } from "./version.js";

const decisions = new Set(["valid", "expired", "revoked", "suspended", "deactivated", "machine_revoked", "invalid", "grace_expired", "clock_tampered"]);
const errors = new Set(["product_not_found", "license_not_found", "license_expired", "license_revoked", "license_suspended", "machine_revoked", "activation_limit_reached", "seat_limit_reached", "deactivation_limit_reached", "tenant_suspended", "tenant_closed", "invalid_activation_secret", "rate_limited"]);

/** An allowlisted local snapshot. Never serialize options, errors or bindings wholesale. */
export function diagnosticReport(activated: boolean, anchorPinned: boolean, state: LicenseState | null, error?: unknown): string {
  const code = error instanceof TalosApiError
    ? (errors.has(error.errorCode ?? "") ? error.errorCode! : "api_error")
    : error instanceof TalosSignatureError ? "signature_verification_failed"
    : error != null ? "client_error" : null;
  const decision = state == null ? null : decisions.has(state.decision) ? state.decision : "unknown";
  const advice: Record<string, string> = {
    signature_verification_failed: "Check the pinned anchor, product configuration and system time. Keep signature verification enabled.",
    activation_limit_reached: "Open the license's devices in the portal. Release an unused device or review its activation limit.",
    seat_limit_reached: "Close an unused app session or review the concurrent seat limit.",
    license_expired: "Renew the license in the portal, then validate again.",
    expired: "Renew the license in the portal, then validate again.",
    license_revoked: "Revocation is permanent. Ask the vendor for a replacement license.",
    revoked: "Revocation is permanent. Ask the vendor for a replacement license.",
    license_suspended: "Ask the vendor to review the suspension before activating a new device.",
    suspended: "Ask the vendor to review the suspension.",
    machine_revoked: "Ask the vendor to review this device in the portal.",
    grace_expired: "Reconnect to the configured Talos server and validate. Do not extend the local grace deadline.",
    clock_tampered: "Correct the system clock and validate online.",
    client_error: "Check connectivity, server configuration and local state access. The exception text is intentionally excluded.",
  };
  const action = advice[code ?? decision ?? ""]
    ?? (code ? "Review the licensing call and configuration with the vendor. HTTP errors are not signed license decisions."
      : state?.isOffline ? "The last decision was offline. Check connectivity and validate online; this snapshot cannot identify the transport failure."
      : !activated ? "Activate with a license key, then validate the saved activation."
      : decision === "valid" ? "The last licensing call returned valid. Check the portal for this device's recorded validation."
      : "Run a licensing check and generate a new report. Ask the vendor to review an invalid decision.");
  const timestamp = (value: number | null | undefined) => typeof value === "number" && Number.isFinite(value) ? value : null;
  return JSON.stringify({
    schema_version: 1,
    sdk: SDK_ID,
    generated_at: Math.floor(Date.now() / 1000),
    activated,
    anchor_pinned: anchorPinned,
    decision,
    is_offline: state?.isOffline ?? null,
    license_expires_at: timestamp(state?.licenseExpiresAt),
    grace_until: timestamp(state?.graceUntil),
    error_code: code,
    http_status: error instanceof TalosApiError && Number.isInteger(error.statusCode) && error.statusCode >= 100 && error.statusCode <= 599 ? error.statusCode : null,
    next_action: action,
  }, null, 2);
}
