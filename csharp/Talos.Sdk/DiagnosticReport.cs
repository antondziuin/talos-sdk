using System;
using System.Collections.Generic;

namespace Talos.Sdk
{
    // Fixed fields only: exception messages, options, fingerprints and binding
    // objects may contain secrets and must never reach this serializer.
    internal sealed class DiagnosticReport
    {
        public int SchemaVersion { get; set; } = 1;
        public string Sdk { get; set; } = SdkVersion.Id;
        public long GeneratedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        public bool Activated { get; set; }
        public bool AnchorPinned { get; set; }
        public string? Decision { get; set; }
        public bool? IsOffline { get; set; }
        public long? LicenseExpiresAt { get; set; }
        public long? GraceUntil { get; set; }
        public string? ErrorCode { get; set; }
        public int? HttpStatus { get; set; }
        public string NextAction { get; set; } = "";

        private static readonly HashSet<string> Decisions = new HashSet<string>(StringComparer.Ordinal)
        { "valid", "expired", "revoked", "suspended", "deactivated", "machine_revoked", "invalid", "grace_expired", "clock_tampered" };
        private static readonly HashSet<string> Errors = new HashSet<string>(StringComparer.Ordinal)
        { "product_not_found", "license_not_found", "license_expired", "license_revoked", "license_suspended", "machine_revoked", "activation_limit_reached", "seat_limit_reached", "deactivation_limit_reached", "tenant_suspended", "tenant_closed", "invalid_activation_secret", "rate_limited" };

        internal static DiagnosticReport Create(bool activated, bool anchorPinned, LicenseState? state, Exception? error)
        {
            var apiError = error as TalosApiException;
            string? code = apiError != null ? (apiError.Error != null && Errors.Contains(apiError.Error) ? apiError.Error : "api_error")
                : error is TalosSignatureException ? "signature_verification_failed" : error != null ? "client_error" : null;
            string? decision = state == null ? null : Decisions.Contains(state.Decision) ? state.Decision : "unknown";
            string action = (code ?? decision) switch
            {
                "signature_verification_failed" => "Check the pinned anchor, product configuration and system time. Keep signature verification enabled.",
                "activation_limit_reached" => "Open the license's devices in the portal. Release an unused device or review its activation limit.",
                "seat_limit_reached" => "Close an unused app session or review the concurrent seat limit.",
                "license_expired" or "expired" => "Renew the license in the portal, then validate again.",
                "license_revoked" or "revoked" => "Revocation is permanent. Ask the vendor for a replacement license.",
                "license_suspended" => "Ask the vendor to review the suspension before activating a new device.",
                "suspended" => "Ask the vendor to review the suspension.",
                "machine_revoked" => "Ask the vendor to review this device in the portal.",
                "grace_expired" => "Reconnect to the configured Talos server and validate. Do not extend the local grace deadline.",
                "clock_tampered" => "Correct the system clock and validate online.",
                "client_error" => "Check connectivity, server configuration and local state access. The exception text is intentionally excluded.",
                _ => code != null ? "Review the licensing call and configuration with the vendor. HTTP errors are not signed license decisions."
                    : state?.IsOffline == true ? "The last decision was offline. Check connectivity and validate online; this snapshot cannot identify the transport failure."
                    : !activated ? "Activate with a license key, then validate the saved activation."
                    : decision == "valid" ? "The last licensing call returned valid. Check the portal for this device's recorded validation."
                    : "Run a licensing check and generate a new report. Ask the vendor to review an invalid decision.",
            };
            return new DiagnosticReport
            {
                Activated = activated, AnchorPinned = anchorPinned, Decision = decision,
                IsOffline = state?.IsOffline, LicenseExpiresAt = state?.LicenseExpiresAt,
                GraceUntil = state?.GraceUntil, ErrorCode = code,
                HttpStatus = apiError != null && apiError.StatusCode >= 100 && apiError.StatusCode <= 599 ? apiError.StatusCode : null,
                NextAction = action,
            };
        }
    }
}
