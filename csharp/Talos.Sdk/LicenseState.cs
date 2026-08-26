using System.Text.Json;

namespace Talos.Sdk
{
    /// <summary>
    /// The current, cryptographically-verified license verdict. Constructed only
    /// from a token whose signature verified against the pinned product key.
    /// </summary>
    public sealed class LicenseState
    {
        /// <summary>
        /// <c>valid | expired | revoked | suspended | deactivated |
        /// machine_revoked | invalid</c>, plus two verdicts only the client can
        /// reach: <c>grace_expired</c> (offline past the licence's grace window)
        /// and <c>clock_tampered</c> (the system clock moved back behind a
        /// signed server time already seen).
        /// </summary>
        public string Decision { get; internal set; } = "unknown";

        /// <summary>Whether the license is currently valid for use.</summary>
        public bool IsValid => Decision == "valid";

        /// <summary>Business expiry (unix seconds), or null for perpetual.</summary>
        public long? LicenseExpiresAt { get; internal set; }

        /// <summary>
        /// True when this verdict came from the local cache rather than a live
        /// server — the licence is being honoured on trust, inside the window
        /// the policy allows.
        /// </summary>
        public bool IsOffline { get; internal set; }

        /// <summary>
        /// Unix seconds after which the app should validate again. Chosen by the
        /// server and carried in a signed claim, so it cannot be lengthened in
        /// transit.
        /// </summary>
        public long? RevalidateAfter { get; internal set; }

        /// <summary>Unix seconds until which this verdict may be honoured offline.</summary>
        public long? GraceUntil { get; internal set; }

        /// <summary>Entitlement bag (server-defined), as raw JSON.</summary>
        public JsonElement Features { get; internal set; }

        /// <summary>Whether a boolean/numeric feature flag is enabled.</summary>
        public bool IsFeatureEnabled(string name)
        {
            if (Features.ValueKind != JsonValueKind.Object) return false;
            if (!Features.TryGetProperty(name, out var v)) return false;
            return v.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Number => v.GetDouble() != 0,
                JsonValueKind.String => !string.IsNullOrEmpty(v.GetString()),
                _ => false,
            };
        }

        /// <summary>Integer entitlement (e.g. a seat count), or null.</summary>
        public long? GetEntitlementInt(string name)
        {
            if (Features.ValueKind == JsonValueKind.Object
                && Features.TryGetProperty(name, out var v)
                && v.ValueKind == JsonValueKind.Number
                && v.TryGetInt64(out long n))
            {
                return n;
            }
            return null;
        }
    }
}
