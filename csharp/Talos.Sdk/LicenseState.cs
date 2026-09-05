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

        /// <summary>
        /// One entitlement, whatever type the developer put there, or
        /// <c>null</c> when the bag does not carry it.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The general accessor, and the reason it exists: an entitlement bag is
        /// server-defined free-form JSON, so a caller with a value that is not a
        /// boolean and not an integer — a tier name, a list of enabled modules,
        /// an object — had `Features` and a `TryGetProperty` call to write
        /// themselves. That is the SDK handing back its own parsing problem.
        /// This is the counterpart of the Node SDK's <c>getEntitlement</c>,
        /// which has been there since that client shipped.
        /// </para>
        /// <para>
        /// Returns <c>JsonElement?</c> rather than an invented wrapper type.
        /// <c>JsonElement</c> already is one, it is what the value actually
        /// arrived as, and a wrapper would only add a layer to unwrap before
        /// reaching the same API.
        /// </para>
        /// </remarks>
        public JsonElement? GetEntitlement(string name)
        {
            if (Features.ValueKind == JsonValueKind.Object
                && Features.TryGetProperty(name, out var v))
            {
                return v;
            }
            return null;
        }

        /// <summary>String entitlement (e.g. a tier name), or null.</summary>
        /// <remarks>
        /// Deliberately strict about the type: a number here returns
        /// <c>null</c> rather than its digits. An entitlement that changed
        /// shape server-side should be visibly absent, not silently coerced
        /// into something a comparison against <c>"pro"</c> would fail anyway.
        /// </remarks>
        public string? GetEntitlementString(string name)
        {
            var v = GetEntitlement(name);
            return v is { ValueKind: JsonValueKind.String } e ? e.GetString() : null;
        }

        /// <summary>
        /// Boolean entitlement, or <c>null</c> when absent or not a boolean.
        /// </summary>
        /// <remarks>
        /// Distinct from <see cref="IsFeatureEnabled"/>, and both are worth
        /// having. That one answers "may this run", folding absent, <c>false</c>,
        /// <c>0</c> and <c>""</c> together into a single decision — which is
        /// what a feature gate wants. This one tells absent from <c>false</c>,
        /// which is what code that has to distinguish "not licensed for it" from
        /// "licensed and switched off" needs.
        /// </remarks>
        public bool? GetEntitlementBool(string name)
        {
            var v = GetEntitlement(name);
            return v?.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => null,
            };
        }
    }
}
