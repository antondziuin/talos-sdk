using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Talos.Sdk
{
    /// <summary>
    /// Verification of Talos-compact tokens:
    /// <c>talos.&lt;ver&gt;.&lt;typ&gt;.&lt;b64url(payload)&gt;.&lt;b64url(sig)&gt;</c>,
    /// an Ed25519 signature over the exact ASCII prefix bytes. Verifies against a
    /// single pinned key or a keyset (any of which may have signed it during a key
    /// rotation), IGNORES any <c>kid</c>, and enforces <c>typ</c>, <c>aud</c>, the
    /// echoed nonce, and <c>nbf</c>/<c>exp</c>.
    /// </summary>
    internal static class TalosCompact
    {
        private const long ClockSkewSeconds = 60;

        public static JsonElement Verify(
            byte[] publicKey, string expectedTyp, string expectedAud, string expectedNonce, string token)
            => Verify(new[] { publicKey }, expectedTyp, expectedAud, expectedNonce, token);

        public static JsonElement Verify(
            IReadOnlyList<byte[]> keys,
            string expectedTyp,
            string expectedAud,
            string expectedNonce,
            string token)
        {
            JsonElement claims = ParseAndVerify(keys, expectedTyp, token);

            string? aud = GetString(claims, "aud");
            if (aud != expectedAud)
                throw new TalosSignatureException("audience mismatch");
            string? non = GetString(claims, "non");
            if (non != expectedNonce)
                throw new TalosSignatureException("nonce mismatch (possible replay)");

            // Required, not "checked if present". Every live token the server
            // mints carries both, so a token without them did not come from a
            // server that knows what it is doing — and treating a missing
            // `exp` as "no expiry" turns one server-side omission into a
            // verdict that is valid forever on every install in the field.
            // Cached tokens are a different path (see VerifyCached), where
            // `exp` deliberately does not apply.
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (!claims.TryGetProperty("nbf", out var nbf) || nbf.ValueKind != JsonValueKind.Number)
                throw new TalosSignatureException("token has no nbf");
            if (now + ClockSkewSeconds < nbf.GetInt64())
                throw new TalosSignatureException("token not yet valid");
            if (!claims.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number)
                throw new TalosSignatureException("token has no exp");
            if (now - ClockSkewSeconds > exp.GetInt64())
                throw new TalosSignatureException("token expired");

            return claims;
        }

        /// <summary>
        /// Verify a token restored from the local cache, for use while offline.
        /// <para>
        /// Two checks from <see cref="Verify(IReadOnlyList{byte[]}, string, string, string, string)"/>
        /// deliberately do not apply. The nonce belonged to the request that
        /// fetched this token, and <c>exp</c> is the short window in which it
        /// counts as <i>fresh</i> — a cached decision is by definition being used
        /// after that. What bounds offline use instead is the <c>grace_until</c>
        /// claim, which the caller enforces, together with the persisted
        /// server-time high-water mark that stops the system clock being wound
        /// back to extend it.
        /// </para>
        /// <para>
        /// Everything binding the token to this machine still holds: the
        /// signature under a pinned key, <c>typ</c>, <c>aud</c>, <c>nbf</c>, and
        /// the caller's fingerprint check.
        /// </para>
        /// </summary>
        public static JsonElement VerifyCached(
            IReadOnlyList<byte[]> keys, string expectedTyp, string expectedAud, string token)
        {
            JsonElement claims = ParseAndVerify(keys, expectedTyp, token);
            if (GetString(claims, "aud") != expectedAud)
                throw new TalosSignatureException("audience mismatch");
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (claims.TryGetProperty("nbf", out var nbf) && nbf.ValueKind == JsonValueKind.Number
                && now + ClockSkewSeconds < nbf.GetInt64())
                throw new TalosSignatureException("cached token not yet valid");
            return claims;
        }

        /// <summary>
        /// Verify a signed update <b>manifest</b> (<c>typ=manifest</c>) against the
        /// pinned release key(s). No nonce and no short <c>exp</c> (a manifest is a
        /// static artifact); enforces the signature, <c>aud</c>, and <c>not_before</c>.
        /// </summary>
        public static JsonElement VerifyManifest(byte[] releaseKey, string expectedAud, string token)
            => VerifyManifest(new[] { releaseKey }, expectedAud, token);

        public static JsonElement VerifyManifest(
            IReadOnlyList<byte[]> releaseKeys, string expectedAud, string token)
        {
            JsonElement claims = ParseAndVerify(releaseKeys, "manifest", token);
            string? aud = GetString(claims, "aud");
            if (aud != expectedAud)
                throw new TalosSignatureException("audience mismatch");
            if (claims.TryGetProperty("not_before", out var nb) && nb.ValueKind == JsonValueKind.Number)
            {
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (now + ClockSkewSeconds < nb.GetInt64())
                    throw new TalosSignatureException("manifest not yet released");
            }
            return claims;
        }

        /// <summary>
        /// Verify a signed <b>keyset</b> (<c>typ=keyset</c>) against the pinned
        /// anchor key. The keyset lists the product's current, rotatable
        /// license/release public keys, so an SDK that pins only the anchor learns
        /// the signing keys from it — a rotated key never breaks a deployed app.
        /// </summary>
        public static JsonElement VerifyKeyset(byte[] anchorKey, string expectedAud, string token)
        {
            JsonElement claims = ParseAndVerify(new[] { anchorKey }, "keyset", token);
            string? aud = GetString(claims, "aud");
            if (aud != expectedAud)
                throw new TalosSignatureException("audience mismatch");
            return claims;
        }

        /// <summary>
        /// Parse a token, check scheme/version/<c>typ</c>, and verify the signature
        /// against ANY of <paramref name="keys"/>. Returns the decoded claims.
        /// </summary>
        private static JsonElement ParseAndVerify(
            IReadOnlyList<byte[]> keys, string expectedTyp, string token)
        {
            string[] parts = token.Split('.');
            if (parts.Length != 5)
                throw new TalosSignatureException("malformed token");
            if (parts[0] != "talos")
                throw new TalosSignatureException("unexpected scheme");
            if (parts[1] != "1")
                throw new TalosSignatureException("unsupported wire version");
            if (parts[2] != expectedTyp)
                throw new TalosSignatureException("token type mismatch");
            if (keys.Count == 0)
                throw new TalosSignatureException("no verification key");

            int lastDot = token.LastIndexOf('.');
            byte[] prefix = Encoding.ASCII.GetBytes(token.Substring(0, lastDot));
            byte[] sig = Base64Url.Decode(parts[4]);

            bool ok = false;
            foreach (byte[] key in keys)
            {
                var verifier = new Ed25519Signer();
                verifier.Init(false, new Ed25519PublicKeyParameters(key, 0));
                verifier.BlockUpdate(prefix, 0, prefix.Length);
                if (verifier.VerifySignature(sig)) { ok = true; break; }
            }
            if (!ok)
                throw new TalosSignatureException("signature verification failed");

            byte[] payload = Base64Url.Decode(parts[3]);
            using var doc = JsonDocument.Parse(payload);
            return doc.RootElement.Clone();
        }

        private static string? GetString(JsonElement e, string name)
        {
            return e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString()
                : null;
        }
    }
}
