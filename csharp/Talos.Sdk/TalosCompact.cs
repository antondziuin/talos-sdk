using System;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Talos.Sdk
{
    /// <summary>
    /// Verification of Talos-compact tokens:
    /// <c>talos.&lt;ver&gt;.&lt;typ&gt;.&lt;b64url(payload)&gt;.&lt;b64url(sig)&gt;</c>,
    /// an Ed25519 signature over the exact ASCII prefix bytes. The verifier is
    /// pinned to a single product key and IGNORES any <c>kid</c> in the payload
    /// (kid is a server-side rotation aid, never a key selector). It enforces
    /// <c>typ</c>, <c>aud</c>, the echoed nonce, and <c>nbf</c>/<c>exp</c>.
    /// </summary>
    internal static class TalosCompact
    {
        private const long ClockSkewSeconds = 60;

        public static JsonElement Verify(
            byte[] publicKey,
            string expectedTyp,
            string expectedAud,
            string expectedNonce,
            string token)
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

            int lastDot = token.LastIndexOf('.');
            byte[] prefix = Encoding.ASCII.GetBytes(token.Substring(0, lastDot));
            byte[] sig = Base64Url.Decode(parts[4]);

            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            verifier.BlockUpdate(prefix, 0, prefix.Length);
            if (!verifier.VerifySignature(sig))
                throw new TalosSignatureException("signature verification failed");

            byte[] payload = Base64Url.Decode(parts[3]);
            using var doc = JsonDocument.Parse(payload);
            JsonElement claims = doc.RootElement.Clone();

            string? aud = GetString(claims, "aud");
            if (aud != expectedAud)
                throw new TalosSignatureException("audience mismatch");
            string? non = GetString(claims, "non");
            if (non != expectedNonce)
                throw new TalosSignatureException("nonce mismatch (possible replay)");

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (claims.TryGetProperty("nbf", out var nbf) && nbf.ValueKind == JsonValueKind.Number
                && now + ClockSkewSeconds < nbf.GetInt64())
                throw new TalosSignatureException("token not yet valid");
            if (claims.TryGetProperty("exp", out var exp) && exp.ValueKind == JsonValueKind.Number
                && now - ClockSkewSeconds > exp.GetInt64())
                throw new TalosSignatureException("token expired");

            return claims;
        }

        private static string? GetString(JsonElement e, string name)
        {
            return e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString()
                : null;
        }
    }
}
