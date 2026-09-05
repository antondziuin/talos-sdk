using System;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Talos.Sdk;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// Client-side Talos-compact verification tests (no server). Mirrors the
    /// Rust `talos-crypto::token` test vectors: a token signed by one key must
    /// verify only under that key, and any tamper must be rejected.
    /// </summary>
    public class VerifyTest
    {
        private static (byte[] pub, Ed25519PrivateKeyParameters priv) Keypair()
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var kp = gen.GenerateKeyPair();
            var priv = (Ed25519PrivateKeyParameters)kp.Private;
            var pub = ((Ed25519PublicKeyParameters)kp.Public).GetEncoded();
            return (pub, priv);
        }

        private static string Mint(Ed25519PrivateKeyParameters priv, string typ, string payloadJson)
        {
            string prefix = $"talos.1.{typ}." + Base64Url.Encode(Encoding.UTF8.GetBytes(payloadJson));
            var signer = new Ed25519Signer();
            signer.Init(true, priv);
            byte[] pb = Encoding.ASCII.GetBytes(prefix);
            signer.BlockUpdate(pb, 0, pb.Length);
            byte[] sig = signer.GenerateSignature();
            return prefix + "." + Base64Url.Encode(sig);
        }

        private static string Payload(string aud, string non)
        {
            long exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 600;
            long nbf = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10;
            return $"{{\"aud\":\"{aud}\",\"non\":\"{non}\",\"nbf\":{nbf},\"exp\":{exp}}}";
        }

        [Fact]
        public void Verifies_Under_Correct_Key()
        {
            var (pub, priv) = Keypair();
            string token = Mint(priv, "activation", Payload("prod_x", "n1"));
            var claims = TalosCompact.Verify(pub, "activation", "prod_x", "n1", token);
            Assert.Equal("prod_x", claims.GetProperty("aud").GetString());
        }

        [Fact]
        public void Rejects_Wrong_Key()
        {
            var (_, priv) = Keypair();
            var (otherPub, _) = Keypair();
            string token = Mint(priv, "activation", Payload("prod_x", "n1"));
            Assert.Throws<TalosSignatureException>(() =>
                TalosCompact.Verify(otherPub, "activation", "prod_x", "n1", token));
        }

        [Fact]
        public void Rejects_Type_Audience_And_Nonce_Mismatch()
        {
            var (pub, priv) = Keypair();
            string token = Mint(priv, "activation", Payload("prod_x", "n1"));
            Assert.Throws<TalosSignatureException>(() =>
                TalosCompact.Verify(pub, "validation", "prod_x", "n1", token)); // typ
            Assert.Throws<TalosSignatureException>(() =>
                TalosCompact.Verify(pub, "activation", "prod_y", "n1", token)); // aud
            Assert.Throws<TalosSignatureException>(() =>
                TalosCompact.Verify(pub, "activation", "prod_x", "n2", token)); // nonce
        }

        [Fact]
        public void Rejects_Tampered_Payload()
        {
            var (pub, priv) = Keypair();
            string token = Mint(priv, "activation", Payload("prod_x", "n1"));
            string[] parts = token.Split('.');
            parts[3] = Base64Url.Encode(Encoding.UTF8.GetBytes(Payload("prod_x", "n1"))) + "AA";
            string forged = string.Join(".", parts);
            Assert.Throws<TalosSignatureException>(() =>
                TalosCompact.Verify(pub, "activation", "prod_x", "n1", forged));
        }
        /// <summary>
        /// <c>nbf</c>/<c>exp</c>, which §4 requires the SDK to check and which
        /// nothing tested.
        /// <para>
        /// The signature is not what these are about: nobody mints these tokens
        /// without the pinned key. They are about a <i>server</i> that emits a
        /// token with no expiry, and a client whose clock has run past one. The
        /// first is a bug that would otherwise produce a verdict valid forever
        /// on every install that received it; the second is the ordinary case
        /// the window exists for.
        /// </para>
        /// </summary>
        private static void ExpectRefused(byte[] pub, Ed25519PrivateKeyParameters priv, string claims)
        {
            string token = Mint(priv, "validation", claims);
            Assert.Throws<TalosSignatureException>(
                () => TalosCompact.Verify(pub, "validation", "prod_x", "n1", token));
        }

        private static void ExpectAccepted(byte[] pub, Ed25519PrivateKeyParameters priv, string claims)
        {
            string token = Mint(priv, "validation", claims);
            TalosCompact.Verify(pub, "validation", "prod_x", "n1", token);
        }

        private static string Claims(string extra) =>
            "{\"aud\":\"prod_x\",\"non\":\"n1\"," + extra + "}";

        [Fact]
        public void Rejects_Expired_And_Not_Yet_Valid_Tokens()
        {
            var (pub, priv) = Keypair();
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            ExpectRefused(pub, priv, Claims($"\"nbf\":{now - 600},\"exp\":{now - 120}"));
            ExpectRefused(pub, priv, Claims($"\"nbf\":{now + 600},\"exp\":{now + 1200}"));

            // A minute of skew in either direction is tolerated: a desktop 30
            // seconds off is the ordinary state of an unsynchronised machine,
            // and refusing it would report a licensing failure for a clock
            // nobody noticed.
            ExpectAccepted(pub, priv, Claims($"\"nbf\":{now - 600},\"exp\":{now - 30}"));
            ExpectAccepted(pub, priv, Claims($"\"nbf\":{now + 30},\"exp\":{now + 600}"));
        }

        [Fact]
        public void Refuses_A_Token_That_Carries_No_Expiry()
        {
            var (pub, priv) = Keypair();
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // Signed by the right key, and still refused: a missing `exp` used
            // to read as "no expiry", so one server-side omission would have
            // been a verdict that never went stale anywhere it landed.
            ExpectRefused(pub, priv, Claims($"\"nbf\":{now - 10}"));
            ExpectRefused(pub, priv, Claims($"\"exp\":{now + 600}"));
            ExpectRefused(pub, priv, Claims("\"nbf\":\"soon\",\"exp\":\"later\""));
        }

    }
}
