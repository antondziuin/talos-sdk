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
    }
}
