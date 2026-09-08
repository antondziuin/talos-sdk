using System;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Talos.Sdk
{
    /// <summary>
    /// The air-gapped exchange, and the identity that makes it possible.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Online, a machine proves who it is with the <c>activation_secret</c> the
    /// server hands back from activate. A machine that cannot reach a server
    /// never gets one — so it makes its own: an Ed25519 pair at the first
    /// offline request, public half in <c>talos-request.json</c>, private half
    /// never leaving this disk. The file the portal issues is bound to that key
    /// as well as to the fingerprint, and anything this machine sends back
    /// afterwards is signed by it.
    /// </para>
    /// <para>
    /// The document format is deliberately <b>not</b> Talos-compact. That
    /// format's <c>typ</c> set is the closed list of things the <i>platform</i>
    /// signs, and putting a machine's key into the same namespace as a product's
    /// is exactly the confusion the tag set exists to prevent. What is copied is
    /// the part that matters: the payload travels base64url-encoded and is
    /// verified as received, never re-serialised, so this SDK, the Node SDK and
    /// the Rust server cannot disagree about JSON key order and turn that into a
    /// signature one of them rejects.
    /// </para>
    /// </remarks>
    public static class Offline
    {
        /// <summary>
        /// Domain tag of <c>talos-request.json</c>, and part of what is signed.
        /// </summary>
        /// <remarks>
        /// It sits inside the signed bytes for the same reason <c>typ</c> does:
        /// one machine key will eventually sign more than one kind of document,
        /// and a signature over a request must not also be a valid signature
        /// over anything else.
        /// </remarks>
        public const string RequestDomain = "talos-offline-request";

        /// <summary>
        /// Domain tag of <c>talos-deactivation.json</c>, the document that hands
        /// a seat back.
        /// </summary>
        /// <remarks>
        /// The second thing a machine key signs, and the reason the domain is
        /// inside the signed bytes rather than beside them: without it a captured
        /// request would be a valid receipt for the same machine, and returning a
        /// seat is not what its owner asked for when they asked for a licence.
        /// </remarks>
        public const string ReceiptDomain = "talos-offline-deactivation";

        /// <summary><c>kind</c> of the file the portal issues back.</summary>
        public const string LicenseFileKind = "talos-offline-license";

        internal const int DocVersion = 1;

        /// <summary>
        /// Generate this machine's identity: the raw 32-byte private seed and
        /// public key, both base64.
        /// </summary>
        /// <remarks>
        /// The private half is stored as the raw seed rather than PKCS#8, unlike
        /// the Node SDK's copy of this. It never leaves the machine and nothing
        /// else parses it, so the encoding is a local detail on each side; what
        /// has to agree is the <i>public</i> half, which is raw-32 base64
        /// everywhere in this project — on the wire, in <c>license_files</c>, and
        /// in the <c>mpk</c> claim.
        /// </remarks>
        internal static (string PrivateKey, string PublicKey) GenerateMachineKey()
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair pair = gen.GenerateKeyPair();
            return (
                Convert.ToBase64String(((Ed25519PrivateKeyParameters)pair.Private).GetEncoded()),
                Convert.ToBase64String(((Ed25519PublicKeyParameters)pair.Public).GetEncoded()));
        }

        /// <summary>
        /// The exact ASCII bytes a machine-signed document is signed over:
        /// <c>&lt;domain&gt;.&lt;ver&gt;.&lt;b64url(payload)&gt;</c>.
        /// </summary>
        internal static string SignedMessage(string domain, string payloadB64) =>
            domain + "." + DocVersion + "." + payloadB64;

        /// <summary>Sign a payload as a machine document.</summary>
        internal static OfflineDocument SignDocument(
            string privateKeyB64, string domain, string payloadJson)
        {
            string req = Base64Url.Encode(Encoding.UTF8.GetBytes(payloadJson));
            byte[] msg = Encoding.ASCII.GetBytes(SignedMessage(domain, req));
            var signer = new Ed25519Signer();
            signer.Init(true, new Ed25519PrivateKeyParameters(Convert.FromBase64String(privateKeyB64), 0));
            signer.BlockUpdate(msg, 0, msg.Length);
            return new OfflineDocument
            {
                V = DocVersion,
                Kind = domain,
                Req = req,
                Sig = Base64Url.Encode(signer.GenerateSignature()),
            };
        }
    }

    /// <summary>
    /// A document this machine signed, for a human to carry to the vendor.
    /// </summary>
    /// <remarks>
    /// Two of them share this shape, which is why the type is not named after
    /// either: <c>talos-request.json</c> from
    /// <see cref="TalosClient.CreateOfflineRequest"/>, which asks for a licence
    /// file, and <c>talos-deactivation.json</c> from
    /// <see cref="TalosClient.CreateOfflineDeactivation"/>, which hands the seat
    /// back. <see cref="Kind"/> says which, and it is inside the signed bytes —
    /// so one is never a valid version of the other.
    /// <para>
    /// Write <see cref="ToJson"/> to a file and hand it over.
    /// </para>
    /// </remarks>
    public sealed class OfflineDocument
    {
        /// <summary>Document version. <c>1</c>.</summary>
        public int V { get; set; } = Offline.DocVersion;

        /// <summary>
        /// <see cref="Offline.RequestDomain"/> or <see cref="Offline.ReceiptDomain"/>
        /// — also the domain inside the signed bytes.
        /// </summary>
        public string Kind { get; set; } = Offline.RequestDomain;

        /// <summary>base64url of the payload.</summary>
        public string Req { get; set; } = "";

        /// <summary>
        /// base64url Ed25519 signature over <c>"&lt;kind&gt;.1.&lt;req&gt;"</c>,
        /// by this machine's own key.
        /// </summary>
        public string Sig { get; set; } = "";

        /// <summary>The document, as it should be written to disk.</summary>
        /// <remarks>
        /// Serialised here rather than left to the caller because this library is
        /// trim- and AOT-safe: a host calling <c>JsonSerializer.Serialize</c> on
        /// this type would reach for reflection, which is exactly what
        /// <see cref="WireJson"/> exists to avoid.
        /// </remarks>
        public string ToJson() => JsonSerializer.Serialize(this, WireJson.Default.OfflineDocument);
    }
}
