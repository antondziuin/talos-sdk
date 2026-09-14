using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace Talos.Sdk
{
    /// <summary>Application-pinned wallet trust anchors. Never load these from an untrusted certificate.</summary>
    public sealed class WalletOptions
    {
        public string Issuer { get; set; } = "";
        public string ProductId { get; set; } = "";
        public long ChainId { get; set; } = 84532;
        public string Contract { get; set; } = "";
        public string? StatePath { get; set; }
        public string? CoordinatorUrl { get; set; }
        public string? RenewalUrl { get; set; }
        public Action<string>? OnRefreshError { get; set; }
        public System.Collections.Generic.IReadOnlyDictionary<string, string>? FingerprintComponents { get; set; }
        public Action<string>? OnSessionLost { get; set; }
    }
    /// <summary>Portable certificate. Its validity alone never authorizes a running process.</summary>
    public sealed class WalletCertificate
    {
        internal JsonElement Root { get; }
        internal JsonElement License => Root.GetProperty("license");
        public string Issuer => Root.GetProperty("issuer").GetString()!;
        public string Holder => License.GetProperty("holder").GetString()!;
        public long ExpiresAt => License.GetProperty("expires_at").GetInt64();
        public long NotBefore => License.GetProperty("not_before").GetInt64();
        public string CoordinatorKey => License.GetProperty("coordinator_key").GetString()!;
        public string CoordinatorUrl => Root.GetProperty("coordinator_url").GetString()!;
        public string Json => Root.GetRawText();
        public WalletCertificate(string json)
        {
            if (json.Length > 65536) throw new ArgumentException("certificate_too_large");
            using var doc = JsonDocument.Parse(json);
            Root = doc.RootElement.Clone();
        }
    }
    /// <summary>Shared EIP-712 hashing and signature verification; compatible with Base's verifier.</summary>
    public static class WalletProtocol
    {
        internal const string LicenseType = "License(bytes32 tenantId,bytes32 productId,bytes32 licenseId,address holder,uint64 notBefore,uint64 expiresAt,bytes32 entitlementsHash,bytes32 coordinatorKey,uint8 maxConcurrentDevices)";
        internal const string DeviceType = "DeviceAuthorization(bytes32 tenantId,bytes32 productId,bytes32 licenseId,address issuer,address holder,bytes32 deviceKey,bytes32 fingerprintHash)";
        internal static string Str(JsonElement e, string name) => e.GetProperty(name).GetString()!;
        internal static byte[] Bytes(string s, int length)
        {
            if (s == null || !s.StartsWith("0x", StringComparison.Ordinal) || s.Length != 2 + 2 * length) throw new ArgumentException("invalid_hex");
            var result = new byte[length];
            for (int i = 0; i < length; i++) result[i] = Convert.ToByte(s.Substring(2 + i * 2, 2), 16);
            return result;
        }
        internal static string Hex(byte[] bytes) => "0x" + BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        internal static byte[] Hash(byte[] bytes)
        {
            var h = new KeccakDigest(256); h.BlockUpdate(bytes, 0, bytes.Length);
            var result = new byte[32]; h.DoFinal(result, 0); return result;
        }
        internal static byte[] Hash(string text) => Hash(Encoding.UTF8.GetBytes(text));
        internal static byte[] Join(params byte[][] parts) => parts.SelectMany(p => p).ToArray();
        internal static byte[] Word(long n)
        {
            if (n < 0 || n > 9007199254740991) throw new ArgumentException("invalid_integer");
            var w = new byte[32]; var b = new BigInteger(n.ToString(System.Globalization.CultureInfo.InvariantCulture)).ToByteArrayUnsigned();
            Buffer.BlockCopy(b, 0, w, 32 - b.Length, b.Length); return w;
        }
        internal static byte[] Address(string a) => Join(new byte[12], Bytes(a, 20));
        internal static byte[][] LicenseWords(WalletCertificate c)
        {
            var l = c.License;
            return new[] { Bytes(Str(l, "tenant_id"), 32), Bytes(Str(l, "product_id"), 32), Bytes(Str(l, "license_id"), 32), Address(c.Holder), Word(c.NotBefore), Word(c.ExpiresAt), Bytes(Str(l, "entitlements_hash"), 32), Bytes(c.CoordinatorKey, 32), Word(l.GetProperty("max_concurrent_devices").GetInt32()) };
        }
        internal static byte[] Typed(WalletCertificate c, byte[] contents)
        {
            long chain = c.Root.GetProperty("chain_id").GetInt64();
            if (chain != 8453 && chain != 84532 && chain != 31337) throw new ArgumentException("wrong_chain");
            var domain = Hash(Join(Hash("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"), Hash("TalosLicenseVerifier"), Hash("1"), Word(chain), Address(Str(c.Root, "contract"))));
            return Hash(Join(new byte[] { 0x19, 0x01 }, domain, contents));
        }
        public static string LicenseDigest(WalletCertificate c) => Hex(Typed(c, Hash(Join(Hash(LicenseType), Join(LicenseWords(c))))));
        internal static string VerifyLicenseCallData(WalletCertificate c) => Hex(Join(
            Hash("verifyLicense((bytes32,bytes32,bytes32,address,uint64,uint64,bytes32,bytes32,uint8),bytes,address)").Take(4).ToArray(),
            Join(LicenseWords(c)), Word(11 * 32), Address(c.Issuer), Word(65), Bytes(Str(c.Root, "signature"), 65), new byte[31]));
        public static string DeviceDigest(WalletCertificate c, string deviceKey, string fingerprintHash)
        {
            var l = c.License;
            return Hex(Typed(c, Hash(Join(Hash(DeviceType), Bytes(Str(l, "tenant_id"), 32), Bytes(Str(l, "product_id"), 32), Bytes(Str(l, "license_id"), 32), Address(c.Issuer), Address(c.Holder), Bytes(deviceKey, 32), Bytes(fingerprintHash, 32)))));
        }
        public static string LicenseRef(WalletCertificate c) => Hex(Hash(Join(Address(c.Issuer), Bytes(Str(c.License, "tenant_id"), 32), Bytes(Str(c.License, "product_id"), 32), Bytes(Str(c.License, "license_id"), 32))));
        public static string DeviceRef(string key, string fingerprint) => Hex(Hash(Join(Bytes(key, 32), Bytes(fingerprint, 32))));
        internal static string Recover(string digest, string signature)
        {
            var b = Bytes(signature, 65); var curve = SecNamedCurves.GetByName("secp256k1");
            var r = new BigInteger(1, b.Take(32).ToArray()); var s = new BigInteger(1, b.Skip(32).Take(32).ToArray());
            if ((b[64] != 27 && b[64] != 28) || r.SignValue <= 0 || r.CompareTo(curve.N) >= 0 || s.SignValue <= 0 || s.CompareTo(curve.N.ShiftRight(1)) > 0) throw new ArgumentException("noncanonical_signature");
            var point = curve.Curve.DecodePoint(Join(new[] { (byte)(b[64] - 27 + 2) }, b.Take(32).ToArray()));
            if (!point.Multiply(curve.N).IsInfinity) throw new ArgumentException("invalid_signature");
            var e = new BigInteger(1, Bytes(digest, 32));
            var q = point.Multiply(s).Subtract(curve.G.Multiply(e.Mod(curve.N))).Multiply(r.ModInverse(curve.N)).Normalize();
            return Hex(Hash(q.GetEncoded(false).Skip(1).ToArray()).Skip(12).ToArray());
        }
        public static JsonElement VerifyCertificate(WalletCertificate c, WalletOptions trust, long? at = null)
        {
            long now = at ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (c.Root.GetProperty("v").GetInt32() != 1 || Str(c.Root, "kind") != "talos-wallet-license" || c.License.GetProperty("max_concurrent_devices").GetInt32() != 1
                || !string.Equals(c.Issuer, trust.Issuer, StringComparison.OrdinalIgnoreCase) || !string.Equals(Str(c.License, "product_id"), trust.ProductId, StringComparison.OrdinalIgnoreCase)
                || c.Root.GetProperty("chain_id").GetInt64() != trust.ChainId || !string.Equals(Str(c.Root, "contract"), trust.Contract, StringComparison.OrdinalIgnoreCase)
                || Bytes(c.Holder, 20).All(x => x == 0) || Bytes(c.CoordinatorKey, 32).All(x => x == 0) || Bytes(trust.Contract, 20).All(x => x == 0)
                || c.NotBefore > now || (c.ExpiresAt != 0 && (now >= c.ExpiresAt || c.ExpiresAt <= c.NotBefore))) throw new ArgumentException("invalid_certificate");
            if (!string.Equals(Recover(LicenseDigest(c), Str(c.Root, "signature")), trust.Issuer, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("invalid_issuer_signature");
            var ent = Decode(Str(c.Root, "entitlements"));
            if (Hex(Hash(ent)) != Str(c.License, "entitlements_hash").ToLowerInvariant()) throw new ArgumentException("invalid_entitlements_hash");
            using var doc = JsonDocument.Parse(ent);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new ArgumentException("invalid_entitlements");
            return doc.RootElement.Clone();
        }
        public static void VerifyDevice(WalletCertificate c, string key, string fingerprint, string signature)
        {
            if (Bytes(key, 32).All(x => x == 0) || !string.Equals(Recover(DeviceDigest(c, key, fingerprint), signature), c.Holder, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("invalid_wallet_signature");
        }
        internal static byte[] Decode(string b64) => Convert.FromBase64String(b64.Replace('-', '+').Replace('_', '/').PadRight((b64.Length + 3) / 4 * 4, '='));
        internal static JsonElement VerifyMessage(string key, string kind, JsonElement message)
        {
            string payload = Str(message, "payload");
            if (payload.Length > 65536) throw new ArgumentException("message_too_large");
            var signer = new Ed25519Signer(); signer.Init(false, new Ed25519PublicKeyParameters(Bytes(key, 32), 0));
            var text = Encoding.UTF8.GetBytes("talos-wallet.1." + kind + "." + payload); signer.BlockUpdate(text, 0, text.Length);
            if (!signer.VerifySignature(Bytes(Str(message, "signature"), 64))) throw new ArgumentException("invalid_coordinator_signature");
            using var doc = JsonDocument.Parse(Decode(payload)); return doc.RootElement.Clone();
        }
        internal static string Write(Action<Utf8JsonWriter> build)
        {
            using var stream = new MemoryStream(); using (var writer = new Utf8JsonWriter(stream)) { build(writer); writer.Flush(); }
            return Encoding.UTF8.GetString(stream.ToArray());
        }
        public static string DeviceTypedData(WalletCertificate c, string key, string fingerprint)
        {
            return Write(w =>
            {
                w.WriteStartObject(); w.WritePropertyName("domain"); w.WriteStartObject(); w.WriteString("name", "TalosLicenseVerifier"); w.WriteString("version", "1");
                w.WriteNumber("chainId", c.Root.GetProperty("chain_id").GetInt64()); w.WriteString("verifyingContract", Str(c.Root, "contract")); w.WriteEndObject();
                w.WriteString("primaryType", "DeviceAuthorization"); w.WritePropertyName("types"); w.WriteStartObject();
                void Fields(string name, string[] names, string[] types) { w.WritePropertyName(name); w.WriteStartArray(); for (int i = 0; i < names.Length; i++) { w.WriteStartObject(); w.WriteString("name", names[i]); w.WriteString("type", types[i]); w.WriteEndObject(); } w.WriteEndArray(); }
                Fields("EIP712Domain", new[] { "name", "version", "chainId", "verifyingContract" }, new[] { "string", "string", "uint256", "address" });
                Fields("DeviceAuthorization", new[] { "tenantId", "productId", "licenseId", "issuer", "holder", "deviceKey", "fingerprintHash" }, new[] { "bytes32", "bytes32", "bytes32", "address", "address", "bytes32", "bytes32" }); w.WriteEndObject();
                w.WritePropertyName("message"); w.WriteStartObject(); w.WriteString("tenantId", Str(c.License, "tenant_id")); w.WriteString("productId", Str(c.License, "product_id")); w.WriteString("licenseId", Str(c.License, "license_id"));
                w.WriteString("issuer", c.Issuer); w.WriteString("holder", c.Holder); w.WriteString("deviceKey", key); w.WriteString("fingerprintHash", fingerprint); w.WriteEndObject(); w.WriteEndObject();
            });
        }
    }
}
