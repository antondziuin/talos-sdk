using System;
using System.Linq;
using System.Text.Json;
using static Talos.Sdk.WalletProtocol;

namespace Talos.Sdk
{
    public sealed class DeviceEnrollment
    {
        internal JsonElement Root { get; }
        internal WalletCertificate Context { get; }
        public string Json => Root.GetRawText();
        public long Revision => Root.GetProperty("revision").GetInt64();
        public string RenewalUrl => Str(Root, "renewal_url");
        public DeviceEnrollment(string json)
        {
            if (json.Length > 16384) throw new ArgumentException("enrollment_too_large");
            using var doc = JsonDocument.Parse(json); Root = doc.RootElement.Clone();
            Context = new WalletCertificate(Write(w =>
            {
                w.WriteStartObject(); w.WriteNumber("chain_id", Root.GetProperty("chain_id").GetInt64()); w.WriteString("contract", Str(Root, "contract")); w.WriteString("issuer", Str(Root, "issuer"));
                w.WritePropertyName("license"); w.WriteStartObject(); foreach (var id in new[] { "tenant_id", "product_id", "license_id" }) w.WriteString(id, DeviceProtocol.UuidHash(Str(Root, id)));
                w.WriteString("holder", Str(Root, "holder")); w.WriteEndObject(); w.WriteEndObject();
            }));
        }
    }
    public sealed class DeviceCertificate
    {
        internal WalletCertificate Data { get; }
        internal JsonElement Root => Data.Root;
        internal JsonElement License => Data.License;
        public long ExpiresAt => Data.ExpiresAt;
        public long NotBefore => Data.NotBefore;
        public string Json => Data.Json;
        public DeviceCertificate(string json) { Data = new WalletCertificate(json); }
    }
    public static class DeviceProtocol
    {
        public const long ValiditySeconds = 604800, RenewAfterSeconds = 86400;
        private const string EnrollmentType = "Enrollment(bytes32 tenantId,bytes32 productId,bytes32 licenseId,address holder,uint64 revision,uint64 issuedAt,bytes32 renewalUrlHash)";
        private const string CertificateType = "DeviceLicense(bytes32 tenantId,bytes32 productId,bytes32 licenseId,address holder,bytes32 deviceKey,bytes32 fingerprintHash,uint64 revision,uint64 notBefore,uint64 expiresAt,bytes32 entitlementsHash)";
        internal static string UuidHash(string id) { if (!Guid.TryParseExact(id, "D", out var g)) throw new ArgumentException("invalid_uuid"); return Hex(Hash(Bytes("0x" + g.ToString("N"), 16))); }
        public static string EnrollmentDigest(DeviceEnrollment e) { var r = e.Root; return Hex(Typed(e.Context, Hash(Join(Hash(EnrollmentType), Bytes(UuidHash(Str(r, "tenant_id")), 32), Bytes(UuidHash(Str(r, "product_id")), 32), Bytes(UuidHash(Str(r, "license_id")), 32), Address(Str(r, "holder")), Word(e.Revision), Word(r.GetProperty("issued_at").GetInt64()), Hash(e.RenewalUrl))))); }
        public static string CertificateDigest(DeviceCertificate c) { var l = c.License; return Hex(Typed(c.Data, Hash(Join(Hash(CertificateType), Bytes(Str(l, "tenant_id"), 32), Bytes(Str(l, "product_id"), 32), Bytes(Str(l, "license_id"), 32), Address(Str(l, "holder")), Bytes(Str(l, "device_key"), 32), Bytes(Str(l, "fingerprint_hash"), 32), Word(l.GetProperty("revision").GetInt64()), Word(c.NotBefore), Word(c.ExpiresAt), Bytes(Str(l, "entitlements_hash"), 32))))); }
        internal static string Endpoint(string value) { var u = new Uri(value); if ((u.Scheme != "https" && !(u.Scheme == "http" && new[] { "localhost", "127.0.0.1", "[::1]" }.Contains(u.Host))) || u.UserInfo != "" || u.Query != "" || u.Fragment != "") throw new ArgumentException("invalid_renewal_url"); return u.AbsoluteUri.TrimEnd('/'); }
        public static void VerifyEnrollment(DeviceEnrollment e, WalletOptions trust)
        {
            var r = e.Root;
            if (r.GetProperty("v").GetInt32() != 2 || Str(r, "kind") != "talos-wallet-enrollment" || !Eq(Str(r, "issuer"), trust.Issuer) || !Eq(Str(r, "contract"), trust.Contract) || r.GetProperty("chain_id").GetInt64() != trust.ChainId || !Eq(UuidHash(Str(r, "product_id")), trust.ProductId) || e.Revision < 1 || Bytes(trust.Contract, 20).All(x => x == 0) || Bytes(Str(r, "holder"), 20).All(x => x == 0)) throw new ArgumentException("invalid_enrollment");
            Endpoint(e.RenewalUrl);
            if (!Eq(Recover(EnrollmentDigest(e), Str(r, "signature")), trust.Issuer)) throw new ArgumentException("invalid_issuer_signature");
        }
        internal static bool Eq(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        public static JsonElement VerifyCertificate(DeviceCertificate c, DeviceEnrollment e, string deviceKey, string fingerprint, WalletOptions trust, long? at = null)
        {
            VerifyEnrollment(e, trust); var r = c.Root; var l = c.License; long now = at ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (r.GetProperty("v").GetInt32() != 2 || Str(r, "kind") != "talos-device-certificate" || !Eq(Str(r, "issuer"), trust.Issuer) || !Eq(Str(r, "contract"), trust.Contract) || r.GetProperty("chain_id").GetInt64() != trust.ChainId
                || Str(l, "tenant_id") != UuidHash(Str(e.Root, "tenant_id")) || Str(l, "product_id") != UuidHash(Str(e.Root, "product_id")) || Str(l, "license_id") != UuidHash(Str(e.Root, "license_id")) || !Eq(Str(l, "holder"), Str(e.Root, "holder"))
                || Str(l, "device_key") != deviceKey || Str(l, "fingerprint_hash") != fingerprint || Bytes(deviceKey, 32).All(x => x == 0) || l.GetProperty("revision").GetInt64() != e.Revision || c.NotBefore > now || c.ExpiresAt <= now || c.ExpiresAt <= c.NotBefore || c.ExpiresAt - c.NotBefore > ValiditySeconds) throw new ArgumentException("invalid_device_certificate");
            if (!Eq(Recover(CertificateDigest(c), Str(r, "signature")), trust.Issuer)) throw new ArgumentException("invalid_issuer_signature");
            var bytes = Decode(Str(r, "entitlements")); if (bytes.Length > 32768 || Hex(Hash(bytes)) != Str(l, "entitlements_hash")) throw new ArgumentException("invalid_entitlements_hash");
            using var doc = JsonDocument.Parse(bytes); if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new ArgumentException("invalid_entitlements"); return doc.RootElement.Clone();
        }
        internal static string VerifyCallData(DeviceCertificate c)
        {
            var l = c.License;
            return Hex(Join(Hash("verifyDeviceCertificate((bytes32,bytes32,bytes32,address,bytes32,bytes32,uint64,uint64,uint64,bytes32),bytes,address)").Take(4).ToArray(),
                Bytes(Str(l, "tenant_id"), 32), Bytes(Str(l, "product_id"), 32), Bytes(Str(l, "license_id"), 32), Address(Str(l, "holder")), Bytes(Str(l, "device_key"), 32), Bytes(Str(l, "fingerprint_hash"), 32), Word(l.GetProperty("revision").GetInt64()), Word(c.NotBefore), Word(c.ExpiresAt), Bytes(Str(l, "entitlements_hash"), 32),
                Word(12 * 32), Address(Str(c.Root, "issuer")), Word(65), Bytes(Str(c.Root, "signature"), 65), new byte[31]));
        }
        internal static JsonElement Challenge(string issuer, JsonElement m) { string p = Str(m, "payload"); if (p.Length > 4096 || !Eq(Recover(Hex(Hash("talos-wallet.2.challenge." + p)), Str(m, "signature")), issuer)) throw new ArgumentException("invalid_challenge"); using var doc = JsonDocument.Parse(Decode(p)); return doc.RootElement.Clone(); }
    }
}
