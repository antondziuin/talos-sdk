using System;
using System.IO;
using System.Text.Json;
using Xunit;
namespace Talos.Sdk.Tests
{
    public class DeviceProtocolTest
    {
        [Fact]
        public void SharedHashesSignaturesBindingAndSevenDayBoundary()
        {
            using var doc=JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"device-contract-vectors.json")));var r=doc.RootElement;
            var e=new DeviceEnrollment(r.GetProperty("enrollment").GetRawText());var c=new DeviceCertificate(r.GetProperty("certificate").GetRawText());var d=r.GetProperty("device");
            string key=d.GetProperty("device_key").GetString()!,fp=d.GetProperty("fingerprint_hash").GetString()!;
            var trust=new WalletOptions{Issuer=r.GetProperty("certificate").GetProperty("issuer").GetString()!,ProductId=r.GetProperty("certificate").GetProperty("license").GetProperty("product_id").GetString()!,ChainId=84532,Contract="0x0505050505050505050505050505050505050505"};
            Assert.Equal(r.GetProperty("enrollment_digest").GetString(),DeviceProtocol.EnrollmentDigest(e));Assert.Equal(r.GetProperty("certificate_digest").GetString(),DeviceProtocol.CertificateDigest(c));
            Assert.True(DeviceProtocol.VerifyCertificate(c,e,key,fp,trust,c.NotBefore).GetProperty("pro").GetBoolean());
            Assert.Throws<ArgumentException>(()=>DeviceProtocol.VerifyCertificate(c,e,key,fp,trust,c.ExpiresAt));
            Assert.Throws<ArgumentException>(()=>DeviceProtocol.VerifyCertificate(c,e,fp,key,trust,c.NotBefore));
            Assert.Throws<ArgumentException>(()=>DeviceProtocol.VerifyEnrollment(new DeviceEnrollment(e.Json.Replace("http://127.0.0.1:8080","https://attacker.example")),trust));
            Assert.Throws<ArgumentException>(()=>DeviceProtocol.VerifyCertificate(new DeviceCertificate(c.Json.Replace(c.ExpiresAt.ToString(),(c.ExpiresAt+1).ToString())),e,key,fp,trust,c.NotBefore));
        }
    }
}
