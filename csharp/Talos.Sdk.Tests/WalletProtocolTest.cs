using System;
using System.IO;
using System.Text.Json;
using Xunit;

namespace Talos.Sdk.Tests
{
    public class WalletProtocolTest
    {
        [Fact]
        public void SharedSignaturesHashesAndExpiry()
        {
            using var document=JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"wallet-contract-vectors.json")));
            var root=document.RootElement;var c=new WalletCertificate(root.GetProperty("certificate").GetRawText());var d=root.GetProperty("device");
            string key=d.GetProperty("device_key").GetString()!,fp=d.GetProperty("fingerprint_hash").GetString()!;
            Assert.Equal(root.GetProperty("license_digest").GetString(),WalletProtocol.LicenseDigest(c));
            Assert.Equal(root.GetProperty("device_digest").GetString(),WalletProtocol.DeviceDigest(c,key,fp));
            Assert.Equal(root.GetProperty("license_ref").GetString(),WalletProtocol.LicenseRef(c));
            Assert.Equal(root.GetProperty("device_ref").GetString(),WalletProtocol.DeviceRef(key,fp));
            var trust=new WalletOptions{Issuer=c.Issuer,ProductId=root.GetProperty("certificate").GetProperty("license").GetProperty("product_id").GetString()!,ChainId=84532,Contract="0x0505050505050505050505050505050505050505"};
            Assert.True(WalletProtocol.VerifyCertificate(c,trust,1800000000).GetProperty("pro").GetBoolean());
            WalletProtocol.VerifyDevice(c,key,fp,d.GetProperty("signature").GetString()!);
            Assert.Throws<ArgumentException>(()=>WalletProtocol.VerifyCertificate(c,trust,c.ExpiresAt));
            trust.ChainId=8453;Assert.Throws<ArgumentException>(()=>WalletProtocol.VerifyCertificate(c,trust,1800000000));
        }
    }
}
