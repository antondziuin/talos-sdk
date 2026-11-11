using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
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
        [Fact]
        public void EthereumSepoliaSignaturesCannotReplayAcrossChains()
        {
            var node=JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"wallet-contract-vectors.json")))!["certificate"]!;
            node["chain_id"]=11155111L;
            var trust=new WalletOptions{Issuer=node["issuer"]!.GetValue<string>(),ProductId=node["license"]!["product_id"]!.GetValue<string>(),ChainId=11155111,Contract=node["contract"]!.GetValue<string>()};
            string digest=WalletProtocol.LicenseDigest(new WalletCertificate(node.ToJsonString()));
            node["signature"]=WalletSessionTest.Sign(1,digest,s=>{if(!DeviceProtocol.Eq(WalletProtocol.Recover(digest,s),trust.Issuer))throw new ArgumentException();});
            var c=new WalletCertificate(node.ToJsonString());
            Assert.True(WalletProtocol.VerifyCertificate(c,trust,c.NotBefore).GetProperty("pro").GetBoolean());
            trust.ChainId=84532;Assert.Throws<ArgumentException>(()=>WalletProtocol.VerifyCertificate(c,trust,c.NotBefore));
            node["chain_id"]=84532L;Assert.Throws<ArgumentException>(()=>WalletProtocol.VerifyCertificate(new WalletCertificate(node.ToJsonString()),trust,c.NotBefore));
            node["chain_id"]=1L;Assert.Throws<ArgumentException>(()=>WalletProtocol.LicenseDigest(new WalletCertificate(node.ToJsonString())));
        }
    }
}
