using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;
using static Talos.Sdk.WalletProtocol;
namespace Talos.Sdk.Tests;

public class DeviceClientTest
{
    sealed class IssuerHandler:HttpMessageHandler
    {
        public bool Offline,Invalid;
        public int Duration=604800;
        public Task? BeforeRequest;
        public int Renewals;
        public string? Bound;
        public WalletOptions Trust=null!;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            if(BeforeRequest!=null)await BeforeRequest;
            if(Offline)throw new HttpRequestException("offline");
            var b=JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!;long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if(request.RequestUri!.AbsolutePath.EndsWith("challenge",StringComparison.Ordinal)){
                var e=new DeviceEnrollment(b["enrollment"]!.ToJsonString());var device=b["device"]!;
                string payload=Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new{nonce=Guid.NewGuid().ToString(),license_ref=LicenseRef(e.Context),device_ref=DeviceRef(device["device_key"]!.GetValue<string>(),device["fingerprint_hash"]!.GetValue<string>()),revision=e.Revision,issued_at=now,expires_at=now+120}))).TrimEnd('=').Replace('+','-').Replace('/','_');
                string digest=Hex(Hash("talos-wallet.2.challenge."+payload));string signature=WalletSessionTest.Sign(1,digest,s=>{if(!DeviceProtocol.Eq(Recover(digest,s),Trust.Issuer))throw new ArgumentException();});
                return new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(new{payload,signature}))};
            }
            var d=b["context"]!["device"]!;string key=d["device_key"]!.GetValue<string>(),fp=d["fingerprint_hash"]!.GetValue<string>();
            var verify=new Ed25519Signer();verify.Init(false,new Ed25519PublicKeyParameters(Bytes(key,32),0));var text=Encoding.UTF8.GetBytes("talos-wallet.2.proof."+b["challenge"]!["payload"]!.GetValue<string>());verify.BlockUpdate(text,0,text.Length);Assert.True(verify.VerifySignature(Bytes(b["proof"]!.GetValue<string>(),64)));
            if(Bound!=null&&Bound!=key)return new HttpResponseMessage(HttpStatusCode.Conflict){Content=new StringContent("{}")};Bound=key;
            var node=JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"device-contract-vectors.json")))!["certificate"]!;
            node["license"]!["device_key"]=key;node["license"]!["fingerprint_hash"]=fp;node["license"]!["not_before"]=now;node["license"]!["expires_at"]=now+Duration;
            node["signature"]=WalletSessionTest.Sign(1,DeviceProtocol.CertificateDigest(new DeviceCertificate(node.ToJsonString())),s=>{if(!DeviceProtocol.Eq(Recover(DeviceProtocol.CertificateDigest(new DeviceCertificate(node.ToJsonString())),s),Trust.Issuer))throw new ArgumentException();});
            if(Invalid)node["license"]!["expires_at"]=now+999999;
            Renewals++;return new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(node.ToJsonString())};
        }
    }
    [Fact]
    public async Task FirstActivationOfflineRestartCopyAndFailedRenewal()
    {
        string directory=Path.Combine(Path.GetTempPath(),"talos-device-cs-"+Guid.NewGuid());
        try {
            var raw=JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"device-contract-vectors.json")))!;
            var e=new DeviceEnrollment(raw["enrollment"]!.ToJsonString());var options=new WalletOptions{Issuer=e.Context.Issuer,ProductId=Str(e.Context.License,"product_id"),ChainId=84532,Contract=Str(e.Root,"contract"),StatePath=Path.Combine(directory,"state"),FingerprintComponents=new Dictionary<string,string>{{"test","one"}}};
            using var handler=new IssuerHandler{Trust=options};using var http=new HttpClient(handler);
            using(var c=new DeviceLicenseClient(options,http)){
                c.ImportEnrollment(e.Json);c.AcceptDeviceAuthorization(WalletSessionTest.Sign(2,DeviceDigest(e.Context,c.DeviceKey,c.FingerprintHash),s=>VerifyDevice(e.Context,c.DeviceKey,c.FingerprintHash,s)));
                handler.Offline=true;await Assert.ThrowsAsync<HttpRequestException>(()=>c.StartAsync());Assert.False(c.CanRun);
                handler.Offline=false;await c.StartAsync();Assert.True(c.CanRun);long? expiry=c.ExpiresAt;
                handler.Invalid=true;await Assert.ThrowsAsync<ArgumentException>(()=>c.RefreshAsync());Assert.True(c.CanRun);Assert.Equal(expiry,c.ExpiresAt);handler.Invalid=false;
                handler.Offline=true;await Assert.ThrowsAsync<HttpRequestException>(()=>c.RefreshAsync());Assert.True(c.CanRun);await c.StopAsync();
            }
            using(var restored=new DeviceLicenseClient(options,http)){restored.ImportEnrollment(e.Json);await restored.StartAsync();Assert.True(restored.CanRun);Assert.True(restored.GetEntitlement("pro")!.Value.GetBoolean());await restored.StopAsync();}
            options.FingerprintComponents=new Dictionary<string,string>{{"test","other"}};
            using(var copied=new DeviceLicenseClient(options,http)){Assert.False(copied.IsDeviceAuthorized);await Assert.ThrowsAnyAsync<Exception>(()=>copied.StartAsync());Assert.False(copied.CanRun);}
        }finally{if(Directory.Exists(directory))Directory.Delete(directory,true);}
    }
    [Fact]
    public async Task ExpiredPermitCannotRunAndLongerThanSevenDaysIsRejected()
    {
        string directory=Path.Combine(Path.GetTempPath(),"talos-device-expiry-"+Guid.NewGuid());
        try{
            var raw=JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"device-contract-vectors.json")))!;var e=new DeviceEnrollment(raw["enrollment"]!.ToJsonString());
            var options=new WalletOptions{Issuer=e.Context.Issuer,ProductId=Str(e.Context.License,"product_id"),ChainId=84532,Contract=Str(e.Root,"contract"),StatePath=Path.Combine(directory,"state")};
            using var handler=new IssuerHandler{Trust=options,Duration=604801};using var http=new HttpClient(handler);using var c=new DeviceLicenseClient(options,http);
            c.ImportEnrollment(e.Json);c.AcceptDeviceAuthorization(WalletSessionTest.Sign(2,DeviceDigest(e.Context,c.DeviceKey,c.FingerprintHash),s=>VerifyDevice(e.Context,c.DeviceKey,c.FingerprintHash,s)));
            await Assert.ThrowsAsync<ArgumentException>(()=>c.StartAsync());handler.Duration=2;await c.StartAsync();Assert.True(c.CanRun);handler.Offline=true;
            await Task.Delay(2100);Assert.False(c.CanRun);Assert.Throws<InvalidOperationException>(()=>c.RequireValidCertificate());
        }finally{if(Directory.Exists(directory))Directory.Delete(directory,true);}
    }
    [Fact]
    public async Task OtherProcessCannotOverwriteRenewalAndConcurrentStartDoesNotSucceedEarly()
    {
        string directory=Path.Combine(Path.GetTempPath(),"talos-device-review-"+Guid.NewGuid());
        try {
            var raw=JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"device-contract-vectors.json")))!;
            var e=new DeviceEnrollment(raw["enrollment"]!.ToJsonString());
            var options=new WalletOptions{Issuer=e.Context.Issuer,ProductId=Str(e.Context.License,"product_id"),ChainId=84532,Contract=Str(e.Root,"contract"),StatePath=Path.Combine(directory,"state")};
            using var handler=new IssuerHandler{Trust=options,Duration=600};using var http=new HttpClient(handler);
            using var a=new DeviceLicenseClient(options,http);
            a.ImportEnrollment(e.Json);a.AcceptDeviceAuthorization(WalletSessionTest.Sign(2,DeviceDigest(e.Context,a.DeviceKey,a.FingerprintHash),s=>VerifyDevice(e.Context,a.DeviceKey,a.FingerprintHash,s)));
            var blocked=new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);handler.BeforeRequest=blocked.Task;handler.Offline=true;
            var first=a.StartAsync();var second=a.StartAsync();Assert.False(second.IsCompleted);
            blocked.SetResult(true);await Assert.ThrowsAsync<HttpRequestException>(()=>first);await Assert.ThrowsAsync<HttpRequestException>(()=>second);
            handler.BeforeRequest=null;handler.Offline=false;await a.StartAsync();
            using var b=new DeviceLicenseClient(options,http);await b.StartAsync();
            handler.Duration=604800;await a.RefreshAsync();long? expiry=a.ExpiresAt;
            await b.StopAsync();handler.Offline=true;
            using var restored=new DeviceLicenseClient(options,http);await restored.StartAsync();Assert.Equal(expiry,restored.ExpiresAt);
        }finally{if(Directory.Exists(directory))Directory.Delete(directory,true);}
    }

}
