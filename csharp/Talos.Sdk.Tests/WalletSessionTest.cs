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
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Xunit;

namespace Talos.Sdk.Tests;

public class WalletSessionTest
{
    internal static string Sign(byte seed,string digest,Action<string> verify)
    {
        var curve=SecNamedCurves.GetByName("secp256k1");
        var signer=new ECDsaSigner();signer.Init(true,new ECPrivateKeyParameters(new BigInteger(1,Enumerable.Repeat(seed,32).ToArray()),new ECDomainParameters(curve.Curve,curve.G,curve.N,curve.H)));
        var rs=signer.GenerateSignature(WalletProtocol.Bytes(digest,32));
        if(rs[1].CompareTo(curve.N.ShiftRight(1))>0)rs[1]=curve.N.Subtract(rs[1]);
        byte[] Pad(BigInteger n){var b=n.ToByteArrayUnsigned();return new byte[32-b.Length].Concat(b).ToArray();}
        foreach(byte v in new byte[]{27,28}){string sig=WalletProtocol.Hex(WalletProtocol.Join(Pad(rs[0]),Pad(rs[1]),new[]{v}));try{verify(sig);return sig;}catch(ArgumentException){}}
        throw new Exception("test signing failed");
    }
    static (WalletLicenseClient client,WalletCertificate cert) Setup(HttpClient? http=null,string? endpoint=null,string? certificate=null,string? path=null,string device="a",string? verifier=null)
    {
        var raw=JsonNode.Parse(certificate??File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"wallet-contract-vectors.json")))!;
        var node=certificate==null?raw["certificate"]!:raw;
        if(certificate==null){node["license"]!["not_before"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds()-10;node["license"]!["expires_at"]=0;
            node["license"]!["license_id"]=WalletProtocol.Hex(WalletProtocol.Hash(Guid.NewGuid().ToString()));}
        if(endpoint!=null)node["coordinator_url"]=endpoint;
        if(verifier!=null){node["chain_id"]=31337L;node["contract"]=verifier;node["license"]!["not_before"]=0L;}
        var options=new WalletOptions{Issuer=node["issuer"]!.GetValue<string>(),ProductId=node["license"]!["product_id"]!.GetValue<string>(),ChainId=node["chain_id"]!.GetValue<long>(),Contract=node["contract"]!.GetValue<string>(),StatePath=path??Path.Combine(Path.GetTempPath(),"talos-wallet-cs-"+Guid.NewGuid(),"state"),FingerprintComponents=new Dictionary<string,string>{{"machine_guid",device}}};
        if(certificate==null)node["signature"]=Sign(1,WalletProtocol.LicenseDigest(new WalletCertificate(node.ToJsonString())),s=>{node["signature"]=s;WalletProtocol.VerifyCertificate(new WalletCertificate(node.ToJsonString()),options);});
        var cert=new WalletCertificate(node.ToJsonString());var client=new WalletLicenseClient(options,http);client.ImportCertificate(cert.Json);
        client.AcceptDeviceAuthorization(Sign(2,WalletProtocol.DeviceDigest(cert,client.DeviceKey,client.FingerprintHash),s=>WalletProtocol.VerifyDevice(cert,client.DeviceKey,client.FingerprintHash,s)));
        return(client,cert);
    }
    sealed class CoordinatorHandler:HttpMessageHandler
    {
        public int Duration=60,Delay;
        public bool Invalid;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            var body=JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!;long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();string kind;
            JsonNode value;
            if(request.RequestUri!.AbsolutePath.EndsWith("challenge",StringComparison.Ordinal))
            {
                var cert=new WalletCertificate(body["certificate"]!.ToJsonString());var device=body["device"]!;
                value=JsonSerializer.SerializeToNode(new {nonce=Guid.NewGuid().ToString(),license_ref=WalletProtocol.LicenseRef(cert),device_ref=WalletProtocol.DeviceRef(device["device_key"]!.GetValue<string>(),device["fingerprint_hash"]!.GetValue<string>()),instance_id=body["instance_id"]!.GetValue<string>(),action=body["action"]!.GetValue<string>(),issued_at=now,expires_at=now+30})!;kind="challenge";
            }
            else{value=JsonNode.Parse(WalletProtocol.Decode(body["challenge"]!["payload"]!.GetValue<string>()))!;kind=body["context"]!["action"]!.GetValue<string>()=="release"?"released":"lease";value["issued_at"]=now;value["expires_at"]=now+(kind=="lease"?Duration:0);value["renew_after_s"]=20;}
            string payload=Convert.ToBase64String(Encoding.UTF8.GetBytes(value.ToJsonString())).TrimEnd('=').Replace('+','-').Replace('/','_');
            var signer=new Ed25519Signer();signer.Init(true,new Ed25519PrivateKeyParameters(Enumerable.Repeat((byte)3,32).ToArray(),0));var bytes=Encoding.UTF8.GetBytes("talos-wallet.1."+kind+"."+payload);signer.BlockUpdate(bytes,0,bytes.Length);
            string json=JsonSerializer.Serialize(new {payload,signature=WalletProtocol.Hex(Invalid?new byte[64]:signer.GenerateSignature())});
            if(kind!="challenge")await Task.Delay(Delay,ct);
            return new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(json)};
        }
    }
    [Fact]
    public async Task GateExpiresAndRestartGetsNewId()
    {
        using var handler=new CoordinatorHandler{Duration=6};using var http=new HttpClient(handler);var(c,_)=Setup(http);using(c){
            await c.StartSessionAsync();Assert.True(c.CanRun);Assert.True(c.GetEntitlement("pro")!.Value.GetBoolean());
            await Task.Delay(1100);Assert.False(c.CanRun);Assert.Throws<InvalidOperationException>(()=>c.RequireActiveSession());
            string old=c.InstanceId;await c.StopSessionAsync();handler.Duration=60;await c.StartSessionAsync();Assert.NotEqual(old,c.InstanceId);Assert.True(c.CanRun);await c.StopSessionAsync();}
    }
    [Fact]
    public async Task InvalidOrLateReplyCannotGrantAccess()
    {
        using var handler=new CoordinatorHandler{Invalid=true};using var http=new HttpClient(handler);var(c,_)=Setup(http);using(c){
            await Assert.ThrowsAsync<ArgumentException>(()=>c.StartSessionAsync());Assert.False(c.CanRun);
            handler.Invalid=false;handler.Duration=6;handler.Delay=1100;await Assert.ThrowsAsync<InvalidOperationException>(()=>c.StartSessionAsync());Assert.False(c.CanRun);
            handler.Duration=60;handler.Delay=150;var start=c.StartSessionAsync();await Task.Delay(50);c.NotifyResume();await Assert.ThrowsAsync<InvalidOperationException>(()=>start);Assert.False(c.CanRun);
            handler.Delay=150;start=c.StartSessionAsync();await Task.Delay(50);await c.StopSessionAsync();await Assert.ThrowsAsync<InvalidOperationException>(()=>start);Assert.False(c.CanRun);}
    }
    [Fact]
    public async Task ReadOnlyContractCallVerifiesWithoutGrantingSession()
    {
        string? rpc=Environment.GetEnvironmentVariable("TALOS_WALLET_TEST_RPC"),verifier=Environment.GetEnvironmentVariable("TALOS_WALLET_TEST_CONTRACT");if(rpc==null||verifier==null)return;
        var(c,_)=Setup(verifier:verifier);using(c){Assert.True(await c.VerifyViaContractAsync(rpc));Assert.False(c.CanRun);}
    }
    [Fact]
    public async Task RealCoordinatorSharesDeviceAndRefusesAnother()
    {
        string? endpoint=Environment.GetEnvironmentVariable("TALOS_COORDINATOR_URL");if(endpoint==null)return;
        string path=Path.Combine(Path.GetTempPath(),"talos-wallet-cs-live-"+Guid.NewGuid(),"a");
        var(a,cert)=Setup(endpoint:endpoint,path:path);var(a2,_)=Setup(endpoint:endpoint,certificate:cert.Json,path:path);var(b,_)=Setup(endpoint:endpoint,certificate:cert.Json,device:"b");
        using(a)using(a2)using(b){try{Assert.Equal(a.DeviceKey,a2.DeviceKey);await Task.WhenAll(a.StartSessionAsync(),a2.StartSessionAsync());Assert.True(a.CanRun);Assert.True(a2.CanRun);
            var error=await Assert.ThrowsAsync<HttpRequestException>(()=>b.StartSessionAsync());Assert.Contains("license_in_use",error.Message);
            await a.StopSessionAsync();Assert.True(a2.CanRun);await a.StartSessionAsync();Assert.True(a.CanRun);
            await a.StopSessionAsync();await a2.StopSessionAsync();await Assert.ThrowsAsync<HttpRequestException>(()=>b.StartSessionAsync());}
            finally{await a.StopSessionAsync();await a2.StopSessionAsync();await b.StopSessionAsync();}}
    }
}
