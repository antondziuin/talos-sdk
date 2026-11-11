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
using Xunit;
using static Talos.Sdk.WalletProtocol;

namespace Talos.Sdk.Tests;

public class RegistryLicenseTest
{
    static string Id(byte value) => Hex(Enumerable.Repeat(value, 32).ToArray());
    static string Addr(byte value) => Hex(Enumerable.Repeat(value, 20).ToArray());
    sealed class RpcHandler : HttpMessageHandler
    {
        internal long Chain = 11155111, Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 2, Number = 100;
        internal string BlockHash = Id(170);
        internal string? LatestHash;
        internal bool SnapshotReorg;
        internal readonly Dictionary<string, Queue<long>> Latest = new Dictionary<string, Queue<long>>();
        internal readonly Dictionary<long, (string Hash, long Timestamp)> History = new Dictionary<long, (string, long)>();
        internal long Before = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10, Expires = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600, Revision = 1, Status = 1, Version = 1;
        internal string Holder = Addr(2), Device = Id(0), Rights = Hex(Hash("{\"pro\":true,\"seats\":2}")), Code = "0x6000";
        internal bool Valid = true;
        internal int Error;
        internal readonly HashSet<string> Unavailable = new HashSet<string>();
        internal readonly List<(string Url, string Method, JsonElement Params)> Calls = new List<(string, string, JsonElement)>();
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            using var doc = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct)); var r = doc.RootElement;
            string method = Str(r, "method"), url = request.RequestUri!.AbsoluteUri; var parameters = r.GetProperty("params");
            Calls.Add((url, method, parameters.Clone()));
            if (Unavailable.Contains(url)) throw new HttpRequestException("network down");
            if (Error != 0) return Json(new { jsonrpc = "2.0", id = 1, error = new { code = Error, message = "fixture" } });
            object result;
            if (method == "eth_chainId") result = "0x" + Chain.ToString("x");
            else if (method == "eth_getBlockByNumber")
            {
                string tag = parameters[0].GetString()!;
                long number = tag == "latest" ? Latest.TryGetValue(url, out var sequence) && sequence.Count > 0 ? sequence.Dequeue() : Number : Convert.ToInt64(tag.Substring(2), 16);
                var head = History.TryGetValue(number, out var historic) ? historic : (Hash: BlockHash, Timestamp);
                result = new { number = "0x" + number.ToString("x"), hash = tag == "latest" ? LatestHash ?? head.Hash : head.Hash, timestamp = "0x" + head.Timestamp.ToString("x") };
            }
            else if (method == "eth_getCode") result = Code;
            else if (method == "eth_call")
            {
                Assert.Equal(Addr(5), Str(parameters[0], "to"));
                string data = Str(parameters[0], "data");
                if (data.StartsWith(Selector("registryVersion()"), StringComparison.Ordinal)) result = Hex(Word(Version));
                else if (data.StartsWith(Selector("getLicense(address,bytes32,bytes32)"), StringComparison.Ordinal))
                {
                    Assert.Equal(Call("getLicense(address,bytes32,bytes32)", Address(Addr(1)), Bytes(Id(7), 32), Bytes(Id(8), 32)), data);
                    result = Hex(Join(Address(Holder), Bytes(Device, 32), Word(Before), Word(Expires), Bytes(Rights, 32), Word(Revision), Word(Status)));
                }
                else if (data.StartsWith(Selector("checkLicense(address,bytes32,bytes32,address,bytes32,bytes32)"), StringComparison.Ordinal)) { result = Hex(Word(Valid ? 1 : 0)); if (SnapshotReorg) BlockHash = Id(187); }
                else throw new Exception("unexpected transaction or API call");
            }
            else throw new Exception("unexpected RPC method");
            return Json(new { jsonrpc = "2.0", id = 1, result });
        }
        static HttpResponseMessage Json<T>(T value) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(value)) };
    }
    static string Selector(string signature) => Hex(Hash(signature).Take(4).ToArray());
    static string Call(string signature, params byte[][] words) => Hex(Join(Hash(signature).Take(4).ToArray(), Join(words)));
    static string Manifest(long chainId = 11155111) => JsonSerializer.Serialize(new { v = 1, kind = "talos-registry-license", chain_id = chainId, contract = Addr(5), issuer = Addr(1), product_id = Id(7), license_id = Id(8), holder = Addr(2), entitlements = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"pro\":true,\"seats\":2}")).TrimEnd('=').Replace('+', '-').Replace('/', '_') });
    sealed class Fixture : IDisposable
    {
        internal readonly string DirectoryPath = Path.Combine(Path.GetTempPath(), "talos-registry-cs-" + Guid.NewGuid());
        internal readonly RpcHandler Handler = new RpcHandler();
        internal readonly HttpClient Http;
        internal readonly RegistryLicenseOptions Options;
        internal readonly RegistryLicenseClient Client;
        internal Fixture(long chainId = 11155111, bool singleProvider = false)
        {
            Http = new HttpClient(Handler);
            Options = new RegistryLicenseOptions { Issuer = Addr(1), ProductId = Id(7), ChainId = chainId, Contract = Addr(5), RpcUrls = singleProvider ? new[] { "https://rpc-one.example/" } : new[] { "https://rpc-one.example/", "https://rpc-two.example/" }, StatePath = Path.Combine(DirectoryPath, "state"), FingerprintComponents = new Dictionary<string, string> { { "fixture", "one" } } };
            Handler.Chain = chainId; Client = new RegistryLicenseClient(Options, Http); Handler.Device = Client.DeviceKey; Client.ImportLicense(Manifest(chainId));
        }
        public void Dispose() { Client.Dispose(); Http.Dispose(); if (Directory.Exists(DirectoryPath)) Directory.Delete(DirectoryPath, true); }
    }

    [Fact]
    public void BindingTransactionAndEncryptedDevicePersistence()
    {
        using var f = new Fixture(); var tx = f.Client.CreateDeviceBinding();
        Assert.Equal(11155111, tx.ChainId); Assert.Equal(Addr(5), tx.To); Assert.Equal(Addr(2), tx.ExpectedHolder); Assert.Equal(0, tx.Value);
        Assert.Equal(Call("bindDevice(address,bytes32,bytes32,bytes32)", Address(Addr(1)), Bytes(Id(7), 32), Bytes(Id(8), 32), Bytes(f.Client.DeviceKey, 32)), tx.Data);
        var bytes = File.ReadAllBytes(f.Options.StatePath!); Assert.Equal("TLS1", Encoding.ASCII.GetString(bytes.Take(4).ToArray())); Assert.DoesNotContain("machineKey", Encoding.UTF8.GetString(bytes));
        using var same = new RegistryLicenseClient(f.Options, f.Http); Assert.Equal(f.Client.DeviceKey, same.DeviceKey);
        f.Options.FingerprintComponents = new Dictionary<string, string> { { "fixture", "another" } };
        using var other = new RegistryLicenseClient(f.Options, f.Http); Assert.NotEqual(f.Client.DeviceKey, other.DeviceKey);
        Assert.Empty(f.Handler.Calls);
    }

    [Fact]
    public async Task FreshPinnedBlockReadsAndRevocationNeverUseCachedAuthorization()
    {
        using var f = new Fixture(); var state = await f.Client.ValidateAsync();
        Assert.True(state.IsValid); Assert.True(state.Entitlements.GetProperty("pro").GetBoolean()); Assert.Equal(100, state.BlockNumber); Assert.Equal(f.Handler.Expires, state.ExpiresAt);
        foreach (var call in f.Handler.Calls.Where(c => c.Method == "eth_call" || c.Method == "eth_getCode")) Assert.Equal("0x64", call.Params[call.Params.GetArrayLength() - 1].GetString());
        Assert.True((await f.Client.GetEntitlementAsync("pro"))!.Value.GetBoolean());
        f.Handler.Status = 3; var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.RequireValidLicenseAsync()); Assert.Equal("license_revoked", error.Code);
        Assert.All(f.Handler.Calls, call => Assert.Equal(f.Options.RpcUrls[0], call.Url));
    }

    [Fact]
    public async Task TransportFallbackAndCompleteOutageFailClosed()
    {
        using var f = new Fixture(); f.Handler.Unavailable.Add(f.Options.RpcUrls[0]); Assert.True((await f.Client.ValidateAsync()).IsValid);
        Assert.Contains(f.Handler.Calls, c => c.Url == f.Options.RpcUrls[1]); f.Handler.Unavailable.Add(f.Options.RpcUrls[1]);
        var error = await Assert.ThrowsAnyAsync<RegistryLicenseException>(() => f.Client.ValidateAsync()); Assert.Equal("registry_rpc_unavailable", error.Code);
        await Assert.ThrowsAnyAsync<RegistryLicenseException>(() => f.Client.GetEntitlementAsync("pro"));
    }

    [Theory]
    [InlineData("missing", "license_missing")]
    [InlineData("suspended", "license_suspended")]
    [InlineData("revoked", "license_revoked")]
    [InlineData("expired", "license_expired")]
    [InlineData("future", "license_not_started")]
    [InlineData("unbound", "device_not_bound")]
    [InlineData("device", "wrong_device")]
    [InlineData("holder", "wrong_license_holder")]
    [InlineData("entitlements", "invalid_entitlements_hash")]
    [InlineData("chain", "wrong_rpc_chain")]
    [InlineData("version", "wrong_registry_version")]
    [InlineData("code", "registry_contract_missing")]
    [InlineData("check", "registry_license_rejected")]
    [InlineData("revert", "registry_rpc_rejected")]
    public async Task AuthoritativeRefusalsNeverConsultAnotherProvider(string scenario, string code)
    {
        using var f = new Fixture();
        switch (scenario)
        {
            case "missing": f.Handler.Status = 0; break; case "suspended": f.Handler.Status = 2; break; case "revoked": f.Handler.Status = 3; break;
            case "expired": f.Handler.Expires = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); break; case "future": f.Handler.Before = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20; break;
            case "unbound": f.Handler.Device = Id(0); break; case "device": f.Handler.Device = Id(3); break; case "holder": f.Handler.Holder = Addr(3); break;
            case "entitlements": f.Handler.Rights = Id(0); break; case "chain": f.Handler.Chain = 1; break; case "version": f.Handler.Version = 2; break;
            case "code": f.Handler.Code = "0x"; break; case "check": f.Handler.Valid = false; break; case "revert": f.Handler.Error = 3; break;
        }
        var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ValidateAsync()); Assert.Equal(code, error.Code);
        Assert.All(f.Handler.Calls, c => Assert.Equal(f.Options.RpcUrls[0], c.Url));
    }

    [Fact]
    public async Task StaleAndRolledBackBlocksAreRefused()
    {
        using var f = new Fixture(); f.Handler.Timestamp -= 301;
        var stale = await Assert.ThrowsAnyAsync<RegistryLicenseException>(() => f.Client.ValidateAsync()); Assert.Equal("stale_rpc_block", stale.Code);
        f.Handler.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 1; await f.Client.ValidateAsync(); f.Handler.Timestamp--;
        var rollback = await Assert.ThrowsAnyAsync<RegistryLicenseException>(() => f.Client.ValidateAsync()); Assert.Equal("rpc_block_rollback", rollback.Code);
    }

    [Fact]
    public async Task PerpetualAndRenewedRecordsComeFromTheChain()
    {
        using var f = new Fixture(); f.Handler.Expires = 0; Assert.Null((await f.Client.ValidateAsync()).ExpiresAt);
        f.Handler.Expires = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 7200; f.Handler.Revision++; Assert.Equal(2, (await f.Client.ValidateAsync()).Revision);
        var manifest = JsonNode.Parse(Manifest())!; manifest["entitlements"] = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"pro\":false}")).TrimEnd('='); f.Client.ImportLicense(manifest.ToJsonString());
        var wrong = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ValidateAsync()); Assert.Equal("invalid_entitlements_hash", wrong.Code);
        f.Handler.Rights = Hex(Hash("{\"pro\":false}")); Assert.False((await f.Client.GetEntitlementAsync("pro"))!.Value.GetBoolean());
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("product_id")]
    [InlineData("contract")]
    [InlineData("chain_id")]
    [InlineData("entitlements")]
    public void ManifestTrustIsIndependentOfTheCustomerFile(string field)
    {
        using var f = new Fixture(); var manifest = JsonNode.Parse(Manifest())!;
        if (field == "chain_id") manifest[field] = 1; else manifest[field] = field == "product_id" ? Id(3) : field == "entitlements" ? "%%%" : Addr(3);
        var error = Assert.Throws<RegistryLicenseException>(() => f.Client.ImportLicense(manifest.ToJsonString())); Assert.Equal("invalid_registry_manifest", error.Code); Assert.Empty(f.Handler.Calls);
    }

    [Fact]
    public async Task BaseIsExplicitlyPinnedAndOtherProductionNetworksAreRejected()
    {
        using var f = new Fixture(8453); Assert.True((await f.Client.ValidateAsync()).IsValid);
        Assert.Equal("invalid_registry_manifest", Assert.Throws<RegistryLicenseException>(() => f.Client.ImportLicense(Manifest())).Code);
        f.Options.ChainId = 1;
        Assert.Equal("invalid_registry_configuration", Assert.Throws<RegistryLicenseException>(() => new RegistryLicenseClient(f.Options, f.Http)).Code);
    }

    [Fact]
    public async Task SingleProviderRetriesOneBlockLagWithoutReadingLowerLicenseSnapshot()
    {
        using var f = new Fixture(singleProvider: true); await f.Client.ValidateAsync(); f.Handler.Calls.Clear();
        f.Handler.Latest[f.Options.RpcUrls[0]] = new Queue<long>(new long[] { 99, 100 });
        Assert.Equal(100, (await f.Client.ValidateAsync()).BlockNumber);
        Assert.All(f.Handler.Calls.Where(c => c.Method == "eth_call"), c => Assert.Equal("0x64", c.Params[1].GetString()));
        Assert.Equal(2, f.Handler.Calls.Count(c => c.Method == "eth_getBlockByNumber" && c.Params[0].GetString() == "latest"));
    }

    [Fact]
    public async Task LagPrefersNextPinnedProvider()
    {
        using var f = new Fixture(); await f.Client.ValidateAsync(); f.Handler.Calls.Clear();
        f.Handler.Latest[f.Options.RpcUrls[0]] = new Queue<long>(new long[] { 99 });
        Assert.Equal(100, (await f.Client.ValidateAsync()).BlockNumber);
        Assert.All(f.Handler.Calls.Where(c => c.Method == "eth_call"), c => Assert.Equal(f.Options.RpcUrls[1], c.Url));
    }

    [Fact]
    public async Task RefusedRevocationPersistsHeadAcrossRestartAndBlocksStaleActiveState()
    {
        using var f = new Fixture(); await f.Client.ValidateAsync();
        f.Handler.History[100] = (f.Handler.BlockHash, f.Handler.Timestamp);
        f.Handler.Number = 101; f.Handler.BlockHash = Id(187); f.Handler.Status = 3; f.Handler.Revision = 2;
        Assert.Equal("license_revoked", (await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ValidateAsync())).Code);
        using var restarted = new RegistryLicenseClient(f.Options, f.Http); restarted.ImportLicense(Manifest());
        f.Handler.Status = 1;
        foreach (var url in f.Options.RpcUrls) f.Handler.Latest[url] = new Queue<long>(new long[] { 100 });
        Assert.Equal("rpc_block_lag", (await Assert.ThrowsAnyAsync<RegistryLicenseException>(() => restarted.ValidateAsync())).Code);
    }

    [Fact]
    public async Task CanonicalReorgRecoversOnlyWithCompatibleRevision()
    {
        using var f = new Fixture(); await f.Client.ValidateAsync();
        f.Handler.BlockHash = Id(187); f.Handler.Timestamp--; f.Handler.Revision = 2;
        Assert.Equal(Id(187), (await f.Client.ValidateAsync()).BlockHash);
        Assert.Equal(2, (await f.Client.ValidateAsync()).Revision);
        f.Handler.BlockHash = Id(204); f.Handler.Revision = 1;
        Assert.Equal("registry_reorg_conflict", (await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ValidateAsync())).Code);
    }

    [Fact]
    public async Task ObservedTerminalRevocationCannotReviveAcrossReorgAndRestart()
    {
        using var f = new Fixture(); f.Handler.Status = 3; f.Handler.Revision = 2;
        Assert.Equal("license_revoked", (await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ValidateAsync())).Code);
        f.Handler.BlockHash = Id(187); f.Handler.Status = 1; f.Handler.Revision = 3;
        using var restarted = new RegistryLicenseClient(f.Options, f.Http); restarted.ImportLicense(Manifest());
        Assert.Equal("license_revoked", (await Assert.ThrowsAsync<RegistryLicenseException>(() => restarted.ValidateAsync())).Code);
    }

    [Fact]
    public async Task SnapshotChangingDuringContractReadsIsRejectedWithoutCommit()
    {
        using var f = new Fixture(singleProvider: true); f.Handler.SnapshotReorg = true;
        Assert.Equal("rpc_snapshot_reorg", (await Assert.ThrowsAnyAsync<RegistryLicenseException>(() => f.Client.ValidateAsync())).Code);
        f.Handler.SnapshotReorg = false; f.Handler.BlockHash = Id(170);
        Assert.Equal(Id(170), (await f.Client.ValidateAsync()).BlockHash);
    }

    [Fact]
    public async Task MissingLowerRevisionRecordRemainsAuthoritativeAndAdvancesHead()
    {
        using var f = new Fixture(); await f.Client.ValidateAsync(); f.Handler.Calls.Clear();
        f.Handler.History[100] = (f.Handler.BlockHash, f.Handler.Timestamp);
        f.Handler.Number = 101; f.Handler.BlockHash = Id(187); f.Handler.Status = 0; f.Handler.Revision = 0;
        Assert.Equal("license_missing", (await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ValidateAsync())).Code);
        Assert.All(f.Handler.Calls, c => Assert.Equal(f.Options.RpcUrls[0], c.Url));
        f.Handler.Status = 1; f.Handler.Revision = 1;
        foreach (var url in f.Options.RpcUrls) f.Handler.Latest[url] = new Queue<long>(new long[] { 100 });
        Assert.Equal("rpc_block_lag", (await Assert.ThrowsAnyAsync<RegistryLicenseException>(() => f.Client.ValidateAsync())).Code);
    }

    [Theory]
    [InlineData(true, "rpc_snapshot_reorg")]
    [InlineData(false, "rpc_block_rollback")]
    public async Task InconsistentCanonicalHistoryIsRejectedBeforeContractReads(bool conflictingHeader, string error)
    {
        using var f = new Fixture(singleProvider: true); await f.Client.ValidateAsync(); f.Handler.Calls.Clear();
        if (conflictingHeader) f.Handler.LatestHash = Id(187);
        else { f.Handler.History[100] = (f.Handler.BlockHash, f.Handler.Timestamp); f.Handler.Number = 101; f.Handler.BlockHash = Id(187); f.Handler.Timestamp--; }
        Assert.Equal(error, (await Assert.ThrowsAnyAsync<RegistryLicenseException>(() => f.Client.ValidateAsync())).Code);
        Assert.DoesNotContain(f.Handler.Calls, c => c.Method == "eth_call");
    }
}
