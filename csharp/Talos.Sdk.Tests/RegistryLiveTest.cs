using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;
using static Talos.Sdk.WalletProtocol;

namespace Talos.Sdk.Tests;

public sealed class LocalRegistryFactAttribute : FactAttribute
{
    public LocalRegistryFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("TALOS_REGISTRY_TEST_RPC") == null || Environment.GetEnvironmentVariable("TALOS_REGISTRY_TEST_CONTRACT") == null) Skip = "Set TALOS_REGISTRY_TEST_RPC and TALOS_REGISTRY_TEST_CONTRACT for an isolated local chain (31337).";
    }
}

public class RegistryLiveTest
{
    static string Call(string signature, params byte[][] words) => Hex(Join(Hash(signature).Take(4).ToArray(), Join(words)));

    [LocalRegistryFact]
    public async Task DirectRpcIssueBindCheckAndRevokeWithoutTalos()
    {
        string endpoint = Environment.GetEnvironmentVariable("TALOS_REGISTRY_TEST_RPC")!, contract = Environment.GetEnvironmentVariable("TALOS_REGISTRY_TEST_CONTRACT")!;
        Assert.Contains(new Uri(endpoint).Host, new[] { "localhost", "127.0.0.1", "[::1]" });
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) };
        async Task<JsonElement> Rpc(string method, object[] parameters)
        {
            using var content = new StringContent(JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method, @params = parameters }), Encoding.UTF8, "application/json");
            using var response = await http.PostAsync(endpoint, content); response.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); Assert.False(doc.RootElement.TryGetProperty("error", out _)); return doc.RootElement.GetProperty("result").Clone();
        }
        Assert.Equal("0x7a69", (await Rpc("eth_chainId", Array.Empty<object>())).GetString());
        var accounts = await Rpc("eth_accounts", Array.Empty<object>()); string issuer = accounts[0].GetString()!, holder = accounts[1].GetString()!;
        async Task Send(string from, string data)
        {
            string hash = (await Rpc("eth_sendTransaction", new object[] { new { from, to = contract, data, value = "0x0", gas = "0x300000" } })).GetString()!;
            for (int i = 0; i < 30; i++)
            {
                var receipt = await Rpc("eth_getTransactionReceipt", new object[] { hash });
                if (receipt.ValueKind != JsonValueKind.Null) { Assert.Equal("0x1", Str(receipt, "status")); return; }
                await Task.Delay(50);
            }
            throw new Exception("local test transaction receipt timed out");
        }
        string product = Hex(Hash("csharp-registry-test-" + Guid.NewGuid())), license = Hex(Hash(Guid.NewGuid().ToString()));
        string directory = Path.Combine(Path.GetTempPath(), "talos-registry-live-cs-" + Guid.NewGuid());
        try
        {
            var options = new RegistryLicenseOptions { Issuer = issuer, ProductId = product, ChainId = 31337, Contract = contract, RpcUrls = new[] { endpoint }, StatePath = Path.Combine(directory, "state") };
            using var client = new RegistryLicenseClient(options, http);
            client.ImportLicense(JsonSerializer.Serialize(new { v = 1, kind = "talos-registry-license", chain_id = 31337, contract, issuer, product_id = product, license_id = license, holder, entitlements = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"pro\":true}")).TrimEnd('=').Replace('+', '-').Replace('/', '_') }));
            var missing = await Assert.ThrowsAsync<RegistryLicenseException>(() => client.ValidateAsync()); Assert.Equal("license_missing", missing.Code);
            await Send(issuer, Call("issueLicense(bytes32,bytes32,address,uint64,uint64,bytes32)", Bytes(product, 32), Bytes(license, 32), Address(holder), Word(0), Word(0), Hash("{\"pro\":true}")));
            var unbound = await Assert.ThrowsAsync<RegistryLicenseException>(() => client.ValidateAsync()); Assert.Equal("device_not_bound", unbound.Code);
            var bind = client.CreateDeviceBinding(); Assert.Equal(holder, bind.ExpectedHolder); await Send(holder, bind.Data);
            var valid = await client.ValidateAsync(); Assert.True(valid.IsValid); Assert.Null(valid.ExpiresAt); Assert.Equal(2, valid.Revision); Assert.True((await client.GetEntitlementAsync("pro"))!.Value.GetBoolean());
            await Send(issuer, Call("suspendLicense(bytes32,bytes32)", Bytes(product, 32), Bytes(license, 32)));
            var suspended = await Assert.ThrowsAsync<RegistryLicenseException>(() => client.ValidateAsync()); Assert.Equal("license_suspended", suspended.Code);
            await Send(issuer, Call("resumeLicense(bytes32,bytes32)", Bytes(product, 32), Bytes(license, 32))); Assert.True((await client.ValidateAsync()).IsValid);
            await Send(issuer, Call("revokeLicense(bytes32,bytes32)", Bytes(product, 32), Bytes(license, 32)));
            var revoked = await Assert.ThrowsAsync<RegistryLicenseException>(() => client.ValidateAsync()); Assert.Equal("license_revoked", revoked.Code);
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }
}
