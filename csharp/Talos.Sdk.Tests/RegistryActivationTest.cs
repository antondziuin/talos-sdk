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

public class RegistryActivationTest
{
    [Fact]
    public void BaseSafePublicationHasLongerDefaultAndExplicitTimeoutStillWins()
    {
        Assert.Equal(TimeSpan.FromMinutes(10), new RegistryActivationOptions().TimeoutForChain(8453));
        Assert.Equal(TimeSpan.FromMinutes(2), new RegistryActivationOptions().TimeoutForChain(11155111));
        Assert.Equal(TimeSpan.FromSeconds(7), new RegistryActivationOptions { Timeout = TimeSpan.FromSeconds(7) }.TimeoutForChain(8453));
    }
    const string Token = "tpt_registry_activation_fixture", Code = "TEST-CODE-ONLY-NEVER-PERSIST", Job = "12345678-1234-4234-8234-123456789abc";
    static string Id(byte n) => Hex(Enumerable.Repeat(n, 32).ToArray());
    static string Addr(byte n) => Hex(Enumerable.Repeat(n, 20).ToArray());
    static string Manifest() => JsonSerializer.Serialize(new { v = 1, kind = "talos-registry-license", chain_id = 11155111, contract = Addr(5), issuer = Addr(1), product_id = Id(7), license_id = Id(8), holder = Addr(1), entitlements = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"pro\":true}")).TrimEnd('=') });
    sealed class Handler : HttpMessageHandler
    {
        internal bool Pending, Failed, ApiOffline, BadProof, HangClaim, HangStatus, HangRpc;
        internal int ChainStatus = 1, Claims, Polls, RpcWaits;
        readonly long BlockTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 1;
        internal string DeviceKey = Id(0), Error = "", PollError = "", ResponseManifest = Manifest(), AcceptedCode = Code, JobId = Job;
        internal readonly List<(string Url, JsonElement Body)> Requests = new List<(string, JsonElement)>();
        internal readonly TaskCompletionSource<HttpResponseMessage> ClaimResponse = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource<HttpResponseMessage> StatusResponse = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource<bool> RpcGate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        internal HttpResponseMessage Activation(bool ready)
        {
            using var manifest = JsonDocument.Parse(ResponseManifest);
            return Json(new { status = Failed ? "failed" : ready ? "ready" : "pending", activation_id = JobId,
                manifest = Failed || !ready ? (JsonElement?)null : manifest.RootElement.Clone(), error = Failed ? "fixture_worker_error" : null, retry_after_s = 2 });
        }
        static HttpResponseMessage Json<T>(T value, HttpStatusCode status = HttpStatusCode.OK) => new HttpResponseMessage(status) { Content = new StringContent(JsonSerializer.Serialize(value)) };
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            using var doc = JsonDocument.Parse(await request.Content!.ReadAsStringAsync()); var r = doc.RootElement; string url = request.RequestUri!.AbsoluteUri;
            Requests.Add((url, r.Clone()));
            if (url.StartsWith("https://activation.example/", StringComparison.Ordinal))
            {
                if (ApiOffline) throw new HttpRequestException("private transport detail must never escape");
                bool claim = url.EndsWith("/activate", StringComparison.Ordinal); if (claim) Claims++; else Polls++;
                Assert.Equal(Token, Str(r, "product_token")); string key = Str(r, "device_key");
                string text = claim ? "talos-registry-activation.1." + Hex(Hash(Token)) + "." + Hex(Hash(Str(r, "license_key").Trim())) + "." + key + "." + Str(r, "request_id").ToLowerInvariant()
                    : "talos-registry-status.1." + Hex(Hash(Token)) + "." + JobId + "." + key;
                var verifier = new Ed25519Signer(); verifier.Init(false, new Ed25519PublicKeyParameters(Bytes(key, 32), 0)); var bytes = Encoding.ASCII.GetBytes(text); verifier.BlockUpdate(bytes, 0, bytes.Length); Assert.True(verifier.VerifySignature(Bytes(Str(r, "proof"), 64)));
                if (!claim) { Assert.Equal(JobId, Str(r, "activation_id")); Assert.False(r.TryGetProperty("license_key", out _)); }
                if (BadProof) return Json(new { error = "invalid_device_proof" }, HttpStatusCode.BadRequest);
                string error = Error != "" ? Error : !claim ? PollError : "";
                if (error != "") return Json(new { error }, error == "activation_not_found" ? HttpStatusCode.NotFound : error == "temporary_unavailable" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.Conflict);
                if (claim && Str(r, "license_key") != AcceptedCode) return Json(new { error = "license_not_found" }, HttpStatusCode.NotFound);
                DeviceKey = key;
                if (claim && HangClaim) return await ClaimResponse.Task;
                if (!claim && HangStatus) return await StatusResponse.Task;
                return Activation(!claim && !Pending);
            }
            Assert.Equal("https://rpc.example/", url);
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); string method = Str(r, "method"); object result;
            if (method == "eth_chainId") result = "0xaa36a7";
            else if (method == "eth_getBlockByNumber") result = new { number = "0x64", hash = Id(170), timestamp = "0x" + BlockTimestamp.ToString("x") };
            else if (method == "eth_getCode") result = "0x6000";
            else if (method == "eth_call")
            {
                string data = Str(r.GetProperty("params")[0], "data"), selector = data.Substring(0, 10);
                if (selector == Hex(Hash("registryVersion()").Take(4).ToArray())) result = Hex(Word(1));
                else if (selector == Hex(Hash("getLicense(address,bytes32,bytes32)").Take(4).ToArray()))
                {
                    if (HangRpc) { RpcWaits++; await RpcGate.Task; }
                    result = Hex(Join(Address(Addr(1)), Bytes(DeviceKey, 32), Word(now - 10), Word(now + 3600), Hash("{\"pro\":true}"), Word(2), Word(ChainStatus)));
                }
                else if (selector == Hex(Hash("checkLicense(address,bytes32,bytes32,address,bytes32,bytes32)").Take(4).ToArray())) result = Hex(Word(ChainStatus == 1 ? 1 : 0));
                else throw new Exception("SDK attempted an Ethereum wallet action");
            }
            else throw new Exception("SDK attempted a non-read-only RPC method");
            return Json(new { jsonrpc = "2.0", id = 1, result });
        }
    }
    sealed class Fixture : IDisposable
    {
        internal readonly string DirectoryPath = Path.Combine(Path.GetTempPath(), "talos-registry-activation-cs-" + Guid.NewGuid());
        internal readonly Handler Handler = new Handler();
        internal readonly HttpClient Http;
        internal readonly RegistryLicenseOptions Options;
        internal readonly RegistryLicenseClient Client;
        internal readonly StateStore Store;
        internal Fixture()
        {
            Http = new HttpClient(Handler);
            Options = new RegistryLicenseOptions { Issuer = Addr(1), ProductId = Id(7), ChainId = 11155111, Contract = Addr(5), RpcUrls = new[] { "https://rpc.example/" }, ActivationUrl = "https://activation.example", ProductToken = Token,
                StatePath = Path.Combine(DirectoryPath, "state"), FingerprintComponents = new Dictionary<string, string> { { "fixture", "activation" } } };
            Client = Create();
            string scope = "wallet-registry:11155111:" + Options.Contract.ToLowerInvariant() + ":" + Options.Issuer.ToLowerInvariant() + ":" + Options.ProductId.ToLowerInvariant();
            Store = new StateStore(Options.StatePath!, scope, Fingerprint.Collect(scope, Options.FingerprintComponents).Composite);
        }
        internal RegistryLicenseClient Create() => new RegistryLicenseClient(Options, Http);
        public void Dispose() { Client.Dispose(); Http.Dispose(); if (Directory.Exists(DirectoryPath)) Directory.Delete(DirectoryPath, true); }
    }

    [Fact]
    public async Task ClaimsWithDeviceProofThenRestartsUsingOnlyRpc()
    {
        using var f = new Fixture(); var progress = new List<string>();
        var state = await f.Client.ActivateAsync("  " + Code + "  ", new RegistryActivationOptions { OnProgress = p => progress.Add(p.Status) });
        Assert.True(state.IsValid); Assert.Equal(1, f.Handler.Claims); Assert.Equal(1, f.Handler.Polls); Assert.Equal(new[] { "pending", "validating", "ready" }, progress);
        Assert.True(f.Client.IsActivated); Assert.False(f.Client.HasPendingActivation);
        var saved = f.Store.Load()!; Assert.NotNull(saved.RegistryManifest); Assert.Null(saved.RegistryActivationId);
        Assert.False(JsonSerializer.Serialize(saved).Contains(Code, StringComparison.Ordinal)); Assert.False(JsonSerializer.Serialize(saved).Contains(Hex(Hash(Code)), StringComparison.Ordinal));
        f.Handler.ApiOffline = true; int before = f.Handler.Requests.Count(r => r.Url.StartsWith("https://activation.example/", StringComparison.Ordinal));
        using var restored = f.Create(); Assert.True(restored.IsActivated); Assert.Equal(f.Client.DeviceKey, restored.DeviceKey);
        Assert.True((await restored.GetEntitlementAsync("pro"))!.Value.GetBoolean()); Assert.True((await restored.ValidateAsync()).IsValid);
        Assert.Equal(before, f.Handler.Requests.Count(r => r.Url.StartsWith("https://activation.example/", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task UnknownPersistedActivationIsForgottenAndNewCodeWorksAfterAnotherRestart()
    {
        using var f = new Fixture(); f.Handler.Pending = true; using var cancel = new CancellationTokenSource();
        var interrupted = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code,
            new RegistryActivationOptions { OnProgress = _ => cancel.Cancel() }, cancel.Token));
        Assert.Equal("registry_activation_aborted", interrupted.Code); Assert.Equal(Job, f.Store.Load()!.RegistryActivationId);
        using var resumed = f.Create(); Assert.True(resumed.HasPendingActivation); f.Handler.Error = "activation_not_found";
        var missing = await Assert.ThrowsAsync<RegistryLicenseException>(() => resumed.ResumeActivationAsync());
        Assert.Equal("activation_not_found", missing.Code); Assert.False(resumed.HasPendingActivation); Assert.False(resumed.IsActivated);
        Assert.Null(f.Store.Load()!.RegistryActivationId); Assert.Null(f.Store.Load()!.RegistryManifest);
        using var restarted = f.Create(); Assert.False(restarted.HasPendingActivation); Assert.Equal(f.Client.DeviceKey, restarted.DeviceKey);
        Assert.Equal("activation_code_required", (await Assert.ThrowsAsync<RegistryLicenseException>(() => restarted.ResumeActivationAsync())).Code);
        const string replacementCode = "NEW-SYNTHETIC-CODE-ONLY";
        f.Handler.Error = ""; f.Handler.Pending = false; f.Handler.AcceptedCode = replacementCode; f.Handler.JobId = "87654321-4321-4321-8321-cba987654321";
        var manifest = JsonNode.Parse(Manifest())!; manifest["license_id"] = Id(9); f.Handler.ResponseManifest = manifest.ToJsonString();
        Assert.True((await restarted.ActivateAsync(replacementCode)).IsValid); Assert.Equal(2, f.Handler.Claims);
        using var finalRestart = f.Create(); Assert.True(finalRestart.IsActivated); Assert.False(finalRestart.HasPendingActivation);
        Assert.True((await finalRestart.RequireValidLicenseAsync()).IsValid);
        Assert.Equal(new[] { Code, replacementCode }, f.Handler.Requests.Where(request => request.Url.EndsWith("/activate", StringComparison.Ordinal)).Select(request => Str(request.Body, "license_key")));
        string saved = JsonSerializer.Serialize(f.Store.Load()); Assert.DoesNotContain(Code, saved); Assert.DoesNotContain(replacementCode, saved);
    }

    [Fact]
    public async Task NewlySavedJobIsClearedWhenItsFirstPollReportsMissing()
    {
        using var f = new Fixture(); f.Handler.PollError = "activation_not_found";
        Assert.Equal("activation_not_found", (await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code))).Code);
        Assert.Equal(1, f.Handler.Claims); Assert.Equal(1, f.Handler.Polls); Assert.False(f.Client.HasPendingActivation);
        Assert.Null(f.Store.Load()!.RegistryActivationId); Assert.Null(f.Store.Load()!.RegistryManifest);
        using var restarted = f.Create(); Assert.Equal(f.Client.DeviceKey, restarted.DeviceKey); Assert.False(restarted.HasPendingActivation);
        f.Handler.AcceptedCode = "REPLACEMENT-SYNTHETIC-CODE"; f.Handler.JobId = "87654321-4321-4321-8321-cba987654321"; f.Handler.PollError = "";
        Assert.True((await restarted.ActivateAsync(f.Handler.AcceptedCode)).IsValid); Assert.Equal(2, f.Handler.Claims);
    }

    [Fact]
    public async Task TransientPollFailureKeepsSavedJobAndRestartDoesNotClaimAgain()
    {
        using var f = new Fixture(); f.Handler.PollError = "temporary_unavailable";
        Assert.Equal("registry_activation_http_503", (await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code))).Code);
        Assert.True(f.Client.HasPendingActivation); Assert.Equal(Job, f.Store.Load()!.RegistryActivationId);
        f.Handler.PollError = "";
        using var restarted = f.Create(); Assert.True((await restarted.ResumeActivationAsync()).IsValid); Assert.Equal(1, f.Handler.Claims);
    }

    [Fact]
    public async Task PendingTimeoutPersistsJobAndRestartResumesWithoutCode()
    {
        using var f = new Fixture(); f.Handler.Pending = true;
        var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code, new RegistryActivationOptions { Timeout = TimeSpan.FromMilliseconds(100) })); Assert.Equal("registry_activation_timeout", error.Code);
        Assert.False(f.Client.IsActivated); Assert.True(f.Client.HasPendingActivation); Assert.Equal(Job, f.Store.Load()!.RegistryActivationId);
        Assert.False(JsonSerializer.Serialize(f.Store.Load()).Contains(Code, StringComparison.Ordinal));
        using var restored = f.Create(); Assert.True(restored.HasPendingActivation); f.Handler.Pending = false;
        Assert.True((await restored.ResumeActivationAsync()).IsValid); Assert.Equal(1, f.Handler.Claims);
    }

    [Fact]
    public async Task CancellationPreservesPendingJobAndNeverLeaksItsReason()
    {
        using var f = new Fixture(); f.Handler.Pending = true; using var cancel = new CancellationTokenSource();
        var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code, new RegistryActivationOptions { OnProgress = _ => cancel.Cancel() }, cancel.Token)); Assert.Equal("registry_activation_aborted", error.Code);
        Assert.False(f.Client.IsActivated); Assert.True(f.Client.HasPendingActivation); f.Handler.Pending = false;
        using var restored = f.Create(); Assert.True((await restored.ResumeActivationAsync()).IsValid); Assert.Equal(1, f.Handler.Claims);
    }

    [Fact]
    public async Task AlreadyCancelledCallSendsNothing()
    {
        using var f = new Fixture(); using var cancel = new CancellationTokenSource(); cancel.Cancel();
        var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code, cancellationToken: cancel.Token)); Assert.Equal("registry_activation_aborted", error.Code); Assert.Empty(f.Handler.Requests);
    }

    [Fact]
    public async Task LateReadyReplyCannotImportAfterTimeout()
    {
        using var f = new Fixture(); f.Handler.HangClaim = true;
        var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code, new RegistryActivationOptions { Timeout = TimeSpan.FromMilliseconds(25) })); Assert.Equal("registry_activation_timeout", error.Code);
        f.Handler.ClaimResponse.SetResult(f.Handler.Activation(true)); await Task.Delay(10);
        Assert.False(f.Client.IsActivated); Assert.Null(f.Store.Load()!.RegistryManifest);
    }

    [Theory]
    [InlineData("wrong-code", "license_not_found")]
    [InlineData("proof", "invalid_device_proof")]
    [InlineData("other-device", "activation_already_bound")]
    [InlineData("failed", "registry_activation_failed")]
    public async Task RefusalsNeverGrantOrPersistAuthorization(string scenario, string expected)
    {
        using var f = new Fixture();
        if (scenario == "proof") f.Handler.BadProof = true; if (scenario == "other-device") f.Handler.Error = "activation_already_bound"; if (scenario == "failed") f.Handler.Failed = true;
        var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(scenario == "wrong-code" ? "OTHER-SYNTHETIC-CODE" : Code)); Assert.Equal(expected, error.Code);
        Assert.False(f.Client.IsActivated); Assert.False(f.Client.HasPendingActivation); Assert.Null(f.Store.Load()!.RegistryManifest);
        Assert.All(f.Handler.Requests, r => Assert.StartsWith("https://activation.example/", r.Url));
    }

    [Fact]
    public async Task ReadyApiCannotOverrideRevokedChainState()
    {
        using var f = new Fixture(); f.Handler.ChainStatus = 3; var progress = new List<string>();
        var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code, new RegistryActivationOptions { OnProgress = p => progress.Add(p.Status) })); Assert.Equal("license_revoked", error.Code); Assert.DoesNotContain("ready", progress);
        Assert.False(f.Client.IsActivated); Assert.True(f.Client.HasPendingActivation); Assert.Null(f.Store.Load()!.RegistryManifest);
        using var restored = f.Create(); Assert.False(restored.IsActivated); Assert.True(restored.HasPendingActivation);
        var again = await Assert.ThrowsAsync<RegistryLicenseException>(() => restored.ResumeActivationAsync()); Assert.Equal("license_revoked", again.Code); Assert.Equal(1, f.Handler.Claims);
    }

    [Fact]
    public async Task LaggingRpcPreservesPendingAndCommitsOnlyAfterFreshConfirmation()
    {
        using var f = new Fixture(); f.Handler.ChainStatus = 0;
        var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code)); Assert.Equal("license_missing", error.Code);
        Assert.False(f.Client.IsActivated); Assert.Null(f.Store.Load()!.RegistryManifest);
        using var restored = f.Create(); Assert.True(restored.HasPendingActivation); Assert.False(restored.IsActivated); f.Handler.ChainStatus = 1;
        Assert.True((await restored.ResumeActivationAsync()).IsValid); Assert.Equal(1, f.Handler.Claims); Assert.True(restored.IsActivated); Assert.False(restored.HasPendingActivation);
        f.Handler.ApiOffline = true; using var restarted = f.Create(); Assert.True((await restarted.ValidateAsync()).IsValid);
    }

    [Fact]
    public async Task RpcCandidateIsNeverExposedBeforeIndependentValidation()
    {
        using var f = new Fixture(); f.Handler.HangRpc = true; var work = f.Client.ActivateAsync(Code);
        while (f.Handler.RpcWaits == 0) await Task.Delay(1);
        Assert.False(f.Client.IsActivated); Assert.True(f.Client.HasPendingActivation); Assert.Null(f.Store.Load()!.RegistryManifest);
        var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ValidateAsync()); Assert.Equal("registry_manifest_required", error.Code);
        f.Handler.RpcGate.SetResult(true); Assert.True((await work).IsValid); Assert.True(f.Client.IsActivated);
    }

    [Fact]
    public async Task UntrustedAndSecretShapedManifestFieldsAreNeverPersisted()
    {
        using var f = new Fixture(); var wrong = JsonNode.Parse(Manifest())!; wrong["issuer"] = Addr(3); f.Handler.ResponseManifest = wrong.ToJsonString();
        var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code)); Assert.Equal("invalid_registry_manifest", error.Code); Assert.Null(f.Store.Load()!.RegistryManifest);
        var extra = JsonNode.Parse(Manifest())!; extra["license_key"] = Code; f.Handler.ResponseManifest = extra.ToJsonString();
        var second = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ResumeActivationAsync()); Assert.Equal("invalid_registry_manifest", second.Code); Assert.False(JsonSerializer.Serialize(f.Store.Load()).Contains(Code, StringComparison.Ordinal));
    }

    [Fact]
    public async Task TamperedCachedTrustCannotAutoImport()
    {
        using var f = new Fixture(); await f.Client.ActivateAsync(Code); var saved = f.Store.Load()!; var wrong = JsonNode.Parse(Manifest())!; wrong["contract"] = Addr(3); saved.RegistryManifest = wrong.ToJsonString(); f.Store.Save(saved);
        using var restored = f.Create(); Assert.False(restored.IsActivated); var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => restored.ValidateAsync()); Assert.Equal("registry_manifest_required", error.Code);
    }

    [Fact]
    public async Task ConcurrentStartsShareOneClaim()
    {
        using var f = new Fixture(); var both = await Task.WhenAll(f.Client.ActivateAsync(Code), f.Client.ActivateAsync(Code)); Assert.All(both, r => Assert.True(r.IsValid)); Assert.Equal(1, f.Handler.Claims);
        using var restored = f.Create(); Assert.True(restored.IsActivated);
    }

    [Fact]
    public async Task LateActivationCannotOverwriteAManualImport()
    {
        using var f = new Fixture(); f.Handler.HangStatus = true; var work = f.Client.ActivateAsync(Code);
        while (f.Handler.Polls == 0) await Task.Delay(1);
        var replacement = JsonNode.Parse(Manifest())!; replacement["license_id"] = Id(9); f.Client.ImportLicense(replacement.ToJsonString());
        f.Handler.StatusResponse.SetResult(f.Handler.Activation(true)); var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => work); Assert.Equal("registry_activation_interrupted", error.Code); Assert.Null(f.Store.Load()!.RegistryManifest);
    }

    [Fact]
    public async Task ArbitraryApiAndTransportErrorsAreSanitized()
    {
        using var f = new Fixture(); f.Handler.Error = Code; var error = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code)); Assert.Equal("registry_activation_http_409", error.Code);
        f.Handler.Error = ""; f.Handler.ApiOffline = true; var offline = await Assert.ThrowsAsync<RegistryLicenseException>(() => f.Client.ActivateAsync(Code)); Assert.Equal("registry_activation_unavailable", offline.Code);
    }

    [Fact]
    public async Task MalformedPersistedChainObservationsFailClosed()
    {
        using var f = new Fixture(); await f.Client.ActivateAsync(Code);
        var saved = f.Store.Load()!; saved.RegistryChainState = "{\"v\":1,\"head\":{\"number\":100,\"hash\":\"0x00\",\"timestamp\":1},\"licenses\":{}}"; f.Store.Save(saved);
        using var restored = f.Create();
        Assert.Equal("invalid_registry_chain_state", (await Assert.ThrowsAsync<RegistryLicenseException>(() => restored.ValidateAsync())).Code);
    }
}
