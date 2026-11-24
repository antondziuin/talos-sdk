using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using static Talos.Sdk.WalletProtocol;

namespace Talos.Sdk
{
    /// <summary>Application-pinned registry and RPC configuration. Do not obtain trust anchors from a customer file.</summary>
    public sealed class RegistryLicenseOptions
    {
        public string Issuer { get; set; } = "";
        public string ProductId { get; set; } = "";
        public long ChainId { get; set; } = 11155111;
        public string Contract { get; set; } = "";
        public IReadOnlyList<string> RpcUrls { get; set; } = Array.Empty<string>();
        public string? StatePath { get; set; }
        public IReadOnlyDictionary<string, string>? FingerprintComponents { get; set; }
        public string? ActivationUrl { get; set; }
        public string? ProductToken { get; set; }
    }

    public class RegistryLicenseException : Exception
    {
        public string Code { get; }
        public RegistryLicenseException(string code) : base(code) { Code = code; }
    }

    /// <summary>Public license lookup information. Expiry, status and device binding come only from the registry.</summary>
    public sealed class RegistryLicenseManifest
    {
        internal JsonElement Root { get; }
        internal string Issuer => Str(Root, "issuer");
        internal string ProductId => Str(Root, "product_id");
        internal string LicenseId => Str(Root, "license_id");
        internal string Holder => Str(Root, "holder");
        public string Json => Root.GetRawText();
        public RegistryLicenseManifest(string json)
        {
            try
            {
                if (json.Length > 65536) throw new ArgumentException();
                using var doc = JsonDocument.Parse(json);
                Root = doc.RootElement.Clone();
            }
            catch (Exception e) when (e is JsonException || e is ArgumentException) { throw new RegistryLicenseException("invalid_registry_manifest"); }
        }
    }

    public sealed class RegistryDeviceBinding
    {
        public long ChainId { get; }
        public string To { get; }
        public string Data { get; }
        public long Value => 0;
        public string ExpectedHolder { get; }
        internal RegistryDeviceBinding(long chainId, string to, string data, string holder) { ChainId = chainId; To = to; Data = data; ExpectedHolder = holder; }
    }

    /// <summary>A fresh chain observation, not an offline execution permit. Recheck before each protected operation.</summary>
    public sealed class RegistryLicenseState
    {
        public bool IsValid => true;
        public JsonElement Entitlements { get; }
        public long? ExpiresAt { get; }
        public long NotBefore { get; }
        public long Revision { get; }
        public long BlockNumber { get; }
        public string BlockHash { get; }
        public long CheckedAt { get; }
        internal RegistryLicenseState(JsonElement entitlements, long expires, long before, long revision, long block, string hash, long at)
        { Entitlements = entitlements.Clone(); ExpiresAt = expires == 0 ? (long?)null : expires; NotBefore = before; Revision = revision; BlockNumber = block; BlockHash = hash; CheckedAt = at; }
    }

    /// <summary>Reads validity directly from RPC. Optional code activation contacts Talos only to arrange publication.</summary>
    public sealed partial class RegistryLicenseClient : IDisposable
    {
        private sealed class TransientRpcException : RegistryLicenseException { internal TransientRpcException(string code) : base(code) { } }
        private readonly RegistryLicenseOptions _options;
        private readonly HttpClient _http;
        private readonly bool _ownsHttp;
        private readonly StateStore _store;
        private readonly string _path;
        private readonly object _gate = new object();
        private RegistryLicenseManifest? _license;
        private JsonElement _entitlements;
        private string _entitlementsHash = "";
        private int _generation;
        private bool _disposed;
        private double _highWater = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        private long _anchor = Stopwatch.GetTimestamp();
        public string DeviceKey { get; }

        public RegistryLicenseClient(RegistryLicenseOptions options, HttpClient? http = null)
        {
            try
            {
                foreach (var a in new[] { options.Issuer, options.Contract }) if (Bytes(a, 20).All(x => x == 0)) throw new ArgumentException();
                if (Bytes(options.ProductId, 32).All(x => x == 0) || !new long[] { 8453, 11155111, 31337 }.Contains(options.ChainId) || options.RpcUrls.Count < 1 || options.RpcUrls.Count > 5) throw new ArgumentException();
                foreach (var endpoint in options.RpcUrls)
                {
                    var u = new Uri(endpoint);
                    if ((u.Scheme != "https" && !(u.Scheme == "http" && new[] { "localhost", "127.0.0.1", "[::1]" }.Contains(u.Host))) || u.UserInfo != "" || u.Fragment != "") throw new ArgumentException();
                }
                if (options.ActivationUrl != null || options.ProductToken != null)
                {
                    if (string.IsNullOrEmpty(options.ProductToken) || options.ProductToken!.Length > 256 || options.ActivationUrl == null) throw new ArgumentException();
                    ActivationEndpoint(options.ActivationUrl);
                }
                _options = new RegistryLicenseOptions { Issuer = options.Issuer, ProductId = options.ProductId, ChainId = options.ChainId, Contract = options.Contract, RpcUrls = options.RpcUrls.ToArray(), ActivationUrl = options.ActivationUrl, ProductToken = options.ProductToken };
            }
            catch (Exception e) when (e is ArgumentException || e is FormatException || e is NullReferenceException) { throw new RegistryLicenseException("invalid_registry_configuration"); }
            string scope = "wallet-registry:" + _options.ChainId.ToString(CultureInfo.InvariantCulture) + ":" + _options.Contract.ToLowerInvariant() + ":" + _options.Issuer.ToLowerInvariant() + ":" + _options.ProductId.ToLowerInvariant();
            var fp = Fingerprint.Collect(scope, options.FingerprintComponents);
            _path = options.StatePath ?? StateStore.DefaultPath(scope);
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
            _store = new StateStore(_path, scope, fp.Composite);
            using (var mutex = StorageMutex())
            {
                WaitMutex(mutex);
                try
                {
                    var saved = _store.Load();
                    if (saved?.MachineKey == null)
                    {
                        var seed = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(seed);
                        var pair = new Ed25519PrivateKeyParameters(seed, 0);
                        saved = new StoredBinding { Fingerprint = fp.Composite, MachineKey = Convert.ToBase64String(Join(Bytes("0x302e020100300506032b657004220420", 16), seed)), MachinePublicKey = Convert.ToBase64String(pair.GeneratePublicKey().GetEncoded()) };
                        if (!_store.Save(saved)) throw new RegistryLicenseException("device_key_not_saved");
                    }
                    var raw = Convert.FromBase64String(saved.MachineKey);
                    if (raw.Length != 48 || !raw.Take(16).SequenceEqual(Bytes("0x302e020100300506032b657004220420", 16))) throw new RegistryLicenseException("invalid_device_key");
                    _activationKey = new Ed25519PrivateKeyParameters(raw.Skip(16).ToArray(), 0);
                    DeviceKey = Hex(_activationKey.GeneratePublicKey().GetEncoded());
                    _highWater = Math.Max(_highWater, Math.Max(saved.TimeHighWater, saved.OfflineSeen));
                }
                finally { mutex.ReleaseMutex(); }
            }
            _http = http ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) };
            _ownsHttp = http == null;
            RestoreActivationState();
        }

        public static Task<RegistryLicenseClient> CreateAsync(RegistryLicenseOptions options, HttpClient? http = null) => Task.FromResult(new RegistryLicenseClient(options, http));
        private Mutex StorageMutex() => new Mutex(false, "talos-registry-" + Hex(Hash(Path.GetFullPath(_path))).Substring(2));
        private static void WaitMutex(Mutex mutex) { try { if (!mutex.WaitOne(TimeSpan.FromSeconds(30))) throw new IOException("device_store_busy"); } catch (AbandonedMutexException) { } }
        private void RequireOpen() { if (_disposed) throw new ObjectDisposedException(nameof(RegistryLicenseClient)); }
        private long Now()
        {
            lock (_gate)
            {
                long mono = Stopwatch.GetTimestamp();
                _highWater = Math.Max(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), _highWater + Math.Max(0, (mono - _anchor) * 1.0 / Stopwatch.Frequency));
                _anchor = mono; return (long)_highWater;
            }
        }

        public void ImportLicense(string json) => ImportLicense(new RegistryLicenseManifest(json));
        public void ImportLicense(RegistryLicenseManifest manifest)
        {
            lock (_gate)
            {
                RequireOpen();
                var parsed = ParseManifest(manifest);
                _entitlements = parsed.Entitlements; _entitlementsHash = parsed.Hash; _license = manifest; _generation++;
            }
        }
        private (JsonElement Entitlements, string Hash) ParseManifest(RegistryLicenseManifest manifest)
        {
                try
                {
                    var r = manifest.Root;
                    if (r.EnumerateObject().Any(p => !new[] { "v", "kind", "chain_id", "contract", "issuer", "product_id", "license_id", "holder", "entitlements" }.Contains(p.Name))) throw new ArgumentException();
                    if (r.GetProperty("v").GetInt32() != 1 || Str(r, "kind") != "talos-registry-license" || r.GetProperty("chain_id").GetInt64() != _options.ChainId || !DeviceProtocol.Eq(manifest.Issuer, _options.Issuer) || !DeviceProtocol.Eq(manifest.ProductId, _options.ProductId) || !DeviceProtocol.Eq(Str(r, "contract"), _options.Contract)) throw new ArgumentException();
                    foreach (var a in new[] { manifest.Issuer, Str(r, "contract"), manifest.Holder }) if (Bytes(a, 20).All(x => x == 0)) throw new ArgumentException();
                    foreach (var id in new[] { manifest.ProductId, manifest.LicenseId }) if (Bytes(id, 32).All(x => x == 0)) throw new ArgumentException();
                    string encoded = Str(r, "entitlements"); var bytes = Decode(encoded);
                    if (bytes.Length > 32768 || Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != encoded) throw new ArgumentException();
                    using var ent = JsonDocument.Parse(bytes);
                    if (ent.RootElement.ValueKind != JsonValueKind.Object) throw new ArgumentException();
                    return (ent.RootElement.Clone(), Hex(Hash(bytes)));
                }
                catch (Exception e) when (e is ArgumentException || e is JsonException || e is FormatException || e is InvalidOperationException || e is KeyNotFoundException || e is OverflowException) { throw new RegistryLicenseException("invalid_registry_manifest"); }
        }

        private static string Call(string signature, params byte[][] args) => Hex(Join(Hash(signature).Take(4).ToArray(), Join(args)));
        public RegistryDeviceBinding CreateDeviceBinding()
        {
            lock (_gate)
            {
                RequireOpen(); var m = _license ?? throw new RegistryLicenseException("registry_manifest_required");
                return new RegistryDeviceBinding(_options.ChainId, _options.Contract, Call("bindDevice(address,bytes32,bytes32,bytes32)", Address(_options.Issuer), Bytes(_options.ProductId, 32), Bytes(m.LicenseId, 32), Bytes(DeviceKey, 32)), m.Holder);
            }
        }

        private async Task<JsonElement> Rpc(string endpoint, string method, Action<Utf8JsonWriter> parameters, CancellationToken ct)
        {
            string body = Write(w => { w.WriteStartObject(); w.WriteString("jsonrpc", "2.0"); w.WriteNumber("id", 1); w.WriteString("method", method); w.WritePropertyName("params"); parameters(w); w.WriteEndObject(); });
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(10));
                using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
                using var response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false);
                int status = (int)response.StatusCode;
                if (!response.IsSuccessStatusCode)
                {
                    if (status == 401 || status == 403 || status == 408 || status == 429 || status >= 500) throw new TransientRpcException("registry_rpc_unavailable");
                    throw new RegistryLicenseException("registry_rpc_rejected");
                }
                string raw = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (raw.Length > 1048576) throw new RegistryLicenseException("invalid_registry_rpc_response");
                using var doc = JsonDocument.Parse(raw); var r = doc.RootElement;
                if (Str(r, "jsonrpc") != "2.0" || r.GetProperty("id").GetInt32() != 1) throw new RegistryLicenseException("invalid_registry_rpc_response");
                if (r.TryGetProperty("error", out var error) && error.ValueKind != JsonValueKind.Null)
                {
                    int code = error.GetProperty("code").GetInt32();
                    if (code == -32005 || code == -32002 || code == -32603) throw new TransientRpcException("registry_rpc_unavailable");
                    throw new RegistryLicenseException("registry_rpc_rejected");
                }
                return r.GetProperty("result").Clone();
            }
            catch (HttpRequestException) { throw new TransientRpcException("registry_rpc_unavailable"); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new TransientRpcException("registry_rpc_unavailable"); }
            catch (Exception e) when (e is JsonException || e is KeyNotFoundException || e is InvalidOperationException || e is FormatException || e is OverflowException) { throw new RegistryLicenseException("invalid_registry_rpc_response"); }
        }

        private static void Empty(Utf8JsonWriter w) { w.WriteStartArray(); w.WriteEndArray(); }
        private static long Quantity(string? value)
        {
            if (value == null || !value.StartsWith("0x", StringComparison.Ordinal) || value.Length < 3 || !long.TryParse(value.Substring(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var number) || number < 0 || number > 9007199254740991) throw new RegistryLicenseException("invalid_registry_rpc_response");
            return number;
        }
        private static long Number(byte[] bytes, int word)
        {
            int offset = word * 32;
            if (bytes.Skip(offset).Take(24).Any(x => x != 0)) throw new RegistryLicenseException("invalid_registry_record");
            ulong number = 0; for (int i = 24; i < 32; i++) number = (number << 8) | bytes[offset + i];
            if (number > 9007199254740991) throw new RegistryLicenseException("invalid_registry_record");
            return (long)number;
        }
        private async Task<string> EthCall(string endpoint, string data, string block, CancellationToken ct)
        {
            var result = await Rpc(endpoint, "eth_call", w => { w.WriteStartArray(); w.WriteStartObject(); w.WriteString("to", _options.Contract); w.WriteString("data", data); w.WriteEndObject(); w.WriteStringValue(block); w.WriteEndArray(); }, ct).ConfigureAwait(false);
            if (result.ValueKind != JsonValueKind.String) throw new RegistryLicenseException("invalid_registry_rpc_response");
            return result.GetString() ?? throw new RegistryLicenseException("invalid_registry_rpc_response");
        }

        /// <summary>Always reads fresh RPC state. An authoritative refusal never consults another provider.</summary>
        public async Task<RegistryLicenseState> ValidateAsync(CancellationToken ct = default)
        {
            RegistryLicenseManifest license; JsonElement entitlements; string hash; int generation;
            lock (_gate) { RequireOpen(); license = _license ?? throw new RegistryLicenseException("registry_manifest_required"); entitlements = _entitlements; hash = _entitlementsHash; generation = _generation; }
            return await ValidateCandidate(license, entitlements, hash, generation, ct).ConfigureAwait(false);
        }
        private async Task<RegistryLicenseState> ValidateCandidate(RegistryLicenseManifest license, JsonElement entitlements, string hash, int generation, CancellationToken ct)
        {
            RegistryLicenseException? last = null;
            foreach (string endpoint in _options.RpcUrls)
            {
                try { return await Read(endpoint, license, entitlements, hash, generation, ct).ConfigureAwait(false); }
                catch (TransientRpcException e) { last = e; }
            }
            throw last ?? new RegistryLicenseException("registry_rpc_unavailable");
        }

        private async Task<RegistryLicenseState> Read(string endpoint, RegistryLicenseManifest m, JsonElement entitlements, string entitlementsHash, int generation, CancellationToken ct)
        {
            var chain = await Rpc(endpoint, "eth_chainId", Empty, ct).ConfigureAwait(false);
            if (chain.ValueKind != JsonValueKind.String) throw new RegistryLicenseException("invalid_registry_rpc_response");
            if (Quantity(chain.GetString()) != _options.ChainId) throw new RegistryLicenseException("wrong_rpc_chain");
            var saved = _store.Load(); var initial = ChainState(saved?.RegistryChainState);
            var block = Block(await BlockAt(endpoint, "latest", ct).ConfigureAwait(false)); bool reorg = false;
            if (initial != null)
            {
                if (block.Number < initial.Head.Number)
                {
                    if (initial.Head.Number - block.Number != 1) throw new TransientRpcException("rpc_block_lag");
                    var known = await BlockAt(endpoint, initial.Head.Tag, ct).ConfigureAwait(false);
                    if (known.ValueKind == JsonValueKind.Null || !SameHead(initial.Head, Block(known))) throw new TransientRpcException("rpc_block_lag");
                    if (_options.RpcUrls.Count > 1) throw new TransientRpcException("rpc_block_lag");
                    await Task.Delay(1000, ct).ConfigureAwait(false);
                    block = Block(await BlockAt(endpoint, "latest", ct).ConfigureAwait(false));
                    if (block.Number < initial.Head.Number) throw new TransientRpcException("rpc_block_lag");
                }
                var anchor = await BlockAt(endpoint, initial.Head.Tag, ct).ConfigureAwait(false);
                if (anchor.ValueKind == JsonValueKind.Null) throw new TransientRpcException("rpc_canonicality_unavailable");
                var canonical = Block(anchor);
                if (canonical.Number != initial.Head.Number) throw new TransientRpcException("rpc_canonicality_unavailable");
                if (block.Number == initial.Head.Number && !SameHead(block, canonical)) throw new TransientRpcException("rpc_snapshot_reorg");
                reorg = !DeviceProtocol.Eq(canonical.Hash, initial.Head.Hash);
                if (!reorg && canonical.Timestamp != initial.Head.Timestamp) throw new TransientRpcException("rpc_block_rollback");
                if (!reorg && block.Timestamp < canonical.Timestamp) throw new TransientRpcException("rpc_block_rollback");
            }
            else if (block.Timestamp < (saved?.TimeHighWater ?? 0)) throw new TransientRpcException("rpc_block_rollback");
            string tag = block.Tag, blockHash = block.Hash; long number = block.Number, timestamp = block.Timestamp;
            long now = Now(); if (timestamp < now - 300 || timestamp > now + 30) throw new TransientRpcException("stale_rpc_block");
            var code = await Rpc(endpoint, "eth_getCode", w => { w.WriteStartArray(); w.WriteStringValue(_options.Contract); w.WriteStringValue(tag); w.WriteEndArray(); }, ct).ConfigureAwait(false);
            static byte[] CheckedBytes(string hex, int len)
            {
                try { return Bytes(hex, len); }
                catch (Exception e) when (e is ArgumentException || e is FormatException) { throw new RegistryLicenseException("invalid_registry_rpc_response"); }
            }
            if (code.ValueKind != JsonValueKind.String) throw new RegistryLicenseException("invalid_registry_rpc_response");
            string codeHex = code.GetString() ?? "";
            if (codeHex.Length <= 2 || codeHex.Length % 2 != 0) throw new RegistryLicenseException("registry_contract_missing");
            CheckedBytes(codeHex, (codeHex.Length - 2) / 2);
            if (!CheckedBytes(await EthCall(endpoint, Call("registryVersion()"), tag, ct).ConfigureAwait(false), 32).SequenceEqual(Word(1))) throw new RegistryLicenseException("wrong_registry_version");
            var words = CheckedBytes(await EthCall(endpoint, Call("getLicense(address,bytes32,bytes32)", Address(_options.Issuer), Bytes(_options.ProductId, 32), Bytes(m.LicenseId, 32)), tag, ct).ConfigureAwait(false), 7 * 32);
            long before = Number(words, 2), expires = Number(words, 3), revision = Number(words, 5), status = Number(words, 6);
            if (status > 3 || (status != 0 && revision == 0)) throw new RegistryLicenseException("invalid_registry_record");
            if (words.Take(12).Any(x => x != 0)) throw new RegistryLicenseException("invalid_registry_record");
            string holder = Hex(words.Skip(12).Take(20).ToArray()), device = Hex(words.Skip(32).Take(32).ToArray()), rights = Hex(words.Skip(4 * 32).Take(32).ToArray());
            now = Now();
            string? refusal = status != 1 ? status == 0 ? "license_missing" : status == 2 ? "license_suspended" : "license_revoked"
                : !DeviceProtocol.Eq(holder, m.Holder) ? "wrong_license_holder" : Bytes(device, 32).All(x => x == 0) ? "device_not_bound"
                : !DeviceProtocol.Eq(device, DeviceKey) ? "wrong_device" : !DeviceProtocol.Eq(rights, entitlementsHash) ? "invalid_entitlements_hash"
                : before > timestamp || before > now ? "license_not_started" : expires != 0 && (expires <= timestamp || expires <= now || expires <= before) ? "license_expired" : null;
            if (refusal == null)
            {
                var check = CheckedBytes(await EthCall(endpoint, Call("checkLicense(address,bytes32,bytes32,address,bytes32,bytes32)", Address(_options.Issuer), Bytes(_options.ProductId, 32), Bytes(m.LicenseId, 32), Address(m.Holder), Bytes(DeviceKey, 32), Bytes(entitlementsHash, 32)), tag, ct).ConfigureAwait(false), 32);
                if (!check.SequenceEqual(Word(1))) refusal = "registry_license_rejected";
            }
            var final = await BlockAt(endpoint, tag, ct).ConfigureAwait(false);
            if (final.ValueKind == JsonValueKind.Null || !SameHead(block, Block(final))) throw new TransientRpcException("rpc_snapshot_reorg");
            ct.ThrowIfCancellationRequested();
            if (Observe(block, initial, m.LicenseId, revision, status == 3, refusal != null, reorg, generation)) throw new RegistryLicenseException("license_revoked");
            if (refusal != null) throw new RegistryLicenseException(refusal);
            lock (_gate) { RequireOpen(); if (generation != _generation) throw new RegistryLicenseException("license_changed_during_validation"); }
            now = Now();
            if (expires != 0 && expires <= now) throw new RegistryLicenseException("license_expired");
            if (timestamp < now - 300) throw new TransientRpcException("stale_rpc_block");
            ct.ThrowIfCancellationRequested();
            return new RegistryLicenseState(entitlements, expires, before, revision, number, blockHash, now);
        }

        public Task<RegistryLicenseState> RequireValidLicenseAsync(CancellationToken ct = default) => ValidateAsync(ct);
        public async Task<JsonElement?> GetEntitlementAsync(string name, CancellationToken ct = default)
        { var state = await ValidateAsync(ct).ConfigureAwait(false); return state.Entitlements.TryGetProperty(name, out var value) ? value.Clone() : (JsonElement?)null; }
        public void Dispose() { lock (_gate) { _disposed = true; _generation++; if (_ownsHttp) _http.Dispose(); } }
    }
}
