using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Talos.Sdk
{
    /// <summary>One running process on an authorized device. Call RequireActiveSession before protected work.</summary>
    public sealed class WalletLicenseClient : IDisposable
    {
        private readonly WalletOptions _options;
        private readonly string _path;
        private readonly Ed25519PrivateKeyParameters _key;
        private readonly HttpClient _http;
        private readonly bool _ownsHttp;
        private readonly object _gate = new object();
        private readonly SemaphoreSlim _requests = new SemaphoreSlim(1, 1);
        private WalletCertificate? _certificate;
        private string? _authorization;
        private JsonElement _entitlements;
        private CancellationTokenSource? _loop;
        private long _deadline;
        private long _lastMono = Stopwatch.GetTimestamp(), _lastWall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        private int _generation, _leaseEpoch;
        private bool _started, _stopping;
        public string InstanceId { get; private set; } = Guid.NewGuid().ToString();
        public string DeviceKey { get; }
        public string FingerprintHash { get; }
        public bool IsDeviceAuthorized => _certificate != null && _authorization != null;

        public WalletLicenseClient(WalletOptions options, HttpClient? http = null)
        {
            _options = options;
            string scope = "wallet:" + options.Issuer.ToLowerInvariant() + ":" + options.ProductId.ToLowerInvariant();
            var fp = Fingerprint.Collect(scope, options.FingerprintComponents);
            _path = options.StatePath ?? StateStore.DefaultPath(scope);
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
            FingerprintHash = WalletProtocol.Hex(WalletProtocol.Hash(fp.Composite));
            using (var mutex = StorageMutex())
            {
                WaitMutex(mutex);
                try
                {
                    var store = new StateStore(_path, scope, fp.Composite);
                    var saved = store.Load();
                    if (saved?.MachineKey == null)
                    {
                        var seed = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(seed);
                        var kp = new Ed25519PrivateKeyParameters(seed, 0);
                        saved = new StoredBinding { Fingerprint = fp.Composite, MachineKey = Convert.ToBase64String(WalletProtocol.Join(WalletProtocol.Bytes("0x302e020100300506032b657004220420", 16), seed)), MachinePublicKey = Convert.ToBase64String(kp.GeneratePublicKey().GetEncoded()) };
                        if (!store.Save(saved)) throw new IOException("device_key_not_saved");
                    }
                    var raw = Convert.FromBase64String(saved.MachineKey);
                    if (raw.Length != 48) throw new IOException("invalid_device_key");
                    _key = new Ed25519PrivateKeyParameters(raw.Skip(16).ToArray(), 0);
                    DeviceKey = WalletProtocol.Hex(_key.GeneratePublicKey().GetEncoded());
                }
                finally { mutex.ReleaseMutex(); }
            }
            _http = http ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) }; _ownsHttp = http == null;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(_path + ".wallet.json"));
                ImportCertificate(doc.RootElement.GetProperty("certificate").GetRawText(), false);
                if (doc.RootElement.TryGetProperty("authorization", out var a) && a.ValueKind == JsonValueKind.Object)
                {
                    if (WalletProtocol.Str(a, "device_key") != DeviceKey || WalletProtocol.Str(a, "fingerprint_hash") != FingerprintHash) throw new ArgumentException("wrong_device");
                    AcceptDeviceAuthorization(WalletProtocol.Str(a, "signature"), false);
                }
            }
            catch (IOException) { }
            catch (JsonException) { }
            catch (ArgumentException) { }
            catch (System.Collections.Generic.KeyNotFoundException) { }
            catch (InvalidOperationException) { }
        }
        private Mutex StorageMutex() => new Mutex(false, "talos-wallet-" + WalletProtocol.Hex(WalletProtocol.Hash(Path.GetFullPath(_path))).Substring(2));
        private static void WaitMutex(Mutex mutex) { try { if (!mutex.WaitOne(TimeSpan.FromSeconds(30))) throw new IOException("device_store_busy"); } catch (AbandonedMutexException) { } }
        public void ImportCertificate(string json, bool persist = true)
        {
            lock (_gate)
            {
                if (_started) throw new InvalidOperationException("stop_session_before_import");
                var cert = new WalletCertificate(json); var ent = WalletProtocol.VerifyCertificate(cert, _options);
                if (_certificate != null && WalletProtocol.LicenseRef(cert) != WalletProtocol.LicenseRef(_certificate)) _authorization = null;
                _certificate = cert; _entitlements = ent;
                if (persist) Save();
            }
        }
        public string CreateDeviceAuthorization() => WalletProtocol.DeviceTypedData(_certificate ?? throw new InvalidOperationException("certificate_required"), DeviceKey, FingerprintHash);
        public void AcceptDeviceAuthorization(string signature, bool persist = true)
        {
            if (_certificate == null) throw new InvalidOperationException("certificate_required");
            WalletProtocol.VerifyDevice(_certificate, DeviceKey, FingerprintHash, signature); _authorization = signature; if (persist) Save();
        }
        private void Device(Utf8JsonWriter w)
        {
            w.WriteStartObject(); w.WriteString("device_key", DeviceKey); w.WriteString("fingerprint_hash", FingerprintHash); w.WriteString("signature", _authorization); w.WriteEndObject();
        }
        private void Save()
        {
            using var mutex = StorageMutex(); WaitMutex(mutex);
            try
            {
                var data = WalletProtocol.Write(w => { w.WriteStartObject(); w.WritePropertyName("certificate"); _certificate!.Root.WriteTo(w); w.WritePropertyName("authorization"); if (_authorization == null) w.WriteNullValue(); else Device(w); w.WriteEndObject(); });
                string path = _path + ".wallet.json", temp = path + "." + Guid.NewGuid() + ".tmp"; File.WriteAllText(temp, data);
                if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
            }
            finally { mutex.ReleaseMutex(); }
        }
        public bool CanRun
        {
            get
            {
                lock (_gate)
                {
                    long mono = Stopwatch.GetTimestamp(), wall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    if (Math.Abs((wall - _lastWall) - (mono - _lastMono) * 1000.0 / Stopwatch.Frequency) > 1500) { _deadline = 0; _leaseEpoch++; _lastMono = mono; _lastWall = wall; }
                    return _started && mono < _deadline;
                }
            }
        }
        public void RequireActiveSession() { if (!CanRun) throw new InvalidOperationException("active_session_required"); }
        public JsonElement? GetEntitlement(string name) { RequireActiveSession(); return _entitlements.TryGetProperty(name, out var value) ? value.Clone() : (JsonElement?)null; }
        public void NotifyResume() { lock (_gate) { _deadline = 0; _leaseEpoch++; } }
        public async Task StartSessionAsync(CancellationToken ct = default)
        {
            int generation;
            lock (_gate) { if (_started || _stopping) throw new InvalidOperationException("session_already_started_or_stopping"); InstanceId = Guid.NewGuid().ToString(); generation = ++_generation; _started = true; }
            try { await Exchange("acquire", ct).ConfigureAwait(false); lock (_gate) { if (!_started || generation != _generation) throw new InvalidOperationException("session_interrupted"); _loop = new CancellationTokenSource(); _ = RenewLoop(_loop.Token); } }
            catch { lock (_gate) { if (generation == _generation) _started = false; } throw; }
        }
        private async Task RenewLoop(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(CanRun ? 20000 : 2000, ct).ConfigureAwait(false);
                    try { await Exchange("renew", ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
                    catch (Exception e) { if (!CanRun) _options.OnSessionLost?.Invoke(e.Message); }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        }
        public async Task StopSessionAsync(CancellationToken ct = default)
        {
            lock (_gate) { if (_stopping) return; _stopping = true; _started = false; _deadline = 0; _generation++; }
            _loop?.Cancel();
            try { if (IsDeviceAuthorized) { try { await Exchange("release", ct).ConfigureAwait(false); } catch (HttpRequestException) { } catch (TaskCanceledException) { } } }
            finally { lock (_gate) _stopping = false; }
        }
        private string Context(string action) => WalletProtocol.Write(w => { w.WriteStartObject(); w.WritePropertyName("certificate"); _certificate!.Root.WriteTo(w); w.WritePropertyName("device"); Device(w); w.WriteString("instance_id", InstanceId); w.WriteString("action", action); w.WriteEndObject(); });
        private async Task<JsonElement> Request(string path, string body, HttpMethod method, CancellationToken ct)
        {
            var endpoint = new Uri(_options.CoordinatorUrl ?? _certificate!.CoordinatorUrl);
            if (endpoint.UserInfo != "" || (endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.IsLoopback))) throw new InvalidOperationException("insecure_coordinator_url");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(10));
            using var req = new HttpRequestMessage(method, endpoint.AbsoluteUri.TrimEnd('/') + path) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            using var res = await _http.SendAsync(req, timeout.Token).ConfigureAwait(false);
            string raw = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (raw.Length > 65536) throw new HttpRequestException("response_too_large");
            using var doc = JsonDocument.Parse(raw);
            if (!res.IsSuccessStatusCode) throw new HttpRequestException(doc.RootElement.TryGetProperty("error", out var error) ? error.GetString() : "coordinator_unavailable");
            return doc.RootElement.Clone();
        }
        private async Task Exchange(string action, CancellationToken ct)
        {
            if (!IsDeviceAuthorized) throw new InvalidOperationException("device_authorization_required");
            int generation; lock (_gate) generation = _generation;
            await _requests.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                int leaseEpoch; lock (_gate) { if (action != "release" && (!_started || generation != _generation)) throw new InvalidOperationException("session_interrupted"); leaseEpoch = _leaseEpoch; }
                var c = _certificate!; string context = Context(action);
                var signed = await Request("/v1/leases/challenge", context, HttpMethod.Post, ct).ConfigureAwait(false);
                var ch = WalletProtocol.VerifyMessage(c.CoordinatorKey, "challenge", signed);
                string reference = WalletProtocol.LicenseRef(c), device = WalletProtocol.DeviceRef(DeviceKey, FingerprintHash);
                if (WalletProtocol.Str(ch, "license_ref") != reference || WalletProtocol.Str(ch, "device_ref") != device || WalletProtocol.Str(ch, "instance_id") != InstanceId || WalletProtocol.Str(ch, "action") != action
                    || ch.GetProperty("expires_at").GetInt64() - ch.GetProperty("issued_at").GetInt64() != 30) throw new InvalidOperationException("challenge_mismatch");
                var signer = new Ed25519Signer(); signer.Init(true, _key); var text = Encoding.UTF8.GetBytes("talos-wallet.1.proof." + WalletProtocol.Str(signed, "payload")); signer.BlockUpdate(text, 0, text.Length);
                var body = WalletProtocol.Write(w => { w.WriteStartObject(); w.WritePropertyName("context"); using (var ctx = JsonDocument.Parse(context)) ctx.RootElement.WriteTo(w); w.WritePropertyName("challenge"); signed.WriteTo(w); w.WriteString("proof", WalletProtocol.Hex(signer.GenerateSignature())); w.WriteEndObject(); });
                long start = Stopwatch.GetTimestamp(), startWall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                string path = action == "acquire" ? "/v1/leases" : "/v1/leases/" + InstanceId + (action == "renew" ? "/renew" : "");
                var result = await Request(path, body, action == "release" ? HttpMethod.Delete : HttpMethod.Post, ct).ConfigureAwait(false);
                var lease = WalletProtocol.VerifyMessage(c.CoordinatorKey, action == "release" ? "released" : "lease", result);
                long issued = lease.GetProperty("issued_at").GetInt64(), expires = lease.GetProperty("expires_at").GetInt64();
                if (WalletProtocol.Str(lease, "nonce") != WalletProtocol.Str(ch, "nonce") || WalletProtocol.Str(lease, "license_ref") != reference || WalletProtocol.Str(lease, "device_ref") != device || WalletProtocol.Str(lease, "instance_id") != InstanceId
                    || expires - issued > 60 || issued < ch.GetProperty("issued_at").GetInt64() || (c.ExpiresAt != 0 && expires > c.ExpiresAt)) throw new InvalidOperationException("lease_mismatch");
                if (action != "release") lock (_gate)
                {
                    long deadline = start + (expires - issued - 5) * Stopwatch.Frequency;
                    if (Stopwatch.GetTimestamp() >= deadline) throw new InvalidOperationException("lease_expired_in_transit");
                    if (generation == _generation && _started) { if (leaseEpoch != _leaseEpoch || Math.Abs((DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - startWall) - (Stopwatch.GetTimestamp() - start) * 1000.0 / Stopwatch.Frequency) > 1500) throw new InvalidOperationException("session_interrupted_by_clock_or_resume"); _deadline = deadline; _lastMono = Stopwatch.GetTimestamp(); _lastWall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); }
                }
            }
            finally { _requests.Release(); }
        }
        /// <summary>Read-only eth_call. Certificate validation alone never grants a running session.</summary>
        public async Task<bool> VerifyViaContractAsync(string rpcUrl, CancellationToken ct = default)
        {
            var cert = _certificate ?? throw new InvalidOperationException("certificate_required");
            WalletProtocol.VerifyCertificate(cert, _options);
            async Task<JsonElement> Rpc(string method, Action<Utf8JsonWriter> parameters)
            {
                string body = WalletProtocol.Write(w => { w.WriteStartObject(); w.WriteString("jsonrpc", "2.0"); w.WriteNumber("id", 1); w.WriteString("method", method); w.WritePropertyName("params"); parameters(w); w.WriteEndObject(); });
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(10));
                using var request = new HttpRequestMessage(HttpMethod.Post, rpcUrl) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
                using var response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false); response.EnsureSuccessStatusCode();
                using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync().ConfigureAwait(false));
                if (doc.RootElement.TryGetProperty("error", out _)) throw new HttpRequestException("rpc_unavailable");
                return doc.RootElement.GetProperty("result").Clone();
            }
            var chain = await Rpc("eth_chainId", w => { w.WriteStartArray(); w.WriteEndArray(); }).ConfigureAwait(false);
            if (Convert.ToInt64(chain.GetString(), 16) != _options.ChainId) throw new InvalidOperationException("wrong_rpc_chain");
            string data = WalletProtocol.VerifyLicenseCallData(cert);
            var result = await Rpc("eth_call", w => { w.WriteStartArray(); w.WriteStartObject(); w.WriteString("to", _options.Contract); w.WriteString("data", data); w.WriteEndObject(); w.WriteStringValue("latest"); w.WriteEndArray(); }).ConfigureAwait(false);
            return result.GetString() == WalletProtocol.Hex(WalletProtocol.Word(1));
        }
        /// <summary>Stops local access immediately. Call StopSessionAsync for best-effort server notification.</summary>
        public void Dispose() { lock (_gate) { _started = false; _deadline = 0; _generation++; } _loop?.Cancel(); if (_ownsHttp) _http.Dispose(); }
    }
}
