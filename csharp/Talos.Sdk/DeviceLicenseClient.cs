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
using static Talos.Sdk.WalletProtocol;

namespace Talos.Sdk
{
    /// <summary>Seven-day offline permit with automatic daily renewal through Talos.</summary>
    public sealed class DeviceLicenseClient : IDisposable
    {
        private readonly WalletOptions _options;
        private readonly string _path;
        private readonly Ed25519PrivateKeyParameters _key;
        private readonly HttpClient _http;
        private readonly bool _ownsHttp;
        private readonly object _gate = new object();
        private readonly SemaphoreSlim _requests = new SemaphoreSlim(1, 1);
        private DeviceEnrollment? _enrollment;
        private DeviceCertificate? _certificate;
        private string? _authorization;
        private JsonElement _entitlements;
        private CancellationTokenSource? _loop;
        private Task? _loopTask;
        private Task? _starting;
        private bool _started;
        private int _generation;
        private double _highWater = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        private long _anchor = Stopwatch.GetTimestamp();
        public string DeviceKey { get; }
        public string FingerprintHash { get; }
        public long? ExpiresAt { get { lock (_gate) return _certificate?.ExpiresAt; } }
        public bool IsDeviceAuthorized { get { lock (_gate) return _enrollment != null && _authorization != null; } }
        public DeviceLicenseClient(WalletOptions options, HttpClient? http = null)
        {
            _options = new WalletOptions { Issuer = options.Issuer, ProductId = options.ProductId, ChainId = options.ChainId, Contract = options.Contract, RenewalUrl = options.RenewalUrl, OnRefreshError = options.OnRefreshError };
            string scope = "wallet-device:" + options.Issuer.ToLowerInvariant() + ":" + options.ProductId.ToLowerInvariant();
            var fp = Fingerprint.Collect(scope, options.FingerprintComponents); FingerprintHash = Hex(Hash(fp.Composite));
            _path = options.StatePath ?? StateStore.DefaultPath(scope); Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
            using (var mutex = StorageMutex())
            {
                WaitMutex(mutex);
                try
                {
                    var store = new StateStore(_path, scope, fp.Composite); var saved = store.Load();
                    if (saved?.MachineKey == null)
                    {
                        var seed = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(seed); var kp = new Ed25519PrivateKeyParameters(seed, 0);
                        saved = new StoredBinding { Fingerprint = fp.Composite, MachineKey = Convert.ToBase64String(Join(Bytes("0x302e020100300506032b657004220420", 16), seed)), MachinePublicKey = Convert.ToBase64String(kp.GeneratePublicKey().GetEncoded()) }; if (!store.Save(saved)) throw new IOException("device_key_not_saved");
                    }
                    var raw = Convert.FromBase64String(saved.MachineKey); if (raw.Length != 48) throw new IOException("invalid_device_key"); _key = new Ed25519PrivateKeyParameters(raw.Skip(16).ToArray(), 0); DeviceKey = Hex(_key.GeneratePublicKey().GetEncoded());
                }
                finally { mutex.ReleaseMutex(); }
            }
            _http = http ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) }; _ownsHttp = http == null;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(_path + ".device.json")); var r = doc.RootElement;
                if (r.TryGetProperty("observed_at", out var at) && at.TryGetInt64(out var observed) && observed <= 9007199254740991) _highWater = Math.Max(_highWater, observed);
                ImportEnrollment(r.GetProperty("enrollment").GetRawText(), false);
                if (r.TryGetProperty("authorization", out var a) && a.ValueKind == JsonValueKind.Object) { if (Str(a, "device_key") != DeviceKey || Str(a, "fingerprint_hash") != FingerprintHash) throw new ArgumentException("wrong_device"); AcceptDeviceAuthorization(Str(a, "signature"), false); }
                if (_authorization != null && r.TryGetProperty("certificate", out var c) && c.ValueKind == JsonValueKind.Object) { var cert = new DeviceCertificate(c.GetRawText()); _entitlements = DeviceProtocol.VerifyCertificate(cert, _enrollment!, DeviceKey, FingerprintHash, _options, Now()); _certificate = cert; }
            }
            catch (Exception e) when (e is IOException || e is JsonException || e is ArgumentException || e is InvalidOperationException || e is System.Collections.Generic.KeyNotFoundException || e is FormatException) {/* Expired cache can renew online; unverified data never permits execution. */}
        }
        private Mutex StorageMutex() => new Mutex(false, "talos-wallet-" + Hex(Hash(Path.GetFullPath(_path))).Substring(2));
        private static void WaitMutex(Mutex m) { try { if (!m.WaitOne(TimeSpan.FromSeconds(30))) throw new IOException("device_store_busy"); } catch (AbandonedMutexException) { } }
        private long Now() { long mono = Stopwatch.GetTimestamp(); _highWater = Math.Max(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), _highWater + Math.Max(0, (mono - _anchor) * 1000.0 / Stopwatch.Frequency)); _anchor = mono; return (long)(_highWater / 1000); }
        public bool CanRun { get { lock (_gate) return _started && _certificate != null && Now() < _certificate.ExpiresAt; } }
        public void RequireValidCertificate() { if (!CanRun) throw new InvalidOperationException("device_certificate_expired"); }
        public JsonElement? GetEntitlement(string name) { lock (_gate) { RequireValidCertificate(); return _entitlements.TryGetProperty(name, out var v) ? v.Clone() : (JsonElement?)null; } }
        public void ImportEnrollment(string json, bool persist = true) { lock (_gate) { if (_started) throw new InvalidOperationException("stop_before_import"); var e = new DeviceEnrollment(json); DeviceProtocol.VerifyEnrollment(e, _options); if (_enrollment != null && Str(_enrollment.Root, "signature") == Str(e.Root, "signature")) { if (persist) Save(); return; } _generation++; _enrollment = e; _certificate = null; _authorization = null; if (persist) Save(); } }
        public string CreateDeviceAuthorization() { lock (_gate) return DeviceTypedData((_enrollment ?? throw new InvalidOperationException("enrollment_required")).Context, DeviceKey, FingerprintHash); }
        public void AcceptDeviceAuthorization(string signature, bool persist = true) { lock (_gate) { if (_enrollment == null) throw new InvalidOperationException("enrollment_required"); VerifyDevice(_enrollment.Context, DeviceKey, FingerprintHash, signature); _authorization = signature; if (persist) Save(); } }
        private void Device(Utf8JsonWriter w) { w.WriteStartObject(); w.WriteString("device_key", DeviceKey); w.WriteString("fingerprint_hash", FingerprintHash); w.WriteString("signature", _authorization); w.WriteEndObject(); }
        private void Save()
        {
            Now(); using var mutex = StorageMutex(); WaitMutex(mutex);
            try
            {
                double observed = _highWater;
                DeviceEnrollment? enrollment = _enrollment;
                DeviceCertificate? certificate = _certificate;
                string? authorization = _authorization;
                JsonElement? preserved = null;
                try
                {
                    using var old = JsonDocument.Parse(File.ReadAllText(_path + ".device.json"));
                    var r = old.RootElement;
                    if (r.TryGetProperty("observed_at", out var at) && at.TryGetInt64(out var n) && n <= 9007199254740991) observed = Math.Max(observed, n);
                    if (r.TryGetProperty("enrollment", out var oldEnrollment) && oldEnrollment.ValueKind == JsonValueKind.Object)
                    {
                        var prior = new DeviceEnrollment(oldEnrollment.GetRawText());
                        DeviceProtocol.VerifyEnrollment(prior, _options);
                        bool same = _enrollment == null || LicenseRef(prior.Context) == LicenseRef(_enrollment.Context);
                        if (same && (_enrollment == null || prior.Revision > _enrollment.Revision)) preserved = r.Clone();
                        else if (same && prior.Revision == _enrollment?.Revision && r.TryGetProperty("authorization", out var auth) && auth.ValueKind == JsonValueKind.Object && r.TryGetProperty("certificate", out var cert) && cert.ValueKind == JsonValueKind.Object && Str(auth, "device_key") == DeviceKey && Str(auth, "fingerprint_hash") == FingerprintHash)
                        {
                            var newer = new DeviceCertificate(cert.GetRawText());
                            if (_certificate == null || newer.NotBefore > _certificate.NotBefore || (newer.NotBefore == _certificate.NotBefore && newer.ExpiresAt > _certificate.ExpiresAt))
                            {
                                VerifyDevice(prior.Context, DeviceKey, FingerprintHash, Str(auth, "signature"));
                                DeviceProtocol.VerifyCertificate(newer, prior, DeviceKey, FingerprintHash, _options, Now());
                                preserved = r.Clone();
                            }
                        }
                    }
                }
                catch (Exception e) when (e is IOException || e is JsonException || e is ArgumentException || e is InvalidOperationException || e is FormatException || e is System.Collections.Generic.KeyNotFoundException) { }
                // Keep a newer revision or certificate written by another process.
                var data = Write(w =>
                {
                    w.WriteStartObject();
                    if (preserved.HasValue)
                    {
                        foreach (var property in preserved.Value.EnumerateObject()) if (property.Name != "observed_at") property.WriteTo(w);
                    }
                    else
                    {
                        w.WritePropertyName("enrollment"); if (enrollment == null) w.WriteNullValue(); else enrollment.Root.WriteTo(w);
                        w.WritePropertyName("authorization"); if (authorization == null) w.WriteNullValue(); else Device(w);
                        w.WritePropertyName("certificate"); if (certificate == null) w.WriteNullValue(); else certificate.Root.WriteTo(w);
                    }
                    w.WriteNumber("observed_at", (long)Math.Ceiling(observed)); w.WriteEndObject();
                });
                string path = _path + ".device.json", temp = path + "." + Guid.NewGuid() + ".tmp"; File.WriteAllText(temp, data); if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
            }
            finally { mutex.ReleaseMutex(); }
        }
        public Task StartAsync(CancellationToken ct = default)
        {
            lock (_gate)
            {
                if (_starting != null && !_starting.IsCompleted) return _starting;
                _starting = StartInternalAsync(ct);
                return _starting;
            }
        }
        private async Task StartInternalAsync(CancellationToken ct)
        {
            int generation; lock (_gate) { if (_started) return; _started = true; generation = _generation; }
            try { if (!CanRun) await RefreshAsync(ct).ConfigureAwait(false); lock (_gate) { if (!_started || generation != _generation) throw new InvalidOperationException("start_interrupted"); Save(); _loop = new CancellationTokenSource(); _loopTask = RenewLoop(_loop.Token); } }
            catch { lock (_gate) { if (generation == _generation) _started = false; } throw; }
        }
        private async Task RenewLoop(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    long due; lock (_gate) due = Math.Min((_certificate?.NotBefore ?? 0) + DeviceProtocol.RenewAfterSeconds, (_certificate?.ExpiresAt ?? 0) - 3600) - Now(); await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, Math.Min(due, 86400))), ct).ConfigureAwait(false);
                    try { await RefreshAsync(ct).ConfigureAwait(false); } catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; } catch (Exception e) { try { _options.OnRefreshError?.Invoke(e.Message); } catch {/* application callback */} }
                    await Task.Delay(TimeSpan.FromHours(1), ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        }
        /// <summary>Call on connectivity restoration. Keeps an unexpired offline permit valid.</summary>
        public async Task NotifyResumeAsync(CancellationToken ct = default) { lock (_gate) { if (!_started || (_certificate != null && Now() < Math.Min(_certificate.NotBefore + DeviceProtocol.RenewAfterSeconds, _certificate.ExpiresAt - 3600))) return; } try { await RefreshAsync(ct).ConfigureAwait(false); } catch (Exception e) when (!(e is OperationCanceledException)) { try { _options.OnRefreshError?.Invoke(e.Message); } catch { } } }
        public async Task StopAsync(CancellationToken ct = default)
        {
            Task? loop; lock (_gate) { _started = false; _generation++; _loop?.Cancel(); loop = _loopTask; }
            if (loop != null) await loop.ConfigureAwait(false); await _requests.WaitAsync(ct).ConfigureAwait(false); try { lock (_gate) { _loop?.Dispose(); _loop = null; _loopTask = null; Save(); } } finally { _requests.Release(); }
        }
        private async Task<JsonElement> Post(string endpoint, string path, string body, CancellationToken ct)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(10));
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint + "/v1/client/wallet/" + path) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            using var response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false); response.EnsureSuccessStatusCode(); string raw = await response.Content.ReadAsStringAsync().ConfigureAwait(false); if (raw.Length > 65536) throw new HttpRequestException("response_too_large"); using var doc = JsonDocument.Parse(raw); return doc.RootElement.Clone();
        }
        public async Task RefreshAsync(CancellationToken ct = default)
        {
            int generation; lock (_gate) generation = _generation; await _requests.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                DeviceEnrollment e; string context; lock (_gate) { e = _enrollment ?? throw new InvalidOperationException("enrollment_required"); if (_authorization == null) throw new InvalidOperationException("device_authorization_required"); context = Write(w => { w.WriteStartObject(); w.WritePropertyName("enrollment"); e.Root.WriteTo(w); w.WritePropertyName("device"); Device(w); w.WriteEndObject(); }); }
                string endpoint = DeviceProtocol.Endpoint(_options.RenewalUrl ?? e.RenewalUrl); var message = await Post(endpoint, "challenge", context, ct).ConfigureAwait(false); var challenge = DeviceProtocol.Challenge(_options.Issuer, message); long now; lock (_gate) now = Now();
                long issued = challenge.GetProperty("issued_at").GetInt64(), expires = challenge.GetProperty("expires_at").GetInt64();
                if (Str(challenge, "license_ref") != LicenseRef(e.Context) || Str(challenge, "device_ref") != DeviceRef(DeviceKey, FingerprintHash) || challenge.GetProperty("revision").GetInt64() != e.Revision || issued > now + 30 || expires <= now || expires > issued + 120) throw new ArgumentException("invalid_challenge");
                var signer = new Ed25519Signer(); signer.Init(true, _key); var bytes = Encoding.UTF8.GetBytes("talos-wallet.2.proof." + Str(message, "payload")); signer.BlockUpdate(bytes, 0, bytes.Length); string proof = Hex(signer.GenerateSignature());
                string body = Write(w => { w.WriteStartObject(); w.WritePropertyName("context"); using (var doc = JsonDocument.Parse(context)) doc.RootElement.WriteTo(w); w.WritePropertyName("challenge"); message.WriteTo(w); w.WriteString("proof", proof); w.WriteEndObject(); });
                var raw = await Post(endpoint, "renew", body, ct).ConfigureAwait(false); var cert = new DeviceCertificate(raw.GetRawText());
                lock (_gate) { var ent = DeviceProtocol.VerifyCertificate(cert, e, DeviceKey, FingerprintHash, _options, Now()); if (generation != _generation) return; if (_certificate != null && cert.NotBefore < _certificate.NotBefore) throw new ArgumentException("certificate_rollback"); _certificate = cert; _entitlements = ent; Save(); }
            }
            finally { _requests.Release(); }
        }
        public async Task<bool> VerifyViaContractAsync(string rpcUrl, CancellationToken ct = default)
        {
            var cert = _certificate ?? throw new InvalidOperationException("certificate_required");
            DeviceProtocol.VerifyCertificate(cert, _enrollment ?? throw new InvalidOperationException("enrollment_required"), DeviceKey, FingerprintHash, _options);
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
            string data = DeviceProtocol.VerifyCallData(cert);
            var result = await Rpc("eth_call", w => { w.WriteStartArray(); w.WriteStartObject(); w.WriteString("to", _options.Contract); w.WriteString("data", data); w.WriteEndObject(); w.WriteStringValue("latest"); w.WriteEndArray(); }).ConfigureAwait(false);
            return result.GetString() == WalletProtocol.Hex(WalletProtocol.Word(1));
        }
        public void Dispose() { lock (_gate) { _started = false; _generation++; _loop?.Cancel(); Save(); } if (_ownsHttp) _http.Dispose(); }
    }
}
