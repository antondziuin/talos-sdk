using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using static Talos.Sdk.WalletProtocol;

namespace Talos.Sdk
{
    public sealed class RegistryActivationOptions
    {
        private TimeSpan? _timeout;
        public TimeSpan Timeout { get => _timeout ?? TimeSpan.FromMinutes(2); set => _timeout = value; }
        internal TimeSpan TimeoutForChain(long chain) => _timeout ?? TimeSpan.FromMinutes(chain == 8453 ? 10 : 2);
        public Action<RegistryActivationProgress>? OnProgress { get; set; }
    }
    public sealed class RegistryActivationProgress
    {
        public string Status { get; }
        public string ActivationId { get; }
        public int RetryAfterSeconds { get; }
        internal RegistryActivationProgress(string status, string id, int retry) { Status = status; ActivationId = id; RetryAfterSeconds = retry; }
    }
    public static class RegistryActivationProtocol
    {
        public static string ActivationMessage(string productToken, string code, string deviceKey, string requestId)
        {
            Bytes(deviceKey, 32); if (!Guid.TryParseExact(requestId, "D", out var id)) throw new RegistryLicenseException("invalid_activation_request_id");
            return "talos-registry-activation.1." + Hex(Hash(productToken)) + "." + Hex(Hash(code.Trim())) + "." + deviceKey.ToLowerInvariant() + "." + id.ToString("D");
        }
        public static string StatusMessage(string productToken, string activationId, string deviceKey)
        {
            Bytes(deviceKey, 32); if (!Guid.TryParseExact(activationId, "D", out var id)) throw new RegistryLicenseException("invalid_activation_id");
            return "talos-registry-status.1." + Hex(Hash(productToken)) + "." + id.ToString("D") + "." + deviceKey.ToLowerInvariant();
        }
    }

    public sealed partial class RegistryLicenseClient
    {
        private readonly Ed25519PrivateKeyParameters _activationKey;
        private string? _activationId;
        private Task<RegistryLicenseState>? _activationWork;
        /// <summary>A public manifest is held locally. Protected operations still require fresh ValidateAsync.</summary>
        public bool IsActivated { get { lock (_gate) return _license != null; } }
        public bool HasPendingActivation { get { lock (_gate) return _activationId != null; } }

        private static string ActivationEndpoint(string value)
        {
            try
            {
                var url = new Uri(value);
                if ((url.Scheme != "https" && !(url.Scheme == "http" && new[] { "localhost", "127.0.0.1", "[::1]" }.Contains(url.Host))) || url.UserInfo != "" || url.Query != "" || url.Fragment != "") throw new ArgumentException();
                return url.AbsoluteUri.TrimEnd('/');
            }
            catch (Exception e) when (e is FormatException || e is ArgumentException) { throw new RegistryLicenseException("invalid_registry_activation_url"); }
        }

        private void RestoreActivationState()
        {
            lock (_gate)
            {
                var saved = _store.Load();
                if (_license == null && saved?.RegistryManifest != null) { try { ImportLicense(saved.RegistryManifest); } catch (RegistryLicenseException) { } }
                if (_license == null && Guid.TryParseExact(saved?.RegistryActivationId, "D", out var id)) _activationId = id.ToString("D");
            }
        }

        /// <summary>Claims a code with the local Ed25519 key, then waits for ready and fresh RPC validation. No customer wallet is used.</summary>
        public Task<RegistryLicenseState> ActivateAsync(string? code = null, RegistryActivationOptions? options = null, CancellationToken cancellationToken = default)
        {
            lock (_gate)
            {
                RequireOpen();
                if (_activationWork != null && !_activationWork.IsCompleted) return _activationWork;
                _activationWork = ActivateWithDeadline(code, options ?? new RegistryActivationOptions(), cancellationToken);
                return _activationWork;
            }
        }
        public Task<RegistryLicenseState> ResumeActivationAsync(RegistryActivationOptions? options = null, CancellationToken cancellationToken = default) => ActivateAsync(null, options, cancellationToken);

        private async Task<RegistryLicenseState> ActivateWithDeadline(string? code, RegistryActivationOptions options, CancellationToken cancellationToken)
        {
            TimeSpan timeout = options.TimeoutForChain(_options.ChainId);
            double milliseconds = timeout.TotalMilliseconds;
            if (milliseconds < 1 || milliseconds > 600000 || double.IsNaN(milliseconds)) throw new RegistryLicenseException("invalid_registry_activation_timeout");
            if (cancellationToken.IsCancellationRequested) throw new RegistryLicenseException("registry_activation_aborted");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(timeout);
            var work = ActivateInternal(code, options, deadline.Token);
            try
            {
                if (await Task.WhenAny(work, Task.Delay(System.Threading.Timeout.Infinite, deadline.Token)).ConfigureAwait(false) != work)
                {
                    _ = work.ContinueWith(t => { _ = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
                    throw new RegistryLicenseException(cancellationToken.IsCancellationRequested ? "registry_activation_aborted" : "registry_activation_timeout");
                }
                return await work.ConfigureAwait(false);
            }
            catch (OperationCanceledException) { throw new RegistryLicenseException(cancellationToken.IsCancellationRequested ? "registry_activation_aborted" : "registry_activation_timeout"); }
            finally { deadline.Cancel(); }
        }

        private string ActivationProof(string message)
        {
            var signer = new Ed25519Signer(); signer.Init(true, _activationKey); var bytes = Encoding.ASCII.GetBytes(message); signer.BlockUpdate(bytes, 0, bytes.Length); return Hex(signer.GenerateSignature());
        }
        private sealed class ActivationResponse
        {
            internal string Status = "", Id = "";
            internal RegistryLicenseManifest? Manifest;
            internal int Retry;
        }
        private async Task<ActivationResponse> ActivationPost(string path, string body, CancellationToken ct)
        {
            string raw; System.Net.HttpStatusCode status;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, ActivationEndpoint(_options.ActivationUrl!) + "/v1/client/registry/" + path) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
                using var response = await _http.SendAsync(request, ct).ConfigureAwait(false); status = response.StatusCode;
                raw = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch (HttpRequestException) { throw new RegistryLicenseException("registry_activation_unavailable"); }
            // HttpClient's own timeout is a transport failure, not the caller's deadline or cancellation.
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new RegistryLicenseException("registry_activation_unavailable"); }
            if (raw.Length > 65536) throw new RegistryLicenseException("invalid_registry_activation_response");
            try
            {
                using var doc = JsonDocument.Parse(raw); var r = doc.RootElement;
                if ((int)status < 200 || (int)status >= 300)
                {
                    string? error = r.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;
                    var known = new[] { "license_not_found", "activation_already_bound", "automatic_activation_not_enabled", "invalid_registry_activation", "invalid_device_proof", "activation_not_found", "license_inactive", "tenant_closed" };
                    throw new RegistryLicenseException(error != null && known.Contains(error) ? error : "registry_activation_http_" + (int)status);
                }
                string state = Str(r, "status");
                if (!new[] { "pending", "ready", "failed" }.Contains(state) || !Guid.TryParseExact(Str(r, "activation_id"), "D", out var id)) throw new ArgumentException();
                int retry = r.GetProperty("retry_after_s").GetInt32();
                var manifest = r.GetProperty("manifest");
                if (retry < 0 || retry > 60 || (state == "ready" ? manifest.ValueKind != JsonValueKind.Object || r.GetProperty("error").ValueKind != JsonValueKind.Null : manifest.ValueKind != JsonValueKind.Null)) throw new ArgumentException();
                return new ActivationResponse { Status = state, Id = id.ToString("D"), Retry = retry, Manifest = state == "ready" ? new RegistryLicenseManifest(manifest.GetRawText()) : null };
            }
            catch (Exception e) when (e is JsonException || e is ArgumentException || e is System.Collections.Generic.KeyNotFoundException || e is InvalidOperationException) { throw new RegistryLicenseException("invalid_registry_activation_response"); }
        }

        private void SaveActivation(string id, RegistryLicenseManifest? manifest, bool failed, int generation, CancellationToken ct)
        {
            lock (_gate)
            {
                RequireOpen(); ct.ThrowIfCancellationRequested(); if (generation != _generation) throw new RegistryLicenseException("registry_activation_interrupted");
                using var mutex = StorageMutex(); WaitMutex(mutex);
                try
                {
                    ct.ThrowIfCancellationRequested();
                    var saved = _store.Load();
                    if (saved?.MachineKey == null || saved.MachinePublicKey == null || Hex(Convert.FromBase64String(saved.MachinePublicKey)) != DeviceKey) throw new RegistryLicenseException("device_key_missing");
                    if (saved.RegistryActivationId != null && !DeviceProtocol.Eq(saved.RegistryActivationId, id)) throw new RegistryLicenseException("registry_activation_state_conflict");
                    if (manifest != null)
                    {
                        ParseManifest(manifest);
                        if (saved.RegistryManifest != null)
                        {
                            var old = new RegistryLicenseManifest(saved.RegistryManifest); ParseManifest(old);
                            foreach (var property in manifest.Root.EnumerateObject())
                            {
                                var prior = old.Root.GetProperty(property.Name);
                                bool equal = property.Value.ValueKind == JsonValueKind.String
                                    ? (property.Name == "entitlements" || property.Name == "kind" ? property.Value.GetString() == prior.GetString() : DeviceProtocol.Eq(property.Value.GetString()!, prior.GetString()!))
                                    : property.Value.GetRawText() == prior.GetRawText();
                                if (!equal) throw new RegistryLicenseException("registry_activation_state_conflict");
                            }
                        }
                        saved.RegistryManifest = manifest.Json; saved.RegistryActivationId = null;
                    }
                    else if (failed) saved.RegistryActivationId = null;
                    else
                    {
                        if (saved.RegistryManifest != null) throw new RegistryLicenseException("registry_activation_state_conflict");
                        saved.RegistryActivationId = id;
                    }
                    if (!_store.Save(saved)) throw new RegistryLicenseException("device_state_not_saved");
                    _activationId = manifest != null || failed ? null : id;
                }
                finally { mutex.ReleaseMutex(); }
            }
        }

        private Task<ActivationResponse> PollActivation(string id, CancellationToken ct)
        {
            string proof = ActivationProof(RegistryActivationProtocol.StatusMessage(_options.ProductToken!, id, DeviceKey));
            return ActivationPost("activation-status", Write(w => { w.WriteStartObject(); w.WriteString("product_token", _options.ProductToken); w.WriteString("activation_id", id); w.WriteString("device_key", DeviceKey); w.WriteString("proof", proof); w.WriteEndObject(); }), ct);
        }

        private async Task<RegistryLicenseState> ActivateInternal(string? code, RegistryActivationOptions options, CancellationToken ct)
        {
            int generation; string? pending; bool imported;
            lock (_gate) { RequireOpen(); ct.ThrowIfCancellationRequested(); RestoreActivationState(); generation = _generation; pending = _activationId; imported = _license != null; }
            if (imported) return await ValidateAsync(ct).ConfigureAwait(false);
            if (_options.ActivationUrl == null || _options.ProductToken == null) throw new RegistryLicenseException("registry_activation_not_configured");
            void Active() { ct.ThrowIfCancellationRequested(); lock (_gate) { RequireOpen(); if (generation != _generation) throw new RegistryLicenseException("registry_activation_interrupted"); } }
            void Progress(string status, string id, int retry) { try { options.OnProgress?.Invoke(new RegistryActivationProgress(status, id, retry)); } catch { } }
            async Task<ActivationResponse> Poll(string id)
            {
                try { return await PollActivation(id, ct).ConfigureAwait(false); }
                // The server no longer has this job. Forget it, or every later ActivateAsync(code) polls it forever.
                catch (RegistryLicenseException e) when (e.Code == "activation_not_found") { SaveActivation(id, null, true, generation, ct); throw; }
            }
            ActivationResponse response;
            if (pending != null) response = await Poll(pending).ConfigureAwait(false);
            else
            {
                string normalized = code?.Trim() ?? "";
                if (normalized.Length == 0 || normalized.Length > 512) throw new RegistryLicenseException("activation_code_required");
                string requestId = Guid.NewGuid().ToString("D");
                string proof = ActivationProof(RegistryActivationProtocol.ActivationMessage(_options.ProductToken, normalized, DeviceKey, requestId));
                try { response = await ActivationPost("activate", Write(w => { w.WriteStartObject(); w.WriteString("product_token", _options.ProductToken); w.WriteString("license_key", normalized); w.WriteString("device_key", DeviceKey); w.WriteString("request_id", requestId); w.WriteString("proof", proof); w.WriteEndObject(); }), ct).ConfigureAwait(false); }
                finally { normalized = ""; }
            }
            while (true)
            {
                Active();
                lock (_gate) { if (_activationId != null && response.Id != _activationId) throw new RegistryLicenseException("invalid_registry_activation_response"); }
                if (response.Status == "failed") { SaveActivation(response.Id, null, true, generation, ct); throw new RegistryLicenseException("registry_activation_failed"); }
                if (response.Status == "ready")
                {
                    var candidate = ParseManifest(response.Manifest!);
                    // Ready alone is not an authorization. Preserve the resumable
                    // job until fresh RPC validates its exact manifest and device.
                    SaveActivation(response.Id, null, false, generation, ct); Progress("validating", response.Id, 0);
                    await ValidateCandidate(response.Manifest!, candidate.Entitlements, candidate.Hash, generation, ct).ConfigureAwait(false);
                    Active(); SaveActivation(response.Id, response.Manifest, false, generation, ct);
                    lock (_gate) { Active(); ImportLicense(response.Manifest!); generation = _generation; }
                    var state = await ValidateAsync(ct).ConfigureAwait(false); Active(); Progress("ready", response.Id, 0); return state;
                }
                SaveActivation(response.Id, null, false, generation, ct); Progress("pending", response.Id, response.Retry);
                Active();
                response = await Poll(response.Id).ConfigureAwait(false);
                if (response.Status == "pending") await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, response.Retry)), ct).ConfigureAwait(false);
            }
        }
    }
}
