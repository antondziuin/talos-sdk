using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Talos.Sdk
{
    /// <summary>Configuration for a <see cref="TalosClient"/>.</summary>
    public sealed class TalosOptions
    {
        /// <summary>The product's public token (<c>tpt_…</c>) from the portal.</summary>
        public string ProductToken { get; set; } = "";

        /// <summary>The product's Ed25519 public key, base64 (from the portal).</summary>
        public string PublicKey { get; set; } = "";

        /// <summary>Base URL of the Talos (or self-hosted) server.</summary>
        public string ServerUrl { get; set; } = "";

        /// <summary>Optional app version reported in telemetry/heartbeats.</summary>
        public string? AppVersion { get; set; }

        /// <summary>Optional shared <see cref="System.Net.Http.HttpClient"/>.</summary>
        public HttpClient? HttpClient { get; set; }
    }

    /// <summary>
    /// Online-first Talos client. Every trust decision is a signed token verified
    /// against the pinned product key, so a fake/MITM server cannot forge an
    /// acceptable answer. One instance per product; holds the per-machine
    /// activation secret after <see cref="ActivateAsync"/>.
    /// </summary>
    public sealed class TalosClient
    {
        private readonly TalosOptions _options;
        private readonly HttpClient _http;
        private readonly byte[] _publicKey;
        private readonly string _fingerprint;
        private readonly bool _ownsHttp;

        private string? _licenseKey;
        private string? _activationSecret;
        private string? _machineId;

        public TalosClient(TalosOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            if (string.IsNullOrEmpty(options.ProductToken)) throw new ArgumentException("ProductToken required");
            if (string.IsNullOrEmpty(options.PublicKey)) throw new ArgumentException("PublicKey required");
            if (string.IsNullOrEmpty(options.ServerUrl)) throw new ArgumentException("ServerUrl required");
            _publicKey = Convert.FromBase64String(options.PublicKey);
            if (_publicKey.Length != 32) throw new ArgumentException("PublicKey must decode to 32 bytes");
            _http = options.HttpClient ?? new HttpClient();
            _ownsHttp = options.HttpClient == null;
            _fingerprint = Fingerprint.Compute();
        }

        /// <summary>The last verified license state, if any.</summary>
        public LicenseState? Current { get; private set; }

        /// <summary>Whether a feature is enabled per the last verified state.</summary>
        public bool IsFeatureEnabled(string name) => Current?.IsFeatureEnabled(name) ?? false;

        /// <summary>Activate a license on this machine.</summary>
        public async Task<LicenseState> ActivateAsync(string licenseKey, CancellationToken ct = default)
        {
            string nonce = NewNonce();
            var body = new
            {
                product_token = _options.ProductToken,
                license_key = licenseKey,
                fingerprint = new { composite = _fingerprint, components = new { } },
                nonce,
                os = RuntimeInformation.OSDescription,
                arch = RuntimeInformation.OSArchitecture.ToString(),
                app_version = _options.AppVersion,
                sdk_version = "csharp/0.0.0",
            };
            using var doc = await PostAsync("/v1/client/activate", body, ct).ConfigureAwait(false);
            JsonElement root = doc.RootElement;

            string token = root.GetProperty("activation_token").GetString()!;
            JsonElement claims = TalosCompact.Verify(
                _publicKey, "activation", _options.ProductToken, nonce, token);

            _licenseKey = licenseKey;
            _activationSecret = root.GetProperty("activation_secret").GetString();
            _machineId = root.GetProperty("machine_id").GetString();

            Current = StateFromClaims(claims, "valid");
            return Current;
        }

        /// <summary>Re-validate the license (machine-bound, no seat consumed).</summary>
        public async Task<LicenseState> ValidateAsync(CancellationToken ct = default)
        {
            RequireActivated();
            string nonce = NewNonce();
            var body = new
            {
                product_token = _options.ProductToken,
                license_key = _licenseKey,
                fingerprint = new { composite = _fingerprint, components = new { } },
                activation_secret = _activationSecret,
                nonce,
            };
            using var doc = await PostAsync("/v1/client/validate", body, ct).ConfigureAwait(false);
            string token = doc.RootElement.GetProperty("validation_token").GetString()!;
            JsonElement claims = TalosCompact.Verify(
                _publicKey, "validation", _options.ProductToken, nonce, token);

            string decision = claims.TryGetProperty("decision", out var d) ? d.GetString() ?? "invalid" : "invalid";
            Current = StateFromClaims(claims, decision);
            return Current;
        }

        /// <summary>Release this machine's seat.</summary>
        public async Task DeactivateAsync(CancellationToken ct = default)
        {
            RequireActivated();
            var body = new
            {
                product_token = _options.ProductToken,
                license_key = _licenseKey,
                fingerprint = new { composite = _fingerprint, components = new { } },
                activation_secret = _activationSecret,
            };
            using var _ = await PostAsync("/v1/client/deactivate", body, ct).ConfigureAwait(false);
            Current = null;
            _activationSecret = null;
            _machineId = null;
        }

        private void RequireActivated()
        {
            if (_activationSecret == null || _licenseKey == null)
                throw new TalosException("not activated: call ActivateAsync first");
        }

        private LicenseState StateFromClaims(JsonElement claims, string decision)
        {
            var state = new LicenseState { Decision = decision };
            if (claims.TryGetProperty("lic", out var lic) && lic.ValueKind == JsonValueKind.Object)
            {
                if (lic.TryGetProperty("features", out var feats))
                    state.Features = feats.Clone();
                if (lic.TryGetProperty("lic_exp", out var exp) && exp.ValueKind == JsonValueKind.Number)
                    state.LicenseExpiresAt = exp.GetInt64();
            }
            return state;
        }

        private async Task<JsonDocument> PostAsync(string path, object body, CancellationToken ct)
        {
            string json = JsonSerializer.Serialize(body);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync(_options.ServerUrl.TrimEnd('/') + path, content, ct)
                .ConfigureAwait(false);
            string text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                string? err = TryReadError(text);
                throw new TalosApiException((int)resp.StatusCode, err);
            }
            return string.IsNullOrEmpty(text) ? JsonDocument.Parse("{}") : JsonDocument.Parse(text);
        }

        private static string? TryReadError(string text)
        {
            try
            {
                using var doc = JsonDocument.Parse(text);
                return doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;
            }
            catch
            {
                return null;
            }
        }

        private static string NewNonce()
        {
            byte[] b = new byte[16];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(b);
            return Base64Url.Encode(b);
        }
    }
}
