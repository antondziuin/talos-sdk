using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        /// <summary>
        /// The product's <b>anchor</b> public key, base64 (from the portal's
        /// Integration page). The rotation-safe root: the SDK fetches the
        /// anchor-signed keyset and learns the current license/release keys from
        /// it, so rotating a signing key never breaks a deployed app. Strongly
        /// recommended. If set, <see cref="PublicKey"/> is optional (a fallback).
        /// </summary>
        public string? AnchorPublicKey { get; set; }

        /// <summary>
        /// The product's Ed25519 license public key, base64. A direct pin used to
        /// verify activation/validation tokens when no keyset is loaded. Optional
        /// if <see cref="AnchorPublicKey"/> is set.
        /// </summary>
        public string PublicKey { get; set; } = "";

        /// <summary>
        /// The product's <b>release</b>-signing public key, base64. Direct pin
        /// used to verify update manifests when no keyset is loaded. Falls back to
        /// <see cref="PublicKey"/> when unset.
        /// </summary>
        public string? ReleasePublicKey { get; set; }

        /// <summary>Base URL of the Talos (or self-hosted) server.</summary>
        public string ServerUrl { get; set; } = "";

        /// <summary>Optional app version reported in telemetry/heartbeats.</summary>
        public string? AppVersion { get; set; }

        /// <summary>
        /// The name shown for this seat in the developer's portal. Defaults to
        /// <see cref="Environment.MachineName"/>.
        /// </summary>
        /// <remarks>
        /// Unlike the hostname folded into the fingerprint, this one is stored
        /// and displayed as written — it is what a support agent reads when a
        /// customer says "release the one on my old laptop", and without it
        /// every seat on a licence is an indistinguishable hash prefix. Set it
        /// to <c>""</c> to send nothing if a machine name would be more
        /// identifying than your users expect.
        /// </remarks>
        public string? Hostname { get; set; }

        /// <summary>Optional shared <see cref="System.Net.Http.HttpClient"/>.</summary>
        public HttpClient? HttpClient { get; set; }

        /// <summary>
        /// How long a licensing call may take before it is abandoned, in
        /// milliseconds. Default 10000; <c>0</c> disables it.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <c>HttpClient</c>'s own default is 100 seconds, which is a very long
        /// time to hold a splash screen on the one code path a user cannot
        /// skip. Setting <c>HttpClient.Timeout</c> instead was the alternative,
        /// and it is not available when the client is shared: a
        /// caller-supplied one belongs to the caller, and reaching into it
        /// would change the timeout of every other request their application
        /// makes.
        /// </para>
        /// <para>
        /// It does <b>not</b> apply to <c>DownloadUpdateAsync</c>. A
        /// total-duration cap on a multi-megabyte artifact is a size limit
        /// disguised as a safeguard — the same thirty seconds that is generous
        /// for a licensing call fails every download on a slow connection. That
        /// one is bounded by the manifest's signed size instead.
        /// </para>
        /// </remarks>
        public int? HttpTimeoutMs { get; set; }

        /// <summary>
        /// Extra fingerprint components, merged over the ones the SDK collects.
        /// Use this where the BCL cannot reach the hardware (notably macOS, and
        /// Unity/mobile hosts) and your app can: supply e.g.
        /// <c>{"smbios_uuid", "&lt;value&gt;"}</c> and the server gains the
        /// evidence it needs to keep a seat across a hardware change instead of
        /// forcing a re-activation. Values are hashed like any other component,
        /// so raw identifiers never leave the machine. See
        /// <c>docs/FINGERPRINT.md</c> for the recognised ids and their weights.
        /// </summary>
        public IReadOnlyDictionary<string, string>? ExtraFingerprintComponents { get; set; }

        /// <summary>
        /// Where to keep this machine's activation across restarts. Defaults to
        /// a per-product file under the OS user-data directory (see
        /// <see cref="StateStore.DefaultPath"/>).
        /// </summary>
        public string? StatePath { get; set; }

        /// <summary>
        /// Persist the machine binding (default <c>true</c>).
        /// <para>
        /// Turn it off only for a process that should not leave a licence on
        /// disk — a test, or a short-lived worker. The cost is that every start
        /// must activate again, which rotates the activation secret and is
        /// refused while the tenant is suspended, so a long-lived desktop app
        /// wants this on.
        /// </para>
        /// </summary>
        public bool PersistState { get; set; } = true;
    }

    /// <summary>
    /// Online-first Talos client. Every trust decision is a signed token verified
    /// against the pinned product key, so a fake/MITM server cannot forge an
    /// acceptable answer. One instance per product; holds the per-machine
    /// activation secret after <see cref="ActivateAsync"/>.
    /// </summary>
    public sealed class TalosClient : IDisposable
    {
        /// <summary>
        /// Tolerance for a slow or slightly-off clock, in seconds. Matches the
        /// token verifier's; the point is to be forgiving about drift while
        /// still catching a clock that has been moved.
        /// </summary>
        private const long ClockSkewSeconds = 60;

        /// <summary>
        /// Fallback check-in cadence, used only until the first heartbeat
        /// reports the policy's own. Matches the server's
        /// <c>policies.heartbeat_interval_s</c> default.
        /// </summary>
        private const int DefaultHeartbeatSeconds = 600;

        private readonly TalosOptions _options;
        private readonly HttpClient _http;
        private readonly byte[]? _anchorKey;
        private readonly byte[]? _publicKey;
        private readonly byte[]? _releaseKey;
        private readonly string _fingerprint;
        private readonly FingerprintData _fp;
        private readonly bool _ownsHttp;
        private bool _disposed;

        // Learned from the anchor-signed keyset; take precedence over the pins.
        private List<byte[]> _keysetLicenseKeys = new List<byte[]>();
        private List<byte[]> _keysetReleaseKeys = new List<byte[]>();

        private string? _licenseKey;
        private string? _activationSecret;
        private string? _machineId;
        private readonly StateStore? _store;
        /// <summary>Everything persisted for this product; written back as one file.</summary>
        private StoredBinding? _binding;
        /// <summary>
        /// True while the adopted keyset came off disk. One refresh per process
        /// upgrades it, so a rotation is picked up, but a client that cannot
        /// reach the server keeps verifying with what it already trusts.
        /// </summary>
        private bool _keysetFromCache;

        /// <summary>
        /// The <c>iat</c> of the adopted keyset, unix seconds, or 0 if unknown.
        /// <para>
        /// Kept so a keyset can go stale. Without it the refresh happens once per
        /// process, which is fine for a desktop app that restarts and useless for
        /// a service host that runs for weeks — a signing key revoked in the
        /// portal would never reach it.
        /// </para>
        /// </summary>
        private long _keysetIssuedAt;

        /// <summary>
        /// How long an adopted keyset is trusted before a refresh is attempted:
        /// the upper bound on how long a revoked signing key keeps being accepted
        /// by an install that stays online.
        /// <para>
        /// A day is the trade. Shorter multiplies load on a public endpoint
        /// serving a document that changes about once a year; longer widens the
        /// window in which a compromised key still works.
        /// </para>
        /// </summary>
        private const long KeysetMaxAgeSeconds = 24 * 60 * 60;
        private CancellationTokenSource? _renewCts;
        private CancellationTokenSource? _checkInCts;
        /// <summary>Bumped on release so an in-flight renewal cannot resurrect the seat.</summary>
        private volatile int _leaseGeneration;
        /// <summary>Default instance id for floating leases: one per client object.</summary>
        private readonly string _instanceId = Guid.NewGuid().ToString("N");

        public TalosClient(TalosOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            if (string.IsNullOrEmpty(options.ProductToken)) throw new ArgumentException("ProductToken required");
            if (string.IsNullOrEmpty(options.ServerUrl)) throw new ArgumentException("ServerUrl required");
            if (string.IsNullOrEmpty(options.AnchorPublicKey) && string.IsNullOrEmpty(options.PublicKey))
                throw new ArgumentException("AnchorPublicKey or PublicKey required");
            _anchorKey = Decode32(options.AnchorPublicKey, "AnchorPublicKey");
            _publicKey = Decode32(options.PublicKey, "PublicKey");
            // Direct release pin falls back to the license pin (keyset overrides both).
            _releaseKey = string.IsNullOrEmpty(options.ReleasePublicKey)
                ? _publicKey
                : Decode32(options.ReleasePublicKey, "ReleasePublicKey");
            _http = options.HttpClient ?? new HttpClient();
            _ownsHttp = options.HttpClient == null;
            _fp = Fingerprint.Collect(options.ProductToken, options.ExtraFingerprintComponents);
            _fingerprint = _fp.Composite;

            // Restore the machine binding in the constructor, so a client built
            // at startup is already usable: ValidateAsync works with no
            // ActivateAsync call and no prompt for the licence key.
            _store = options.PersistState
                ? new StateStore(
                    options.StatePath ?? StateStore.DefaultPath(options.ProductToken),
                    options.ProductToken,
                    StateStore.KeyMaterial(_fp.Components))
                : null;
            StoredBinding? stored = _store?.Load();
            if (stored != null)
            {
                _binding = stored;
                _licenseKey = stored.LicenseKey;
                _activationSecret = stored.ActivationSecret;
                _machineId = stored.MachineId;
                // Adopt the cached keyset before anything asks for a
                // verification key. Without it an anchor-only client has nothing
                // to verify a cached decision with, and the offline path is
                // unreachable in exactly the situation it exists for.
                if (!string.IsNullOrEmpty(stored.Keyset))
                {
                    try
                    {
                        AdoptKeyset(stored.Keyset);
                        _keysetFromCache = _keysetLicenseKeys.Count > 0;
                    }
                    catch (TalosException)
                    {
                        // A keyset that no longer verifies under the pinned
                        // anchor is not a startup failure: fetch a fresh one.
                    }
                }

                PromoteDownloadedRelease();
            }
        }

        /// <summary>
        /// A release that was downloaded and is now the version running:
        /// promote its <c>release_seq</c> to the anti-downgrade mark.
        /// </summary>
        /// <remarks>
        /// This is the whole of "the SDK knows what is installed". The SDK
        /// downloads and verifies bytes; the host installs them, its own way,
        /// usually across a restart — so installation is not an event the SDK
        /// can observe. What it can observe is the result, because
        /// <c>AppVersion</c> is the host saying which version it is. When that
        /// equals the version whose bytes were fetched, the download became an
        /// install. Only forward: yanking a release stops it being offered and
        /// must not walk an install that already applied it back onto an older
        /// build.
        /// </remarks>
        private void PromoteDownloadedRelease()
        {
            if (_binding == null) return;
            if (string.IsNullOrEmpty(_binding.PendingVersion)) return;
            if (_binding.PendingVersion != _options.AppVersion) return;
            long mark = Math.Max(_binding.ReleaseSeqHighWater, _binding.PendingReleaseSeq);
            Persist(b =>
            {
                b.ReleaseSeqHighWater = mark;
                b.PendingVersion = null;
                b.PendingReleaseSeq = 0;
            });
        }

        /// <summary>
        /// The <c>release_seq</c> no update may go at or below.
        /// </summary>
        /// <remarks>
        /// The host's explicit value wins when it gives one — it knows things
        /// the SDK cannot, such as a build installed by a package manager — and
        /// the persisted mark is the default that makes anti-downgrade work for
        /// the hosts that give nothing, which is every example and most
        /// applications.
        /// </remarks>
        private long? ReleaseFloor(long? explicitSeq)
        {
            if (explicitSeq is long given) return given;
            long mark = _binding?.ReleaseSeqHighWater ?? 0;
            return mark > 0 ? mark : null;
        }

        /// <summary>
        /// Note which release's bytes are now on disk, so the next start can
        /// tell whether they were installed.
        /// </summary>
        /// <remarks>
        /// Called after the hash check, never before: a download that failed
        /// verification is not a release this install is about to be running,
        /// and recording it would let a corrupt or substituted file raise the
        /// anti-downgrade floor past a good build.
        /// </remarks>
        private void RememberDownloaded(UpdateInfo info)
        {
            if (info.ReleaseSeq <= (_binding?.ReleaseSeqHighWater ?? 0)) return;
            Persist(b =>
            {
                b.PendingVersion = info.Version;
                b.PendingReleaseSeq = info.ReleaseSeq;
            });
        }

        /// <summary>
        /// Whether this machine already holds an activation — restored from disk
        /// on construction, so this is the startup question: prompt for a licence
        /// key, or go straight to <see cref="ValidateAsync"/>?
        /// </summary>
        public bool IsActivated => _activationSecret != null && _licenseKey != null;

        /// <summary>The server's id for this machine, once activated.</summary>
        public string? MachineId => _machineId;

        private static byte[]? Decode32(string? b64, string name)
        {
            if (string.IsNullOrEmpty(b64)) return null;
            byte[] raw = Convert.FromBase64String(b64);
            if (raw.Length != 32) throw new ArgumentException($"{name} must decode to 32 bytes");
            return raw;
        }

        /// <summary>
        /// Fetch and verify the product's keyset (signed by the pinned anchor) and
        /// adopt its current license/release keys. Called automatically during
        /// <see cref="ActivateAsync"/>; call it again after a server-side key
        /// rotation to keep verifying with no config change. No-op without an anchor.
        /// </summary>
        public async Task RefreshKeysetAsync(CancellationToken ct = default)
        {
            if (_anchorKey == null) return;
            var body = new { product_token = _options.ProductToken };
            using var doc = await PostAsync("/v1/client/keyset", body, ct).ConfigureAwait(false);
            if (doc.RootElement.TryGetProperty("keyset", out var ks) && ks.ValueKind == JsonValueKind.String)
            {
                AdoptKeyset(ks.GetString());
                _keysetFromCache = false;
                Persist(b => b.Keyset = ks.GetString());
            }
        }

        /// <summary>
        /// Make sure a verification key exists before a response has to be
        /// verified.
        /// <para>
        /// A restored binding goes straight to Validate, skipping Activate —
        /// which is the only place the keyset used to be adopted. An anchor-only
        /// client (the recommended pinning, and the one that survives key
        /// rotation) therefore had nothing to verify with on the app's
        /// <i>second</i> launch, and every call failed with "keyset
        /// unavailable". Only persistence made that reachable: before it,
        /// Activate always ran first.
        /// </para>
        /// <para>
        /// Fetching it lazily rather than storing it also keeps trust material
        /// out of the state file: the keys are re-derived from the pinned anchor
        /// once per process and never cached across one.
        /// </para>
        /// </summary>
        private async Task EnsureKeysetAsync(CancellationToken ct)
        {
            if (_anchorKey == null) return;
            if (_keysetLicenseKeys.Count > 0 && !_keysetFromCache && !KeysetIsStale()) return;
            try
            {
                await RefreshKeysetAsync(ct).ConfigureAwait(false);
            }
            catch when (_keysetLicenseKeys.Count > 0)
            {
                // A refresh that cannot reach the server must not break a client
                // that already has keys it trusts: that turns a network problem
                // into a licensing failure, which is the one outcome the whole
                // grace design exists to avoid. With nothing adopted at all there
                // is no fallback, and the exception is the caller's to see.
            }
        }

        /// <summary>
        /// Whether the adopted keyset is old enough to be worth re-fetching.
        /// <para>
        /// This is what makes revoking a compromised signing key mean anything to
        /// an install: a revoked key is omitted from the keyset, so a client only
        /// stops trusting it once it fetches a newer one. Refreshing only on the
        /// first call of a process bounds that by "next restart", which for a
        /// long-running host is not a bound at all.
        /// </para>
        /// </summary>
        private bool KeysetIsStale()
        {
            if (_keysetIssuedAt == 0) return true;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return now - _keysetIssuedAt > KeysetMaxAgeSeconds;
        }

        private void AdoptKeyset(string? token)
        {
            if (_anchorKey == null || string.IsNullOrEmpty(token)) return;
            JsonElement claims = TalosCompact.VerifyKeyset(_anchorKey, _options.ProductToken, token!);
            // From the signed claims, not from a local clock reading taken when
            // the fetch happened: a client whose clock is wrong would otherwise
            // decide its keyset is fresh forever, or refetch on every call.
            _keysetIssuedAt = claims.TryGetProperty("iat", out var iat)
                && iat.ValueKind == JsonValueKind.Number
                && iat.TryGetInt64(out long v)
                ? v
                : 0;
            var licenseKeys = new List<byte[]>();
            var releaseKeys = new List<byte[]>();
            if (claims.TryGetProperty("keys", out var keys) && keys.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in keys.EnumerateArray())
                {
                    string? pk = GetStr(entry, "pk");
                    string? purpose = GetStr(entry, "purpose");
                    if (pk == null) continue;
                    byte[] raw = Convert.FromBase64String(pk);
                    if (raw.Length != 32) continue;
                    if (purpose == "license") licenseKeys.Add(raw);
                    else if (purpose == "release") releaseKeys.Add(raw);
                }
            }
            _keysetLicenseKeys = licenseKeys;
            _keysetReleaseKeys = releaseKeys;
        }

        private IReadOnlyList<byte[]> LicenseVerifyKeys()
        {
            if (_keysetLicenseKeys.Count > 0) return _keysetLicenseKeys;
            if (_publicKey != null) return new[] { _publicKey };
            throw new TalosSignatureException("no license verification key (keyset unavailable)");
        }

        private IReadOnlyList<byte[]> ReleaseVerifyKeys()
        {
            if (_keysetReleaseKeys.Count > 0) return _keysetReleaseKeys;
            if (_releaseKey != null) return new[] { _releaseKey };
            throw new TalosSignatureException("no release verification key (keyset unavailable)");
        }

        /// <summary>The last verified license state, if any.</summary>
        public LicenseState? Current { get; private set; }

        /// <summary>Whether a feature is enabled per the last verified state.</summary>
        public bool IsFeatureEnabled(string name) => Current?.IsFeatureEnabled(name) ?? false;

        /// <summary>
        /// Ensure this machine is activated on <paramref name="licenseKey"/>, and
        /// return the verified state. Safe to call on every start.
        /// <para>
        /// When a binding for the same key is already held, this
        /// <b>re-validates</b> instead of re-activating. Same one round trip,
        /// three different outcomes: the activation secret is not rotated (so a
        /// second copy of the app on the same machine does not knock the first
        /// one out), no seat accounting is touched, and — because activate is the
        /// only client route refused for a suspended tenant — the developer's own
        /// paying users keep working while their vendor's account is suspended,
        /// which is what "graduated suspension" was supposed to mean.
        /// </para>
        /// <para>
        /// It falls back to a real activation when the stored binding is no
        /// longer usable: the seat was released from the portal, or the secret
        /// was rotated elsewhere.
        /// </para>
        /// </summary>
        public async Task<LicenseState> ActivateAsync(string licenseKey, CancellationToken ct = default)
        {
            if (IsActivated && _licenseKey == licenseKey)
            {
                try
                {
                    LicenseState state = await ValidateAsync(ct).ConfigureAwait(false);
                    // `deactivated` means the developer released the seat; taking
                    // it again is exactly what re-activating is for. Every other
                    // verdict — including machine_revoked — is the server's
                    // answer, and re-activating would only replace it with a less
                    // specific error.
                    if (state.Decision != "deactivated") return state;
                }
                catch (TalosApiException e) when (e.StatusCode == 401 || e.StatusCode == 404)
                {
                    // 401: the secret was rotated elsewhere. 404: the machine (or
                    // licence) is gone. Anything else is a real failure and must
                    // not be papered over by silently spending a seat.
                }
                ForgetBinding();
            }

            string nonce = NewNonce();
            var body = new
            {
                product_token = _options.ProductToken,
                license_key = licenseKey,
                fingerprint = new { composite = _fingerprint, components = _fp.Components },
                nonce,
                hostname = ReportedHostname(),
                os = RuntimeInformation.OSDescription,
                arch = RuntimeInformation.OSArchitecture.ToString(),
                app_version = _options.AppVersion,
                sdk_version = SdkVersion.Id,
            };
            using var doc = await PostAsync("/v1/client/activate", body, ct).ConfigureAwait(false);
            JsonElement root = doc.RootElement;

            // Adopt the keyset delivered with activation, then verify against the
            // current license keys (so a rotated key still works).
            if (root.TryGetProperty("keyset", out var ks) && ks.ValueKind == JsonValueKind.String)
                AdoptKeyset(ks.GetString());
            string token = root.GetProperty("activation_token").GetString()!;
            JsonElement claims = TalosCompact.Verify(
                LicenseVerifyKeys(), "activation", _options.ProductToken, nonce, token);

            _licenseKey = licenseKey;
            _activationSecret = root.GetProperty("activation_secret").GetString();
            _machineId = root.GetProperty("machine_id").GetString();
            _binding = new StoredBinding
            {
                LicenseKey = licenseKey,
                ActivationSecret = _activationSecret ?? "",
                MachineId = _machineId ?? "",
                Fingerprint = _fingerprint,
                // A fresh activation invalidates any cached verdict for the
                // previous binding; keep only the keyset, which is per product,
                // not per machine.
                Keyset = ks.ValueKind == JsonValueKind.String ? ks.GetString() : _binding?.Keyset,
                TimeHighWater = _binding?.TimeHighWater ?? 0,
            };
            AdvanceClock(claims);
            _store?.Save(_binding);

            Current = StateFromClaims(claims, "valid", false);
            return Current;
        }

        /// <summary>
        /// The heartbeat cadence the server's policy asks for, in seconds, taken
        /// from the last heartbeat's <b>signed</b> claims — so it cannot be
        /// lengthened in transit by anyone wanting a fleet to check in less
        /// often. Null until the first heartbeat of this process.
        /// </summary>
        public int? HeartbeatIntervalSeconds { get; private set; }

        /// <summary>
        /// Run the check-ins the server's policy asks for, in the background.
        /// <para>
        /// Two knobs have existed on the wire since Phase 1 and reached no
        /// client: <c>heartbeat_interval_s</c> (how often an install reports in
        /// — the telemetry rate, and the upper bound on how long a revocation
        /// takes to arrive) and <c>reval_after</c> (when the entitlement bag and
        /// the offline cache should be refreshed). Both are signed. This loop is
        /// what makes them a lever the developer can actually pull: change the
        /// policy, and deployed apps follow.
        /// </para>
        /// <para>
        /// One loop serves both. Each tick re-validates if the signed
        /// <c>reval_after</c> has passed, and otherwise sends a heartbeat —
        /// which is also what renews the cached verdict that
        /// <see cref="ValidateAsync"/> falls back on, so an app that runs this
        /// stays inside its grace window with no scheduling of its own.
        /// </para>
        /// <para>Opt-in, and idempotent: calling it again replaces the loop.</para>
        /// </summary>
        public void StartCheckIns(
            Action<LicenseState>? onState = null, Action<Exception>? onError = null)
        {
            StopCheckIns();
            var cts = new CancellationTokenSource();
            _checkInCts = cts;
            CancellationToken token = cts.Token;
            _ = Task.Run(async () =>
            {
                try
                {
                    while (!token.IsCancellationRequested)
                    {
                        int secs = Math.Max(60, HeartbeatIntervalSeconds ?? DefaultHeartbeatSeconds);
                        await Task.Delay(TimeSpan.FromSeconds(secs), token).ConfigureAwait(false);
                        if (token.IsCancellationRequested) return;
                        try
                        {
                            long? due = Current?.RevalidateAfter;
                            LicenseState state =
                                due == null || DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= due.Value
                                    ? await ValidateAsync(token).ConfigureAwait(false)
                                    : await HeartbeatAsync(token).ConfigureAwait(false);
                            onState?.Invoke(state);
                        }
                        catch (OperationCanceledException) when (token.IsCancellationRequested)
                        {
                            return;
                        }
                        catch (Exception ex)
                        {
                            // Report and keep going: a network outage must not
                            // silently end the loop, or the app would never
                            // notice the connection coming back.
                            onError?.Invoke(ex);
                        }
                    }
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    // Stopped — nothing to report.
                }
                finally
                {
                    if (ReferenceEquals(_checkInCts, cts)) _checkInCts = null;
                    cts.Dispose();
                }
            });
        }

        /// <summary>Stop the background check-ins started by <see cref="StartCheckIns"/>.</summary>
        public void StopCheckIns()
        {
            // Cancel but do NOT dispose here — the loop disposes its own CTS.
            _checkInCts?.Cancel();
            _checkInCts = null;
        }

        /// <summary>
        /// Stop the background loops and release the <see cref="HttpClient"/>
        /// this client created for itself.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The field recording whether the client owns its <c>HttpClient</c>
        /// has existed since the constructor did, read by nothing: the disposal
        /// it was declared for was never written. So the documented quickstart
        /// shape — construct a client without supplying one — leaked a
        /// socket-holding <c>HttpClient</c> per instance, and
        /// <c>using (var talos = new TalosClient(...))</c> did not compile. A
        /// host that builds one per product or reloads plugins accumulates them
        /// until it runs out of ports.
        /// </para>
        /// <para>
        /// A supplied <c>HttpClient</c> is left alone: the caller owns it, very
        /// likely shares it, and disposing someone else's is a worse bug than
        /// leaking your own. Idempotent, so a <c>using</c> block around an
        /// explicit dispose is safe.
        /// </para>
        /// </remarks>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            // Cancel before disposing: the loops own their CTS objects and
            // observe cancellation to unwind, so cancelling is what actually
            // stops them.
            StopRenew();
            StopCheckIns();
            if (_ownsHttp) _http.Dispose();
        }

        /// <summary>Drop the machine binding, in memory and on disk.</summary>
        private void ForgetBinding()
        {
            _licenseKey = null;
            _activationSecret = null;
            _machineId = null;
            Current = null;
            _binding = null;
            _store?.Clear();
        }

        /// <summary>Mutate the persisted binding and write it back.</summary>
        private void Persist(Action<StoredBinding> patch)
        {
            if (_store == null || _binding == null) return;
            patch(_binding);
            _store.Save(_binding);
        }

        /// <summary>
        /// Advance the server-time high-water mark from a signed claim.
        /// <para>
        /// Only ever forward: this is the mark that keeps offline grace bounded
        /// when the user owns the clock. <c>iat</c> is used when a token carries
        /// no explicit <c>server_time</c> (activation does not) — both are the
        /// server's clock, signed.
        /// </para>
        /// </summary>
        private void AdvanceClock(JsonElement claims)
        {
            long? seen = Num(claims, "server_time") ?? Num(claims, "iat");
            if (seen == null || _binding == null) return;
            if (seen.Value > _binding.TimeHighWater) _binding.TimeHighWater = seen.Value;
        }

        private static long? Num(JsonElement o, string name) =>
            o.ValueKind == JsonValueKind.Object
            && o.TryGetProperty(name, out var v)
            && v.ValueKind == JsonValueKind.Number
            && v.TryGetInt64(out long n)
                ? n
                : (long?)null;

        /// <summary>
        /// Re-validate the license (machine-bound, no seat consumed).
        /// <para>
        /// Online-first, and offline-tolerant: if the server cannot be reached
        /// the last verified verdict is honoured until the policy's
        /// <c>grace_until</c>, so a laptop on a plane keeps working. An HTTP
        /// status is an <i>answer</i> and is never masked by the cache.
        /// </para>
        /// </summary>
        public async Task<LicenseState> ValidateAsync(CancellationToken ct = default)
        {
            RequireActivated();
            try
            {
                await EnsureKeysetAsync(ct).ConfigureAwait(false);
                string nonce = NewNonce();
                var body = new
                {
                    product_token = _options.ProductToken,
                    license_key = _licenseKey,
                    fingerprint = new { composite = _fingerprint, components = _fp.Components },
                    activation_secret = _activationSecret,
                    nonce,
                    // Sent here as well as on activation and heartbeat, because
                    // check-ins are opt-in and this call is not: an application
                    // that validates on launch and never starts them would
                    // otherwise show, forever, whatever version it activated on.
                    app_version = _options.AppVersion,
                    sdk_version = SdkVersion.Id,
                };
                using var doc = await PostAsync("/v1/client/validate", body, ct).ConfigureAwait(false);
                string token = doc.RootElement.GetProperty("validation_token").GetString()!;
                JsonElement claims = TalosCompact.Verify(
                    LicenseVerifyKeys(), "validation", _options.ProductToken, nonce, token);

                string decision = claims.TryGetProperty("decision", out var d)
                    ? d.GetString() ?? "invalid"
                    : "invalid";
                AdvanceClock(claims);
                Persist(b => b.Validation = token);
                Current = StateFromClaims(claims, decision, false);
                return Current;
            }
            catch (Exception e) when (!(e is TalosApiException) && !(e is OperationCanceledException))
            {
                // An HTTP status is an *answer* — "revoked", "no such machine",
                // "tenant suspended". Honouring a cached verdict over one would
                // turn every negative answer into hours of grace, which is the
                // opposite of what grace is for. Only the absence of an answer
                // falls back: a dead network, or a response that fails
                // verification (a garbled or forged reply tells us nothing, so
                // per the trust model it is treated as unreachable, never as
                // valid). A cancellation is the caller's decision, not the
                // network's, so it propagates untouched.
                LicenseState? offline = OfflineDecision();
                if (offline == null) throw;
                Current = offline;
                return offline;
            }
        }

        /// <summary>
        /// The verdict from the local cache, or null when there is nothing
        /// usable.
        /// <para>
        /// This is the whole offline story, and every check here is
        /// load-bearing: the token is re-verified under the pinned key, so a
        /// cache edited on disk is worthless; <c>fph</c> must be this machine,
        /// so copying a state file to a second computer and pulling the network
        /// cable does not licence it; <c>grace_until</c> — the policy's
        /// <c>offline_grace_hours</c>, signed — bounds how long a verdict may
        /// outlive its issuance; the licence's own expiry is re-checked, because
        /// a cached "valid" must not outlive the subscription it was issued
        /// under; and the clock is checked against a mark that only moves
        /// forward, since every deadline above is evaluated against a clock the
        /// user controls.
        /// </para>
        /// </summary>
        private LicenseState? OfflineDecision()
        {
            string? token = _binding?.Validation;
            if (string.IsNullOrEmpty(token)) return null;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            long highWater = _binding!.TimeHighWater;
            if (highWater > 0 && now + ClockSkewSeconds < highWater)
            {
                // Distinct from "expired": nothing has run out, the machine is
                // lying about the time. Say so, rather than reporting a licence
                // problem the user cannot act on.
                return new LicenseState { Decision = "clock_tampered", IsOffline = true };
            }

            JsonElement claims;
            try
            {
                claims = TalosCompact.VerifyCached(
                    LicenseVerifyKeys(), "validation", _options.ProductToken, token!);
            }
            catch (TalosException)
            {
                return null;
            }
            if (GetStr(claims, "fph") != _fingerprint) return null;

            long? graceUntil = Num(claims, "grace_until");
            string decision = GetStr(claims, "decision") ?? "invalid";
            LicenseState cached = StateFromClaims(claims, decision, true);
            if (graceUntil == null || now > graceUntil.Value)
            {
                cached.Decision = "grace_expired";
                return cached;
            }
            if (cached.LicenseExpiresAt != null && now > cached.LicenseExpiresAt.Value)
            {
                cached.Decision = "expired";
            }
            return cached;
        }

        /// <summary>
        /// Send a heartbeat: refreshes this machine's last-seen state, feeds the
        /// developer's monitoring (version adoption / active installs), and
        /// returns the current signed decision — so a revocation reaches the app
        /// within one heartbeat interval. Call periodically while the app runs.
        /// The response is a signed <c>typ=heartbeat</c> token, so a MITM cannot
        /// forge the status or lengthen the interval.
        /// </summary>
        public async Task<LicenseState> HeartbeatAsync(CancellationToken ct = default)
        {
            RequireActivated();
            await EnsureKeysetAsync(ct).ConfigureAwait(false);
            string nonce = NewNonce();
            var body = new
            {
                product_token = _options.ProductToken,
                license_key = _licenseKey,
                fingerprint = new { composite = _fingerprint, components = _fp.Components },
                activation_secret = _activationSecret,
                nonce,
                app_version = _options.AppVersion,
                os = RuntimeInformation.OSDescription,
                arch = RuntimeInformation.OSArchitecture.ToString(),
                sdk_version = SdkVersion.Id,
            };
            using var doc = await PostAsync("/v1/client/heartbeat", body, ct).ConfigureAwait(false);
            JsonElement claims = TalosCompact.Verify(
                LicenseVerifyKeys(), "heartbeat", _options.ProductToken, nonce,
                doc.RootElement.GetProperty("heartbeat_token").GetString()!);

            string decision = GetStr(claims, "decision") ?? "invalid";
            // The cadence comes from the SIGNED claims, never the response
            // envelope: the whole point of signing it is that nobody in the
            // middle can tell a fleet to check in less often.
            long? interval = Num(claims, "heartbeat_interval_s");
            if (interval != null && interval.Value > 0)
                HeartbeatIntervalSeconds = (int)interval.Value;
            // Every signed server clock we see pushes the high-water mark
            // forward, not just validation's — a heartbeat is the most frequent
            // call there is.
            AdvanceClock(claims);
            Persist(_ => { });
            // A heartbeat carries the decision but not the entitlement bag; keep
            // the features from the last activate/validate.
            Current = new LicenseState
            {
                Decision = decision,
                Features = Current?.Features ?? default,
                LicenseExpiresAt = Current?.LicenseExpiresAt,
                RevalidateAfter = Current?.RevalidateAfter,
                GraceUntil = Current?.GraceUntil,
            };
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
                fingerprint = new { composite = _fingerprint, components = _fp.Components },
                activation_secret = _activationSecret,
            };
            using var _ = await PostAsync("/v1/client/deactivate", body, ct).ConfigureAwait(false);
            ForgetBinding();
        }

        /// <summary>
        /// Acquire a floating seat (concurrent-use license). The server arbitrates
        /// the cap atomically, so this either returns a seat or throws
        /// <see cref="TalosApiException"/> with <c>seat_limit_reached</c> (409).
        /// The seat is auto-renewed in the background unless disabled; always
        /// <see cref="ReleaseLeaseAsync"/> on clean exit (a crash lets it expire).
        /// </summary>
        public async Task<Lease> AcquireLeaseAsync(
            AcquireLeaseOptions? opts = null, CancellationToken ct = default)
        {
            RequireActivated();
            await EnsureKeysetAsync(ct).ConfigureAwait(false);
            opts ??= new AcquireLeaseOptions();
            string instanceId = opts.InstanceId ?? _instanceId;
            // Snapshot the generation: if ReleaseLeaseAsync runs while this request
            // is in flight, we must not adopt the seat we just took.
            int generation = _leaseGeneration;
            string nonce = NewNonce();
            var body = new
            {
                product_token = _options.ProductToken,
                license_key = _licenseKey,
                fingerprint = new { composite = _fingerprint, components = _fp.Components },
                activation_secret = _activationSecret,
                instance_id = instanceId,
                nonce,
            };
            using var doc = await PostAsync("/v1/client/leases", body, ct).ConfigureAwait(false);
            JsonElement root = doc.RootElement;

            // The lease token is signed: a MITM cannot fabricate a seat.
            JsonElement claims = TalosCompact.Verify(
                LicenseVerifyKeys(), "lease", _options.ProductToken, nonce,
                root.GetProperty("lease_token").GetString()!);

            // The signed grant must be for the instance and machine we asked
            // about — otherwise a server could hand every process one seat's token.
            if (GetStr(claims, "inst") != instanceId || GetStr(claims, "fph") != _fingerprint)
                throw new TalosSignatureException("lease token does not match this instance");

            // Seat facts come from the SIGNED claims, never the unsigned envelope,
            // so a MITM cannot misreport occupancy. `renew_after_s` is only a
            // scheduling hint; the budget comes from the token's OWN clock
            // (exp vs server_time) so a wrong local clock cannot collapse the
            // renew loop into a tight retry storm.
            long expiresAt = claims.TryGetProperty("exp", out var e) && e.ValueKind == JsonValueKind.Number
                ? e.GetInt64() : 0;
            long serverNow = claims.TryGetProperty("server_time", out var st) && st.ValueKind == JsonValueKind.Number
                ? st.GetInt64() : DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long budget = Math.Max(1, expiresAt - serverNow);
            int hinted = root.TryGetProperty("renew_after_s", out var r) && r.ValueKind == JsonValueKind.Number
                ? r.GetInt32() : 0;
            var lease = new Lease
            {
                Id = GetStr(claims, "lease") ?? "",
                InstanceId = instanceId,
                ExpiresAt = expiresAt,
                RenewAfterSeconds = hinted > 0 && hinted <= budget
                    ? hinted
                    : (int)Math.Max(1, budget / 3),
                SeatsInUse = claims.TryGetProperty("seats_in_use", out var s) && s.ValueKind == JsonValueKind.Number
                    ? s.GetInt64() : 0,
                MaxSeats = claims.TryGetProperty("max_seats", out var m) && m.ValueKind == JsonValueKind.Number
                    ? m.GetInt32() : 0,
            };

            if (generation != _leaseGeneration)
            {
                // Released while this was in flight: hand the seat back rather
                // than holding it to TTL, and never re-adopt it locally.
                _ = ReleaseInstanceAsync(instanceId, CancellationToken.None);
                return lease;
            }
            CurrentLease = lease;

            if (opts.AutoRenew) StartRenew(opts);
            return lease;
        }

        /// <summary>Best-effort release of one instance's seat (stale-renewal cleanup).</summary>
        private async Task ReleaseInstanceAsync(string instanceId, CancellationToken ct)
        {
            if (_activationSecret == null || _licenseKey == null) return;
            var body = new
            {
                product_token = _options.ProductToken,
                license_key = _licenseKey,
                fingerprint = new { composite = _fingerprint, components = _fp.Components },
                activation_secret = _activationSecret,
                instance_id = instanceId,
            };
            try
            {
                using var _ = await SendAsync(HttpMethod.Delete, "/v1/client/leases", body, ct)
                    .ConfigureAwait(false);
            }
            catch
            {
                // Best effort — the seat expires on its own if this cannot land.
            }
        }

        /// <summary>The currently held floating seat, if any.</summary>
        public Lease? CurrentLease { get; private set; }

        /// <summary>Release the floating seat (clean exit) and stop auto-renewal.</summary>
        public async Task ReleaseLeaseAsync(CancellationToken ct = default)
        {
            // Bump the generation FIRST so an in-flight renewal cannot resurrect
            // the seat after we release it.
            _leaseGeneration++;
            StopRenew();
            Lease? lease = CurrentLease;
            CurrentLease = null;
            if (lease == null) return;
            await ReleaseInstanceAsync(lease.InstanceId, ct).ConfigureAwait(false);
        }

        private void StartRenew(AcquireLeaseOptions opts)
        {
            StopRenew();
            var cts = new CancellationTokenSource();
            _renewCts = cts;
            // Capture the token once: StopRenew must never dispose a CTS this
            // task is still reading (that would raise ObjectDisposedException
            // and surface a clean release as a spurious OnLeaseLost).
            CancellationToken token = cts.Token;
            int generation = _leaseGeneration;
            _ = Task.Run(async () =>
            {
                try
                {
                    while (!token.IsCancellationRequested)
                    {
                        int delay = Math.Max(1, CurrentLease?.RenewAfterSeconds ?? 200);
                        await Task.Delay(TimeSpan.FromSeconds(delay), token).ConfigureAwait(false);
                        if (token.IsCancellationRequested || generation != _leaseGeneration) return;
                        await AcquireLeaseAsync(
                            new AcquireLeaseOptions
                            {
                                InstanceId = CurrentLease?.InstanceId ?? _instanceId,
                                AutoRenew = false,
                            },
                            token).ConfigureAwait(false);
                    }
                }
                // ONLY our own cancellation is benign. An HttpClient timeout also
                // raises TaskCanceledException; treating that as "released" would
                // stop renewing silently and let the seat lapse while the app runs.
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    // Released or disposed — nothing to report.
                }
                catch (Exception ex)
                {
                    if (generation != _leaseGeneration) return;
                    CurrentLease = null;
                    opts.OnLeaseLost?.Invoke(ex.Message);
                }
                finally
                {
                    // Dispose from the task that owns it, and only if it is still
                    // the current one.
                    if (ReferenceEquals(_renewCts, cts)) _renewCts = null;
                    cts.Dispose();
                }
            });
        }

        private void StopRenew()
        {
            // Cancel but do NOT dispose here — the renew task disposes its own CTS.
            _renewCts?.Cancel();
            _renewCts = null;
        }

        /// <summary>
        /// Ask whether a newer release is available. Returns a verified
        /// <see cref="UpdateInfo"/> (all metadata from the manifest signed by the
        /// pinned release key), or <c>null</c> when up to date. Enforces
        /// anti-downgrade: a manifest whose <c>release_seq</c> is at or below
        /// <see cref="CheckForUpdateOptions.CurrentReleaseSeq"/> is treated as no update.
        /// </summary>
        public async Task<UpdateInfo?> CheckForUpdateAsync(
            CheckForUpdateOptions? opts = null, CancellationToken ct = default)
        {
            RequireActivated();
            await EnsureKeysetAsync(ct).ConfigureAwait(false);
            opts ??= new CheckForUpdateOptions();
            var body = new
            {
                product_token = _options.ProductToken,
                license_key = _licenseKey,
                fingerprint = new { composite = _fingerprint, components = _fp.Components },
                activation_secret = _activationSecret,
                current_version = opts.CurrentVersion ?? _options.AppVersion,
                current_release_seq = ReleaseFloor(opts.CurrentReleaseSeq),
                channel = opts.Channel,
            };
            using var doc = await PostAsync("/v1/client/updates/check", body, ct).ConfigureAwait(false);
            JsonElement root = doc.RootElement;
            if (!root.TryGetProperty("update_available", out var ua) || ua.ValueKind != JsonValueKind.True)
                return null;

            string manifest = root.GetProperty("manifest").GetString()
                ?? throw new TalosSignatureException("update available but no manifest");
            // Trust only the signed manifest for version/seq/artifact metadata.
            JsonElement m = TalosCompact.VerifyManifest(ReleaseVerifyKeys(), _options.ProductToken, manifest);

            long releaseSeq = m.TryGetProperty("release_seq", out var rs) && rs.ValueKind == JsonValueKind.Number
                ? rs.GetInt64() : 0;
            // Anti-downgrade, checked here as well as on the server: the
            // server's answer is the one an attacker replaces, and this one is
            // checked against a mark on this machine and a manifest signed by
            // the pinned key.
            if (ReleaseFloor(opts.CurrentReleaseSeq) is long cur && releaseSeq <= cur)
                return null; // anti-downgrade: never surface an older-or-equal manifest.

            // Untrusted transport map: platform/arch/kind → download path.
            var downloads = new Dictionary<string, string>();
            if (root.TryGetProperty("artifacts", out var respArts) && respArts.ValueKind == JsonValueKind.Array)
            {
                foreach (var d in respArts.EnumerateArray())
                {
                    string? path = GetStr(d, "download_path");
                    if (path != null)
                        downloads[SelKey(GetStr(d, "platform"), GetStr(d, "arch"), GetStr(d, "kind"))] = path;
                }
            }

            var artifacts = new List<UpdateArtifact>();
            if (m.TryGetProperty("artifacts", out var manArts) && manArts.ValueKind == JsonValueKind.Array)
            {
                foreach (var a in manArts.EnumerateArray())
                {
                    string platform = GetStr(a, "platform") ?? "";
                    string arch = GetStr(a, "arch") ?? "";
                    string kind = GetStr(a, "kind") ?? "";
                    downloads.TryGetValue(SelKey(platform, arch, kind), out var dp);
                    artifacts.Add(new UpdateArtifact
                    {
                        Platform = platform,
                        Arch = arch,
                        Kind = kind,
                        Filename = GetStr(a, "filename") ?? "",
                        Size = a.TryGetProperty("size", out var sz) && sz.ValueKind == JsonValueKind.Number ? sz.GetInt64() : 0,
                        Sha256 = GetStr(a, "sha256") ?? "",
                        DownloadPath = dp,
                    });
                }
            }

            // Patches, keyed by what distinguishes them from each other: the
            // version they apply to and the file they rebuild. A release that
            // supports upgrading from three versions and ships two files carries six.
            var deltaPaths = new Dictionary<string, string>();
            if (root.TryGetProperty("deltas", out var respDeltas) && respDeltas.ValueKind == JsonValueKind.Array)
            {
                foreach (var d in respDeltas.EnumerateArray())
                {
                    string? path = GetStr(d, "download_path");
                    if (path != null)
                        deltaPaths[DeltaKey(GetStr(d, "platform"), GetStr(d, "arch"), GetStr(d, "from"), GetStr(d, "target_kind"))] = path;
                }
            }

            var deltas = new List<UpdateDelta>();
            if (m.TryGetProperty("deltas", out var manDeltas) && manDeltas.ValueKind == JsonValueKind.Array)
            {
                foreach (var d in manDeltas.EnumerateArray())
                {
                    string platform = GetStr(d, "platform") ?? "";
                    string arch = GetStr(d, "arch") ?? "";
                    string from = GetStr(d, "from") ?? "";
                    JsonElement t = d.TryGetProperty("target", out var tv) ? tv : default;
                    string targetKind = GetStr(t, "kind") ?? "";
                    deltaPaths.TryGetValue(DeltaKey(platform, arch, from, targetKind), out var dp);
                    deltas.Add(new UpdateDelta
                    {
                        Platform = platform,
                        Arch = arch,
                        From = from,
                        FromSeq = GetLong(d, "from_seq"),
                        Filename = GetStr(d, "filename") ?? "",
                        Size = GetLong(d, "size"),
                        Sha256 = GetStr(d, "sha256") ?? "",
                        Target = new UpdateDeltaTarget
                        {
                            Kind = targetKind,
                            Filename = GetStr(t, "filename") ?? "",
                            Size = GetLong(t, "size"),
                            Sha256 = GetStr(t, "sha256") ?? "",
                        },
                        DownloadPath = dp,
                    });
                }
            }

            return new UpdateInfo
            {
                Version = GetStr(m, "version") ?? "",
                ReleaseSeq = releaseSeq,
                Mandatory = m.TryGetProperty("mandatory", out var md) && md.ValueKind == JsonValueKind.True,
                NotesUrl = GetStr(m, "notes_url"),
                Artifacts = artifacts,
                Deltas = deltas,
            };
        }

        /// <summary>
        /// The patch that upgrades this machine, or <c>null</c> if there is none.
        /// </summary>
        /// <remarks>
        /// Matches on the <b>exact</b> published version string, not on version
        /// ordering: a patch applies to the bytes it was built against, and "close
        /// enough" produces a corrupt file rather than an error. A machine whose
        /// installed version is not one the release ships a patch from simply
        /// downloads the full build.
        /// <para>
        /// <paramref name="targetKind"/> picks which shipped file to rebuild when a
        /// release carries patches for several. With more than one candidate and no
        /// kind given this returns <c>null</c> rather than guessing — choosing
        /// wrongly would download megabytes and rebuild a file the host was not
        /// updating.
        /// </para>
        /// </remarks>
        public UpdateDelta? SelectDelta(UpdateInfo info, string? from = null, string? targetKind = null)
        {
            string? want = from ?? _options.AppVersion;
            if (string.IsNullOrEmpty(want)) return null;
            var (platform, arch) = HostTarget();
            var matches = info.Deltas
                .Where(d => d.Platform == platform && d.Arch == arch && d.From == want)
                .ToList();
            if (!string.IsNullOrEmpty(targetKind))
                return matches.FirstOrDefault(d => d.Target.Kind == targetKind);
            return matches.Count == 1 ? matches[0] : null;
        }

        /// <summary>
        /// Download a patch and verify its bytes against the manifest's SHA-256,
        /// then write it to <paramref name="destPath"/>. Returns the patch, whose
        /// <c>Target.Sha256</c> is what the rebuilt file must hash to.
        /// </summary>
        /// <remarks>
        /// Does NOT apply it. Applying is the host's job — and so is checking the
        /// result, which <see cref="VerifyAppliedUpdate"/> does. A patch verified on
        /// the way in and a result nobody checks is a signed chain that stops one
        /// step short of the binary that runs.
        /// </remarks>
        public async Task<UpdateDelta> DownloadDeltaAsync(
            UpdateInfo info, string destPath, UpdateDelta? delta = null,
            string? from = null, string? targetKind = null, CancellationToken ct = default)
        {
            RequireActivated();
            UpdateDelta? chosen = delta ?? SelectDelta(info, from, targetKind);
            if (chosen == null) throw new TalosException("no patch applies to this install");
            await FetchVerifiedAsync(chosen.DownloadPath, chosen.Size, chosen.Sha256, destPath, ct)
                .ConfigureAwait(false);
            RememberDownloaded(info);
            return chosen;
        }

        /// <summary>
        /// Check that applying a patch produced the file the signed manifest said
        /// it would. Throws <see cref="TalosSignatureException"/> if not.
        /// </summary>
        /// <remarks>
        /// This is the last link in the chain and the easiest one to leave out. The
        /// patch itself was verified on the way in, but a patcher can fail halfway,
        /// apply to the wrong base file, or be handed bytes from somewhere else
        /// entirely — and every one of those produces a file that nothing has
        /// vouched for. Hashes the file as a stream, so a multi-gigabyte install is
        /// not brought into memory.
        /// <para>
        /// Static, and needs no licence or activation: run it from the updater
        /// process, after the application it belongs to has exited.
        /// </para>
        /// </remarks>
        public static void VerifyAppliedUpdate(string filePath, UpdateDelta delta)
        {
            string actual;
            using (var sha = SHA256.Create())
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] hash = sha.ComputeHash(fs);
                var sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash) sb.Append(b.ToString("x2"));
                actual = sb.ToString();
            }
            if (!string.Equals(actual, delta.Target.Sha256, StringComparison.Ordinal))
                throw new TalosSignatureException(
                    "applied update does not match the signed manifest: expected "
                    + delta.Target.Sha256 + ", got " + actual);
        }

        /// <summary>
        /// Download one artifact of an update and verify its bytes against the
        /// manifest SHA-256, then write it to <paramref name="destPath"/>. Returns
        /// the chosen artifact. Does NOT apply or execute anything — verification
        /// and installation are the host application's responsibility.
        /// </summary>
        public async Task<UpdateArtifact> DownloadUpdateAsync(
            UpdateInfo info, string destPath, UpdateArtifact? artifact = null, CancellationToken ct = default)
        {
            RequireActivated();
            UpdateArtifact? chosen = artifact ?? PickArtifact(info.Artifacts);
            if (chosen == null) throw new TalosException("no artifact matches this platform");
            await FetchVerifiedAsync(chosen.DownloadPath, chosen.Size, chosen.Sha256, destPath, ct)
                .ConfigureAwait(false);
            RememberDownloaded(info);
            return chosen;
        }

        /// <summary>
        /// Fetch one file over the entitled download route and write it only once
        /// its bytes match the size and hash the signed manifest names. Shared by
        /// full builds and patches, which differ in what they are for and not at
        /// all in how their bytes are checked.
        /// </summary>
        private async Task FetchVerifiedAsync(
            string? downloadPath, long size, string sha256, string destPath, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(downloadPath)) throw new TalosException("artifact has no download path");

            using var req = new HttpRequestMessage(HttpMethod.Get, _options.ServerUrl.TrimEnd('/') + downloadPath);
            req.Headers.TryAddWithoutValidation("x-talos-product-token", _options.ProductToken);
            req.Headers.TryAddWithoutValidation("x-talos-license-key", _licenseKey);
            req.Headers.TryAddWithoutValidation("x-talos-activation-secret", _activationSecret);
            req.Headers.TryAddWithoutValidation("x-talos-fingerprint", _fingerprint);
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                throw new TalosApiException((int)resp.StatusCode, null);

            // The download channel is untrusted (could stream an unbounded body to
            // exhaust memory before the hash check). Cap the read at the manifest's
            // trusted Size, then verify the SHA-256 from the signed manifest.
            if (resp.Content.Headers.ContentLength is long cl && cl > size)
                throw new TalosSignatureException("artifact exceeds manifest size");
            using var stream = await resp.Content.ReadAsStreamAsync().ConfigureAwait(false);
            byte[] bytes = await ReadCappedAsync(stream, size, ct).ConfigureAwait(false);

            string actual = Sha256Hex(bytes);
            if (!string.Equals(actual, sha256, StringComparison.Ordinal))
                throw new TalosSignatureException("artifact hash mismatch (tampered or wrong bytes)");

#if NET5_0_OR_GREATER
            await File.WriteAllBytesAsync(destPath, bytes, ct).ConfigureAwait(false);
#else
            using (var fs = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None))
                await fs.WriteAsync(bytes, 0, bytes.Length, ct).ConfigureAwait(false);
#endif
        }

        private static async Task<byte[]> ReadCappedAsync(Stream stream, long cap, CancellationToken ct)
        {
            using var ms = new MemoryStream();
            byte[] buf = new byte[81920];
            long total = 0;
            int n;
            while ((n = await stream.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false)) > 0)
            {
                total += n;
                if (total > cap)
                    throw new TalosSignatureException("artifact exceeds manifest size");
                ms.Write(buf, 0, n);
            }
            return ms.ToArray();
        }

        private static string? GetStr(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        private static long GetLong(JsonElement e, string name) =>
            e.ValueKind == JsonValueKind.Object
            && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
                ? v.GetInt64() : 0;

        private static string SelKey(string? platform, string? arch, string? kind) =>
            $"{platform}/{arch}/{kind}";

        private static string DeltaKey(string? platform, string? arch, string? from, string? targetKind) =>
            $"{platform}/{arch}/{from}/{targetKind}";

        /// <summary>The platform and arch names this machine matches artifacts by.</summary>
        private static (string Platform, string Arch) HostTarget()
        {
            string platform =
                RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "windows" :
                RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "macos" :
                RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "unknown";
            return (platform, RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant());
        }

        private static string Sha256Hex(byte[] bytes)
        {
            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(bytes);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        private static UpdateArtifact? PickArtifact(IReadOnlyList<UpdateArtifact> artifacts)
        {
            var (platform, arch) = HostTarget();
            var matches = artifacts.Where(a => a.Platform == platform && a.Arch == arch).ToList();
            return matches.FirstOrDefault(a => a.Kind == "installer") ?? matches.FirstOrDefault();
        }

        private void RequireActivated()
        {
            if (_activationSecret == null || _licenseKey == null)
                throw new TalosException("not activated: call ActivateAsync first");
        }

        private LicenseState StateFromClaims(JsonElement claims, string decision, bool isOffline)
        {
            var state = new LicenseState { Decision = decision, IsOffline = isOffline };
            long? revalHours = null;
            long? graceHours = null;
            if (claims.TryGetProperty("lic", out var lic) && lic.ValueKind == JsonValueKind.Object)
            {
                if (lic.TryGetProperty("features", out var feats))
                    state.Features = feats.Clone();
                if (lic.TryGetProperty("lic_exp", out var exp) && exp.ValueKind == JsonValueKind.Number)
                    state.LicenseExpiresAt = exp.GetInt64();
                revalHours = Num(lic, "reval_h");
                graceHours = Num(lic, "grace_h");
            }
            // Validation carries absolute deadlines; activation carries the same
            // policy as hours beside its `iat`. Prefer the absolute form and
            // derive the other, so both tokens answer "when should I come back?"
            // the same way.
            long iat = Num(claims, "iat") ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            state.RevalidateAfter = Num(claims, "reval_after")
                ?? (revalHours == null ? (long?)null : iat + revalHours.Value * 3600);
            state.GraceUntil = Num(claims, "grace_until")
                ?? (graceHours == null ? (long?)null : iat + graceHours.Value * 3600);
            return state;
        }

        private Task<JsonDocument> PostAsync(string path, object body, CancellationToken ct)
            => SendAsync(HttpMethod.Post, path, body, ct);

        /// <summary>
        /// Default cap on a licensing call, in milliseconds.
        /// </summary>
        /// <remarks>
        /// Ten seconds: long enough that a slow network is not mistaken for a
        /// dead one, short enough that an application blocked on it still
        /// starts. <c>HttpClient</c>'s own default is 100 seconds.
        /// </remarks>
        private const int DefaultHttpTimeoutMs = 10_000;

        private async Task<JsonDocument> SendAsync(
            HttpMethod method, string path, object body, CancellationToken ct)
        {
            string json = JsonSerializer.Serialize(body);
            using var req = new HttpRequestMessage(method, _options.ServerUrl.TrimEnd('/') + path)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
            // A linked source rather than `HttpClient.Timeout`, because a
            // supplied client belongs to the caller and this must not change
            // the timeout of every other request their application makes.
            int ms = _options.HttpTimeoutMs ?? DefaultHttpTimeoutMs;
            using var timeout = ms > 0
                ? CancellationTokenSource.CreateLinkedTokenSource(ct)
                : null;
            timeout?.CancelAfter(ms);
            var token = timeout?.Token ?? ct;
            HttpResponseMessage resp;
            try
            {
                resp = await _http.SendAsync(req, token).ConfigureAwait(false);
            }
            // Our timeout, not the caller's cancellation — the caller's token is
            // still unsignalled. It has to surface as a Talos exception rather
            // than a cancellation, because `ValidateAsync` turns a network
            // failure into the grace-period path and an OperationCanceledException
            // there would take the application down instead of letting it keep
            // running offline.
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new TalosException($"request timed out after {ms}ms");
            }
            // Disposed here rather than by a `using` on the assignment, because
            // the send is inside a try that has to name the exception it catches.
            using var response = resp;
            string text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                string? err = TryReadError(text);
                throw new TalosApiException((int)response.StatusCode, err);
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

        /// <summary>
        /// The machine name to report, or null to report none.
        /// </summary>
        /// <remarks>
        /// An explicit <c>""</c> means "do not send". Omitting the field leaves
        /// whatever the server already holds, because the server coalesces — so
        /// sending an empty string would not clear it either, and suppression
        /// has to happen here.
        /// </remarks>
        private string? ReportedHostname()
        {
            string? h = _options.Hostname ?? SafeMachineName();
            return string.IsNullOrEmpty(h) ? null : h;
        }

        private static string? SafeMachineName()
        {
            try { return Environment.MachineName; }
            // Locked-down hosts can refuse this. A missing name is a blank
            // column, never a failed activation.
            catch { return null; }
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
