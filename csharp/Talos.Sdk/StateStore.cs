using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Talos.Sdk
{
    /// <summary>
    /// The machine binding the server hands back at activation, held across
    /// process restarts.
    /// <para>
    /// Without this the binding died with the process and every application
    /// start had to call activate again — which burns a round trip the protocol
    /// was designed to avoid, rotates the activation secret out from under any
    /// other running copy, and (because activate is the one client route refused
    /// for a suspended tenant) turns the platform owner's deliberately graduated
    /// suspension into a hard kill switch for the developer's own paying users.
    /// </para>
    /// </summary>
    public sealed class StoredBinding
    {
        /// <summary>
        /// SHA-256 of the licence key as it was typed, hex — <b>not</b> the key.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The key itself used to live here so the next call could send it. It
        /// no longer has to: the server resolves a licence from the activation
        /// secret, which is the credential those calls authenticate with
        /// anyway. What was left was a plaintext licence key in a file on every
        /// customer's machine — a credential-shaped file, and exactly what an
        /// infostealer collects.
        /// </para>
        /// <para>
        /// A hash is kept because one thing still needs it: calling
        /// <c>ActivateAsync</c> twice with the same key must validate rather
        /// than spend a second seat, and that comparison is all the stored value
        /// was ever used for. It cannot be replayed to the server, which matches
        /// an HMAC under its own pepper. Hashed as typed, without normalising,
        /// because the comparison it replaces was a string equality on the same
        /// input.
        /// </para>
        /// </remarks>
        public string LicenseKeyHash { get; set; } = "";
        public string ActivationSecret { get; set; } = "";
        public string MachineId { get; set; } = "";

        /// <summary>
        /// The fingerprint composite at activation time. Informational: it is
        /// <b>not</b> required to match on restore, because a machine whose
        /// hardware drifted is exactly the case the server's fuzzy matcher
        /// exists to resolve. Discarding the binding here would re-activate the
        /// customer whose disk was replaced — the support ticket the drift
        /// budget was built to prevent.
        /// </summary>
        public string Fingerprint { get; set; } = "";

        /// <summary>
        /// The last anchor-signed keyset token.
        /// <para>
        /// Cached because an anchor-only client — the pinning that survives key
        /// rotation — otherwise has no verification key at all until it can
        /// reach the server, which is exactly the situation the offline path
        /// exists for. The anchor is compiled into the app, the keyset is signed
        /// by it, and the validation token is signed by a key it lists: the
        /// whole chain verifies offline against a root the network cannot
        /// influence.
        /// </para>
        /// </summary>
        public string? Keyset { get; set; }

        /// <summary>The last verified <c>typ=validation</c> token — the offline verdict.</summary>
        public string? Validation { get; set; }

        /// <summary>
        /// The highest server clock ever seen, in unix seconds, taken from a
        /// signed claim.
        /// <para>
        /// This is what makes offline grace bounded. Grace is evaluated against
        /// the local clock, which the user controls; with no mark that only
        /// moves forward, winding the clock back would renew a 72-hour window
        /// indefinitely. A monotonic timer is not a substitute — it resets on
        /// reboot and on a VM snapshot restore, which is the case that matters.
        /// </para>
        /// </summary>
        public long TimeHighWater { get; set; }

        /// <summary>
        /// The highest <c>release_seq</c> this install is known to be running,
        /// and the floor <c>CheckForUpdateAsync</c> refuses to go below.
        /// <para>
        /// Anti-downgrade only works against a mark that outlives the process,
        /// and until this existed there was none: the floor came entirely from
        /// <c>CurrentReleaseSeq</c>, which the host had to compute and pass, and
        /// which no example passed. <c>docs/SECURITY.md</c> described a
        /// high-water mark that did not exist, so "yanking a release does not
        /// recall it from installs that already applied it" rested on the host
        /// having implemented the mark itself.
        /// </para>
        /// </summary>
        public long ReleaseSeqHighWater { get; set; }

        /// <summary>
        /// A release whose bytes were downloaded and verified but which is not
        /// running yet: the version string from its signed manifest, and its
        /// <c>release_seq</c>. Null when there is none pending.
        /// <para>
        /// The SDK downloads; the host installs, in its own way, on its own
        /// schedule, usually after a restart. So "installed" is not an event the
        /// SDK can see — but the result is, because the host tells it which
        /// version it is on every time a client is constructed. When
        /// <c>AppVersion</c> matches what was downloaded, the download became an
        /// install and the mark advances.
        /// </para>
        /// </summary>
        public string? PendingVersion { get; set; }

        /// <summary>The <c>release_seq</c> of <see cref="PendingVersion"/>.</summary>
        public long PendingReleaseSeq { get; set; }
    }

    /// <summary>Reads and writes one product's machine binding.</summary>
    public sealed class StateStore
    {
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("TLS1");
        private const int IvLen = 12;
        private const int TagBits = 128;
        private const int TagLen = TagBits / 8;

        private readonly string _path;
        private readonly byte[] _key;
        private readonly byte[] _aad;

        public StateStore(string path, string productToken, string keyMaterial)
        {
            _path = path;
            _aad = Encoding.UTF8.GetBytes(productToken);
            _key = Hkdf(
                Encoding.UTF8.GetBytes(keyMaterial),
                Encoding.UTF8.GetBytes("talos-state-v1"),
                _aad,
                32);
        }

        /// <summary>Where the binding lives, per product, per OS convention.</summary>
        /// <remarks>
        /// The directory is named by a hash of the product token rather than the
        /// token itself: filesystem-safe without assuming anything about the
        /// token's alphabet, and two products never collide.
        /// </remarks>
        public static string DefaultPath(string productToken)
        {
            string slot;
            using (var sha = SHA256.Create())
            {
                byte[] h = sha.ComputeHash(Encoding.UTF8.GetBytes(productToken));
                var sb = new StringBuilder(16);
                for (int i = 0; i < 8; i++) sb.Append(h[i].ToString("x2"));
                slot = sb.ToString();
            }
            // LocalApplicationData is %LOCALAPPDATA% on Windows,
            // ~/Library/Application Support on macOS, and $XDG_DATA_HOME (or
            // ~/.local/share) on Linux — the convention on each host.
            string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(root))
                root = Path.Combine(Path.GetTempPath(), "talos");
            return Path.Combine(root, "Talos", slot, "state.bin");
        }

        /// <summary>
        /// Key material for the state file, chosen for <b>stability</b> rather
        /// than strength: a hardware change must not lock the user out of their
        /// own stored licence key. <c>machine_guid</c> and <c>smbios_uuid</c>
        /// survive component swaps; <c>os_install</c> survives everything short
        /// of a reinstall, which invalidates the other two anyway.
        /// <para>
        /// These values are already HMAC'd per product by the fingerprint
        /// collector, so nothing here reveals an identifier the server does not
        /// already hold.
        /// </para>
        /// <para>
        /// Where a host offers none of them the file is obfuscated rather than
        /// bound to the machine, and that is the honest description. It matters
        /// less than it sounds: the server resolves a machine by fingerprint and
        /// demands the activation secret, so a state file copied to a different
        /// computer does not validate there. This layer is tamper-evidence and
        /// resistance to casual copying — never secrecy from someone who owns
        /// the machine.
        /// </para>
        /// </summary>
        /// <summary>
        /// Which key hash a stored file yields: its own, or one derived from a
        /// licence key an older version left in the clear.
        /// </summary>
        /// <remarks>
        /// An older file carries `licenseKey`. Upgraded in place rather than
        /// discarded: the customer keeps their seat — charging every existing
        /// install a re-activation for a change made on their behalf would be a
        /// poor trade — and the plaintext stops existing on disk at the next
        /// save, which is when it actually leaves the machine.
        ///
        /// A separate function because it is the whole decision, and testing it
        /// through the sealed envelope would mean a test that rebuilds the
        /// envelope.
        /// </remarks>
        public static string ResolveKeyHash(string? storedHash, string? legacyKey)
        {
            if (!string.IsNullOrEmpty(storedHash)) return storedHash!;
            return string.IsNullOrEmpty(legacyKey) ? "" : HashLicenseKey(legacyKey!);
        }

        /// <summary>SHA-256 of a licence key, hex.</summary>
        /// <remarks>
        /// Used only to recognise "the same key as last time" without keeping
        /// the key. Not a credential and accepted by nothing: the server matches
        /// an HMAC computed under a pepper this process has never seen.
        /// </remarks>
        public static string HashLicenseKey(string key)
        {
            using var sha = SHA256.Create();
            byte[] h = sha.ComputeHash(Encoding.UTF8.GetBytes(key));
#if NET8_0_OR_GREATER
            return Convert.ToHexString(h).ToLowerInvariant();
#else
            var sb = new StringBuilder(h.Length * 2);
            foreach (byte b in h) sb.Append(b.ToString("x2"));
            return sb.ToString();
#endif
        }

        public static string KeyMaterial(IReadOnlyDictionary<string, string> components)
        {
            foreach (string id in new[] { "machine_guid", "smbios_uuid", "os_install" })
            {
                if (components.TryGetValue(id, out string? v) && !string.IsNullOrEmpty(v)) return v!;
            }
            return "talos-unbound";
        }

        /// <summary>
        /// Load the binding, or null if there is none.
        /// <para>
        /// Never throws. A state file that is missing, truncated, from another
        /// product, written by a future version, or simply corrupt must degrade
        /// to "not activated yet" — the app then activates again. Throwing here
        /// would turn a damaged cache into a launch failure.
        /// </para>
        /// </summary>
        public StoredBinding? Load()
        {
            try
            {
                if (!File.Exists(_path)) return null;
                byte[] raw = File.ReadAllBytes(_path);
                if (raw.Length < Magic.Length + IvLen + TagLen) return null;
                for (int i = 0; i < Magic.Length; i++)
                    if (raw[i] != Magic[i]) return null;

                var iv = new byte[IvLen];
                Buffer.BlockCopy(raw, Magic.Length, iv, 0, IvLen);
                int off = Magic.Length + IvLen;
                var sealedBytes = new byte[raw.Length - off];
                Buffer.BlockCopy(raw, off, sealedBytes, 0, sealedBytes.Length);

                byte[] plain = Gcm(false, iv, sealedBytes);
                using var doc = JsonDocument.Parse(plain);
                JsonElement root = doc.RootElement;
                if (!root.TryGetProperty("v", out var v) || v.GetInt32() != 1) return null;
                var b = new StoredBinding
                {
                    LicenseKeyHash =
                        ResolveKeyHash(Str(root, "licenseKeyHash"), Str(root, "licenseKey")),
                    ActivationSecret = Str(root, "activationSecret"),
                    MachineId = Str(root, "machineId"),
                    Fingerprint = Str(root, "fingerprint"),
                    Keyset = Str(root, "keyset") is { Length: > 0 } k ? k : null,
                    Validation = Str(root, "validation") is { Length: > 0 } v2 ? v2 : null,
                    TimeHighWater =
                        root.TryGetProperty("timeHighWater", out var hw)
                        && hw.ValueKind == JsonValueKind.Number
                            ? hw.GetInt64()
                            : 0,
                    ReleaseSeqHighWater =
                        root.TryGetProperty("releaseSeqHighWater", out var rw)
                        && rw.ValueKind == JsonValueKind.Number
                            ? rw.GetInt64()
                            : 0,
                    // Read field by field rather than trusted wholesale: this
                    // file is on a disk the user owns, so every value out of it
                    // is input, and a pending release missing half of itself
                    // must not become a floor.
                    PendingVersion = Str(root, "pendingVersion") is { Length: > 0 } pv ? pv : null,
                    PendingReleaseSeq =
                        root.TryGetProperty("pendingReleaseSeq", out var pr)
                        && pr.ValueKind == JsonValueKind.Number
                            ? pr.GetInt64()
                            : 0,
                };
                // The activation secret is what makes a binding usable. The key
                // hash serves one local comparison, and a file that somehow
                // lacks it is still a seat this machine holds.
                return b.ActivationSecret.Length > 0 ? b : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Persist the binding. Best-effort by design: a read-only or full disk
        /// costs the user a re-activation next launch, and must not fail the
        /// activation that just succeeded.
        /// </summary>
        public bool Save(StoredBinding b)
        {
            try
            {
                string json = JsonSerializer.Serialize(
                    new StateFileDto
                    {
                        V = 1,
                        LicenseKeyHash = b.LicenseKeyHash,
                        ActivationSecret = b.ActivationSecret,
                        MachineId = b.MachineId,
                        Fingerprint = b.Fingerprint,
                        Keyset = b.Keyset,
                        Validation = b.Validation,
                        TimeHighWater = b.TimeHighWater,
                        ReleaseSeqHighWater = b.ReleaseSeqHighWater,
                        PendingVersion = b.PendingVersion,
                        PendingReleaseSeq = b.PendingReleaseSeq,
                    },
                    StateJson.Default.StateFileDto);
                var iv = new byte[IvLen];
                using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(iv);
                byte[] sealedBytes = Gcm(true, iv, Encoding.UTF8.GetBytes(json));

                var outBytes = new byte[Magic.Length + IvLen + sealedBytes.Length];
                Buffer.BlockCopy(Magic, 0, outBytes, 0, Magic.Length);
                Buffer.BlockCopy(iv, 0, outBytes, Magic.Length, IvLen);
                Buffer.BlockCopy(sealedBytes, 0, outBytes, Magic.Length + IvLen, sealedBytes.Length);

                string dir = Path.GetDirectoryName(_path)!;
                Directory.CreateDirectory(dir);
                // Write-then-replace: a crash mid-write leaves the previous
                // binding intact rather than a half file that reads as "never
                // activated".
                string tmp = _path + ".tmp";
                File.WriteAllBytes(tmp, outBytes);
                if (File.Exists(_path)) File.Delete(_path);
                File.Move(tmp, _path);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Forget the binding (deactivation).</summary>
        public void Clear()
        {
            try
            {
                if (File.Exists(_path)) File.Delete(_path);
            }
            catch
            {
                /* ignore */
            }
        }

        private static string Str(JsonElement o, string name) =>
            o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() ?? ""
                : "";

        /// <summary>
        /// AES-256-GCM through BouncyCastle rather than the BCL, because
        /// <c>System.Security.Cryptography.AesGcm</c> does not exist on
        /// netstandard2.0 and this SDK targets it for .NET Framework and Unity
        /// hosts. BouncyCastle is already a dependency for Ed25519, so this
        /// costs nothing and keeps one code path across both TFMs.
        /// </summary>
        private byte[] Gcm(bool encrypt, byte[] iv, byte[] input)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(encrypt, new AeadParameters(new KeyParameter(_key), TagBits, iv, _aad));
            var output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);
            if (len == output.Length) return output;
            var trimmed = new byte[len];
            Buffer.BlockCopy(output, 0, trimmed, 0, len);
            return trimmed;
        }

        private static byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int length)
        {
            var gen = new HkdfBytesGenerator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
            gen.Init(new HkdfParameters(ikm, salt, info));
            var okm = new byte[length];
            gen.GenerateBytes(okm, 0, length);
            return okm;
        }
    }

    /// <summary>
    /// The state file's shape on disk.
    /// </summary>
    /// <remarks>
    /// Written through <see cref="StateJson"/> rather than reflected over: a
    /// trimmed or NativeAOT application would otherwise write an empty object
    /// here and lose its activation on every launch. Only the writer is
    /// declared — <see cref="StateStore.Load"/> reads the file field by field
    /// through <c>JsonDocument</c>, deliberately, because this file lives on a
    /// disk the user owns and every value in it is input.
    /// </remarks>
    internal sealed class StateFileDto
    {
        public int V { get; set; }
        public string? LicenseKeyHash { get; set; }
        public string? ActivationSecret { get; set; }
        public string? MachineId { get; set; }
        public string? Fingerprint { get; set; }
        public string? Keyset { get; set; }
        public string? Validation { get; set; }
        public long TimeHighWater { get; set; }
        public long ReleaseSeqHighWater { get; set; }
        public string? PendingVersion { get; set; }
        public long PendingReleaseSeq { get; set; }
    }

    /// <summary>
    /// Compile-time serializer for the state file. camelCase, unlike the wire's
    /// snake_case, because that is what files written by every earlier version
    /// already use and <see cref="StateStore.Load"/> still reads.
    /// </summary>
    [JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
    [JsonSerializable(typeof(StateFileDto))]
    internal partial class StateJson : JsonSerializerContext
    {
    }
}
