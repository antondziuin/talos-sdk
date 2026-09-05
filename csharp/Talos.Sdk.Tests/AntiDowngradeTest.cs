using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Talos.Sdk;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// The anti-downgrade high-water mark, which <c>docs/SECURITY.md</c>
    /// described for some time before it existed.
    /// <para>
    /// The rule it states is that yanking a release, or lowering its rollout
    /// share, stops the release being <i>offered</i> and does not recall it from
    /// installs that already applied it — because the SDK will not walk
    /// backwards. All of that rested on <c>CurrentReleaseSeq</c>, a number the
    /// host had to compute and pass on every call. No example passed it, the SDK
    /// stored nothing, and so a client that had installed 1.1.0 and then saw a
    /// server offering 1.0.0 — a rollback, a stale replica, or somebody in the
    /// middle — took it as an update.
    /// </para>
    /// <para>
    /// The mark has to survive the process to mean anything, so these tests are
    /// about what one client writes and the <i>next</i> one reads.
    /// </para>
    /// </summary>
    public class AntiDowngradeTest
    {
        private const string Product = "tpt_antidowngrade";

        private static readonly string Platform =
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "windows" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "macos" :
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "unknown";

        private static readonly string Arch =
            RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();

        private static readonly byte[] Build = Encoding.UTF8.GetBytes("the bytes of the build");

        private static (string PubB64, Ed25519PrivateKeyParameters Sk) Keypair()
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair pair = gen.GenerateKeyPair();
            var pub = (Ed25519PublicKeyParameters)pair.Public;
            return (Convert.ToBase64String(pub.GetEncoded()), (Ed25519PrivateKeyParameters)pair.Private);
        }

        private static string B64Url(byte[] b) =>
            Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        private static string Mint(Ed25519PrivateKeyParameters sk, string typ, object payload)
        {
            string prefix = $"talos.1.{typ}." + B64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
            var signer = new Ed25519Signer();
            signer.Init(true, sk);
            byte[] bytes = Encoding.ASCII.GetBytes(prefix);
            signer.BlockUpdate(bytes, 0, bytes.Length);
            return prefix + "." + B64Url(signer.GenerateSignature());
        }

        private static string Sha(byte[] b)
        {
            using var sha = SHA256.Create();
            var sb = new StringBuilder();
            foreach (byte x in sha.ComputeHash(b)) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        private static string Manifest(Ed25519PrivateKeyParameters sk, string version, long releaseSeq) =>
            Mint(sk, "manifest", new Dictionary<string, object?>
            {
                ["v"] = 1,
                ["typ"] = "manifest",
                ["aud"] = Product,
                ["version"] = version,
                ["release_seq"] = releaseSeq,
                ["mandatory"] = false,
                ["artifacts"] = new[]
                {
                    new Dictionary<string, object?>
                    {
                        ["platform"] = Platform,
                        ["arch"] = Arch,
                        ["kind"] = "installer",
                        ["filename"] = $"app-{version}.exe",
                        ["size"] = Build.Length,
                        ["sha256"] = Sha(Build),
                    },
                },
                ["deltas"] = Array.Empty<object>(),
            });

        private sealed class Router : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, HttpResponseMessage> _f;
            public Router(Func<HttpRequestMessage, HttpResponseMessage> f) => _f = f;

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
                Task.FromResult(_f(request));
        }

        /// <summary>
        /// A server offering one release, and recording what the client claimed
        /// to be running — the value the server-side check is made against, and
        /// the one that was always absent.
        /// </summary>
        private static HttpClient Server(
            Ed25519PrivateKeyParameters sk, string version, long releaseSeq, List<long?> seen,
            byte[]? serveInstead = null)
        {
            return new HttpClient(new Router(req =>
            {
                if (req.RequestUri!.AbsolutePath.EndsWith("/updates/check", StringComparison.Ordinal))
                {
                    string sent = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                    using var doc = JsonDocument.Parse(sent);
                    seen.Add(
                        doc.RootElement.TryGetProperty("current_release_seq", out var c)
                        && c.ValueKind == JsonValueKind.Number
                            ? c.GetInt64()
                            : (long?)null);
                    var body = new Dictionary<string, object?>
                    {
                        ["update_available"] = true,
                        ["version"] = version,
                        ["release_seq"] = releaseSeq,
                        ["manifest"] = Manifest(sk, version, releaseSeq),
                        ["artifacts"] = new[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["platform"] = Platform,
                                ["arch"] = Arch,
                                ["kind"] = "installer",
                                ["artifact_id"] = "a1",
                                ["download_path"] = "/v1/client/updates/artifacts/a1",
                            },
                        },
                    };
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
                    };
                }
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(serveInstead ?? Build),
                };
            }));
        }

        /// <summary>One machine's state file, reused across "restarts".</summary>
        private static string StateFile()
        {
            string file = Path.Combine(
                Directory.CreateDirectory(
                    Path.Combine(Path.GetTempPath(), "talos-adg-" + Guid.NewGuid().ToString("N"))).FullName,
                "state.bin");
            var fp = Talos.Sdk.Fingerprint.Collect(Product, null);
            new StateStore(file, Product, StateStore.KeyMaterial(fp.Components)).Save(new StoredBinding
            {
                LicenseKey = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
                ActivationSecret = "secret",
                MachineId = "m1",
                Fingerprint = fp.Composite,
            });
            return file;
        }

        private static TalosClient Client(string file, string pubB64, HttpClient http, string appVersion) =>
            new TalosClient(new TalosOptions
            {
                ProductToken = Product,
                PublicKey = pubB64,
                ReleasePublicKey = pubB64,
                ServerUrl = "http://127.0.0.1:1",
                StatePath = file,
                AppVersion = appVersion,
                HttpClient = http,
            });

        private static string TempFile(string name) => Path.Combine(
            Directory.CreateDirectory(
                Path.Combine(Path.GetTempPath(), "talos-adg-out-" + Guid.NewGuid().ToString("N"))).FullName,
            name);

        [Fact]
        public async Task RemembersWhatItInstalledAndRefusesToGoBack()
        {
            var (pub, sk) = Keypair();
            string file = StateFile();
            var seen = new List<long?>();

            // 1.0.0 running, 1.1.0 offered. Nothing is stored yet, so the SDK
            // claims nothing — an install adopting the SDK mid-life must not
            // have its first update refused by a floor it invented.
            var a = Client(file, pub, Server(sk, "1.1.0", 42, seen), "1.0.0");
            UpdateInfo info = (await a.CheckForUpdateAsync())!;
            Assert.Equal(42, info.ReleaseSeq);
            Assert.Null(seen[0]);

            // Downloaded and verified. Still not installed: the host writes the
            // bytes somewhere and does its own thing with them, usually after a
            // restart.
            await a.DownloadUpdateAsync(info, TempFile("app.exe"));

            // A second client on the same machine, still running 1.0.0 — a
            // restart where the update was fetched and not applied. The mark
            // must not move, or a download that was never installed would block
            // the release that was.
            var notYet = Client(file, pub, Server(sk, "1.1.0", 42, seen), "1.0.0");
            Assert.Equal(42, (await notYet.CheckForUpdateAsync())!.ReleaseSeq);
            Assert.Null(seen[1]);

            // Now the host is running 1.1.0: the download became an install, and
            // the SDK can tell because the version it was given matches the one
            // it fetched.
            var after = Client(file, pub, Server(sk, "1.0.0", 41, seen), "1.1.0");
            Assert.Null(await after.CheckForUpdateAsync());
            Assert.Equal(42, seen[2]);

            // …and the same answer on the next start, from disk rather than from
            // anything this process happened to remember. That is the whole
            // point: a mark that dies with the process protects nothing, because
            // the attack is a server offering an old build to an application
            // that has just started.
            var later = Client(file, pub, Server(sk, "1.0.0", 41, seen), "1.1.0");
            Assert.Null(await later.CheckForUpdateAsync());
            Assert.Equal(42, seen[3]);
        }

        [Fact]
        public async Task TheHostCanOverrideAFloorTheSdkCannotKnow()
        {
            var (pub, sk) = Keypair();
            var seen = new List<long?>();
            var c = Client(StateFile(), pub, Server(sk, "1.1.0", 42, seen), "1.0.0");

            // A package manager installed 1.2.0 behind the SDK's back. The host
            // knows; the SDK cannot, and says so rather than offering the older
            // build.
            Assert.Null(await c.CheckForUpdateAsync(new CheckForUpdateOptions { CurrentReleaseSeq = 50 }));
            Assert.Equal(50, seen[0]);
        }

        [Fact]
        public async Task ADownloadThatFailedVerificationDoesNotRaiseTheFloor()
        {
            var (pub, sk) = Keypair();
            string file = StateFile();
            var seen = new List<long?>();

            // The manifest names the real build; the download serves something
            // else.
            var tampered = Server(sk, "1.1.0", 42, seen, Encoding.UTF8.GetBytes("not the build at all"));
            var a = Client(file, pub, tampered, "1.0.0");
            UpdateInfo info = (await a.CheckForUpdateAsync())!;
            await Assert.ThrowsAnyAsync<TalosException>(
                () => a.DownloadUpdateAsync(info, TempFile("app.exe")));

            // Even if the host then reports the version the tampered file
            // claimed to be, nothing was recorded — so the floor did not move
            // past a good build.
            var next = Client(file, pub, Server(sk, "1.1.0", 42, seen), "1.1.0");
            Assert.Equal(42, (await next.CheckForUpdateAsync())!.ReleaseSeq);
        }
    }
}
