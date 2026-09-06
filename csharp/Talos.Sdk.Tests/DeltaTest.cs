using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    /// Patches, from the client's side.
    /// <para>
    /// Two things have to hold and neither follows from the wire format alone. A
    /// patch must never turn up among the full builds — <c>DownloadUpdateAsync</c>
    /// picks "the artifact for this platform" and hands the file to the host, so
    /// a patch in that list is a patch a host tries to run. And the chain of
    /// signatures has to reach past the patch to the file it produces: verifying
    /// the patch's own bytes says nothing about what comes out of the patcher,
    /// which is the thing that actually gets executed.
    /// </para>
    /// </summary>
    public class DeltaTest
    {
        private const string Product = "tpt_delta_test";

        // The host names the SDK matches artifacts by. Derived the same way the
        // SDK derives them, so the test asserts selection and not what machine it
        // happens to run on.
        private static readonly string Platform =
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "windows" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "macos" :
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "unknown";

        private static readonly string Arch =
            RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();

        private static readonly byte[] Installer = Encoding.UTF8.GetBytes("the whole installer, all of it");
        private static readonly byte[] Archive = Encoding.UTF8.GetBytes("the portable archive");
        private static readonly byte[] PatchToInstaller = Encoding.UTF8.GetBytes("just the diff");
        private static readonly byte[] PatchToArchive = Encoding.UTF8.GetBytes("a different diff");

        // ---- minting ---------------------------------------------------------

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

        private static Dictionary<string, object?> Artifact(string kind, string filename, byte[] body) =>
            new Dictionary<string, object?>
            {
                ["platform"] = Platform,
                ["arch"] = Arch,
                ["kind"] = kind,
                ["filename"] = filename,
                ["size"] = body.Length,
                ["sha256"] = Sha(body),
            };

        private static Dictionary<string, object?> Delta(
            string from, string filename, byte[] body, string targetKind, string targetName, byte[] target) =>
            new Dictionary<string, object?>
            {
                ["platform"] = Platform,
                ["arch"] = Arch,
                ["from"] = from,
                ["from_seq"] = 41,
                ["filename"] = filename,
                ["size"] = body.Length,
                ["sha256"] = Sha(body),
                ["target"] = new Dictionary<string, object?>
                {
                    ["kind"] = targetKind,
                    ["filename"] = targetName,
                    ["size"] = target.Length,
                    ["sha256"] = Sha(target),
                },
            };

        /// <summary>A signed manifest for 1.1.0 carrying patches from 1.0.0.</summary>
        private static string Manifest(Ed25519PrivateKeyParameters sk, bool withDeltas = true)
        {
            var claims = new Dictionary<string, object?>
            {
                ["v"] = 1,
                ["typ"] = "manifest",
                ["aud"] = Product,
                ["version"] = "1.1.0",
                ["release_seq"] = 42,
                ["mandatory"] = false,
                ["artifacts"] = new[]
                {
                    Artifact("installer", "app-1.1.0.exe", Installer),
                    Artifact("archive", "app-1.1.0.zip", Archive),
                },
            };
            if (withDeltas)
            {
                claims["deltas"] = new[]
                {
                    Delta("1.0.0", "to-installer.patch", PatchToInstaller, "installer", "app-1.1.0.exe", Installer),
                    Delta("1.0.0", "to-archive.patch", PatchToArchive, "archive", "app-1.1.0.zip", Archive),
                };
            }
            return Mint(sk, "manifest", claims);
        }

        // ---- transport -------------------------------------------------------

        private sealed class Router : HttpMessageHandler
        {
            private readonly Func<string, HttpResponseMessage> _f;
            public Router(Func<string, HttpResponseMessage> f) => _f = f;

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
                Task.FromResult(_f(request.RequestUri!.AbsolutePath));
        }

        /// <summary>
        /// A server answering the update check with the signed manifest plus the
        /// transport routes, and serving each file from its own path.
        /// </summary>
        private static HttpClient Server(
            Ed25519PrivateKeyParameters sk,
            IDictionary<string, byte[]> files,
            bool withDeltas = true)
        {
            return new HttpClient(new Router(path =>
            {
                if (path.EndsWith("/updates/check", StringComparison.Ordinal))
                {
                    var body = new Dictionary<string, object?>
                    {
                        ["update_available"] = true,
                        ["version"] = "1.1.0",
                        ["release_seq"] = 42,
                        ["manifest"] = Manifest(sk, withDeltas),
                        ["artifacts"] = new[]
                        {
                            Route("a1", "installer"),
                            Route("a2", "archive"),
                        },
                    };
                    if (withDeltas)
                    {
                        body["deltas"] = new[]
                        {
                            DeltaRoute("d1", "1.0.0", "installer"),
                            DeltaRoute("d2", "1.0.0", "archive"),
                        };
                    }
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
                    };
                }
                string id = path.Split('/').Last();
                if (!files.TryGetValue(id, out byte[]? bytes))
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
            }));
        }

        private static Dictionary<string, object?> Route(string id, string kind) =>
            new Dictionary<string, object?>
            {
                ["platform"] = Platform,
                ["arch"] = Arch,
                ["kind"] = kind,
                ["artifact_id"] = id,
                ["download_path"] = "/v1/client/updates/artifacts/" + id,
            };

        private static Dictionary<string, object?> DeltaRoute(string id, string from, string targetKind) =>
            new Dictionary<string, object?>
            {
                ["platform"] = Platform,
                ["arch"] = Arch,
                ["from"] = from,
                ["target_kind"] = targetKind,
                ["artifact_id"] = id,
                ["download_path"] = "/v1/client/updates/artifacts/" + id,
            };

        private static Dictionary<string, byte[]> Files() => new Dictionary<string, byte[]>
        {
            ["a1"] = Installer,
            ["a2"] = Archive,
            ["d1"] = PatchToInstaller,
            ["d2"] = PatchToArchive,
        };

        private static TalosClient Client(string pubB64, HttpClient http, string appVersion)
        {
            string file = Path.Combine(
                Directory.CreateDirectory(
                    Path.Combine(Path.GetTempPath(), "talos-delta-" + Guid.NewGuid().ToString("N"))).FullName,
                "state.bin");
            var fp = Talos.Sdk.Fingerprint.Collect(Product, null);
            new StateStore(file, Product, StateStore.KeyMaterial(fp.Components)).Save(new StoredBinding
            {
                LicenseKeyHash = StateStore.HashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"),
                ActivationSecret = "secret",
                MachineId = "m1",
                Fingerprint = fp.Composite,
            });
            return new TalosClient(new TalosOptions
            {
                ProductToken = Product,
                PublicKey = pubB64,
                ReleasePublicKey = pubB64,
                ServerUrl = "http://127.0.0.1:1",
                StatePath = file,
                AppVersion = appVersion,
                HttpClient = http,
            });
        }

        private static string TempFile(string name) => Path.Combine(
            Directory.CreateDirectory(
                Path.Combine(Path.GetTempPath(), "talos-delta-out-" + Guid.NewGuid().ToString("N"))).FullName,
            name);

        // ---- the properties ---------------------------------------------------

        [Fact]
        public async Task KeepsPatchesOutOfTheListDownloadUpdatePicksFrom()
        {
            var (pub, sk) = Keypair();
            var client = Client(pub, Server(sk, Files()), "1.0.0");
            UpdateInfo info = (await client.CheckForUpdateAsync())!;

            Assert.Equal(new[] { "installer", "archive" }, info.Artifacts.Select(a => a.Kind));
            Assert.DoesNotContain(info.Artifacts, a => a.Kind == "delta");
            Assert.Equal(2, info.Deltas.Count);

            // The default pick is still a whole build. A patch here would be
            // handed to the host as if it were an installer, on machines already
            // in the field that nobody can update to fix.
            UpdateArtifact chosen = await client.DownloadUpdateAsync(info, TempFile("app.exe"));
            Assert.Equal("installer", chosen.Kind);
        }

        [Fact]
        public async Task MatchesAPatchOnTheExactInstalledVersionAndNothingElse()
        {
            var (pub, sk) = Keypair();
            var client = Client(pub, Server(sk, Files()), "1.0.0");
            UpdateInfo info = (await client.CheckForUpdateAsync())!;

            // Two patches from 1.0.0, one per shipped file. Which one is wanted
            // is not something the SDK can infer, so it refuses rather than
            // downloading megabytes to rebuild the file nobody was updating.
            Assert.Null(client.SelectDelta(info));
            Assert.Equal("to-installer.patch", client.SelectDelta(info, targetKind: "installer")!.Filename);
            Assert.Equal("to-archive.patch", client.SelectDelta(info, targetKind: "archive")!.Filename);

            // A version this release ships no patch from gets the full build.
            // Deliberately not "the nearest older version": a patch applies to
            // the bytes it was built against, and close enough produces a corrupt
            // file rather than an error.
            Assert.Null(client.SelectDelta(info, from: "1.0.1", targetKind: "installer"));
            Assert.Null(client.SelectDelta(info, from: "0.9.0", targetKind: "installer"));
        }

        [Fact]
        public async Task VerifiesThePatchOnTheWayInAndTheFileItProducesOnTheWayOut()
        {
            var (pub, sk) = Keypair();
            var client = Client(pub, Server(sk, Files()), "1.0.0");
            UpdateInfo info = (await client.CheckForUpdateAsync())!;

            UpdateDelta delta = await client.DownloadDeltaAsync(
                info, TempFile("to-installer.patch"), targetKind: "installer");
            Assert.Equal("1.0.0", delta.From);
            Assert.Equal(Sha(Installer), delta.Target.Sha256);
            Assert.NotEqual(delta.Sha256, delta.Target.Sha256);

            // Applying is the host's job. Whatever it produces is checked against
            // the manifest, which is the step that keeps the signature reaching
            // the binary that actually runs.
            string applied = TempFile("app-1.1.0.exe");
            File.WriteAllBytes(applied, Installer);
            TalosClient.VerifyAppliedUpdate(applied, delta);

            // A patcher that stopped halfway, applied to the wrong base, or wrote
            // somebody else's bytes: all of them land here.
            string wrong = TempFile("half-applied.exe");
            File.WriteAllBytes(wrong, Installer.Take(Installer.Length - 1).ToArray());
            var ex = Assert.Throws<TalosSignatureException>(() => TalosClient.VerifyAppliedUpdate(wrong, delta));
            Assert.Contains("does not match the signed manifest", ex.Message);
        }

        [Fact]
        public async Task RefusesPatchBytesThatDoNotMatchTheSignedManifest()
        {
            var (pub, sk) = Keypair();
            var files = Files();
            // Exactly as long as the real patch, so what refuses it is the hash
            // and not the size cap — which would leave the hash check unexercised.
            files["d1"] = Encoding.UTF8.GetBytes("JUST THE DIFF");
            Assert.Equal(PatchToInstaller.Length, files["d1"].Length);

            var client = Client(pub, Server(sk, files), "1.0.0");
            UpdateInfo info = (await client.CheckForUpdateAsync())!;

            // The download route is untrusted exactly like a full artifact's, and
            // a patch is the more attractive thing to swap: it is small, and its
            // output is executable.
            var ex = await Assert.ThrowsAsync<TalosSignatureException>(() =>
                client.DownloadDeltaAsync(info, TempFile("bad.patch"), targetKind: "installer"));
            Assert.Contains("hash mismatch", ex.Message);
        }

        [Fact]
        public async Task HasNothingToOfferAnInstallWhoseVersionWasNeverPublished()
        {
            var (pub, sk) = Keypair();
            var client = Client(pub, Server(sk, Files()), "0.1.0");
            UpdateInfo info = (await client.CheckForUpdateAsync())!;

            Assert.Null(client.SelectDelta(info, targetKind: "installer"));
            await Assert.ThrowsAsync<TalosException>(() =>
                client.DownloadDeltaAsync(info, TempFile("none.patch"), targetKind: "installer"));
        }

        [Fact]
        public async Task ReadsAManifestWithNoDeltasAsOneWithNoDeltas()
        {
            // Every release published before patches existed looks like this, and
            // there are installs out there that will be offered one.
            var (pub, sk) = Keypair();
            var client = Client(pub, Server(sk, Files(), withDeltas: false), "1.0.0");
            UpdateInfo info = (await client.CheckForUpdateAsync())!;

            Assert.Empty(info.Deltas);
            Assert.Null(client.SelectDelta(info));
        }
    }
}
