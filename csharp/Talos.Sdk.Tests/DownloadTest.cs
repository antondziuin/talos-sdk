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
    /// What an artifact download does while it is running, and what it leaves
    /// behind when it fails.
    /// <para>
    /// It used to buffer the whole body, check the hash, and only then write —
    /// which is correct about the bytes and wrong about everything else. A
    /// desktop application shipping a two-gigabyte installer asked the smallest
    /// machine in the field for two gigabytes of RAM, and the host had nothing to
    /// show a user for the several minutes it took: one <c>Task</c>, no output,
    /// indistinguishable from a hang.
    /// </para>
    /// <para>
    /// Streaming it fixes both and puts a new thing at risk — unverified bytes
    /// sitting at the path the host is about to run. So the two properties here
    /// are that progress arrives <i>while</i> the download is in flight, and that
    /// a download which fails verification leaves the destination as it was.
    /// </para>
    /// </summary>
    public class DownloadTest
    {
        private const string Product = "tpt_download_test";

        private static readonly string Platform =
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "windows" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "macos" :
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "unknown";

        private static readonly string Arch =
            RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();

        /// <summary>Four buffer-fills long at the chunk size the fake server uses.</summary>
        private static readonly byte[] Build =
            Encoding.UTF8.GetBytes("the bytes of the build, enough of them to arrive in pieces");

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

        private static string Manifest(Ed25519PrivateKeyParameters sk) =>
            Mint(sk, "manifest", new Dictionary<string, object?>
            {
                ["v"] = 1,
                ["typ"] = "manifest",
                ["aud"] = Product,
                ["version"] = "1.1.0",
                ["release_seq"] = 42,
                ["mandatory"] = false,
                ["artifacts"] = new[]
                {
                    new Dictionary<string, object?>
                    {
                        ["platform"] = Platform,
                        ["arch"] = Arch,
                        ["kind"] = "installer",
                        ["filename"] = "app-1.1.0.exe",
                        ["size"] = Build.Length,
                        ["sha256"] = Sha(Build),
                    },
                },
                ["deltas"] = Array.Empty<object>(),
            });

        // ---- transport -------------------------------------------------------

        /// <summary>
        /// A body that arrives a few bytes at a time, the way a socket delivers
        /// one. <c>CanSeek</c> is false so <c>StreamContent</c> advertises no
        /// <c>Content-Length</c> — the progress totals then have nowhere to come
        /// from but the signed manifest, which is where they must come from
        /// anyway: the download host is untrusted, and a bar it can drive can be
        /// parked at 100% while bytes are still arriving.
        /// </summary>
        private sealed class ChunkStream : Stream
        {
            private readonly byte[] _bytes;
            private readonly int _chunk;
            private int _pos;

            public ChunkStream(byte[] bytes, int chunk)
            {
                _bytes = bytes;
                _chunk = chunk;
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => _pos;
                set => throw new NotSupportedException();
            }

            public override void Flush() { }

            public override int Read(byte[] buffer, int offset, int count)
            {
                int n = Math.Min(Math.Min(_chunk, count), _bytes.Length - _pos);
                Array.Copy(_bytes, _pos, buffer, offset, n);
                _pos += n;
                return n;
            }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private sealed class Router : HttpMessageHandler
        {
            private readonly Func<string, HttpResponseMessage> _f;
            public Router(Func<string, HttpResponseMessage> f) => _f = f;

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
                Task.FromResult(_f(request.RequestUri!.AbsolutePath));
        }

        private static HttpClient Server(Ed25519PrivateKeyParameters sk, byte[] serve, int chunk = 16)
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
                        ["manifest"] = Manifest(sk),
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
                    Content = new StreamContent(new ChunkStream(serve, chunk)),
                };
            }));
        }

        private static TalosClient Client(string pubB64, HttpClient http)
        {
            string file = Path.Combine(
                Directory.CreateDirectory(
                    Path.Combine(Path.GetTempPath(), "talos-dl-" + Guid.NewGuid().ToString("N"))).FullName,
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
                AppVersion = "1.0.0",
                HttpClient = http,
            });
        }

        private static string OutDir() => Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), "talos-dl-out-" + Guid.NewGuid().ToString("N"))).FullName;

        /// <summary>
        /// Records synchronously. <c>Progress&lt;T&gt;</c> posts to a
        /// synchronisation context, so reports would land after the await that is
        /// asserting on them and the test would pass or fail by timing.
        /// </summary>
        private sealed class Recorder : IProgress<DownloadProgress>
        {
            public List<DownloadProgress> Reports { get; } = new List<DownloadProgress>();

            public void Report(DownloadProgress value) => Reports.Add(value);
        }

        // ---- the properties ---------------------------------------------------

        [Fact]
        public async Task ReportsProgressWhileTheBytesAreStillArriving()
        {
            var (pub, sk) = Keypair();
            var client = Client(pub, Server(sk, Build));
            UpdateInfo info = (await client.CheckForUpdateAsync())!;
            string dest = Path.Combine(OutDir(), "app.exe");

            var progress = new Recorder();
            await client.DownloadUpdateAsync(info, dest, progress: progress);

            // The point of the whole change: a report from part-way through. An
            // implementation that buffers the body and reports once at the end
            // satisfies "has a progress parameter" and gives a host nothing to
            // draw, so that is the thing asserted rather than the count.
            Assert.Contains(progress.Reports, r => r.BytesReceived > 0 && r.BytesReceived < r.TotalBytes);

            // Totals are the manifest's, and this server sends no Content-Length.
            Assert.All(progress.Reports, r => Assert.Equal(Build.Length, r.TotalBytes));

            // Monotonic, and never past the cap it is bounded by.
            for (int i = 1; i < progress.Reports.Count; i++)
                Assert.True(progress.Reports[i].BytesReceived > progress.Reports[i - 1].BytesReceived);
            DownloadProgress last = progress.Reports.Last();
            Assert.Equal(Build.Length, last.BytesReceived);
            Assert.Equal(1.0, last.Fraction);

            Assert.Equal(Build, File.ReadAllBytes(dest));
        }

        [Fact]
        public async Task LeavesTheDestinationAloneWhenTheBytesDoNotVerify()
        {
            var (pub, sk) = Keypair();
            // Exactly as long as the real build, so what refuses it is the hash
            // and not the size cap.
            byte[] wrong = Encoding.UTF8.GetBytes("THE BYTES OF THE BUILD, ENOUGH OF THEM TO ARRIVE IN PIECES");
            Assert.Equal(Build.Length, wrong.Length);

            var client = Client(pub, Server(sk, wrong));
            UpdateInfo info = (await client.CheckForUpdateAsync())!;

            string dir = OutDir();
            string dest = Path.Combine(dir, "app.exe");
            byte[] installed = Encoding.UTF8.GetBytes("the build already installed here");
            File.WriteAllBytes(dest, installed);

            var ex = await Assert.ThrowsAsync<TalosSignatureException>(() =>
                client.DownloadUpdateAsync(info, dest));
            Assert.Contains("hash mismatch", ex.Message);

            // Streaming to disk is what makes this worth asserting: the bytes
            // were written before anything vouched for them, and the only reason
            // the host is not now holding an unverified file at the path it is
            // about to run is that they went somewhere else first.
            Assert.Equal(installed, File.ReadAllBytes(dest));
            Assert.Equal(new[] { "app.exe" }, Directory.GetFiles(dir).Select(Path.GetFileName).ToArray());
        }

        [Fact]
        public async Task LeavesNothingBehindWhenTheBodyRunsPastTheManifestSize()
        {
            var (pub, sk) = Keypair();
            byte[] tooMuch = Build.Concat(Encoding.UTF8.GetBytes(" and then some")).ToArray();

            var client = Client(pub, Server(sk, tooMuch));
            UpdateInfo info = (await client.CheckForUpdateAsync())!;

            string dir = OutDir();
            var ex = await Assert.ThrowsAsync<TalosSignatureException>(() =>
                client.DownloadUpdateAsync(info, Path.Combine(dir, "app.exe")));
            Assert.Contains("exceeds manifest size", ex.Message);

            // The cap now fires with a part file already open and partly written.
            Assert.Empty(Directory.GetFiles(dir));
        }
    }
}
