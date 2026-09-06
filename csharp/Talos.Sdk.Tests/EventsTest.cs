using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
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
    /// The licence events, which are about edges rather than levels.
    /// <para>
    /// Everything here was already computable by the host: <c>StartCheckIns</c>
    /// hands it the verdict on every tick, and diffing consecutive verdicts is
    /// what tells "grace has begun" from "grace is still on". But every host
    /// doing that arithmetic writes the same bug — a warning re-raised every ten
    /// minutes for the whole outage, or a banner that never comes down — so the
    /// bookkeeping belongs here, once.
    /// </para>
    /// <para>
    /// So the assertions are about firing <i>once</i> on the way in, about the
    /// four verdicts not being confused with one another, and about a handler
    /// being unable to change the verdict it is being told about.
    /// </para>
    /// </summary>
    public class EventsTest
    {
        private const string Product = "tpt_events_test";

        private static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        private static string Composite() => Talos.Sdk.Fingerprint.Collect(Product, null).Composite;

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

        private static string Mint(Ed25519PrivateKeyParameters sk, string typ, string payloadJson)
        {
            string prefix = $"talos.1.{typ}." + B64Url(Encoding.UTF8.GetBytes(payloadJson));
            var signer = new Ed25519Signer();
            signer.Init(true, sk);
            byte[] bytes = Encoding.ASCII.GetBytes(prefix);
            signer.BlockUpdate(bytes, 0, bytes.Length);
            return prefix + "." + B64Url(signer.GenerateSignature());
        }

        private static Dictionary<string, object?> ValidationClaims(string decision, string nonce)
        {
            long now = Now();
            return new Dictionary<string, object?>
            {
                ["aud"] = Product,
                ["typ"] = "validation",
                ["iat"] = now,
                ["nbf"] = now - 60,
                ["exp"] = now + 300,
                ["non"] = nonce,
                ["decision"] = decision,
                ["server_time"] = now,
                ["reval_after"] = now + 86_400,
                ["grace_until"] = now + 3600,
                ["fph"] = Composite(),
                ["lic"] = new Dictionary<string, object?>
                {
                    ["features"] = new Dictionary<string, object?> { ["pro"] = true },
                    ["lic_exp"] = null,
                },
            };
        }

        /// <summary>A cached verdict on disk, as a previous run would have left it.</summary>
        private static string Seed(Ed25519PrivateKeyParameters sk, Action<Dictionary<string, object?>>? tweak = null)
        {
            var claims = ValidationClaims("valid", "whatever-the-request-echoed");
            claims["exp"] = Now() - 30; // stale as a fresh proof; that is what makes it a cache
            tweak?.Invoke(claims);
            string file = Path.Combine(
                Directory.CreateDirectory(
                    Path.Combine(Path.GetTempPath(), "talos-events-" + Guid.NewGuid().ToString("N"))).FullName,
                "state.bin");
            var fp = Talos.Sdk.Fingerprint.Collect(Product, null);
            new StateStore(file, Product, StateStore.KeyMaterial(fp.Components)).Save(new StoredBinding
            {
                LicenseKeyHash = StateStore.HashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"),
                ActivationSecret = "secret",
                MachineId = "m1",
                Fingerprint = fp.Composite,
                Validation = Mint(sk, "validation", JsonSerializer.Serialize(claims)),
                TimeHighWater = Now() - 60,
            });
            return file;
        }

        private sealed class Stub : HttpMessageHandler
        {
            private readonly Func<string, HttpResponseMessage> _f;
            public Stub(Func<string, HttpResponseMessage> f) => _f = f;

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken ct)
            {
                string body = request.Content == null
                    ? ""
                    : await request.Content.ReadAsStringAsync().ConfigureAwait(false);
                return _f(body);
            }
        }

        private static HttpClient DeadNetwork() =>
            new HttpClient(new Stub(_ => throw new HttpRequestException("ENOTFOUND")));

        /// <summary>
        /// A live server answering every validate with a signed decision, read
        /// afresh each call so one client can be told two different things.
        /// </summary>
        private static HttpClient Answering(Ed25519PrivateKeyParameters sk, Func<string> decision) =>
            new HttpClient(new Stub(body =>
            {
                using var doc = JsonDocument.Parse(body);
                string nonce = doc.RootElement.GetProperty("nonce").GetString()!;
                string token = Mint(sk, "validation",
                    JsonSerializer.Serialize(ValidationClaims(decision(), nonce)));
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(new Dictionary<string, object?> { ["validation_token"] = token }),
                        Encoding.UTF8,
                        "application/json"),
                };
            }));

        private static TalosClient Client(string pubB64, string statePath, HttpClient? http = null) =>
            new TalosClient(new TalosOptions
            {
                ProductToken = Product,
                PublicKey = pubB64,
                ServerUrl = "http://127.0.0.1:1",
                StatePath = statePath,
                HttpClient = http ?? DeadNetwork(),
            });

        // ---- the properties ---------------------------------------------------

        [Fact]
        public async Task AnnouncesGraceOnceForAnOutageThatLastsAllDay()
        {
            var (pub, sk) = Keypair();
            var client = Client(pub, Seed(sk));
            var started = new List<LicenseState>();
            var invalid = new List<LicenseState>();
            client.GracePeriodStarted += (_, s) => started.Add(s);
            client.LicenseInvalid += (_, s) => invalid.Add(s);

            await client.ValidateAsync();
            await client.ValidateAsync();
            await client.ValidateAsync();

            // Three check-ins on a dead network, one event. The level is still
            // there for anyone who wants it, on Current.
            Assert.Single(started);
            Assert.True(started[0].IsOffline);
            Assert.True(started[0].IsValid);
            Assert.Empty(invalid);
            Assert.True(client.Current!.IsOffline);
        }

        [Fact]
        public async Task TellsTheEndOfGraceApartFromTheLicenceGoingBad()
        {
            var (pub, sk) = Keypair();
            var client = Client(pub, Seed(sk, c => c["grace_until"] = Now() - 1));
            var expired = new List<LicenseState>();
            var invalid = new List<LicenseState>();
            client.GracePeriodExpired += (_, s) => expired.Add(s);
            client.LicenseInvalid += (_, s) => invalid.Add(s);

            await client.ValidateAsync();
            await client.ValidateAsync();

            // The licence is fine; what ran out is permission to keep believing a
            // cached answer. Reporting that as "your licence is invalid" sends the
            // user to support instead of to their network.
            Assert.Single(expired);
            Assert.Equal("grace_expired", expired[0].Decision);
            Assert.Empty(invalid);
        }

        [Fact]
        public async Task ReportsAClockThatWentBackwardsAsItsOwnThing()
        {
            var (pub, sk) = Keypair();
            // A high-water mark ahead of the local clock: the machine is lying
            // about the time, which is not a licence problem and must not be
            // announced as one.
            string file = Seed(sk);
            var fp = Talos.Sdk.Fingerprint.Collect(Product, null);
            var store = new StateStore(file, Product, StateStore.KeyMaterial(fp.Components));
            StoredBinding binding = store.Load()!;
            binding.TimeHighWater = Now() + 7 * 86_400;
            store.Save(binding);

            var client = Client(pub, file);
            var tampered = new List<LicenseState>();
            var invalid = new List<LicenseState>();
            client.ClockTamperDetected += (_, s) => tampered.Add(s);
            client.LicenseInvalid += (_, s) => invalid.Add(s);

            await client.ValidateAsync();
            await client.ValidateAsync();

            Assert.Single(tampered);
            Assert.Equal("clock_tampered", tampered[0].Decision);
            Assert.Empty(invalid);
        }

        [Fact]
        public async Task RaisesInvalidOncePerReasonAndAgainWhenTheReasonChanges()
        {
            var (pub, sk) = Keypair();
            string decision = "revoked";
            var client = Client(pub, Seed(sk), Answering(sk, () => decision));
            var seen = new List<string>();
            client.LicenseInvalid += (_, s) => seen.Add(s.Decision);

            Assert.Equal("revoked", (await client.ValidateAsync()).Decision);
            await client.ValidateAsync();

            // Same verdict twice is not a transition; a different one is, because
            // "your subscription lapsed" and "this machine was revoked" are
            // different things to put in front of a user.
            Assert.Equal(new[] { "revoked" }, seen);

            decision = "expired";
            await client.ValidateAsync();
            await client.ValidateAsync();
            Assert.Equal(new[] { "revoked", "expired" }, seen);
        }

        [Fact]
        public async Task AHandlerThatThrowsCannotChangeTheVerdict()
        {
            var (pub, sk) = Keypair();
            var client = Client(pub, Seed(sk), Answering(sk, () => "revoked"));
            client.LicenseInvalid += (_, _) => throw new InvalidOperationException("host bug");

            // The events are raised from inside ValidateAsync, whose own catch
            // treats a throw as an unreachable server. Letting a handler's
            // exception out would turn a live "revoked" answer into offline
            // grace: the licensing bypass would be a bug in the host's UI code.
            LicenseState state = await client.ValidateAsync();
            Assert.Equal("revoked", state.Decision);
            Assert.False(state.IsOffline);
        }
    }
}
