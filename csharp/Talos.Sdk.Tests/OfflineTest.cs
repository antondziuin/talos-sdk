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
    /// The offline path, with no server at all.
    /// <para>
    /// These assertions are the entire reason <c>offline_grace_hours</c> exists
    /// as a policy knob, and until now nothing read it: every SDK call was a
    /// live round trip that threw on a dead network, so a laptop on a plane lost
    /// the licensed application immediately regardless of the configured
    /// tolerance.
    /// </para>
    /// </summary>
    public class OfflineTest
    {
        private const string Product = "tpt_offline_test";

        private static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        /// <summary>This machine's composite, as the client will compute it.</summary>
        private static string Composite() => Talos.Sdk.Fingerprint.Collect(Product, null).Composite;

        // ---- token minting -------------------------------------------------

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

        /// <summary>A validation token as the server would have signed it.</summary>
        private static string ValidationJson(Action<Dictionary<string, object?>>? tweak = null)
        {
            long now = Now();
            var claims = new Dictionary<string, object?>
            {
                ["aud"] = Product,
                ["typ"] = "validation",
                ["iat"] = now - 60,
                ["nbf"] = now - 60,
                ["exp"] = now - 30, // deliberately already stale as a *fresh* proof
                ["non"] = "whatever-the-request-echoed",
                ["decision"] = "valid",
                ["server_time"] = now - 60,
                ["reval_after"] = now + 86_400,
                ["grace_until"] = now + 3600,
                ["fph"] = Composite(),
                ["lic"] = new Dictionary<string, object?>
                {
                    ["features"] = new Dictionary<string, object?> { ["pro"] = true },
                    ["lic_exp"] = null,
                },
            };
            tweak?.Invoke(claims);
            return JsonSerializer.Serialize(claims);
        }

        private static string Seed(
            Ed25519PrivateKeyParameters sk,
            string? validationJson,
            Action<StoredBinding>? tweak = null)
        {
            string file = Path.Combine(
                Directory.CreateDirectory(
                    Path.Combine(Path.GetTempPath(), "talos-offline-" + Guid.NewGuid().ToString("N"))).FullName,
                "state.bin");
            var fp = Talos.Sdk.Fingerprint.Collect(Product, null);
            var binding = new StoredBinding
            {
                LicenseKeyHash = StateStore.HashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"),
                ActivationSecret = "secret",
                MachineId = "m1",
                Fingerprint = fp.Composite,
                Validation = validationJson == null ? null : Mint(sk, "validation", validationJson),
                TimeHighWater = Now() - 60,
            };
            tweak?.Invoke(binding);
            new StateStore(file, Product, StateStore.KeyMaterial(fp.Components)).Save(binding);
            return file;
        }

        // ---- transport stubs ------------------------------------------------

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

        /// <summary>A network that is simply not there.</summary>
        private static HttpClient DeadNetwork() =>
            new HttpClient(new Stub(_ => throw new HttpRequestException("ENOTFOUND")));

        private static HttpClient Answers(HttpStatusCode code, string json) =>
            new HttpClient(new Stub(_ => new HttpResponseMessage(code)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
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

        // ---- the properties -------------------------------------------------

        [Fact]
        public async Task HonoursACachedVerdictWhileTheNetworkIsDown()
        {
            var (pub, sk) = Keypair();
            LicenseState state = await Client(pub, Seed(sk, ValidationJson())).ValidateAsync();
            Assert.Equal("valid", state.Decision);
            Assert.True(state.IsValid);
            Assert.True(state.IsOffline);
            Assert.True(state.IsFeatureEnabled("pro"));
            // The cadence the server signed is surfaced, so the app can schedule.
            Assert.True(state.RevalidateAfter > Now());
            Assert.True(state.GraceUntil > Now());
        }

        [Fact]
        public async Task StopsHonouringItOnceTheGraceWindowCloses()
        {
            var (pub, sk) = Keypair();
            string file = Seed(sk, ValidationJson(c => c["grace_until"] = Now() - 1));
            LicenseState state = await Client(pub, file).ValidateAsync();
            Assert.Equal("grace_expired", state.Decision);
            Assert.False(state.IsValid);
            Assert.True(state.IsOffline);
        }

        [Fact]
        public async Task RefusesToExtendGraceByWindingTheClockBack()
        {
            // The high-water mark is a server clock already seen, signed. A local
            // clock behind it is not a licence problem, it is a lie about the
            // time — and without this check moving the clock back would renew
            // the grace window indefinitely.
            var (pub, sk) = Keypair();
            string file = Seed(sk, ValidationJson(), b => b.TimeHighWater = Now() + 7 * 86_400);
            LicenseState state = await Client(pub, file).ValidateAsync();
            Assert.Equal("clock_tampered", state.Decision);
            Assert.False(state.IsValid);
        }

        [Fact]
        public async Task DoesNotHonourACacheIssuedForAnotherMachine()
        {
            // Copying the state file to a second computer and pulling the
            // network cable is the cheapest possible attack on offline grace.
            var (pub, sk) = Keypair();
            string file = Seed(sk, ValidationJson(c => c["fph"] = "fp2:some-other-machine"));
            await Assert.ThrowsAsync<HttpRequestException>(() => Client(pub, file).ValidateAsync());
        }

        [Fact]
        public async Task DoesNotHonourACacheSignedByTheWrongKey()
        {
            var (_, sk) = Keypair();
            var (otherPub, _) = Keypair();
            string file = Seed(sk, ValidationJson());
            await Assert.ThrowsAsync<HttpRequestException>(
                () => Client(otherPub, file).ValidateAsync());
        }

        [Fact]
        public async Task DoesNotLetACachedVerdictOutliveTheLicence()
        {
            // Inside the grace window, but the subscription itself has since
            // lapsed. Grace covers an unreachable server, not an expired
            // customer.
            var (pub, sk) = Keypair();
            string file = Seed(sk, ValidationJson(c => c["lic"] = new Dictionary<string, object?>
            {
                ["features"] = new Dictionary<string, object?> { ["pro"] = true },
                ["lic_exp"] = Now() - 10,
            }));
            LicenseState state = await Client(pub, file).ValidateAsync();
            Assert.Equal("expired", state.Decision);
            Assert.True(state.IsOffline);
        }

        [Fact]
        public async Task NeverMasksAnAnswerFromTheServer()
        {
            // A status code is a verdict — "revoked", "no such machine",
            // "tenant suspended". Falling back to the cache would turn every
            // negative answer into hours of grace, the opposite of its purpose.
            var (pub, sk) = Keypair();
            string file = Seed(sk, ValidationJson());
            var http = Answers(HttpStatusCode.NotFound, "{\"error\":\"machine_not_found\"}");
            await Assert.ThrowsAsync<TalosApiException>(() => Client(pub, file, http).ValidateAsync());
        }

        [Fact]
        public async Task CachesALiveVerdictSoTheNextLaunchCanUseIt()
        {
            var (pub, sk) = Keypair();
            string file = Seed(sk, null); // no cached validation at all

            // A server that echoes the nonce the client actually generated.
            var live = new HttpClient(new Stub(body =>
            {
                using var doc = JsonDocument.Parse(body);
                string nonce = doc.RootElement.GetProperty("nonce").GetString()!;
                string token = Mint(sk, "validation", ValidationJson(c =>
                {
                    c["non"] = nonce;
                    c["exp"] = Now() + 600;
                }));
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(new { validation_token = token }),
                        Encoding.UTF8,
                        "application/json"),
                };
            }));

            LicenseState online = await Client(pub, file, live).ValidateAsync();
            Assert.Equal("valid", online.Decision);
            Assert.False(online.IsOffline);

            // Next launch, no network: the verdict just cached is honoured.
            LicenseState offline = await Client(pub, file).ValidateAsync();
            Assert.Equal("valid", offline.Decision);
            Assert.True(offline.IsOffline);
        }

        [Fact]
        public async Task TakesTheCheckInCadenceFromTheSignedClaimsNotTheEnvelope()
        {
            // The interval decides telemetry volume and how long a revocation
            // takes to reach an install. Reading it from the unsigned envelope
            // would let anyone in the middle tell a fleet to check in less often.
            var (pub, sk) = Keypair();
            string file = Seed(sk, ValidationJson());
            var live = new HttpClient(new Stub(body =>
            {
                using var doc = JsonDocument.Parse(body);
                string nonce = doc.RootElement.GetProperty("nonce").GetString()!;
                long now = Now();
                string token = Mint(sk, "heartbeat", JsonSerializer.Serialize(
                    new Dictionary<string, object?>
                    {
                        ["aud"] = Product,
                        ["typ"] = "heartbeat",
                        ["iat"] = now,
                        ["nbf"] = now - 5,
                        ["exp"] = now + 600,
                        ["non"] = nonce,
                        ["decision"] = "valid",
                        ["server_time"] = now,
                        ["heartbeat_interval_s"] = 42,
                    }));
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(new
                        {
                            heartbeat_token = token,
                            heartbeat_interval_s = 999, // the envelope lies
                            license_status = "valid",
                        }),
                        Encoding.UTF8,
                        "application/json"),
                };
            }));

            TalosClient c = Client(pub, file, live);
            Assert.Null(c.HeartbeatIntervalSeconds);
            await c.HeartbeatAsync();
            Assert.Equal(42, c.HeartbeatIntervalSeconds);
        }

        [Fact]
        public async Task HasNothingToFallBackOnBeforeTheFirstValidation()
        {
            var (pub, sk) = Keypair();
            string file = Seed(sk, null);
            await Assert.ThrowsAsync<HttpRequestException>(() => Client(pub, file).ValidateAsync());
        }
    }
}
