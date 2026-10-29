using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// Air-gapped activation: the machine identity this SDK generates for itself,
    /// the request it writes, and the file it is handed back.
    /// <para>
    /// Distinct from <see cref="OfflineTest"/>, which is about <i>grace</i> — an
    /// install that has been online coasting on a cached verdict. Nothing here
    /// has ever seen a server, and the assertions that matter are the ones about
    /// what still binds a decision to one machine when no server will ever be
    /// asked again.
    /// </para>
    /// </summary>
    public class OfflineLicenseTest
    {
        private const string Product = "tpt_offline_file_test";

        private static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        private static string Composite() => Fingerprint.Collect(Product, null).Composite;

        private static (string PubB64, Ed25519PrivateKeyParameters Sk) Keypair()
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair pair = gen.GenerateKeyPair();
            return (
                Convert.ToBase64String(((Ed25519PublicKeyParameters)pair.Public).GetEncoded()),
                (Ed25519PrivateKeyParameters)pair.Private);
        }

        private static string B64Url(byte[] b) =>
            Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        private static byte[] B64UrlDecode(string s)
        {
            string t = s.Replace('-', '+').Replace('_', '/');
            switch (t.Length % 4)
            {
                case 2: t += "=="; break;
                case 3: t += "="; break;
            }
            return Convert.FromBase64String(t);
        }

        private static string Mint(Ed25519PrivateKeyParameters sk, string typ, string payloadJson)
        {
            string prefix = $"talos.1.{typ}." + B64Url(Encoding.UTF8.GetBytes(payloadJson));
            var signer = new Ed25519Signer();
            signer.Init(true, sk);
            byte[] bytes = Encoding.ASCII.GetBytes(prefix);
            signer.BlockUpdate(bytes, 0, bytes.Length);
            return prefix + "." + B64Url(signer.GenerateSignature());
        }

        /// <summary>The claims the portal signs into a <c>typ=offline</c> file.</summary>
        private static string OfflineJson(string mpk, Action<Dictionary<string, object?>>? tweak = null)
        {
            long now = Now();
            var claims = new Dictionary<string, object?>
            {
                ["aud"] = Product,
                ["typ"] = "offline",
                ["sub"] = "01a07b9c-0000-7000-8000-000000000001",
                ["iat"] = now - 60,
                ["nbf"] = now - 60,
                ["exp"] = now + 90 * 86_400,
                ["non"] = "the-nonce-the-request-carried",
                ["decision"] = "valid",
                ["server_time"] = now - 60,
                ["fph"] = Composite(),
                ["mpk"] = mpk,
                ["mid"] = "m-air-1",
                ["fid"] = "f-air-1",
                ["lic"] = new Dictionary<string, object?>
                {
                    ["features"] = new Dictionary<string, object?> { ["pro"] = true },
                    ["lic_exp"] = null,
                },
            };
            tweak?.Invoke(claims);
            return JsonSerializer.Serialize(claims);
        }

        private static string TempFile(string name) => Path.Combine(
            Directory.CreateDirectory(
                Path.Combine(Path.GetTempPath(), "talos-air-" + Guid.NewGuid().ToString("N"))).FullName,
            name);

        /// <summary><c>license.talos</c>, as the portal hands it back.</summary>
        private static string LicenseFile(string token, string? keyset = null)
        {
            string path = TempFile("license.talos");
            File.WriteAllText(path, JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["v"] = 1,
                ["kind"] = Offline.LicenseFileKind,
                ["token"] = token,
                ["keyset"] = keyset,
            }));
            return path;
        }

        /// <summary>A network that is simply not there — which is the whole point.</summary>
        private sealed class Dead : HttpMessageHandler
        {
            public int Calls { get; private set; }
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, System.Threading.CancellationToken ct)
            {
                Calls++;
                throw new HttpRequestException("ENOTFOUND");
            }
        }

        private static TalosClient Client(
            string statePath, string? publicKey = null, string? anchor = null, Dead? network = null) =>
            new TalosClient(new TalosOptions
            {
                ProductToken = Product,
                PublicKey = publicKey ?? "",
                AnchorPublicKey = anchor,
                ServerUrl = "http://127.0.0.1:1",
                StatePath = statePath,
                HttpClient = new HttpClient(network ?? new Dead()),
            });

        private static JsonElement PayloadOf(OfflineDocument doc)
        {
            using var parsed = JsonDocument.Parse(B64UrlDecode(doc.Req));
            return parsed.RootElement.Clone();
        }

        // ---- the request -----------------------------------------------------

        [Fact]
        public void TheRequestIsSignedByTheKeyItNamesAndCarriesThisMachinesFingerprint()
        {
            var (pub, _) = Keypair();
            OfflineDocument doc = Client(TempFile("state.bin"), publicKey: pub)
                .CreateOfflineRequest("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");
            Assert.Equal(Offline.RequestDomain, doc.Kind);

            JsonElement payload = PayloadOf(doc);
            Assert.Equal(Product, payload.GetProperty("product_token").GetString());
            Assert.Equal(
                Composite(), payload.GetProperty("fingerprint").GetProperty("composite").GetString());
            Assert.Equal(
                "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", payload.GetProperty("license_key").GetString());

            // The document is self-certifying: the key that signed it is named
            // inside what it signed, which is what makes the request worth
            // anything at all to a portal that has never met this machine.
            byte[] raw = Convert.FromBase64String(payload.GetProperty("machine_pubkey").GetString()!);
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(raw, 0));
            byte[] msg = Encoding.ASCII.GetBytes(
                Offline.RequestDomain + ".1." + doc.Req);
            verifier.BlockUpdate(msg, 0, msg.Length);
            Assert.True(verifier.VerifySignature(B64UrlDecode(doc.Sig)));
        }

        [Fact]
        public void TheRequestKeepsOneIdentityAcrossCallsAndRestarts()
        {
            var (pub, _) = Keypair();
            string state = TempFile("state.bin");
            JsonElement first = PayloadOf(Client(state, publicKey: pub).CreateOfflineRequest());
            JsonElement second = PayloadOf(Client(state, publicKey: pub).CreateOfflineRequest());
            // A second identity would mean the file the vendor is about to sign
            // is bound to a key this install has already replaced.
            Assert.Equal(
                first.GetProperty("machine_pubkey").GetString(),
                second.GetProperty("machine_pubkey").GetString());
            Assert.NotEqual(
                first.GetProperty("nonce").GetString(), second.GetProperty("nonce").GetString());
        }

        [Fact]
        public void TheRequestSerialisesToTheDocumentTheServerReads()
        {
            var (pub, _) = Keypair();
            OfflineDocument doc = Client(TempFile("state.bin"), publicKey: pub).CreateOfflineRequest();
            using var parsed = JsonDocument.Parse(doc.ToJson());
            JsonElement root = parsed.RootElement;
            // Four fields, spelled the way the portal route deserialises them —
            // and produced by the source-generated serializer, so a trimmed host
            // writes the same bytes rather than an empty envelope.
            Assert.Equal(1, root.GetProperty("v").GetInt32());
            Assert.Equal(Offline.RequestDomain, root.GetProperty("kind").GetString());
            Assert.Equal(doc.Req, root.GetProperty("req").GetString());
            Assert.Equal(doc.Sig, root.GetProperty("sig").GetString());
        }

        // ---- loading a file --------------------------------------------------

        /// <summary>A client that has produced a request, and its machine key.</summary>
        private static (TalosClient Talos, string Mpk, string State, Ed25519PrivateKeyParameters Key)
            Requested()
        {
            var (pub, sk) = Keypair();
            string state = TempFile("state.bin");
            TalosClient talos = Client(state, publicKey: pub);
            string mpk = PayloadOf(talos.CreateOfflineRequest())
                .GetProperty("machine_pubkey").GetString()!;
            return (talos, mpk, state, sk);
        }

        [Fact]
        public async Task LicensesTheMachineItWasIssuedForWithNoNetworkAtAll()
        {
            var (talos, mpk, _, key) = Requested();
            LicenseState state = await talos.LoadOfflineLicenseAsync(
                LicenseFile(Mint(key, "offline", OfflineJson(mpk))));
            Assert.Equal("valid", state.Decision);
            Assert.True(state.IsValid);
            Assert.True(state.IsOffline);
            Assert.True(state.IsFeatureEnabled("pro"));
            // No cadence to return to, and the file's own horizon bounds it.
            Assert.Null(state.RevalidateAfter);
            Assert.True(state.GraceUntil > Now());
            Assert.True(talos.IsActivated);
            Assert.Equal("m-air-1", talos.MachineId);
        }

        [Fact]
        public async Task SurvivesARestartAndValidateAnswersFromTheFile()
        {
            var (pub, key) = Keypair();
            string state = TempFile("state.bin");
            TalosClient talos = Client(state, publicKey: pub);
            string mpk = PayloadOf(talos.CreateOfflineRequest())
                .GetProperty("machine_pubkey").GetString()!;
            await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(key, "offline", OfflineJson(mpk))));

            // A fresh client over the same state: this is every launch after the
            // first, and it must not need the file again or a server that is not
            // there.
            TalosClient restarted = Client(state, publicKey: pub);
            Assert.True(restarted.IsActivated);
            LicenseState verdict = await restarted.ValidateAsync();
            Assert.Equal("valid", verdict.Decision);
            Assert.True(verdict.IsOffline);
        }

        [Fact]
        public async Task ExplicitlyPerpetualFilesSurviveDecadesAndOfflineRestarts()
        {
            var (pub, key) = Keypair();
            string path = TempFile("state.bin");
            var network = new Dead();
            TalosClient talos = Client(path, publicKey: pub, network: network);
            string mpk = PayloadOf(talos.CreateOfflineRequest())
                .GetProperty("machine_pubkey").GetString()!;
            long issued = Now() - 80L * 365 * 86_400;
            LicenseState state = await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(
                key, "offline", OfflineJson(mpk, c =>
                {
                    c["iat"] = issued;
                    c["nbf"] = issued;
                    c["server_time"] = issued;
                    c["exp"] = null;
                    c["perpetual"] = true;
                }))));
            Assert.True(state.IsValid);
            Assert.Null(state.GraceUntil);
            Assert.Null(state.LicenseExpiresAt);

            TalosClient restarted = Client(path, publicKey: pub, network: network);
            LicenseState verdict = await restarted.ValidateAsync();
            Assert.True(verdict.IsValid);
            Assert.True(verdict.IsOffline);
            Assert.True(verdict.IsFeatureEnabled("pro"));
            Assert.Null(verdict.GraceUntil);
            Assert.Equal(0, network.Calls);
        }

        [Theory]
        [InlineData("missing_flag")]
        [InlineData("missing_exp")]
        [InlineData("malformed_exp")]
        [InlineData("malformed_flag")]
        [InlineData("business_expiry")]
        [InlineData("missing_business_expiry")]
        [InlineData("bounded_expired")]
        public async Task InvalidPerpetualFilesFailClosed(string problem)
        {
            var (talos, mpk, _, key) = Requested();
            LicenseState state = await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(
                key, "offline", OfflineJson(mpk, c =>
                {
                    c["exp"] = null;
                    c["perpetual"] = true;
                    switch (problem)
                    {
                        case "missing_flag": c.Remove("perpetual"); break;
                        case "missing_exp": c.Remove("exp"); break;
                        case "malformed_exp": c["exp"] = "never"; break;
                        case "malformed_flag": c["perpetual"] = "true"; break;
                        case "business_expiry":
                            c["lic"] = new Dictionary<string, object?> { ["lic_exp"] = Now() + 86_400 };
                            break;
                        case "missing_business_expiry":
                            c["lic"] = new Dictionary<string, object?>();
                            break;
                        case "bounded_expired": c["exp"] = Now() - 1; break;
                    }
                }))));
            Assert.Equal("offline_file_expired", state.Decision);
            Assert.False(state.IsValid);
        }

        [Fact]
        public async Task RefusesAFileCutForAnotherMachinesFingerprint()
        {
            var (talos, mpk, _, key) = Requested();
            LicenseState state = await talos.LoadOfflineLicenseAsync(LicenseFile(
                Mint(key, "offline", OfflineJson(mpk, c => c["fph"] = "fp2:some-other-machine"))));
            // The fingerprint is what stops the whole state directory being
            // copied to a second computer, where the machine key would come along
            // with it.
            Assert.Equal("machine_mismatch", state.Decision);
            Assert.False(state.IsValid);
        }

        [Fact]
        public async Task RefusesAFileCutForAnotherMachinesKey()
        {
            var (talos, _, _, key) = Requested();
            var (somebodyElse, _) = Keypair();
            LicenseState state = await talos.LoadOfflineLicenseAsync(
                LicenseFile(Mint(key, "offline", OfflineJson(somebodyElse))));
            // And the key is what stops the file alone being worth anything: a
            // file lifted off a colleague's laptop names a key this install
            // cannot hold.
            Assert.Equal("machine_mismatch", state.Decision);
        }

        [Fact]
        public async Task DistinguishesTheFileRunningOutFromTheLicenceRunningOut()
        {
            var (talos, mpk, _, key) = Requested();
            LicenseState expired = await talos.LoadOfflineLicenseAsync(
                LicenseFile(Mint(key, "offline", OfflineJson(mpk, c => c["exp"] = Now() - 1))));
            Assert.Equal("offline_file_expired", expired.Decision);

            var (other, mpk2, _, key2) = Requested();
            LicenseState ended = await other.LoadOfflineLicenseAsync(LicenseFile(Mint(
                key2,
                "offline",
                OfflineJson(mpk2, c => c["lic"] = new Dictionary<string, object?>
                {
                    ["features"] = new Dictionary<string, object?>(),
                    ["lic_exp"] = Now() - 1,
                }))));
            // Same symptom for the user, different remedy: a new file versus a
            // renewal.
            Assert.Equal("expired", ended.Decision);
            Assert.True(ended.LicenseExpiresAt < Now());
        }

        [Fact]
        public async Task RefusesToOutliveItsExpiryByWindingTheClockBack()
        {
            var (talos, mpk, _, key) = Requested();
            // A file issued with a server time a week in the future: the only
            // server clock this install will ever see, and the mark it is held to.
            LicenseState state = await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(
                key,
                "offline",
                OfflineJson(mpk, c =>
                {
                    c["iat"] = Now() + 7 * 86_400;
                    c["server_time"] = Now() + 7 * 86_400;
                }))));
            Assert.Equal("valid", state.Decision);

            // Now the clock is behind what we have already seen. Nothing has run
            // out — the machine is lying about the time, and saying so is
            // different from reporting a licence problem the user cannot act on.
            LicenseState again = await talos.ValidateAsync();
            Assert.Equal("clock_tampered", again.Decision);
        }

        [Fact]
        public async Task ThrowsForAFileThatIsNotALicenceRatherThanReturningAVerdict()
        {
            var (talos, mpk, _, _) = Requested();
            var (_, someoneElsesKey) = Keypair();

            // A signature under a key this product does not use.
            await Assert.ThrowsAsync<TalosSignatureException>(() =>
                talos.LoadOfflineLicenseAsync(
                    LicenseFile(Mint(someoneElsesKey, "offline", OfflineJson(mpk)))));

            // Another product's file. Verdicts are about *this* licence; a file
            // for a different application is a mistake in what was copied, not a
            // decision.
            var (_, _, _, key) = Requested();
            await Assert.ThrowsAsync<TalosSignatureException>(() =>
                talos.LoadOfflineLicenseAsync(LicenseFile(
                    Mint(key, "offline", OfflineJson(mpk, c => c["aud"] = "tpt_another_app")))));

            // Not one of ours at all.
            string junk = TempFile("license.talos");
            File.WriteAllText(junk, "not json");
            var e = await Assert.ThrowsAsync<TalosException>(
                () => talos.LoadOfflineLicenseAsync(junk));
            Assert.Contains("offline licence file", e.Message);

            // And a path that is not there names the file rather than throwing an
            // IOException from underneath the SDK.
            var missing = await Assert.ThrowsAsync<TalosException>(
                () => talos.LoadOfflineLicenseAsync(Path.Combine(Path.GetTempPath(), "nope.talos")));
            Assert.Contains("cannot read", missing.Message);
        }

        [Fact]
        public async Task HandsTheSeatBackAndDropsTheLicenceBeforeTheReceiptExists()
        {
            var (pub, key) = Keypair();
            string state = TempFile("state.bin");
            TalosClient talos = Client(state, publicKey: pub);
            string mpk = PayloadOf(talos.CreateOfflineRequest())
                .GetProperty("machine_pubkey").GetString()!;
            await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(key, "offline", OfflineJson(mpk))));

            OfflineDocument receipt = talos.CreateOfflineDeactivation();
            Assert.Equal(Offline.ReceiptDomain, receipt.Kind);
            JsonElement payload = PayloadOf(receipt);
            Assert.Equal("f-air-1", payload.GetProperty("fid").GetString());
            Assert.Equal("m-air-1", payload.GetProperty("mid").GetString());
            Assert.Equal(Composite(), payload.GetProperty("fph").GetString());

            // Signed by the same key the file is bound to — which is the only
            // reason a server that has never spoken to this machine can believe
            // it.
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(Convert.FromBase64String(mpk), 0));
            byte[] msg = Encoding.ASCII.GetBytes(
                Offline.SignedMessage(Offline.ReceiptDomain, receipt.Req));
            verifier.BlockUpdate(msg, 0, msg.Length);
            Assert.True(verifier.VerifySignature(B64UrlDecode(receipt.Sig)));

            // The licence is gone here, not when the vendor gets round to the
            // upload: an application that writes the file, loses it, or never
            // sends it has still stopped using the seat it is giving up.
            Assert.False(talos.IsActivated);
            TalosClient restarted = Client(state, publicKey: pub);
            Assert.False(restarted.IsActivated);
            await Assert.ThrowsAsync<TalosException>(() => restarted.ValidateAsync());
        }

        [Fact]
        public void RefusesToWriteAReceiptWhenThereIsNoOfflineLicenceToHandBack()
        {
            var (talos, _, _, _) = Requested();
            // A document saying otherwise would be a lie the vendor acts on: a
            // seat freed for an install that is still running.
            var e = Assert.Throws<TalosException>(() => talos.CreateOfflineDeactivation());
            Assert.Contains("no offline licence", e.Message);
        }

        [Fact]
        public async Task VerifiesAgainstAKeysetCarriedInsideTheFileWithOnlyTheAnchorPinned()
        {
            // The load-bearing case for an air-gapped install: pinning the anchor
            // is what survives key rotation, and an anchor-only client has no
            // licence key at all until it fetches a keyset — from a server it
            // cannot reach. So the file brings one.
            var (anchorPub, anchorSk) = Keypair();
            var (signingPub, signingSk) = Keypair();
            string state = TempFile("state.bin");
            TalosClient talos = Client(state, anchor: anchorPub);
            string mpk = PayloadOf(talos.CreateOfflineRequest())
                .GetProperty("machine_pubkey").GetString()!;

            string keyset = Mint(anchorSk, "keyset", JsonSerializer.Serialize(
                new Dictionary<string, object?>
                {
                    ["v"] = 1,
                    ["typ"] = "keyset",
                    ["aud"] = Product,
                    ["iat"] = Now() - 60,
                    ["anchor_kid"] = "anchor1",
                    ["keys"] = new[]
                    {
                        new Dictionary<string, object?>
                        {
                            ["kid"] = "k1",
                            ["purpose"] = "license",
                            ["pk"] = signingPub,
                            ["status"] = "active",
                        },
                    },
                }));
            LicenseState verdict = await talos.LoadOfflineLicenseAsync(
                LicenseFile(Mint(signingSk, "offline", OfflineJson(mpk)), keyset));
            Assert.Equal("valid", verdict.Decision);
        }
    }
}
