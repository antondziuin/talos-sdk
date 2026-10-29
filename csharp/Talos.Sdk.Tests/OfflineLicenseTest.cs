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

        private static string PortableJson(Action<Dictionary<string, object?>>? tweak = null) =>
            OfflineJson("", c =>
            {
                c.Remove("fph");
                c.Remove("mpk");
                c.Remove("mid");
                c["binding"] = "portable";
                c["perpetual"] = true;
                c["exp"] = null;
                tweak?.Invoke(c);
            });

        private static StateStore SeedOnline(string path)
        {
            var fp = Fingerprint.Collect(Product, null);
            var store = new StateStore(path, Product, StateStore.KeyMaterial(fp.Components));
            Assert.True(store.Save(new StoredBinding
            {
                LicenseKeyHash = StateStore.HashLicenseKey("old-online-key"),
                ActivationSecret = "old-online-secret",
                MachineId = "old-online-machine",
                Fingerprint = fp.Composite,
                Validation = "old-online-cache",
                ReleaseSeqHighWater = 7,
            }));
            return store;
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

        private sealed class PendingResponse : HttpMessageHandler
        {
            public readonly TaskCompletionSource<bool> Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public readonly TaskCompletionSource<HttpResponseMessage> Reply = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public string? Nonce;
            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, System.Threading.CancellationToken ct)
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
                Nonce = body.RootElement.TryGetProperty("nonce", out var nonce) ? nonce.GetString() : null;
                Started.SetResult(true);
                return await Reply.Task;
            }
        }

        private static TalosClient Client(
            string statePath, string? publicKey = null, string? anchor = null, Dead? network = null,
            string? machineGuid = null, HttpMessageHandler? handler = null) =>
            new TalosClient(new TalosOptions
            {
                ProductToken = Product,
                PublicKey = publicKey ?? "",
                AnchorPublicKey = anchor,
                ServerUrl = "http://127.0.0.1:1",
                StatePath = statePath,
                HttpClient = new HttpClient(handler ?? network ?? new Dead()),
                ExtraFingerprintComponents = machineGuid == null ? null
                    : new Dictionary<string, string> { ["machine_guid"] = machineGuid },
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

        [Fact]
        public async Task TheSamePortableFileWorksOnDifferentMachinesWithoutRequestsOrNetwork()
        {
            var (pub, key) = Keypair();
            var (anchor, anchorKey) = Keypair();
            string keyset = Mint(anchorKey, "keyset", JsonSerializer.Serialize(new
            {
                aud = Product,
                iat = Now() - 60,
                keys = new[] { new { kid = "k1", purpose = "license", pk = pub, status = "active" } },
            }));
            string file = LicenseFile(Mint(key, "offline", PortableJson()), keyset);
            var network = new Dead();
            foreach (string machine in new[] { "portable-pc-a", "portable-pc-b" })
            {
                string path = TempFile("state.bin");
                TalosClient talos = Client(path, anchor: anchor, network: network, machineGuid: machine);
                Assert.False(talos.IsActivated);
                LicenseState state = await talos.LoadOfflineLicenseAsync(file);
                Assert.True(state.IsValid && state.IsOffline);
                Assert.Null(state.GraceUntil);
                Assert.Null(talos.MachineId);
                Assert.Contains("portable", Assert.Throws<TalosException>(
                    () => talos.CreateOfflineDeactivation()).Message);
                Assert.True(talos.IsActivated);
                TalosClient restarted = Client(path, anchor: anchor, network: network, machineGuid: machine);
                Assert.True((await restarted.ValidateAsync()).IsValid);
                Assert.True(restarted.IsFeatureEnabled("pro"));
            }
            Assert.Equal(0, network.Calls);
        }

        [Theory]
        [InlineData("portable")]
        [InlineData("machine")]
        public async Task AValidOfflineImportReplacesAnOnlineActivation(string binding)
        {
            var (pub, key) = Keypair();
            string path = TempFile("state.bin");
            StateStore store = SeedOnline(path);
            var network = new Dead();
            TalosClient talos = Client(path, publicKey: pub, network: network);
            string claims = binding == "portable" ? PortableJson() : OfflineJson(
                PayloadOf(talos.CreateOfflineRequest()).GetProperty("machine_pubkey").GetString()!,
                c => c["binding"] = "machine");
            Assert.True((await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(key, "offline", claims)))).IsValid);
            Assert.True((await talos.ValidateAsync()).IsValid);
            Assert.True((await Client(path, publicKey: pub, network: network).ValidateAsync()).IsValid);
            StoredBinding saved = store.Load()!;
            Assert.Equal("", saved.ActivationSecret);
            Assert.Equal("", saved.LicenseKeyHash);
            Assert.Null(saved.Validation);
            Assert.Equal(7, saved.ReleaseSeqHighWater);
            Assert.Equal(0, network.Calls);
        }

        [Theory]
        [InlineData("missing_binding")]
        [InlineData("unknown_binding")]
        [InlineData("null_binding")]
        [InlineData("missing_flag")]
        [InlineData("false_flag")]
        [InlineData("malformed_flag")]
        [InlineData("missing_exp")]
        [InlineData("malformed_exp")]
        [InlineData("bounded_exp")]
        [InlineData("business_expiry")]
        [InlineData("missing_business_expiry")]
        [InlineData("null_fph")]
        [InlineData("null_mpk")]
        [InlineData("null_mid")]
        [InlineData("missing_fid")]
        [InlineData("empty_fid")]
        [InlineData("missing_sub")]
        [InlineData("empty_sub")]
        [InlineData("missing_decision")]
        [InlineData("revoked_decision")]
        public async Task InvalidPortableFilesDoNotEraseAnOnlineActivation(string problem)
        {
            var (pub, key) = Keypair();
            string path = TempFile("state.bin");
            StateStore store = SeedOnline(path);
            TalosClient talos = Client(path, publicKey: pub);
            string claims = PortableJson(c =>
            {
                switch (problem)
                {
                    case "missing_binding": c.Remove("binding"); break;
                    case "unknown_binding": c["binding"] = "unknown"; break;
                    case "null_binding": c["binding"] = null; break;
                    case "missing_flag": c.Remove("perpetual"); break;
                    case "false_flag": c["perpetual"] = false; break;
                    case "malformed_flag": c["perpetual"] = "true"; break;
                    case "missing_exp": c.Remove("exp"); break;
                    case "malformed_exp": c["exp"] = "never"; break;
                    case "bounded_exp": c["exp"] = Now() + 86_400; break;
                    case "business_expiry":
                        c["lic"] = new Dictionary<string, object?> { ["lic_exp"] = Now() + 86_400 };
                        break;
                    case "missing_business_expiry": c["lic"] = new Dictionary<string, object?>(); break;
                    case "null_fph": c["fph"] = null; break;
                    case "null_mpk": c["mpk"] = null; break;
                    case "null_mid": c["mid"] = null; break;
                    case "missing_fid": c.Remove("fid"); break;
                    case "empty_fid": c["fid"] = " "; break;
                    case "missing_sub": c.Remove("sub"); break;
                    case "empty_sub": c["sub"] = ""; break;
                    case "missing_decision": c.Remove("decision"); break;
                    case "revoked_decision": c["decision"] = "revoked"; break;
                }
            });
            Assert.False((await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(key, "offline", claims)))).IsValid);
            Assert.Equal("old-online-secret", store.Load()!.ActivationSecret);
            Assert.Equal("old-online-cache", store.Load()!.Validation);
            Assert.Equal("old-online-machine", Client(path, publicKey: pub).MachineId);
        }

        [Fact]
        public async Task PortableBindingStillRequiresTheOriginalSignatureAndProduct()
        {
            var (pub, key) = Keypair();
            TalosClient talos = Client(TempFile("state.bin"), publicKey: pub);
            string[] parts = Mint(key, "offline", OfflineJson("machine-key")).Split('.');
            parts[3] = B64Url(Encoding.UTF8.GetBytes(PortableJson()));
            await Assert.ThrowsAsync<TalosSignatureException>(
                () => talos.LoadOfflineLicenseAsync(LicenseFile(string.Join(".", parts))));
            await Assert.ThrowsAsync<TalosSignatureException>(() => talos.LoadOfflineLicenseAsync(
                LicenseFile(Mint(key, "offline", PortableJson(c => c["aud"] = "another-product")))));
            Assert.False(talos.IsActivated);
        }

        [Theory]
        [InlineData("activate")]
        [InlineData("validate")]
        [InlineData("heartbeat")]
        public async Task OlderOnlineRepliesCannotReplaceANewPortableImport(string operation)
        {
            foreach (int status in new[] { 200, 403 })
            {
                var (pub, key) = Keypair();
                string path = TempFile("state.bin");
                StateStore store = SeedOnline(path);
                var network = new PendingResponse();
                TalosClient talos = Client(path, publicKey: pub, handler: network);
                Task<LicenseState> pending = operation == "activate" ? talos.ActivateAsync("different-key")
                    : operation == "validate" ? talos.ValidateAsync() : talos.HeartbeatAsync();
                await network.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.True((await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(key, "offline", PortableJson())))).IsValid);
                string typ = operation == "activate" ? "activation" : operation == "validate" ? "validation" : "heartbeat";
                var body = status == 403
                    ? new Dictionary<string, object?> { ["error"] = "license_revoked" }
                    : new Dictionary<string, object?>
                    {
                        [typ + "_token"] = Mint(key, typ, JsonSerializer.Serialize(new
                        {
                            aud = Product,
                            non = network.Nonce,
                            iat = Now(),
                            nbf = Now() - 5,
                            exp = Now() + 600,
                            decision = "revoked",
                            server_time = Now(),
                            lic = new { features = new { }, lic_exp = (long?)null },
                        })),
                        ["activation_secret"] = "stale-online-secret",
                        ["machine_id"] = "stale-machine",
                    };
                network.Reply.SetResult(new HttpResponseMessage((System.Net.HttpStatusCode)status)
                {
                    Content = new StringContent(JsonSerializer.Serialize(body)),
                });
                LicenseState state = await pending;
                Assert.True(state.IsValid && state.IsOffline);
                Assert.True(talos.Current!.IsValid && talos.Current.IsOffline);
                Assert.Equal("", store.Load()!.ActivationSecret);
                Assert.True((await Client(path, publicKey: pub).ValidateAsync()).IsValid);
            }
        }

        private static string Keyset(Ed25519PrivateKeyParameters anchor, string signer, long iat) =>
            Mint(anchor, "keyset", JsonSerializer.Serialize(new
            {
                aud = Product,
                iat,
                keys = new[] { new { purpose = "license", pk = signer } },
            }));

        [Fact]
        public async Task OlderEmbeddedKeysetsCannotRestoreARevokedSigner()
        {
            var (anchor, anchorKey) = Keypair();
            var (old, oldKey) = Keypair();
            var (current, currentKey) = Keypair();
            string path = TempFile("state.bin");
            StateStore store = SeedOnline(path);
            StoredBinding saved = store.Load()!;
            long issuedAt = Now();
            string currentKeyset = saved.Keyset = Keyset(anchorKey, current, issuedAt);
            Assert.True(store.Save(saved));
            TalosClient talos = Client(path, anchor: anchor);
            foreach (long replayedAt in new[] { issuedAt - 1, issuedAt })
            {
                await Assert.ThrowsAsync<TalosSignatureException>(() => talos.LoadOfflineLicenseAsync(
                    LicenseFile(Mint(oldKey, "offline", PortableJson()), Keyset(anchorKey, old, replayedAt))));
            }
            Assert.Equal(currentKeyset, store.Load()!.Keyset);
            Assert.True((await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(currentKey, "offline", PortableJson())))).IsValid);
            Assert.Equal(currentKeyset, store.Load()!.Keyset);
        }

        [Fact]
        public async Task ARejectedOfflineFileDoesNotReplaceTheCurrentTrustedKeyset()
        {
            var (anchor, anchorKey) = Keypair();
            var (current, currentKey) = Keypair();
            var (candidate, candidateKey) = Keypair();
            string path = TempFile("state.bin");
            StateStore store = SeedOnline(path);
            StoredBinding saved = store.Load()!;
            string currentKeyset = saved.Keyset = Keyset(anchorKey, current, Now() - 60);
            Assert.True(store.Save(saved));
            TalosClient talos = Client(path, anchor: anchor);
            Assert.False((await talos.LoadOfflineLicenseAsync(LicenseFile(
                Mint(candidateKey, "offline", PortableJson(c => c["decision"] = "revoked")),
                Keyset(anchorKey, candidate, Now())))).IsValid);
            Assert.Equal("old-online-secret", store.Load()!.ActivationSecret);
            Assert.True((await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(currentKey, "offline", PortableJson())))).IsValid);
            Assert.Equal(currentKeyset, store.Load()!.Keyset);
        }

        [Fact]
        public async Task OfflineStateEventsRunAfterTheLicensingLockIsReleased()
        {
            var (pub, key) = Keypair();
            TalosClient talos = Client(TempFile("state.bin"), publicKey: pub);
            bool completed = false;
            talos.GracePeriodStarted += (_, _) =>
            {
                var validation = Task.Run(() => talos.ValidateAsync());
                completed = validation.Wait(TimeSpan.FromSeconds(2)) && validation.Result.IsValid;
            };
            Assert.True((await talos.LoadOfflineLicenseAsync(LicenseFile(Mint(key, "offline", PortableJson())))).IsValid);
            Assert.True(completed, "a state event may synchronously invoke SDK work on another thread");
        }

        [Fact]
        public async Task AnOlderInFlightRefreshCannotReplaceTheNewOfflineTrust()
        {
            var (anchor, anchorKey) = Keypair();
            var (online, _) = Keypair();
            var (portable, portableKey) = Keypair();
            var (later, _) = Keypair();
            long issuedAt = Now();
            string path = TempFile("state.bin");
            StateStore store = SeedOnline(path);
            StoredBinding saved = store.Load()!;
            saved.Keyset = Keyset(anchorKey, online, issuedAt - 60);
            Assert.True(store.Save(saved));
            var network = new PendingResponse();
            TalosClient talos = Client(path, anchor: anchor, handler: network);
            Task pending = talos.RefreshKeysetAsync();
            await network.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            string portableKeyset = Keyset(anchorKey, portable, issuedAt);
            Assert.True((await talos.LoadOfflineLicenseAsync(LicenseFile(
                Mint(portableKey, "offline", PortableJson()), portableKeyset))).IsValid);
            network.Reply.SetResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new { keyset = Keyset(anchorKey, later, issuedAt + 60) })),
            });
            await pending;
            Assert.True((await talos.ValidateAsync()).IsValid);
            Assert.Equal(portableKeyset, store.Load()!.Keyset);
            Assert.True((await Client(path, anchor: anchor).ValidateAsync()).IsValid);
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
