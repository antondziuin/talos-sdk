using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Talos.Sdk;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// Cross-language contract test: drives the real Rust <c>/v1/client</c> API
    /// and verifies the signed tokens with the product's actual public key.
    /// Skipped unless <c>TALOS_CONTRACT=1</c> and the config env vars are set (a
    /// running server + a demo license — see the orchestration in CI/docs).
    /// </summary>
    public class ContractTest
    {
        [Fact]
        public async Task Activate_Validate_Deactivate_Roundtrip()
        {
            if (Environment.GetEnvironmentVariable("TALOS_CONTRACT") != "1")
                return; // not configured — treat as a no-op pass

            // Pin ONLY the anchor: the demo rotated both signing keys, so the SDK
            // has no direct key and MUST learn the (rotated) license/release keys
            // from the anchor-signed keyset. Verifying proves keyset-consume.
            // A per-run state file: the point of the persistence is that it
            // outlives the client object, so it must not be the developer's own.
            string statePath = Path.Combine(Path.GetTempPath(), $"talos-state-{Guid.NewGuid():N}.bin");
            Func<TalosOptions> options = () => new TalosOptions
            {
                ProductToken = Env("TALOS_PRODUCT_TOKEN"),
                AnchorPublicKey = Env("TALOS_ANCHOR_PUBLIC_KEY"),
                ServerUrl = Env("TALOS_SERVER_URL"),
                AppVersion = "1.0.0",
                StatePath = statePath,
            };
            string licenseKey = Env("TALOS_LICENSE_KEY");
            var client = new TalosClient(options());
            Assert.False(client.IsActivated, "nothing is stored before the first activation");

            // Activate: the activation token verifies under a keyset-learned key.
            LicenseState activated = await client.ActivateAsync(licenseKey);
            Assert.True(activated.IsValid, "activation should be valid");
            Assert.True(client.IsFeatureEnabled("pro"), "the 'pro' entitlement is set");
            Assert.Equal(5, client.Current!.GetEntitlementInt("seats"));

            // Explicitly refresh the keyset (exercises the standalone endpoint),
            // then validate against the keyset-learned key.
            await client.RefreshKeysetAsync();
            LicenseState validated = await client.ValidateAsync();
            Assert.Equal("valid", validated.Decision);

            // A second re-validate still works (idempotent, seat retained).
            LicenseState again = await client.ValidateAsync();
            Assert.True(again.IsValid);

            // --- the machine binding outlives the process ---------------------
            // A second client that never calls Activate: this is the app's next
            // launch. Before the binding was persisted every start had to
            // activate again - burning a round trip the protocol exists to
            // avoid, rotating the secret out from under any other running copy,
            // and (because activate is the one client route refused for a
            // suspended tenant) taking the developer's own paying users offline
            // the moment their vendor's account was suspended.
            var restarted = new TalosClient(options());
            Assert.True(restarted.IsActivated, "the binding was restored from disk");
            Assert.Equal(client.MachineId, restarted.MachineId);
            Assert.Equal("valid", (await restarted.ValidateAsync()).Decision);

            // Activate on an existing binding re-validates instead of
            // re-activating. The proof is the FIRST client: a real activation
            // would have rotated the secret and left it holding a dead one.
            Assert.Equal("valid", (await restarted.ActivateAsync(licenseKey)).Decision);
            Assert.Equal("valid", (await client.ValidateAsync()).Decision);

            // Updates: check → verified manifest → download → SHA-256 verification.
            UpdateInfo? upd = await client.CheckForUpdateAsync(
                new CheckForUpdateOptions { CurrentVersion = Env("TALOS_CURRENT_VERSION") });
            Assert.NotNull(upd);
            Assert.Equal(Env("TALOS_UPDATE_VERSION"), upd!.Version);
            Assert.True(upd.ReleaseSeq > 0);
            Assert.NotEmpty(upd.Artifacts);

            string dest = Path.Combine(Path.GetTempPath(), $"talos-dl-{Guid.NewGuid():N}");
            UpdateArtifact got = await client.DownloadUpdateAsync(upd, dest, upd.Artifacts[0]);
            Assert.Equal(upd.Artifacts[0].Filename, got.Filename);
            Assert.Equal(got.Size, new FileInfo(dest).Length);

            // Anti-downgrade: checking with a seq at/above the latest yields no update.
            UpdateInfo? none = await client.CheckForUpdateAsync(
                new CheckForUpdateOptions { CurrentReleaseSeq = upd.ReleaseSeq });
            Assert.Null(none);

            // Heartbeat: signed decision + the telemetry source for monitoring.
            // With something subscribed it also carries the update hint, which
            // is the one path in this SDK that spans two routes and a signed
            // claim the server only sets when asked — so it is worth proving
            // against a real server rather than a stub of one.
            var announced = new List<UpdateInfo>();
            client.UpdateAvailable += (_, info) => announced.Add(info);
            LicenseState beat = await client.HeartbeatAsync();
            Assert.Equal("valid", beat.Decision);
            Assert.Single(announced);
            Assert.Equal(Env("TALOS_UPDATE_VERSION"), announced[0].Version);

            // Floating seats (the demo policy has max_concurrent_seats = 1).
            Lease lease = await client.AcquireLeaseAsync(
                new AcquireLeaseOptions { InstanceId = "inst-1", AutoRenew = false });
            Assert.Equal(1, lease.MaxSeats);
            Assert.Equal(1, lease.SeatsInUse);

            // Re-acquiring the SAME instance renews rather than taking a second seat.
            Lease renewed = await client.AcquireLeaseAsync(
                new AcquireLeaseOptions { InstanceId = "inst-1", AutoRenew = false });
            Assert.Equal(1, renewed.SeatsInUse);

            // A DIFFERENT instance is refused while the only seat is held.
            var refused = await Assert.ThrowsAsync<TalosApiException>(() =>
                client.AcquireLeaseAsync(
                    new AcquireLeaseOptions { InstanceId = "inst-2", AutoRenew = false }));
            Assert.Equal(409, refused.StatusCode);

            // Releasing frees the seat for the waiting instance.
            await client.ReleaseLeaseAsync();
            Lease second = await client.AcquireLeaseAsync(
                new AcquireLeaseOptions { InstanceId = "inst-2", AutoRenew = false });
            Assert.Equal(1, second.SeatsInUse);
            await client.ReleaseLeaseAsync();

            // Deactivate releases the seat; validating afterwards must fail
            // (machine no longer found / secret cleared).
            await client.DeactivateAsync();
            await Assert.ThrowsAsync<TalosException>(() => client.ValidateAsync());
            // Deactivation forgets the binding on disk too, or the next launch
            // would restore a seat the user just gave back.
            Assert.False(new TalosClient(options()).IsActivated);
        }

        /// <summary>
        /// A real answer, changed on the way back — what a MITM proxy or a
        /// hosts-file redirect actually does.
        /// <para>
        /// The unit tests reject a token this SDK tampered with itself, signed by
        /// a key it generated moments earlier. This one takes a verdict a real
        /// server signed with a key this client learned from a real anchor-signed
        /// keyset, flips one character of the signature, and requires the refusal
        /// anyway. That is the difference between "the verifier works on our own
        /// fixtures" and "the verifier works on the wire".
        /// </para>
        /// </summary>
        [Fact]
        public async Task RefusesAServerAnswerAProxyChangedOnTheWayBack()
        {
            if (Environment.GetEnvironmentVariable("TALOS_CONTRACT") != "1")
                return; // not configured — treat as a no-op pass

            var meddler = new Meddler();
            TalosClient client = LiveClient(meddler);
            Assert.True((await client.ActivateAsync(Env("TALOS_LICENSE_KEY"))).IsValid);

            meddler.Alter = FlipOneSignatureCharacter;
            await Assert.ThrowsAsync<TalosSignatureException>(() => client.ValidateAsync());
        }

        /// <summary>
        /// A real answer, replayed for a later request.
        /// <para>
        /// The captured verdict is genuine: signed by the server, for this
        /// machine, under a key this client trusts, and — unlike a stub — with
        /// every claim a live verdict carries. The only thing wrong with it is
        /// that it answers the previous question, which is what an attacker
        /// replaying a "valid" from before a revocation is counting on. The nonce
        /// refuses it, and this is the only test that proves the server puts the
        /// client's own nonce where the client looks for it.
        /// </para>
        /// <para>
        /// What that refusal looks like from the outside is the part worth
        /// pinning down. A reply that fails verification tells this SDK nothing,
        /// so it counts as silence rather than as a verdict: the call falls back
        /// to the cached decision and comes back marked offline. So the
        /// assertion is not "it threw" — it is that the replay did not land as a
        /// fresh check-in. If it ever did, an attacker could hold a licence in
        /// "valid" indefinitely by repeating one recording.
        /// </para>
        /// </summary>
        [Fact]
        public async Task RefusesAServerAnswerReplayedForALaterRequest()
        {
            if (Environment.GetEnvironmentVariable("TALOS_CONTRACT") != "1")
                return;

            var meddler = new Meddler();
            TalosClient client = LiveClient(meddler);
            Assert.True((await client.ActivateAsync(Env("TALOS_LICENSE_KEY"))).IsValid);

            LicenseState live = await client.ValidateAsync();
            Assert.Equal("valid", live.Decision);
            Assert.False(live.IsOffline, "the answer to its own question is a live verdict");

            // From here every answer is the recording of that one.
            string? captured = null;
            meddler.Alter = body => captured ??= body;
            _ = await client.ValidateAsync();   // captures; still answers its own nonce

            LicenseState replayed = await client.ValidateAsync();
            Assert.True(replayed.IsOffline, "a replayed answer must not count as a live verdict");
        }

        /// <summary>Flip one character of the signature segment of every Talos-compact
        /// token in a response body, leaving a token that still parses.</summary>
        private static string FlipOneSignatureCharacter(string body)
        {
            string changed = Regex.Replace(
                body,
                @"(talos\.1\.[a-z_]+\.[A-Za-z0-9_-]+\.)([A-Za-z0-9_-])",
                m => m.Groups[1].Value + (m.Groups[2].Value == "A" ? "B" : "A"));
            // A regex that matched nothing would turn this into a test that
            // asserts a valid token is valid.
            Assert.NotEqual(body, changed);
            return changed;
        }

        private static TalosClient LiveClient(Meddler meddler) => new TalosClient(new TalosOptions
        {
            ProductToken = Env("TALOS_PRODUCT_TOKEN"),
            AnchorPublicKey = Env("TALOS_ANCHOR_PUBLIC_KEY"),
            ServerUrl = Env("TALOS_SERVER_URL"),
            AppVersion = "1.0.0",
            StatePath = Path.Combine(Path.GetTempPath(), $"talos-state-{Guid.NewGuid():N}.bin"),
            HttpClient = new HttpClient(meddler),
        });

        /// <summary>
        /// The real transport, with a seam where a hostile network would be: the
        /// request reaches the actual server and the actual answer comes back,
        /// and only then is it altered.
        /// </summary>
        private sealed class Meddler : DelegatingHandler
        {
            public Func<string, string>? Alter;

            public Meddler() : base(new HttpClientHandler()) { }

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken ct)
            {
                HttpResponseMessage res = await base.SendAsync(request, ct);
                if (Alter is null) return res;
                string body = await res.Content.ReadAsStringAsync(ct);
                res.Content = new StringContent(Alter(body), Encoding.UTF8, "application/json");
                return res;
            }
        }

        private static string Env(string name)
        {
            string? v = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrEmpty(v))
                throw new InvalidOperationException($"{name} must be set for the contract test");
            return v!;
        }
    }
}
