using System;
using System.IO;
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
            LicenseState beat = await client.HeartbeatAsync();
            Assert.Equal("valid", beat.Decision);

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

        private static string Env(string name)
        {
            string? v = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrEmpty(v))
                throw new InvalidOperationException($"{name} must be set for the contract test");
            return v!;
        }
    }
}
