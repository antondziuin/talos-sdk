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
            var options = new TalosOptions
            {
                ProductToken = Env("TALOS_PRODUCT_TOKEN"),
                AnchorPublicKey = Env("TALOS_ANCHOR_PUBLIC_KEY"),
                ServerUrl = Env("TALOS_SERVER_URL"),
                AppVersion = "1.0.0",
            };
            string licenseKey = Env("TALOS_LICENSE_KEY");
            var client = new TalosClient(options);

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

            // Deactivate releases the seat; validating afterwards must fail
            // (machine no longer found / secret cleared).
            await client.DeactivateAsync();
            await Assert.ThrowsAsync<TalosException>(() => client.ValidateAsync());
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
