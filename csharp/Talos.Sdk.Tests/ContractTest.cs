using System;
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

            var options = new TalosOptions
            {
                ProductToken = Env("TALOS_PRODUCT_TOKEN"),
                PublicKey = Env("TALOS_PUBLIC_KEY"),
                ServerUrl = Env("TALOS_SERVER_URL"),
                AppVersion = "1.0.0",
            };
            string licenseKey = Env("TALOS_LICENSE_KEY");
            var client = new TalosClient(options);

            // Activate: the returned activation token verifies under the pinned key.
            LicenseState activated = await client.ActivateAsync(licenseKey);
            Assert.True(activated.IsValid, "activation should be valid");
            Assert.True(client.IsFeatureEnabled("pro"), "the 'pro' entitlement is set");
            Assert.Equal(5, client.Current!.GetEntitlementInt("seats"));

            // Validate: machine-bound signed decision.
            LicenseState validated = await client.ValidateAsync();
            Assert.Equal("valid", validated.Decision);

            // A second re-validate still works (idempotent, seat retained).
            LicenseState again = await client.ValidateAsync();
            Assert.True(again.IsValid);

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
