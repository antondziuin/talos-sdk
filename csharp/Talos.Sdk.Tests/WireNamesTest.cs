using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Talos.Sdk;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// The field names this SDK actually puts on the wire.
    /// <para>
    /// Request bodies used to be anonymous objects whose property names <i>were</i>
    /// the wire names, written out one call site at a time. They are declared
    /// types now, serialized through a compile-time generator so a trimmed or
    /// NativeAOT application does not send an empty object — and their names come
    /// from a naming policy instead of from the source. A policy is a rule
    /// applied at a distance: rename a property, add one whose casing the rule
    /// handles differently, and the request still compiles, still serializes, and
    /// silently stops carrying a field the server needs.
    /// </para>
    /// <para>
    /// So this asserts the names on the bytes leaving the client, per route. The
    /// server answers 500 to everything: what is being tested is the request, and
    /// a body is sent before any answer comes back.
    /// </para>
    /// </summary>
    public class WireNamesTest
    {
        private const string Product = "tpt_wire_names";

        private sealed class Capture : HttpMessageHandler
        {
            public readonly Dictionary<string, string> Bodies = new Dictionary<string, string>();

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken ct)
            {
                Bodies[request.RequestUri!.AbsolutePath] = request.Content == null
                    ? ""
                    : await request.Content.ReadAsStringAsync().ConfigureAwait(false);
                return new HttpResponseMessage(HttpStatusCode.InternalServerError);
            }
        }

        /// <summary>An activated client, so every route can be reached.</summary>
        private static TalosClient Client(Capture capture)
        {
            string file = Path.Combine(
                Directory.CreateDirectory(
                    Path.Combine(Path.GetTempPath(), "talos-wire-" + Guid.NewGuid().ToString("N"))).FullName,
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
                PublicKey = Convert.ToBase64String(new byte[32]),
                ServerUrl = "http://127.0.0.1:1",
                StatePath = file,
                AppVersion = "1.0.0",
                HttpClient = new HttpClient(capture),
            });
        }

        private static void AssertNames(string body, params string[] expected)
        {
            using var doc = JsonDocument.Parse(body);
            var seen = new List<string>();
            foreach (JsonProperty p in doc.RootElement.EnumerateObject()) seen.Add(p.Name);
            Assert.Equal(expected, seen.ToArray());
        }

        [Fact]
        public async Task EveryRequestCarriesTheFieldNamesTheServerReads()
        {
            var capture = new Capture();
            var client = Client(capture);
            client.UpdateAvailable += (_, _) => { };

            // A different key from the seeded binding, so this takes the real
            // activation route rather than the re-validate shortcut.
            await Assert.ThrowsAsync<TalosApiException>(
                () => client.ActivateAsync("ZZZZZ-YYYYY-XXXXX-WWWWW-VVVVV"));
            await Assert.ThrowsAsync<TalosApiException>(() => client.ValidateAsync());
            await Assert.ThrowsAsync<TalosApiException>(() => client.HeartbeatAsync());
            await Assert.ThrowsAsync<TalosApiException>(() => client.CheckForUpdateAsync());
            await Assert.ThrowsAsync<TalosApiException>(() =>
                client.AcquireLeaseAsync(new AcquireLeaseOptions { InstanceId = "i1", AutoRenew = false }));
            await Assert.ThrowsAsync<TalosApiException>(() => client.DeactivateAsync());

            AssertNames(
                capture.Bodies["/v1/client/activate"],
                "product_token", "license_key", "fingerprint", "nonce", "hostname",
                "os", "arch", "app_version", "sdk_version");
            AssertNames(
                capture.Bodies["/v1/client/validate"],
                "product_token", "fingerprint", "activation_secret", "nonce",
                "app_version", "sdk_version");
            AssertNames(
                capture.Bodies["/v1/client/heartbeat"],
                "product_token", "fingerprint", "activation_secret", "nonce",
                "app_version", "os", "arch", "sdk_version", "update_channel");
            AssertNames(
                capture.Bodies["/v1/client/updates/check"],
                "product_token", "fingerprint", "activation_secret", "current_version",
                "current_release_seq", "channel");
            AssertNames(
                capture.Bodies["/v1/client/leases"],
                "product_token", "fingerprint", "activation_secret", "instance_id", "nonce");
            AssertNames(
                capture.Bodies["/v1/client/deactivate"],
                "product_token", "fingerprint", "activation_secret");

            // The nested block, which is the one shape every call shares.
            using var doc = JsonDocument.Parse(capture.Bodies["/v1/client/heartbeat"]);
            JsonElement fingerprint = doc.RootElement.GetProperty("fingerprint");
            Assert.True(fingerprint.TryGetProperty("composite", out _));
            Assert.True(fingerprint.TryGetProperty("components", out _));

            // Nulls are written, not dropped. The server reads every optional
            // field as an `Option`, so this changes nothing there — but it is
            // what the anonymous objects did, and keeping it is what makes the
            // move to generated serializers invisible on the wire.
            Assert.Equal(
                JsonValueKind.Null,
                JsonDocument.Parse(capture.Bodies["/v1/client/updates/check"])
                    .RootElement.GetProperty("current_release_seq").ValueKind);
        }

        [Fact]
        public void TheStateFileKeepsItsOwnNames()
        {
            // Files written by every earlier version use these, and `Load` reads
            // them field by field. The wire's snake_case policy must not reach
            // this one: a renamed key here is an install that quietly forgets its
            // activation on upgrade.
            string dir = Directory.CreateDirectory(
                Path.Combine(Path.GetTempPath(), "talos-wire-state-" + Guid.NewGuid().ToString("N"))).FullName;
            string file = Path.Combine(dir, "state.bin");
            var fp = Talos.Sdk.Fingerprint.Collect(Product, null);
            var store = new StateStore(file, Product, StateStore.KeyMaterial(fp.Components));
            var binding = new StoredBinding
            {
                LicenseKeyHash = "hash",
                ActivationSecret = "secret",
                MachineId = "m1",
                Fingerprint = fp.Composite,
                TimeHighWater = 7,
                ReleaseSeqHighWater = 9,
                PendingVersion = "1.1.0",
                PendingReleaseSeq = 11,
            };
            Assert.True(store.Save(binding));

            StoredBinding? read = store.Load();
            Assert.NotNull(read);
            Assert.Equal("secret", read!.ActivationSecret);
            Assert.Equal("hash", read.LicenseKeyHash);
            Assert.Equal(7, read.TimeHighWater);
            Assert.Equal(9, read.ReleaseSeqHighWater);
            Assert.Equal("1.1.0", read.PendingVersion);
            Assert.Equal(11, read.PendingReleaseSeq);
        }
    }
}
