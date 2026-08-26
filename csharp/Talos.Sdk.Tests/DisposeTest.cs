using System;
using System.Net.Http;
using System.Threading.Tasks;
using Talos.Sdk;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// The client cleans up what it created, and leaves alone what it was given.
    /// </summary>
    /// <remarks>
    /// <c>_ownsHttp</c> recorded which of those two cases applied and was read
    /// by nothing — the disposal it was declared for was never written. The
    /// documented quickstart shape constructs a client without supplying an
    /// <c>HttpClient</c>, so it leaked a socket-holding one per instance, and
    /// <c>using (var talos = new TalosClient(...))</c> did not compile.
    /// </remarks>
    public class DisposeTest
    {
        private static TalosOptions Options(HttpClient? http = null) => new TalosOptions
        {
            ProductToken = "tpt_dispose_test",
            PublicKey = Convert.ToBase64String(new byte[32]),
            ServerUrl = "http://127.0.0.1:1",
            HttpClient = http,
            // No state file: this test is about lifetime, not persistence.
            PersistState = false,
        };

        [Fact]
        public void UsingCompilesAndDisposesTwiceSafely()
        {
            using (var talos = new TalosClient(Options()))
            {
                Assert.False(talos.IsActivated);
            }

            // Idempotent, so an explicit Dispose inside a using block is safe.
            var second = new TalosClient(Options());
            second.Dispose();
            second.Dispose();
        }

        [Fact]
        public async Task ASuppliedHttpClientSurvivesDisposal()
        {
            // The caller owns it and very likely shares it across their app.
            // Disposing someone else's HttpClient is a worse bug than leaking
            // your own: every other user of it starts failing.
            using var shared = new HttpClient();
            new TalosClient(Options(shared)).Dispose();

            // Still usable: a disposed HttpClient throws here instead.
            await Assert.ThrowsAnyAsync<Exception>(
                () => shared.GetAsync("http://127.0.0.1:1/"));
            Assert.False(await IsDisposed(shared));
        }

        private static async Task<bool> IsDisposed(HttpClient http)
        {
            try
            {
                await http.GetAsync("http://127.0.0.1:1/");
                return false;
            }
            catch (ObjectDisposedException)
            {
                return true;
            }
            catch
            {
                // Connection refused — the client is alive, nothing is listening.
                return false;
            }
        }
    }
}
