using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Talos.Sdk;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// A licensing call that never comes back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>HttpClient</c>'s own default is 100 seconds, which is a very long time
    /// to hold a splash screen on the one code path a user cannot skip — and
    /// setting <c>HttpClient.Timeout</c> is not available when the client is
    /// shared, because it belongs to the caller and changing it would change
    /// every other request their application makes.
    /// </para>
    /// <para>
    /// The shape of the failure matters as much as the fact of it. An abort has
    /// to arrive as a <see cref="TalosException"/>: <c>ValidateAsync</c> turns a
    /// network failure into the grace-period path, and an
    /// <c>OperationCanceledException</c> escaping instead would stop the
    /// application rather than let it keep running offline.
    /// </para>
    /// </remarks>
    public class TimeoutTest
    {
        /// <summary>A handler that answers only when the request is cancelled.</summary>
        private sealed class Hangs : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException("unreachable");
            }
        }

        private static TalosOptions Options(int? timeoutMs) => new TalosOptions
        {
            ProductToken = "tpt_test",
            PublicKey = Convert.ToBase64String(new byte[32]),
            ServerUrl = "http://127.0.0.1:9",
            StatePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName(), "state.json"),
            HttpClient = new HttpClient(new Hangs()),
            HttpTimeoutMs = timeoutMs,
        };

        [Fact]
        public async Task AbandonsACallThatNeverAnswers()
        {
            using var client = new TalosClient(Options(60));
            var started = DateTime.UtcNow;
            var ex = await Assert.ThrowsAsync<TalosException>(
                () => client.ActivateAsync("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"));
            Assert.Contains("timed out", ex.Message, StringComparison.Ordinal);
            // Bounded by the option and not by the handler's patience, which is
            // infinite: without the timeout this call never returns and the
            // assertion above would hang rather than fail.
            Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(15));
        }

        [Fact]
        public async Task TheCallersOwnCancellationStaysACancellation()
        {
            // The two are told apart by whose token is signalled. A caller who
            // cancels deliberately must get an OperationCanceledException — a
            // TalosException there would be indistinguishable from a network
            // failure, and the grace-period path would treat a deliberate
            // shutdown as an outage.
            using var client = new TalosClient(Options(30_000));
            using var cts = new CancellationTokenSource();
            var task = client.ActivateAsync("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", cts.Token);
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        }
    }
}
