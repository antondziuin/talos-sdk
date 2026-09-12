using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Talos.Sdk;
using Xunit;

namespace Talos.Sdk.Tests
{
    public class DiagnosticsTest
    {
        private sealed class NoRequests : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
                => throw new InvalidOperationException("Diagnostic reports must not use the network.");
        }

        [Fact]
        public void ReportOmitsOptionsAndUntrustedErrors()
        {
            using var http = new HttpClient(new NoRequests());
            using var client = new TalosClient(new TalosOptions
            {
                ProductToken = "tpt_PRIVATE_PRODUCT", ServerUrl = "https://user:PRIVATE_PASSWORD@example.test/PRIVATE_PATH",
                PublicKey = Convert.ToBase64String(new byte[32]), PersistState = false, HttpClient = http,
            });
            string report = client.CreateDiagnosticReport(new TalosApiException(403, "PRIVATE_ERROR_TOKEN"));
            Assert.DoesNotContain("PRIVATE", report);
            using var doc = JsonDocument.Parse(report);
            Assert.Equal(1, doc.RootElement.GetProperty("schema_version").GetInt32());
            Assert.Equal("api_error", doc.RootElement.GetProperty("error_code").GetString());
            Assert.Equal(403, doc.RootElement.GetProperty("http_status").GetInt32());
            Assert.False(client.IsActivated);
            Assert.Null(client.Current);
            Assert.DoesNotContain("PRIVATE", client.CreateDiagnosticReport(new Exception("PRIVATE_STACK")));
        }

        [Fact]
        public void ClassifiesFailuresWithoutChangingTheVerdict()
        {
            var state = new LicenseState { Decision = "grace_expired", IsOffline = true, GraceUntil = 123 };
            var report = DiagnosticReport.Create(true, true, state, null);
            Assert.Equal("grace_expired", report.Decision);
            Assert.Equal(123, report.GraceUntil);
            Assert.Contains("Reconnect", report.NextAction);
            Assert.Equal("signature_verification_failed", DiagnosticReport.Create(true, true, state, new TalosSignatureException("PRIVATE")).ErrorCode);
            Assert.Contains("devices", DiagnosticReport.Create(true, true, state, new TalosApiException(409, "activation_limit_reached")).NextAction);
            state.Decision = "valid";
            Assert.Contains("cannot identify", DiagnosticReport.Create(true, true, state, null).NextAction);
            state.Decision = "PRIVATE_VERDICT";
            Assert.Equal("unknown", DiagnosticReport.Create(true, true, state, null).Decision);
        }
    }
}
