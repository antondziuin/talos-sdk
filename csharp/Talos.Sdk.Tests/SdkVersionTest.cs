using System;
using System.Reflection;
using Talos.Sdk;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// The version the SDK reports has to be the version it is.
    /// </summary>
    /// <remarks>
    /// It fills <c>machines.sdk_version</c>, the column a developer reads to
    /// answer "how many of my customers are still on the old client, and can I
    /// ship a breaking wire change?". The literal this replaced would have said
    /// <c>0.0.0</c> for every release after the first — populated, and worth
    /// nothing.
    /// </remarks>
    public class SdkVersionTest
    {
        [Fact]
        public void TracksTheAssembly()
        {
            string expected = typeof(TalosClient)
                .GetTypeInfo()
                .Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!
                .InformationalVersion;
            int plus = expected.IndexOf('+');
            if (plus >= 0) expected = expected.Substring(0, plus);

            Assert.Equal("csharp/" + expected, SdkVersion.Id);
            Assert.NotEqual("csharp/unknown", SdkVersion.Id);
        }

        [Fact]
        public void CarriesNoBuildMetadata()
        {
            // SourceLink appends "+<sha>" to the informational version. That is
            // provenance, not a version: leaving it on would split one release
            // into a distinct row per build in the adoption table.
            Assert.DoesNotContain("+", SdkVersion.Id);
        }
    }
}
