using System;
using System.Reflection;

namespace Talos.Sdk
{
    /// <summary>
    /// This SDK's own version, as reported to the server on activate and
    /// heartbeat.
    /// </summary>
    /// <remarks>
    /// Read from the assembly rather than written down. The value fills
    /// <c>machines.sdk_version</c>, which is how a developer answers "how many
    /// of my customers are still on the old client, and can I ship a breaking
    /// wire change?" — and the literal it replaces (<c>"csharp/0.0.0"</c>) would
    /// have gone on answering <c>0.0.0</c> for every release after the first,
    /// making the column look populated and mean nothing.
    /// </remarks>
    internal static class SdkVersion
    {
        /// <summary>The wire form: language tag plus version, e.g. <c>csharp/1.2.0</c>.</summary>
        internal static readonly string Id = "csharp/" + Read();

        private static string Read()
        {
            try
            {
                Assembly asm = typeof(SdkVersion).GetTypeInfo().Assembly;
                string? v = asm
                    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                    ?.InformationalVersion;
                if (string.IsNullOrEmpty(v))
                    v = asm.GetName().Version?.ToString();
                if (string.IsNullOrEmpty(v))
                    return "unknown";

                // The SDK appends "+<commit sha>" to the informational version
                // when SourceLink is on. That is build provenance, not a
                // version, and it would turn every build of one release into a
                // distinct value in the developer's adoption table.
                int plus = v!.IndexOf('+');
                return plus < 0 ? v : v.Substring(0, plus);
            }
            catch
            {
                // A trimmed or otherwise unusual host may not surface
                // attributes. An unknown version is a cosmetic gap in someone
                // else's dashboard; a throw here would fail an activation.
                return "unknown";
            }
        }
    }
}
