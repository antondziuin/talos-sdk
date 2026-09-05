using System.Text.Json;
using Talos.Sdk;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// Reading an entitlement bag that is not booleans and integers.
    /// </summary>
    /// <remarks>
    /// The bag is server-defined free-form JSON. The C# SDK could answer "is
    /// this on" and "how many", and for anything else — a tier name, a list of
    /// modules, a nested object — handed back a raw <c>JsonElement</c> and a
    /// <c>TryGetProperty</c> call for the caller to write. The Node SDK has had
    /// <c>getEntitlement</c> since it shipped, so this was also two clients
    /// disagreeing about what an entitlement is.
    /// </remarks>
    public class EntitlementTest
    {
        private static LicenseState WithFeatures(string json)
        {
            using var doc = JsonDocument.Parse(json);
            return new LicenseState { Features = doc.RootElement.Clone() };
        }

        [Fact]
        public void ReadsValuesThatAreNeitherFlagsNorCounts()
        {
            var state = WithFeatures(
                """{"tier":"pro","seats":5,"beta":false,"modules":["a","b"]}""");

            Assert.Equal("pro", state.GetEntitlementString("tier"));
            Assert.Equal(5, state.GetEntitlementInt("seats"));
            // The general accessor is what makes a shape the SDK never
            // anticipated usable at all.
            var modules = state.GetEntitlement("modules");
            Assert.NotNull(modules);
            Assert.Equal(JsonValueKind.Array, modules!.Value.ValueKind);
            Assert.Equal(2, modules.Value.GetArrayLength());
        }

        [Fact]
        public void TellsAbsentApartFromFalse()
        {
            var state = WithFeatures("""{"beta":false}""");

            // `IsFeatureEnabled` folds these together on purpose — a gate wants
            // one answer. Code that has to distinguish "not licensed for it"
            // from "licensed and switched off" needs them apart, and that is
            // the whole reason both exist.
            Assert.False(state.IsFeatureEnabled("beta"));
            Assert.False(state.IsFeatureEnabled("missing"));
            Assert.Equal(false, state.GetEntitlementBool("beta"));
            Assert.Null(state.GetEntitlementBool("missing"));
        }

        [Fact]
        public void RefusesToCoerceAcrossTypes()
        {
            var state = WithFeatures("""{"tier":7,"seats":"many"}""");

            // An entitlement that changed shape server-side should read as
            // absent rather than as a plausible wrong answer: `"7"` would
            // compare false against every tier name the application knows, and
            // it would do so without anything looking wrong.
            Assert.Null(state.GetEntitlementString("tier"));
            Assert.Null(state.GetEntitlementInt("seats"));
            Assert.Null(state.GetEntitlementBool("tier"));
        }

        [Fact]
        public void AnEmptyBagAnswersNullRatherThanThrowing()
        {
            // The state a verdict carries before any entitlement is set, and
            // after a heartbeat, which does not carry the bag at all.
            var state = new LicenseState();
            Assert.Null(state.GetEntitlement("anything"));
            Assert.Null(state.GetEntitlementString("anything"));
            Assert.Null(state.GetEntitlementBool("anything"));
            Assert.False(state.IsFeatureEnabled("anything"));
        }
    }
}
