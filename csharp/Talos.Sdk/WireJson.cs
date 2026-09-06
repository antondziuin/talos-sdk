using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Talos.Sdk
{
    // The request bodies of `/v1/client`, as types rather than as anonymous
    // objects.
    //
    // They were anonymous, which meant `JsonSerializer.Serialize` had to walk
    // them with reflection. That is the one thing a trimmed or AOT-published
    // application cannot do: the trimmer has no way to see that those types are
    // serialized, removes their members, and the app ships a licensing call that
    // sends `{}` — at run time, on a customer's machine, having built cleanly.
    // The C# README recommends NativeAOT.
    //
    // So every request has a declared shape here and a compile-time serializer in
    // `WireJson` below. Names come from the naming policy, not from thirty
    // attributes; `WireNamesTest` pins the ones that actually go over the wire.

    /// <summary>The machine fingerprint, as every client request carries it.</summary>
    internal sealed class FingerprintDto
    {
        public string Composite { get; set; } = "";

        public IReadOnlyDictionary<string, string> Components { get; set; } =
            new Dictionary<string, string>();
    }

    /// <summary>`POST /v1/client/keyset` — which product's keys to serve.</summary>
    internal sealed class KeysetReq
    {
        public string ProductToken { get; set; } = "";
    }

    /// <summary>`POST /v1/client/activate` — the one call that carries the licence key.</summary>
    internal sealed class ActivateReq
    {
        public string ProductToken { get; set; } = "";
        public string LicenseKey { get; set; } = "";
        public FingerprintDto Fingerprint { get; set; } = new FingerprintDto();
        public string Nonce { get; set; } = "";
        public string? Hostname { get; set; }
        public string? Os { get; set; }
        public string? Arch { get; set; }
        public string? AppVersion { get; set; }
        public string? SdkVersion { get; set; }
    }

    /// <summary>`POST /v1/client/validate`.</summary>
    internal sealed class ValidateReq
    {
        public string ProductToken { get; set; } = "";
        public FingerprintDto Fingerprint { get; set; } = new FingerprintDto();
        public string? ActivationSecret { get; set; }
        public string Nonce { get; set; } = "";
        public string? AppVersion { get; set; }
        public string? SdkVersion { get; set; }
    }

    /// <summary>`POST /v1/client/heartbeat`.</summary>
    internal sealed class HeartbeatReq
    {
        public string ProductToken { get; set; } = "";
        public FingerprintDto Fingerprint { get; set; } = new FingerprintDto();
        public string? ActivationSecret { get; set; }
        public string Nonce { get; set; } = "";
        public string? AppVersion { get; set; }
        public string? Os { get; set; }
        public string? Arch { get; set; }
        public string? SdkVersion { get; set; }

        /// <summary>Names the channel only when the update hint is wanted.</summary>
        public string? UpdateChannel { get; set; }
    }

    /// <summary>`POST /v1/client/deactivate`.</summary>
    internal sealed class DeactivateReq
    {
        public string ProductToken { get; set; } = "";
        public FingerprintDto Fingerprint { get; set; } = new FingerprintDto();
        public string? ActivationSecret { get; set; }
    }

    /// <summary>`POST` and `DELETE /v1/client/leases`; the nonce is absent on the release.</summary>
    internal sealed class LeaseReq
    {
        public string ProductToken { get; set; } = "";
        public FingerprintDto Fingerprint { get; set; } = new FingerprintDto();
        public string? ActivationSecret { get; set; }
        public string InstanceId { get; set; } = "";
        public string? Nonce { get; set; }
    }

    /// <summary>`POST /v1/client/updates/check`.</summary>
    internal sealed class UpdateCheckReq
    {
        public string ProductToken { get; set; } = "";
        public FingerprintDto Fingerprint { get; set; } = new FingerprintDto();
        public string? ActivationSecret { get; set; }
        public string? CurrentVersion { get; set; }
        public long? CurrentReleaseSeq { get; set; }
        public string? Channel { get; set; }
    }

    /// <summary>
    /// Compile-time serialization metadata for every request above.
    /// </summary>
    /// <remarks>
    /// The source generator emits a serializer per type at build time, so no
    /// reflection is involved and a trimmed or NativeAOT application keeps
    /// working. <c>IsAotCompatible</c> in the csproj is the other half: it turns
    /// on the analyzers that fail the build if a reflective serializer call comes
    /// back.
    /// <para>
    /// Nulls are written rather than skipped, which is what the anonymous objects
    /// did: the server reads every optional field as an <c>Option</c>, so absent
    /// and null mean the same thing there, and keeping them makes this change
    /// byte-for-byte invisible on the wire.
    /// </para>
    /// </remarks>
    [JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
    [JsonSerializable(typeof(KeysetReq))]
    [JsonSerializable(typeof(ActivateReq))]
    [JsonSerializable(typeof(ValidateReq))]
    [JsonSerializable(typeof(HeartbeatReq))]
    [JsonSerializable(typeof(DeactivateReq))]
    [JsonSerializable(typeof(LeaseReq))]
    [JsonSerializable(typeof(UpdateCheckReq))]
    internal partial class WireJson : JsonSerializerContext
    {
    }
}
