using System;

namespace Talos.Sdk
{
    /// <summary>Base class for all Talos SDK errors.</summary>
    public class TalosException : Exception
    {
        public TalosException(string message) : base(message) { }
    }

    /// <summary>
    /// A server response failed cryptographic verification against the pinned
    /// product key (bad signature, wrong nonce/audience/type, or expired). The
    /// SDK treats this like a network failure — never as "valid".
    /// </summary>
    public sealed class TalosSignatureException : TalosException
    {
        public TalosSignatureException(string message) : base(message) { }
    }

    /// <summary>A non-success HTTP response from the Talos runtime API.</summary>
    public sealed class TalosApiException : TalosException
    {
        public int StatusCode { get; }
        public string? Error { get; }

        public TalosApiException(int statusCode, string? error)
            : base($"talos api error {statusCode}" + (error != null ? $": {error}" : ""))
        {
            StatusCode = statusCode;
            Error = error;
        }
    }
}
