using System;

namespace Talos.Sdk
{
    /// <summary>
    /// A held floating seat. Renew before <see cref="ExpiresAt"/> or the server
    /// reclaims it (the SDK auto-renews unless told otherwise).
    /// </summary>
    public sealed class Lease
    {
        /// <summary>Server-side lease id (from the signed token).</summary>
        public string Id { get; internal set; } = "";

        /// <summary>This process's instance id.</summary>
        public string InstanceId { get; internal set; } = "";

        /// <summary>Unix seconds when the seat is reclaimed unless renewed.</summary>
        public long ExpiresAt { get; internal set; }

        /// <summary>Renew after this many seconds (server-chosen, ttl/3).</summary>
        public int RenewAfterSeconds { get; internal set; }

        public long SeatsInUse { get; internal set; }
        public int MaxSeats { get; internal set; }
    }

    /// <summary>Options for <see cref="TalosClient.AcquireLeaseAsync"/>.</summary>
    public sealed class AcquireLeaseOptions
    {
        /// <summary>
        /// Identifies this running process. Re-acquiring with the same value
        /// renews instead of taking a second seat. Defaults to a per-client id.
        /// </summary>
        public string? InstanceId { get; set; }

        /// <summary>Auto-renew in the background (default true).</summary>
        public bool AutoRenew { get; set; } = true;

        /// <summary>Invoked if a renewal fails and the seat is lost.</summary>
        public Action<string>? OnLeaseLost { get; set; }
    }
}
