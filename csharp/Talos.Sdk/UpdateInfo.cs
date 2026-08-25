using System.Collections.Generic;

namespace Talos.Sdk
{
    /// <summary>One downloadable artifact of an available update (from a verified manifest).</summary>
    public sealed class UpdateArtifact
    {
        public string Platform { get; internal set; } = "";
        public string Arch { get; internal set; } = "";
        public string Kind { get; internal set; } = "";
        public string Filename { get; internal set; } = "";

        /// <summary>Expected size in bytes (from the signed manifest).</summary>
        public long Size { get; internal set; }

        /// <summary>Expected SHA-256, lowercase hex (from the signed manifest).</summary>
        public string Sha256 { get; internal set; } = "";

        /// <summary>
        /// Untrusted transport path; downloaded bytes are verified against
        /// <see cref="Sha256"/>. Null when no download route was advertised.
        /// </summary>
        public string? DownloadPath { get; internal set; }
    }

    /// <summary>A verified available update (all metadata comes from the signed manifest).</summary>
    public sealed class UpdateInfo
    {
        public string Version { get; internal set; } = "";
        public long ReleaseSeq { get; internal set; }
        public bool Mandatory { get; internal set; }
        public string? NotesUrl { get; internal set; }
        public IReadOnlyList<UpdateArtifact> Artifacts { get; internal set; } = new List<UpdateArtifact>();
    }

    /// <summary>Options for <see cref="TalosClient.CheckForUpdateAsync"/>.</summary>
    public sealed class CheckForUpdateOptions
    {
        /// <summary>Currently installed version (informational).</summary>
        public string? CurrentVersion { get; set; }

        /// <summary>Installed manifest <c>release_seq</c> high-water mark (anti-downgrade).</summary>
        public long? CurrentReleaseSeq { get; set; }

        /// <summary>Update channel; defaults to <c>stable</c>.</summary>
        public string? Channel { get; set; }
    }
}
