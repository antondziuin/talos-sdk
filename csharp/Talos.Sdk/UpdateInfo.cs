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

    /// <summary>What applying a patch has to produce.</summary>
    public sealed class UpdateDeltaTarget
    {
        /// <summary>The <c>kind</c> of the full artifact this rebuilds (<c>installer</c>, <c>archive</c>, …).</summary>
        public string Kind { get; internal set; } = "";

        public string Filename { get; internal set; } = "";

        /// <summary>Expected size of the rebuilt file, in bytes (from the signed manifest).</summary>
        public long Size { get; internal set; }

        /// <summary>
        /// Expected SHA-256 of the rebuilt file, lowercase hex (from the signed
        /// manifest). <b>Check it after applying</b> — see
        /// <see cref="TalosClient.VerifyAppliedUpdate"/>. Verifying only the patch
        /// leaves whatever comes out of the patcher unverified, which is the whole
        /// thing the signed manifest exists to prevent.
        /// </summary>
        public string Sha256 { get; internal set; } = "";
    }

    /// <summary>
    /// A patch that turns one already-installed version into this release, from
    /// the signed manifest.
    /// </summary>
    /// <remarks>
    /// Talos hosts and signs patches; it does not produce or apply them. The diff
    /// format belongs to whatever applies it (Velopack, Squirrel, MSIX, bsdiff,
    /// <c>zstd --patch-from</c>), and this SDK deliberately does not run installers.
    /// </remarks>
    public sealed class UpdateDelta
    {
        public string Platform { get; internal set; } = "";
        public string Arch { get; internal set; } = "";

        /// <summary>The installed version this patch applies to, exactly as published.</summary>
        public string From { get; internal set; } = "";

        /// <summary><c>release_seq</c> of the version it applies to (always below this release's).</summary>
        public long FromSeq { get; internal set; }

        public string Filename { get; internal set; } = "";

        /// <summary>Expected size of the patch itself, in bytes.</summary>
        public long Size { get; internal set; }

        /// <summary>Expected SHA-256 of the patch itself, lowercase hex.</summary>
        public string Sha256 { get; internal set; } = "";

        public UpdateDeltaTarget Target { get; internal set; } = new UpdateDeltaTarget();

        /// <summary>Untrusted transport path; the bytes are verified against <see cref="Sha256"/>.</summary>
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

        /// <summary>
        /// Patches this release ships, if any. Never mixed into
        /// <see cref="Artifacts"/>: a patch is not something a host can install,
        /// and an SDK that picks "the artifact for this platform" would hand one
        /// over as if it were a build.
        /// </summary>
        public IReadOnlyList<UpdateDelta> Deltas { get; internal set; } = new List<UpdateDelta>();
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
