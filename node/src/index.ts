export {
  TalosClient,
  LicenseState,
  verifyAppliedUpdate,
  type TalosOptions,
  type FetchLike,
  type FetchResponseLike,
  type UpdateInfo,
  type UpdateArtifact,
  type UpdateDelta,
  type UpdateDeltaTarget,
  type DeltaOptions,
  type DownloadProgress,
  type DownloadProgressCallback,
  type CheckForUpdateOptions,
  type Lease,
  type AcquireLeaseOptions,
  type CheckInOptions,
  type TalosEventName,
  type TalosEventMap,
  type LicenseListener,
} from "./client.js";
export { TalosError, TalosSignatureError, TalosApiError } from "./errors.js";
export { collectFingerprint, type FingerprintData } from "./fingerprint.js";
export { defaultStatePath, hashLicenseKey, StateStore, type StoredBinding } from "./state.js";
export { verifyToken, verifyManifest, verifyKeyset, publicKeyFromBase64 } from "./talos-compact.js";
/**
 * The air-gapped document format. `SignedDoc` is what
 * {@link TalosClient.createOfflineRequest} returns and what gets written to
 * `talos-request.json`; the two tags are exported so a host that builds its own
 * upload UI can label and recognise the files rather than matching strings it
 * copied out of the docs.
 */
export {
  LICENSE_FILE_KIND,
  RECEIPT_DOMAIN,
  REQUEST_DOMAIN,
  type SignedDoc,
} from "./offline.js";
