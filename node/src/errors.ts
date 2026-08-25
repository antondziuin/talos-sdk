/** Base class for all Talos SDK errors. */
export class TalosError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TalosError";
  }
}

/**
 * A server response failed cryptographic verification against the pinned
 * product key (bad signature, wrong nonce/audience/type, or expired). Treated
 * like a network failure — never as "valid".
 */
export class TalosSignatureError extends TalosError {
  constructor(message: string) {
    super(message);
    this.name = "TalosSignatureError";
  }
}

/** A non-success HTTP response from the Talos runtime API. */
export class TalosApiError extends TalosError {
  readonly statusCode: number;
  readonly errorCode: string | undefined;

  constructor(statusCode: number, errorCode: string | undefined) {
    super(`talos api error ${statusCode}${errorCode ? `: ${errorCode}` : ""}`);
    this.name = "TalosApiError";
    this.statusCode = statusCode;
    this.errorCode = errorCode;
  }
}
