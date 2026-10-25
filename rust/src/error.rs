use std::fmt;

/// Everything a Talos call can fail with.
///
/// The variants are the distinctions an application has to act on, and the one
/// that matters most is [`Error::Api`] against the rest. A status code from the
/// server is an *answer* — "revoked", "no such machine", "tenant suspended" —
/// and `validate` never masks it with a cached verdict. Every other failure is
/// the *absence* of an answer, which is what offline grace exists for.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A non-success HTTP response from the Talos runtime API.
    ///
    /// `code` is the server's machine-readable reason (`activation_limit_reached`,
    /// `seat_limit_reached`, `updates_not_entitled`, …) when the body carried one.
    Api {
        /// The HTTP status.
        status: u16,
        /// The server's `error` field, if the body had one.
        code: Option<String>,
    },
    /// A server response failed verification against the pinned key: a bad
    /// signature, the wrong nonce, audience or type, or an expired token.
    ///
    /// Treated like a network failure — never as "valid". A garbled or forged
    /// reply tells the client nothing.
    Signature(String),
    /// The request did not complete: no route, a refused connection, a TLS
    /// failure, or the licensing deadline ([`crate::TalosOptions::http_timeout`])
    /// passing.
    Network(String),
    /// The server answered 2xx with a body this SDK could not read.
    InvalidResponse(String),
    /// A call that needs an activation, made before one exists.
    NotActivated,
    /// The SDK was used in a way that cannot work: missing configuration, a
    /// malformed key, no artifact for this platform, a file that is not a
    /// licence.
    Usage(String),
    /// A local file could not be read or written.
    Io(std::io::Error),
}

impl Error {
    /// The HTTP status of an [`Error::Api`], or `None`.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The server's reason code of an [`Error::Api`], or `None`.
    ///
    /// ```
    /// # fn check(e: &talos_sdk::Error) {
    /// if e.code() == Some("updates_not_entitled") {
    ///     // Maintenance ran out. The application keeps working; say so.
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Api { code, .. } => code.as_deref(),
            _ => None,
        }
    }

    /// Whether this is the server's own answer rather than the lack of one.
    #[must_use]
    pub fn is_api(&self) -> bool {
        matches!(self, Error::Api { .. })
    }

    pub(crate) fn signature(msg: impl Into<String>) -> Self {
        Error::Signature(msg.into())
    }

    pub(crate) fn usage(msg: impl Into<String>) -> Self {
        Error::Usage(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Api {
                status,
                code: Some(code),
            } => write!(f, "talos api error {status}: {code}"),
            Error::Api { status, code: None } => write!(f, "talos api error {status}"),
            Error::Signature(m) => write!(f, "signature verification failed: {m}"),
            Error::Network(m) => write!(f, "network error: {m}"),
            Error::InvalidResponse(m) => write!(f, "invalid server response: {m}"),
            Error::NotActivated => f.write_str("not activated: call activate() first"),
            Error::Usage(m) => f.write_str(m),
            Error::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// `Result` with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
