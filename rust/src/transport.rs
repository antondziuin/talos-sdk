//! The HTTP seam.
//!
//! One trait carries **every** network call the SDK makes, artifact downloads
//! included, so a corporate proxy, a custom CA bundle, request logging or a test
//! double applies uniformly. The built-in implementation (feature `ureq`, on by
//! default) is a blocking rustls client; anything else is a [`Transport`] away.

use std::io::Read;
use std::time::Duration;

/// One request the SDK wants sent.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// `GET`, `POST` or `DELETE`.
    pub method: &'static str,
    /// The absolute URL.
    pub url: String,
    /// Header name/value pairs.
    pub headers: Vec<(&'static str, String)>,
    /// The JSON body, when the request has one.
    pub body: Option<Vec<u8>>,
    /// How long the whole exchange may take, or `None` for no limit.
    ///
    /// Set on every licensing call from
    /// [`TalosOptions::http_timeout`](crate::TalosOptions::http_timeout), and
    /// `None` on an artifact download, which is bounded by the signed manifest's
    /// size instead. An implementation that ignores it has no timeout.
    pub timeout: Option<Duration>,
}

/// What a [`Transport`] hands back.
pub struct HttpResponse {
    /// The HTTP status.
    pub status: u16,
    /// The `content-length` header, if the server sent one. Only a hint: the
    /// download is capped at the signed size whatever this says.
    pub content_length: Option<u64>,
    /// The response body, streamed. A download is hashed and written as it is
    /// read rather than buffered first.
    pub body: Box<dyn Read + Send>,
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("content_length", &self.content_length)
            .finish_non_exhaustive()
    }
}

impl HttpResponse {
    /// A response with an in-memory body — what a test double returns.
    #[must_use]
    pub fn from_bytes(status: u16, body: impl Into<Vec<u8>>) -> Self {
        let body = body.into();
        HttpResponse {
            status,
            content_length: Some(body.len() as u64),
            body: Box::new(std::io::Cursor::new(body)),
        }
    }
}

/// Sends HTTP requests on the SDK's behalf.
///
/// Return `Err` only when there is no response at all — no route, a refused
/// connection, a TLS failure, a timeout. A response with a 4xx or 5xx status is
/// an `Ok` with that status: it is the server's answer, and the SDK treats it
/// very differently from silence.
pub trait Transport: Send + Sync {
    /// Send `request` and return the response, whatever its status.
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String>;
}

#[cfg(feature = "ureq")]
pub use ureq_transport::UreqTransport;

#[cfg(feature = "ureq")]
mod ureq_transport {
    use super::{HttpRequest, HttpResponse, Transport};

    /// The built-in transport: blocking, rustls, statuses returned as answers.
    ///
    /// Public so a custom [`Transport`] can wrap it — to log, to meter, or to
    /// alter answers in a test — rather than reimplement it.
    pub struct UreqTransport {
        agent: ureq::Agent,
    }

    impl Default for UreqTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    impl UreqTransport {
        /// A transport with its own connection pool.
        #[must_use]
        pub fn new() -> Self {
            let config = ureq::Agent::config_builder()
                // A 403 is `updates_not_entitled`, a 409 is a seat that is
                // taken: answers the SDK reads, not transport failures.
                .http_status_as_error(false)
                .build();
            UreqTransport {
                agent: config.into(),
            }
        }

        fn run<B: ureq::AsSendBody>(
            &self,
            request: ureq::http::Request<B>,
            timeout: Option<std::time::Duration>,
        ) -> Result<HttpResponse, String> {
            let request = self
                .agent
                .configure_request(request)
                .timeout_global(timeout)
                .build();
            let response = self.agent.run(request).map_err(|e| e.to_string())?;
            let status = response.status().as_u16();
            let content_length = response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            Ok(HttpResponse {
                status,
                content_length,
                body: Box::new(response.into_body().into_reader()),
            })
        }
    }

    impl Transport for UreqTransport {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            let mut builder = ureq::http::Request::builder()
                .method(request.method)
                .uri(&request.url);
            for (name, value) in &request.headers {
                builder = builder.header(*name, value);
            }
            match request.body {
                Some(body) => self.run(
                    builder.body(body).map_err(|e| e.to_string())?,
                    request.timeout,
                ),
                None => self.run(
                    builder.body(()).map_err(|e| e.to_string())?,
                    request.timeout,
                ),
            }
        }
    }
}
