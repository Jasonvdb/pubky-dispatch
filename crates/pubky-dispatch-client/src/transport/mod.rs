//! How requests reach the Dispatch: plain [`Request`] and [`Response`] types and the
//! [`Transport`] trait, with the HTTPS transport (`http` feature) and a scripted one for
//! tests (`test-support`).
//!
//! A transport only carries bytes. Signing requests and checking answers is the client's
//! (Dispatch wire 7.1); the transport's own duty is where it connects (Dispatch wire 7.1, 8.2).

#[cfg(feature = "http")]
mod http;
#[cfg(feature = "test-support")]
mod mock;

#[cfg(feature = "http")]
pub use http::{HttpConfig, HttpTransport};
#[cfg(feature = "test-support")]
pub use mock::MockTransport;

use std::future::Future;
use std::pin::Pin;

pub use crate::error::TransportError;

/// A boxed future that can move between threads.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One header of a request or a response.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Header {
    /// The name, in lower case as the Dispatch sends them; names are case-insensitive (Dispatch
    /// wire 7.1).
    pub name: String,
    /// The value, exactly as sent.
    pub value: String,
}

impl Header {
    /// A header.
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }
}

/// The value of the header `name` in `headers`, compared case-insensitively. A header that
/// appears more than once reads as absent, so no check is made against one copy while
/// another is used.
pub fn header_value<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    let mut found = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let first = found.next()?;
    if found.next().is_some() {
        return None;
    }
    Some(first.value.as_str())
}

/// How long a call may take, by what it can carry. The client picks the class of every
/// call it makes ([`Request::timeout`]), from the call itself, never from its path; a
/// transport gives each class a timeout (`HttpConfig` for the HTTPS transport).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeoutClass {
    /// A call with a small answer, such as a setting change, a service-time read or an
    /// unconditional allow-list update.
    Ordinary,
    /// A potentially large transfer, such as a page, listing or upload. A batch that
    /// writes claims can return several signed claim views. Other batches can return a
    /// held signed record, shared record view or claim view in a conflict (Dispatch wire
    /// 6.3, 6.5, 7.1, 7.6).
    Bulk,
    /// The feed's long poll (Dispatch wire 7.4.4): the service holds the read for up to
    /// `wait_s` seconds, then answers a page as a [`TimeoutClass::Bulk`] read does.
    LongPoll {
        /// The longest the service holds the read, in seconds: the request's `wait`.
        wait_s: u32,
    },
}

/// A request to the Dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The method, in upper case.
    pub method: String,
    /// The Dispatch origin, `https://host[:port]`, which the request signature covers.
    pub origin: String,
    /// The path and query, exactly as signed and sent; the query is never re-encoded (Dispatch
    /// wire 7.1).
    pub path_and_query: String,
    /// The headers.
    pub headers: Vec<Header>,
    /// The body bytes.
    pub body: Vec<u8>,
    /// How long the call may take: the class the client picked for it. It isn't sent.
    pub timeout: TimeoutClass,
}

impl Request {
    /// The value of the header `name`; see [`header_value`].
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }

    /// The URL the request goes to: the origin, then the path and query.
    pub fn url(&self) -> String {
        format!("{}{}", self.origin, self.path_and_query)
    }
}

/// A response of the Dispatch, not yet checked.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The headers.
    pub headers: Vec<Header>,
    /// The body bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// The value of the header `name`; see [`header_value`].
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

/// Admission for the first local handoff of one exact signed operation body. A
/// transport checks this after its last wait, at the point it releases the request.
pub struct FirstSend {
    clock: std::sync::Arc<dyn crate::clock::Clock>,
    local_ms: u64,
    service_ms: u64,
    before_ms: u64,
    observed: std::time::Instant,
    confirmed: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for FirstSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirstSend")
            .field("before_ms", &self.before_ms)
            .finish_non_exhaustive()
    }
}

impl FirstSend {
    pub(crate) fn new(
        clock: std::sync::Arc<dyn crate::clock::Clock>,
        highest_ms: u64,
        offset_ms: i64,
        before_ms: u64,
    ) -> Self {
        let observed = std::time::Instant::now();
        let local_ms = clock.now_ms();
        Self {
            local_ms,
            clock,
            service_ms: highest_ms.max(local_ms.saturating_add_signed(offset_ms)),
            before_ms,
            observed,
            confirmed: false.into(),
        }
    }

    /// Check immediately before releasing the request. A delayed transport checks
    /// again after becoming writable. Equality is too late (Dispatch spec 10.1).
    /// Report `FirstSendExpired` to the client only if no part of this request was
    /// released. After a partial write, report an uncertain transport failure.
    ///
    /// # Errors
    ///
    /// The deadline has passed or the clocks cannot establish a timely first handoff.
    pub fn check(&self) -> Result<(), TransportError> {
        if self.confirmed() {
            return Ok(());
        }
        let now = self.clock.now_ms();
        let elapsed = now
            .checked_sub(self.local_ms)
            .ok_or(TransportError::FirstSendUnavailable)?;
        let monotonic = u64::try_from(self.observed.elapsed().as_millis()).unwrap_or(u64::MAX);
        let latest = self
            .service_ms
            .saturating_add(elapsed.max(monotonic))
            .max(now);
        if self.local_ms.abs_diff(self.service_ms)
            > pubky_dispatch_core::records::CLOCK_TOLERANCE_MS
        {
            return Err(TransportError::FirstSendUnavailable);
        }
        if latest >= self.before_ms {
            return Err(TransportError::FirstSendExpired);
        }
        Ok(())
    }

    pub(crate) fn confirm(&self) {
        self.confirmed
            .store(true, std::sync::atomic::Ordering::Release);
    }
    pub(crate) fn confirmed(&self) -> bool {
        self.confirmed.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Carries requests to a Dispatch and their responses back.
///
/// Object-safe, so a client holds an `Arc<dyn Transport>`. An implementation follows no
/// redirects and connects only where the Dispatch origin rules allow (Dispatch wire 7.1).
pub trait Transport: Send + Sync {
    /// Send one request and return its response, whatever its status.
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>>;

    /// Carry a batch whose first local handoff has a deadline. A transport that
    /// delegates or queues the request passes the check to the component releasing
    /// it. A transport without that facility leaves the request unsent.
    fn send_before<'a>(
        &'a self,
        _request: Request,
        _first: &'a FirstSend,
    ) -> BoxFuture<'a, Result<Response, TransportError>> {
        Box::pin(async { Err(TransportError::FirstSendUnavailable) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_value_is_case_insensitive() {
        let headers = vec![Header::new("Switch-Server-Time", "t")];
        assert_eq!(header_value(&headers, "switch-server-time"), Some("t"));
        assert_eq!(header_value(&headers, "switch-head"), None);
    }

    #[test]
    fn test_header_value_refuses_a_repeated_header() {
        let headers = vec![
            Header::new("switch-head", "a"),
            Header::new("Switch-Head", "b"),
        ];
        assert_eq!(header_value(&headers, "switch-head"), None);
    }
}
