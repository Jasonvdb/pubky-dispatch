//! How every answer is signed (Switch wire 7.1): the response signature over its status,
//! the request it answers as the service received it, `Switch-Server-Time`, the head field
//! of the `Switch-Head` text as sent and the body, with the key the
//! verdict of the account and its mark gives (Switch wire 7.3, Table 2), or the service key
//! for an answer the service can't tie to an account. Every answer is signed, made last,
//! once the body is whole.

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use pubky_switch_core::{
    chain::SignedHead,
    enc::b64,
    http::{self as wire_http, BodyField, ReceivedHeaders, ReceivedRequest, header},
    time::rfc3339,
};

use super::{Answer, Service};
use crate::{
    http::{Refusal, SwitchRequest, SwitchResponse, error::ApiError},
    keys::{ServiceSigner, sign_head},
    store::AccountTxn,
};

/// The request a response answers, exactly as the service received it (Switch wire 7.1),
/// built once per request from what the transport received, before the service routes it.
///
/// The body field comes from what was received, never from a call site: a [`SwitchRequest`]
/// holds a body the transport read whole, so it binds the body's hash; a [`Refusal`] binds
/// it only where the transport read the body, so a body over its cap binds the empty field.
/// The public read binds no header, by its call, in the core
/// ([`received_request`](wire_http::received_request)).
#[derive(Debug)]
pub(super) struct Received<'a> {
    method: &'a str,
    path_and_query: &'a str,
    origin: &'a str,
    body: BodyField,
    headers: ReceivedHeaders,
}

/// The headers of `map` a received request covers, each value in the order received.
fn received_headers(map: &HeaderMap) -> ReceivedHeaders {
    ReceivedHeaders::of(
        map.iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes())),
    )
}

impl<'a> Received<'a> {
    /// A request the transport read whole, at the switch origin `origin`.
    pub(super) fn read(request: &'a SwitchRequest, origin: &'a str) -> Self {
        Received {
            method: &request.method,
            path_and_query: &request.path_and_query,
            origin,
            body: BodyField::read(&request.body),
            headers: received_headers(&request.headers),
        }
    }

    /// A request the transport refused, at the switch origin `origin`: an unknown route,
    /// whose body it read, or a body over its call's cap, which it didn't (Switch wire 7.1).
    pub(super) fn refused(refusal: &'a Refusal, origin: &'a str) -> Self {
        let (method, path_and_query, headers, body) = match refusal {
            Refusal::UnknownRoute {
                method,
                path_and_query,
                headers,
                body,
            } => (method, path_and_query, headers, BodyField::read(body)),
            Refusal::TooLarge {
                method,
                path_and_query,
                headers,
                ..
            } => (method, path_and_query, headers, BodyField::NotRead),
        };
        Received {
            method,
            path_and_query,
            origin,
            body,
            headers: received_headers(headers),
        }
    }

    /// The header rule it breaks, as its refusal's reason: a signed request header sent more
    /// than once, or present with a value empty or not printable ASCII (Switch wire 7.1
    /// "Each header once, as text").
    pub(super) fn broken_header_rule(&self) -> Option<&'static str> {
        self.headers.broken_rule()
    }

    /// The request every answer to it signs.
    pub(super) fn asked(&self) -> Asked<'_> {
        Asked(ReceivedRequest {
            method: self.method,
            path_and_query: self.path_and_query,
            body: self.body,
            origin: self.origin,
            headers: &self.headers,
        })
    }
}

/// The request an answer answers, as the response signature covers it ([`Received`]).
#[derive(Clone, Copy, Debug)]
pub(super) struct Asked<'a>(ReceivedRequest<'a>);

/// Sign `answer` (Switch wire 7.1): the response signature over its status, the request it
/// answers as the service received it, `Switch-Server-Time`, the head field of the
/// `Switch-Head` text as sent and the body.
pub(super) fn sign_answer(
    signer: &ServiceSigner,
    asked: Asked<'_>,
    time_ms: u64,
    answer: Answer,
) -> SwitchResponse {
    let server_time = rfc3339(time_ms);
    // The head's header text, signed exactly as it is sent.
    let head = answer
        .head
        .as_ref()
        .and_then(|head| HeaderValue::try_from(head.to_header()).ok());
    let signature = wire_http::sign_response(
        signer,
        &wire_http::ResponseParts {
            status: answer.status,
            request: asked.0,
            server_time: &server_time,
            head: head.as_ref().and_then(|value| value.to_str().ok()),
            body: &answer.body,
        },
    );
    let mut headers = Vec::new();
    let mut put = |name: &'static str, value: String| {
        if let Ok(value) = HeaderValue::try_from(value) {
            headers.push((HeaderName::from_static(name), value));
        }
    };
    put(header::SERVICE_SIGNATURE, b64(&signature));
    put(header::SERVER_TIME, server_time);
    if let Some(seconds) = answer.retry_after {
        put(header::RETRY_AFTER, seconds.to_string());
    }
    if answer.cacheable {
        put("cache-control", "public, max-age=60".into());
    }
    if answer.no_store {
        put("cache-control", "no-store".into());
    }
    if let Some(head) = head {
        headers.push((HeaderName::from_static(header::HEAD), head));
    }
    SwitchResponse {
        status: answer.status,
        headers,
        body: answer.body,
    }
}

impl Service {
    /// `error` signed with `signer` at `time_ms`, without a head.
    pub(super) fn signed_error(
        signer: &ServiceSigner,
        asked: Asked<'_>,
        time_ms: u64,
        error: &ApiError,
    ) -> SwitchResponse {
        sign_answer(signer, asked, time_ms, Answer::error(error))
    }

    /// `error` signed with the service key at `time_ms`, without a head: an answer the
    /// service can't tie to an account, at the time base, or one whose verdict's key it
    /// doesn't hold (Switch wire 7.1).
    pub(super) fn service_error(
        &self,
        asked: Asked<'_>,
        time_ms: u64,
        error: &ApiError,
    ) -> SwitchResponse {
        Self::signed_error(&self.keys.current(), asked, time_ms, error)
    }

    /// The signer of `key`, the key the verdict answers with; `None` when the key store
    /// doesn't hold it.
    pub(super) fn signer_of(&self, key: &[u8; 32]) -> Option<ServiceSigner> {
        let signer = self.keys.signer_for(key);
        if signer.is_none() {
            tracing::error!("the key the verdict answers an account with isn't in the key store");
        }
        signer
    }

    /// `error` signed with `key` at `time_ms`, without a head, or a `503` with the service
    /// key at the same time when the key store doesn't hold `key`.
    pub(super) fn keyed_error(
        &self,
        key: &[u8; 32],
        asked: Asked<'_>,
        time_ms: u64,
        error: &ApiError,
    ) -> SwitchResponse {
        match self.signer_of(key) {
            Some(signer) => Self::signed_error(&signer, asked, time_ms, error),
            None => self.service_error(
                asked,
                time_ms,
                &ApiError::unavailable("7.6: a temporary failure"),
            ),
        }
    }

    /// Sign the head of the account's chain as it will be committed, for an answer to the
    /// signer or an own app, with `signer`, the key the verdict gives. Under the account's
    /// lock, before the commit, once the request has been judged there (Switch wire 7.3 step
    /// 10); the mark moves to it once the commit is durable. `None`, signing nothing, while
    /// the instance lock isn't confirmed: another process may hold the database (Switch spec
    /// 6.5). Every head signed under the lock is signed here.
    pub(super) async fn head(
        &self,
        txn: &AccountTxn,
        signer: &ServiceSigner,
    ) -> Option<SignedHead> {
        if !self.lock_is_fresh() {
            tracing::error!("the instance lock isn't confirmed: no head signed");
            return None;
        }
        let head = txn.head();
        Some(sign_head(signer, &head.identity_key, &head.chain_tip()))
    }
}

#[cfg(test)]
mod tests {
    /// Every Rust source under `dir`, with its path.
    fn sources(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                out.push((path, text));
            }
        }
    }

    #[test]
    fn test_signed_received_request_built_only_from_what_was_received() {
        // The body field, and the received request it is part of, come only from what the
        // transport received (Switch wire 7.1): built here, once per request, never chosen
        // by a call site.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        sources(&dir, &mut found);
        let mut builds = 0;
        for (path, text) in &found {
            if path.ends_with("service/signed.rs") {
                let code = text.split("#[cfg(test)]").next().unwrap_or_default();
                assert_eq!(code.matches("BodyField::NotRead").count(), 1);
                assert_eq!(code.matches("BodyField::read(").count(), 2);
                continue;
            }
            for needle in [
                "BodyField",
                "ReceivedRequest",
                "ReceivedHeaders",
                "received_request(",
            ] {
                assert!(
                    !text.contains(needle),
                    "{} builds a received request outside signed.rs: {needle}",
                    path.display()
                );
            }
            builds += text.matches("Received::read(").count();
            builds += text.matches("Received::refused(").count();
        }
        // One for a request the handler serves, one for a refusal of the transport.
        assert_eq!(builds, 2);
    }

    #[test]
    fn test_signed_every_response_is_signed_here() {
        // Every response signature is made by `sign_answer`, the one place that binds the
        // received request (Switch wire 7.1).
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        sources(&dir, &mut found);
        assert!(found.len() > 10, "the service's sources");
        for (path, text) in found {
            if path.ends_with("service/signed.rs") {
                continue;
            }
            for needle in ["sign_response(", "fn sign_answer("] {
                assert!(
                    !text.contains(needle),
                    "{} signs a response outside signed.rs: {needle}",
                    path.display()
                );
            }
        }
    }

    /// Every place the service signs a head or a checkpoint, by file, with how many calls:
    /// each checks the instance lock right before it signs (Switch spec 6.5). A new place is
    /// added here only with that check.
    const SIGNING: [(&str, &str, usize); 3] = [
        ("signed.rs", "sign_head(", 1),
        ("feed.rs", "sign_head(", 2),
        ("retention.rs", "sign_checkpoint(", 1),
    ];

    #[test]
    fn test_signed_every_head_is_signed_where_the_lock_is_checked() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service");
        let mut files = vec![];
        let mut stack = vec![dir];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir).expect("service sources") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    files.push(path);
                }
            }
        }
        for path in files {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let text = std::fs::read_to_string(&path).expect("source");
            // The source before its tests, which sign nothing the service sends.
            let code = text
                .split("\n#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or_default();
            for call in ["sign_head(", "sign_checkpoint("] {
                let found = code.matches(call).count();
                let expected = SIGNING
                    .iter()
                    .find(|(file, signing, _)| *file == name && *signing == call)
                    .map_or(0, |(_, _, count)| *count);
                assert_eq!(found, expected, "{name}: {call}");
                if found > 0 {
                    assert!(code.contains("lock_is_fresh()"), "{name}: no lock check");
                }
            }
        }
    }
}
