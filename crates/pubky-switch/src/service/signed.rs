//! How every answer is signed (Switch wire 7.1): the response signature over its status,
//! the request it answers as the service received it, `Switch-Server-Time`, the head field
//! of the `Switch-Head` text as sent and the body, with the key the
//! verdict of the account and its mark gives (Switch wire 7.3, Table 2), or the service key
//! for an answer the service can't tie to an account. Every answer is signed, made last,
//! once the body is whole.

use axum::http::{HeaderName, HeaderValue};
use pubky_switch_core::{
    chain::{ProofBody, ServiceTransition, SignedHead, TransitionProof},
    enc::b64,
    http::{self as wire_http, BodyField, ReceivedHeaders, ReceivedRequest, Uncompared, header},
    sig::SignedDoc,
    time::rfc3339,
};

use super::{Answer, Service};
use crate::{
    http::{Refusal, SignedHeaders, SwitchRequest, SwitchResponse, error::ApiError},
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

impl<'a> Received<'a> {
    /// A request the transport read whole, at the switch origin `origin`.
    pub(super) fn read(request: &'a SwitchRequest, origin: &'a str) -> Self {
        Received {
            method: &request.method,
            path_and_query: &request.path_and_query,
            origin,
            body: BodyField::read(&request.body),
            headers: request.signed_headers().received().clone(),
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
            headers: SignedHeaders::of(headers).received().clone(),
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

/// The time an answer carries in `Switch-Server-Time` (Switch wire 7.1 Timestamp): so that
/// for each identity it never goes back, the time base goes only on an answer that counts in
/// no comparison of service times, of a class a client tells from the answer and its call
/// ([`wire_http::uncompared`]), or on one that binds a request no client sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AnswerTime {
    /// The time the request stamped (7.3 step 3), on an answer that commits; the last time
    /// the service committed for the identity, on one that commits nothing.
    Account(u64),
    /// The time base, on an answer of the class named, which counts in no comparison.
    TimeBase(u64, Uncompared),
    /// The time base, on an answer that binds a request as it arrived when no client sends
    /// such a request: an unknown route's `404` and the `400` of the header rule outside
    /// enrollment and erasure (7.1 "Each header once, as text", Timestamp).
    Unbound(u64),
}

impl AnswerTime {
    /// The time, in Unix milliseconds.
    pub(super) fn ms(self) -> u64 {
        match self {
            AnswerTime::Account(ms) | AnswerTime::TimeBase(ms, _) | AnswerTime::Unbound(ms) => ms,
        }
    }

    /// The same time on a `503 unavailable` given in place of the answer: a time base stays
    /// one, of that class.
    pub(super) fn unavailable(self) -> Self {
        match self {
            AnswerTime::Account(ms) => AnswerTime::Account(ms),
            AnswerTime::TimeBase(ms, class) => AnswerTime::TimeBase(
                ms,
                match class {
                    Uncompared::Enrollment
                    | Uncompared::AccountDiscovery
                    | Uncompared::Erasure
                    | Uncompared::PublicRead
                    | Uncompared::BodyUnread => class,
                    Uncompared::CreationConflict
                    | Uncompared::Notice
                    | Uncompared::Unavailable
                    | Uncompared::NotHosted => Uncompared::Unavailable,
                },
            ),
            AnswerTime::Unbound(ms) => AnswerTime::TimeBase(ms, Uncompared::Unavailable),
        }
    }
}

/// The time of an answer signed later than it is decided, as a feed read's verdict after
/// its wait (Switch wire 7.1 Timestamp).
#[derive(Clone, Copy, Debug)]
pub(super) enum LaterTime {
    /// The last time the read saw the service commit for the identity.
    Committed(u64),
    /// The time base when it answers, for an answer of the class named, which counts in no
    /// comparison of service times.
    TimeBase(Uncompared),
}

impl LaterTime {
    /// The answer's time, with `base` the time base when it answers.
    pub(super) fn at(self, base: impl FnOnce() -> u64) -> AnswerTime {
        match self {
            LaterTime::Committed(ms) => AnswerTime::Account(ms),
            LaterTime::TimeBase(class) => AnswerTime::TimeBase(base(), class),
        }
    }
}

/// Sign `answer` at `at` (Switch wire 7.1): the response signature over its status, the
/// request it answers as the service received it, `Switch-Server-Time`, the head field of the
/// `Switch-Head` text as sent and the body.
pub(super) fn sign_answer(
    signer: &ServiceSigner,
    asked: Asked<'_>,
    at: AnswerTime,
    answer: Answer,
) -> SwitchResponse {
    #[cfg(any(test, feature = "test-util"))]
    check_time_base(asked, &answer, at);
    let server_time = rfc3339(at.ms());
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

/// In test builds, every answer signed at the time base is of the class its call site names,
/// as a client tells it from the answer and the call alone (Switch wire 7.1 Timestamp): so
/// every path that signs at the time base the tests take is checked against the client's
/// rule.
#[cfg(any(test, feature = "test-util"))]
fn check_time_base(asked: Asked<'_>, answer: &Answer, at: AnswerTime) {
    let request = asked.0;
    let body: serde_json::Value =
        serde_json::from_slice(&answer.body).unwrap_or(serde_json::Value::Null);
    let code = body
        .get("code")
        .and_then(serde_json::Value::as_str)
        .and_then(wire_http::ErrorCode::parse);
    let class = wire_http::uncompared(
        request.method,
        request.path_and_query,
        request.body,
        answer.status,
        code,
        body.get("current"),
        answer.head.is_some(),
    );
    match at {
        AnswerTime::Account(_) => {}
        // Every answer to the enrollment, the erasure and the public read counts in no
        // comparison, of whatever class the answer itself is.
        AnswerTime::TimeBase(_, named) => assert!(
            class == Some(named)
                || matches!(
                    class,
                    Some(Uncompared::Enrollment | Uncompared::Erasure | Uncompared::PublicRead)
                ),
            "{} {} answered {} {body} at the time base",
            request.method,
            request.path_and_query,
            answer.status
        ),
        AnswerTime::Unbound(_) => assert!(
            matches!(
                (answer.status, code),
                (400, Some(wire_http::ErrorCode::BadRequest))
                    | (404, Some(wire_http::ErrorCode::NotFound))
            ) && class.is_none(),
            "{} {} answered {} {body} as an unbound answer",
            request.method,
            request.path_and_query,
            answer.status
        ),
    }
}

impl Service {
    /// `error` signed with `signer` at `at`, without a head.
    pub(super) fn signed_error(
        signer: &ServiceSigner,
        asked: Asked<'_>,
        at: AnswerTime,
        error: &ApiError,
    ) -> SwitchResponse {
        sign_answer(signer, asked, at, Answer::error(error))
    }

    /// `error` signed with the service key at `at`, without a head: an answer the service
    /// can't tie to an account, at the time base, or one whose verdict's key it doesn't hold
    /// (Switch wire 7.1).
    pub(super) fn service_error(
        &self,
        asked: Asked<'_>,
        at: AnswerTime,
        error: &ApiError,
    ) -> SwitchResponse {
        Self::signed_error(&self.keys.current(), asked, at, error)
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

    /// `error` signed with `key` at `at`, without a head, or a `503` with the service key at
    /// the same time when the key store doesn't hold `key`, which counts in no comparison
    /// like every `503 unavailable` (Switch wire 7.1 Timestamp).
    pub(super) fn keyed_error(
        &self,
        key: &[u8; 32],
        asked: Asked<'_>,
        at: AnswerTime,
        error: &ApiError,
    ) -> SwitchResponse {
        match self.signer_of(key) {
            Some(signer) => Self::signed_error(&signer, asked, at, error),
            None => self.service_error(
                asked,
                at.unavailable(),
                &ApiError::unavailable("7.6: a temporary failure"),
            ),
        }
    }

    /// Sign a service transition while its account is locked and the instance lock is
    /// still confirmed (Switch spec 6.5; wire 7.3 step 10).
    pub(super) fn sign_transition(
        &self,
        txn: &AccountTxn,
        signer: &ServiceSigner,
        transition: &ServiceTransition,
    ) -> Result<SignedDoc, ApiError> {
        if !self.lock_is_fresh() {
            return Err(ApiError::unavailable("7.6: a temporary failure"));
        }
        transition
            .sign(signer, &txn.head().identity_key)
            .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))
    }

    /// Sign a transition proof under the same locks as the state it proves. Check again
    /// after the caller's storage awaits (Switch spec 6.5; wire 7.3 step 10).
    pub(super) fn sign_proof(
        &self,
        txn: &AccountTxn,
        signer: &ServiceSigner,
        body: ProofBody,
    ) -> Result<TransitionProof, ApiError> {
        if !self.lock_is_fresh() {
            return Err(ApiError::unavailable("7.6: a temporary failure"));
        }
        TransitionProof::sign(signer, &txn.head().identity_key, body)
            .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))
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
    use crate::http::error::ApiError;

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
                // The one conversion of the header map, which the received request takes its
                // headers from (`SignedHeaders`).
                if needle == "ReceivedHeaders" && path.ends_with("http/mod.rs") {
                    continue;
                }
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
    fn test_signed_every_time_base_answer_counts_in_no_comparison() {
        // Built from the sources: every place that signs at the time base names the class of
        // its answer, and each class named is one a client tells from the answer and its
        // call and leaves out of its comparison of service times; the answers that bind a
        // request no client sends are the unknown route's and the header rule's (Switch wire
        // 7.1 Timestamp). In test builds `sign_answer` checks each such answer against its
        // class, so every path the tests take is checked too.
        use pubky_switch_core::http::{
            BodyField, ErrorCode, NoticeReason, RecoveryNotice, Uncompared, uncompared,
        };
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        sources(&dir, &mut found);
        let mut named = Vec::new();
        let mut unbound = 0;
        for (path, text) in &found {
            if path.ends_with("service/signed.rs") {
                continue;
            }
            assert!(
                !text.contains("AnswerTime::Account(base_ms"),
                "{} signs the time base as an account's time",
                path.display()
            );
            for (at, _) in text.match_indices("TimeBase(") {
                let rest = &text[at..];
                let call = &rest[..rest.find(')').unwrap_or(rest.len())];
                let Some(class) = call.split("Uncompared::").nth(1) else {
                    panic!("{}: a time base without its class: {call}", path.display());
                };
                named.push(class.trim().to_string());
            }
            unbound += text.matches("AnswerTime::Unbound(").count();
        }
        // The header rule's `400` outside enrollment and erasure, the unknown route's
        // `404` routed by the service and by the transport.
        assert_eq!(
            unbound, 3,
            "the answers that bind a request no client sends"
        );
        assert!(named.len() > 10, "the sites: {named:?}");
        let notice = RecoveryNotice {
            generation: 1,
            reason: NoticeReason::Behind,
            permanent: false,
        };
        for name in &named {
            let class = [
                Uncompared::Enrollment,
                Uncompared::AccountDiscovery,
                Uncompared::Erasure,
                Uncompared::PublicRead,
                Uncompared::BodyUnread,
                Uncompared::CreationConflict,
                Uncompared::Notice,
                Uncompared::Unavailable,
                Uncompared::NotHosted,
            ]
            .into_iter()
            .find(|class| format!("{class:?}") == *name)
            .unwrap_or_else(|| panic!("no class {name}"));
            // A representative answer of the class, built as the service builds it.
            let (method, path, body, error) = match class {
                Uncompared::Enrollment => (
                    "POST",
                    "/v1/enroll",
                    BodyField::read(b"{}"),
                    ApiError::unavailable("7.6: a temporary failure"),
                ),
                Uncompared::AccountDiscovery => (
                    "GET",
                    "/v1/x/account",
                    BodyField::read(b""),
                    ApiError::unavailable("7.6: a temporary failure"),
                ),
                Uncompared::Erasure => (
                    "POST",
                    "/v1/x/erase",
                    BodyField::read(b"{}"),
                    super::super::marking::not_hosted(),
                ),
                Uncompared::PublicRead => (
                    "GET",
                    "/v1/x/identity",
                    BodyField::read(b""),
                    ApiError::rate_limited("9.4", 1),
                ),
                Uncompared::BodyUnread => (
                    "POST",
                    "/v1/x/ops",
                    BodyField::NotRead,
                    ApiError::body_too_large(1),
                ),
                Uncompared::CreationConflict => (
                    "GET",
                    "/v1/x/apps",
                    BodyField::read(b""),
                    super::super::account::creation_conflict(1_767_225_600_000),
                ),
                Uncompared::Notice => (
                    "GET",
                    "/v1/x/apps",
                    BodyField::read(b""),
                    ApiError::new(ErrorCode::RecoveryRequired, "7.3")
                        .with_current(notice.to_current()),
                ),
                Uncompared::Unavailable => (
                    "GET",
                    "/v1/x/apps",
                    BodyField::read(b""),
                    ApiError::unavailable("7.6: a temporary failure"),
                ),
                Uncompared::NotHosted => (
                    "GET",
                    "/v1/x/apps",
                    BodyField::read(b""),
                    super::super::marking::not_hosted(),
                ),
            };
            assert_eq!(
                uncompared(
                    method,
                    path,
                    body,
                    error.status(),
                    Some(error.code),
                    error.current.as_ref(),
                    false
                ),
                Some(class),
                "{name}"
            );
        }
    }

    #[test]
    fn test_signed_every_response_is_signed_here() {
        // Every response signature is made by `sign_answer`, the one place that binds the
        // received request (Switch wire 7.1).
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        sources(&dir, &mut found);
        assert!(found.len() > 10, "the service's sources");
        for (path, text) in &found {
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

    #[test]
    fn test_signed_request_headers_are_read_only_through_signed_headers() {
        // The signed request headers are read through `SignedHeaders`, which represents each
        // value exactly, never from the HTTP header map, where a conversion could drop a
        // value it can't read (Switch wire 7.1 "Each header once, as text"). Only the
        // transport reads the map, for its own headers.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        sources(&dir, &mut found);
        for (path, text) in found {
            if path.ends_with("http/mod.rs") || path.ends_with("http/source.rs") {
                continue;
            }
            let code = text
                .split("\n#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or_default();
            for needle in [
                "headers.get(",
                "headers.get_all(",
                "headers.iter(",
                "HeaderMap",
            ] {
                assert!(
                    !code.contains(needle),
                    "{} reads the HTTP header map: {needle}",
                    path.display()
                );
            }
        }
    }

    /// Every place the service signs state, by file, with how many calls:
    /// each checks the instance lock right before it signs (Switch spec 6.5). A new place is
    /// added here only with that check.
    const SIGNING: [(&str, &str, usize); 5] = [
        ("signed.rs", "sign_head(", 1),
        ("feed.rs", "sign_head(", 1),
        ("retention.rs", "sign_checkpoint(", 1),
        ("signed.rs", "TransitionProof::sign(", 1),
        ("signed.rs", ".sign(signer,", 1),
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
            for call in [
                "sign_head(",
                "sign_checkpoint(",
                "TransitionProof::sign(",
                ".sign(signer,",
            ] {
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
