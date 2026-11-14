//! How every answer is signed (Switch wire 7.1): the response signature over its status,
//! the method and path of the request it answers, the request signature,
//! `Switch-Server-Time`, the `Switch-Head` text as sent and the body, with the key the
//! verdict of the account and its mark gives (Switch wire 7.3, Table 2), or the service key
//! for an answer the service can't tie to an account. Every answer is signed, made last,
//! once the body is whole.

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use pubky_switch_core::{
    chain::SignedHead,
    enc::b64,
    http::{self as wire_http, header},
    time::rfc3339,
};

use super::{Answer, Service};
use crate::{
    http::{SwitchResponse, error::ApiError},
    keys::{ServiceSigner, sign_head},
    store::AccountTxn,
};

/// The request an answer answers, as the response signature covers it (Switch wire 7.1): its
/// method, its path as sent without the query, and its signature bytes, `None` when it has
/// none that decodes.
#[derive(Clone, Copy, Debug)]
pub(super) struct Asked<'a> {
    method: &'a str,
    path: &'a str,
    signature: Option<[u8; 64]>,
}

impl<'a> Asked<'a> {
    /// The request with `method`, `path_and_query` and `headers`.
    pub(super) fn of(method: &'a str, path_and_query: &'a str, headers: &HeaderMap) -> Self {
        Asked {
            method,
            path: wire_http::path_of(path_and_query),
            signature: wire_http::request_signature_of(
                headers
                    .get(header::SIGNATURE)
                    .and_then(|value| value.to_str().ok()),
            ),
        }
    }

    /// The same request with its signature left out of the answer's: the public read's
    /// answer is the same for every reader (Switch wire 7.4.15).
    pub(super) fn unsigned(self) -> Self {
        Asked {
            signature: None,
            ..self
        }
    }
}

/// Sign `answer` (Switch wire 7.1): the response signature over its status, the method and
/// path of the request it answers, the request signature, `Switch-Server-Time`, the
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
            method: asked.method,
            path: asked.path,
            request_signature: asked.signature.as_ref(),
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

    /// `error` signed with the service key at the time base `base_ms`, without a head: an
    /// answer the service can't tie to an account, or one whose account's key it can't
    /// find (Switch wire 7.1).
    pub(super) fn service_error(
        &self,
        asked: Asked<'_>,
        base_ms: u64,
        error: &ApiError,
    ) -> SwitchResponse {
        Self::signed_error(&self.keys.current(), asked, base_ms, error)
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

    /// `error` signed with `key` at `time_ms`, without a head, or with the service key at
    /// the time base when the key store doesn't hold `key`.
    pub(super) fn keyed_error(
        &self,
        key: &[u8; 32],
        asked: Asked<'_>,
        time_ms: u64,
        base_ms: u64,
        error: &ApiError,
    ) -> SwitchResponse {
        match self.signer_of(key) {
            Some(signer) => Self::signed_error(&signer, asked, time_ms, error),
            None => self.service_error(
                asked,
                base_ms,
                &ApiError::unavailable("7.6: a temporary failure"),
            ),
        }
    }

    /// Sign the head of the account's chain as it will be committed, for an answer to the
    /// signer or an own app, with `signer`, the key the verdict gives. Under the account's
    /// lock, before the commit, once the request has been judged there (Switch wire 7.3 step
    /// 10); the mark moves to it once the commit is durable.
    pub(super) async fn head(
        &self,
        txn: &AccountTxn,
        signer: &ServiceSigner,
    ) -> Option<SignedHead> {
        let head = txn.head();
        Some(sign_head(signer, &head.identity_key, &head.chain_tip()))
    }
}
