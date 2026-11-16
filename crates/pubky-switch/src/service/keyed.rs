//! Where every answer is signed (Switch wire 7.1, 7.4.16): with the operator key, or with an
//! account's service key only while the account provably still names that key.
//!
//! An answer of an account's key is signed by [`Service::sign_keyed`], with a [`Proof`]:
//! - [`Proof::Locked`]: the request holds the account's row lock, uncommitted, so no erasure
//!   or change of the key can commit meanwhile, and the key is the transaction's. Only for
//!   what goes out after the same transaction commits, such as the erasure's confirmation:
//!   the commit proves the lock was held all along. A statement that failed may mean the
//!   database ended the transaction and its lock with it, so an answer to a failure under the
//!   lock goes through [`Service::sign_after_failure`] instead;
//! - [`Proof::Checked`]: anything else, a commit already made included. The answer is signed
//!   inside a keyed section ([`crate::store::Store::while_keyed`]), under the account's shared
//!   keying lock, which an erasure and a key change take exclusive before they sign their own
//!   answer.
//!
//! Otherwise the operator's answer goes out instead: as for an account the service doesn't
//! host, for one erased meanwhile (Switch wire 7.3 step 2), and `503` for one whose key
//! changed, or when the keyed section fails. Nothing else in the service signs an answer or a
//! head: `sign_answer` is this module's alone.

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use pubky_switch_core::{
    chain::{ChainTip, SignedHead},
    enc::b64,
    http::{self as wire_http, BodyField, ReceivedHeaders, ReceivedRequest, header},
    time::rfc3339,
};

use super::{Answer, Service, unsigned};
use crate::{
    http::{Refusal, SwitchRequest, SwitchResponse, error::ApiError},
    keys::{KeyId, Mark, ServiceSigner, sign_head},
    store::{AccountTxn, Keyed},
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

    /// Whether it carries one of the signed request headers more than once (Switch wire
    /// 7.1).
    pub(super) fn repeats_a_signed_header(&self) -> bool {
        wire_http::RECEIVED_HEADERS
            .iter()
            .any(|name| self.headers.values(name).len() > 1)
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

/// What shows the account still names the key an answer is signed with.
pub(super) enum Proof<'a> {
    /// The request holds the account's row lock and hasn't committed: the key is `txn`'s.
    /// The borrow keeps the transaction alive while the answer is signed; only what goes out
    /// after that transaction commits may use it (the module's doc).
    Locked(#[allow(dead_code)] &'a AccountTxn),
    /// Checked in a keyed section: `account` names `key`, or, with `pending`, has it as its
    /// pending key of the next generation.
    Checked {
        /// The account.
        account: &'a str,
        /// The key the request loaded.
        key: &'a KeyId,
        /// The key may be the account's pending key (an enrollment's answer).
        pending: bool,
    },
}

impl<'a> Proof<'a> {
    /// [`Proof::Checked`] for `account`'s service key `key`.
    pub(super) fn checked(account: &'a str, key: &'a KeyId) -> Self {
        Proof::Checked {
            account,
            key,
            pending: false,
        }
    }
}

/// Why an answer couldn't be signed with the account's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NotKeyed {
    /// The account is gone.
    Gone,
    /// It names another key, or the keyed section failed.
    Unavailable,
}

/// The signing an answer's builder may do inside its proof: a signed head.
pub(super) struct Signing<'a> {
    signer: &'a ServiceSigner,
}

impl Signing<'_> {
    /// Sign the head at `tip` for `identity`, unless it is behind `mark` (Switch spec 6.5).
    pub(super) fn head(
        &self,
        mark: Option<&Mark>,
        identity: &[u8; 32],
        tip: &ChainTip,
    ) -> Option<SignedHead> {
        sign_head(self.signer, mark, identity, tip).ok()
    }
}

/// Sign `answer` (Switch wire 7.1): the response signature over its status, the request it
/// answers as the service received it, `Switch-Server-Time`, the head field of the
/// `Switch-Head` text as sent and the body.
fn sign_answer(
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
    /// An answer signed with the operator key, at the time base (Switch wire 7.1).
    pub(super) async fn operator_answer(
        &self,
        asked: Asked<'_>,
        base_ms: u64,
        error: &ApiError,
    ) -> SwitchResponse {
        match self.keys.operator().await {
            Ok(signer) => sign_answer(&signer, asked, base_ms, Answer::error(error)),
            Err(failure) => {
                tracing::error!(%failure, "the operator key");
                unsigned(error)
            }
        }
    }

    /// The answer `build` makes, signed with `signer`, an account's service key, under
    /// `proof` (the module's doc). `build` runs synchronously inside the proof, and gives
    /// the answer and its service time; it may sign a head with [`Signing::head`].
    pub(super) async fn try_sign_keyed(
        &self,
        proof: Proof<'_>,
        signer: &ServiceSigner,
        asked: Asked<'_>,
        build: impl FnOnce(&Signing<'_>) -> (Answer, u64),
    ) -> Result<SwitchResponse, NotKeyed> {
        let sign = || {
            let (answer, time_ms) = build(&Signing { signer });
            sign_answer(signer, asked, time_ms, answer)
        };
        match proof {
            Proof::Locked(_) => Ok(sign()),
            Proof::Checked {
                account,
                key,
                pending,
            } => match self.store.while_keyed(account, key, pending, sign).await {
                Ok(Keyed::Signed(signed)) => Ok(signed),
                Ok(Keyed::Gone) => Err(NotKeyed::Gone),
                Ok(Keyed::Rekeyed) => Err(NotKeyed::Unavailable),
                Err(failure) => {
                    tracing::error!(%failure, "a keyed section");
                    Err(NotKeyed::Unavailable)
                }
            },
        }
    }

    /// `answer` at `time_ms`, signed with `signer` under `proof`; otherwise the operator's
    /// answer at `base_ms`: as for an account the service doesn't host when it is gone, for
    /// its signer when `by_signer` ([`Service::no_such_account`]), else `503`.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn sign_keyed(
        &self,
        proof: Proof<'_>,
        signer: &ServiceSigner,
        asked: Asked<'_>,
        time_ms: u64,
        answer: Answer,
        base_ms: u64,
        by_signer: bool,
    ) -> SwitchResponse {
        let account = match &proof {
            Proof::Checked { account, .. } => Some((*account).to_owned()),
            Proof::Locked(_) => None,
        };
        let signed = self
            .try_sign_keyed(proof, signer, asked, |_| (answer, time_ms))
            .await;
        match signed {
            Ok(signed) => signed,
            Err(not_keyed) => {
                self.not_keyed_answer(account.as_deref(), not_keyed, by_signer, asked, base_ms)
                    .await
            }
        }
    }

    /// The answer to a request whose transaction failed under the account's lock: a database
    /// that ended the transaction released its lock, and an erasure may have committed
    /// since. So the transaction is dropped first, holding no second connection, and the
    /// answer is signed only in a keyed section (the module's doc). `key` is the key `signer`
    /// was loaded for, not the transaction's: a request that changed the account's key in
    /// it (Switch wire 3.3) holds the new one there, and a retry may have committed that
    /// change since, so the section checks the key that signs.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn sign_after_failure(
        &self,
        txn: AccountTxn,
        signer: &ServiceSigner,
        key: &KeyId,
        asked: Asked<'_>,
        time_ms: u64,
        answer: Answer,
        base_ms: u64,
        by_signer: bool,
    ) -> SwitchResponse {
        let account = txn.head().id.clone();
        let key = key.clone();
        drop(txn);
        self.sign_keyed(
            Proof::checked(&account, &key),
            signer,
            asked,
            time_ms,
            answer,
            base_ms,
            by_signer,
        )
        .await
    }

    /// The operator's answer in place of one an account's key couldn't sign.
    pub(super) async fn not_keyed_answer(
        &self,
        account: Option<&str>,
        not_keyed: NotKeyed,
        by_signer: bool,
        asked: Asked<'_>,
        base_ms: u64,
    ) -> SwitchResponse {
        let error = match (not_keyed, account) {
            (NotKeyed::Gone, Some(account)) => self.no_such_account(account, by_signer).await,
            _ => ApiError::unavailable("7.6: a temporary failure"),
        };
        self.operator_answer(asked, base_ms, &error).await
    }

    /// Sign the head of the account's chain as it will be committed, for an answer to the
    /// signer or an own app; `None` if the key's mark refuses it. Under the account's lock,
    /// so [`Proof::Locked`] by construction: the answer that carries it is signed under its
    /// own proof.
    pub(super) async fn head(
        &self,
        txn: &AccountTxn,
        signer: &ServiceSigner,
    ) -> Option<SignedHead> {
        let head = txn.head();
        let mark = self.keys.mark(&head.service_key).await.ok()?;
        sign_head(signer, mark.as_ref(), &head.identity_key, &head.chain_tip()).ok()
    }
}

#[cfg(test)]
mod tests {
    /// Every Rust source of the service under `dir`, with its path.
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
    fn test_keyed_signing_happens_only_here() {
        // An answer or a head signed anywhere else in the service could be signed with a key
        // its account no longer names (Switch wire 7.4.16): this module is the only place.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service");
        let mut found = Vec::new();
        sources(&dir, &mut found);
        assert!(found.len() > 10, "the service's sources");
        for (path, text) in found {
            if path.ends_with("keyed.rs") {
                continue;
            }
            for needle in ["sign_response(", "sign_head(", "fn sign_answer("] {
                assert!(
                    !text.contains(needle),
                    "{} signs outside keyed.rs: {needle}",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn test_received_request_built_only_from_what_was_received() {
        // The body field, and the received request it is part of, come only from what the
        // transport received (Switch wire 7.1): built here, once per request, never chosen
        // by a call site.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        sources(&dir, &mut found);
        let mut builds = 0;
        for (path, text) in &found {
            if path.ends_with("service/keyed.rs") {
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
                    "{} builds a received request outside keyed.rs: {needle}",
                    path.display()
                );
            }
            builds += text.matches("Received::read(").count();
            builds += text.matches("Received::refused(").count();
        }
        // One for a request the handler serves, one for a refusal of the transport.
        assert_eq!(builds, 2);
    }
}
