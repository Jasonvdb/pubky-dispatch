//! A feed read the Dispatch holds while the account recovers in place, and a Dispatch that
//! answers feed reads as its operator (Dispatch wire 7.1, 7.4.4, 7.6, spec 12.6 step 1).

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use pubky_dispatch_core::enc::{b64, unb64};
use pubky_dispatch_core::http::header;
use pubky_dispatch_core::records::Inbox;
use pubky_dispatch_core::scopes::Permission;
use serde_json::{Value, json};

use super::moves::{Router, join_on};
use super::*;
use crate::app::{AppError, AppEvent};
use crate::error::{ClientError, TransportError};
use crate::testing::DISPATCH_ORIGIN as ORIGIN;
use crate::transport::{BoxFuture, Header, Request, Response, Transport};

/// The answer a key the app doesn't know signs, as a hostile Dispatch or its operator could.
fn operator_503() -> Value {
    json!({ "code": "unavailable", "message": "7.6: a temporary failure" })
}

/// A feed answer as the transport saw it: status, body, header names, and whether the
/// scripted Dispatch's one key signs it.
type Seen = (u16, Value, Vec<String>, bool);

/// The Dispatch's transport, keeping each feed answer; with `forge`, every feed read is
/// answered instead [`operator_503`] signed with a key the app doesn't know, as a hostile
/// Dispatch or its operator could.
pub(super) struct Recording {
    inner: Arc<dyn Transport>,
    /// The scripted Dispatch's key.
    key: [u8; 32],
    forge: Mutex<bool>,
    feeds: Mutex<Vec<Seen>>,
}

impl Recording {
    fn over(inner: Arc<dyn Transport>, key: [u8; 32]) -> Arc<Self> {
        Arc::new(Self {
            inner,
            key,
            forge: Mutex::new(false),
            feeds: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn forged(request: &Request) -> Response {
        let body = operator_503().to_string().into_bytes();
        let server_time = "2026-01-01T00:00:00.000Z";
        let sent = crate::client::SentRequest::of(request);
        let signature = pubky_dispatch_core::http::sign_response(
            &SigningKey::from_bytes(&[42; 32]),
            &pubky_dispatch_core::http::ResponseParts {
                status: 503,
                request: sent.received(true),
                server_time,
                head: None,
                body: &body,
            },
        );
        Response {
            status: 503,
            headers: vec![
                Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
                Header::new(header::SERVER_TIME, server_time),
            ],
            body,
        }
    }
}

impl Transport for Recording {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            let feed = request.path_and_query.contains("/feed");
            let sent = crate::client::SentRequest::of(&request);
            let answer = if feed && *self.forge.lock().unwrap() {
                Ok(Self::forged(&request))
            } else {
                self.inner.send(request).await
            };
            if feed && let Ok(response) = &answer {
                let body = serde_json::from_slice(&response.body).unwrap_or_default();
                let names = response.headers.iter().map(|h| h.name.clone()).collect();
                let by_dispatch = response
                    .header(header::SERVICE_SIGNATURE)
                    .and_then(|text| unb64(text).ok())
                    .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
                    .zip(response.header(header::SERVER_TIME))
                    .is_some_and(|(signature, time)| {
                        pubky_dispatch_core::http::verify_response(
                            &self.key,
                            &pubky_dispatch_core::http::ResponseParts {
                                status: response.status,
                                request: sent.received(true),
                                server_time: time,
                                head: response.header(header::HEAD),
                                body: &response.body,
                            },
                            &signature,
                        )
                        .is_ok()
                    });
                self.feeds
                    .lock()
                    .unwrap()
                    .push((response.status, body, names, by_dispatch));
            }
            answer
        })
    }
}

#[tokio::test]
async fn test_feed_read_held_across_a_recovery_in_place_is_read_again_at_the_new_sequence() {
    // The app's read is held, in a task of its own, when its account recovers in place.
    // The recovery wakes it, and the Dispatch answers it as the service does, from the
    // account as it then is: the fresh account holds no record of the app, so `403
    // not_current`, no head, under the one key (Dispatch wire 7.4.4). The app reads its own
    // identity.json, learns the new generation from it, and the same read follows the
    // recovery and reads from the start of the new sequence.
    let w = World::new();
    let router = Router::of(&w);
    let recording = Recording::over(w.dispatch.holding_transport(), w.dispatch.service_key());
    router.add_transport(ORIGIN, Arc::clone(&recording) as Arc<dyn Transport>);
    let store = Arc::new(MemoryStore::new());
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 1);
    let feeds_before = recording.feeds.lock().unwrap().len();
    let reading = tokio::spawn(async move {
        let read = app.receive(Some(10)).await;
        (app, read)
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while w.dispatch.held_reads() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the read is held");
    let key = w.dispatch.service_key();
    let prev = w.dispatch.identity_doc().unwrap().hash();
    let doc = w
        .signer
        .sign_next(|body| {
            body.generation = 2;
            body.inbox = Inbox::new(ORIGIN, key);
            body.recovery_from = Some(1);
        })
        .unwrap();
    w.dispatch.recover_in_place(&doc, prev).unwrap();
    // Woken by the recovery: a read left held would never end, the Dispatch's clock standing.
    let (mut app, read) = tokio::time::timeout(std::time::Duration::from_secs(10), reading)
        .await
        .expect("the held read is answered")
        .unwrap();
    // The held read's own answer, with the fields the service's has (endpoints_recovery's
    // test of the same).
    let feeds = recording.feeds.lock().unwrap().clone();
    let (status, body, names, by_dispatch) = &feeds[feeds_before];
    assert_eq!((*status, &body["code"]), (403, &json!("not_current")));
    let mut names = names.clone();
    names.sort_unstable();
    assert_eq!(names, [header::SERVER_TIME, header::SERVICE_SIGNATURE]);
    assert!(*by_dispatch, "signed with the one key");
    // The new generation came from the own identity.json, before the read at the new
    // sequence.
    let report = read.unwrap();
    let at = |wanted: fn(&AppEvent) -> bool| report.events.iter().position(wanted);
    let updated = at(|e| matches!(e, AppEvent::IdentityUpdated { version: 2 }));
    let lost = at(|e| {
        matches!(
            e,
            AppEvent::ProviderLost {
                lost_generation: 1,
                generation: 2
            }
        )
    });
    assert!(updated.is_some() && updated < lost, "{:?}", report.events);
    assert_eq!(app.own_identity().generation(), 2);
    assert_eq!(app.own_identity().inbox().service_key, key);
    assert_eq!(app.cursor().generation, 2);
    assert!(app.alarm().is_none(), "{:?}", app.alarm());
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
}

#[tokio::test]
async fn test_feed_answered_as_the_operator_again_and_again_only_delays() {
    // A Dispatch that answers every feed read `503 unavailable` with a key the app doesn't
    // know, and no newer identity.json: each read fails for now, as for a Dispatch the app
    // can't reach. Nothing moves on the answer's word: the cursor, the own identity.json
    // and the erasure wait stay, no event is raised and no alarm held; once the Dispatch
    // answers as the account again, the app reads on.
    let w = World::new();
    let router = Router::of(&w);
    let recording = Recording::over(w.dispatch.transport(), w.dispatch.service_key());
    router.add_transport(ORIGIN, Arc::clone(&recording) as Arc<dyn Transport>);
    let store = Arc::new(MemoryStore::new());
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    app.receive(None).await.unwrap();
    let cursor = app.cursor();
    let doc = app.own_identity().clone();
    *recording.forge.lock().unwrap() = true;
    for _ in 0..5 {
        let error = app.receive(None).await.unwrap_err();
        assert!(
            matches!(
                error,
                AppError::Dispatch(ClientError::BadServiceSignature { status: 503 })
            ),
            "{error:?}"
        );
        assert_eq!(app.cursor(), cursor);
        assert_eq!(app.own_identity(), &doc);
        assert!(app.alarm().is_none(), "{:?}", app.alarm());
        assert!(app.state.erasing.is_none());
    }
    *recording.forge.lock().unwrap() = false;
    let note = w.note(app.app_id(), "after the operator's answers").0;
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .all(|e| matches!(e, AppEvent::MessageReceived { .. })),
        "{:?}",
        report.events
    );
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::MessageReceived { seq, .. } if *seq == note)),
        "{:?}",
        report.events
    );
}
