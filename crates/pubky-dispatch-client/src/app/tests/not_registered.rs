//! A `403 not_current` an own app gets before its request verified, with no `Dispatch-Head`,
//! is the refusal of a first call: the service holds no record of the app to verify it
//! with (Dispatch wire 7.1 "`Dispatch-Head` on refusals", 7.2). It says the app isn't
//! registered there, not that it was revoked or departed, so the app doesn't take itself as
//! removed on it. A `403 not_current` with the head comes after the request verified, and
//! is (Dispatch spec 12.2, 12.3).

use super::moves::has;
use super::*;
use crate::app::{AppError, AppEvent};
use crate::testing::Fault;
use crate::transport::{BoxFuture, Request, Response, Transport};
use crate::{TransportError, error::ClientError};
use pubky_dispatch_core::http::{ErrorCode, header};

/// The Dispatch, every `403` answered without its head, as before the request verified, and
/// signed again with the service key over that answer (Dispatch wire 7.1).
struct Headless(Arc<dyn Transport>, ed25519_dalek::SigningKey);

impl Transport for Headless {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            let sent = crate::client::SentRequest::of(&request);
            let mut response = self.0.send(request).await?;
            if response.status == 403 {
                response
                    .headers
                    .retain(|h| !h.name.eq_ignore_ascii_case(header::HEAD));
                let server_time = response.header(header::SERVER_TIME).unwrap().to_owned();
                let signature = pubky_dispatch_core::http::sign_response(
                    &self.1,
                    &pubky_dispatch_core::http::ResponseParts {
                        status: response.status,
                        request: sent.received(true),
                        server_time: &server_time,
                        head: None,
                        body: &response.body,
                    },
                );
                response
                    .headers
                    .retain(|h| !h.name.eq_ignore_ascii_case(header::SERVICE_SIGNATURE));
                response.headers.push(crate::transport::Header::new(
                    header::SERVICE_SIGNATURE,
                    &pubky_dispatch_core::enc::b64(&signature),
                ));
            }
            Ok(response)
        })
    }
}

fn not_current() -> Fault {
    Fault::Error {
        path: "feed".into(),
        code: ErrorCode::NotCurrent,
        current: json!(null),
    }
}

#[tokio::test]
async fn test_not_registered_headless_not_current_isnt_a_removal() {
    let w = World::new();
    let me = w.join("wallet").await.app_id();
    let env = AppEnv {
        transport: Arc::new(Headless(
            w.dispatch.transport(),
            w.dispatch.lock().service.clone(),
        )),
        ..w.env()
    };
    let mut app = App::load(env, w.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    w.dispatch.fail_next(not_current());
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(
            &error,
            AppError::Dispatch(ClientError::Dispatch {
                code: ErrorCode::NotCurrent,
                ..
            })
        ),
        "{error:?}"
    );
    assert!(!has(&app.take_events(), |e| matches!(e, AppEvent::Removed)));
    // Not gone: the next read goes on.
    let report = app.receive(None).await.unwrap();
    assert!(!report.stopped, "{:?}", report.events);
    assert!(!has(&report.events, |e| matches!(e, AppEvent::Removed)));
}

#[tokio::test]
async fn test_not_registered_not_current_with_the_head_is_a_removal() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.dispatch.fail_next(not_current());
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Removed)));
}

/// The Dispatch, counting the requests it is sent.
struct Counting(Arc<dyn Transport>, std::sync::atomic::AtomicUsize);

impl Transport for Counting {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.0.send(request)
    }
}

/// A Dispatch that keeps answering the headless refusal, as one that lost the app's record
/// would: every read fails once, with one request and no event, and nothing is retried
/// inside a read, so the host's own schedule of reads bounds the calls.
#[tokio::test]
async fn test_not_registered_repeated_headless_refusals_cost_one_request_a_read() {
    let w = World::new();
    let me = w.join("wallet").await.app_id();
    let counting = Arc::new(Counting(
        w.dispatch.transport(),
        std::sync::atomic::AtomicUsize::new(0),
    ));
    let env = AppEnv {
        transport: Arc::clone(&counting) as Arc<dyn Transport>,
        ..w.env()
    };
    let mut app = App::load(env, w.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    let held = w.dispatch.lock().apps.get_mut(&me).unwrap().record.take();
    for _ in 0..5 {
        let before = counting.1.load(std::sync::atomic::Ordering::SeqCst);
        let error = app.receive(None).await.unwrap_err();
        assert_eq!(error.code(), Some(ErrorCode::NotCurrent), "{error:?}");
        assert_eq!(
            counting.1.load(std::sync::atomic::Ordering::SeqCst) - before,
            1
        );
        assert!(app.take_events().is_empty());
        w.clock.advance_ms(1_000);
    }
    // Once the Dispatch holds the record again, the next read goes on.
    w.dispatch.lock().apps.get_mut(&me).unwrap().record = held;
    let report = app.receive(None).await.unwrap();
    assert!(!report.stopped);
}

/// Revoked while offline, then purged from `removed`: the Dispatch purges the app's record at
/// that delivery and answers its calls without the head (Dispatch wire 7.2 "Where an own app
/// gets `403 not_current`", 9.1), and keeps its kids, so none is registered again (spec
/// 3.6). The newest identity.json lists the app in neither list, so it ends as removed, and
/// reads on as a stopped app.
#[tokio::test]
async fn test_not_registered_purged_app_ends_as_removed() {
    use pubky_dispatch_core::records::RemovedApp;
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let kids = |w: &World| -> usize {
        w.dispatch
            .lock()
            .kids
            .values()
            .filter(|holder| **holder == me)
            .count()
    };
    let registered = kids(&w);
    assert!(registered > 0);
    w.dispatch.revoke(me).unwrap();
    w.next_doc(|body| {
        body.apps.retain(|listed| listed.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    w.clock.advance_ms(1_000);
    w.next_doc(|body| body.removed.retain(|removed| removed.app_id != me));
    assert!(w.dispatch.app(&me).purged);
    assert_eq!(kids(&w), registered);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Removed)));
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
}
