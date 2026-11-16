//! The service time a first send is stamped with ([`App::stamp_service_time`]): none is
//! read while the app holds a recent one of the current service key, and where one is read
//! it is a feed page with no items (Switch wire 7.4.4).

use pubky_switch_core::ops::{AllowKind, OpKind};
use pubky_switch_core::scopes::Permission;

use super::moves::{Router, approve_with, join};
use super::*;
use crate::app::OpBatch;
use crate::app::provider::{FRESH_SERVICE_TIME_MS, RECENT_SERVICE_TIME_MS};
use crate::testing::Fault;

fn conversation(pubky: [u8; 32]) -> OpBatch {
    OpBatch::new().op(OpKind::AllowPut {
        pubky,
        kind: AllowKind::Conversation,
    })
}

/// The feed reads among the requests sent since `from`.
fn feed_reads(router: &Router, from: usize) -> Vec<String> {
    router.log()[from..]
        .iter()
        .filter(|line| line.contains("/feed"))
        .cloned()
        .collect()
}

/// A write whose answer is lost, so its batch stays kept: the time it was stamped at.
async fn stamp_of_a_kept_write(w: &World, app: &mut App) -> u64 {
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(
        app.submit_batch(conversation(w.bob.public()))
            .await
            .is_err()
    );
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    kept[0].1.kept_ms.unwrap()
}

#[tokio::test]
async fn test_service_time_recent_and_of_the_current_key_is_not_read_for_a_first_send() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.receive(None).await.unwrap();
    let held = app.highest_service_time().unwrap();
    // Up to a day on, a later call's first send reads no time: its batch goes alone.
    w.clock.advance_ms(RECENT_SERVICE_TIME_MS);
    let from = router.log().len();
    let stamp = stamp_of_a_kept_write(&w, &mut app).await;
    assert_eq!(feed_reads(&router, from), Vec::<String>::new());
    assert_eq!(router.log().len(), from + 1, "{:?}", router.log());
    // Stamped at the earlier of the device clock and the time held: never after the time
    // the service applied it.
    assert_eq!(stamp, held);
}

#[tokio::test]
async fn test_service_time_older_than_a_day_is_read_before_a_first_send() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.receive(None).await.unwrap();
    w.clock.advance_ms(RECENT_SERVICE_TIME_MS + 1);
    let from = router.log().len();
    let stamp = stamp_of_a_kept_write(&w, &mut app).await;
    // One read of a page with no items, before the batch.
    let reads = feed_reads(&router, from);
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert!(reads[0].ends_with("limit=0"), "{reads:?}");
    let log = router.log();
    assert!(log[from].contains("/feed"), "{log:?}");
    assert!(log[from + 1].contains("/ops"), "{log:?}");
    assert_eq!(stamp, w.clock.now_ms());
}

#[tokio::test]
async fn test_service_time_of_another_key_or_none_is_read_before_a_first_send() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.receive(None).await.unwrap();
    let key = app.state.meta.service_key;
    for held in [
        None,
        app.state
            .service_time
            .map(|time| crate::app::state::ServiceTime {
                key: [9; 32],
                ..time
            }),
    ] {
        // A later call, so no answer of this one brought a time.
        w.clock.advance_ms(FRESH_SERVICE_TIME_MS + 1);
        app.state.service_time = held;
        let from = router.log().len();
        app.submit_batch(conversation([7; 32])).await.unwrap();
        let reads = feed_reads(&router, from);
        assert_eq!(reads.len(), 1, "{held:?}: {reads:?}");
        assert!(reads[0].ends_with("limit=0"), "{reads:?}");
        assert_eq!(app.state.service_time.map(|time| time.key), Some(key));
    }
}

#[tokio::test]
async fn test_service_time_ahead_of_the_device_clock_is_not_read_and_the_device_time_stamps() {
    let w = World::new();
    let router = Router::of(&w);
    // The app's own clock, a minute behind the service's from here on.
    let clock = Arc::new(TestClock::new(w.clock.now_ms()));
    let mut env = router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>);
    env.clock = Arc::clone(&clock) as Arc<dyn Clock>;
    let mut app = App::join(
        env,
        w.protocol.clone(),
        World::config(),
        approve_with(&w, &[Permission::ConversationAdd]),
    )
    .await
    .unwrap();
    w.clock.advance_ms(60_000);
    app.receive(None).await.unwrap();
    let held = app.highest_service_time().unwrap();
    clock.advance_ms(FRESH_SERVICE_TIME_MS + 1);
    w.clock.advance_ms(FRESH_SERVICE_TIME_MS + 1);
    assert!(clock.now_ms() < w.clock.now_ms());
    let from = router.log().len();
    let stamp = stamp_of_a_kept_write(&w, &mut app).await;
    assert_eq!(feed_reads(&router, from), Vec::<String>::new());
    // The earlier of the two: the device clock's when the held time is ahead of it, the
    // held time otherwise.
    assert_eq!(stamp, clock.now_ms().min(held));
}

#[tokio::test]
async fn test_service_time_read_for_a_kept_batch_is_a_page_with_no_items() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.receive(None).await.unwrap();
    stamp_of_a_kept_write(&w, &mut app).await;
    // A later call sends the kept batch again: its age is judged at a time read in that
    // call, whatever time the app holds.
    w.clock.advance_ms(FRESH_SERVICE_TIME_MS + 1);
    let from = router.log().len();
    app.submit_batch(conversation([7; 32])).await.unwrap();
    let reads = feed_reads(&router, from);
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert!(reads[0].ends_with("limit=0"), "{reads:?}");
    assert!(router.log()[from].contains("/feed"), "{:?}", router.log());
    assert!(app.kept_batches().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_service_time_brought_before_a_change_of_service_isnt_fresh_after_it() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.receive(None).await.unwrap();
    // A time an answer of this call brought counts for the call.
    let from = router.log().len();
    app.fresh_service_time().await.unwrap();
    assert_eq!(feed_reads(&router, from), Vec::<String>::new());
    // Once the client is built again, as for another service, it is read again.
    app.rebuild_client().unwrap();
    let from = router.log().len();
    app.fresh_service_time().await.unwrap();
    let reads = feed_reads(&router, from);
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert!(reads[0].ends_with("limit=0"), "{reads:?}");
}

#[tokio::test]
async fn test_service_time_restored_headless_refusal_establishes_watermark() {
    use crate::app::{Alarm, AppError, AppEvent};
    use crate::error::ClientError;
    use pubky_switch_core::http::ErrorCode;

    let w = World::new();
    let original = Box::pin(w.join("wallet")).await;
    let backup = Box::pin(original.backup()).await.unwrap();
    let router = Router::of(&w);
    let mut app = Box::pin(App::restore(
        router.env(&w, Arc::new(MemoryStore::new())),
        w.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    Box::pin(app.refresh_identity()).await.unwrap();
    assert!(
        router.log().is_empty(),
        "restore and revalidation sent no service call"
    );
    assert_eq!(app.highest_service_time(), None);
    let high = START + 2_000;
    let low = START + 1_000;
    w.switch.lock().stamped_ms = high;
    w.switch.fail_next(Fault::Error {
        path: "/directory".into(),
        code: ErrorCode::BadSignature,
        current: json!(null),
    });
    let first = Box::pin(app.receive(None)).await.unwrap_err();
    assert!(
        matches!(
            first,
            AppError::Switch(ClientError::Switch {
                status: 401,
                code: ErrorCode::BadSignature,
                ..
            })
        ),
        "first refusal must verify: {first:?}"
    );
    assert_eq!(app.client.latest_compared_time(), Some(high));
    assert_eq!(
        app.client.latest_server_time(),
        None,
        "headless, not a clock-offset sample"
    );
    assert!(app.alarm().is_none());
    assert!(
        !app.events
            .iter()
            .any(|event| matches!(event, AppEvent::ClockSkew { .. }))
    );
    assert_eq!(router.log().len(), 1, "{:?}", router.log());
    assert!(router.log()[0].ends_with("/directory"));

    w.switch.lock().stamped_ms = low;
    w.switch.fail_next(Fault::Error {
        path: "/directory".into(),
        code: ErrorCode::BadSignature,
        current: json!(null),
    });
    let second = Box::pin(app.receive(None)).await.unwrap_err();
    assert_eq!(
        router.log().len(),
        2,
        "no successful call between refusals: {:?}",
        router.log()
    );
    assert_eq!(app.client.latest_compared_time(), Some(low));
    assert!(
        matches!(second, AppError::Alarm(Alarm::ServiceTimeBackwards {
        highest, signed
    }) if highest == high && signed == low),
        "a restored app must compare its first verified headless answer: {second:?}"
    );
}

#[tokio::test]
async fn test_service_time_stamped_baseline_detects_headless_refusal() {
    use crate::app::{Alarm, AppError};
    use pubky_switch_core::http::ErrorCode;

    let w = World::new();
    let original = Box::pin(w.join("wallet")).await;
    let backup = Box::pin(original.backup()).await.unwrap();
    let router = Router::of(&w);
    let mut app = Box::pin(App::restore(
        router.env(&w, Arc::new(MemoryStore::new())),
        w.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    Box::pin(app.refresh_identity()).await.unwrap();
    assert!(router.log().is_empty());
    assert_eq!(app.highest_service_time(), None);
    let high = START + 2_000;
    let low = START + 1_000;
    w.clock.set_ms(high);
    Box::pin(app.receive(None)).await.unwrap();
    assert_eq!(
        app.highest_service_time(),
        Some(high),
        "stamped baseline established normally"
    );
    let before = router.log().len();
    w.switch.lock().stamped_ms = low;
    w.switch.fail_next(Fault::Error {
        path: "/feed".into(),
        code: ErrorCode::BadSignature,
        current: json!(null),
    });
    let refused = Box::pin(app.receive(None)).await.unwrap_err();
    assert_eq!(router.log().len(), before + 1, "{:?}", router.log());
    assert_eq!(app.client.latest_compared_time(), Some(low));
    assert_eq!(app.client.latest_server_time(), None);
    assert!(
        matches!(refused, AppError::Alarm(Alarm::ServiceTimeBackwards {
        highest, signed
    }) if highest == high && signed == low),
        "the same refusal must alarm after a stamped baseline: {refused:?}"
    );
}

/// A restored app has a pinned service key but no clock sample or time watermark.
async fn restored(w: &World, router: &Router, store: Arc<dyn StateStore>) -> App {
    let original = Box::pin(w.join("wallet")).await;
    let backup = Box::pin(original.backup()).await.unwrap();
    let mut app = Box::pin(App::restore(
        router.env(w, store),
        w.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    Box::pin(app.refresh_identity()).await.unwrap();
    assert_eq!(app.highest_service_time(), None);
    app
}

/// Each request gets the next signed refusal, including the client's automatic retry.
fn refuse_at(
    w: &World,
    router: &Router,
    answers: impl IntoIterator<Item = (u64, pubky_switch_core::http::ErrorCode)>,
) -> Arc<crate::transport::MockTransport> {
    let answers = Mutex::new(
        answers
            .into_iter()
            .collect::<std::collections::VecDeque<_>>(),
    );
    let switch = w.switch.clone();
    let transport = Arc::new(crate::transport::MockTransport::with_handler(
        move |request| {
            let (time, code) = answers
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted refusal");
            switch.lock().stamped_ms = time;
            switch.fail_next(Fault::Error {
                path: request.path_and_query.clone(),
                code,
                current: json!({"server_time": pubky_switch_core::time::rfc3339(START)}),
            });
            switch.handle(request)
        },
    ));
    router.add_transport(crate::testing::SWITCH_ORIGIN, transport.clone());
    transport
}

fn assert_time_alarm(error: crate::app::AppError, highest: u64, signed: u64) {
    assert!(
        matches!(error, crate::app::AppError::Alarm(crate::app::Alarm::ServiceTimeBackwards {
            highest: held, signed: shown
        }) if held == highest && shown == signed),
        "expected time alarm ({highest}, {signed}), got {error:?}"
    );
}

#[tokio::test]
async fn test_service_time_first_headless_refusal_survives_load_without_clock_sample() {
    use pubky_switch_core::http::ErrorCode;
    let w = World::new();
    let router = Router::of(&w);
    let store = Arc::new(MemoryStore::new());
    let mut app = Box::pin(restored(&w, &router, store.clone())).await;
    let id = app.app_id();
    let high = START + 2_000;
    let low = START + 1_000;
    let transport = refuse_at(
        &w,
        &router,
        [
            (high, ErrorCode::BadSignature),
            (low, ErrorCode::BadSignature),
        ],
    );
    assert!(Box::pin(app.receive(None)).await.is_err());
    drop(app);
    let mut loaded = Box::pin(App::load(
        router.env(&w, store),
        w.protocol.clone(),
        World::config(),
        id,
    ))
    .await
    .unwrap();
    assert_eq!(
        loaded.highest_service_time(),
        Some(high),
        "the first refusal is durable"
    );
    assert_eq!(
        loaded.state.service_time.unwrap().offset_ms,
        None,
        "no stamped clock sample"
    );
    assert_eq!(loaded.clock_skew_ms(), Some(high - START));
    Box::pin(loaded.refresh_identity()).await.unwrap();
    assert_time_alarm(Box::pin(loaded.receive(None)).await.unwrap_err(), high, low);
    assert_eq!(transport.requests().len(), 2);
}

#[tokio::test]
async fn test_service_time_higher_headless_refusal_survives_error_reload() {
    use pubky_switch_core::http::ErrorCode;
    let w = World::new();
    let router = Router::of(&w);
    let mut app = Box::pin(join(&w, &router)).await;
    assert_eq!(app.highest_service_time(), Some(START));
    let high = START + 2_000;
    let low = START + 1_000;
    let transport = refuse_at(
        &w,
        &router,
        [
            (high, ErrorCode::BadSignature),
            (low, ErrorCode::BadSignature),
        ],
    );
    assert!(Box::pin(app.receive(None)).await.is_err());
    assert_eq!(app.highest_service_time(), Some(high));
    assert!(app.reload, "the failed receive reloads before the next one");
    assert_time_alarm(Box::pin(app.receive(None)).await.unwrap_err(), high, low);
    assert_eq!(transport.requests().len(), 2);
}

#[tokio::test]
async fn test_service_time_retry_compares_both_headless_answers() {
    use pubky_switch_core::http::ErrorCode;
    let w = World::new();
    let router = Router::of(&w);
    let mut app = Box::pin(restored(&w, &router, Arc::new(MemoryStore::new()))).await;
    let high = START + 2_000;
    let low = START + 1_000;
    let transport = refuse_at(
        &w,
        &router,
        [
            (high, ErrorCode::StaleTimestamp),
            (low, ErrorCode::BadSignature),
        ],
    );
    let error = Box::pin(app.receive(None)).await.unwrap_err();
    assert_eq!(transport.requests().len(), 2, "the same call retried once");
    assert_time_alarm(error, high, low);
}

#[tokio::test]
async fn test_service_time_retry_cannot_hide_first_backward_answer() {
    use pubky_switch_core::http::ErrorCode;
    let w = World::new();
    let router = Router::of(&w);
    let mut app = Box::pin(join(&w, &router)).await;
    assert_eq!(app.highest_service_time(), Some(START));
    let transport = refuse_at(
        &w,
        &router,
        [
            (START - 1_000, ErrorCode::StaleTimestamp),
            (START + 1_000, ErrorCode::BadSignature),
        ],
    );
    let error = Box::pin(app.receive(None)).await.unwrap_err();
    assert_eq!(transport.requests().len(), 2);
    assert_time_alarm(error, START, START - 1_000);
}

#[tokio::test]
async fn test_service_time_retry_uncompared_answer_preserves_first_watermark() {
    use pubky_switch_core::http::ErrorCode;
    let w = World::new();
    let router = Router::of(&w);
    let store = Arc::new(MemoryStore::new());
    let mut app = Box::pin(restored(&w, &router, store.clone())).await;
    let id = app.app_id();
    let high = START + 2_000;
    let transport = refuse_at(
        &w,
        &router,
        [
            (high, ErrorCode::StaleTimestamp),
            (START, ErrorCode::Unavailable),
        ],
    );
    let error = Box::pin(app.receive(None)).await.unwrap_err();
    assert!(
        matches!(
            error,
            crate::app::AppError::Switch(crate::error::ClientError::Switch {
                code: ErrorCode::Unavailable,
                ..
            })
        ),
        "{error:?}"
    );
    assert_eq!(transport.requests().len(), 2);
    drop(app);
    let loaded = Box::pin(App::load(
        router.env(&w, store),
        w.protocol.clone(),
        World::config(),
        id,
    ))
    .await
    .unwrap();
    assert_eq!(loaded.highest_service_time(), Some(high));
    assert_eq!(loaded.state.service_time.unwrap().offset_ms, None);
    assert_eq!(loaded.clock_skew_ms(), Some(high - START));
    assert!(
        loaded.alarm().is_none(),
        "the unavailable time does not compare"
    );
}

#[tokio::test]
async fn test_service_time_retry_nondecreasing_headless_answers_are_not_an_alarm() {
    use pubky_switch_core::http::ErrorCode;
    let w = World::new();
    let router = Router::of(&w);
    let mut app = Box::pin(join(&w, &router)).await;
    let high = START + 2_000;
    let transport = refuse_at(
        &w,
        &router,
        [
            (START + 1_000, ErrorCode::StaleTimestamp),
            (high, ErrorCode::BadSignature),
        ],
    );
    let error = Box::pin(app.receive(None)).await.unwrap_err();
    assert!(
        matches!(
            error,
            crate::app::AppError::Switch(crate::error::ClientError::Switch {
                code: ErrorCode::BadSignature,
                ..
            })
        ),
        "{error:?}"
    );
    assert_eq!(transport.requests().len(), 2);
    assert_eq!(app.highest_service_time(), Some(high));
    assert!(app.alarm().is_none());
}

#[tokio::test]
async fn test_service_time_failed_watermark_commit_is_retried_before_reload() {
    use pubky_switch_core::http::ErrorCode;
    let w = World::new();
    let router = Router::of(&w);
    let store = Arc::new(MemoryStore::new());
    let app = Box::pin(restored(&w, &router, store.clone())).await;
    let id = app.app_id();
    drop(app);
    let fault = Arc::new(crate::store::FaultStore::new(
        store,
        crate::store::Fault::FailBefore(1),
    ));
    let mut app = Box::pin(App::load(
        router.env(&w, fault.clone()),
        w.protocol.clone(),
        World::config(),
        id,
    ))
    .await
    .unwrap();
    Box::pin(app.refresh_identity()).await.unwrap();
    let high = START + 2_000;
    let low = START + 1_000;
    let transport = refuse_at(
        &w,
        &router,
        [
            (high, ErrorCode::BadSignature),
            (low, ErrorCode::BadSignature),
        ],
    );
    let error = Box::pin(app.receive(None)).await.unwrap_err();
    assert!(
        matches!(error, crate::app::AppError::Store(_)),
        "watermark commit must fail: {error:?}"
    );
    assert_eq!(fault.commits(), 1);
    assert_time_alarm(Box::pin(app.receive(None)).await.unwrap_err(), high, low);
    assert_eq!(transport.requests().len(), 2);
}

#[tokio::test]
async fn test_service_time_first_headless_watermark_bounds_automatic_attempts() {
    use crate::app::{AppEvent, Refusal, UserConfirmed};
    use pubky_switch_core::http::ErrorCode;
    use pubky_switch_core::records::CLOCK_TOLERANCE_MS;

    let w = World::new();
    let router = Router::of(&w);
    let store = Arc::new(MemoryStore::new());
    let mut app = Box::pin(restored(&w, &router, store.clone())).await;
    Box::pin(app.end_reconcile(UserConfirmed::new()))
        .await
        .unwrap();
    assert!(app.may_attempt(false).is_ok());
    assert!(app.may_attempt(true).is_ok());
    assert!(app.state.service_time.is_none());
    let ahead = CLOCK_TOLERANCE_MS + 1;
    let high = START + ahead;
    let transport = refuse_at(&w, &router, [(high, ErrorCode::BadSignature)]);
    assert!(Box::pin(app.receive(None)).await.is_err());
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(app.highest_service_time(), Some(high));
    assert_eq!(app.client.latest_server_time(), None);
    assert_eq!(app.state.service_time.unwrap().offset_ms, None);
    assert!(
        app.may_attempt(false).is_ok(),
        "the verified lower bound does not forbid manual attempts"
    );
    assert!(
        matches!(app.may_attempt(true), Err(Refusal::NotNow(_))),
        "automatic attempts must pause at the verified lower bound"
    );
    assert_eq!(
        app.clock_skew_ms(),
        Some(ahead),
        "the verified lower bound is independent of an offset sample"
    );
    assert!(
        app.take_events()
            .iter()
            .any(|event| matches!(event, AppEvent::ClockSkew { skew_ms } if *skew_ms == ahead))
    );
    let id = app.app_id();
    drop(app);
    let loaded = Box::pin(App::load(
        router.env(&w, store),
        w.protocol.clone(),
        World::config(),
        id,
    ))
    .await
    .unwrap();
    assert_eq!(loaded.clock_skew_ms(), Some(ahead));
    assert_eq!(loaded.state.service_time.unwrap().offset_ms, None);
    w.clock.advance_ms(ahead);
    assert!(loaded.may_attempt(true).is_ok());
    assert_eq!(
        transport.requests().len(),
        1,
        "the bound changes without another service response"
    );
}

/// One first comparable refusal after public restore, with no stamped clock sample.
async fn first_headless_clock(
    w: &World,
    router: &Router,
    store: Arc<dyn StateStore>,
    at: u64,
) -> (App, Arc<crate::transport::MockTransport>) {
    use crate::app::{AppError, UserConfirmed};
    use crate::error::ClientError;
    use pubky_switch_core::http::ErrorCode;

    let mut app = Box::pin(restored(w, router, store)).await;
    Box::pin(app.end_reconcile(UserConfirmed::new()))
        .await
        .unwrap();
    assert!(app.may_attempt(false).is_ok());
    assert!(app.may_attempt(true).is_ok());
    assert!(app.state.service_time.is_none());
    let transport = refuse_at(w, router, [(at, ErrorCode::BadSignature)]);
    let error = Box::pin(app.receive(None)).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Switch(ClientError::Switch {
                code: ErrorCode::BadSignature,
                ..
            })
        ),
        "{error:?}"
    );
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(app.highest_service_time(), Some(at));
    assert_eq!(app.client.latest_server_time(), None);
    assert_eq!(app.state.service_time.unwrap().offset_ms, None);
    (app, transport)
}

#[tokio::test]
async fn test_service_time_first_headless_bound_warns_over_tolerance() {
    use crate::app::AppEvent;
    use pubky_switch_core::records::CLOCK_TOLERANCE_MS;
    let w = World::new();
    let router = Router::of(&w);
    let ahead = CLOCK_TOLERANCE_MS + 1;
    let (mut app, _) = Box::pin(first_headless_clock(
        &w,
        &router,
        Arc::new(MemoryStore::new()),
        START + ahead,
    ))
    .await;
    assert!(app.may_attempt(false).is_ok());
    assert!(
        app.take_events()
            .iter()
            .any(|event| matches!(event, AppEvent::ClockSkew { skew_ms } if *skew_ms == ahead)),
        "the verified forward bound must warn without a sampled offset"
    );
}

#[tokio::test]
async fn test_service_time_first_headless_bound_warns_beyond_a_day() {
    use crate::app::{AppEvent, SERVICE_TIME_AHEAD_MS};
    let w = World::new();
    let router = Router::of(&w);
    let ahead = SERVICE_TIME_AHEAD_MS + 1;
    let (mut app, _) = Box::pin(first_headless_clock(
        &w,
        &router,
        Arc::new(MemoryStore::new()),
        START + ahead,
    ))
    .await;
    assert!(
        app.take_events()
            .iter()
            .any(|event| matches!(event, AppEvent::ClockSkew { skew_ms } if *skew_ms == ahead)),
        "a time more than a day ahead must be shown to the user"
    );
    assert!(app.may_attempt(true).is_err());
    assert!(app.may_attempt(false).is_ok());
    assert_eq!(app.state.service_time.unwrap().offset_ms, None);
}

#[tokio::test]
async fn test_service_time_headless_stale_near_and_exact_tolerance_are_healthy() {
    use crate::app::AppEvent;
    use pubky_switch_core::records::{CLOCK_TOLERANCE_MS, DAY_MS};
    for at in [
        START - 3 * DAY_MS,
        START,
        START + 2_000,
        START + CLOCK_TOLERANCE_MS,
    ] {
        let w = World::new();
        let router = Router::of(&w);
        let (mut app, _) = Box::pin(first_headless_clock(
            &w,
            &router,
            Arc::new(MemoryStore::new()),
            at,
        ))
        .await;
        assert!(app.may_attempt(true).is_ok(), "{at}");
        assert!(app.may_attempt(false).is_ok(), "{at}");
        assert!(
            !app.take_events()
                .iter()
                .any(|event| matches!(event, AppEvent::ClockSkew { .. })),
            "{at}"
        );
        assert_eq!(app.state.service_time.unwrap().offset_ms, None, "{at}");
    }
}

#[tokio::test]
async fn test_service_time_headless_forward_bound_is_applied_after_load() {
    use crate::app::Refusal;
    use pubky_switch_core::records::CLOCK_TOLERANCE_MS;
    let w = World::new();
    let router = Router::of(&w);
    let store = Arc::new(MemoryStore::new());
    let high = START + CLOCK_TOLERANCE_MS + 1;
    let (app, transport) = Box::pin(first_headless_clock(&w, &router, store.clone(), high)).await;
    let id = app.app_id();
    drop(app);
    let loaded = Box::pin(App::load(
        router.env(&w, store),
        w.protocol.clone(),
        World::config(),
        id,
    ))
    .await
    .unwrap();
    assert_eq!(loaded.highest_service_time(), Some(high));
    assert_eq!(loaded.state.service_time.unwrap().offset_ms, None);
    assert!(loaded.may_attempt(false).is_ok());
    assert_eq!(transport.requests().len(), 1);
    assert!(
        matches!(loaded.may_attempt(true), Err(Refusal::NotNow(_))),
        "a loaded watermark independently bounds automatic attempts"
    );
}

#[tokio::test]
async fn test_service_time_headless_bound_allows_device_catch_up() {
    use pubky_switch_core::records::CLOCK_TOLERANCE_MS;
    let w = World::new();
    let router = Router::of(&w);
    let high = START + CLOCK_TOLERANCE_MS + 1;
    let (app, transport) = Box::pin(first_headless_clock(
        &w,
        &router,
        Arc::new(MemoryStore::new()),
        high,
    ))
    .await;
    w.clock.advance_ms(1);
    assert!(
        app.may_attempt(true).is_ok(),
        "exact tolerance is permitted"
    );
    w.clock.advance_ms(CLOCK_TOLERANCE_MS);
    assert!(
        app.may_attempt(true).is_ok(),
        "the clock reached the watermark"
    );
    assert!(app.may_attempt(false).is_ok());
    assert_eq!(app.highest_service_time(), Some(high));
    assert_eq!(app.state.service_time.unwrap().offset_ms, None);
    assert_eq!(
        transport.requests().len(),
        1,
        "no new service sample was needed"
    );
}

/// An unapplied commit whose host cannot tell whether it applied.
struct UnknownCommit(Arc<crate::store::FaultStore>);

impl StateStore for UnknownCommit {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, crate::store::StoreError> {
        self.0.get(ns, key)
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<crate::store::KeyValue>, crate::store::StoreError> {
        self.0.scan(ns, prefix, after, limit)
    }

    fn commit(&self, batch: crate::store::WriteBatch) -> Result<(), crate::store::StoreError> {
        self.0.commit(batch).map_err(|error| match error {
            crate::store::StoreError::Unavailable => crate::store::StoreError::Unknown,
            error => error,
        })
    }
}

async fn alarm_commit_case(
    fault: crate::store::Fault,
    unknown_before: bool,
) -> (
    App,
    Arc<crate::store::FaultStore>,
    Arc<crate::transport::MockTransport>,
    crate::app::Alarm,
) {
    use crate::app::{Alarm, Refusal, UserConfirmed};
    use pubky_switch_core::http::ErrorCode;

    let w = World::new();
    let router = Router::of(&w);
    let store = Arc::new(MemoryStore::new());
    let mut app = Box::pin(restored(&w, &router, store.clone())).await;
    Box::pin(app.end_reconcile(UserConfirmed::new()))
        .await
        .unwrap();
    assert!(router.log().is_empty());
    let id = app.app_id();
    drop(app);
    let fault = Arc::new(crate::store::FaultStore::new(store, fault));
    let durable: Arc<dyn StateStore> = if unknown_before {
        Arc::new(UnknownCommit(fault.clone()))
    } else {
        fault.clone()
    };
    let mut app = Box::pin(App::load(
        router.env(&w, durable),
        w.protocol.clone(),
        World::config(),
        id,
    ))
    .await
    .unwrap();
    Box::pin(app.refresh_identity()).await.unwrap();
    assert_eq!(fault.commits(), 0);
    assert!(router.log().is_empty());
    assert_eq!(app.highest_service_time(), None);
    assert_eq!(app.clock_skew_ms(), None);
    assert_eq!(app.may_attempt(false), Ok(()));
    assert_eq!(app.may_attempt(true), Ok(()));
    let high = START + 2_000;
    let low = START + 1_000;
    let transport = refuse_at(
        &w,
        &router,
        [
            (high, ErrorCode::StaleTimestamp),
            (low, ErrorCode::BadSignature),
            (high, ErrorCode::BadSignature),
        ],
    );
    assert_time_alarm(Box::pin(app.receive(None)).await.unwrap_err(), high, low);
    let expected = Alarm::ServiceTimeBackwards {
        highest: high,
        signed: low,
    };
    assert_eq!(fault.commits(), 1);
    assert_eq!(transport.requests().len(), 2);
    assert!(
        transport
            .requests()
            .iter()
            .all(|request| request.path_and_query.ends_with("/directory"))
    );
    assert_eq!(app.alarm(), Some(&expected));
    assert_eq!(app.highest_service_time(), Some(high));
    assert_eq!(app.client.latest_compared_time(), Some(low));
    assert_eq!(app.client.latest_server_time(), None);
    assert_eq!(app.may_attempt(false), Err(Refusal::Stopped));
    assert_eq!(app.may_attempt(true), Err(Refusal::Stopped));
    (app, fault, transport, expected)
}

async fn assert_alarm_survives_reload(
    mut app: App,
    transport: Arc<crate::transport::MockTransport>,
    expected: crate::app::Alarm,
) {
    use crate::app::state::{ServiceTime, key};
    use crate::app::{Alarm, AppError, Refusal};

    let error = Box::pin(app.receive(None)).await.unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Stopped));
    assert_eq!(transport.requests().len(), 2);
    Box::pin(app.pending_duty_events()).await.unwrap();
    assert_eq!(app.alarm(), Some(&expected));
    assert_eq!(
        app.reader().get::<Alarm>(key::ALARM).await.unwrap(),
        Some(expected.clone())
    );
    let time = app
        .reader()
        .get::<ServiceTime>(key::SERVICE_TIME)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(time.highest_ms, START + 2_000);
    assert_eq!(time.offset_ms, None);
    let env = app.env.clone();
    let protocol = app.protocol.clone();
    let config = app.config.clone();
    let id = app.app_id();
    drop(app);
    let mut loaded = Box::pin(App::load(env, protocol, config, id))
        .await
        .unwrap();
    assert_eq!(loaded.alarm(), Some(&expected));
    assert_eq!(loaded.may_attempt(false), Err(Refusal::Stopped));
    assert_eq!(loaded.may_attempt(true), Err(Refusal::Stopped));
    assert_eq!(
        Box::pin(loaded.receive(None)).await.unwrap_err(),
        AppError::Refused(Refusal::Stopped)
    );
    assert_eq!(transport.requests().len(), 2);
}

#[tokio::test]
async fn test_alarm_failed_commit_remains_stopped_after_reload() {
    use crate::app::state::key;
    let (app, _, transport, alarm) =
        Box::pin(alarm_commit_case(crate::store::Fault::FailBefore(1), false)).await;
    assert_eq!(
        app.reader()
            .get::<crate::app::Alarm>(key::ALARM)
            .await
            .unwrap(),
        None
    );
    Box::pin(assert_alarm_survives_reload(app, transport, alarm)).await;
}

#[tokio::test]
async fn test_alarm_unknown_unapplied_commit_remains_stopped_after_reload() {
    use crate::app::state::key;
    let (app, _, transport, alarm) =
        Box::pin(alarm_commit_case(crate::store::Fault::FailBefore(1), true)).await;
    assert_eq!(
        app.reader()
            .get::<crate::app::Alarm>(key::ALARM)
            .await
            .unwrap(),
        None
    );
    Box::pin(assert_alarm_survives_reload(app, transport, alarm)).await;
}

#[tokio::test]
async fn test_alarm_unknown_applied_commit_remains_stopped_after_reload() {
    use crate::app::state::key;
    let (app, _, transport, alarm) =
        Box::pin(alarm_commit_case(crate::store::Fault::FailAfter(1), false)).await;
    assert_eq!(
        app.reader()
            .get::<crate::app::Alarm>(key::ALARM)
            .await
            .unwrap(),
        Some(alarm.clone())
    );
    Box::pin(assert_alarm_survives_reload(app, transport, alarm)).await;
}

#[tokio::test]
async fn test_alarm_failed_retry_stays_stopped_until_persisted() {
    use crate::app::state::key;
    use crate::app::{Alarm, AppError, Refusal};
    let (mut app, fault, transport, alarm) =
        Box::pin(alarm_commit_case(crate::store::Fault::FailBefore(1), false)).await;
    fault.fail_put_once(key::ALARM.as_bytes());
    let error = Box::pin(app.receive(None)).await.unwrap_err();
    assert_eq!(
        error,
        AppError::Store(crate::store::StoreError::Unavailable)
    );
    assert_eq!(app.alarm(), Some(&alarm));
    assert_eq!(app.may_attempt(false), Err(Refusal::Stopped));
    assert_eq!(app.may_attempt(true), Err(Refusal::Stopped));
    assert_eq!(app.reader().get::<Alarm>(key::ALARM).await.unwrap(), None);
    assert_eq!(transport.requests().len(), 2);
    Box::pin(assert_alarm_survives_reload(app, transport, alarm)).await;
}

#[tokio::test]
async fn test_alarm_successful_commit_remains_stopped_after_reload() {
    let (app, fault, transport, alarm) =
        Box::pin(alarm_commit_case(crate::store::Fault::None, false)).await;
    Box::pin(assert_alarm_survives_reload(app, transport, alarm)).await;
    assert_eq!(fault.commits(), 1);
}
