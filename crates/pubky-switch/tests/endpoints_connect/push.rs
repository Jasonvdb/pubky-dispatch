//! Connect wake-ups use the same queue as notifying entries (wire 7.4.7, 8.2).

use super::*;

async fn setup(push: bool, cap: u64) -> Option<Replay> {
    let mut replay = replay().await?;
    replay.service = replay.service.with_isolated_relays();
    replay_chain_through_revoke(&replay).await;
    take_connect_requests(&replay, cap, push).await;
    deliver_bob(&replay).await;
    Some(replay)
}

async fn register(replay: &Replay, name: &str, handles: &[&str]) {
    let keys = vectors("keys.json");
    register_handles(replay, handles, |path, args| {
        app_request(app(&keys, name), "PUT", path, args, ms(&at()))
    })
    .await;
}

async fn register_handles(
    replay: &Replay,
    handles: &[&str],
    request: impl Fn(&str, Vec<u8>) -> SwitchRequest,
) {
    let path = format!("/v1/{}/push", alice_id());
    let put = async |args: Value| {
        let request = request(&path, serde_json::to_vec(&args).expect("registration"));
        let answer = replay.service.handle(request).await;
        assert_eq!(answer.status, 200, "{:?}", body(&answer));
        body(&answer)
    };
    let url = "https://push.example/hook";
    let start = put(json!({"relay_url": url, "handles": []})).await;
    put(json!({"relay_url": url, "handles": handles, "push_key": start["push_key"]})).await;
}

async fn take_handles(replay: &Replay) -> Vec<String> {
    let store = replay.db.store();
    let mut handles = Vec::new();
    for push in store.claim_pushes(16).await.expect("claim") {
        handles.push(push.handle);
        store.finish_push(push.id).await.expect("finish");
    }
    handles.sort();
    handles
}

async fn ask_fresh(replay: &Replay, n: u8) -> SwitchResponse {
    let sender = fresh(n);
    assert_eq!(
        sender.deliver(replay, &sender.doc(1, |_| {})).await.status,
        200
    );
    sender.ask(replay).await
}

#[tokio::test]
async fn test_connect_push_registered_reader_only() {
    let Some(replay) = setup(true, 50).await else {
        return;
    };
    register_executor(&replay).await;
    register(&replay, "executor", &["other"]).await;
    // The wallet can read the list but has no registration yet.
    assert!(pending(&ask(&replay).await));
    assert!(take_handles(&replay).await.is_empty());
    register(&replay, "wallet", &["phone"]).await;
    assert!(pending(&ask_fresh(&replay, 33).await));
    assert_eq!(take_handles(&replay).await, ["phone"]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_stale_registration() {
    let Some(replay) = setup(true, 50).await else {
        return;
    };
    register(&replay, "wallet", &["phone"]).await;
    // Leave the registration in place to exercise the recipient's currency check.
    assert_eq!(
        sqlx_scalar(
            &replay,
            "INSERT INTO kept_app_ids (account_id, app_id, reason)
        SELECT account_id, app_id, 'document' FROM push_registrations WHERE account_id = $1
        RETURNING 1::bigint"
        )
        .await,
        1
    );
    assert!(pending(&ask(&replay).await));
    assert!(take_handles(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_policy_off() {
    let Some(replay) = setup(false, 50).await else {
        return;
    };
    register(&replay, "wallet", &["phone"]).await;
    assert!(pending(&ask(&replay).await));
    assert!(take_handles(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_service_off() {
    let Some(mut replay) = setup(true, 50).await else {
        return;
    };
    register(&replay, "wallet", &["phone"]).await;
    replay.service = replay.restarted_with(Limits::default()).with_push(false);
    assert!(pending(&ask(&replay).await));
    assert!(take_handles(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_full_list() {
    let Some(replay) = setup(true, 0).await else {
        return;
    };
    register(&replay, "wallet", &["phone"]).await;
    let answer = ask(&replay).await;
    assert!(take_handles(&replay).await.is_empty());
    assert_eq!(code(&answer), (429, json!("quota_exceeded")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_denied() {
    let Some(replay) = setup(true, 50).await else {
        return;
    };
    register(&replay, "wallet", &["phone"]).await;
    wallet_op(&replay, OpKind::DenyPut { pubky: bob() }, 70).await;
    assert!(pending(&ask(&replay).await));
    assert!(take_handles(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_admitted() {
    let Some(replay) = setup(true, 50).await else {
        return;
    };
    register(&replay, "wallet", &["phone"]).await;
    let peer = fresh(33);
    wallet_op(
        &replay,
        OpKind::AllowPut {
            pubky: peer.pubky(),
            kind: AllowKind::Contact,
        },
        71,
    )
    .await;
    assert!(pending(&ask_fresh(&replay, 33).await));
    assert!(take_handles(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_minute_across_senders() {
    let Some(mut replay) = setup(true, 50).await else {
        return;
    };
    register(&replay, "wallet", &["one", "two"]).await;
    assert!(pending(&ask(&replay).await));
    assert_eq!(take_handles(&replay).await, ["one", "two"]);
    let pushed_ms = replay.time.peek().base_ms;
    // The minute holds across a restart. The restarted run's first stamp at the account is
    // its mark's time floor, a minute past the account's first request (Switch wire 7.3,
    // "Time base"): restarted just before the floor, the account's time jumps to it, still
    // inside the push's minute.
    let floor_ms = match replay.marks.read(&alice_id()).await.expect("mark") {
        pubky_switch::marks::MarkRead::Mark(mark) => mark.time_floor_ms,
        other => panic!("no mark: {other:?}"),
    };
    assert!((pushed_ms..pushed_ms + 60_000).contains(&floor_ms));
    replay.clock.advance_ms(floor_ms - 1 - pushed_ms);
    replay.service = replay
        .restarted_with(Limits::default())
        .with_isolated_relays();
    assert!(pending(&ask_fresh(&replay, 33).await));
    assert!(take_handles(&replay).await.is_empty());
    replay.clock.advance_ms(pushed_ms + 59_999 - (floor_ms - 1));
    assert!(pending(&ask_fresh(&replay, 35).await));
    assert!(take_handles(&replay).await.is_empty());
    replay.clock.advance_ms(1);
    // The duplicate still gets the pending answer after its push window has elapsed.
    assert!(pending(&ask(&replay).await));
    assert!(take_handles(&replay).await.is_empty());
    assert!(pending(&ask_fresh(&replay, 34).await));
    assert_eq!(take_handles(&replay).await, ["one", "two"]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_new_reader_within_minute() {
    let Some(replay) = setup(true, 50).await else {
        return;
    };
    let reader = add_list_reader(&replay).await;
    register(&replay, "wallet", &["wallet"]).await;
    register_handles(&replay, &[], |path, body| reader.request("PUT", path, body)).await;
    assert!(pending(&ask(&replay).await));
    assert_eq!(take_handles(&replay).await, ["wallet"]);
    register_handles(&replay, &["reader"], |path, body| {
        reader.request("PUT", path, body)
    })
    .await;
    assert!(pending(&ask_fresh(&replay, 33).await));
    assert_eq!(take_handles(&replay).await, ["reader"]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_relay_failure_leaves_request_pending() {
    let Some(mut replay) = setup(true, 50).await else {
        return;
    };
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let relay = axum::Router::new().route(
        "/hook",
        axum::routing::post(async || axum::http::StatusCode::SERVICE_UNAVAILABLE),
    );
    let serving = tokio::spawn(async move { axum::serve(listener, relay).await });
    replay.service = replay
        .service
        .with_relay_route(std::sync::Arc::new(move |_| Some(address)));
    register(&replay, "wallet", &["one"]).await;
    assert!(pending(&ask(&replay).await));
    assert_eq!(replay.service.deliver_pushes().await.failed, 1);
    serving.abort();
    let retries = "SELECT count(*) FROM push_deliveries WHERE account_id = $1
                   AND attempts = 1 AND next_attempt_ms >= entry_at_ms + 20000";
    assert_eq!(sqlx_scalar(&replay, retries).await, 1);
    assert!(take_handles(&replay).await.is_empty());
    assert_eq!(
        requested(&list(&replay, "wallet").await),
        [pubky_id(&bob())]
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_account_in_flight_limit() {
    let Some(replay) = setup(true, 50).await else {
        return;
    };
    register(&replay, "wallet", &["1", "2", "3", "4", "5", "6", "7", "8"]).await;
    assert!(pending(&ask(&replay).await));
    replay.clock.advance_ms(60_000);
    assert!(pending(&ask_fresh(&replay, 33).await));
    assert_eq!(
        sqlx_scalar(
            &replay,
            "SELECT count(*) FROM push_deliveries WHERE account_id = $1"
        )
        .await,
        16
    );
    assert_eq!(take_handles(&replay).await.len(), 8);
    assert_eq!(take_handles(&replay).await.len(), 8);
    replay.db.drop_database().await.expect("drop");
}
