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

async fn try_register_handles(
    replay: &Replay,
    handles: &[&str],
    request: impl Fn(&str, Vec<u8>) -> DispatchRequest,
) -> DispatchResponse {
    let path = format!("/v1/{}/push", alice_id());
    let send = async |args: Value| {
        let request = request(&path, serde_json::to_vec(&args).expect("registration"));
        replay.service.handle(request).await
    };
    let url = "https://push.example/hook";
    let start = send(json!({"relay_url": url, "handles": []})).await;
    assert_eq!(start.status, 200, "{:?}", body(&start));
    let push_key = body(&start)["push_key"].clone();
    send(json!({"relay_url": url, "handles": handles, "push_key": push_key})).await
}

async fn register_handles(
    replay: &Replay,
    handles: &[&str],
    request: impl Fn(&str, Vec<u8>) -> DispatchRequest,
) {
    let answer = try_register_handles(replay, handles, request).await;
    let parsed = body(&answer);
    assert_eq!(answer.status, 200, "{parsed:?}");
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

async fn ask_fresh(replay: &Replay, n: u8) -> DispatchResponse {
    let sender = fresh(n);
    assert_eq!(
        sender.deliver(replay, &sender.doc(1, |_| {})).await.status,
        200
    );
    sender.ask(replay).await
}

fn notifying_envelope_to_wallet() -> Vec<u8> {
    let keys = vectors("keys.json");
    let public: [u8; 32] = pubky_dispatch_core::enc::unb64(
        app(&keys, "wallet")["receive_key"]["public"]
            .as_str()
            .expect("public"),
    )
    .expect("b64")
    .try_into()
    .expect("32");
    pubky_dispatch_core::envelope::seal(
        &hex32(&alice(&keys)["public_hex"]),
        &[pubky_dispatch_core::envelope::Recipient::new(public)],
        &[1; 100],
        true,
    )
    .expect("seal")
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
            reason: PeerReason::Kept,
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
    // its mark's time floor, a minute past the account's first request (Dispatch wire 7.3,
    // "Time base"): restarted just before the floor, the account's time jumps to it, still
    // inside the push's minute.
    let floor_ms = match replay.marks.read(&alice_id()).await.expect("mark") {
        pubky_dispatch::marks::MarkRead::Mark(mark) => mark.time_floor_ms,
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

#[tokio::test]
async fn test_connect_push_notifying_inbox_entry_within_cooldown() {
    // A connect wake-up's 60-second cooldown applies only to connect requests; a normal
    // notifying inbox entry within that window still queues its webhook (Dispatch wire 7.4.7, 8.2).
    let Some(replay) = setup(true, 50).await else {
        return;
    };
    register(&replay, "wallet", &["phone"]).await;
    wallet_op(
        &replay,
        OpKind::AllowPut {
            pubky: bob(),
            reason: PeerReason::Kept,
        },
        72,
    )
    .await;
    assert!(pending(&ask_fresh(&replay, 33).await));
    assert_eq!(take_handles(&replay).await, ["phone"]);
    replay.clock.advance_ms(10_000);
    assert!(pending(&ask_fresh(&replay, 34).await));
    assert!(take_handles(&replay).await.is_empty());
    let version = sqlx_scalar(&replay, "SELECT apps_version FROM accounts WHERE id = $1").await;
    let path = format!("/v1/{}/inbox?apps_version={version}", alice_id());
    let append = replay
        .service
        .handle(other_request(
            "shop",
            ORIGIN,
            "POST",
            &path,
            notifying_envelope_to_wallet(),
            None,
            ms(&at()),
        ))
        .await;
    assert_eq!(append.status, 200, "{:?}", body(&append));
    assert_eq!(take_handles(&replay).await, ["phone"]);
    assert!(pending(&ask_fresh(&replay, 35).await));
    assert!(take_handles(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_push_over_cap_stored_registration_keeps_cooldown() {
    // Ordinary PUT /push caps same-host handles at 8 across an account (Dispatch wire 8.1).
    // With an exceptional over-cap stored registration, an app omitted by the per-host
    // delivery cap has no webhook queued and does not consume its 60-second connect cooldown
    // (Dispatch wire 7.4.7, 8.2).
    let Some(replay) = setup(true, 50).await else {
        return;
    };
    let reader = add_list_reader(&replay).await;
    let wallet_id = app_id_of("wallet");
    let reader_id = reader.cert.app_id();
    assert_ne!(wallet_id, reader_id);
    let fill = ["1", "2", "3", "4", "5", "6", "7", "8"];
    let keys = vectors("keys.json");
    let wallet_put =
        |path: &str, args: Vec<u8>| app_request(app(&keys, "wallet"), "PUT", path, args, ms(&at()));
    let reader_put = |path: &str, args: Vec<u8>| reader.request("PUT", path, args);
    let (omitted, refused) = if wallet_id < reader_id {
        register_handles(&replay, &fill, wallet_put).await;
        let refused = try_register_handles(&replay, &["omitted"], reader_put).await;
        (reader_id, refused)
    } else {
        register_handles(&replay, &fill, reader_put).await;
        let refused = try_register_handles(&replay, &["omitted"], wallet_put).await;
        (wallet_id, refused)
    };
    assert_eq!(code(&refused), (400, json!("bad_request")));
    assert_eq!(
        body(&refused)["message"],
        "8.1: more than 8 handles at one relay host across the account's apps"
    );
    // Establish the exceptional over-cap stored registration through the store boundary.
    let mut txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let before = txn
        .push_registration(&omitted)
        .await
        .expect("registration")
        .expect("stored");
    assert!(before.handles.is_empty());
    txn.set_push_handles(&omitted, &["omitted".to_string()], ms(&at()))
        .await
        .expect("set push handles");
    let after = txn
        .push_registration(&omitted)
        .await
        .expect("registration")
        .expect("stored");
    assert_eq!(after.handles, ["omitted"]);
    txn.commit().await.expect("commit");
    assert!(pending(&ask(&replay).await));
    assert_eq!(take_handles(&replay).await, fill);
    assert!(take_handles(&replay).await.is_empty());
    replay.clock.advance_ms(10_000);
    assert!(pending(&ask_fresh(&replay, 33).await));
    assert_eq!(take_handles(&replay).await, ["omitted"]);
    assert!(take_handles(&replay).await.is_empty());
    assert!(pending(&ask_fresh(&replay, 34).await));
    assert!(take_handles(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}
