//! `GET /v1/{id}/feed` (Switch wire 7.4.4, 7.5) on `chain.json`'s account: the page
//! `http.json` shows, who may read what, paging, the refusals and the long-poll.
//!
//! The vectors fix the service key and the times; set `PUBKY_SWITCH_TEST_DATABASE_URL` to run
//! them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::time::Duration;

use pubky_switch::{
    changes::ChangeListener,
    http::Handler,
    http::SwitchResponse,
    limits::Limits,
    marks::{AccountMark, MarkRead},
};
use pubky_switch_core::{
    chain::ChainTip,
    claims::{ClaimFields, ClaimType},
    enc::pubky_key,
    http::header,
    ops::{Condition, OpKind, OpsRequest, Position, SignedOp, sign_batch},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

/// The service time of `chain.json`'s revoke at seq 9, which the reads below are sent at.
fn revoke_time() -> String {
    item_time(chain_item(&vectors("chain.json"), 9))
}

/// `app`'s feed read with `query`, at `at`.
async fn read(replay: &Replay, app_name: &str, query: &str, at: &str) -> SwitchResponse {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/feed{query}", alice_id());
    let request = if app_name == "signer" {
        signer_request("GET", &path, Vec::new(), ms(at))
    } else {
        app_request(app(&keys, app_name), "GET", &path, Vec::new(), ms(at))
    };
    replay.service.handle(request).await
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn seqs(page: &Value) -> Vec<u64> {
    page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["seq"].as_u64().expect("seq"))
        .collect()
}

#[tokio::test]
async fn test_feed_vectors_page_after_the_registration() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let http = vectors("http.json");
    let expected = named(
        &http["responses"],
        "own app: feed page with an entry and chain items",
    );
    let page_text = expected["body"].as_str().expect("body");
    let expected_page: Value = serde_json::from_str(page_text).expect("page");
    let answer = read(&replay, "wallet", "?after=1:4", &revoke_time()).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let page = body(&answer);
    let item_at = |page: &Value, seq: u64| -> Value {
        page["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["seq"] == seq)
            .cloned()
            .unwrap_or_else(|| panic!("no item {seq}"))
    };
    // The entry at seq 5 comes with the inbox; the rest as http.json has it. The record's
    // create at seq 6, superseded by the update at seq 8, shows as its stub (Switch wire 7.5,
    // 9.1), in the vector as here.
    assert_eq!(seqs(&page), vec![6, 7, 8, 9]);
    assert_eq!(item_at(&page, 6)["type"], "stub");
    for seq in [6, 7, 8, 9] {
        assert_eq!(
            item_at(&page, seq),
            item_at(&expected_page, seq),
            "seq {seq}"
        );
    }
    for member in ["next", "scanned_through", "more", "cursor", "head"] {
        assert_eq!(page[member], expected_page[member], "{member}");
    }
    assert_eq!(
        header_text(&answer, header::HEAD),
        expected["headers"]["switch-head"].as_str(),
        "Switch-Head"
    );
    // As bytes too, in the member order of the vector: each of seqs 6 to 9, and the members
    // after the items, appear in the vector's body exactly as this page writes them. The
    // whole body differs only by the entry at seq 5.
    let text = String::from_utf8(answer.body.clone()).expect("utf-8");
    for seq in [6, 7, 8, 9] {
        let at = text
            .find(&format!(",\"seq\":{seq},"))
            .unwrap_or_else(|| panic!("seq {seq}"));
        let start = text[..at].rfind("{\"type\":").expect("item start");
        let end = text[start..]
            .find(",{\"type\":")
            .or_else(|| text[start..].find("],\"next\""))
            .expect("end")
            + start;
        assert!(page_text.contains(&text[start..end]), "seq {seq} as bytes");
    }
    let tail = &text[text.find("],\"next\"").expect("tail")..];
    assert!(
        page_text.ends_with(tail),
        "the members after the items as bytes"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_pages_from_the_start_by_limit() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // From the start: both identity.json deliveries, then the registration batch whole.
    let page = body(&read(&replay, "wallet", "?limit=3", &at).await);
    assert_eq!(seqs(&page), vec![1, 2, 3, 4]);
    assert_eq!(
        (page["next"].clone(), page["more"].clone()),
        (json!("1:4"), json!(true))
    );
    let page = body(&read(&replay, "wallet", "?after=1:4&limit=1", &at).await);
    assert_eq!(seqs(&page), vec![6]);
    assert_eq!(page["scanned_through"], 6);
    let page = body(&read(&replay, "wallet", "?after=1:6&limit=1", &at).await);
    assert_eq!(seqs(&page), vec![7, 8]);
    let page = body(&read(&replay, "wallet", "?after=1:8", &at).await);
    assert_eq!(seqs(&page), vec![9]);
    assert_eq!(
        (page["next"].clone(), page["more"].clone()),
        (json!("1:9"), json!(false))
    );
    // At the head: an empty page that keeps the position.
    let page = body(&read(&replay, "wallet", "?after=1:9", &at).await);
    assert_eq!((seqs(&page), page["next"].clone()), (vec![], json!("1:9")));
    // A position of another sequence reads from the start of this one.
    let page = body(&read(&replay, "wallet", "?after=2:7&limit=1", &at).await);
    assert_eq!(seqs(&page), vec![1]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_page_with_no_items_carries_its_head_and_cursor_alone() {
    // `limit=0` shows no item and covers no position: `next` is where it starts, `more`
    // whether items follow, with the head and cursor of any page (Switch wire 7.4.4).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let full = body(&read(&replay, "wallet", "?after=1:4", &at).await);
    let answer = read(&replay, "wallet", "?after=1:4&limit=0", &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    let page = body(&answer);
    assert_eq!(seqs(&page), Vec::<u64>::new());
    assert_eq!(
        (
            page["next"].clone(),
            page["scanned_through"].clone(),
            page["more"].clone()
        ),
        (json!("1:4"), json!(4), json!(true))
    );
    assert_eq!(page["head"], full["head"]);
    assert_eq!(page["cursor"], full["cursor"]);
    // At the head nothing follows; from the start, everything does.
    let page = body(&read(&replay, "wallet", "?after=1:9&limit=0", &at).await);
    assert_eq!(
        (seqs(&page), page["next"].clone(), page["more"].clone()),
        (vec![], json!("1:9"), json!(false))
    );
    let page = body(&read(&replay, "wallet", "?limit=0", &at).await);
    assert_eq!(
        (seqs(&page), page["next"].clone(), page["more"].clone()),
        (vec![], json!("1:0"), json!(true))
    );
    // The reader's checks run as for any page: a revoked app is refused.
    let answer = read(&replay, "phone", "?limit=0", &at).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("not_current"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_page_with_no_items_beyond_the_head_and_of_another_sequence() {
    // A page with no items starts where a page with items would: beyond the head it keeps
    // the position with nothing to follow, and a position of another sequence starts at the
    // start of this one (Switch wire 7.4.4).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    for (after, next, scanned, more) in [("1:99", "1:99", 99, false), ("2:7", "1:0", 0, true)] {
        let page = body(&read(&replay, "wallet", &format!("?after={after}&limit=0"), &at).await);
        assert_eq!(
            (
                seqs(&page),
                page["next"].clone(),
                page["scanned_through"].clone(),
                page["more"].clone()
            ),
            (vec![], json!(next), json!(scanned), json!(more)),
            "{after}"
        );
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_page_with_no_items_fails_stop_behind_the_mark() {
    // A state behind the account's mark answers a page with no items as it answers any
    // call: the notice, `503 recovery_required` with the reason `behind`, with no head
    // (Switch wire 7.3, Tables 1 and 2).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "UPDATE accounts SET last_seq = 4, chain_seq = 4, chain_hash = \
         (SELECT chain_hash FROM chain_items WHERE account_id = $1 AND seq = 4) WHERE id = $1",
    )
    .bind(alice_id())
    .execute(&mut conn)
    .await
    .expect("restore");
    conn.close().await.expect("close");
    let answer = read(&replay, "wallet", "?limit=0", &revoke_time()).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (503, json!("recovery_required"))
    );
    assert_eq!(body(&answer)["current"]["reason"], json!("behind"));
    assert!(
        header_text(&answer, header::HEAD).is_none(),
        "no head behind the mark"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_page_ends_at_the_byte_budget() {
    let limits = Limits {
        max_page_bytes: 1,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // Its first item or batch is shown whatever its size, and nothing more.
    let page = body(&read(&replay, "wallet", "", &at).await);
    assert_eq!((seqs(&page), page["more"].clone()), (vec![1], json!(true)));
    let page = body(&read(&replay, "wallet", "?after=1:2", &at).await);
    assert_eq!(
        (seqs(&page), page["next"].clone()),
        (vec![3, 4], json!("1:4"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_refusals() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // Only own apps read the feed: the signer gets 403 permission_missing, with the head.
    let answer = read(&replay, "signer", "", &at).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("permission_missing"))
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    assert_eq!(
        body(&answer).get("cursor"),
        None,
        "no cursor for the signer"
    );
    // A revoked app is no longer current.
    let answer = read(&replay, "phone", "", &at).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("not_current"))
    );
    assert_eq!(
        body(&answer).get("cursor"),
        None,
        "no cursor for a revoked app"
    );
    for query in [
        "?after=9",
        "?after=1:x",
        "?limit=0&wait=1",
        "?limit=501",
        "?wait=26",
    ] {
        let answer = read(&replay, "wallet", query, &at).await;
        assert_eq!(answer.status, 400, "{query}");
    }
    replay.db.drop_database().await.expect("drop");
}

/// Move `app_name`'s cursor to `1:{seq}` with a batch of no operations, at `at`: the status.
async fn move_cursor(replay: &Replay, app_name: &str, seq: u64, at: &str) -> u16 {
    let keys = vectors("keys.json");
    let position = Position { generation: 1, seq };
    let body = OpsRequest::new(&[], Some(position)).to_json();
    let path = format!("/v1/{}/ops", alice_id());
    let request = app_request(app(&keys, app_name), "POST", &path, body, ms(at));
    replay.service.handle(request).await.status
}

/// The `cursor` a page of `app_name`'s feed after `after` reports.
async fn held_cursor(replay: &Replay, app_name: &str, after: &str, at: &str) -> Value {
    let answer = read(replay, app_name, &format!("?after={after}"), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    body(&answer)["cursor"].clone()
}

#[tokio::test]
async fn test_feed_cursor_is_the_one_held_for_the_caller() {
    // Each page reports the `seq` of the cursor the service holds for its caller, 0 before
    // the app's first move, and only the caller's own (Switch spec 8.3, wire 7.4.4).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let record: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "executor app record",
        )["signed"]
            .clone(),
    )
    .expect("record");
    let registered = post(
        &replay,
        "executor",
        &app_batch(
            "executor",
            80,
            vec![(Vec::new(), OpKind::AppPut { record })],
        ),
        ms(&at),
    )
    .await;
    assert_eq!(
        registered.status,
        200,
        "{}",
        String::from_utf8_lossy(&registered.body)
    );
    assert_eq!(held_cursor(&replay, "wallet", "1:10", &at).await, json!(0));
    assert_eq!(
        held_cursor(&replay, "executor", "1:10", &at).await,
        json!(0)
    );
    assert_eq!(move_cursor(&replay, "wallet", 7, &at).await, 200);
    assert_eq!(held_cursor(&replay, "wallet", "1:10", &at).await, json!(7));
    // Another app's page shows its own cursor, never the wallet's.
    assert_eq!(
        held_cursor(&replay, "executor", "1:10", &at).await,
        json!(0)
    );
    assert_eq!(move_cursor(&replay, "executor", 5, &at).await, 200);
    assert_eq!(
        held_cursor(&replay, "executor", "1:10", &at).await,
        json!(5)
    );
    assert_eq!(held_cursor(&replay, "wallet", "1:10", &at).await, json!(7));
    // A move behind it leaves it where it is, and the page says so.
    assert_eq!(move_cursor(&replay, "wallet", 6, &at).await, 200);
    assert_eq!(held_cursor(&replay, "wallet", "1:10", &at).await, json!(7));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_cursor_is_the_apps_whatever_the_reads_position() {
    // The cursor is the app's, shared by its devices: a device reading from behind it, as one
    // restored from a backup at 1:4 would, sees the cursor another device moved, whatever
    // position it reads from (Switch spec 8.3).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    assert_eq!(move_cursor(&replay, "wallet", 8, &at).await, 200);
    let page = body(&read(&replay, "wallet", "?after=1:4", &at).await);
    assert_eq!(
        (seqs(&page), page["cursor"].clone()),
        (vec![6, 7, 8, 9], json!(8))
    );
    let page = body(&read(&replay, "wallet", "", &at).await);
    assert_eq!(page["cursor"], json!(8));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_held_read_reports_the_cursor_as_it_answers() {
    // A held read reports the cursor of the snapshot it answers from: a move made while it
    // waits shows (Switch wire 7.4.4).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let (answer, moved) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        move_cursor(&replay, "wallet", 9, &at).await
    });
    assert_eq!(moved, 200);
    let page = body(&answer);
    assert_eq!((seqs(&page), page["cursor"].clone()), (vec![], json!(9)));
    replay.db.drop_database().await.expect("drop");
}

/// The wallet's delete of the record at seq 10 (`chain.json`'s `record_delete`).
async fn delete_record(replay: &Replay) {
    let chain = vectors("chain.json");
    let delete = &chain["record_delete"];
    let at = item_time(&delete["item"]);
    let signed: SignedDoc = serde_json::from_value(delete["item"]["item"].clone()).expect("op");
    let body = OpsRequest::new(&[SignedOp::peek(&signed).expect("op")], None).to_json();
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        body,
        ms(&at),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

#[tokio::test]
async fn test_feed_long_poll_wakes_at_a_change() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let listener = ChangeListener::connect(replay.db.store())
        .await
        .expect("listen");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(listener.run(replay.service.changes(), async {
        let _ = stopped.await;
    }));
    let chain = vectors("chain.json");
    let delete_at = item_time(&chain["record_delete"]["item"]);
    set_time(&replay.clock, &delete_at);
    let started = std::time::Instant::now();
    let (answer, ()) = tokio::join!(
        read(&replay, "wallet", "?after=1:9&wait=25", &delete_at),
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            delete_record(&replay).await;
        }
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "woken by the change"
    );
    let page = body(&answer);
    assert_eq!(seqs(&page), vec![10]);
    assert_eq!(page["items"][0]["type"], "chain");
    assert_eq!(
        page["items"][0]["proof"],
        chain["record_delete"]["transition_proof"]["signed"]
    );
    assert_eq!(
        page["head"]["chain_hash"],
        chain["record_delete"]["item"]["chain_hash"]
    );
    // The delete superseded the update at seq 8: a stub now.
    let page = body(&read(&replay, "wallet", "?after=1:7", &delete_at).await);
    assert_eq!(page["items"][0]["seq"], 8);
    assert_eq!(page["items"][0]["type"], "stub");
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_long_poll_answers_when_the_wait_ends() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let started = std::time::Instant::now();
    let answer = read(&replay, "wallet", "?after=1:9&wait=1", &revoke_time()).await;
    assert!(started.elapsed() >= Duration::from_secs(1), "waited");
    let page = body(&answer);
    assert_eq!((seqs(&page), page["more"].clone()), (vec![], json!(false)));
    // A page with something to read is answered at once, whatever the wait.
    let started = std::time::Instant::now();
    let page = body(&read(&replay, "wallet", "?after=1:8&wait=25", &revoke_time()).await);
    assert!(started.elapsed() < Duration::from_secs(5), "at once");
    assert_eq!(seqs(&page), vec![9]);
    replay.db.drop_database().await.expect("drop");
}

fn app_batch(name: &str, id: u8, kinds: Vec<(Vec<Condition>, OpKind)>) -> Vec<SignedOp> {
    let keys = vectors("keys.json");
    let entry = app(&keys, name);
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&entry["signing_secret_hex"]));
    let app_id: [u8; 16] = hex::decode(entry["app_id_bytes_hex"].as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("16");
    sign_batch(
        &key,
        &pubky_key(&alice_id()).expect("key"),
        Some(app_id),
        1,
        [id; 16],
        kinds,
    )
    .expect("batch")
}

async fn post(replay: &Replay, name: &str, ops: &[SignedOp], at_ms: u64) -> SwitchResponse {
    let keys = vectors("keys.json");
    let body = OpsRequest::new(ops, None).to_json();
    let path = format!("/v1/{}/ops", alice_id());
    replay
        .service
        .handle(app_request(app(&keys, name), "POST", &path, body, at_ms))
        .await
}

fn attempt(key: u8) -> (Vec<Condition>, OpKind) {
    (
        Vec::new(),
        OpKind::Claim(ClaimFields {
            claim_key: vec![key; 32],
            kind: ClaimType::Attempt,
            expected_step: 0,
            attempt_id: vec![8; 16],
            orphan_after: Some(60),
            deadline: None,
            basis: None,
            evidence_ref: None,
        }),
    )
}

#[tokio::test]
async fn test_feed_long_poll_of_an_app_revoked_meanwhile_is_refused() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let record: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "executor app record",
        )["signed"]
            .clone(),
    )
    .expect("record");
    let at = "2026-01-01T00:00:10.000Z";
    set_time(&replay.clock, at);
    // The executor registers: seq 10.
    let answer = post(
        &replay,
        "executor",
        &app_batch(
            "executor",
            40,
            vec![(Vec::new(), OpKind::AppPut { record })],
        ),
        ms(at),
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let (stop, task) = listen(&replay).await;
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    // The wallet waits after seq 11, its revocation's, which wakes the poll; the executor's
    // attempt after it (seq 12) shows to no read of the wallet's.
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:11&wait=10", at), async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let path = format!("/v1/{}/apps/{wallet}/revoke", alice_id());
        let revoked = replay
            .service
            .handle(signer_request("POST", &path, Vec::new(), ms(at)))
            .await;
        assert_eq!(revoked.status, 200, "revoked");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let written = post(
            &replay,
            "executor",
            &app_batch("executor", 41, vec![attempt(9)]),
            ms(at),
        )
        .await;
        assert_eq!(
            written.status,
            200,
            "{}",
            String::from_utf8_lossy(&written.body)
        );
    });
    // Refused as a fresh request is, with the head.
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("not_current"))
    );
    // Its head is the one the page was read at, the revocation's, past the one its request
    // committed (Switch wire 7.1), and the account's mark covers it (7.3 step 10).
    let mark = mark_of(&replay).await;
    assert_eq!(head_seq(&answer), Some(11));
    assert!(mark.seq >= 11);
    let fresh = read(&replay, "wallet", "?after=1:11", at).await;
    assert_eq!(fresh.status, 403);
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_long_poll_answers_at_the_time_it_reads() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let (stop, task) = listen(&replay).await;
    let early = "2026-01-01T00:00:04.000Z";
    set_time(&replay.clock, early);
    let chain = vectors("chain.json");
    let late = item_time(&chain["record_delete"]["item"]);
    let mut write_time = None;
    let (answer, ()) = tokio::join!(
        read(&replay, "wallet", "?after=1:9&wait=10", early),
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            set_time(&replay.clock, &late);
            delete_record(&replay).await;
            write_time = Some(rfc3339_of(&late));
        }
    );
    assert_eq!(seqs(&body(&answer)), vec![10]);
    // Signed at the time the page was read, never behind what it shows or an answer sent
    // before it (Switch spec 10.1).
    assert_eq!(
        header_text(&answer, header::SERVER_TIME).map(str::to_string),
        write_time
    );
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

fn rfc3339_of(text: &str) -> String {
    pubky_switch_core::time::rfc3339(ms(text))
}

#[tokio::test]
async fn test_feed_refuses_an_app_of_another_identity() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let path = format!("/v1/{}/feed", alice_id());
    let at = ms(&revoke_time());
    // Authenticated first, by its certificate (Switch wire 7.2), then refused: the feed is
    // for own apps (7.4.4).
    let request = other_request("shop", ORIGIN, "GET", &path, Vec::new(), None, at);
    let answer = replay.service.handle(request).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("permission_missing"))
    );
    assert!(header_text(&answer, header::HEAD).is_none());
    let mut request = other_request("shop", ORIGIN, "GET", &path, Vec::new(), None, at);
    request.headers.remove("switch-cert");
    assert_eq!(replay.service.handle(request).await.status, 400);
    // At POST /ops, likewise: its certificate, then 403 not_admitted.
    let ops = format!("/v1/{}/ops", alice_id());
    let request = other_request("shop", ORIGIN, "POST", &ops, b"{}".to_vec(), None, at);
    assert_eq!(
        body(&replay.service.handle(request).await)["code"],
        json!("not_admitted")
    );
    replay.db.drop_database().await.expect("drop");
}

/// Wait until a long-poll waits on the account, its page read after the lock.
async fn until_held(replay: &Replay) {
    let changes = replay.service.changes();
    tokio::time::timeout(Duration::from_secs(10), async {
        while changes.waiting() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the read is held");
}

/// alice's mark.
async fn mark_of(replay: &Replay) -> AccountMark {
    match replay.marks.read(&alice_id()).await.expect("mark store") {
        MarkRead::Mark(mark) => mark,
        other => panic!("no mark: {other:?}"),
    }
}

async fn sql(replay: &Replay, statement: &str) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(statement)
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("statement");
}

#[tokio::test]
async fn test_feed_moves_the_mark_to_the_head_it_shows() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    assert_eq!(mark_of(&replay).await.seq, 9);
    // A head committed meanwhile by a request that hasn't moved the mark yet: the page
    // shows it, so the mark moves to it before the answer goes out (Switch wire 7.3 step
    // 10).
    let at = revoke_time();
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        sql(
                &replay,
                "UPDATE accounts SET last_seq = 10, chain_seq = 10, chain_hash = decode(repeat('ab', 32), 'hex') \
                 WHERE id = $1",
            )
            .await;
    });
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(body(&answer)["head"]["seq"], 10);
    assert_eq!(head_seq(&answer), Some(10));
    assert_eq!(
        mark_of(&replay).await.head(),
        ChainTip {
            generation: 1,
            seq: 10,
            chain_hash: [0xab; 32],
        }
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_long_poll_behind_the_mark_answers_the_notice() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    // A head beyond the state the page reads is signed meanwhile: the page read at the end
    // of the wait is judged again, from a mark read before its snapshot, and answers the
    // notice, signed with the key in the mark, without a head (Switch wire 7.3, Tables 1
    // and 2).
    let at = revoke_time();
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/feed?after=1:9&wait=1", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let sent = Sent::of(&request);
    let (answer, ()) = tokio::join!(replay.service.handle(request), async {
        until_held(&replay).await;
        let ahead = ChainTip {
            generation: 1,
            seq: 50,
            chain_hash: [0xcd; 32],
        };
        replay
            .marks
            .advance(
                &alice_id(),
                ahead,
                service_public(&replay),
                mark_created_at(&replay, &alice_id()).await,
            )
            .await
            .expect("mark");
        // Time passes during the wait.
        replay.clock.set_wall_ms(ms(&at) + 30_000);
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (503, json!("recovery_required"))
    );
    assert_eq!(body(&answer)["current"]["reason"], json!("behind"));
    // Signed when it answers, at the time base then, not at the request's start (Switch
    // wire 7.1 Timestamp, 7.6).
    let time = header_text(&answer, header::SERVER_TIME).expect("server time");
    assert_eq!(
        pubky_switch_core::time::parse_rfc3339(time).expect("time"),
        replay.time.peek().base_ms
    );
    assert_eq!(replay.time.peek().base_ms, ms(&at) + 30_000);
    assert!(header_text(&answer, header::HEAD).is_none());
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    assert_eq!(replay.service.mark_refusals(), 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_long_poll_of_an_account_erased_meanwhile_is_not_hosted() {
    // The page read at the end of the wait is judged again: the account is gone, so the
    // read answers the not-hosted `404`, signed with the service key, without a head
    // (Switch wire 7.4.16 Afterwards, 7.3 step 2).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/feed?after=1:9&wait=1", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let sent = Sent::of(&request);
    let (answer, ()) = tokio::join!(replay.service.handle(request), async {
        until_held(&replay).await;
        // The signer erases the account, naming its newest identity.json (Switch wire
        // 7.4.16).
        let held: SignedDoc = serde_json::from_value(
            named(
                &vectors("documents.json")["documents"],
                "alice identity.json",
            )["signed"]
                .clone(),
        )
        .expect("version 3");
        let held = held.doc_hash().expect("hash");
        let erased = replay
            .service
            .handle(erasure_of(&replay, &alice_id(), Some(&held), ms(&at)).await)
            .await;
        assert_eq!(
            erased.status,
            200,
            "{}",
            String::from_utf8_lossy(&erased.body)
        );
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (404, json!("not_found"))
    );
    assert_eq!(body(&answer)["current"], json!({ "hosted": false }));
    assert!(header_text(&answer, header::HEAD).is_none());
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    replay.db.drop_database().await.expect("drop");
}

fn head_seq(answer: &SwitchResponse) -> Option<u64> {
    let text = header_text(answer, header::HEAD)?;
    let head = pubky_switch_core::chain::SignedHead::from_header(text).ok()?;
    head.to_value()["seq"].as_u64()
}

#[tokio::test]
async fn test_feed_expiry_is_judged_at_the_snapshots_time() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    // A second after the revocation, so the read stamps a time of its own.
    let at = pubky_switch_core::time::rfc3339(ms(&revoke_time()) + 1_000);
    set_time(&replay.clock, &at);
    let read_ms = i64::try_from(ms(&at)).expect("time");
    // A commit once the read's request has committed its stamp, while it waits, stamps a
    // time past the wallet's certificate: the page read after it refuses the wallet, by the
    // snapshot's time, not the request's.
    let expired = ms("2026-12-01T00:00:01.000Z");
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while stamped_time(&replay).await != read_ms {
            assert!(
                std::time::Instant::now() < deadline,
                "the read never committed its stamp"
            );
            tokio::task::yield_now().await;
        }
        sql(
            &replay,
            &format!(
                "UPDATE accounts SET last_seq = 10, chain_seq = 10, \
                 chain_hash = decode(repeat('ab', 32), 'hex'), stamped_time_ms = {expired} \
                 WHERE id = $1"
            ),
        )
        .await;
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("cert_expired"))
    );
    // The snapshot's head, at 10, past the request's own 9 (Switch wire 7.1), the mark moved
    // to it first (7.3 step 10).
    let mark = mark_of(&replay).await;
    assert_eq!(head_seq(&answer), Some(10));
    assert!(mark.seq >= 10);
    assert_eq!(
        header_text(&answer, header::SERVER_TIME),
        Some(pubky_switch_core::time::rfc3339(expired).as_str())
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_store_failure_carries_the_requests_head() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        // A seq given out, so the page reads the chain, which then fails.
        sql(&replay, "UPDATE accounts SET last_seq = 10 WHERE id = $1").await;
        sql(
            &replay,
            "ALTER TABLE chain_items RENAME TO chain_items_gone",
        )
        .await;
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (503, json!("unavailable"))
    );
    assert_eq!(head_seq(&answer), Some(9));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_of_an_account_moved_away_meanwhile_is_staged() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // A version naming another switch arrives during the wait: the page is refused with
    // 503 staged, as a fresh request would be (Switch wire 7.3 step 7).
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("v3");
    let mut moved: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    moved.version = 4;
    moved.inbox.url = "https://other.example".into();
    let key = pubky_switch_core::keys::IdentityKey::from_secret(hex32(
        &alice(&vectors("keys.json"))["secret_hex"],
    ));
    let moved = pubky_switch_core::records::IdentityDoc::sign(&key, moved)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: moved,
        prev: Some(v3.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{}/identity", alice_id());
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let delivered = replay
            .service
            .handle(signer_request("PUT", &path, delivery, ms(&at)))
            .await;
        assert_eq!(
            delivered.status,
            200,
            "{}",
            String::from_utf8_lossy(&delivered.body)
        );
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (503, json!("staged"))
    );
    assert!(head_seq(&answer).is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_401_from_the_page_check_counts_as_a_failed_authentication() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let wallet_bytes = hex::decode(
        app(&keys, "wallet")["app_id_bytes_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex");
    // The phone's record, as the store keeps a signed document.
    let phone_record = serde_json::to_vec(
        &named(&vectors("documents.json")["documents"], "phone app record")["signed"],
    )
    .expect("record");
    // The key the request verified with is no longer the app's by the next snapshot: the
    // record held for it carries another app's key. The page is refused 401, without a
    // head, and the 401 counts.
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query("UPDATE apps SET record = $2, receive_key = NULL WHERE app_id = $1")
            .bind(wallet_bytes.as_slice())
            .bind(phone_record.as_slice())
            .execute(&mut conn)
            .await
            .expect("update");
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (401, json!("bad_signature"))
    );
    assert!(header_text(&answer, header::HEAD).is_none());
    let claimed = (alice_id(), alice_id(), Some(wallet));
    assert_eq!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, ms(&at)),
        1
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_refusal_after_a_wait_is_never_signed_earlier_than_a_read() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let (stop, task) = listen(&replay).await;
    let at = revoke_time();
    let later = ms(&at) + 30_000;
    // The wait reads once at its own time, again after a commit stamped 30 s later, then
    // its last read fails: the refusal is signed at the later time, not the request's.
    // The wait is long enough that only the notifications end it, never its deadline: the
    // last step wakes it again, so the test takes about a second however slow the machine.
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=20", &at), async {
        // Subscribed: the wait has started, and reads after this point.
        while replay.service.changes().waiting() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        sql(
            &replay,
            &format!("UPDATE accounts SET stamped_time_ms = {later} WHERE id = $1"),
        )
        .await;
        sql(&replay, "SELECT pg_notify('pubky_switch_changes', $1)").await;
        // Time for the wait to wake and read at the later stamp before its next read fails.
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        sql(&replay, "UPDATE accounts SET last_seq = 10 WHERE id = $1").await;
        sql(
            &replay,
            "ALTER TABLE chain_items RENAME TO chain_items_gone",
        )
        .await;
        sql(&replay, "SELECT pg_notify('pubky_switch_changes', $1)").await;
    });
    assert_eq!(
        answer.status,
        503,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(
        header_text(&answer, header::SERVER_TIME),
        Some(pubky_switch_core::time::rfc3339(later).as_str())
    );
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_page_check_runs_the_apps_checks_before_the_staged_gate() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let wallet = hex::decode(
        app(&keys, "wallet")["app_id_bytes_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex");
    // During the wait the wallet is revoked and the account moves away: a new request would
    // get 403 not_current (7.3 step 5) before 503 staged (step 7), and so does the page.
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("v3");
    let mut moved: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    moved.version = 4;
    moved.inbox.url = "https://other.example".into();
    let key = pubky_switch_core::keys::IdentityKey::from_secret(hex32(
        &alice(&vectors("keys.json"))["secret_hex"],
    ));
    let moved = pubky_switch_core::records::IdentityDoc::sign(&key, moved)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: moved,
        prev: Some(v3.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{}/identity", alice_id());
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query(
            "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms) \
             VALUES ($1, $2, 'revoked', 0)",
        )
        .bind(alice_id())
        .bind(wallet.as_slice())
        .execute(&mut conn)
        .await
        .expect("revoked");
        let delivered = replay
            .service
            .handle(signer_request("PUT", &path, delivery, ms(&at)))
            .await;
        assert_eq!(
            delivered.status,
            200,
            "{}",
            String::from_utf8_lossy(&delivered.body)
        );
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("not_current"))
    );
    replay.db.drop_database().await.expect("drop");
}

/// The service time alice's account last stamped.
async fn stamped_time(replay: &Replay) -> i64 {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query_scalar("SELECT stamped_time_ms FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("stamp")
}

/// Make alice's mark unable to move, or able again: the mark store's directory of marks
/// read-only, or writable.
fn marks_writable(replay: &Replay, writable: bool) {
    use std::os::unix::fs::PermissionsExt;
    let dir = replay.key_dir().join("accounts").join("marks");
    let mode = if writable { 0o700 } else { 0o500 };
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

#[tokio::test]
async fn test_feed_refusal_whose_mark_cant_move_carries_the_requests_head() {
    // As in the expiry test, a held read is refused from a later snapshot; but the mark
    // can't move to that snapshot's head, so the refusal carries the head the request
    // committed, which the mark covers, never the snapshot's (Switch wire 7.3 step 10).
    // The mark sticks only once the read's own commit is in: stuck before it, the read
    // would answer the temporary `503`, which is right for a mark store that fails there,
    // and not what this test is about.
    let Some(replay) = replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = pubky_switch_core::time::rfc3339(ms(&revoke_time()) + 1_000);
    set_time(&replay.clock, &at);
    let read_ms = i64::try_from(ms(&at)).expect("time");
    let expired = ms("2026-12-01T00:00:01.000Z");
    // The later snapshot wakes the held read, as a commit does: the read never ends by
    // its own clock.
    let (stop, task) = listen(&replay).await;
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=25", &at), async {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while stamped_time(&replay).await != read_ms {
            assert!(
                std::time::Instant::now() < deadline,
                "the read never committed its stamp"
            );
            tokio::task::yield_now().await;
        }
        marks_writable(&replay, false);
        sql(
            &replay,
            &format!(
                "UPDATE accounts SET last_seq = 10, chain_seq = 10, \
                 chain_hash = decode(repeat('ab', 32), 'hex'), stamped_time_ms = {expired} \
                 WHERE id = $1"
            ),
        )
        .await;
        sql(
            &replay,
            &format!("SELECT pg_notify('{}', $1)", pubky_switch::changes::CHANNEL),
        )
        .await;
    });
    marks_writable(&replay, true);
    let _ = stop.send(());
    task.await.expect("listener");
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("cert_expired"))
    );
    assert_eq!(head_seq(&answer), Some(9));
    let mark = mark_of(&replay).await;
    assert_eq!(mark.seq, 9, "the mark didn't move: {mark:?}");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_held_read_ends_when_its_connection_closes() {
    // A client that drops a held read closes its connection: the service drops the read
    // with it, and nothing waits on the account any more.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let service = replay.restarted_with(Limits::default());
    let changes = service.changes();
    let router = pubky_switch::http::router(std::sync::Arc::new(service), Default::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(pubky_switch::http::serve(listener, router, async {
        let _ = stopped.await;
    }));
    let path = format!("/v1/{}/feed?after=1:9&wait=20", alice_id());
    let request = app_request(
        app(&vectors("keys.json"), "wallet"),
        "GET",
        &path,
        Vec::new(),
        ms(&revoke_time()),
    );
    let mut raw = format!("GET {path} HTTP/1.1\r\nhost: switch.example\r\n");
    for (name, value) in &request.headers {
        raw.push_str(&format!(
            "{name}: {}\r\n",
            value.to_str().expect("a text header")
        ));
    }
    raw.push_str("\r\n");
    let mut connection = std::net::TcpStream::connect(address).expect("connect");
    std::io::Write::write_all(&mut connection, raw.as_bytes()).expect("send");
    tokio::time::timeout(Duration::from_secs(10), async {
        while changes.waiting() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the read is held");
    drop(connection);
    tokio::time::timeout(Duration::from_secs(5), async {
        while changes.waiting() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the held read ends with its connection, well before its wait");
    let _ = stop.send(());
    server.await.expect("server").expect("served");
    replay.db.drop_database().await.expect("drop");
}

/// The normal lifecycle change that must not overtake a new signature for a feed snapshot.
#[derive(Clone, Copy, Debug)]
enum FeedChange {
    Recover,
    Erase,
    EnrollAgain,
    Advance,
}

fn held_identity() -> SignedDoc {
    serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("identity")
}

async fn change_feed_account(replay: &Replay, change: FeedChange, at: &str) {
    let original = mark_of(replay).await;
    let held = held_identity();
    let (path, data) = match change {
        FeedChange::Advance => {
            let keys = vectors("keys.json");
            let executor = app(&keys, "executor")["app_id"].as_str().expect("app");
            (
                format!("/v1/{}/apps/{executor}/revoke", alice_id()),
                Vec::new(),
            )
        }
        FeedChange::Recover => {
            let mut fields: pubky_switch_core::records::IdentityBody =
                serde_json::from_slice(&held.body_bytes().expect("body")).expect("body");
            fields.version += 1;
            fields.generation = 2;
            fields.recovery_from = Some(1);
            fields.apps.clear();
            let key = pubky_switch_core::keys::IdentityKey::from_secret(hex32(
                &alice(&vectors("keys.json"))["secret_hex"],
            ));
            let recovery = pubky_switch_core::records::IdentityDoc::sign(&key, fields)
                .expect("sign")
                .signed()
                .clone();
            (
                format!("/v1/{}/identity", alice_id()),
                pubky_switch_core::http::IdentityDelivery {
                    identity: recovery,
                    prev: Some(held.doc_hash().expect("hash")),
                }
                .to_json(),
            )
        }
        FeedChange::Erase | FeedChange::EnrollAgain => {
            let mark = mark_of(replay).await;
            (
                format!("/v1/{}/erase", alice_id()),
                pubky_switch_core::http::erase_body(
                    Some(mark.created_at_ms),
                    Some(&held.doc_hash().expect("hash")),
                ),
            )
        }
    };
    let answer = replay
        .service
        .handle(signer_request(
            if matches!(change, FeedChange::Recover) {
                "PUT"
            } else {
                "POST"
            },
            &path,
            data,
            ms(at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{change:?}: {}",
        String::from_utf8_lossy(&answer.body)
    );
    match change {
        FeedChange::Advance => {
            let later = mark_of(replay).await;
            assert_eq!(later.generation, original.generation);
            assert!(later.seq > original.seq);
        }
        FeedChange::Recover => assert_eq!(mark_of(replay).await.generation, 2),
        FeedChange::Erase | FeedChange::EnrollAgain => assert_eq!(
            replay.marks.read(&alice_id()).await.expect("mark"),
            MarkRead::Missing
        ),
    }
    if matches!(change, FeedChange::EnrollAgain) {
        let now = ms(at) + 1;
        replay.clock.set_wall_ms(now);
        let enrollment = fresh_alice_enrollment(replay, now).await;
        let enrolled = replay.service.handle(enrollment).await;
        assert_eq!(
            enrolled.status,
            200,
            "{}",
            String::from_utf8_lossy(&enrolled.body)
        );
        let created = ms(body(&enrolled)["created"].as_str().expect("creation"));
        let first: SignedDoc = serde_json::from_value(
            named(
                &vectors("documents.json")["documents"],
                "alice identity.json, first delivery (version 1)",
            )["signed"]
                .clone(),
        )
        .expect("first identity");
        let mut prev = None;
        for identity in [first, held_identity()] {
            let hash = identity.doc_hash().expect("hash");
            let delivery = pubky_switch_core::http::IdentityDelivery { identity, prev };
            let delivered = replay
                .service
                .handle(signer_request_at_creation(
                    "PUT",
                    &format!("/v1/{}/identity", alice_id()),
                    delivery.to_json(),
                    now,
                    Some(created),
                ))
                .await;
            assert_eq!(
                delivered.status,
                200,
                "{}",
                String::from_utf8_lossy(&delivered.body)
            );
            prev = Some(hash);
        }
        let later = mark_of(replay).await;
        assert!(later.created_at_ms > original.created_at_ms);
        assert_eq!(later.generation, original.generation);
    }
}

async fn subscribed(replay: &Replay) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while replay.service.changes().waiting() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("feed subscribed after its initial commit and mark");
}

async fn change_before_feed_sign(change: FeedChange, refusal: bool, after_mark: bool) {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        subscribed(&replay).await;
        if refusal {
            // The next snapshot refuses a reader revoked through the normal endpoint.
            let wallet = app(&vectors("keys.json"), "wallet")["app_id"]
                .as_str()
                .expect("app")
                .to_string();
            let path = format!("/v1/{}/apps/{wallet}/revoke", alice_id());
            let revoked = replay
                .service
                .handle(signer_request("POST", &path, Vec::new(), ms(&at)))
                .await;
            assert_eq!(
                revoked.status,
                200,
                "{}",
                String::from_utf8_lossy(&revoked.body)
            );
        }
        let pause = if after_mark {
            replay.service.pause_next_feed_sign()
        } else {
            replay.service.pause_next_mark_move()
        };
        tokio::time::timeout(Duration::from_secs(10), pause.reached())
            .await
            .expect("snapshot reached its final mark or signing turn");
        change_feed_account(&replay, change, &at).await;
        pause.release();
    });
    let head = header_text(&answer, header::HEAD).map(str::to_string);
    replay.db.drop_database().await.expect("drop");
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (503, json!("unavailable")),
        "{change:?}, refusal={refusal}, after_mark={after_mark}"
    );
    assert!(head.is_none(), "ended account/generation: {head:?}");
}

#[tokio::test]
async fn test_feed_snapshot_generation_overtaken_before_signing() {
    for after_mark in [false, true] {
        change_before_feed_sign(FeedChange::Recover, false, after_mark).await;
    }
}

#[tokio::test]
async fn test_feed_snapshot_erased_before_mark_move_has_no_head() {
    for after_mark in [false, true] {
        change_before_feed_sign(FeedChange::Erase, false, after_mark).await;
    }
}

#[tokio::test]
async fn test_feed_snapshot_refusal_overtaken_before_signing() {
    for after_mark in [false, true] {
        change_before_feed_sign(FeedChange::Recover, true, after_mark).await;
    }
}

#[tokio::test]
async fn test_feed_snapshot_refusal_erased_before_signing() {
    for after_mark in [false, true] {
        change_before_feed_sign(FeedChange::Erase, true, after_mark).await;
    }
}

#[tokio::test]
async fn test_feed_account_lock_is_held_through_signing() {
    for change in [FeedChange::Recover, FeedChange::Erase] {
        let Some(replay) = replay().await else { return };
        replay_chain_through_revoke(&replay).await;
        let at = revoke_time();
        let pause = replay.service.pause_next_feed_sign_locked();
        let (answer, overtook) = tokio::join!(read(&replay, "wallet", "?limit=0", &at), async {
            tokio::time::timeout(Duration::from_secs(10), pause.reached())
                .await
                .expect("signing turn");
            let transition = change_feed_account(&replay, change, &at);
            tokio::pin!(transition);
            let overtook = tokio::select! {
                () = &mut transition => true,
                () = tokio::time::sleep(Duration::from_millis(100)) => false,
            };
            pause.release();
            if !overtook {
                transition.await;
            }
            overtook
        });
        replay.db.drop_database().await.expect("drop");
        assert!(!overtook, "transition overtook the signing lock");
        // A head signed before the later transition may finish arriving afterwards.
        assert_eq!(answer.status, 200);
        assert_eq!(body(&answer)["head"]["generation"], 1);
        assert_eq!(head_seq(&answer), Some(9));
    }
}

#[tokio::test]
async fn test_feed_snapshot_cannot_sign_for_another_account_creation() {
    change_before_feed_sign(FeedChange::EnrollAgain, false, true).await;
    // Creation names the account independently of generation and chain tip (wire 7.3).
    // Hold those fields equal so only the creation-time boundary can refuse the page.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let original = mark_of(&replay).await;
    let pause = replay.service.pause_next_feed_sign();
    let at = revoke_time();
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?limit=0", &at), async {
        tokio::time::timeout(Duration::from_secs(10), pause.reached())
            .await
            .expect("signing turn");
        let created = original.created_at_ms + 1;
        let mut txn = replay
            .db
            .store()
            .begin(&alice_id())
            .await
            .expect("begin")
            .expect("account");
        sqlx::query("UPDATE accounts SET created_at_ms = $1 WHERE id = $2")
            .bind(i64::try_from(created).expect("time"))
            .bind(alice_id())
            .execute(txn.conn())
            .await
            .expect("another creation");
        txn.commit().await.expect("commit");
        replay
            .marks
            .take(&alice_id(), original, original.key, created)
            .await
            .expect("matching mark");
        let later = mark_of(&replay).await;
        assert_eq!(later.head(), original.head());
        assert_ne!(later.created_at_ms, original.created_at_ms);
        pause.release();
    });
    replay.db.drop_database().await.expect("drop");
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (503, json!("unavailable"))
    );
    assert!(header_text(&answer, header::HEAD).is_none());
}

#[tokio::test]
async fn test_feed_signing_checks_freshness_after_its_final_storage_reads() {
    use pubky_switch::store::{LockFreshness, LockTiming};
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let freshness = LockFreshness::confirmed_ago(
        Duration::ZERO,
        LockTiming::checking_every(Duration::from_millis(250)),
    );
    let service = replay
        .restarted_with(Limits::default())
        .with_lock_freshness(freshness.clone());
    let pause = service.pause_next_feed_sign_locked();
    let path = format!("/v1/{}/feed?limit=0", alice_id());
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &path,
        Vec::new(),
        ms(&revoke_time()),
    );
    let (answer, ()) = tokio::join!(service.handle(request), async {
        tokio::time::timeout(Duration::from_secs(10), pause.reached())
            .await
            .expect("signing turn");
        while freshness.is_fresh() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        pause.release();
    });
    replay.db.drop_database().await.expect("drop");
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (503, json!("unavailable"))
    );
    assert!(header_text(&answer, header::HEAD).is_none());
}

#[tokio::test]
async fn test_feed_snapshot_cannot_sign_behind_a_later_committed_head() {
    for refusal in [false, true] {
        for after_mark in [false, true] {
            change_before_feed_sign(FeedChange::Advance, refusal, after_mark).await;
        }
    }
}

#[tokio::test]
async fn test_feed_waits_for_erasure_deletion() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let mut blocker = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    sqlx::query("SELECT pg_advisory_lock(774123)")
        .execute(&mut blocker)
        .await
        .expect("lock");
    sqlx::query("CREATE FUNCTION block_account_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(774123); RAISE EXCEPTION 'injected deletion failure'; END $$")
        .execute(&mut blocker).await.expect("function");
    sqlx::query("CREATE TRIGGER block_account_delete BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION block_account_delete()")
        .execute(&mut blocker).await.expect("trigger");
    let answered = AtomicBool::new(false);
    let (feed, (erased, early)) = tokio::join!(
        async {
            let response = Box::pin(read(&replay, "wallet", "?after=1:9&wait=1", &at)).await;
            answered.store(true, Ordering::SeqCst);
            response
        },
        async {
            until_held(&replay).await;
            let held = held_identity().doc_hash().expect("hash");
            let request = erasure_of(&replay, &alice_id(), Some(&held), ms(&at)).await;
            tokio::join!(Box::pin(replay.service.handle(request)), async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !replay
                        .key_dir()
                        .join("accounts/erasure-attempts")
                        .join(alice_id())
                        .exists()
                    {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("erasure attempt written before deletion");
                let early = tokio::time::timeout(Duration::from_secs(2), async {
                    while !answered.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .is_ok();
                sqlx::query("SELECT pg_advisory_unlock(774123)")
                    .execute(&mut blocker)
                    .await
                    .expect("unlock");
                early
            })
        }
    );
    assert_eq!(erased.status, 503, "deletion failed");
    assert!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("lookup")
            .is_some(),
        "account survives"
    );
    assert!(
        replay
            .marks
            .erasure(&alice_id())
            .await
            .expect("erasure")
            .is_none(),
        "failed deletion withdrew record"
    );
    blocker.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
    assert!(
        !early,
        "feed answered before erasure committed: {} {}",
        feed.status,
        String::from_utf8_lossy(&feed.body)
    );
}

#[tokio::test]
async fn test_feed_live_mark_store_loss_refuses_cached_account() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    std::fs::remove_file(replay.key_dir().join("accounts/store-id")).expect("lose store identity");
    let path = format!("/v1/{}/apps", alice_id());
    let request = signer_request("GET", &path, Vec::new(), ms(&revoke_time()));
    let sent = Sent::of(&request);
    let response = Box::pin(replay.service.handle(request)).await;
    assert!(signed_with(&response, &service_public(&replay), &sent));
    replay.db.drop_database().await.expect("drop");
    assert_eq!(
        response.status,
        503,
        "cached account signed after store loss: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert!(header_text(&response, header::HEAD).is_none());
}

async fn until_account_lock_waits(replay: &Replay) {
    let mut connection = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event = 'advisory')")
                .fetch_one(&mut connection).await.expect("waiting");
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.expect("request passed lookup and waits for identity lock");
    connection.close().await.expect("close");
}

#[tokio::test]
async fn test_feed_account_erased_again_uses_remaining_mark_verdict() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let old = mark_of(&replay).await;
    let erased_at = old.created_at_ms + 1;
    let request = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    );
    let (answer, ()) = tokio::join!(Box::pin(replay.service.handle(request)), async {
        until_account_lock_waits(&replay).await;
        replay
            .marks
            .record_erasure(&alice_id(), erased_at)
            .await
            .expect("erased older account");
        replay
            .marks
            .take(&alice_id(), old, old.key, erased_at + 1)
            .await
            .expect("later account's mark");
        txn.commit().await.expect("release lock");
    });
    assert!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("lookup")
            .is_none(),
        "restored old account erased again"
    );
    assert!(
        mark_of(&replay).await.created_at_ms > erased_at,
        "later mark stays"
    );
    let retry = Box::pin(replay.service.handle(signer_request_at_creation(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
        Some(erased_at + 1),
    )))
    .await;
    replay.db.drop_database().await.expect("drop");
    assert_eq!(
        retry.status,
        503,
        "new request sees lost account: {}",
        String::from_utf8_lossy(&retry.body)
    );
    assert_eq!(
        answer.status,
        409,
        "old creation must conflict before the lost-account verdict: {}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(body(&answer)["code"], "conflict");
    assert_eq!(
        body(&answer)["current"],
        json!({"created": pubky_switch_core::time::rfc3339(erased_at + 1)})
    );
    assert_eq!(body(&retry)["code"], "recovery_required");
    assert_eq!(body(&retry)["current"]["reason"], "behind");
    assert!(header_text(&retry, header::HEAD).is_none());
    assert!(header_text(&answer, header::HEAD).is_none());
}

#[tokio::test]
async fn test_feed_account_lost_between_lookup_and_lock_uses_mark() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let request = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    );
    let (answer, ()) = tokio::join!(Box::pin(replay.service.handle(request)), async {
        until_account_lock_waits(&replay).await;
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(alice_id())
            .execute(txn.conn())
            .await
            .expect("lost account state");
        txn.commit().await.expect("release lock");
    });
    let retry = Box::pin(replay.service.handle(signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    )))
    .await;
    replay.db.drop_database().await.expect("drop");
    assert_eq!(retry.status, 503, "new request sees lost account");
    assert_eq!(
        answer.status,
        503,
        "begin(None) skips mark verdict: {}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(body(&answer)["code"], "recovery_required");
    assert_eq!(body(&answer)["current"]["reason"], "behind");
    assert_eq!(body(&answer), body(&retry));
    assert!(header_text(&answer, header::HEAD).is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn test_feed_failed_erasure_record_does_not_erase_account() {
    use std::os::unix::fs::PermissionsExt;
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let erasures = replay.key_dir().join("accounts/erasure-attempts");
    let permissions = std::fs::metadata(&erasures)
        .expect("metadata")
        .permissions();
    std::fs::set_permissions(&erasures, std::fs::Permissions::from_mode(0o500)).expect("read only");
    let held = held_identity().doc_hash().expect("hash");
    let request = erasure_of(&replay, &alice_id(), Some(&held), ms(&revoke_time())).await;
    let erased = Box::pin(replay.service.handle(request)).await;
    std::fs::set_permissions(&erasures, permissions).expect("writable");
    assert_eq!(erased.status, 503);
    assert!(!erasures.join(alice_id()).exists(), "no record landed");
    assert!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("lookup")
            .is_some()
    );
    let request = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    );
    let answer = Box::pin(replay.service.handle(request)).await;
    let survived = replay
        .db
        .store()
        .lookup(&alice_id())
        .await
        .expect("lookup")
        .is_some();
    replay.db.drop_database().await.expect("drop");
    assert!(
        survived,
        "a record that was never written must not erase the account"
    );
    assert_eq!(answer.status, 200);
}

#[tokio::test]
async fn test_feed_withdrawn_erasure_is_rechecked_after_waiting_for_lock() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let erased_at = mark_of(&replay).await.created_at_ms + 1;
    replay
        .marks
        .record_erasure(&alice_id(), erased_at)
        .await
        .expect("pending erasure");
    let request = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    );
    let (answer, ()) = tokio::join!(Box::pin(replay.service.handle(request)), async {
        until_account_lock_waits(&replay).await;
        replay
            .marks
            .withdraw_erasure(&alice_id(), erased_at, None)
            .await
            .expect("withdraw failed erasure");
        txn.commit().await.expect("release lock");
    });
    let survived = replay
        .db
        .store()
        .lookup(&alice_id())
        .await
        .expect("lookup")
        .is_some();
    let mark = replay.marks.read(&alice_id()).await.expect("mark");
    let erasure = replay.marks.erasure(&alice_id()).await.expect("erasure");
    replay.db.drop_database().await.expect("drop");
    assert!(survived, "the withdrawn intent authorizes no deletion");
    assert!(matches!(mark, pubky_switch::marks::MarkRead::Mark(_)));
    assert_eq!(erasure, None);
    assert_eq!(answer.status, 200);
}

#[tokio::test]
async fn test_feed_failed_deletion_keeps_the_lock_until_record_withdrawal() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut connection = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    sqlx::query("CREATE SEQUENCE delete_attempt")
        .execute(&mut connection)
        .await
        .expect("sequence");
    sqlx::query("CREATE FUNCTION fail_account_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('delete_attempt') = 1 THEN RAISE EXCEPTION 'injected deletion failure'; END IF; RETURN OLD; END $$")
        .execute(&mut connection).await.expect("function");
    sqlx::query("CREATE TRIGGER fail_account_delete BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION fail_account_delete()")
        .execute(&mut connection).await.expect("trigger");
    let pause = replay.service.pause_next_erase_failure();
    let held = held_identity().doc_hash().expect("hash");
    let request = erasure_of(&replay, &alice_id(), Some(&held), ms(&revoke_time())).await;
    let answered = AtomicBool::new(false);
    let (erased, (answer, early)) = tokio::join!(Box::pin(replay.service.handle(request)), async {
        tokio::time::timeout(Duration::from_secs(5), pause.reached())
            .await
            .expect("failed deletion");
        let request = signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&revoke_time()),
        );
        tokio::join!(
            async {
                let answer = Box::pin(replay.service.handle(request)).await;
                answered.store(true, Ordering::SeqCst);
                answer
            },
            async {
                let early = tokio::time::timeout(Duration::from_millis(500), async {
                    while !answered.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .is_ok();
                pause.release();
                early
            }
        )
    });
    let survived = replay
        .db
        .store()
        .lookup(&alice_id())
        .await
        .expect("lookup")
        .is_some();
    let record = replay.marks.erasure(&alice_id()).await.expect("record");
    connection.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
    assert_eq!(erased.status, 503);
    assert!(
        survived,
        "a request must not complete an erasure whose failure is withdrawing its record"
    );
    assert_eq!(record, None);
    assert!(!early, "request passed the erasure before withdrawal");
    assert_eq!(answer.status, 200);
}

#[tokio::test]
async fn test_feed_failed_deferred_deletion_keeps_the_lock_until_record_withdrawal() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut connection = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    sqlx::query("CREATE SEQUENCE delete_attempt")
        .execute(&mut connection)
        .await
        .expect("sequence");
    sqlx::query("CREATE FUNCTION fail_account_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('delete_attempt') = 1 THEN RAISE EXCEPTION 'injected deletion failure'; END IF; RETURN OLD; END $$")
        .execute(&mut connection).await.expect("function");
    sqlx::query("CREATE CONSTRAINT TRIGGER fail_account_delete AFTER DELETE ON accounts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_account_delete()")
        .execute(&mut connection).await.expect("trigger");
    let pause = replay.service.pause_next_erase_failure();
    let held = held_identity().doc_hash().expect("hash");
    let request = erasure_of(&replay, &alice_id(), Some(&held), ms(&revoke_time())).await;
    let answered = AtomicBool::new(false);
    let (erased, (answer, early)) = tokio::join!(Box::pin(replay.service.handle(request)), async {
        tokio::time::timeout(Duration::from_secs(5), pause.reached())
            .await
            .expect("failed deletion");
        let request = signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&revoke_time()),
        );
        tokio::join!(
            async {
                let answer = Box::pin(replay.service.handle(request)).await;
                answered.store(true, Ordering::SeqCst);
                answer
            },
            async {
                let early = tokio::time::timeout(Duration::from_millis(500), async {
                    while !answered.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .is_ok();
                pause.release();
                early
            }
        )
    });
    let survived = replay
        .db
        .store()
        .lookup(&alice_id())
        .await
        .expect("lookup")
        .is_some();
    let record = replay.marks.erasure(&alice_id()).await.expect("record");
    connection.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
    assert_eq!(erased.status, 503);
    assert!(
        survived,
        "a request must not complete an erasure whose failure is withdrawing its record"
    );
    assert_eq!(record, None);
    assert!(!early, "request passed the erasure before withdrawal");
    assert_eq!(answer.status, 200);
}
#[tokio::test]
async fn test_feed_failed_deletion_with_expired_lock_preserves_account() {
    use pubky_switch::store::{LockFreshness, LockTiming};
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut connection = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    sqlx::query("CREATE SEQUENCE delete_attempt")
        .execute(&mut connection)
        .await
        .expect("sequence");
    sqlx::query("CREATE FUNCTION fail_account_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('delete_attempt') = 1 THEN RAISE EXCEPTION 'injected deletion failure'; END IF; RETURN OLD; END $$")
        .execute(&mut connection).await.expect("function");
    sqlx::query("CREATE TRIGGER fail_account_delete BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION fail_account_delete()")
        .execute(&mut connection).await.expect("trigger");
    let service = replay
        .restarted_with(pubky_switch::limits::Limits::default())
        .with_lock_freshness(LockFreshness::confirmed_ago(
            Duration::ZERO,
            LockTiming::checking_every(Duration::from_secs(1)),
        ));
    let pause = service.pause_next_erase_failure();
    let held = held_identity().doc_hash().expect("hash");
    let request = erasure_of(&replay, &alice_id(), Some(&held), ms(&revoke_time())).await;
    let (erased, ()) = tokio::join!(Box::pin(service.handle(request)), async {
        tokio::time::timeout(Duration::from_secs(5), pause.reached())
            .await
            .expect("failed deletion");
        tokio::time::sleep(Duration::from_secs(3)).await;
        pause.release();
    });
    assert_eq!(erased.status, 503);
    assert!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("lookup")
            .is_some(),
        "the database rejected the deletion"
    );
    let read = Box::pin(replay.service.handle(signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    )))
    .await;
    let survived = replay
        .db
        .store()
        .lookup(&alice_id())
        .await
        .expect("lookup")
        .is_some();
    let record = replay.marks.erasure(&alice_id()).await.expect("record");
    connection.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
    assert!(
        survived,
        "a failed erasure cannot become committed when the lock is fresh again; read status {}, record {:?}",
        read.status, record
    );
    assert_eq!(record, None);
    assert_eq!(read.status, 200);
}
#[tokio::test]
async fn test_feed_failed_deletion_with_unwritable_record_preserves_account() {
    use std::os::unix::fs::PermissionsExt;
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut connection = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    sqlx::query("CREATE SEQUENCE delete_attempt")
        .execute(&mut connection)
        .await
        .expect("sequence");
    sqlx::query("CREATE FUNCTION fail_account_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('delete_attempt') = 1 THEN RAISE EXCEPTION 'injected deletion failure'; END IF; RETURN OLD; END $$")
        .execute(&mut connection).await.expect("function");
    sqlx::query("CREATE TRIGGER fail_account_delete BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION fail_account_delete()")
        .execute(&mut connection).await.expect("trigger");
    let service = replay.restarted_with(pubky_switch::limits::Limits::default());
    let erasures = replay.key_dir().join("accounts/erasure-attempts");
    let permissions = std::fs::metadata(&erasures)
        .expect("metadata")
        .permissions();
    let pause = service.pause_next_erase_failure();
    let held = held_identity().doc_hash().expect("hash");
    let request = erasure_of(&replay, &alice_id(), Some(&held), ms(&revoke_time())).await;
    let (erased, ()) = tokio::join!(Box::pin(service.handle(request)), async {
        tokio::time::timeout(Duration::from_secs(5), pause.reached())
            .await
            .expect("failed deletion");
        std::fs::set_permissions(&erasures, std::fs::Permissions::from_mode(0o500))
            .expect("read only");
        pause.release();
    });
    std::fs::set_permissions(&erasures, permissions).expect("writable");
    assert_eq!(erased.status, 503);
    assert!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("lookup")
            .is_some(),
        "the database rejected the deletion"
    );
    let reopened = pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        pubky_switch::marks::MarkStore::open(replay.key_dir()).expect("reopened marks"),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    );
    let read = Box::pin(reopened.handle(signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    )))
    .await;
    let survived = replay
        .db
        .store()
        .lookup(&alice_id())
        .await
        .expect("lookup")
        .is_some();
    let record = pubky_switch::marks::MarkView::open(replay.key_dir())
        .expect("view")
        .erasure(&alice_id())
        .expect("record");
    connection.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
    assert!(
        survived,
        "a failed erasure cannot become committed after the mark store becomes writable and reloads; read status {}, record {:?}",
        read.status, record
    );
    assert_eq!(record, None);
    assert_eq!(read.status, 200);
}

async fn signer_waiting_for_later_mark(lost_sql: bool) {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let old = mark_of(&replay).await;
    let later_created = old.created_at_ms + 1;
    let query = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    );
    let sent = Sent::of(&query);
    let (answer, ()) = tokio::join!(Box::pin(replay.service.handle(query)), async {
        until_account_lock_waits(&replay).await;
        if lost_sql {
            sqlx::query("DELETE FROM accounts WHERE id = $1")
                .bind(alice_id())
                .execute(txn.conn())
                .await
                .expect("lost SQL");
            replay
                .marks
                .take(&alice_id(), old, old.key, later_created)
                .await
                .expect("later mark");
        } else {
            // A restored older SQL row beside the later lifetime's staged mark
            // (Switch account binding 1.1).
            replay
                .marks
                .delete(&alice_id())
                .await
                .expect("old mark erased");
            replay
                .marks
                .create_zero(&alice_id(), old.key, later_created)
                .await
                .expect("later zero mark");
        }
        txn.commit().await.expect("release lock");
    });
    assert_eq!(
        answer.status,
        409,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(body(&answer)["code"], "conflict");
    assert_eq!(
        body(&answer)["current"],
        json!({"created": pubky_switch_core::time::rfc3339(later_created)})
    );
    assert!(header_text(&answer, header::HEAD).is_none());
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    let mark = mark_of(&replay).await;
    assert_eq!(mark.created_at_ms, later_created);
    assert_eq!(mark.seq, if lost_sql { old.seq } else { 0 });
    let stored = replay.db.store().lookup(&alice_id()).await.expect("lookup");
    if lost_sql {
        assert!(stored.is_none());
    } else {
        let stored = stored.expect("older SQL retained");
        assert_eq!(stored.created_at_ms, old.created_at_ms);
        assert_eq!(stored.chain, Some((old.seq, old.chain_hash)));
    }
    assert_eq!(
        replay.marks.erasure(&alice_id()).await.expect("erasure"),
        None
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_signer_waiting_for_later_zero_mark_keeps_creation_binding() {
    Box::pin(signer_waiting_for_later_mark(false)).await;
}

#[tokio::test]
async fn test_signer_waiting_for_lost_row_keeps_creation_binding() {
    Box::pin(signer_waiting_for_later_mark(true)).await;
}
