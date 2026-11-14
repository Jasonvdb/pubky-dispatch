//! The verdict of an account and its mark on the request path (Switch wire 7.3 steps 2 and
//! 10, Tables 1 and 2; 7.6) on `chain.json`'s account: a lost or corrupt mark, a mark behind
//! or ahead of the state, a fork, what the notice replaces and what it doesn't, the mark's
//! move after a commit and its crash points, a stale instance lock, a mark store that can't
//! be read, and the not-hosted and unknown-route `404`s.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// The tests fail on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::{os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

use axum::http::HeaderMap;
use pubky_switch::{
    http::{Handler, Refusal, SwitchRequest, SwitchResponse, route::route},
    limits::Limits,
    marks::{AccountMark, MarkRead, MarkStore},
    service::Service,
    store::{LockFreshness, LockTiming},
};
use pubky_switch_core::{
    chain::ChainTip,
    enc::{b64, unb64},
    http::header,
    ops::OpsRequest,
    time::parse_rfc3339,
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

fn bob_id() -> String {
    vectors("keys.json")["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .expect("bob")["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn code(answer: &SwitchResponse) -> String {
    body(answer)["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// The chain hash `chain.json` gives at `seq`.
fn hash_at(seq: u64) -> [u8; 32] {
    unb64(
        chain_item(&vectors("chain.json"), seq)["chain_hash"]
            .as_str()
            .expect("hash"),
    )
    .expect("b64")
    .try_into()
    .expect("32")
}

/// The time of `chain.json`'s item at `seq`, in Unix milliseconds.
fn time_of(seq: u64) -> u64 {
    ms(&item_time(chain_item(&vectors("chain.json"), seq)))
}

/// A service on `replay`'s database, key store and clock, with `limits` and a mark store
/// opened afresh on its directory: what a restarted process reads, every mark from its file.
fn restarted(replay: &Replay, limits: Limits) -> (Service, MarkStore) {
    let marks = MarkStore::open(replay.key_dir()).expect("mark store");
    let service = Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        marks.clone(),
        replay.time.clone(),
        limits,
    );
    (service, marks)
}

fn accounts_dir(replay: &Replay) -> PathBuf {
    replay.key_dir().join("accounts")
}

fn mark_file(replay: &Replay) -> PathBuf {
    accounts_dir(replay).join("marks").join(alice_id())
}

/// alice's mark as `marks` holds it.
async fn mark_in(marks: &MarkStore) -> AccountMark {
    match marks.read(&alice_id()).await.expect("read") {
        MarkRead::Mark(mark) => mark,
        other => panic!("no mark: {other:?}"),
    }
}

/// alice's account's last given-out `seq` and stamped time.
async fn account_row(replay: &Replay) -> (i64, i64) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let row = sqlx::query_as("SELECT last_seq, stamped_time_ms FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("account");
    conn.close().await.expect("close");
    row
}

async fn sql(replay: &Replay, statements: &[&str]) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for statement in statements {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("sql");
    }
    conn.close().await.expect("close");
}

/// alice's signer reads her apps at `at_ms`: an own signed request that carries the head.
fn apps_read(at_ms: u64) -> SwitchRequest {
    signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        at_ms,
    )
}

/// The same request with a signature that doesn't verify.
fn bad_signature(mut request: SwitchRequest) -> SwitchRequest {
    request
        .headers
        .insert(header::SIGNATURE, b64(&[7u8; 64]).parse().expect("header"));
    request
}

/// The public read of alice's `identity.json`, unsigned.
fn public_read() -> SwitchRequest {
    request(
        "GET",
        &format!("/v1/{}/identity", alice_id()),
        &[],
        Vec::new(),
    )
}

fn from_source(mut request: SwitchRequest, ip: &str) -> SwitchRequest {
    request.source = Some(pubky_switch::http::source::NetworkSource::of(
        ip.parse().expect("ip"),
    ));
    request
}

/// The wallet's batch of `chain.json`'s items at `seqs`, at the first item's time, the
/// clock set to it, so its proofs are `chain.json`'s.
fn wallet_batch(replay: &Replay, seqs: &[u64]) -> SwitchRequest {
    let at_ms = time_of(seqs[0]);
    replay.clock.set_wall_ms(at_ms);
    let keys = vectors("keys.json");
    let body = OpsRequest::new(&ops_at(&vectors("chain.json"), seqs), None).to_json();
    app_request(
        app(&keys, "wallet"),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        body,
        at_ms,
    )
}

/// The mark a healthy answer at the head `seq` leaves.
fn mark_at(old: &AccountMark, seq: u64) -> AccountMark {
    AccountMark {
        seq,
        chain_hash: hash_at(seq),
        ..*old
    }
}

/// alice served (`chain.json` seqs 1 and 2), the clock a minute past her last commit, so
/// the time base and her stamped time differ: her mark, and the time base.
async fn served(replay: &Replay) -> (AccountMark, u64) {
    serve_alice(replay).await;
    let mark = mark_in(&replay.marks).await;
    assert_eq!(mark, mark_at(&mark, 2), "the mark at the head of seq 2");
    let base = time_of(2) + 60_000;
    replay.clock.set_wall_ms(base);
    assert_eq!(replay.time.peek().base_ms, base, "the time base");
    (mark, base)
}

/// The answer is the notice (Switch wire 7.6) for `reason` at `generation`: no head, at the
/// time base, signed with the service key and bound to `sent`.
fn assert_notice(
    replay: &Replay,
    answer: &SwitchResponse,
    sent: &Sent,
    reason: &str,
    generation: u64,
) {
    assert_eq!(
        (answer.status, body(answer)),
        (
            503,
            json!({
                "code": "recovery_required",
                "message": "7.3: the account awaits the start of a new generation",
                "current": { "generation": generation, "reason": reason, "permanent": false },
            })
        ),
        "the notice"
    );
    assert_signed_without_head(replay, answer, sent);
}

/// The answer carries no head, is signed at the time base with the service key and bound to
/// `sent` (Switch wire 7.1, 7.3 under Table 2).
fn assert_signed_without_head(replay: &Replay, answer: &SwitchResponse, sent: &Sent) {
    assert!(header_text(answer, header::HEAD).is_none(), "no head");
    let time = header_text(answer, header::SERVER_TIME).expect("server time");
    assert_eq!(
        parse_rfc3339(time).expect("time"),
        replay.time.peek().base_ms,
        "Switch-Server-Time is the time base"
    );
    assert!(
        signed_with(answer, &service_public(replay), sent),
        "signed with the service key"
    );
}

/// A lost mark: the file deleted, read afresh by a restarted service.
async fn lose_mark(replay: &Replay, limits: Limits) -> (Service, MarkStore) {
    std::fs::remove_file(mark_file(replay)).expect("delete the mark");
    restarted(replay, limits)
}

#[tokio::test]
async fn test_marks_lost_mark_answers_the_notice() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, base) = served(&replay).await;
    // Healthy, the mark in place: served with the head.
    let healthy = replay.service.handle(apps_read(base)).await;
    assert_eq!(
        healthy.status,
        200,
        "{}",
        String::from_utf8_lossy(&healthy.body)
    );
    assert!(header_text(&healthy, header::HEAD).is_some(), "the head");
    let (service, marks) = lose_mark(&replay, Limits::default()).await;
    assert_eq!(
        marks.read(&alice_id()).await.expect("read"),
        MarkRead::Missing
    );
    let request = apps_read(base);
    let sent = Sent::of(&request);
    let answer = service.handle(request).await;
    // A serving account without its mark fails stop (Switch wire 7.3, Table 1).
    assert_notice(&replay, &answer, &sent, "mark_lost", mark.generation);
    assert_eq!(service.mark_refusals(), 1, "the notice counted");
    // Nothing is written anew by a request that starts nothing.
    assert_eq!(
        marks.read(&alice_id()).await.expect("read"),
        MarkRead::Missing
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_corrupt_mark_answers_the_notice() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, base) = served(&replay).await;
    std::fs::write(mark_file(&replay), b"not a mark").expect("junk");
    let (service, marks) = restarted(&replay, Limits::default());
    assert_eq!(
        marks.read(&alice_id()).await.expect("read"),
        MarkRead::NotAMark
    );
    let request = apps_read(base);
    let sent = Sent::of(&request);
    let answer = service.handle(request).await;
    // A file that doesn't read as a mark is as no mark (Switch wire 7.3, Table 1).
    assert_notice(&replay, &answer, &sent, "mark_lost", mark.generation);
    assert_eq!(service.mark_refusals(), 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_state_ahead_of_the_mark_is_healthy_and_moves_it() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, _) = served(&replay).await;
    let batch = replay.service.handle(wallet_batch(&replay, &[3, 4])).await;
    assert_eq!(
        batch.status,
        200,
        "{}",
        String::from_utf8_lossy(&batch.body)
    );
    assert_eq!(mark_in(&replay.marks).await, mark_at(&mark, 4), "moved");
    // The mark back at seq 2, as a move that failed after its commit leaves it.
    replay.marks.delete(&alice_id()).await.expect("delete");
    let at_two = mark_at(&mark, 2);
    replay
        .marks
        .write_anew(&alice_id(), at_two.head(), at_two.key, at_two.created_at_ms)
        .await
        .expect("write");
    let at = time_of(3) + 60_000;
    replay.clock.set_wall_ms(at);
    let answer = replay.service.handle(apps_read(at)).await;
    // State at or past the mark: healthy, served with the head (Switch wire 7.3, Table 1).
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "the head");
    assert!(signed_with(
        &answer,
        &service_public(&replay),
        &Sent::of(&apps_read(at))
    ));
    // The answer carried a head: the mark moved to it (Table 3).
    assert_eq!(mark_in(&replay.marks).await, mark_at(&mark, 4), "moved");
    assert_eq!(replay.service.mark_refusals(), 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_state_ahead_with_another_hash_at_the_mark_is_a_fork() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, _) = served(&replay).await;
    let batch = replay.service.handle(wallet_batch(&replay, &[3, 4])).await;
    assert_eq!(
        batch.status,
        200,
        "{}",
        String::from_utf8_lossy(&batch.body)
    );
    // A mark at seq 2 whose chain hash isn't the stub's there.
    replay.marks.delete(&alice_id()).await.expect("delete");
    let other = ChainTip {
        chain_hash: [9; 32],
        ..mark_at(&mark, 2).head()
    };
    replay
        .marks
        .write_anew(&alice_id(), other, mark.key, mark.created_at_ms)
        .await
        .expect("write");
    let at = time_of(3) + 60_000;
    replay.clock.set_wall_ms(at);
    let request = apps_read(at);
    let sent = Sent::of(&request);
    let answer = replay.service.handle(request).await;
    // A state past the mark with another chain hash at the mark's seq (Switch wire 7.3,
    // under Table 1).
    assert_notice(&replay, &answer, &sent, "fork", mark.generation);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_database_older_than_the_mark_answers_behind() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, base) = served(&replay).await;
    // The mark advanced past the state, as after a restore of an older database.
    let ahead = ChainTip {
        generation: mark.generation,
        seq: 40,
        chain_hash: [3; 32],
    };
    replay
        .marks
        .advance(&alice_id(), ahead, mark.key, mark.created_at_ms)
        .await
        .expect("advance");
    let request = apps_read(base);
    let sent = Sent::of(&request);
    let answer = replay.service.handle(request).await;
    // State behind the mark: failing, `behind`, at the mark's generation (Switch wire 7.3,
    // Table 1; 7.6).
    assert_notice(&replay, &answer, &sent, "behind", mark.generation);
    assert_eq!(replay.service.mark_refusals(), 1);
    // The mark stays where it was.
    assert_eq!(mark_in(&replay.marks).await.head(), ahead);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_mark_at_the_state_with_another_hash_answers_fork() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, base) = served(&replay).await;
    replay.marks.delete(&alice_id()).await.expect("delete");
    let other = ChainTip {
        chain_hash: [9; 32],
        ..mark.head()
    };
    replay
        .marks
        .write_anew(&alice_id(), other, mark.key, mark.created_at_ms)
        .await
        .expect("write");
    let request = apps_read(base);
    let sent = Sent::of(&request);
    let answer = replay.service.handle(request).await;
    // Mark at the state's pair, another chain hash (Switch wire 7.3, Table 1).
    assert_notice(&replay, &answer, &sent, "fork", mark.generation);
    assert_eq!(replay.service.mark_refusals(), 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_notice_replaces_refusals_before_authentication() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, base) = served(&replay).await;
    let shop_reads_apps = || {
        other_request(
            "shop",
            ORIGIN,
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            None,
            base,
        )
    };
    let wallet_reads_apps = || {
        let keys = vectors("keys.json");
        app_request(
            app(&keys, "wallet"),
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            base,
        )
    };
    // Healthy: a bad signature is a 401, another identity's app at a signer call a 403
    // before the lock, an own app there a 403, and the public read served.
    let unsigned = replay.service.handle(bad_signature(apps_read(base))).await;
    assert_eq!(
        (unsigned.status, code(&unsigned).as_str()),
        (401, "bad_signature")
    );
    assert_eq!(replay.service.handle(shop_reads_apps()).await.status, 403);
    assert_eq!(replay.service.handle(wallet_reads_apps()).await.status, 403);
    assert_eq!(replay.service.handle(public_read()).await.status, 200);

    let (service, _) = lose_mark(&replay, Limits::default()).await;
    // The notice goes to every caller, a 401 and a 403 before authentication included
    // (Switch wire 7.3 under Table 2).
    let requests = [
        bad_signature(apps_read(base)),
        shop_reads_apps(),
        wallet_reads_apps(),
        public_read(),
    ];
    let count = requests.len();
    for (n, request) in requests.into_iter().enumerate() {
        let sent = Sent::of(&request);
        let answer = service.handle(request).await;
        assert_notice(&replay, &answer, &sent, "mark_lost", mark.generation);
        assert_eq!(service.mark_refusals(), u64::try_from(n + 1).expect("n"));
    }
    assert_eq!(
        service.mark_refusals(),
        u64::try_from(count).expect("count")
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_replaced_401_counts_as_a_failed_authentication() {
    let Some(replay) = replay_with(Limits {
        auth_failures_per_source_per_min: 1,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    let (mark, base) = served(&replay).await;
    let (service, _) = lose_mark(
        &replay,
        Limits {
            auth_failures_per_source_per_min: 1,
            ..Limits::default()
        },
    )
    .await;
    let source = "203.0.113.7";
    let request = from_source(bad_signature(apps_read(base)), source);
    let sent = Sent::of(&request);
    let answer = service.handle(request).await;
    assert_notice(&replay, &answer, &sent, "mark_lost", mark.generation);
    // The 401 the notice replaced counts against its source (Switch wire 7.3 under Table 2,
    // 9.4).
    let claimed = (alice_id(), alice_id(), None);
    assert_eq!(
        service.failed_authentications().claimed(&claimed, base),
        1,
        "counted"
    );
    // A signed request that verifies is not counted.
    let good = service
        .handle(from_source(apps_read(base), "203.0.113.8"))
        .await;
    assert_eq!(code(&good), "recovery_required");
    assert_eq!(service.failed_authentications().claimed(&claimed, base), 1);
    // And the source's limit, reached, is a 429 that the notice doesn't replace.
    let request = from_source(apps_read(base), source);
    let sent = Sent::of(&request);
    let limited = service.handle(request).await;
    assert_eq!(
        (limited.status, code(&limited).as_str()),
        (429, "rate_limited")
    );
    assert_signed_without_head(&replay, &limited, &sent);
    assert_eq!(service.mark_refusals(), 2, "the 429 is no notice");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_public_read_limit_stays_a_429() {
    let limits = Limits {
        identity_reads_per_source_per_min: 1,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits.clone()).await else {
        return;
    };
    let (mark, _) = served(&replay).await;
    let (service, _) = lose_mark(&replay, limits).await;
    let source = "198.51.100.4";
    let request = from_source(public_read(), source);
    let sent = Sent::of(&request);
    let first = service.handle(request).await;
    assert_notice(&replay, &first, &sent, "mark_lost", mark.generation);
    // A 429 before authentication stays (Switch wire 7.3 under Table 2, 9.4).
    let request = from_source(public_read(), source);
    let sent = Sent::of(&request);
    let limited = service.handle(request).await;
    assert_eq!(
        (limited.status, code(&limited).as_str()),
        (429, "rate_limited")
    );
    assert_signed_without_head(&replay, &limited, &sent);
    assert_eq!(service.mark_refusals(), 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_413_from_the_transport_stays() {
    let Some(replay) = replay().await else {
        return;
    };
    let (_, base) = served(&replay).await;
    let (service, _) = lose_mark(&replay, Limits::default()).await;
    let path = format!("/v1/{}/identity", alice_id());
    let request = signer_request("PUT", &path, Vec::new(), base);
    let sent = Sent::of(&request);
    let answer = service
        .refuse(Refusal::TooLarge {
            route: route("PUT", &path),
            method: "PUT".into(),
            path_and_query: path.clone(),
            headers: request.headers.clone(),
            cap: 64,
        })
        .await;
    // Refused before the body is read, by the transport: no verdict is judged (Switch wire
    // 7.1).
    assert_eq!((answer.status, code(&answer).as_str()), (413, "too_large"));
    assert_signed_without_head(&replay, &answer, &sent);
    assert_eq!(service.mark_refusals(), 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_failed_move_answers_503_and_the_retry_moves_it() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, _) = served(&replay).await;
    let marks_dir = accounts_dir(&replay).join("marks");
    std::fs::set_permissions(&marks_dir, std::fs::Permissions::from_mode(0o500))
        .expect("read-only");
    let request = wallet_batch(&replay, &[3, 4]);
    let sent = Sent::of(&request);
    let answer = Box::pin(replay.service.handle(request)).await;
    std::fs::set_permissions(&marks_dir, std::fs::Permissions::from_mode(0o700)).expect("writable");
    // The commit held and the mark's move failed: `503 unavailable`, signed, without a head
    // (Switch wire 7.3, "Moving it").
    assert_eq!(
        (answer.status, code(&answer).as_str()),
        (503, "unavailable")
    );
    assert!(header_text(&answer, header::HEAD).is_none(), "no head");
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    assert_eq!(account_row(&replay).await.0, 4, "the commit held");
    assert_eq!(mark_in(&replay.marks).await, mark, "the mark unchanged");
    // A restart: the same database and key directory.
    let marks = MarkStore::open(replay.key_dir()).expect("mark store");
    assert_eq!(mark_in(&marks).await, mark, "the mark unchanged on disk");
    let service = Box::pin(Service::start(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        marks.clone(),
        replay.time.clone(),
        Limits::default(),
    ))
    .await;
    // The state ahead of the mark: healthy; the same batch is a retry, answered as one with
    // the head, and the mark moves.
    let retry = Box::pin(service.handle(wallet_batch(&replay, &[3, 4]))).await;
    assert_eq!(
        retry.status,
        200,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    let retried = body(&retry);
    let chain = vectors("chain.json");
    let proofs: Vec<pubky_switch_core::sig::SignedDoc> =
        serde_json::from_value(retried["proofs"].clone()).expect("proofs");
    assert_eq!(proofs, vec![proof_at(&chain, 3), proof_at(&chain, 4)]);
    assert_eq!(retried["head"]["seq"], 4);
    assert!(header_text(&retry, header::HEAD).is_some(), "the head");
    assert_eq!(account_row(&replay).await.0, 4, "no seq given out again");
    assert_eq!(mark_in(&marks).await, mark_at(&mark, 4), "moved");
    assert_eq!(service.mark_refusals(), 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_failed_commit_leaves_the_mark() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, _) = served(&replay).await;
    let before = account_row(&replay).await;
    sql(
        &replay,
        &[
            "CREATE FUNCTION fail_at_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
             RAISE EXCEPTION 'a commit that fails'; END $$",
            "CREATE CONSTRAINT TRIGGER fail_at_commit AFTER UPDATE ON accounts \
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_at_commit()",
        ],
    )
    .await;
    let request = wallet_batch(&replay, &[3, 4]);
    let sent = Sent::of(&request);
    let answer = replay.service.handle(request).await;
    // Nothing committed, the stamp included: `503`, and the mark doesn't move (Switch wire
    // 7.3 step 10, "Moving it").
    assert_eq!(
        (answer.status, code(&answer).as_str()),
        (503, "unavailable")
    );
    assert!(header_text(&answer, header::HEAD).is_none(), "no head");
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    assert_eq!(account_row(&replay).await, before, "nothing committed");
    assert_eq!(mark_in(&replay.marks).await, mark, "the mark unchanged");
    sql(&replay, &["DROP TRIGGER fail_at_commit ON accounts"]).await;
    // Once commits hold again, the same batch commits and the mark moves.
    let answer = replay.service.handle(wallet_batch(&replay, &[3, 4])).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(mark_in(&replay.marks).await, mark_at(&mark, 4), "moved");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_stale_instance_lock_refuses_a_write() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, _) = served(&replay).await;
    let before = account_row(&replay).await;
    let timing = LockTiming::checking_every(Duration::from_secs(5));
    let with_lock = |freshness: LockFreshness| {
        replay
            .restarted_with(Limits::default())
            .with_lock_freshness(freshness)
    };
    // Last confirmed three checks ago: stale (Switch spec 6.5).
    let stale = with_lock(LockFreshness::confirmed_ago(
        Duration::from_secs(15),
        timing,
    ));
    let request = wallet_batch(&replay, &[3, 4]);
    let sent = Sent::of(&request);
    let answer = stale.handle(request).await;
    assert_eq!(
        (answer.status, code(&answer).as_str()),
        (503, "unavailable")
    );
    assert!(header_text(&answer, header::HEAD).is_none(), "no head");
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    assert_eq!(account_row(&replay).await, before, "nothing committed");
    assert_eq!(mark_in(&replay.marks).await, mark, "the mark unchanged");
    // Confirmed just now: the same write goes through.
    let fresh = with_lock(LockFreshness::confirmed_ago(Duration::ZERO, timing));
    let answer = fresh.handle(wallet_batch(&replay, &[3, 4])).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(account_row(&replay).await.0, 4);
    assert_eq!(mark_in(&replay.marks).await, mark_at(&mark, 4), "moved");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_unreadable_store_answers_unavailable() {
    let Some(replay) = replay().await else {
        return;
    };
    let (_, base) = served(&replay).await;
    std::fs::remove_file(accounts_dir(&replay).join("store-id")).expect("remove store-id");
    let (service, _) = restarted(&replay, Limits::default());
    for request in [apps_read(base), public_read()] {
        let sent = Sent::of(&request);
        let answer = service.handle(request).await;
        // The verdict is unknown: `503 unavailable`, without a head (Switch wire 7.3,
        // Table 2).
        assert_eq!(
            (answer.status, code(&answer).as_str()),
            (503, "unavailable")
        );
        assert_signed_without_head(&replay, &answer, &sent);
    }
    assert_eq!(service.mark_refusals(), 0, "no notice");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_not_hosted_404_is_bound_to_the_request() {
    let Some(replay) = replay().await else {
        return;
    };
    let base = time_of(2);
    replay.clock.set_wall_ms(base);
    // An identity never enrolled here: the public read, and a request alice signed.
    let reads = [
        request(
            "GET",
            &format!("/v1/{}/identity", bob_id()),
            &[],
            Vec::new(),
        ),
        apps_read(base),
    ];
    for request in reads {
        let sent = Sent::of(&request);
        let answer = replay.service.handle(request).await;
        // `current: { "hosted": false }`, no head, signed with the service key (Switch
        // wire 7.3 step 2).
        assert_eq!(
            (answer.status, body(&answer)),
            (
                404,
                json!({
                    "code": "not_found",
                    "message": "no such account",
                    "current": { "hosted": false },
                })
            )
        );
        assert_signed_without_head(&replay, &answer, &sent);
        // Bound to the request's method and path (7.1).
        let elsewhere = Sent {
            path: format!("{}/other", sent.path),
            ..sent.clone()
        };
        assert!(!signed_with(&answer, &service_public(&replay), &elsewhere));
        let other_method = Sent {
            method: "POST".into(),
            ..sent
        };
        assert!(!signed_with(
            &answer,
            &service_public(&replay),
            &other_method
        ));
    }
    assert_eq!(replay.service.mark_refusals(), 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_unknown_route_404_is_signed() {
    let Some(replay) = replay().await else {
        return;
    };
    let base = time_of(2);
    replay.clock.set_wall_ms(base);
    let path = "/v2/no/such/route";
    let sent = Sent {
        method: "GET".into(),
        path: path.into(),
        signature: None,
    };
    let answer = replay
        .service
        .refuse(Refusal::UnknownRoute {
            method: "GET".into(),
            path_and_query: path.into(),
            headers: HeaderMap::new(),
        })
        .await;
    // Step 1: an unknown route is `404`, signed with the service key (Switch wire 7.3).
    assert_eq!((answer.status, code(&answer).as_str()), (404, "not_found"));
    assert_signed_without_head(&replay, &answer, &sent);
    let elsewhere = Sent {
        path: "/v2/another/route".into(),
        ..sent
    };
    assert!(!signed_with(&answer, &service_public(&replay), &elsewhere));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_refusals_count_each_notice() {
    let Some(replay) = replay().await else {
        return;
    };
    let (_, base) = served(&replay).await;
    // Healthy answers count nothing.
    assert_eq!(replay.service.handle(apps_read(base)).await.status, 200);
    assert_eq!(replay.service.handle(public_read()).await.status, 200);
    assert_eq!(replay.service.mark_refusals(), 0);
    let (service, _) = lose_mark(&replay, Limits::default()).await;
    // Each notice counts, also the same account's again (Switch wire 7.6).
    for n in 1..=3 {
        let answer = service.handle(apps_read(base)).await;
        assert_eq!(code(&answer), "recovery_required");
        assert_eq!(service.mark_refusals(), n);
    }
    // The not-hosted 404 counts nothing.
    let not_hosted = service
        .handle(request(
            "GET",
            &format!("/v1/{}/identity", bob_id()),
            &[],
            Vec::new(),
        ))
        .await;
    assert_eq!(not_hosted.status, 404);
    assert_eq!(service.mark_refusals(), 3);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_later_generation_over_a_forked_earlier_chain_is_a_fork() {
    // The fork rule under Table 1 looks at the stub of the mark's generation at the mark's
    // `seq` whenever the service holds it, whatever the state's generation: a state at a
    // later generation over a chain whose stub there has another hash is a fork (Switch
    // wire 7.3).
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, _) = served(&replay).await;
    let batch = replay.service.handle(wallet_batch(&replay, &[3, 4])).await;
    assert_eq!(
        batch.status,
        200,
        "{}",
        String::from_utf8_lossy(&batch.body)
    );
    // The state at generation 2, its chain's stubs those of generation 1, and a mark at
    // generation 1's seq 2 whose chain hash isn't the stub's there.
    sql(
        &replay,
        &[&format!(
            "UPDATE accounts SET generation = 2 WHERE id = '{}'",
            alice_id()
        )],
    )
    .await;
    replay.marks.delete(&alice_id()).await.expect("delete");
    let other = ChainTip {
        chain_hash: [9; 32],
        ..mark_at(&mark, 2).head()
    };
    replay
        .marks
        .write_anew(&alice_id(), other, mark.key, mark.created_at_ms)
        .await
        .expect("write");
    let at = time_of(3) + 60_000;
    replay.clock.set_wall_ms(at);
    let request = apps_read(at);
    let sent = Sent::of(&request);
    let answer = replay.service.handle(request).await;
    assert_notice(&replay, &answer, &sent, "fork", 2);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_unknown_verdict_carries_the_identitys_service_time() {
    // The `503` of an unknown verdict carries the identity's service time, which never goes
    // back, also while the time base is behind the time it last stamped; only the notice
    // and the not-hosted `404` carry the time base (Switch wire 7.1 Timestamp, 7.3 step 2).
    let Some(replay) = replay().await else {
        return;
    };
    let (_, _) = served(&replay).await;
    let stamped = u64::try_from(account_row(&replay).await.1).expect("time");
    let base = stamped - 60_000;
    replay.clock.set_wall_ms(base);
    assert_eq!(
        replay.time.peek().base_ms,
        base,
        "the time base behind the stamp"
    );
    std::fs::remove_file(accounts_dir(&replay).join("store-id")).expect("remove store-id");
    let (service, _) = restarted(&replay, Limits::default());
    let request = apps_read(base);
    let sent = Sent::of(&request);
    let answer = service.handle(request).await;
    assert_eq!(
        (answer.status, code(&answer).as_str()),
        (503, "unavailable")
    );
    assert!(header_text(&answer, header::HEAD).is_none(), "no head");
    let time = header_text(&answer, header::SERVER_TIME).expect("server time");
    assert_eq!(
        parse_rfc3339(time).expect("time"),
        stamped,
        "the service time"
    );
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    replay.db.drop_database().await.expect("drop");
}
