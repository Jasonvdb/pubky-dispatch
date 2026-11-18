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

/// The mark a healthy answer at the head `seq` leaves, at the count and tag the account
/// holds.
async fn moved_to(replay: &Replay, old: &AccountMark, seq: u64) -> AccountMark {
    AccountMark {
        state_version: state_version_of(replay, &alice_id()).await,
        state_tag: state_tag_of(replay, &alice_id()).await,
        ..mark_at(old, seq)
    }
}

/// The mark a healthy answer at the head `seq` leaves, its count as `old`'s.
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
    assert_signed_without_head_at(replay, answer, sent, replay.time.peek().base_ms);
}

/// The answer carries no head, is signed at `time_ms` with the service key and bound to
/// `sent` (Switch wire 7.1, 7.3 under Table 2).
fn assert_signed_without_head_at(
    replay: &Replay,
    answer: &SwitchResponse,
    sent: &Sent,
    time_ms: u64,
) {
    assert!(header_text(answer, header::HEAD).is_none(), "no head");
    let time = header_text(answer, header::SERVER_TIME).expect("server time");
    assert_eq!(
        parse_rfc3339(time).expect("time"),
        time_ms,
        "Switch-Server-Time"
    );
    assert!(
        signed_with(answer, &service_public(replay), sent),
        "signed with the service key"
    );
}

/// The last time the service committed for alice, which an answer that commits nothing
/// carries (Switch wire 7.1 Timestamp).
async fn last_committed(replay: &Replay) -> u64 {
    u64::try_from(account_row(replay).await.1).expect("ms")
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
async fn test_marks_notice_to_the_public_read_binds_no_header() {
    // The public read decides nothing by its headers on the notice's path either: a read
    // signed by the signer, one with headers that decode to nothing and the unsigned read
    // get the same notice, byte for byte, bound to no header (Switch wire 7.1, 7.3, 7.4.15).
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, base) = served(&replay).await;
    let (service, _marks) = lose_mark(&replay, Limits::default()).await;
    let bare = public_read();
    let sent = Sent::of(&bare);
    let unsigned = service.handle(bare).await;
    assert_notice(&replay, &unsigned, &sent, "mark_lost", mark.generation);
    let path = format!("/v1/{}/identity", alice_id());
    let signed = service
        .handle(signer_request("GET", &path, Vec::new(), base))
        .await;
    let junk = service
        .handle(request(
            "GET",
            &path,
            &[
                (header::SIGNATURE, "junk"),
                (header::INVITE_CODE, ""),
                (header::TIMESTAMP, "never"),
            ],
            Vec::new(),
        ))
        .await;
    for answer in [&signed, &junk] {
        assert_eq!(answer.status, unsigned.status);
        assert_eq!(answer.headers, unsigned.headers);
        assert_eq!(answer.body, unsigned.body);
    }
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
    assert_eq!(
        mark_in(&replay.marks).await,
        moved_to(&replay, &mark, 4).await,
        "moved"
    );
    // The mark back at seq 2, as a move that failed after its commit leaves it.
    replay.marks.delete(&alice_id()).await.expect("delete");
    let at_two = mark_at(&mark, 2);
    replay
        .marks
        .write_anew(
            &alice_id(),
            at_head(at_two.head()),
            at_two.key,
            at_two.created_at_ms,
        )
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
    assert_eq!(
        mark_in(&replay.marks).await,
        moved_to(&replay, &mark, 4).await,
        "moved"
    );
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
        .write_anew(&alice_id(), at_head(other), mark.key, mark.created_at_ms)
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
        .advance(
            &alice_id(),
            keeping_count(&replay.marks, &alice_id(), ahead).await,
            mark.key,
            mark.created_at_ms,
        )
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
        .write_anew(&alice_id(), at_head(other), mark.key, mark.created_at_ms)
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
    // It commits nothing: at the last committed time (Switch wire 7.1 Timestamp).
    let committed = last_committed(&replay).await;
    assert_signed_without_head_at(&replay, &limited, &sent, committed);
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
    // It commits nothing: at the last committed time (Switch wire 7.1 Timestamp).
    let committed = last_committed(&replay).await;
    assert_signed_without_head_at(&replay, &limited, &sent, committed);
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
    // Refused before the body is read, by the transport: no verdict is judged, and the
    // answer binds the empty body field (Switch wire 7.1).
    assert_eq!((answer.status, code(&answer).as_str()), (413, "too_large"));
    assert_signed_without_head(&replay, &answer, &sent.clone().unread());
    assert!(!signed_with(&answer, &service_public(&replay), &sent));
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
    assert_eq!(
        mark_in(&marks).await,
        moved_to(&replay, &mark, 4).await,
        "moved"
    );
    assert_eq!(service.mark_refusals(), 0);
    replay.db.drop_database().await.expect("drop");
}

/// alice's wallet's batch of no operation that moves its cursor to `seq` of generation 1,
/// at `at_ms`: a cursor sync, which takes no `seq` (Switch wire 6.2, spec 8.3).
fn cursor_sync(seq: u64, at_ms: u64) -> SwitchRequest {
    let keys = vectors("keys.json");
    let position = pubky_switch_core::ops::Position { generation: 1, seq };
    app_request(
        app(&keys, "wallet"),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        OpsRequest::new(&[], Some(position)).to_json(),
        at_ms,
    )
}

/// alice served, and her wallet's first call made: the batch of `chain.json` seqs 3 and 4,
/// which moves no cursor. Her mark, and the time to sign the next calls at.
async fn wallet_in(replay: &Replay) -> (AccountMark, u64) {
    served(replay).await;
    let answer = Box::pin(replay.service.handle(wallet_batch(replay, &[3, 4]))).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    (mark_in(&replay.marks).await, time_of(3))
}

/// alice's wallet's cursor, as SQL values.
async fn wallet_cursor(replay: &Replay) -> (String, String) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let (generation, seq): (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT cursor_generation, cursor_seq FROM apps WHERE account_id = $1 AND app_id = $2",
    )
    .bind(alice_id())
    .bind(app_id_of("wallet").as_slice())
    .fetch_one(&mut conn)
    .await
    .expect("cursor");
    conn.close().await.expect("close");
    let text = |value: Option<i64>| value.map_or("NULL".to_string(), |value| value.to_string());
    (text(generation), text(seq))
}

/// alice's account's count and her mark's.
async fn counts(replay: &Replay, marks: &MarkStore) -> (u64, u64) {
    (
        state_version_of(replay, &alice_id()).await,
        mark_in(marks).await.state_version,
    )
}

#[tokio::test]
async fn test_marks_cursor_sync_lost_to_a_restore_is_behind_the_mark() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, base) = wallet_in(&replay).await;
    let count = state_version_of(&replay, &alice_id()).await;
    assert_eq!(
        mark.state_version, count,
        "the mark covers every commit so far"
    );
    let (generation, seq) = wallet_cursor(&replay).await;
    let answer = Box::pin(replay.service.handle(cursor_sync(4, base))).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // The cursor moved, which counts, and the mark covers it, its head unchanged.
    assert_ne!(
        wallet_cursor(&replay).await,
        (generation.clone(), seq.clone())
    );
    assert_eq!(counts(&replay, &replay.marks).await, (count + 1, count + 1));
    assert_eq!(mark_in(&replay.marks).await.head(), mark.head());
    // A restore that loses only the cursor sync: the account is behind its mark.
    sql(
        &replay,
        &[
            &format!("UPDATE apps SET cursor_generation = {generation}, cursor_seq = {seq}"),
            &format!("UPDATE accounts SET state_version = {count}"),
        ],
    )
    .await;
    let request = apps_read(base);
    let sent = Sent::of(&request);
    let answer = Box::pin(replay.service.handle(request)).await;
    assert_notice(&replay, &answer, &sent, "behind", mark.generation);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_refused_request_counts_nothing() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, _) = served(&replay).await;
    let count = state_version_of(&replay, &alice_id()).await;
    // A batch that skips a `seq`: refused, and what its endpoint wrote is undone.
    let refused = Box::pin(replay.service.handle(wallet_batch(&replay, &[4]))).await;
    assert!(refused.status >= 400, "{}", refused.status);
    assert_eq!(counts(&replay, &replay.marks).await, (count, count));
    assert_eq!(mark_in(&replay.marks).await, mark, "the mark unchanged");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_crash_between_a_counted_commit_and_its_mark_move_fails_closed() {
    let Some(replay) = replay().await else {
        return;
    };
    let (mark, base) = wallet_in(&replay).await;
    let count = state_version_of(&replay, &alice_id()).await;
    // The commit of a cursor sync holds and the mark can't move: the answer isn't released
    // (Switch wire 7.3, "Moving it").
    let marks_dir = accounts_dir(&replay).join("marks");
    std::fs::set_permissions(&marks_dir, std::fs::Permissions::from_mode(0o500))
        .expect("read-only");
    let request = cursor_sync(3, base);
    let sent = Sent::of(&request);
    let answer = Box::pin(replay.service.handle(request)).await;
    std::fs::set_permissions(&marks_dir, std::fs::Permissions::from_mode(0o700)).expect("writable");
    assert_eq!(
        (answer.status, code(&answer).as_str()),
        (503, "unavailable")
    );
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    assert!(
        header_text(&answer, header::HEAD).is_none(),
        "nothing acknowledged"
    );
    assert_eq!(counts(&replay, &replay.marks).await, (count + 1, count));
    // A restart in that state: the state is ahead of the mark, a higher count with a tag of
    // its own, which Table 1 judges healthy, neither behind nor a fork. The app's retry is
    // answered as a retry, once the mark has moved to the committed count; nothing is
    // acknowledged before the mark catches up.
    let (service, marks) = restarted(&replay, Limits::default());
    let retry = Box::pin(service.handle(cursor_sync(3, base))).await;
    assert_eq!(
        retry.status,
        200,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    assert!(header_text(&retry, header::HEAD).is_some(), "the head");
    assert_eq!(counts(&replay, &marks).await, (count + 1, count + 1));
    assert_eq!(
        mark_in(&marks).await.state_tag,
        state_tag_of(&replay, &alice_id()).await
    );
    let read = Box::pin(service.handle(apps_read(base))).await;
    assert_eq!(read.status, 200, "{}", String::from_utf8_lossy(&read.body));
    assert_eq!(counts(&replay, &marks).await, (count + 1, count + 1));
    let next = Box::pin(service.handle(cursor_sync(4, base))).await;
    assert_eq!(next.status, 200, "{}", String::from_utf8_lossy(&next.body));
    assert_eq!(counts(&replay, &marks).await, (count + 2, count + 2));
    assert_eq!(mark_in(&marks).await.head(), mark.head());
    assert_eq!(service.mark_refusals(), 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_crash_after_the_mark_move_before_the_answer_is_healthy() {
    let Some(replay) = replay().await else {
        return;
    };
    let (_, base) = wallet_in(&replay).await;
    let count = state_version_of(&replay, &alice_id()).await;
    // The cursor sync commits and its mark moves; the process dies before the answer is
    // released: the mark is at the committed count by then (Switch wire 7.3, "Moving it").
    let pause = replay.service.pause_next_release();
    let mut handling = Box::pin(replay.service.handle(cursor_sync(4, base)));
    tokio::select! {
        answer = &mut handling => panic!("released before the pause: {}", answer.status),
        () = pause.reached() => {}
    }
    assert_eq!(
        counts(&replay, &replay.marks).await,
        (count + 1, count + 1),
        "the mark at the state before the answer goes out"
    );
    drop(handling);
    // A restart: healthy, and the app's retry is answered, changing nothing.
    let (service, marks) = restarted(&replay, Limits::default());
    let retry = Box::pin(service.handle(cursor_sync(4, base))).await;
    assert_eq!(
        retry.status,
        200,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    assert_eq!(counts(&replay, &marks).await, (count + 1, count + 1));
    let read = Box::pin(service.handle(apps_read(base))).await;
    assert_eq!(read.status, 200, "{}", String::from_utf8_lossy(&read.body));
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
    assert_eq!(
        mark_in(&replay.marks).await,
        moved_to(&replay, &mark, 4).await,
        "moved"
    );
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
    assert_eq!(
        mark_in(&replay.marks).await,
        moved_to(&replay, &mark, 4).await,
        "moved"
    );
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
        // Table 2), which commits nothing: at the last committed time (Switch wire 7.1
        // Timestamp).
        assert_eq!(
            (answer.status, code(&answer).as_str()),
            (503, "unavailable")
        );
        let committed = last_committed(&replay).await;
        assert_ne!(committed, replay.time.peek().base_ms, "not the time base");
        assert_signed_without_head_at(&replay, &answer, &sent, committed);
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
        // Bound to the request as received, its method and path among it (7.1).
        let elsewhere = sent.clone().at_path(format!("/v1/{}/other", bob_id()));
        assert!(!signed_with(&answer, &service_public(&replay), &elsewhere));
        let other_method = sent.with_method("POST");
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
    let sent = Sent::unrouted("GET", path);
    let answer = replay
        .service
        .refuse(Refusal::UnknownRoute {
            method: "GET".into(),
            path_and_query: path.into(),
            headers: HeaderMap::new(),
            body: Default::default(),
        })
        .await;
    // Step 1: an unknown route is `404`, signed with the service key (Switch wire 7.3).
    assert_eq!((answer.status, code(&answer).as_str()), (404, "not_found"));
    assert_signed_without_head(&replay, &answer, &sent);
    let elsewhere = sent.at_path("/v2/another/route".into());
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
        .write_anew(&alice_id(), at_head(other), mark.key, mark.created_at_ms)
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

/// The `Switch-Server-Time` of `answer`, in Unix milliseconds.
fn time_shown(answer: &SwitchResponse) -> u64 {
    ms(header_text(answer, header::SERVER_TIME).expect("Switch-Server-Time"))
}

#[tokio::test]
async fn test_marks_answers_that_commit_nothing_never_run_ahead_of_the_next_commit() {
    // An answer that commits nothing carries the last time the service committed for the
    // identity, never the identity's service time of the moment: so once the wall clock goes
    // back, within the 5 minutes the time base follows it, the next commit stamps no time
    // earlier than one an answer already showed (Switch wire 7.1 Timestamp, spec 10.1).
    let Some(replay) = replay().await else {
        return;
    };
    let (_, base) = served(&replay).await;
    let committed = replay.service.handle(apps_read(base)).await;
    assert_eq!(committed.status, 200);
    let last_committed = time_shown(&committed);
    let ahead = base + 240_000;
    replay.clock.set_wall_ms(ahead);
    assert_eq!(replay.time.peek().base_ms, ahead, "the time base");
    let mut shown = Vec::new();
    // Refused before the lock: a request signature that doesn't verify, a stale timestamp.
    for (request, code_of) in [
        (bad_signature(apps_read(ahead)), "bad_signature"),
        (apps_read(ahead - 301_000), "stale_timestamp"),
    ] {
        let answer = replay.service.handle(request).await;
        assert_eq!(code(&answer), code_of);
        shown.push((code_of, time_shown(&answer)));
    }
    // A `429` before authentication, at a hosted account.
    let (limited, _) = restarted(
        &replay,
        Limits {
            auth_failures_per_source_per_min: 1,
            ..Limits::default()
        },
    );
    let source = "203.0.113.9";
    let failed = limited
        .handle(from_source(bad_signature(apps_read(ahead)), source))
        .await;
    assert_eq!(code(&failed), "bad_signature");
    let answer = limited.handle(from_source(apps_read(ahead), source)).await;
    assert_eq!(code(&answer), "rate_limited");
    shown.push(("rate_limited", time_shown(&answer)));
    // The `503` of a mark store that can't be read, to a call and to an enrollment.
    let store_id = accounts_dir(&replay).join("store-id");
    let id = std::fs::read(&store_id).expect("store-id");
    std::fs::remove_file(&store_id).expect("remove store-id");
    let (unread, _) = restarted(&replay, Limits::default());
    let http = vectors("http.json");
    let enrollment = named(&http["requests"], "signer: enrollment");
    let enrollment_body =
        pubky_switch_core::enc::unb64(enrollment["body_b64"].as_str().expect("body")).expect("b64");
    for (request, what) in [
        (apps_read(ahead), "a call"),
        (
            signer_request("POST", "/v1/enroll", enrollment_body, ahead),
            "an enrollment",
        ),
    ] {
        let answer = unread.handle(request).await;
        assert_eq!(code(&answer), "unavailable", "{what}");
        shown.push((what, time_shown(&answer)));
    }
    std::fs::write(&store_id, id).expect("restore store-id");
    for (what, at) in &shown {
        assert_eq!(*at, last_committed, "{what}: the last committed time");
    }
    assert_eq!(
        account_row(&replay).await.1,
        i64::try_from(last_committed).expect("ms")
    );
    // The wall clock back by two minutes: the next commit stamps the time base, earlier than
    // the time those answers would have shown had they carried the time of the moment, and
    // no earlier than any they showed.
    let back = ahead - 120_000;
    replay.clock.set_wall_ms(back);
    assert_eq!(replay.time.peek().base_ms, back, "the time base went back");
    let next = replay.service.handle(apps_read(back)).await;
    assert_eq!(next.status, 200);
    let stamped = time_shown(&next);
    assert_eq!(stamped, back);
    for (what, at) in &shown {
        assert!(*at <= stamped, "{what}: {at} shown, {stamped} stamped next");
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_lost_identity_over_its_source_limit_gets_the_notice() {
    // An identity the service holds no account for has no committed time, so every answer
    // to it counts in no comparison of service times: at a lost identity the notice, at the
    // time base, answers in place of a `429` before authentication too, with no signature
    // work (Switch wire 7.1 Timestamp, 7.3 under Table 2, 9.4).
    let limits = Limits {
        auth_failures_per_source_per_min: 1,
        identity_reads_per_source_per_min: 1,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    let head = ChainTip {
        generation: 1,
        seq: 2,
        chain_hash: [7; 32],
    };
    replay
        .marks
        .write_anew(
            &alice_id(),
            at_head(head),
            service_public(&replay),
            time_of(1),
        )
        .await
        .expect("mark");
    let base = time_of(2) + 60_000;
    replay.clock.set_wall_ms(base);
    let source = "203.0.113.21";
    let request = from_source(bad_signature(apps_read(base)), source);
    let sent = Sent::of(&request);
    let answer = replay.service.handle(request).await;
    assert_notice(&replay, &answer, &sent, "behind", 1);
    let claimed = (alice_id(), alice_id(), None);
    assert_eq!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, base),
        1,
        "the replaced 401 counted"
    );
    // The source's limit reached: the notice, not a `429`, and no signature checked.
    for request in [
        bad_signature(apps_read(base)),
        apps_read(base),
        public_read(),
        public_read(),
    ] {
        let request = from_source(request, source);
        let sent = Sent::of(&request);
        let answer = replay.service.handle(request).await;
        assert_notice(&replay, &answer, &sent, "behind", 1);
    }
    assert_eq!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, base),
        1,
        "nothing verified past the limit"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_failed_account_lookup_answers_unavailable_at_the_time_base() {
    // A database that fails when the account is looked up: a `503 unavailable` before any
    // committed time is known, at the time base, which counts in no comparison of service
    // times like every `503 unavailable` (Switch wire 7.1 Timestamp, 7.3 step 2).
    let Some(replay) = replay().await else {
        return;
    };
    let (_, base) = served(&replay).await;
    let committed = last_committed(&replay).await;
    assert_ne!(
        committed, base,
        "the time base differs from the committed time"
    );
    sql(&replay, &["ALTER TABLE accounts RENAME TO accounts_away"]).await;
    let request = apps_read(base);
    let sent = Sent::of(&request);
    let answer = replay.service.handle(request).await;
    sql(&replay, &["ALTER TABLE accounts_away RENAME TO accounts"]).await;
    assert_eq!(
        (answer.status, code(&answer).as_str()),
        (503, "unavailable")
    );
    assert_signed_without_head_at(&replay, &answer, &sent, base);
    // Looked up again, the account answers as before.
    let answer = replay.service.handle(apps_read(base)).await;
    assert_eq!(answer.status, 200);
    replay.db.drop_database().await.expect("drop");
}

// A lost individual file is judged while the original store and service remain open.
async fn live_record_loss(corrupt: bool, write: bool) {
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let identity = alice_id();
    let path = replay.key_dir().join("accounts/marks").join(&identity);
    let held = replay.marks.read(&identity).await.expect("held mark");
    assert!(matches!(held, MarkRead::Mark(_)));
    let stamp = ms(&item_time(chain_item(&vectors("chain.json"), 3)));
    replay.clock.set_wall_ms(stamp);
    if corrupt {
        std::fs::write(&path, b"not a mark").expect("corrupt");
    } else {
        std::fs::remove_file(&path).expect("remove");
    }
    let keys = vectors("keys.json");
    let request = if write {
        app_request(
            app(&keys, "wallet"),
            "POST",
            &format!("/v1/{identity}/ops"),
            OpsRequest::new(&ops_at(&vectors("chain.json"), &[3, 4]), None).to_json(),
            stamp,
        )
    } else {
        signer_request("GET", &format!("/v1/{identity}/apps"), Vec::new(), stamp)
    };
    let sent = Sent::of(&request);
    let answer = Box::pin(replay.service.handle(request)).await;
    let read = replay.marks.read(&identity).await.expect("live mark");
    let verified = signed_with(&answer, &service_public(&replay), &sent);
    replay.db.drop_database().await.expect("drop");
    let value: Value = serde_json::from_slice(&answer.body).expect("body");
    assert_eq!(
        (answer.status, value["code"].clone()),
        (503, json!("recovery_required"))
    );
    assert_eq!(value["current"]["reason"], "mark_lost");
    assert!(header_text(&answer, header::HEAD).is_none());
    assert!(verified);
    assert_eq!(
        read,
        if corrupt {
            MarkRead::NotAMark
        } else {
            MarkRead::Missing
        }
    );
}

#[tokio::test]
async fn test_marks_live_missing_record_refuses_a_read() {
    live_record_loss(false, false).await;
}
#[tokio::test]
async fn test_marks_live_corrupt_record_refuses_a_read() {
    live_record_loss(true, false).await;
}
#[tokio::test]
async fn test_marks_live_missing_record_refuses_a_write() {
    live_record_loss(false, true).await;
}
#[tokio::test]
async fn test_marks_live_corrupt_record_refuses_a_write() {
    live_record_loss(true, true).await;
}

#[tokio::test]
async fn test_marks_verdict_reads_the_selected_retirement() {
    let Some(replay) = replay().await else { return };
    let (_, base) = served(&replay).await;
    let identity = alice_id();
    replay
        .marks
        .retire(&identity, 2)
        .await
        .expect("other generation");
    let retired_dir = accounts_dir(&replay).join("retired");
    std::fs::write(retired_dir.join(format!("{identity}.2")), b"invalid")
        .expect("other generation corrupt");
    let request = apps_read(base);
    let sent = Sent::of(&request);
    let answer = Box::pin(replay.service.handle(request)).await;
    assert_eq!(answer.status, 200, "an unselected generation is not read");
    assert!(header_text(&answer, header::HEAD).is_some());
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    replay
        .marks
        .retire(&identity, 1)
        .await
        .expect("selected generation");
    for lose_mark in [false, true] {
        if lose_mark {
            std::fs::remove_file(mark_file(&replay)).expect("lose mark");
        }
        let answer = Box::pin(replay.service.handle(apps_read(base))).await;
        assert_eq!(
            (answer.status, code(&answer).as_str()),
            (503, "recovery_required")
        );
        assert_eq!(
            body(&answer)["current"]["permanent"],
            true,
            "mark generation or account generation"
        );
    }
    std::fs::write(retired_dir.join(format!("{identity}.1")), b"invalid")
        .expect("selected generation corrupt");
    let request = apps_read(base);
    let sent = Sent::of(&request);
    let answer = Box::pin(replay.service.handle(request)).await;
    assert_eq!(
        (answer.status, code(&answer).as_str()),
        (503, "unavailable")
    );
    assert_signed_without_head_at(&replay, &answer, &sent, base);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_marks_unrelated_erasure_loss_leaves_account_serving() {
    let Some(replay) = replay().await else { return };
    let (_, base) = served(&replay).await;
    replay
        .marks
        .record_erasure(&bob_id(), 100)
        .await
        .expect("other account erasure");
    std::fs::remove_file(accounts_dir(&replay).join("erasures").join(bob_id()))
        .expect("lose other record");
    let request = apps_read(base);
    let sent = Sent::of(&request);
    let answer = Box::pin(replay.service.handle(request)).await;
    assert_eq!(answer.status, 200);
    assert!(header_text(&answer, header::HEAD).is_some());
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    let request = wallet_batch(&replay, &[3, 4]);
    let sent = Sent::of(&request);
    let answer = Box::pin(replay.service.handle(request)).await;
    assert_eq!(answer.status, 200);
    assert!(header_text(&answer, header::HEAD).is_some());
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    assert!(
        replay.marks.erasures().await.is_err(),
        "aggregate checks every record"
    );
    replay.db.drop_database().await.expect("drop");
}
