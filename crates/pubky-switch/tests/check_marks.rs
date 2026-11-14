//! The operator's check of every account and every mark without one, against PostgreSQL:
//! each state of the service's verdict, the summary, reading only, and a replica's verdict
//! (Switch spec 6.5, Switch wire 7.3 "Accounts and marks", Table 1).
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// A test fails on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::{
    fs,
    path::{Path, PathBuf},
};

use pubky_switch::{
    check_marks::{self, AccountReport, CheckOptions, DatabaseChoice, MarkState, Report},
    http::Handler,
    keys::KeyStore,
    marks::{AccountMark, Advance, MarkRead},
    store::{NewAccount, heads::open_read_only_with, testing::TestDatabase},
};
use pubky_switch_core::{
    chain::ChainTip,
    keys::IdentityKey,
    records::{IdentityBody, IdentityDoc, IdentityPolicy, Inbox},
};
use sqlx::Connection;
use support::*;

const T0: u64 = 1_767_225_600_000;

/// alice's Pubky ID.
fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

/// Account `id`, created at `T0`; serving when its enrollment's `identity.json` names this
/// service's origin and `service_key`.
fn new_account(id: &str, service_key: [u8; 32], serving: bool) -> NewAccount {
    let identity = IdentityKey::from_secret([7; 32]);
    let doc = serving.then(|| {
        let body = IdentityBody::first(
            identity.public(),
            [4; 16],
            Inbox::new(ORIGIN, service_key),
            IdentityPolicy::default(),
        );
        IdentityDoc::sign(&identity, body)
            .expect("sign")
            .signed()
            .clone()
    });
    NewAccount {
        id: id.into(),
        identity_key: identity.public(),
        generation: 1,
        created_at_ms: T0,
        limits: pubky_switch_core::records::Limits::default(),
        identity_doc: doc,
        revoked_apps: Vec::new(),
        enrollment_hash: [0; 32],
    }
}

/// Create account `id` in `replay`'s store, with its (0, 0) mark, as an enrollment makes
/// them (Switch wire 7.3, Table 3).
async fn create(replay: &Replay, id: &str, serving: bool) -> NewAccount {
    let account = new_account(id, service_public(replay), serving);
    assert!(
        replay
            .db
            .store()
            .create_account(&account)
            .await
            .expect("create")
    );
    replay
        .marks
        .create_zero(id, service_public(replay), T0)
        .await
        .expect("mark");
    account
}

/// Append one chain item per hash to account `id` in `db`, moving the mark to each head
/// after its commit when `replay` is given (Switch wire 7.3, "Moving it").
async fn append(db: &TestDatabase, replay: Option<&Replay>, id: &str, hashes: &[u8]) {
    for hash in hashes {
        let mut txn = db.store().begin(id).await.expect("begin").expect("account");
        let seq = txn.next_seq().expect("seq");
        txn.set_chain_head(seq, [*hash; 32]).expect("head");
        let committed = txn.commit().await.expect("commit");
        if let Some(replay) = replay {
            let head = committed.head().chain_tip();
            let moved = replay
                .marks
                .advance(id, head, service_public(replay))
                .await
                .expect("advance");
            assert!(matches!(moved, Advance::Moved(_)), "{moved:?}");
        }
    }
}

/// Move `id`'s mark to `(generation, seq)` with chain hash `[hash; 32]`, as a head the
/// database then lost.
async fn mark_at(replay: &Replay, id: &str, generation: u64, seq: u64, hash: u8) {
    let head = ChainTip {
        generation,
        seq,
        chain_hash: [hash; 32],
    };
    let moved = replay
        .marks
        .advance(id, head, service_public(replay))
        .await
        .expect("advance");
    assert!(matches!(moved, Advance::Moved(_)), "{moved:?}");
}

/// `id`'s mark.
async fn mark_of(replay: &Replay, id: &str) -> AccountMark {
    match replay.marks.read(id).await.expect("read") {
        MarkRead::Mark(mark) => mark,
        other => panic!("no mark: {other:?}"),
    }
}

/// Write `id`'s mark anew at `(generation, seq)` with chain hash `[hash; 32]`: another
/// history at the same position.
async fn mark_anew(replay: &Replay, id: &str, generation: u64, seq: u64, hash: u8) {
    let created = mark_of(replay, id).await.created_at_ms;
    replay.marks.delete(id).await.expect("delete");
    let head = ChainTip {
        generation,
        seq,
        chain_hash: [hash; 32],
    };
    replay
        .marks
        .write_anew(id, head, service_public(replay), created)
        .await
        .expect("write anew");
}

fn options(db: &TestDatabase, key_dir: &Path, all: bool) -> CheckOptions {
    CheckOptions {
        database: db.options().clone(),
        choice: DatabaseChoice::Configured,
        key_dir: key_dir.to_path_buf(),
        origin: ORIGIN.into(),
        all,
    }
}

async fn check(replay: &Replay, all: bool) -> Report {
    check_marks::run(&options(&replay.db, replay.key_dir(), all))
        .await
        .expect("check")
}

fn find<'a>(accounts: &'a [AccountReport], id: &str) -> &'a AccountReport {
    accounts
        .iter()
        .find(|account| account.account == id)
        .expect("a line for the account")
}

/// Run `sql` on a connection that may write, as the service or a restore would.
async fn write(db: &TestDatabase, sql: &str) {
    let mut conn = sqlx::PgConnection::connect_with(db.options())
        .await
        .expect("connect");
    sqlx::raw_sql(sql).execute(&mut conn).await.expect("write");
    conn.close().await.expect("close");
}

#[tokio::test]
async fn test_check_marks_serving_account_is_healthy() {
    // alice enrolled and given two identity.json versions: her mark moved with each head.
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let report = check(&replay, true).await;
    let line = find(&report.accounts, &alice_id());
    assert_eq!(
        (
            line.state,
            line.hosted,
            line.serving,
            line.head_seq,
            line.mark_seq
        ),
        (MarkState::Healthy, true, true, Some(2), Some(2))
    );
    assert_eq!((line.generation, line.permanent), (None, false));
    assert_eq!(report.summary.accounts, 1);
    assert_eq!(report.summary.serving, 1);
    assert_eq!(report.summary.needs_attention, 0);
    assert!(!report.needs_attention());

    // Without `all`, nothing to report: the summary alone.
    let report = check(&replay, false).await;
    assert!(report.accounts.is_empty());
    let text = report.to_json_lines().expect("encode");
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with("{\"summary\":"), "{text}");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_check_marks_reports_behind_fork_and_mark_lost() {
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let alice = alice_id();

    // The mark past the state: the database is older than what the service signed.
    mark_at(&replay, &alice, 1, 4, 4).await;
    let report = check(&replay, false).await;
    let line = find(&report.accounts, &alice);
    assert_eq!(
        (line.state, line.head_seq, line.mark_seq, line.generation),
        (MarkState::Behind, Some(2), Some(4), Some(1))
    );
    assert!(!line.permanent);
    assert!(report.needs_attention());

    // Another history at the state's own position.
    mark_anew(&replay, &alice, 1, 2, 9).await;
    let report = check(&replay, false).await;
    let line = find(&report.accounts, &alice);
    assert_eq!(
        (line.state, line.head_seq, line.mark_seq, line.generation),
        (MarkState::Fork, Some(2), Some(2), Some(1))
    );

    // The mark file gone.
    fs::remove_file(replay.key_dir().join("accounts/marks").join(&alice)).expect("remove");
    let report = check(&replay, false).await;
    let line = find(&report.accounts, &alice);
    assert_eq!(
        (line.state, line.serving, line.head_seq, line.mark_seq),
        (MarkState::MarkLost, true, Some(2), None)
    );
    assert_eq!(report.summary.states[&MarkState::MarkLost], 1);
    assert_eq!(report.summary.needs_attention, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_check_marks_reports_a_fork_past_the_mark() {
    // The state is past the mark in its generation and the stub it holds at the mark's seq
    // has another chain hash: a fork, as the service judges it (Switch wire 7.3, Table 1).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let alice = alice_id();
    mark_anew(&replay, &alice, 1, 1, 9).await;
    let at = ms(&item_time(&vectors("chain.json")["items"][1]));
    let answer = replay
        .service
        .handle(signer_request(
            "GET",
            &format!("/v1/{alice}/allow"),
            Vec::new(),
            at,
        ))
        .await;
    assert_eq!(answer.status, 503);
    let body: serde_json::Value = serde_json::from_slice(&answer.body).expect("json");
    assert_eq!(body["current"]["reason"], "fork", "{body}");

    let report = check(&replay, false).await;
    let line = find(&report.accounts, &alice);
    assert_eq!(
        (line.state, line.head_seq, line.mark_seq),
        (MarkState::Fork, Some(2), Some(1))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_check_marks_reports_marks_without_an_account() {
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let alice = alice_id();
    // A (0, 0) mark without an account is no account: nothing to report.
    replay
        .marks
        .create_zero("zero", service_public(&replay), T0)
        .await
        .expect("mark");
    // alice's account gone, as a restore from before her enrollment leaves it.
    write(
        &replay.db,
        &format!("DELETE FROM accounts WHERE id = '{alice}'"),
    )
    .await;
    let report = check(&replay, true).await;
    assert_eq!(report.accounts.len(), 1, "{:?}", report.accounts);
    let line = find(&report.accounts, &alice);
    assert_eq!(
        (
            line.state,
            line.hosted,
            line.serving,
            line.head_seq,
            line.mark_seq
        ),
        (MarkState::Lost, false, false, None, Some(2))
    );
    assert_eq!((line.generation, line.permanent), (Some(1), false));
    assert_eq!(report.summary.accounts, 0);
    assert_eq!(report.summary.needs_attention, 1);

    // An erasure recorded before the mark was created belongs to an earlier account: still
    // lost.
    let created = mark_of(&replay, &alice).await.created_at_ms;
    assert!(created > 0, "the mark's creation time");
    replay
        .keys
        .record_erasure(&alice, created - 1)
        .await
        .expect("record");
    let report = check(&replay, false).await;
    assert_eq!(find(&report.accounts, &alice).state, MarkState::Lost);

    // Recorded at the mark's creation: the mark is the erasure's leftover.
    replay
        .keys
        .record_erasure(&alice, created)
        .await
        .expect("record");
    let report = check(&replay, false).await;
    let line = find(&report.accounts, &alice);
    assert_eq!(
        (line.state, line.hosted, line.mark_seq, line.generation),
        (MarkState::Leftover, false, Some(2), None)
    );
    assert_eq!(report.summary.states[&MarkState::Leftover], 1);
    assert_eq!(report.summary.states[&MarkState::Lost], 0);
    assert!(report.needs_attention());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_check_marks_reports_an_account_created_by_an_erasure_record() {
    let Some(replay) = replay().await else { return };
    create(&replay, "renewed", true).await;
    append(&replay.db, Some(&replay), "renewed", &[1]).await;
    // A record before the account's creation is an earlier account's.
    replay
        .keys
        .record_erasure("renewed", T0 - 1)
        .await
        .expect("record");
    let report = check(&replay, true).await;
    assert_eq!(find(&report.accounts, "renewed").state, MarkState::Healthy);
    // A record at the account's creation: a restore brought it back.
    replay
        .keys
        .record_erasure("renewed", T0)
        .await
        .expect("record");
    let report = check(&replay, true).await;
    let line = find(&report.accounts, "renewed");
    assert_eq!(
        (line.state, line.hosted, line.head_seq, line.mark_seq),
        (MarkState::ErasedAgain, true, Some(1), Some(1))
    );
    assert_eq!(report.summary.needs_attention, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_check_marks_summary_and_exit_status() {
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    // Enrolled, no document naming this service yet, its mark at (0, 0).
    create(&replay, "staged", false).await;
    // Healthy and staged need no operator: the check exits 0.
    let report = check(&replay, true).await;
    assert_eq!(find(&report.accounts, "staged").state, MarkState::Staged);
    assert!(!report.needs_attention());
    assert_eq!(report.summary.needs_attention, 0);

    // Staged holding no chain, its mark recording a head.
    create(&replay, "bounded", false).await;
    mark_at(&replay, "bounded", 1, 1, 1).await;
    create(&replay, "behind", true).await;
    append(&replay.db, Some(&replay), "behind", &[1]).await;
    mark_at(&replay, "behind", 1, 3, 3).await;
    // A mark recording a head, with no account.
    replay
        .marks
        .create_zero("lost", service_public(&replay), T0)
        .await
        .expect("mark");
    mark_at(&replay, "lost", 1, 1, 1).await;

    let report = check(&replay, true).await;
    assert_eq!(report.accounts.len(), 5);
    assert_eq!(find(&report.accounts, "bounded").state, MarkState::Bounded);
    let summary = &report.summary;
    assert_eq!(summary.database, DatabaseChoice::Configured);
    assert_eq!(summary.accounts, 4);
    assert_eq!(summary.serving, 2);
    assert_eq!(summary.needs_attention, 3);
    for (state, count) in [
        (MarkState::Healthy, 1),
        (MarkState::Staged, 1),
        (MarkState::Bounded, 1),
        (MarkState::Behind, 1),
        (MarkState::Lost, 1),
        (MarkState::Fork, 0),
        (MarkState::MarkLost, 0),
        (MarkState::Leftover, 0),
        (MarkState::ErasedAgain, 0),
    ] {
        assert_eq!(summary.states[&state], count, "{state:?}");
    }
    // The check exits 2.
    assert!(report.needs_attention());

    // Without `all`: the accounts that need attention in the order of their IDs, then the
    // marks without one; the summary still counts every line.
    let report = check(&replay, false).await;
    let ids: Vec<&str> = report
        .accounts
        .iter()
        .map(|line| line.account.as_str())
        .collect();
    assert_eq!(ids, ["behind", "bounded", "lost"]);
    assert_eq!(report.summary.accounts, 4);
    let text = report.to_json_lines().expect("encode");
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("json"))
        .collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(
        lines[0],
        serde_json::json!({
            "account": "behind", "hosted": true, "serving": true, "state": "behind",
            "generation": 1, "permanent": false, "head_seq": 1, "mark_seq": 3
        })
    );
    assert_eq!(lines[3]["summary"]["needs_attention"], 3);
    assert_eq!(lines[3]["summary"]["states"]["lost"], 1);
    replay.db.drop_database().await.expect("drop");
}

/// Every file under `dir`, with its content.
fn listing(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut all = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(&next).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                all.push((path.clone(), Vec::new()));
                stack.push(path);
            } else {
                let bytes = fs::read(&path).expect("read");
                all.push((path, bytes));
            }
        }
    }
    all.sort();
    all
}

/// The accounts table, as text.
async fn accounts_digest(db: &TestDatabase) -> String {
    let mut conn = sqlx::PgConnection::connect_with(db.options())
        .await
        .expect("connect");
    let digest = sqlx::query_scalar(
        "SELECT coalesce(md5(string_agg(a::text, '|' ORDER BY a.id)), '') FROM accounts a",
    )
    .fetch_one(&mut conn)
    .await
    .expect("digest");
    conn.close().await.expect("close");
    digest
}

#[tokio::test]
async fn test_check_marks_reads_only() {
    // The service deletes a leftover and erases an account again at a request or at start;
    // the check reports them and changes nothing.
    let Some(replay) = replay().await else { return };
    let dir = replay.key_dir();
    create(&replay, "behind", true).await;
    append(&replay.db, Some(&replay), "behind", &[1]).await;
    mark_at(&replay, "behind", 1, 3, 3).await;
    create(&replay, "erased", true).await;
    replay
        .keys
        .record_erasure("erased", T0)
        .await
        .expect("record");
    replay
        .marks
        .create_zero("leftover", service_public(&replay), T0)
        .await
        .expect("mark");
    replay
        .keys
        .record_erasure("leftover", T0)
        .await
        .expect("record");

    let files = listing(dir);
    let digest = accounts_digest(&replay.db).await;
    let report = check(&replay, true).await;
    assert_eq!(report.summary.needs_attention, 3);
    assert_eq!(
        find(&report.accounts, "erased").state,
        MarkState::ErasedAgain
    );
    assert_eq!(
        find(&report.accounts, "leftover").state,
        MarkState::Leftover
    );
    assert_eq!(listing(dir), files, "the key directory is unchanged");
    assert_eq!(
        accounts_digest(&replay.db).await,
        digest,
        "the database is unchanged"
    );

    // The check's session refuses writes.
    let mut conn = open_read_only_with(replay.db.options())
        .await
        .expect("connect");
    let refused = sqlx::query("UPDATE accounts SET generation = generation")
        .execute(&mut conn)
        .await
        .expect_err("read only");
    let code = refused
        .as_database_error()
        .and_then(|error| error.code())
        .map(|code| code.to_string());
    assert_eq!(code.as_deref(), Some("25006"), "{refused}");
    conn.close().await.expect("close");

    // A key directory that isn't there fails the check, and nothing is made.
    let absent = dir.join("absent");
    let error = check_marks::run(&options(&replay.db, &absent, true))
        .await
        .expect_err("no key store");
    assert!(matches!(error, check_marks::CheckError::Keys(_)), "{error}");
    assert!(!absent.exists());
    assert_eq!(listing(dir), files);

    // A mark store that can't be read fails the check: no verdict without the marks.
    fs::remove_file(dir.join("accounts/store-id")).expect("remove");
    let files = listing(dir);
    let error = check_marks::run(&options(&replay.db, dir, true))
        .await
        .expect_err("no mark store");
    assert!(
        matches!(error, check_marks::CheckError::Marks(_)),
        "{error}"
    );
    assert_eq!(listing(dir), files);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_check_marks_replica_gives_its_own_verdict() {
    let Some(replay) = replay().await else { return };
    let Some(replica) = pubky_switch::store::testing::test_database().await else {
        return;
    };
    // The configured database holds three chain items the mark covers; the replica, the
    // same account with the first only, as a lagging standby would.
    let account = create(&replay, "lagging", true).await;
    append(&replay.db, Some(&replay), "lagging", &[1, 2, 3]).await;
    assert!(
        replica
            .store()
            .create_account(&account)
            .await
            .expect("create")
    );
    append(&replica, None, "lagging", &[1]).await;

    let configured = check(&replay, true).await;
    assert_eq!(configured.summary.database, DatabaseChoice::Configured);
    assert_eq!(
        find(&configured.accounts, "lagging").state,
        MarkState::Healthy
    );
    assert!(!configured.needs_attention());

    let on_replica = check_marks::run(&CheckOptions {
        database: replica.options().clone(),
        choice: DatabaseChoice::Replica,
        ..options(&replay.db, replay.key_dir(), true)
    })
    .await
    .expect("check");
    assert_eq!(on_replica.summary.database, DatabaseChoice::Replica);
    let line = find(&on_replica.accounts, "lagging");
    assert_eq!(
        (line.state, line.serving, line.head_seq, line.mark_seq),
        (MarkState::Behind, true, Some(1), Some(3))
    );
    assert!(on_replica.needs_attention());
    replica.drop_database().await.expect("drop");
    replay.db.drop_database().await.expect("drop");
}

#[test]
fn test_check_marks_options_from_config() {
    let mut config = pubky_switch::config::Config::default();
    assert!(matches!(
        CheckOptions::from_config(&config, Some("postgres://h/db"), false),
        Err(check_marks::CheckError::NoKeyStore)
    ));
    config.keys.path = Some(PathBuf::from("/nonexistent/keys"));
    // Without an origin no account reads as serving: refused, not a pass.
    assert!(matches!(
        CheckOptions::from_config(&config, Some("postgres://h/db"), false),
        Err(check_marks::CheckError::NoOrigin)
    ));
    config.server.origin = Some(ORIGIN.into());
    let options =
        CheckOptions::from_config(&config, Some("postgres://h/db"), true).expect("options");
    assert_eq!(options.choice, DatabaseChoice::Replica);
    assert_eq!(options.origin, ORIGIN);
    assert!(options.all);
    assert!(CheckOptions::from_config(&config, Some("not a url"), false).is_err());
}
