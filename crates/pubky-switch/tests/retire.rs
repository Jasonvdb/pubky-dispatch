//! The operator's retirement of a generation, against PostgreSQL: who may be retired, at
//! which generation, that a refusal records nothing, the key store's lock, and the notice
//! the service answers afterwards (Switch spec 6.5, "Retiring a generation"; Switch wire
//! 7.3, Tables 1 and 3).
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// A test fails on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::{fs, path::Path};

use pubky_switch::{
    http::Handler,
    keys::FileKeyStore,
    limits::Limits,
    marks::{Advance, MarkStore},
    retire::{self, Refusal, RetireError, RetireOptions, Retired},
    service::Service,
    store::{NewAccount, testing::TestDatabase},
};
use pubky_switch_core::{
    chain::ChainTip,
    http::NoticeReason,
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

fn options(replay: &Replay, identity: &str, generation: u64) -> RetireOptions {
    RetireOptions {
        database: replay.db.options().clone(),
        key_dir: replay.key_dir().to_path_buf(),
        origin: ORIGIN.into(),
        identity: identity.into(),
        generation,
    }
}

async fn retire(replay: &Replay, identity: &str, generation: u64) -> Result<Retired, RetireError> {
    retire::run(&options(replay, identity, generation)).await
}

/// Retire, expecting `refusal`.
async fn refused(replay: &Replay, identity: &str, generation: u64, refusal: Refusal) {
    match retire(replay, identity, generation).await {
        Err(RetireError::Refused(found)) => assert_eq!(found, refusal),
        other => panic!("expected {refusal:?}, got {other:?}"),
    }
}

/// Every retirement file in the store, by name.
fn retirements(key_dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(key_dir.join("accounts/retired"))
        .expect("retired dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("utf-8")
        })
        .collect();
    names.sort();
    names
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

/// Create staged account `id` at generation 1 with its (0, 0) mark, holding an
/// `identity.json` that names `origin`, or none.
async fn create_staged(replay: &Replay, id: &str, origin: Option<&str>) {
    let identity = IdentityKey::from_secret([7; 32]);
    let doc = origin.map(|origin| {
        let body = IdentityBody::first(
            identity.public(),
            [4; 16],
            Inbox::new(origin, service_public(replay)),
            IdentityPolicy::default(),
        );
        IdentityDoc::sign(&identity, body)
            .expect("sign")
            .signed()
            .clone()
    });
    let account = NewAccount {
        id: id.into(),
        identity_key: identity.public(),
        generation: 1,
        created_at_ms: T0,
        limits: pubky_switch_core::records::Limits::default(),
        identity_doc: doc,
        revoked_apps: Vec::new(),
        enrollment_hash: [0; 32],
    };
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
}

/// Append one chain item per hash to account `id`, without moving its mark.
async fn append(db: &TestDatabase, id: &str, hashes: &[u8]) {
    for hash in hashes {
        let mut txn = db.store().begin(id).await.expect("begin").expect("account");
        let seq = txn.next_seq().expect("seq");
        txn.set_chain_head(seq, [*hash; 32]).expect("head");
        txn.commit().await.expect("commit");
    }
}

/// Run `sql` on a connection that may write, as a restore would.
async fn write(db: &TestDatabase, sql: &str) {
    let mut conn = sqlx::PgConnection::connect_with(db.options())
        .await
        .expect("connect");
    sqlx::raw_sql(sql).execute(&mut conn).await.expect("write");
    conn.close().await.expect("close");
}

#[tokio::test]
async fn test_retire_lost_identity() {
    // alice's account gone, as a restore from before her enrollment leaves it, with her
    // mark at the head the service signed: a lost identity, retired at the mark's
    // generation.
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let alice = alice_id();
    write(
        &replay.db,
        &format!("DELETE FROM accounts WHERE id = '{alice}'"),
    )
    .await;
    let retired = retire(&replay, &alice, 1).await.expect("retired");
    assert_eq!((retired.retired, retired.already_retired), (1, false));
    assert_eq!(
        (
            retired.notice.generation,
            retired.notice.reason,
            retired.notice.permanent
        ),
        (1, NoticeReason::Behind, true)
    );
    assert_eq!(retirements(replay.key_dir()), vec![format!("{alice}.1")]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_failing_serving_account() {
    // alice's state behind her mark: she fails stop, and is retired; the notice keeps its
    // reason and becomes permanent. A second retirement changes nothing.
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let alice = alice_id();
    mark_at(&replay, &alice, 1, 4, 4).await;
    let retired = retire(&replay, &alice, 1).await.expect("retired");
    assert_eq!(
        (
            retired.retired,
            retired.already_retired,
            retired.notice.reason,
            retired.notice.permanent
        ),
        (1, false, NoticeReason::Behind, true)
    );
    let line: serde_json::Value =
        serde_json::from_str(&retired.to_json_line().expect("json")).expect("parse");
    assert_eq!(
        line,
        serde_json::json!({
            "account": alice, "retired": 1, "already_retired": false,
            "notice": {"generation": 1, "reason": "behind", "permanent": true}
        })
    );

    let again = retire(&replay, &alice, 1).await.expect("a no-op");
    assert_eq!(
        (again.retired, again.already_retired, again.notice),
        (1, true, retired.notice)
    );
    assert_eq!(retirements(replay.key_dir()), vec![format!("{alice}.1")]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_mark_lost_takes_the_account_generation() {
    // alice's mark file gone: she fails stop, `mark_lost`, and is retired at her account's
    // generation.
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let alice = alice_id();
    fs::remove_file(replay.key_dir().join("accounts/marks").join(&alice)).expect("remove");
    refused(
        &replay,
        &alice,
        2,
        Refusal::WrongGeneration {
            given: 2,
            retirable: 1,
        },
    )
    .await;
    let retired = retire(&replay, &alice, 1).await.expect("retired");
    assert_eq!(
        (retired.notice.reason, retired.notice.permanent),
        (NoticeReason::MarkLost, true)
    );
    assert_eq!(retirements(replay.key_dir()), vec![format!("{alice}.1")]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_generation_zero_refused() {
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let alice = alice_id();
    mark_at(&replay, &alice, 1, 4, 4).await;
    refused(&replay, &alice, 0, Refusal::GenerationZero).await;
    assert!(retirements(replay.key_dir()).is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_wrong_generation_refused() {
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let alice = alice_id();
    mark_at(&replay, &alice, 1, 4, 4).await;
    refused(
        &replay,
        &alice,
        2,
        Refusal::WrongGeneration {
            given: 2,
            retirable: 1,
        },
    )
    .await;
    assert!(retirements(replay.key_dir()).is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_healthy_account_refused() {
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    refused(&replay, &alice_id(), 1, Refusal::Healthy).await;
    assert!(retirements(replay.key_dir()).is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_staged_account_refused() {
    // A move's target that no document names: staged at (0, 0), then bounded by a mark
    // that records a head. Neither is retired: its ways out are the abort and the erasure.
    let Some(replay) = replay().await else { return };
    create_staged(&replay, "target", None).await;
    refused(&replay, "target", 1, Refusal::Staged).await;
    mark_at(&replay, "target", 1, 3, 3).await;
    refused(&replay, "target", 1, Refusal::Staged).await;
    assert!(retirements(replay.key_dir()).is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_failing_account_named_elsewhere_refused() {
    // An account holding a chain behind its mark fails stop, but its newest identity.json
    // names another service: it is staged here, and isn't retired.
    let Some(replay) = replay().await else { return };
    create_staged(&replay, "elsewhere", Some(BOB_ORIGIN)).await;
    append(&replay.db, "elsewhere", &[1, 2]).await;
    mark_at(&replay, "elsewhere", 1, 4, 4).await;
    refused(&replay, "elsewhere", 1, Refusal::Staged).await;
    // And the same without a document.
    create_staged(&replay, "unnamed", None).await;
    append(&replay.db, "unnamed", &[1]).await;
    mark_at(&replay, "unnamed", 1, 4, 4).await;
    refused(&replay, "unnamed", 1, Refusal::Staged).await;
    assert!(retirements(replay.key_dir()).is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_not_hosted_refused() {
    // No account and no mark, or a (0, 0) mark without an account.
    let Some(replay) = replay().await else { return };
    refused(&replay, "nobody", 1, Refusal::NotHosted).await;
    replay
        .marks
        .create_zero("zero", service_public(&replay), T0)
        .await
        .expect("mark");
    refused(&replay, "zero", 1, Refusal::NotHosted).await;
    refused(&replay, "../x", 1, Refusal::InvalidIdentity).await;
    assert!(retirements(replay.key_dir()).is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_refused_while_the_service_holds_the_lock() {
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let alice = alice_id();
    mark_at(&replay, &alice, 1, 4, 4).await;
    let lock = FileKeyStore::lock_dir(replay.key_dir()).expect("lock");
    match retire(&replay, &alice, 1).await {
        Err(RetireError::Refused(Refusal::ServiceRunning(_))) => {}
        other => panic!("expected the service's lock, got {other:?}"),
    }
    assert!(retirements(replay.key_dir()).is_empty());
    drop(lock);
    retire(&replay, &alice, 1).await.expect("retired once free");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_service_answers_permanent_notice() {
    // After the retirement a service started on the same key store and database answers
    // alice's requests with the permanent notice (Switch wire 7.6).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let alice = alice_id();
    mark_at(&replay, &alice, 1, 4, 4).await;
    let at = ms(&item_time(&vectors("chain.json")["items"][1]));
    let notice = |service: Service| {
        let path = format!("/v1/{alice}/allow");
        async move {
            let answer = service
                .handle(signer_request("GET", &path, Vec::new(), at))
                .await;
            assert_eq!(answer.status, 503);
            let body: serde_json::Value = serde_json::from_slice(&answer.body).expect("json");
            body["current"].clone()
        }
    };
    let before = notice(replay.restarted_with(Limits::default())).await;
    assert_eq!(before["permanent"], false, "{before}");

    retire(&replay, &alice, 1).await.expect("retired");
    let started = Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        MarkStore::open(replay.key_dir()).expect("mark store"),
        replay.time.clone(),
        Limits::default(),
    );
    let after = notice(started).await;
    assert_eq!(
        after,
        serde_json::json!({"generation": 1, "reason": "behind", "permanent": true})
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retire_activation_at_a_staged_account_with_a_retired_generation_clears_nothing() {
    // alice's account is staged at her (0, 0) mark, and generation 1 is retired for her, as
    // a lost identity's retirement that her new enrollment kept. An activation there isn't
    // judged as one that clears the mark: it reaches only the answer of a call the service
    // doesn't serve, and the mark stays where it was (Switch wire 7.3, Tables 2 and 3).
    let Some(replay) = replay().await else { return };
    let alice = alice_id();
    let keys = vectors("keys.json");
    let identity = IdentityKey::from_secret(hex32(&support::alice(&keys)["secret_hex"]));
    let account = NewAccount {
        id: alice.clone(),
        identity_key: identity.public(),
        generation: 1,
        created_at_ms: T0,
        limits: pubky_switch_core::records::Limits::default(),
        identity_doc: None,
        revoked_apps: Vec::new(),
        enrollment_hash: [0; 32],
    };
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
        .create_zero(&alice, service_public(&replay), T0)
        .await
        .expect("mark");
    replay.marks.retire(&alice, 1).await.expect("retire");
    let before = replay.marks.read(&alice).await.expect("read");
    let at = T0 + 1_000;
    replay.clock.set_wall_ms(at);
    let path = format!("/v1/{alice}/import/activate");
    let answer = replay
        .service
        .handle(signer_request("POST", &path, b"{}".to_vec(), at))
        .await;
    assert_eq!(answer.status, 503);
    let body: serde_json::Value = serde_json::from_slice(&answer.body).expect("json");
    assert_eq!(body["code"], "unavailable", "{body}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|message| message.contains("isn't served yet")),
        "{body}"
    );
    assert!(header_text(&answer, "switch-head").is_none());
    assert_eq!(replay.marks.read(&alice).await.expect("read"), before);
    replay.db.drop_database().await.expect("drop");
}
