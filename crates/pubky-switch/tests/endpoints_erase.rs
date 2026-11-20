//! `POST /v1/{id}/erase` (Switch wire 7.4.16, spec 12.7) on alice's account: the vectors,
//! what is deleted and what isn't, the order of the record, the deletion and the mark (Switch
//! wire 7.3, Table 3), what every later call answers, the refusals, and the erasures a
//! restored database or a leftover mark calls for (Switch wire 7.3, Table 1).
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// The tests fail on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use pubky_switch::{
    http::{Handler, SwitchRequest, SwitchResponse},
    keys::{KeyId, KeyStore},
    marks::MarkRead,
    service::Service,
};
use pubky_switch_core::{
    chain::ChainTip,
    http::{erase_body, header},
    time::rfc3339,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

/// Every table holding an account's state, each with its account column. All reference
/// `accounts` with `ON DELETE CASCADE`.
const ACCOUNT_TABLES: &[(&str, &str)] = &[
    ("accounts", "id"),
    ("state_history", "account_id"),
    ("kept_app_ids", "account_id"),
    ("chain_items", "account_id"),
    ("chain_retention", "account_id"),
    ("enrollment_answers", "account_id"),
    ("apps", "account_id"),
    ("receive_keys", "account_id"),
    ("key_bundle_parts", "account_id"),
    ("shared_records", "account_id"),
    ("claims", "account_id"),
    ("claim_entries", "account_id"),
    ("peer_admissions", "account_id"),
    ("denied_peers", "account_id"),
    ("invite_codes", "account_id"),
    ("batches", "account_id"),
    ("app_listings", "account_id"),
    ("peer_copies", "account_id"),
    ("peer_floors", "account_id"),
    ("inbox_entries", "account_id"),
    ("sender_flags", "account_id"),
    ("handovers", "account_id"),
    ("held_revoked_apps", "account_id"),
    ("divergent_uploads", "account_id"),
    ("connect_requests", "account_id"),
    ("push_registrations", "account_id"),
    ("push_deliveries", "account_id"),
];

/// The not-hosted `404` body (Switch wire 7.3 step 2).
const NOT_HOSTED: &str =
    r#"{"code":"not_found","message":"no such account","current":{"hosted":false}}"#;

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

fn erase_path() -> String {
    format!("/v1/{}/erase", alice_id())
}

fn apps_path() -> String {
    format!("/v1/{}/apps", alice_id())
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn code_of(answer: &SwitchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

fn text(answer: &SwitchResponse) -> String {
    String::from_utf8_lossy(&answer.body).into_owned()
}

fn no_head(answer: &SwitchResponse) -> bool {
    header_text(answer, header::HEAD).is_none()
}

fn revoke_time() -> String {
    item_time(chain_item(&vectors("chain.json"), 9))
}

/// The document hash of documents.json's `name`.
fn doc_hash(name: &str) -> [u8; 32] {
    let doc: pubky_switch_core::sig::SignedDoc = serde_json::from_value(
        named(&vectors("documents.json")["documents"], name)["signed"].clone(),
    )
    .expect("signed doc");
    doc.doc_hash().expect("hash")
}

/// The hash of alice's version 3, the newest `identity.json` `serve_alice` leaves.
fn held_hash() -> [u8; 32] {
    doc_hash("alice identity.json")
}

/// The time of the enrollment answer in http.json, when `serve_alice` enrolls alice.
fn enrolled_time() -> String {
    named(
        &vectors("http.json")["responses"],
        "signer: enrollment answer, signed with the service key",
    )["headers"]["switch-server-time"]
        .as_str()
        .expect("time")
        .to_string()
}

/// The time of the erasure answer naming its `identity.json` in http.json.
fn hash_vector_time() -> String {
    named(
        &vectors("http.json")["responses"],
        "signer: account erasure answer to the request naming its identity.json, signed with the service key, no head",
    )["headers"]["switch-server-time"]
        .as_str()
        .expect("time")
        .to_string()
}

/// The signer's erasure of alice's account naming the creation time `created` and `hash`,
/// signed at `at_ms` (Switch wire 7.4.16).
fn erasure_naming(created: Option<u64>, hash: Option<&[u8; 32]>, at_ms: u64) -> SwitchRequest {
    signer_request_at_creation(
        "POST",
        &erase_path(),
        erase_body(created, hash),
        at_ms,
        created,
    )
}

/// The signer's erasure of alice's account naming its creation time, as the mark's file or
/// the account holds it, and `hash`, signed at `at_ms` (Switch wire 7.4.16).
async fn erasure(replay: &Replay, hash: Option<&[u8; 32]>, at_ms: u64) -> SwitchRequest {
    erasure_of(replay, &alice_id(), hash, at_ms).await
}

/// The signer's erasure of alice's account naming `hash`, at `at`.
async fn erase(replay: &Replay, hash: Option<&[u8; 32]>, at: &str) -> SwitchResponse {
    let request = erasure(replay, hash, ms(at)).await;
    replay.service.handle(request).await
}

/// The signer's erasure of alice's account naming her version 3, at `at`.
async fn erase_held(replay: &Replay, at: &str) -> SwitchResponse {
    erase(replay, Some(&held_hash()), at).await
}

/// alice enrolled by the vector, staged, holding no `identity.json`; the enrollment's time.
async fn enroll_alice(replay: &Replay) -> String {
    let at = enrolled_time();
    set_time(&replay.clock, &at);
    let enrollment = fresh_alice_enrollment(replay, ms(&at)).await;
    let answer = replay.service.handle(enrollment).await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    at
}

/// How many rows each account table holds for `account`.
async fn rows(replay: &Replay, account: &str) -> Vec<(&'static str, i64)> {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let mut counts = Vec::new();
    for (table, column) in ACCOUNT_TABLES {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE {column} = $1"))
                .bind(account)
                .fetch_one(&mut conn)
                .await
                .expect("count");
        counts.push((*table, count));
    }
    conn.close().await.expect("close");
    counts
}

/// Whether no account table holds a row of alice's account.
async fn all_gone(replay: &Replay) -> bool {
    rows(replay, &alice_id())
        .await
        .iter()
        .all(|(_, count)| *count == 0)
}

/// When alice's account was created, if it is there.
async fn created_at(replay: &Replay) -> Option<u64> {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let at: Option<i64> = sqlx::query_scalar("SELECT created_at_ms FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_optional(&mut conn)
        .await
        .expect("created");
    conn.close().await.expect("close");
    at.map(|at| u64::try_from(at).expect("time"))
}

/// What the mark store holds for `identity`, as its file is now.
async fn mark_of(replay: &Replay, identity: &str) -> MarkRead {
    pubky_switch::marks::MarkView::open(replay.key_dir())
        .expect("mark store")
        .read(identity)
        .expect("mark")
}

/// The mark the store holds for `identity`, which must be one.
async fn held_mark(replay: &Replay, identity: &str) -> pubky_switch::marks::AccountMark {
    match mark_of(replay, identity).await {
        MarkRead::Mark(mark) => mark,
        other => panic!("no mark: {other:?}"),
    }
}

/// The erasure's record the ledger holds for alice.
async fn record_of(replay: &Replay) -> Option<u64> {
    replay.marks.erasure(&alice_id()).await.expect("ledger")
}

/// A service on `replay`'s database, keys and clock, its mark store opened again, as after
/// a restart: it reads every mark from its file.
fn reopened(replay: &Replay) -> Service {
    Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        pubky_switch::marks::MarkStore::open(replay.key_dir()).expect("mark store"),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    )
}

/// alice's mark lost: its file deleted (Switch wire 7.3, Table 1); a service that reads it
/// afresh, [`reopened`], finds none.
fn lose_alice_mark(replay: &Replay) {
    let file = replay
        .key_dir()
        .join("accounts")
        .join("marks")
        .join(alice_id());
    std::fs::remove_file(file).expect("delete the mark");
}

/// A head at alice's generation 1 that her state doesn't reach.
fn head_at(seq: u64) -> ChainTip {
    ChainTip {
        generation: 1,
        seq,
        chain_hash: [7; 32],
    }
}

/// Make `dir` read-only (or writable again), so a write in it fails.
fn set_read_only(dir: &std::path::Path, read_only: bool) {
    use std::os::unix::fs::PermissionsExt;
    let mode = if read_only { 0o500 } else { 0o700 };
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// `request` as sent, which an answer to it binds (Switch wire 7.1); it carries a signature.
fn signed_sent(request: &SwitchRequest) -> Sent {
    let sent = Sent::of(request);
    assert!(sent.signed(), "signature");
    sent
}

/// `answer` to `sent` is the not-hosted `404` (Switch wire 7.3 step 2, 7.4.16 Afterwards):
/// `current: { "hosted": false }`, no head, signed with the service key over the request as
/// the service received it.
fn assert_not_hosted(replay: &Replay, answer: &SwitchResponse, sent: &Sent, name: &str) {
    assert_eq!(answer.status, 404, "{name}: {}", text(answer));
    assert_eq!(text(answer), NOT_HOSTED, "{name}");
    assert!(no_head(answer), "{name}");
    assert!(
        signed_with(answer, &service_public(replay), sent),
        "{name}: signed with the service key"
    );
    let elsewhere = sent.clone().at_path(format!("/v1/{}/x", alice_id()));
    assert!(
        !signed_with(answer, &service_public(replay), &elsewhere),
        "{name}: bound to the path"
    );
    let other_method = sent.clone().with_method("DELETE");
    assert!(
        !signed_with(answer, &service_public(replay), &other_method),
        "{name}: bound to the method"
    );
}

/// Send `request` to `service` and check it gets the not-hosted `404`.
async fn not_hosted_to(replay: &Replay, service: &Service, request: SwitchRequest, name: &str) {
    let sent = Sent::of(&request);
    let answer = service.handle(request).await;
    assert_not_hosted(replay, &answer, &sent, name);
}

/// A service on `replay`'s database, keys, marks and clock, made as the binary makes it at
/// start, with `retention_days` of backups.
async fn started(replay: &Replay, retention_days: Option<u64>) -> Service {
    Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        replay.marks.clone(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    )
    .with_backup_retention_days(retention_days)
    .started()
    .await
}

#[tokio::test]
async fn test_erase_vector_answer() {
    // http.json's erasure naming only the account's creation time, the `created` of its
    // enrollment answer, at alice's account after her enrollment and before her first
    // delivery, which holds no `identity.json`, and its answer: `{ "erased": true }`, signed
    // with the service key, without a head (Switch wire 7.4.16).
    let Some(replay) = replay().await else { return };
    enroll_alice(&replay).await;
    let http = vectors("http.json");
    let expected = named(
        &http["responses"],
        "signer: account erasure answer, signed with the service key, no head",
    );
    let at = expected["headers"]["switch-server-time"]
        .as_str()
        .expect("time");
    set_time(&replay.clock, at);
    let request = vector_request(named(
        &http["requests"],
        "signer: account erasure, naming the account's creation time",
    ));
    assert_eq!(
        request.body.as_ref(),
        erase_body(Some(ms(&enrolled_time())), None).as_slice()
    );
    let answer = replay.service.handle(request).await;
    assert_matches(&answer, expected);
    assert!(no_head(&answer));
    assert!(all_gone(&replay).await);
    assert_eq!(mark_of(&replay, &alice_id()).await, MarkRead::Missing);
    assert_eq!(durable_record(&replay), Some(ms(at)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_vector_naming_the_identity_json_it_follows() {
    // http.json's erasure naming the hash of alice's version 3, which her account holds, and
    // its answer: `{ "erased": true }`, signed with the service key, without a head (Switch
    // wire 7.4.16).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let http = vectors("http.json");
    let expected = named(
        &http["responses"],
        "signer: account erasure answer to the request naming its identity.json, signed with the service key, no head",
    );
    set_time(&replay.clock, &hash_vector_time());
    let request = vector_request(named(
        &http["requests"],
        "signer: account erasure, naming the account's creation time and the identity.json it follows",
    ));
    let answer = replay.service.handle(request).await;
    assert_matches(&answer, expected);
    assert!(no_head(&answer));
    assert!(all_gone(&replay).await);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_vector_naming_another_identity_json_is_conflict() {
    // http.json's erasure naming alice's version 1 while her account holds version 3: the
    // vector's `409 conflict`, signed with the service key, without a head, carrying the
    // creation time it was checked against in `current.created` and, at a healthy account,
    // nothing else there. The account stays and its mark covers the due sweep (Switch wire
    // 7.3, 7.4.16).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let before = rows(&replay, &alice_id()).await;
    let mark = held_mark(&replay, &alice_id()).await;
    let http = vectors("http.json");
    let expected = named(
        &http["responses"],
        "signer: account erasure refused, the account holds another identity.json, 409 conflict with current.created, no head",
    );
    set_time(&replay.clock, &hash_vector_time());
    let request = vector_request(named(
        &http["requests"],
        "signer: account erasure naming an identity.json the account doesn't hold",
    ));
    let answer = replay.service.handle(request).await;
    assert_matches(&answer, expected);
    assert!(no_head(&answer));
    assert_eq!(
        body(&answer)["current"],
        serde_json::json!({ "created": enrolled_time() })
    );
    assert_eq!(rows(&replay, &alice_id()).await, before, "nothing deleted");
    let after = held_mark(&replay, &alice_id()).await;
    assert_eq!(after.head(), mark.head());
    assert_eq!(after.state_version, mark.state_version + 1);
    assert_ne!(after.state_tag, mark.state_tag);
    assert!(after.time_floor_ms >= mark.time_floor_ms);
    assert_eq!(record_of(&replay).await, None);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_deletes_the_account_and_nothing_else() {
    // Every row of alice's state goes, and her mark; the erasure's record is in the mark store,
    // and the service key stays; bob's account on the same service keeps every row and his
    // mark (Switch wire 7.4.16, 7.3 Table 3, spec 12.7).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let bob = serve_bob(&replay).await;
    // bob's account names alice: a kept peer, and a copy of her identity.json. They are bob's,
    // and stay (7.4.16 Not erased).
    let alice_key = hex32(&alice(&vectors("keys.json"))["public_hex"]);
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "INSERT INTO peer_admissions (account_id, kept, pubky) \
         VALUES ($1, TRUE, $2)",
    )
    .bind(&bob)
    .bind(alice_key.as_slice())
    .execute(&mut conn)
    .await
    .expect("kept peer");
    let copy = serde_json::to_vec(
        &named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"],
    )
    .expect("copy");
    sqlx::query(
        "INSERT INTO peer_copies (account_id, identity, doc, version, generation, body_hash) \
         VALUES ($1, $2, $3, 3, 1, $4)",
    )
    .bind(&bob)
    .bind(alice_key.as_slice())
    .bind(copy)
    .bind([0u8; 32].as_slice())
    .execute(&mut conn)
    .await
    .expect("peer copy");
    // A stored hand-over on each account: alice's goes, bob's stays (7.4.17).
    for account in [alice_id(), bob.clone()] {
        sqlx::query("INSERT INTO handovers (account_id, target_app_id, body) VALUES ($1, $2, $3)")
            .bind(account)
            .bind([1u8; 16].as_slice())
            .bind(b"{}".as_slice())
            .execute(&mut conn)
            .await
            .expect("a hand-over");
    }
    conn.close().await.expect("close");
    let bob_before = rows(&replay, &bob).await;
    for table in ["peer_admissions", "peer_copies"] {
        assert!(
            bob_before.iter().any(|(t, n)| *t == table && *n > 0),
            "bob holds {table} rows naming alice"
        );
    }
    let alice_before = rows(&replay, &alice_id()).await;
    for table in [
        "accounts",
        "chain_items",
        "apps",
        "claims",
        "enrollment_answers",
    ] {
        assert!(
            alice_before.iter().any(|(t, n)| *t == table && *n > 0),
            "alice holds {table} rows to erase"
        );
    }
    let bob_mark = held_mark(&replay, &bob).await;
    assert!(matches!(
        mark_of(&replay, &alice_id()).await,
        MarkRead::Mark(_)
    ));
    let key = service_public(&replay);
    let at = revoke_time();
    let answer = erase_held(&replay, &at).await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    for (table, count) in rows(&replay, &alice_id()).await {
        assert_eq!(count, 0, "{table}");
    }
    assert_eq!(rows(&replay, &bob).await, bob_before);
    assert_eq!(mark_of(&replay, &alice_id()).await, MarkRead::Missing);
    assert_eq!(held_mark(&replay, &bob).await, bob_mark, "bob's mark stays");
    assert_eq!(record_of(&replay).await, Some(ms(&at)));
    assert_eq!(
        replay.marks.erasure(&bob).await.expect("ledger"),
        None,
        "no record for bob"
    );
    assert_eq!(service_public(&replay), key, "the service key stays");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_every_account_table_cascades() {
    // Read from the schema's foreign keys, whatever their columns' names: every foreign key
    // that reaches `accounts` deletes in cascade, and every table that reaches it is in
    // `ACCOUNT_TABLES`; every other table is one the erasure leaves by design (7.4.16).
    let Some(replay) = replay().await else { return };
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    // (table, referenced table, delete rule) for every foreign key in the schema.
    let keys: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.conrelid::regclass::text, c.confrelid::regclass::text, c.confdeltype::text \
         FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace \
         WHERE c.contype = 'f' AND n.nspname = current_schema()",
    )
    .fetch_all(&mut conn)
    .await
    .expect("foreign keys");
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = current_schema()",
    )
    .fetch_all(&mut conn)
    .await
    .expect("tables");
    conn.close().await.expect("close");
    // The tables reaching `accounts` through foreign keys, transitively.
    let mut reached = vec!["accounts".to_owned()];
    loop {
        let more: Vec<String> = keys
            .iter()
            .filter(|(table, to, _)| reached.contains(to) && !reached.contains(table))
            .map(|(table, _, _)| table.clone())
            .collect();
        if more.is_empty() {
            break;
        }
        reached.extend(more);
    }
    for (table, to, rule) in &keys {
        if reached.contains(to) {
            assert_eq!(rule, "c", "{table}'s foreign key to {to} cascades");
        }
    }
    let mut listed: Vec<&str> = ACCOUNT_TABLES.iter().map(|(t, _)| *t).collect();
    listed.sort_unstable();
    let mut found: Vec<&str> = reached.iter().map(String::as_str).collect();
    found.sort_unstable();
    assert_eq!(
        found, listed,
        "ACCOUNT_TABLES names every table of an account"
    );
    for table in &tables {
        assert!(
            reached.contains(table)
                || ["erased_keys", "erasure_outcomes", "_sqlx_migrations"]
                    .contains(&table.as_str()),
            "{table} holds nothing of an account, or reaches accounts"
        );
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_forgets_the_accounts_counts() {
    // The failed-authentication counts at the account go with it (Switch wire 7.4.16, 9.4).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let mut bad = signer_request("GET", &apps_path(), Vec::new(), ms(&at));
    bad.headers.insert(
        header::SIGNATURE,
        pubky_switch_core::enc::b64(&[0u8; 64])
            .parse()
            .expect("header"),
    );
    assert_eq!(code_of(&replay.service.handle(bad).await).0, 401);
    let claimed = (alice_id(), alice_id(), None);
    let base = replay.time.peek().base_ms;
    assert!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, base)
            > 0
    );
    // A public read and the replayed batches counted against the account's other limits.
    let read = replay
        .service
        .handle(request(
            "GET",
            &format!("/v1/{}/identity", alice_id()),
            &[],
            Vec::new(),
        ))
        .await;
    assert_eq!(read.status, 200);
    let failed = replay
        .service
        .failed_authentications()
        .counted_at(&alice_id());
    assert!(
        replay.service.counted_at(&alice_id()) > failed,
        "counts beyond the failures"
    );
    assert_eq!(erase_held(&replay, &at).await.status, 200);
    assert_eq!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, base),
        0
    );
    assert_eq!(
        replay.service.counted_at(&alice_id()),
        0,
        "every count of the account"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_after_a_purge() {
    // The wallet revoked and purged (Switch wire 9.1): the erasure deletes every row as
    // before, the purged App ID's included.
    let Some(replay) = replay().await else { return };
    let (held, at) = purge_wallet(&replay).await;
    let answer = replay
        .service
        .handle(erasure(&replay, Some(&held.doc_hash().expect("hash")), at).await)
        .await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    for (table, count) in rows(&replay, &alice_id()).await {
        assert_eq!(count, 0, "{table}");
    }
    not_hosted_to(
        &replay,
        &replay.service,
        signer_request("GET", &apps_path(), Vec::new(), at),
        "signer read",
    )
    .await;
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_of_an_account_holding_an_item_that_doesnt_read() {
    // A chain item whose stored document doesn't read (Switch wire 7.5): the signer can still
    // erase the account, since nothing the erasure runs reads that document.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    sql_on(
        &replay,
        &alice_id(),
        "UPDATE chain_items SET item_bytes = '\\x00'::BYTEA WHERE account_id = $1 AND seq = 3",
    )
    .await;
    let answer = erase_held(&replay, &revoke_time()).await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_then_every_call_is_the_not_hosted_404() {
    // Afterwards the account is one the service doesn't host: the public read, the signer's
    // calls, an app's, another identity's, and the erasure again (the retry of a lost `200`)
    // get the `404` with `current: { "hosted": false }`, signed with the service key over
    // their method and path, without a head (Switch wire 7.4.16, 7.3 step 2).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let created = creation_time(&replay, &alice_id()).await;
    assert_eq!(erase_held(&replay, &at).await.status, 200);
    let keys = vectors("keys.json");
    let requests = vec![
        (
            "public read",
            request(
                "GET",
                &format!("/v1/{}/identity", alice_id()),
                &[],
                Vec::new(),
            ),
        ),
        (
            "signer read",
            signer_request("GET", &apps_path(), Vec::new(), ms(&at)),
        ),
        (
            "signer delivery",
            signer_request(
                "PUT",
                &format!("/v1/{}/identity", alice_id()),
                b"{}".to_vec(),
                ms(&at),
            ),
        ),
        (
            "own app feed",
            app_request(
                app(&keys, "wallet"),
                "GET",
                &format!("/v1/{}/feed", alice_id()),
                Vec::new(),
                ms(&at),
            ),
        ),
        (
            "inbox append from another identity",
            other_request(
                "shop",
                ORIGIN,
                "POST",
                &format!("/v1/{}/inbox", alice_id()),
                b"{}".to_vec(),
                None,
                ms(&at),
            ),
        ),
        (
            "erasure again",
            erasure_naming(created, Some(&held_hash()), ms(&at)),
        ),
        (
            "erasure again without a hash",
            erasure_naming(created, None, ms(&at)),
        ),
    ];
    for (name, request) in requests {
        not_hosted_to(&replay, &replay.service, request, name).await;
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_retry_with_the_hash_after_it_landed_is_the_not_hosted_404() {
    // The erasure naming the held version lands; a retry with the same body finds no account:
    // the not-hosted `404`, never a `409` (7.4.16).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = hash_vector_time();
    set_time(&replay.clock, &at);
    let created = creation_time(&replay, &alice_id()).await;
    assert_eq!(erase_held(&replay, &at).await.status, 200);
    not_hosted_to(
        &replay,
        &replay.service,
        erasure_naming(created, Some(&held_hash()), ms(&at) + 1000),
        "retry",
    )
    .await;
    replay.db.drop_database().await.expect("drop");
}

/// The vectors' enrollment with another nonce, signed by alice: a fresh one, not a retry.
async fn fresh_enrollment(replay: &Replay, nonce: u8, at_ms: u64) -> Vec<u8> {
    use pubky_switch_core::{
        keys::IdentityKey,
        records::{Enrollment, EnrollmentBody},
        sig::SignedDoc,
    };
    let http = vectors("http.json");
    let vector = named(&http["requests"], "signer: enrollment");
    let body: Value = serde_json::from_slice(
        &pubky_switch_core::enc::unb64(vector["body_b64"].as_str().expect("body")).expect("b64"),
    )
    .expect("json");
    let signed: SignedDoc = serde_json::from_value(body["enrollment"].clone()).expect("signed");
    let mut fields: EnrollmentBody =
        serde_json::from_slice(&signed.body_bytes().expect("body")).expect("enrollment body");
    fields.nonce = [nonce; 16];
    fields.intent = new_alice_enrollment_intent(replay, at_ms).await;
    let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let enrollment = Enrollment::sign(&key, fields).expect("sign");
    serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).expect("json")
}

#[tokio::test]
async fn test_erase_then_enrollment_starts_a_new_account() {
    // `POST /v1/enroll` after an erasure creates a new, staged account, with nothing of the
    // old one, answered with the same service key, its (0, 0) mark created with it, after the
    // erasure's record (Switch wire 7.4.16 Afterwards, 7.3 Table 3).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let served = item_time(&vectors("chain.json")["items"][1]);
    assert_eq!(erase_held(&replay, &served).await.status, 200);
    let erased_at = record_of(&replay).await.expect("recorded");
    replay.clock.set_wall_ms(erased_at + 1);
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            fresh_enrollment(&replay, 5, erased_at + 1).await,
            erased_at + 1,
        ))
        .await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    assert_eq!(
        body(&answer)["service_key"],
        json!(pubky_switch_core::enc::b64(&service_public(&replay)))
    );
    let created = created_at(&replay).await.expect("the new account");
    assert!(created > erased_at, "created after the erasure");
    let mark = held_mark(&replay, &alice_id()).await;
    assert_eq!(
        (mark.generation, mark.seq, mark.created_at_ms),
        (0, 0, created)
    );
    let held: Vec<_> = rows(&replay, &alice_id())
        .await
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(table, _)| table)
        .collect();
    assert_eq!(held, ["accounts", "enrollment_answers"]);
    // Staged: it serves nothing until its first delivery (7.3 step 7).
    let apps = replay
        .service
        .handle(signer_request_at_creation(
            "GET",
            &apps_path(),
            Vec::new(),
            erased_at + 1,
            Some(created),
        ))
        .await;
    assert_eq!(code_of(&apps), (503, json!("staged")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_and_enrollment_before_a_mark_move_leave_the_new_mark() {
    // A request's mark moves after its commit, outside the identity's lock. An erasure and
    // a new enrollment that land in between leave the new account's (0, 0) mark as it is:
    // the move is the erased account's, the request answers `503 unavailable` without a
    // head, and nothing signed for its commit goes out (Switch wire 7.3, "Moving it",
    // Table 3).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let chain = vectors("chain.json");
    let at_ms = ms(&item_time(chain_item(&chain, 3)));
    replay.clock.set_wall_ms(at_ms);
    let batch = app_request(
        app(&vectors("keys.json"), "wallet"),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        pubky_switch_core::ops::OpsRequest::new(&ops_at(&chain, &[3, 4]), None).to_json(),
        at_ms,
    );
    let sent = Sent::of(&batch);
    let pause = replay.service.pause_next_mark_move();
    let later_ms = at_ms + 60_000;
    let (answer, created) = tokio::join!(Box::pin(replay.service.handle(batch)), async {
        pause.reached().await;
        replay.clock.set_wall_ms(later_ms);
        let erased = replay
            .service
            .handle(erasure(&replay, Some(&held_hash()), later_ms).await)
            .await;
        assert_eq!(erased.status, 200, "{}", text(&erased));
        replay.clock.set_wall_ms(later_ms + 1);
        let enrolled = replay
            .service
            .handle(signer_request(
                "POST",
                "/v1/enroll",
                fresh_enrollment(&replay, 7, later_ms + 1).await,
                later_ms + 1,
            ))
            .await;
        assert_eq!(enrolled.status, 200, "{}", text(&enrolled));
        let created = created_at(&replay).await.expect("the new account");
        pause.release();
        created
    });
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer), "no head of the erased account");
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    let mark = held_mark(&replay, &alice_id()).await;
    assert_eq!(
        (
            mark.generation,
            mark.seq,
            mark.chain_hash,
            mark.created_at_ms
        ),
        (0, 0, [0; 32], created),
        "the new account's mark stays"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_wakes_the_reads_waiting_on_the_account() {
    // The erasure's change notice wakes a feed read waiting on the account at once, not at its
    // wait's end, and it answers as for an account the service doesn't host (Switch wire
    // 7.4.16 Afterwards).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let listener = pubky_switch::changes::ChangeListener::connect(replay.db.store())
        .await
        .expect("listen");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(listener.run(replay.service.changes(), async {
        let _ = stopped.await;
    }));
    let at = revoke_time();
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/feed?after=1:9&wait=20", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let sent = signed_sent(&request);
    let started = std::time::Instant::now();
    let (answer, ()) = tokio::join!(replay.service.handle(request), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(erase_held(&replay, &at).await.status, 200);
    });
    assert_not_hosted(&replay, &answer, &sent, "the waiting read");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "woken by the erasure"
    );
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_without_a_hash_at_an_account_holding_identity_json_is_conflict() {
    // A body without `identity_hash` at an account that holds an `identity.json` is `409
    // conflict`, without a head, and nothing is deleted; the held hash then erases (7.4.16).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let before = rows(&replay, &alice_id()).await;
    let at = revoke_time();
    let answer = erase(&replay, None, &at).await;
    assert_eq!(code_of(&answer), (409, json!("conflict")));
    assert!(no_head(&answer));
    assert_eq!(rows(&replay, &alice_id()).await, before);
    assert_eq!(record_of(&replay).await, None);
    assert_eq!(erase_held(&replay, &at).await.status, 200);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_naming_a_hash_at_an_account_holding_no_identity_json_is_conflict() {
    // A staged account, enrolled and not yet delivered to, holds no `identity.json`: a hash
    // can't match, `409 conflict`, nothing deleted; the body `{}` erases it (7.4.16).
    let Some(replay) = replay().await else { return };
    let at = ms(&enroll_alice(&replay).await) + 1000;
    let named_hash = replay
        .service
        .handle(erasure(&replay, Some(&[9; 32]), at).await)
        .await;
    assert_eq!(code_of(&named_hash), (409, json!("conflict")));
    assert!(no_head(&named_hash));
    assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 1));
    assert_eq!(
        replay
            .service
            .handle(erasure(&replay, None, at).await)
            .await
            .status,
        200
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_refused_past_the_time_floor_raises_it() {
    // A refused erasure commits its stamp, which later answers show: where it passes the
    // mark's time floor, the floor rises first, a minute past it, as for every request
    // (Switch wire 7.3, "Trusted time").
    let Some(replay) = replay().await else { return };
    let at = ms(&enroll_alice(&replay).await) + 1000;
    let before = held_mark(&replay, &alice_id()).await;
    assert!(before.time_floor_ms < at);
    replay.clock.set_wall_ms(at);
    let refused = replay
        .service
        .handle(erasure(&replay, Some(&[9; 32]), at).await)
        .await;
    assert_eq!(code_of(&refused), (409, json!("conflict")));
    assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 1));
    assert_eq!(
        held_mark(&replay, &alice_id()).await,
        pubky_switch::marks::AccountMark {
            time_floor_ms: at + pubky_switch::marks::TIME_FLOOR_STEP_MS,
            ..before
        }
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_malformed_body_is_bad_request_not_conflict() {
    // A malformed `identity_hash` (short, not a string, null), an unknown member, or a body
    // that isn't an object is `400`, never a `409`, without a head, and nothing is deleted
    // (wire 7.4.16, 1.1).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = hash_vector_time();
    set_time(&replay.clock, &at);
    let before = rows(&replay, &alice_id()).await;
    let held = pubky_switch_core::enc::b64(&held_hash());
    for body in [
        r#"{"identity_hash":"AA"}"#.to_string(),
        r#"{"identity_hash":7}"#.to_string(),
        format!(r#"{{"identity_hash":"{held}","x":1}}"#),
        r#"{"x":1}"#.to_string(),
        "[]".to_string(),
        String::new(),
    ] {
        let answer = replay
            .service
            .handle(signer_request(
                "POST",
                &erase_path(),
                body.clone().into_bytes(),
                ms(&at),
            ))
            .await;
        assert_eq!(code_of(&answer), (400, json!("bad_request")), "{body}");
        assert!(no_head(&answer), "{body}");
    }
    assert_eq!(rows(&replay, &alice_id()).await, before, "nothing deleted");
    assert_eq!(record_of(&replay).await, None);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_only_the_signer() {
    // An app's call is `403 permission_missing`, an own app's and one of another identity's;
    // a timestamp more than 5 minutes off is `401 stale_timestamp`; none carries a head, and
    // nothing is erased (Switch wire 7.4.16, 7.6).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let created = creation_time(&replay, &alice_id()).await;
    let keys = vectors("keys.json");
    let own = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "POST",
            &erase_path(),
            erase_body(created, Some(&held_hash())),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&own), (403, json!("permission_missing")));
    assert!(no_head(&own));
    let other = replay
        .service
        .handle(other_request(
            "shop",
            ORIGIN,
            "POST",
            &erase_path(),
            erase_body(created, Some(&held_hash())),
            None,
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&other), (403, json!("permission_missing")));
    assert!(no_head(&other));
    let stale = erase_held(&replay, "2026-01-01T00:30:00.000Z").await;
    assert_eq!(code_of(&stale), (401, json!("stale_timestamp")));
    assert!(no_head(&stale));
    assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 1));
    assert_eq!(record_of(&replay).await, None);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_conflict_at_a_failing_account_carries_the_held_copy() {
    // At an account that answers the notice, its mark lost or ahead of its state, a `409`
    // carries `current: { "created", "identity": <the signed doc held> }`; at a staged one
    // holding none, `identity: null`. Then the erasure naming the copy goes through, signed with the service key,
    // without a head (Switch wire 7.4.16, 7.3 Table 2).
    let held_copy = named(
        &vectors("documents.json")["documents"],
        "alice identity.json",
    )["signed"]
        .clone();
    for lost in [true, false] {
        let Some(replay) = replay().await else { return };
        serve_alice(&replay).await;
        let at = hash_vector_time();
        set_time(&replay.clock, &at);
        if lost {
            lose_alice_mark(&replay);
        } else {
            replay
                .marks
                .advance(
                    &alice_id(),
                    keeping_count(&replay.marks, &alice_id(), head_at(50)).await,
                    service_public(&replay),
                    mark_created_at(&replay, &alice_id()).await,
                )
                .await
                .expect("the mark ahead");
        }
        let service = reopened(&replay);
        let apps = service
            .handle(signer_request("GET", &apps_path(), Vec::new(), ms(&at)))
            .await;
        let reason = if lost { "mark_lost" } else { "behind" };
        assert_eq!(
            code_of(&apps),
            (503, json!("recovery_required")),
            "{reason}"
        );
        assert_eq!(body(&apps)["current"]["reason"], json!(reason));
        let older = doc_hash("alice identity.json, first delivery (version 1)");
        let created = rfc3339(creation_time(&replay, &alice_id()).await.expect("created"));
        for hash in [None, Some(older)] {
            let answer = service
                .handle(erasure(&replay, hash.as_ref(), ms(&at)).await)
                .await;
            assert_eq!(code_of(&answer), (409, json!("conflict")), "{reason}");
            assert!(no_head(&answer), "{reason}");
            assert_eq!(
                body(&answer)["current"],
                json!({ "created": created, "identity": held_copy }),
                "{reason}"
            );
        }
        assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 1));
        let request = erasure(&replay, Some(&held_hash()), ms(&at)).await;
        let sent = signed_sent(&request);
        let answer = service.handle(request).await;
        assert_eq!(answer.status, 200, "{reason}: {}", text(&answer));
        assert!(no_head(&answer));
        assert!(signed_with(&answer, &service_public(&replay), &sent));
        assert!(all_gone(&replay).await, "{reason}");
        assert_eq!(mark_of(&replay, &alice_id()).await, MarkRead::Missing);
        replay.db.drop_database().await.expect("drop");
    }
    // A staged account holding no document, its mark lost: failing, and the copy is `null`.
    let Some(replay) = replay().await else { return };
    let at = ms(&enroll_alice(&replay).await) + 1000;
    lose_alice_mark(&replay);
    let service = reopened(&replay);
    let answer = service
        .handle(erasure(&replay, Some(&held_hash()), at).await)
        .await;
    assert_eq!(code_of(&answer), (409, json!("conflict")));
    assert!(no_head(&answer));
    let created = rfc3339(creation_time(&replay, &alice_id()).await.expect("created"));
    assert_eq!(
        body(&answer)["current"],
        json!({ "created": created, "identity": null })
    );
    assert_eq!(
        service
            .handle(erasure(&replay, None, at).await)
            .await
            .status,
        200
    );
    replay.db.drop_database().await.expect("drop");
}

/// alice's identity lost here: a mark recording a head created at `created`, no account,
/// no erasure's record (Switch wire 7.3, Table 1).
async fn lost_identity(replay: &Replay, created: &str) {
    let written = replay
        .marks
        .write_anew(
            &alice_id(),
            at_head(head_at(2)),
            service_public(replay),
            ms(created),
        )
        .await
        .expect("mark");
    assert!(matches!(
        written,
        pubky_switch::marks::MarkWrite::Written(_)
    ));
}

#[tokio::test]
async fn test_erase_at_a_lost_identity_writes_the_record_and_deletes_the_mark() {
    // A lost identity answers the notice; the signer's erasure goes through whatever it
    // names: `200 { "erased": true }`, signed with the key in the mark, no head; the record
    // is written, the mark deleted, and afterwards every call gets the not-hosted `404`
    // (Switch wire 7.4.16, 7.3 Tables 2 and 3).
    let Some(replay) = replay().await else { return };
    let created = "2026-01-01T00:00:00.000Z";
    let now = "2026-01-01T00:01:00.000Z";
    lost_identity(&replay, created).await;
    set_time(&replay.clock, now);
    let apps = replay
        .service
        .handle(signer_request_at_creation(
            "GET",
            &apps_path(),
            Vec::new(),
            ms(now),
            Some(ms(created)),
        ))
        .await;
    assert_eq!(code_of(&apps), (503, json!("recovery_required")));
    assert_eq!(body(&apps)["current"]["reason"], json!("behind"));
    let request = erasure(&replay, Some(&[9; 32]), ms(now)).await;
    let sent = signed_sent(&request);
    let answer = replay.service.handle(request).await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    assert_eq!(answer.body.as_slice(), br#"{"erased":true}"#);
    assert!(no_head(&answer));
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    assert_eq!(record_of(&replay).await, Some(ms(now)));
    assert_eq!(mark_of(&replay, &alice_id()).await, MarkRead::Missing);
    not_hosted_to(
        &replay,
        &replay.service,
        signer_request_at_creation("GET", &apps_path(), Vec::new(), ms(now), Some(ms(created))),
        "signer read",
    )
    .await;
    not_hosted_to(
        &replay,
        &replay.service,
        erasure(&replay, None, ms(now)).await,
        "erasure again",
    )
    .await;
    replay.db.drop_database().await.expect("drop");
}

/// Wait until `n` backends of the test database wait for a lock.
async fn lock_waiters(options: &sqlx::postgres::PgConnectOptions, n: i64) {
    let mut watcher = sqlx::PgConnection::connect_with(options)
        .await
        .expect("conn");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
             AND datname = current_database()",
        )
        .fetch_one(&mut watcher)
        .await
        .expect("count");
        if count >= n {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{count} waiting, not {n}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn test_erase_answer_waits_for_the_deletion_to_commit() {
    // The order of Table 3 (Switch wire 7.3, 7.4.16): while the deletion waits to commit, the
    // record is already durable in the ledger, the mark is still there, and no answer has
    // left; once it commits, the mark goes and the answer is released.
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = hash_vector_time();
    set_time(&replay.clock, &at);
    // A row of alice's state held, so the deletion's cascade waits for it.
    let mut holder = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("begin");
    sqlx::query("SELECT 1 FROM enrollment_answers WHERE account_id = $1 FOR UPDATE")
        .bind(alice_id())
        .execute(&mut holder)
        .await
        .expect("hold");
    let answered = AtomicBool::new(false);
    let options = replay.db.options().clone();
    let (answer, ()) = tokio::join!(
        async {
            let answer = erase_held(&replay, &at).await;
            answered.store(true, Ordering::SeqCst);
            answer
        },
        async {
            lock_waiters(&options, 1).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(
                !answered.load(Ordering::SeqCst),
                "no answer before the commit"
            );
            assert!(
                replay
                    .key_dir()
                    .join("accounts/erasure-attempts")
                    .join(alice_id())
                    .exists(),
                "the attempt first, durably"
            );
            assert_eq!(
                durable_record(&replay),
                None,
                "no completed authority before deletion"
            );
            assert!(
                matches!(
                    replay.marks.read(&alice_id()).await.expect("live mark"),
                    MarkRead::Mark(_)
                ),
                "the mark after the commit"
            );
            assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 1));
            sqlx::query("COMMIT")
                .execute(&mut holder)
                .await
                .expect("commit");
        }
    );
    assert_eq!(answer.status, 200, "{}", text(&answer));
    assert!(all_gone(&replay).await);
    assert_eq!(mark_of(&replay, &alice_id()).await, MarkRead::Missing);
    holder.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_deletion_that_doesnt_commit_withdraws_the_record() {
    // The deletion doesn't commit: `503 unavailable`, signed with the service key, without a
    // head; the record is taken back, the mark and every row stay, and the account still
    // serves; the retry erases (Switch wire 7.4.16 Order, 7.3 Table 3).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for statement in [
        "CREATE FUNCTION refuse_erasure() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'refused'; END $$",
        "CREATE CONSTRAINT TRIGGER refuse_erasure AFTER DELETE ON accounts \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_erasure()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    let before = rows(&replay, &alice_id()).await;
    let mark = held_mark(&replay, &alice_id()).await;
    let at = revoke_time();
    let request = erasure(&replay, Some(&held_hash()), ms(&at)).await;
    let sent = signed_sent(&request);
    let answer = replay.service.handle(request).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    assert_eq!(rows(&replay, &alice_id()).await, before);
    assert_eq!(record_of(&replay).await, None, "the record is withdrawn");
    assert_eq!(durable_record(&replay), None, "and its file");
    assert_eq!(held_mark(&replay, &alice_id()).await, mark);
    let apps = replay
        .service
        .handle(signer_request("GET", &apps_path(), Vec::new(), ms(&at)))
        .await;
    assert_eq!(apps.status, 200, "still serves: {}", text(&apps));
    sqlx::query("DROP TRIGGER refuse_erasure ON accounts")
        .execute(&mut conn)
        .await
        .expect("drop trigger");
    conn.close().await.expect("close");
    assert_eq!(erase_held(&replay, &at).await.status, 200);
    assert_eq!(record_of(&replay).await, Some(ms(&at)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_record_that_cant_be_written_deletes_nothing() {
    // The record comes first (Switch wire 7.3, Table 3): where the ledger can't take it, the
    // answer is `503 unavailable`, signed, without a head, and nothing is deleted, the mark
    // included; once it can, the retry erases.
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = hash_vector_time();
    set_time(&replay.clock, &at);
    let before = rows(&replay, &alice_id()).await;
    let mark = held_mark(&replay, &alice_id()).await;
    let ledger = replay.key_dir().join("accounts").join("erasure-attempts");
    set_read_only(&ledger, true);
    let request = erasure(&replay, Some(&held_hash()), ms(&at)).await;
    let sent = signed_sent(&request);
    let answer = replay.service.handle(request).await;
    set_read_only(&ledger, false);
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    assert_eq!(rows(&replay, &alice_id()).await, before);
    assert_same_but_floor(held_mark(&replay, &alice_id()).await, mark);
    // A new authenticated retry performs the deletion; no completed record was published.
    let retry = erase_held(&replay, &at).await;
    assert_eq!(retry.status, 200, "{}", text(&retry));
    assert!(all_gone(&replay).await);
    // Either way the record is durable before the account goes.
    assert!(durable_record(&replay).is_some());
    replay.db.drop_database().await.expect("drop");
}

/// `held` is `mark` but for its time floor, which a refused erasure's stamp raises where it
/// passes it (Switch wire 7.3, "Time base").
fn assert_same_but_floor(
    held: pubky_switch::marks::AccountMark,
    mark: pubky_switch::marks::AccountMark,
) {
    assert!(
        held.time_floor_ms >= mark.time_floor_ms,
        "the floor never goes back"
    );
    assert_eq!(
        pubky_switch::marks::AccountMark {
            time_floor_ms: mark.time_floor_ms,
            ..held
        },
        mark
    );
}

/// alice's erasure's record as the mark store's files hold it, read by a view opened now.
fn durable_record(replay: &Replay) -> Option<u64> {
    pubky_switch::marks::MarkView::open(replay.key_dir())
        .expect("mark store view")
        .erasure(&alice_id())
        .expect("read erasure record")
}

#[tokio::test]
async fn test_erase_under_a_stale_instance_lock_deletes_nothing() {
    // The erasure deletes a mark: a service whose instance lock is stale refuses it with
    // `503 unavailable`, without a head, writing no record and deleting nothing (Switch spec
    // 6.5, wire 7.3); a service whose lock is fresh erases.
    use pubky_switch::store::{LockFreshness, LockTiming};
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = hash_vector_time();
    set_time(&replay.clock, &at);
    let before = rows(&replay, &alice_id()).await;
    let timing = LockTiming::checking_every(Duration::from_secs(1));
    let stale = replay
        .restarted_with(pubky_switch::limits::Limits::default())
        .with_lock_freshness(LockFreshness::confirmed_ago(
            Duration::from_secs(60),
            timing,
        ));
    let answer = stale
        .handle(erasure(&replay, Some(&held_hash()), ms(&at)).await)
        .await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    assert_eq!(rows(&replay, &alice_id()).await, before);
    assert_eq!(record_of(&replay).await, None);
    assert!(matches!(
        mark_of(&replay, &alice_id()).await,
        MarkRead::Mark(_)
    ));
    let fresh = replay
        .restarted_with(pubky_switch::limits::Limits::default())
        .with_lock_freshness(LockFreshness::confirmed_ago(Duration::ZERO, timing));
    let answer = fresh
        .handle(erasure(&replay, Some(&held_hash()), ms(&at)).await)
        .await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    replay.db.drop_database().await.expect("drop");
}

/// `first`, then `second`, queued in that order behind a hold on alice's account row, and
/// answered once the hold ends: so they run one after the other, as two requests that come
/// at the same moment do.
async fn queued(
    replay: &Replay,
    first: impl std::future::Future<Output = SwitchResponse>,
    second: impl std::future::Future<Output = SwitchResponse>,
) -> (SwitchResponse, SwitchResponse) {
    let mut holder = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("begin");
    sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(alice_id())
        .execute(&mut holder)
        .await
        .expect("lock");
    let options = replay.db.options().clone();
    let (first, (second, ())) = tokio::join!(first, async {
        lock_waiters(&options, 1).await;
        tokio::join!(second, async {
            lock_waiters(&options, 2).await;
            sqlx::query("COMMIT")
                .execute(&mut holder)
                .await
                .expect("commit");
        })
    });
    (first, second)
}

/// An invite code that expired at `at`, for the minute's sweep to drop, and the sweep due
/// at the next request.
async fn expired_invite(replay: &Replay, at: &str) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("UPDATE accounts SET swept_at_ms = NULL WHERE id = $1")
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("due");
    sqlx::query(
        "INSERT INTO invite_codes (account_id, code_hash, max_uses, writer, expires_at_ms) \
         VALUES ($1, decode(repeat('ab', 32), 'hex'), 1, \
         decode(repeat('cd', 16), 'hex'), $2)",
    )
    .bind(alice_id())
    .bind(i64::try_from(ms(at)).expect("ms"))
    .execute(&mut conn)
    .await
    .expect("invite");
    conn.close().await.expect("close");
}

#[tokio::test]
async fn test_erase_conflict_covers_the_sweep_it_committed() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    expired_invite(&replay, &at).await;
    log_swept_invite_codes(&replay).await;
    let before = held_mark(&replay, &alice_id()).await;

    let answer = erase(&replay, None, &at).await;
    assert_eq!(code_of(&answer), (409, json!("conflict")));
    assert!(no_head(&answer));
    assert_eq!(swept_invite_codes(&replay).await, 1);
    let after = held_mark(&replay, &alice_id()).await;
    assert_eq!(after.head(), before.head());
    assert_eq!(after.state_version, before.state_version + 1);
    assert_eq!(
        state_version_of(&replay, &alice_id()).await,
        after.state_version
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_and_a_sweep_at_the_same_moment_run_one_after_the_other() {
    // A request that sweeps and the erasure, at the same moment, in either order: each
    // takes the account's lock, so one runs after the other. A sweep before the erasure is
    // answered, and the erasure then deletes everything; a sweep after it finds no account
    // and gets the not-hosted `404` (Switch wire 7.3 step 4, 7.4.16).
    for sweep_first in [true, false] {
        let Some(replay) = replay().await else { return };
        replay_chain_through_revoke(&replay).await;
        let at = revoke_time();
        expired_invite(&replay, &at).await;
        log_swept_invite_codes(&replay).await;
        let apps = signer_request("GET", &apps_path(), Vec::new(), ms(&at));
        let sent = Sent::of(&apps);
        let apps = replay.service.handle(apps);
        let (swept, erased) = if sweep_first {
            queued(&replay, apps, erase_held(&replay, &at)).await
        } else {
            let (erased, swept) = queued(&replay, erase_held(&replay, &at), apps).await;
            (swept, erased)
        };
        assert_eq!(erased.status, 200, "{}", text(&erased));
        if sweep_first {
            assert_eq!(swept.status, 200, "{}", text(&swept));
        } else {
            assert_not_hosted(&replay, &swept, &sent, "the sweep after");
        }
        assert!(all_gone(&replay).await, "sweep first: {sweep_first}");
        // A sweep ran before the erasure took the account: whichever request came first
        // swept the expired code at its step 4.
        assert_eq!(
            swept_invite_codes(&replay).await,
            1,
            "sweep first: {sweep_first}"
        );
        replay.db.drop_database().await.expect("drop");
    }
}

/// A push key alice's erasure left owed deleting (Switch wire 8.1): made in the key store,
/// and owed in `erased_keys`.
async fn owed_push_key(replay: &Replay) -> KeyId {
    replay
        .marks
        .record_erasure(&alice_id(), 7)
        .await
        .expect("completed erasure");
    let id = KeyId::random().expect("id");
    replay.keys.generate_as(&id).await.expect("key");
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("INSERT INTO erased_keys (key_id, account_id, erased_at_ms) VALUES ($1, $2, 7)")
        .bind(id.as_str())
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("owed");
    conn.close().await.expect("close");
    id
}

/// How many push keys are owed deleting.
async fn owed_count(replay: &Replay) -> i64 {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM erased_keys")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    conn.close().await.expect("close");
    left
}

#[tokio::test]
async fn test_erase_owed_keys_swept_later() {
    // A push key an erasure owes deleting, left by a key store failure or a crash, goes at
    // the next sweep, and its row with it (Switch wire 7.4.16, 8.1).
    let Some(replay) = replay().await else { return };
    let key = owed_push_key(&replay).await;
    assert!(replay.keys.public_key(&key).await.is_ok());
    assert_eq!(replay.service.sweep_erased_keys().await, Some(Vec::new()));
    assert_eq!(owed_count(&replay).await, 0);
    assert!(replay.keys.public_key(&key).await.is_err());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_owed_keys_swept_at_start() {
    // A push key an erasure left owed goes when a service starts (Switch wire 7.4.16, 8.1).
    let Some(replay) = replay().await else { return };
    let key = owed_push_key(&replay).await;
    let _started = Service::start(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        replay.marks.clone(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    )
    .await;
    assert_eq!(owed_count(&replay).await, 0);
    assert!(replay.keys.public_key(&key).await.is_err());
    replay.db.drop_database().await.expect("drop");
}

/// alice's account as a database restored from a backup taken before its erasure holds it
/// (Switch spec 6.5): the database as it was, and the mark store as the erasure left it, its
/// record a minute after the account was created and her mark deleted. The time recorded.
async fn restored_after_erasure(replay: &Replay) -> u64 {
    let created = created_at(replay).await.expect("the account");
    let erased_at = created + 60_000;
    replay
        .marks
        .record_erasure(&alice_id(), erased_at)
        .await
        .expect("ledger");
    replay.marks.delete(&alice_id()).await.expect("mark");
    erased_at
}

/// A call, made at a service time.
type CallAt<'a> = dyn Fn(&str) -> SwitchRequest + 'a;

#[tokio::test]
async fn test_erase_restored_account_is_erased_again_before_any_call_is_served() {
    // A database restored from before an erasure brings the account back; the first call to
    // it, whatever it is, erases it again before anything is served or signed, and is
    // answered as for an account the service doesn't host (Switch spec 6.5, wire 7.3 Table
    // 1, first row). Each call on a restore of its own, so every path's check is tried.
    let keys = vectors("keys.json");
    let id = alice_id();
    let calls: Vec<(&str, Box<CallAt>)> = vec![
        (
            "public read",
            Box::new(|_| {
                request(
                    "GET",
                    &format!("/v1/{}/identity", alice_id()),
                    &[],
                    Vec::new(),
                )
            }),
        ),
        (
            "signer read",
            Box::new(|at| signer_request("GET", &apps_path(), Vec::new(), ms(at))),
        ),
        (
            "signer delivery",
            Box::new(|at| {
                signer_request(
                    "PUT",
                    &format!("/v1/{}/identity", alice_id()),
                    b"{}".to_vec(),
                    ms(at),
                )
            }),
        ),
        (
            "signer erasure",
            Box::new(|at| erasure_naming(Some(ms(&enrolled_time())), Some(&held_hash()), ms(at))),
        ),
        (
            "own app feed",
            Box::new(|at| {
                app_request(
                    app(&keys, "wallet"),
                    "GET",
                    &format!("/v1/{}/feed?wait=25", alice_id()),
                    Vec::new(),
                    ms(at),
                )
            }),
        ),
        (
            "own app batch",
            Box::new(|at| {
                let body = pubky_switch_core::ops::OpsRequest::new(
                    &[],
                    Some(pubky_switch_core::ops::Position {
                        generation: 1,
                        seq: 4,
                    }),
                )
                .to_json();
                app_request(
                    app(&keys, "wallet"),
                    "POST",
                    &format!("/v1/{}/ops", alice_id()),
                    body,
                    ms(at),
                )
            }),
        ),
        (
            "own app push",
            Box::new(|at| {
                app_request(
                    app(&keys, "wallet"),
                    "PUT",
                    &format!("/v1/{}/push", alice_id()),
                    b"{}".to_vec(),
                    ms(at),
                )
            }),
        ),
        (
            "inbox append from another identity",
            Box::new(|at| {
                other_request(
                    "shop",
                    ORIGIN,
                    "POST",
                    &format!("/v1/{}/inbox", alice_id()),
                    b"{}".to_vec(),
                    None,
                    ms(at),
                )
            }),
        ),
        (
            "directory read from another identity",
            Box::new(|at| {
                other_request(
                    "shop",
                    ORIGIN,
                    "GET",
                    &format!("/v1/{}/directory", alice_id()),
                    Vec::new(),
                    None,
                    ms(at),
                )
            }),
        ),
        (
            "connect request from another identity",
            Box::new(|at| {
                other_request(
                    "shop",
                    ORIGIN,
                    "POST",
                    &format!("/v1/{}/connect", alice_id()),
                    b"{}".to_vec(),
                    None,
                    ms(at),
                )
            }),
        ),
    ];
    for (name, call) in &calls {
        let Some(replay) = replay().await else { return };
        replay_chain_through_revoke(&replay).await;
        let erased_at = restored_after_erasure(&replay).await;
        not_hosted_to(&replay, &replay.service, call(&revoke_time()), name).await;
        assert!(all_gone(&replay).await, "{name}: the state is erased again");
        // The ledger keeps the erasure, so a later restore is erased again too.
        assert_eq!(
            replay.marks.erasure(&id).await.expect("ledger"),
            Some(erased_at),
            "{name}"
        );
        replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_erase_restored_account_is_erased_again_at_start() {
    // The service the binary starts erases every restored account the ledger names before
    // it takes a request (Switch spec 6.5, wire 7.3 Table 1); an account the ledger doesn't
    // name stays.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let bob = serve_bob(&replay).await;
    restored_after_erasure(&replay).await;
    assert!(!all_gone(&replay).await, "restored");
    let service = started(&replay, None).await;
    assert!(all_gone(&replay).await, "erased before any request");
    assert_eq!(rows(&replay, &bob).await[0], ("accounts", 1), "bob stays");
    not_hosted_to(
        &replay,
        &service,
        signer_request("GET", &apps_path(), Vec::new(), ms(&revoke_time())),
        "signer read",
    )
    .await;
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_restored_account_erased_again_keeps_a_later_accounts_mark() {
    // A restored account erased again, at a request and at start, deletes only a mark created
    // at or before the erasure's record: the mark of a later account, created after it, stays
    // (Switch wire 7.3, Table 3), and the identity is then judged by the row "None" with it:
    // a (0, 0) mark is not hosted (Table 1).
    for at_start in [false, true] {
        let Some(replay) = replay().await else { return };
        replay_chain_through_revoke(&replay).await;
        let erased_at = restored_after_erasure(&replay).await;
        replay
            .marks
            .create_zero(&alice_id(), service_public(&replay), erased_at + 1000)
            .await
            .expect("a later mark");
        let request = signer_request_at_creation(
            "GET",
            &apps_path(),
            Vec::new(),
            ms(&revoke_time()),
            Some(erased_at + 1000),
        );
        if at_start {
            let service = started(&replay, None).await;
            assert!(all_gone(&replay).await, "erased at start");
            not_hosted_to(&replay, &service, request, "after the start").await;
        } else {
            not_hosted_to(&replay, &replay.service, request, "at the request").await;
        }
        assert!(all_gone(&replay).await, "at start: {at_start}");
        let mark = held_mark(&replay, &alice_id()).await;
        assert_eq!(mark.created_at_ms, erased_at + 1000, "at start: {at_start}");
        replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_erase_restored_account_whose_mark_is_still_held_is_erased_with_it() {
    // A restored account whose mark is still there, created at or before the erasure's
    // record (its deletion failed after the erasure): erased again at the first call, and
    // the mark the record covers deleted with it (Switch spec 6.5, wire 7.3 Tables 1 and 3).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let created = created_at(&replay).await.expect("the account");
    replay
        .marks
        .record_erasure(&alice_id(), created + 60_000)
        .await
        .expect("ledger");
    assert!(held_mark(&replay, &alice_id()).await.created_at_ms <= created + 60_000);
    not_hosted_to(
        &replay,
        &replay.service,
        request(
            "GET",
            &format!("/v1/{}/identity", alice_id()),
            &[],
            Vec::new(),
        ),
        "public read",
    )
    .await;
    assert!(all_gone(&replay).await, "erased again");
    assert_eq!(mark_of(&replay, &alice_id()).await, MarkRead::Missing);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_restored_account_then_enrollment_starts_a_new_account() {
    // An enrollment of a restored account's identity erases the old account first and makes
    // a new one, created after the ledger's erasure time, which no later check takes for a
    // restored one (Switch spec 6.5, wire 3.7).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let erased_at = restored_after_erasure(&replay).await;
    replay.clock.set_wall_ms(erased_at);
    let discovery = signer_request(
        "GET",
        &format!("/v1/{}/account", alice_id()),
        Vec::new(),
        erased_at,
    );
    let refused = replay.service.handle(discovery).await;
    assert_eq!(code_of(&refused), (503, json!("unavailable")));
    assert!(
        created_at(&replay).await.is_some(),
        "discovery is read-only"
    );
    let cleanup = request(
        "GET",
        &format!("/v1/{}/identity", alice_id()),
        &[],
        Vec::new(),
    );
    not_hosted_to(
        &replay,
        &replay.service,
        cleanup,
        "covered restored account",
    )
    .await;
    let at = erased_at + 1;
    replay.clock.set_wall_ms(at);
    let created = enroll_named(&replay, 5, at).await;
    assert!(created > erased_at, "created after the erasure");
    // Nothing of the old account: only the new account's row and its enrollment answer.
    let held: Vec<_> = rows(&replay, &alice_id())
        .await
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(table, _)| table)
        .collect();
    assert_eq!(held, ["accounts", "enrollment_answers"]);
    assert_eq!(held_mark(&replay, &alice_id()).await.created_at_ms, created);
    // A start and a call later, it is still there: staged, as a new account is.
    let service = started(&replay, None).await;
    let apps = service
        .handle(signer_request_at_creation(
            "GET",
            &apps_path(),
            Vec::new(),
            at,
            Some(created),
        ))
        .await;
    assert_eq!(code_of(&apps), (503, json!("staged")));
    assert_eq!(created_at(&replay).await, Some(created));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_account_enrolled_after_its_erasure_is_kept() {
    // A backward wall clock cannot create a lifetime before its erasure. After trusted
    // time catches up, the new account survives startup and ordinary requests
    // (Switch account binding 2.2 and 3.1).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let ahead = "2026-01-01T00:04:00.000Z";
    set_time(&replay.clock, ahead);
    assert_eq!(erase_held(&replay, ahead).await.status, 200);
    let erased_at = record_of(&replay).await.expect("recorded");
    let at = enrolled_time();
    assert!(ms(&at) < erased_at, "enrolled at an earlier time");
    set_time(&replay.clock, &at);
    let query = signer_request(
        "GET",
        &format!("/v1/{}/account", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let refused = replay.service.handle(query).await;
    assert_eq!(code_of(&refused), (503, json!("unavailable")));
    assert_eq!(created_at(&replay).await, None);
    assert_eq!(record_of(&replay).await, Some(erased_at));
    replay.clock.set_wall_ms(erased_at + 1);
    let created = enroll_named(&replay, 5, erased_at + 1).await;
    assert_eq!(created, erased_at + 1);
    let service = started(&replay, None).await;
    let apps = service
        .handle(signer_request_at_creation(
            "GET",
            &apps_path(),
            Vec::new(),
            erased_at + 1,
            Some(created),
        ))
        .await;
    assert_eq!(code_of(&apps), (503, json!("staged")));
    assert_eq!(created_at(&replay).await, Some(created), "kept");
    assert_eq!(held_mark(&replay, &alice_id()).await.created_at_ms, created);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_restored_account_is_never_served_while_the_mark_store_cant_be_read() {
    // Without the mark store the verdict is unknown: every call is `503 unavailable`, without
    // a head, and nothing is erased; once the store reads again, the account is erased again
    // (Switch spec 6.5, wire 7.3 Tables 1 and 2).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    restored_after_erasure(&replay).await;
    let store_id = replay.key_dir().join("accounts").join("store-id");
    let saved = std::fs::read(&store_id).expect("store id");
    std::fs::remove_file(&store_id).expect("remove the store id");
    let service = reopened(&replay);
    let keys = vectors("keys.json");
    let at = revoke_time();
    let feed = || {
        app_request(
            app(&keys, "wallet"),
            "GET",
            &format!("/v1/{}/feed", alice_id()),
            Vec::new(),
            ms(&at),
        )
    };
    let request = feed();
    let sent = signed_sent(&request);
    let answer = service.handle(request).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    assert!(signed_with(&answer, &service_public(&replay), &sent));
    assert!(!all_gone(&replay).await, "nothing erased yet");
    std::fs::write(&store_id, saved).expect("restore the store id");
    not_hosted_to(&replay, &service, feed(), "once it reads").await;
    assert!(all_gone(&replay).await);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_leftover_mark_is_deleted_at_a_request_and_at_start() {
    // A mark with no account, created at or before an erasure's record for the identity, is
    // a leftover: the identity is not hosted, and the mark is deleted at a later request and
    // at start. A mark created after the record is a later account's: the identity is lost,
    // and its mark stays (Switch wire 7.3, Table 1).
    let erased_at = ms("2026-01-01T00:00:30.000Z");
    let now = "2026-01-01T00:01:00.000Z";
    for at_start in [false, true] {
        for leftover in [true, false] {
            let name = format!("at start: {at_start}, leftover: {leftover}");
            let Some(replay) = replay().await else { return };
            replay
                .marks
                .record_erasure(&alice_id(), erased_at)
                .await
                .expect("record");
            let created = if leftover {
                erased_at - 1000
            } else {
                erased_at + 1000
            };
            replay
                .marks
                .write_anew(
                    &alice_id(),
                    at_head(head_at(2)),
                    service_public(&replay),
                    created,
                )
                .await
                .expect("mark");
            set_time(&replay.clock, now);
            let request =
                signer_request_at_creation("GET", &apps_path(), Vec::new(), ms(now), Some(created));
            let service = if at_start {
                started(&replay, None).await
            } else {
                replay.restarted_with(pubky_switch::limits::Limits::default())
            };
            if at_start {
                assert_eq!(
                    matches!(mark_of(&replay, &alice_id()).await, MarkRead::Missing),
                    leftover,
                    "{name}: deleted at start"
                );
            }
            if leftover {
                not_hosted_to(&replay, &service, request, &name).await;
                assert_eq!(
                    mark_of(&replay, &alice_id()).await,
                    MarkRead::Missing,
                    "{name}"
                );
            } else {
                let answer = service.handle(request).await;
                assert_eq!(
                    code_of(&answer),
                    (503, json!("recovery_required")),
                    "{name}"
                );
                assert_eq!(
                    held_mark(&replay, &alice_id()).await.created_at_ms,
                    created,
                    "{name}"
                );
            }
            replay.db.drop_database().await.expect("drop");
        }
    }
}

#[tokio::test]
async fn test_erase_ledger_forgets_an_erasure_once_its_backups_aged_out() {
    // With `keys.backup_retention_days`, a start forgets the erasures older than that by
    // trusted time and keeps the younger; without the setting, or without trusted time, it
    // forgets none (Switch spec 6.5).
    let Some(replay) = replay().await else { return };
    let day = 24 * 60 * 60 * 1000;
    let now = "2026-03-01T00:00:00.000Z";
    set_time(&replay.clock, now);
    for (identity, age) in [("aaa", 3 * day), ("bbb", day / 2)] {
        replay
            .marks
            .record_erasure(identity, ms(now) - age)
            .await
            .expect("record");
    }
    let held = || async {
        replay
            .marks
            .erasures()
            .await
            .expect("ledger")
            .into_iter()
            .map(|(identity, _)| identity)
            .collect::<Vec<_>>()
    };
    let _ = started(&replay, None).await;
    assert_eq!(
        held().await,
        ["aaa", "bbb"],
        "kept for good without the setting"
    );
    let untrusted = Arc::new(pubky_switch::time::TrustedTime::new(
        pubky_switch::time::TrustedTimeConfig {
            required: true,
            ..pubky_switch::time::TrustedTimeConfig::default()
        },
        replay.clock.clone(),
    ));
    let _ = Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        replay.marks.clone(),
        untrusted,
        pubky_switch::limits::Limits::default(),
    )
    .with_backup_retention_days(Some(1))
    .started()
    .await;
    assert_eq!(held().await, ["aaa", "bbb"], "kept without trusted time");
    let _ = started(&replay, Some(1)).await;
    assert_eq!(held().await, ["bbb"], "the erasure older than a day goes");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_aged_record_goes_only_after_its_leftover_mark() {
    // Forgetting an aged erasure (after each erasure, by trusted time) deletes the leftover
    // mark its record covers first; where that mark can't be deleted, the record stays for
    // the next pass, so no record goes while a mark it covers is left (Switch wire 7.3,
    // Table 3: the operator drops an erasure's record).
    let day = 24 * 60 * 60 * 1000;
    for deletable in [true, false] {
        let Some(replay) = replay().await else { return };
        serve_alice(&replay).await;
        let at = hash_vector_time();
        set_time(&replay.clock, &at);
        // alice's time floor a minute past `at`, as a request at `at` leaves it: the
        // erasure's stamp, the restarted run's first at alice, is the floor and raises
        // nothing, so it writes no mark where the mark store is read-only (Switch wire 7.3,
        // "Time base").
        let floor_ms = ms(&at) + pubky_switch::marks::TIME_FLOOR_STEP_MS;
        replay
            .marks
            .raise_floor(
                &alice_id(),
                mark_created_at(&replay, &alice_id()).await,
                floor_ms,
            )
            .await
            .expect("floor");
        // bob's erasure three days ago, its mark left over from an account created before.
        let bob = bob_id();
        replay
            .marks
            .record_erasure(&bob, ms(&at) - 3 * day)
            .await
            .expect("record");
        replay
            .marks
            .create_zero(&bob, service_public(&replay), ms(&at) - 4 * day)
            .await
            .expect("leftover");
        let service = replay
            .restarted_with(pubky_switch::limits::Limits::default())
            .with_backup_retention_days(Some(1));
        let marks_dir = replay.key_dir().join("accounts").join("marks");
        if !deletable {
            set_read_only(&marks_dir, true);
        }
        let answer = service
            .handle(erasure(&replay, Some(&held_hash()), ms(&at)).await)
            .await;
        set_read_only(&marks_dir, false);
        assert_eq!(answer.status, 200, "{}", text(&answer));
        let bob_record = replay.marks.erasure(&bob).await.expect("ledger");
        if deletable {
            assert_eq!(mark_of(&replay, &bob).await, MarkRead::Missing);
            assert_eq!(bob_record, None, "the aged record goes after its leftover");
        } else {
            assert!(matches!(mark_of(&replay, &bob).await, MarkRead::Mark(_)));
            assert_eq!(
                bob_record,
                Some(ms(&at) - 3 * day),
                "kept while its leftover stays"
            );
        }
        // Stamped by the restarted run, its first stamp at alice: the time floor.
        assert_eq!(record_of(&replay).await, Some(floor_ms), "alice's is young");
        replay.db.drop_database().await.expect("drop");
    }
}

/// The same request again, byte for byte: a replay of `request`.
fn replayed(request: &SwitchRequest) -> SwitchRequest {
    SwitchRequest {
        route: request.route.clone(),
        method: request.method.clone(),
        path_and_query: request.path_and_query.clone(),
        headers: request.headers.clone(),
        body: request.body.clone(),
        source: request.source,
    }
}

/// An enrollment of alice with `nonce` (a fresh one), signed at `at_ms`, answered `200`; the
/// creation time its answer names, which is the mark's and the account's (Switch wire 3.7).
async fn enroll_named(replay: &Replay, nonce: u8, at_ms: u64) -> u64 {
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            fresh_enrollment(replay, nonce, at_ms).await,
            at_ms,
        ))
        .await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    let named = body(&answer)["created"]
        .as_str()
        .expect("the answer names `created`")
        .to_string();
    let created = ms(&named);
    assert_eq!(named, rfc3339(created), "a time with three fraction digits");
    assert_eq!(held_mark(replay, &alice_id()).await.created_at_ms, created);
    assert_eq!(created_at(replay).await, Some(created));
    created
}

/// The `current` a `409` to an erasure carries.
fn conflict_current(answer: &SwitchResponse) -> Value {
    assert_eq!(
        code_of(answer),
        (409, json!("conflict")),
        "{}",
        text(answer)
    );
    assert!(no_head(answer));
    body(answer)["current"].clone()
}

#[tokio::test]
async fn test_erase_replay_after_reenroll_refused() {
    // An erasure of a staged account names its creation time T1; replayed within its five
    // minutes at a later account of the identity, created at T2 > T1, it is `409 conflict`
    // naming T2, and the later account, its mark and the erasure's record stay as they are
    // (Switch wire 7.4.16, 3.7).
    let Some(replay) = replay().await else { return };
    let at = ms(&enrolled_time());
    set_time(&replay.clock, &enrolled_time());
    let t1 = enroll_named(&replay, 1, at).await;
    let request = erasure_naming(Some(t1), None, at + 60_000);
    let again = replayed(&request);
    let erased = replay.service.handle(request).await;
    assert_eq!(erased.status, 200, "{}", text(&erased));
    let next = record_of(&replay).await.expect("completed erasure") + 1;
    replay.clock.set_wall_ms(next);
    let t2 = enroll_named(&replay, 2, next).await;
    assert!(t2 > t1, "the later account is created later");
    let mark = held_mark(&replay, &alice_id()).await;
    let record = record_of(&replay).await;
    let answer = replay.service.handle(again).await;
    assert_eq!(conflict_current(&answer), json!({ "created": rfc3339(t2) }));
    assert_eq!(created_at(&replay).await, Some(t2), "the account stays");
    assert_eq!(
        held_mark(&replay, &alice_id()).await,
        mark,
        "its mark stays"
    );
    assert_eq!(record_of(&replay).await, record, "the record stays");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_names_creation_time_erases() {
    // At the later account, an erasure naming its own creation time T2 erases it, its
    // record dated no earlier than T2 (Switch wire 7.4.16, 7.3 Table 3).
    let Some(replay) = replay().await else { return };
    let at = ms(&enrolled_time());
    set_time(&replay.clock, &enrolled_time());
    let t1 = enroll_named(&replay, 1, at).await;
    let erased = replay
        .service
        .handle(erasure_naming(Some(t1), None, at + 60_000))
        .await;
    assert_eq!(erased.status, 200, "{}", text(&erased));
    let next = record_of(&replay).await.expect("completed erasure") + 1;
    replay.clock.set_wall_ms(next);
    let t2 = enroll_named(&replay, 2, next).await;
    let answer = replay
        .service
        .handle(erasure_naming(Some(t2), None, at + 60_000))
        .await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    assert!(all_gone(&replay).await);
    assert_eq!(mark_of(&replay, &alice_id()).await, MarkRead::Missing);
    assert!(record_of(&replay).await.expect("recorded") >= t2);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_lost_enrollment_answer_learns_created() {
    // Discovery supplies a lost binding without an incomplete destructive request
    // (Switch account binding 1 and 2).
    let Some(replay) = replay().await else { return };
    let at = ms(&enroll_alice(&replay).await);
    let created = held_mark(&replay, &alice_id()).await.created_at_ms;
    let answer = replay.service.handle(erasure_naming(None, None, at)).await;
    assert_eq!(code_of(&answer), (400, json!("bad_request")));
    assert!(no_head(&answer));
    assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 1));
    assert_eq!(record_of(&replay).await, None);
    let key = pubky_switch_core::keys::IdentityKey::from_secret(hex32(
        &alice(&vectors("keys.json"))["secret_hex"],
    ));
    let observation = account_observation(&replay, &key, at).await;
    let learned = observation
        .verify(&key.public(), ORIGIN)
        .expect("observation")
        .body()
        .created
        .expect("creation");
    assert_eq!(learned, created);
    let answer = replay
        .service
        .handle(erasure_naming(Some(learned), None, at))
        .await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    assert!(all_gone(&replay).await);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_replay_after_erasure_not_hosted() {
    // An erasure replayed before any new enrollment meets the not-hosted `404`, signed with
    // the service key, and changes nothing; replayed at a later account, it is `409 conflict`
    // naming the later account's creation time (Switch wire 7.4.16, 7.3 step 2).
    let Some(replay) = replay().await else { return };
    let at = ms(&enroll_alice(&replay).await);
    let t1 = held_mark(&replay, &alice_id()).await.created_at_ms;
    let request = erasure_naming(Some(t1), None, at + 60_000);
    let first_replay = replayed(&request);
    let second_replay = replayed(&request);
    assert_eq!(replay.service.handle(request).await.status, 200);
    let record = record_of(&replay).await;
    not_hosted_to(&replay, &replay.service, first_replay, "replayed").await;
    assert!(all_gone(&replay).await);
    assert_eq!(mark_of(&replay, &alice_id()).await, MarkRead::Missing);
    assert_eq!(record_of(&replay).await, record, "the record stays");
    let next = record_of(&replay).await.expect("completed erasure") + 1;
    replay.clock.set_wall_ms(next);
    let t2 = enroll_named(&replay, 2, next).await;
    let answer = replay.service.handle(second_replay).await;
    assert_eq!(conflict_current(&answer), json!({ "created": rfc3339(t2) }));
    assert_eq!(created_at(&replay).await, Some(t2));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_wrong_created_conflict() {
    // An erasure naming another creation time, by a millisecond, is `409 conflict` carrying
    // `current.created` at a healthy, a staged, a bounded and a failing account, and at one
    // whose mark is lost, by the account's own creation time. The common conflict has only
    // `current.created`. Nothing is deleted, no record written, the
    // mark kept; the erasure naming the creation time then erases (Switch wire 7.4.16, 7.3
    // Tables 2 and 3).
    for case in ["healthy", "staged", "bounded", "failing", "mark lost"] {
        let Some(replay) = replay().await else { return };
        let (at, hash) = if matches!(case, "staged" | "bounded") {
            (ms(&enroll_alice(&replay).await) + 1000, None)
        } else {
            serve_alice(&replay).await;
            let at = hash_vector_time();
            set_time(&replay.clock, &at);
            (ms(&at), Some(held_hash()))
        };
        match case {
            "bounded" => {
                replay
                    .marks
                    .advance(
                        &alice_id(),
                        keeping_count(&replay.marks, &alice_id(), head_at(2)).await,
                        service_public(&replay),
                        mark_created_at(&replay, &alice_id()).await,
                    )
                    .await
                    .expect("a head in the staged account's mark");
            }
            "failing" => {
                replay
                    .marks
                    .advance(
                        &alice_id(),
                        keeping_count(&replay.marks, &alice_id(), head_at(50)).await,
                        service_public(&replay),
                        mark_created_at(&replay, &alice_id()).await,
                    )
                    .await
                    .expect("the mark ahead");
            }
            "mark lost" => lose_alice_mark(&replay),
            _ => {}
        }
        let service = reopened(&replay);
        let created = if case == "mark lost" {
            created_at(&replay).await.expect("the account's own time")
        } else {
            held_mark(&replay, &alice_id()).await.created_at_ms
        };
        let expected = json!({ "created": rfc3339(created) });
        let before = rows(&replay, &alice_id()).await;
        let mark = mark_of(&replay, &alice_id()).await;
        let answer = service
            .handle(erasure_naming(Some(created + 1), hash.as_ref(), at))
            .await;
        assert_eq!(conflict_current(&answer), expected, "{case}");
        assert_eq!(rows(&replay, &alice_id()).await, before, "{case}");
        assert_eq!(mark_of(&replay, &alice_id()).await, mark, "{case}");
        assert_eq!(record_of(&replay).await, None, "{case}");
        let answer = service
            .handle(erasure_naming(Some(created), hash.as_ref(), at))
            .await;
        assert_eq!(answer.status, 200, "{case}: {}", text(&answer));
        assert!(all_gone(&replay).await, "{case}");
        replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_erase_lost_identity_requires_created() {
    // At a lost identity an erasure naming another creation time than the mark's is `409
    // conflict` carrying only the mark's time, signed with the key in the
    // mark: no record, the mark kept. Naming the mark's time erases: the record, then the
    // mark deleted (Switch wire 7.4.16, 7.3 Tables 2 and 3).
    let Some(replay) = replay().await else { return };
    let created = "2026-01-01T00:00:00.250Z";
    let now = "2026-01-01T00:01:00.000Z";
    lost_identity(&replay, created).await;
    set_time(&replay.clock, now);
    let mark = held_mark(&replay, &alice_id()).await;
    for named in [None, Some(ms(created) + 1), Some(ms(created) - 250)] {
        let request = erasure_naming(named, None, ms(now));
        let sent = signed_sent(&request);
        let answer = replay.service.handle(request).await;
        if named.is_some() {
            assert_eq!(
                conflict_current(&answer),
                json!({ "created": created }),
                "{named:?}"
            );
        } else {
            assert_eq!(code_of(&answer), (400, json!("bad_request")));
            assert!(no_head(&answer));
        }
        assert!(signed_with(&answer, &service_public(&replay), &sent));
        assert_eq!(record_of(&replay).await, None, "{named:?}");
        assert_eq!(held_mark(&replay, &alice_id()).await, mark, "{named:?}");
    }
    let answer = replay
        .service
        .handle(erasure_naming(Some(ms(created)), None, ms(now)))
        .await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    assert_eq!(record_of(&replay).await, Some(ms(now)));
    assert_eq!(mark_of(&replay, &alice_id()).await, MarkRead::Missing);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_created_later_than_taken_over_mark() {
    // Discovery cannot mint authority from a future creation or erasure. Once trusted
    // time passes that floor, an authorized takeover/create is strictly later
    // (Switch account binding 2.2 and 3.1).
    let base = ms(&enrolled_time());
    let ahead = base + 60_000;
    for case in ["lost mark", "(0, 0) mark", "record", "none"] {
        let Some(replay) = replay().await else { return };
        set_time(&replay.clock, &enrolled_time());
        match case {
            "lost mark" => lost_identity(&replay, &rfc3339(ahead)).await,
            "(0, 0) mark" => {
                replay
                    .marks
                    .create_zero(&alice_id(), service_public(&replay), ahead)
                    .await
                    .expect("a (0, 0) mark");
            }
            "record" => {
                replay
                    .marks
                    .record_erasure(&alice_id(), ahead)
                    .await
                    .expect("record");
            }
            _ => {}
        }
        let expected = if case == "none" { base } else { ahead + 1 };
        if case != "none" {
            let before = mark_of(&replay, &alice_id()).await;
            let erasure = record_of(&replay).await;
            let query = signer_request(
                "GET",
                &format!("/v1/{}/account", alice_id()),
                Vec::new(),
                base,
            );
            let sent = Sent::of(&query);
            let answer = replay.service.handle(query).await;
            assert_eq!(code_of(&answer), (503, json!("unavailable")), "{case}");
            assert!(no_head(&answer));
            assert!(signed_with(&answer, &service_public(&replay), &sent));
            assert_eq!(mark_of(&replay, &alice_id()).await, before);
            assert_eq!(record_of(&replay).await, erasure);
            assert_eq!(created_at(&replay).await, None);
            replay.clock.set_wall_ms(expected);
        }
        let created = enroll_named(&replay, 1, expected).await;
        assert_eq!(created, expected, "{case}");
        replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_enroll_replacement_waits_for_the_next_millisecond() {
    // A zero-mark takeover waits until trusted time is strictly above the old creation;
    // retrying the exact signed intent then creates one later lifetime (account binding 3).
    let Some(replay) = replay().await else { return };
    let base = ms(&enrolled_time());
    set_time(&replay.clock, &enrolled_time());
    let mut earlier = enroll_named(&replay, 1, base).await;
    assert_eq!(earlier, base);
    for nonce in [2, 3] {
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(alice_id())
            .execute(&mut conn)
            .await
            .expect("the account's row lost");
        conn.close().await.expect("close");
        let pending = signer_request(
            "POST",
            "/v1/enroll",
            fresh_enrollment(&replay, nonce, earlier).await,
            earlier,
        );
        let retry = replayed(&pending);
        let mark = held_mark(&replay, &alice_id()).await;
        let refused = replay.service.handle(pending).await;
        assert_eq!(code_of(&refused), (503, json!("unavailable")));
        assert_eq!(created_at(&replay).await, None);
        assert_eq!(held_mark(&replay, &alice_id()).await, mark);
        replay.clock.set_wall_ms(earlier + 1);
        let answer = replay.service.handle(retry).await;
        assert_eq!(answer.status, 200, "{}", text(&answer));
        let created = ms(body(&answer)["created"].as_str().expect("created"));
        assert_eq!(created, earlier + 1, "taking the mark over");
        assert_eq!(created_at(&replay).await, Some(created));
        assert_eq!(held_mark(&replay, &alice_id()).await.created_at_ms, created);
        earlier = created;
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_right_after_an_erasure_is_created_after_its_record() {
    // Creation waits until trusted time passes the erasure's floor. The same signed
    // intent then creates the later lifetime, which the old erasure cannot reach
    // (Switch account binding 2.2 and 3; Switch wire 7.3 and 7.4.16).
    let Some(replay) = replay().await else { return };
    let base = ms(&enrolled_time());
    set_time(&replay.clock, &enrolled_time());
    let first = enroll_named(&replay, 1, base).await;
    let request = erasure_naming(Some(first), None, base);
    let again = replayed(&request);
    let erased = replay.service.handle(request).await;
    assert_eq!(erased.status, 200, "{}", text(&erased));
    assert_eq!(record_of(&replay).await, Some(first));
    let pending = signer_request(
        "POST",
        "/v1/enroll",
        fresh_enrollment(&replay, 2, base).await,
        base,
    );
    let retry = replayed(&pending);
    let refused = replay.service.handle(pending).await;
    assert_eq!(code_of(&refused), (503, json!("unavailable")));
    assert_eq!(created_at(&replay).await, None);
    replay.clock.set_wall_ms(base + 1);
    let enrolled = replay.service.handle(retry).await;
    assert_eq!(enrolled.status, 200, "{}", text(&enrolled));
    let later = ms(body(&enrolled)["created"].as_str().expect("created"));
    assert_eq!(later, first + 1);
    let answer = replay.service.handle(again).await;
    assert_eq!(
        conflict_current(&answer),
        json!({ "created": rfc3339(later) })
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erasure_record_not_before_created() {
    // With the time base behind the creation time an erasure names, its record is dated at
    // that creation time, not before: at an account and at a lost identity (Switch wire 7.3,
    // Table 3).
    let base = ms(&enrolled_time());
    let ahead = base + 60_000;
    for lost in [false, true] {
        let Some(replay) = replay().await else { return };
        set_time(&replay.clock, &enrolled_time());
        let created = if lost {
            lost_identity(&replay, &rfc3339(ahead)).await;
            ahead
        } else {
            replay
                .marks
                .create_zero(&alice_id(), service_public(&replay), ahead)
                .await
                .expect("a (0, 0) mark");
            replay.clock.set_wall_ms(ahead + 1);
            enroll_named(&replay, 1, ahead + 1).await
        };
        replay.clock.set_wall_ms(base);
        assert!(created > base, "created after the time base");
        let answer = replay
            .service
            .handle(erasure_naming(Some(created), None, base))
            .await;
        assert_eq!(answer.status, 200, "lost: {lost}: {}", text(&answer));
        assert_eq!(record_of(&replay).await, Some(created), "lost: {lost}");
        replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_erasure_record_drop_under_a_day_refused() {
    // The operator's drop of aged erasures, by trusted time, keeps a record younger than a
    // day whatever `keys.backup_retention_days` says, and drops one older (Switch wire 7.3,
    // Table 3; spec 6.5).
    let Some(replay) = replay().await else { return };
    let day = 24 * 60 * 60 * 1000;
    let now = "2026-03-01T00:00:00.000Z";
    set_time(&replay.clock, now);
    for (identity, age) in [("aaa", 2 * day), ("bbb", day - 1000), ("ccc", 1000)] {
        replay
            .marks
            .record_erasure(identity, ms(now) - age)
            .await
            .expect("record");
    }
    let _ = started(&replay, Some(0)).await;
    let held: Vec<_> = replay
        .marks
        .erasures()
        .await
        .expect("ledger")
        .into_iter()
        .map(|(identity, _)| identity)
        .collect();
    assert_eq!(held, ["bbb", "ccc"], "the records younger than a day stay");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_body_created_required_shape() {
    // An unknown member or a `created` that isn't a time is `400 bad_request`; a body
    // without `created` cannot agree with its required header and is also malformed.
    // Nothing is deleted. A matching body and header erase (Switch account binding 1).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = hash_vector_time();
    set_time(&replay.clock, &at);
    let created = held_mark(&replay, &alice_id()).await.created_at_ms;
    let time = rfc3339(created);
    let hash = pubky_switch_core::enc::b64(&held_hash());
    let before = rows(&replay, &alice_id()).await;
    for body in [
        format!(r#"{{"created":"{time}","identity_hash":"{hash}","x":1}}"#),
        format!(r#"{{"created":"yesterday","identity_hash":"{hash}"}}"#),
        format!(r#"{{"created":"2026-13-01T00:00:00.000Z","identity_hash":"{hash}"}}"#),
        format!(r#"{{"created":{created},"identity_hash":"{hash}"}}"#),
    ] {
        let answer = replay
            .service
            .handle(signer_request(
                "POST",
                &erase_path(),
                body.clone().into_bytes(),
                ms(&at),
            ))
            .await;
        assert_eq!(code_of(&answer), (400, json!("bad_request")), "{body}");
        assert!(no_head(&answer), "{body}");
    }
    let missing = replay
        .service
        .handle(erasure_naming(None, Some(&held_hash()), ms(&at)))
        .await;
    assert_eq!(code_of(&missing), (400, json!("bad_request")));
    assert!(no_head(&missing));
    // Null is also not a valid creation matching the required header.
    let null = replay
        .service
        .handle(signer_request(
            "POST",
            &erase_path(),
            format!(r#"{{"created":null,"identity_hash":"{hash}"}}"#).into_bytes(),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&null), (400, json!("bad_request")));
    assert!(no_head(&null));
    assert_eq!(rows(&replay, &alice_id()).await, before, "nothing deleted");
    assert_eq!(record_of(&replay).await, None);
    let answer = replay
        .service
        .handle(erasure_naming(Some(created), Some(&held_hash()), ms(&at)))
        .await;
    assert_eq!(answer.status, 200, "{}", text(&answer));
    replay.db.drop_database().await.expect("drop");
}

/// Leave an actual authenticated attempt whose deletion and rejection receipt both fail.
/// No completed record exists; a restart must keep this uncertainty (wire 7.3 Table 3).
async fn unresolved_erasure(replay: &Replay) -> Vec<u8> {
    unresolved_erasure_at(replay, false).await
}

async fn unresolved_erasure_at(replay: &Replay, at_commit: bool) -> Vec<u8> {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    for statement in [
        "CREATE FUNCTION refuse_attempt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected receipt failure'; END $$",
        if at_commit {
            "CREATE CONSTRAINT TRIGGER refuse_attempt AFTER INSERT OR UPDATE ON erasure_outcomes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_attempt()"
        } else {
            "CREATE TRIGGER refuse_attempt BEFORE INSERT OR UPDATE ON erasure_outcomes FOR EACH ROW EXECUTE FUNCTION refuse_attempt()"
        },
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    // The receipt write is part of the DELETE transaction. Its rejection rolls back all
    // account rows, and rejecting the attempt cannot itself commit a receipt either.
    let before = rows(replay, &alice_id()).await;
    let answer = erase(replay, Some(&held_hash()), &revoke_time()).await;
    assert_eq!(answer.status, 503);
    assert_eq!(rows(replay, &alice_id()).await, before);
    assert_eq!(durable_record(replay), None);
    let attempt = std::fs::read(
        replay
            .key_dir()
            .join("accounts/erasure-attempts")
            .join(alice_id()),
    )
    .expect("durable attempt");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM erasure_outcomes")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(
        count, 0,
        "no successful or rejected outcome was acknowledged"
    );
    sqlx::query("DROP TRIGGER refuse_attempt ON erasure_outcomes")
        .execute(&mut conn)
        .await
        .expect("drop trigger");
    conn.close().await.expect("close");
    attempt
}

async fn apps_after_reload(replay: &Replay) -> SwitchResponse {
    Box::pin(reopened(replay).handle(signer_request(
        "GET",
        &apps_path(),
        Vec::new(),
        ms(&revoke_time()),
    )))
    .await
}

#[tokio::test]
async fn test_erase_unresolved_receipt_refuses_reads_and_authenticates_retry() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    unresolved_erasure(&replay).await;
    let read = apps_after_reload(&replay).await;
    assert_eq!(read.status, 503);
    assert!(no_head(&read));
    assert!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("account")
            .is_some()
    );
    let service = reopened(&replay);
    let mut request = erasure(&replay, Some(&held_hash()), ms(&revoke_time())).await;
    request.headers.remove(header::SIGNATURE);
    assert_eq!(Box::pin(service.handle(request)).await.status, 401);
    let created = replay
        .db
        .store()
        .lookup(&alice_id())
        .await
        .expect("lookup")
        .expect("account")
        .created_at_ms;
    let wrong_creation = erasure_naming(Some(created + 1), Some(&held_hash()), ms(&revoke_time()));
    assert_eq!(Box::pin(service.handle(wrong_creation)).await.status, 409);
    let wrong = erasure(&replay, Some(&[6; 32]), ms(&revoke_time())).await;
    assert_eq!(Box::pin(service.handle(wrong)).await.status, 409);
    assert!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("account")
            .is_some()
    );
    let request = erasure(&replay, Some(&held_hash()), ms(&revoke_time())).await;
    assert_eq!(Box::pin(service.handle(request)).await.status, 200);
    assert!(all_gone(&replay).await);
    assert!(durable_record(&replay).is_some());
    assert_eq!(apps_after_reload(&replay).await.status, 404);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_missing_receipt_never_infers_completion_from_absence() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let attempt = unresolved_erasure(&replay).await;
    let binding: Value = serde_json::from_slice(&attempt).expect("attempt");
    let created = binding["created_at_ms"].as_u64().expect("created");
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("absent state without receipt");
    conn.close().await.expect("close");
    let read = apps_after_reload(&replay).await;
    assert_eq!(read.status, 503, "absence is not a COMMIT receipt");
    assert!(no_head(&read));
    assert_eq!(durable_record(&replay), None);
    let service = reopened(&replay);
    let wrong = erasure_naming(Some(created), Some(&[6; 32]), ms(&revoke_time()));
    assert_eq!(Box::pin(service.handle(wrong)).await.status, 409);
    let retry = erasure_naming(Some(created), Some(&held_hash()), ms(&revoke_time()));
    assert_eq!(Box::pin(service.handle(retry)).await.status, 200);
    assert!(durable_record(&replay).is_some());
    assert_eq!(apps_after_reload(&replay).await.status, 404);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_committed_receipt_completes_after_reload_and_survives_restore() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let attempt = unresolved_erasure(&replay).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    sqlx::query("CREATE TEMP TABLE account_backup AS TABLE accounts")
        .execute(&mut conn)
        .await
        .expect("backup");
    sqlx::query("BEGIN")
        .execute(&mut conn)
        .await
        .expect("begin");
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("delete");
    sqlx::query(
        "INSERT INTO erasure_outcomes (identity, attempt, committed) VALUES ($1, $2, true)",
    )
    .bind(alice_id())
    .bind(&attempt)
    .execute(&mut conn)
    .await
    .expect("receipt");
    sqlx::query("COMMIT")
        .execute(&mut conn)
        .await
        .expect("commit deletion and receipt");
    assert_eq!(
        durable_record(&replay),
        None,
        "crash before external completion"
    );
    assert_eq!(apps_after_reload(&replay).await.status, 404);
    assert!(durable_record(&replay).is_some());
    sqlx::query("DELETE FROM erasure_outcomes")
        .execute(&mut conn)
        .await
        .expect("restore before receipt");
    sqlx::query("INSERT INTO accounts SELECT * FROM account_backup")
        .execute(&mut conn)
        .await
        .expect("restored account");
    assert!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("restored")
            .is_some()
    );
    assert_eq!(
        apps_after_reload(&replay).await.status,
        404,
        "completed external evidence covers the restore"
    );
    assert!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("deleted again")
            .is_none()
    );
    conn.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_restore_before_completion_remains_unknown_with_account() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let attempt = unresolved_erasure(&replay).await;
    let before = replay
        .db
        .store()
        .lookup(&alice_id())
        .await
        .expect("account")
        .expect("present");
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    // Restore the account row from before the committed deletion, losing its receipt.
    sqlx::query("CREATE TEMP TABLE account_backup AS TABLE accounts")
        .execute(&mut conn)
        .await
        .expect("backup");
    sqlx::query("BEGIN")
        .execute(&mut conn)
        .await
        .expect("begin");
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("delete");
    sqlx::query(
        "INSERT INTO erasure_outcomes (identity, attempt, committed) VALUES ($1, $2, true)",
    )
    .bind(alice_id())
    .bind(&attempt)
    .execute(&mut conn)
    .await
    .expect("receipt");
    sqlx::query("COMMIT")
        .execute(&mut conn)
        .await
        .expect("committed deletion and receipt");
    sqlx::query("DELETE FROM erasure_outcomes")
        .execute(&mut conn)
        .await
        .expect("restore loses receipt");
    sqlx::query("INSERT INTO accounts SELECT * FROM account_backup")
        .execute(&mut conn)
        .await
        .expect("restore account");
    let read = apps_after_reload(&replay).await;
    assert_eq!(read.status, 503);
    assert!(no_head(&read));
    assert_eq!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("restored")
            .expect("present")
            .created_at_ms,
        before.created_at_ms
    );
    assert_eq!(durable_record(&replay), None);
    conn.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_completed_record_failure_withholds_absence_until_reload() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let ledger = replay.key_dir().join("accounts/erasures");
    set_read_only(&ledger, true);
    let response = erase(&replay, Some(&held_hash()), &revoke_time()).await;
    assert_eq!(response.status, 503);
    assert!(all_gone(&replay).await, "deletion and receipt committed");
    assert_eq!(durable_record(&replay), None);
    let read = apps_after_reload(&replay).await;
    assert_eq!(read.status, 503, "no completed external authority yet");
    assert!(no_head(&read));
    set_read_only(&ledger, false);
    assert_eq!(apps_after_reload(&replay).await.status, 404);
    assert!(durable_record(&replay).is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_unknown_commit_error_keeps_attempt_until_authenticated_retry() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let before = rows(&replay, &alice_id()).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    for statement in [
        "CREATE FUNCTION unknown_erasure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE = '40003', MESSAGE = 'statement completion unknown'; END $$",
        "CREATE CONSTRAINT TRIGGER unknown_erasure AFTER DELETE ON accounts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION unknown_erasure()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    assert_eq!(
        erase(&replay, Some(&held_hash()), &revoke_time())
            .await
            .status,
        503
    );
    assert_eq!(rows(&replay, &alice_id()).await, before);
    assert_eq!(apps_after_reload(&replay).await.status, 503);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM erasure_outcomes")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(count, 0, "unknown COMMIT is not a durable rejection");
    sqlx::query("DROP TRIGGER unknown_erasure ON accounts")
        .execute(&mut conn)
        .await
        .expect("drop");
    let service = reopened(&replay);
    let retry = erasure(&replay, Some(&held_hash()), ms(&revoke_time())).await;
    assert_eq!(Box::pin(service.handle(retry)).await.status, 200);
    assert!(durable_record(&replay).is_some());
    conn.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_receipt_commit_failure_remains_unresolved_after_reload() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    unresolved_erasure_at(&replay, true).await;
    assert_eq!(apps_after_reload(&replay).await.status, 503);
    let service = reopened(&replay);
    let request = erasure(&replay, Some(&held_hash()), ms(&revoke_time())).await;
    assert_eq!(Box::pin(service.handle(request)).await.status, 200);
    assert!(all_gone(&replay).await);
    assert!(durable_record(&replay).is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_receipt_must_match_every_attempt_binding() {
    for field in ["token", "created_at_ms", "erased_at_ms", "identity_hash"] {
        let Some(replay) = replay().await else { return };
        replay_chain_through_revoke(&replay).await;
        let attempt = unresolved_erasure(&replay).await;
        let original = String::from_utf8(attempt.clone()).expect("json");
        let value: Value = serde_json::from_slice(&attempt).expect("attempt");
        let next = match field {
            "token" => json!("11".repeat(32)),
            "identity_hash" => json!([8; 32].to_vec()),
            _ => json!(value[field].as_u64().expect("time") + 1),
        };
        let wrong = original.replace(
            &format!("\"{field}\":{}", value[field]),
            &format!("\"{field}\":{next}"),
        );
        assert_ne!(wrong.as_bytes(), attempt);
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("connect");
        sqlx::query(
            "INSERT INTO erasure_outcomes (identity, attempt, committed) VALUES ($1, $2, true)",
        )
        .bind(alice_id())
        .bind(wrong.into_bytes())
        .execute(&mut conn)
        .await
        .expect("different receipt");
        let read = apps_after_reload(&replay).await;
        assert_eq!(read.status, 503, "{field}");
        assert!(no_head(&read));
        assert!(
            replay
                .db
                .store()
                .lookup(&alice_id())
                .await
                .expect("account")
                .is_some(),
            "{field}"
        );
        assert_eq!(durable_record(&replay), None);
        conn.close().await.expect("close");
        replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_erase_resolved_receipt_cleanup_failure_retries_at_startup() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    for statement in [
        "CREATE FUNCTION keep_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected cleanup failure'; END $$",
        "CREATE TRIGGER keep_receipt BEFORE DELETE ON erasure_outcomes FOR EACH ROW EXECUTE FUNCTION keep_receipt()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    assert_eq!(
        erase(&replay, Some(&held_hash()), &revoke_time())
            .await
            .status,
        200
    );
    assert!(durable_record(&replay).is_some());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM erasure_outcomes")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(count, 1, "failed cleanup retains the receipt");
    assert_eq!(apps_after_reload(&replay).await.status, 404);
    sqlx::query("DROP TRIGGER keep_receipt ON erasure_outcomes")
        .execute(&mut conn)
        .await
        .expect("drop");
    let _service = Box::pin(reopened(&replay).started()).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM erasure_outcomes")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(count, 0, "startup discards only already-resolved evidence");
    conn.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}

async fn receipt_waits_past_freshness(rejected: bool) {
    use pubky_switch::store::{LockFreshness, LockTiming};
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    for statement in [
        "CREATE SEQUENCE receipt_writes",
        "CREATE FUNCTION delay_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('receipt_writes') = 1 THEN PERFORM pg_sleep(3); END IF; RETURN NEW; END $$",
        "CREATE TRIGGER delay_receipt BEFORE INSERT OR UPDATE ON erasure_outcomes FOR EACH ROW EXECUTE FUNCTION delay_receipt()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    if rejected {
        for statement in [
            "CREATE FUNCTION reject_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected deletion refusal'; END $$",
            "CREATE TRIGGER reject_delete BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION reject_delete()",
        ] {
            sqlx::query(statement)
                .execute(&mut conn)
                .await
                .expect("delete trigger");
        }
    }
    let service = replay
        .restarted_with(pubky_switch::limits::Limits::default())
        .with_lock_freshness(LockFreshness::confirmed_ago(
            Duration::ZERO,
            LockTiming::checking_every(Duration::from_secs(1)),
        ));
    let request = erasure(&replay, Some(&held_hash()), ms(&revoke_time())).await;
    assert_eq!(Box::pin(service.handle(request)).await.status, 503);
    assert!(
        replay
            .db
            .store()
            .lookup(&alice_id())
            .await
            .expect("account")
            .is_some(),
        "stale commit cannot delete"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM erasure_outcomes")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(count, 0, "stale receipt must not commit");
    let writes: i64 = sqlx::query_scalar("SELECT last_value FROM receipt_writes")
        .fetch_one(&mut conn)
        .await
        .expect("write reached");
    assert_eq!(writes, 1);
    assert_eq!(
        apps_after_reload(&replay).await.status,
        503,
        "unknown until a fresh signer retries"
    );
    if rejected {
        sqlx::query("DROP TRIGGER reject_delete ON accounts")
            .execute(&mut conn)
            .await
            .expect("drop");
    }
    let fresh = reopened(&replay);
    let request = erasure(&replay, Some(&held_hash()), ms(&revoke_time())).await;
    assert_eq!(Box::pin(fresh.handle(request)).await.status, 200);
    assert!(durable_record(&replay).is_some());
    conn.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_freshness_checked_after_committed_receipt_write() {
    Box::pin(receipt_waits_past_freshness(false)).await;
}

#[tokio::test]
async fn test_erase_freshness_checked_after_rejected_receipt_write() {
    Box::pin(receipt_waits_past_freshness(true)).await;
}

#[tokio::test]
async fn test_enroll_waiting_for_unresolved_erasure_changes_nothing() {
    // An enrollment which already passed step 2 must repeat that judgement after it
    // waits for the identity lock (Switch wire 7.3, Table 3).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let before = rows(&replay, &alice_id()).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connect");
    for statement in [
        "CREATE FUNCTION refuse_queued_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected receipt failure'; END $$",
        "CREATE TRIGGER refuse_queued_receipt BEFORE INSERT OR UPDATE ON erasure_outcomes FOR EACH ROW EXECUTE FUNCTION refuse_queued_receipt()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("receipt trigger");
    }
    let at = revoke_time();
    set_time(&replay.clock, &at);
    let enrollment = signer_request(
        "POST",
        "/v1/enroll",
        fresh_enrollment(&replay, 99, ms(&at)).await,
        ms(&at),
    );
    // queued holds the account row. The erasure takes the identity lock and waits for
    // that row before its pending attempt is written. The enrollment passes step 2,
    // waits for the same identity lock, then wakes after the deletion rolled back.
    let (erased, enrolled) = queued(
        &replay,
        erase(&replay, Some(&held_hash()), &at),
        replay.service.handle(enrollment),
    )
    .await;
    assert_eq!(code_of(&erased), (503, json!("unavailable")));
    assert!(
        replay
            .key_dir()
            .join("accounts/erasure-attempts")
            .join(alice_id())
            .exists(),
        "the unresolved attempt remains durable"
    );
    assert_eq!(durable_record(&replay), None);
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM erasure_outcomes")
        .fetch_one(&mut conn)
        .await
        .expect("receipts");
    assert_eq!(receipts, 0, "neither outcome receipt committed");
    let after = rows(&replay, &alice_id()).await;
    conn.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
    assert_eq!(
        code_of(&enrolled),
        (503, json!("unavailable")),
        "an enrollment may not answer an unresolved account"
    );
    assert!(no_head(&enrolled));
    assert_eq!(
        after, before,
        "the waiting enrollment commits no account state"
    );
}
