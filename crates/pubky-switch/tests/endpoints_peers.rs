//! `PUT /v1/{id}/peers` (Switch wire 7.4.5): the `http.json` deliveries to bob's switch,
//! admission of another identity's app, own apps' deliveries, the held-version rules and
//! the peer limit with its floors.
//!
//! The vectors fix the service keys and the times; set `PUBKY_SWITCH_TEST_DATABASE_URL` to
//! run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::{
    http::{Handler, SwitchResponse},
    limits::Limits,
};
use pubky_switch_core::{
    admission::PeerReason,
    keys::IdentityKey,
    ops::{OpKind, OpsRequest, sign_batch},
    records::{IdentityBody, IdentityDoc, IdentityPolicy, Inbox},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

fn doc(name: &str) -> SignedDoc {
    serde_json::from_value(named(&vectors("documents.json")["documents"], name)["signed"].clone())
        .expect("document")
}

fn identity(name: &str) -> Value {
    vectors("keys.json")["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == name)
        .cloned()
        .expect("identity")
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn status_and_code(answer: &SwitchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

/// `doc` as a `PUT /peers` body.
fn delivery(doc: &SignedDoc) -> Vec<u8> {
    serde_json::to_vec(doc).expect("body")
}

/// `name`'s document `base` with `change` applied, signed by `name`'s identity key.
fn changed(name: &str, base: &SignedDoc, change: impl FnOnce(&mut IdentityBody)) -> SignedDoc {
    let mut body: IdentityBody =
        serde_json::from_slice(&base.body_bytes().expect("body")).expect("identity body");
    change(&mut body);
    let key = IdentityKey::from_secret(hex32(&identity(name)["secret_hex"]));
    IdentityDoc::sign(&key, body)
        .expect("sign")
        .signed()
        .clone()
}

#[tokio::test]
async fn test_peers_vectors_at_bobs_switch() {
    let Some(replay) = replay_at(BOB_ORIGIN, "service/bob", Limits::default(), false).await else {
        return;
    };
    let bob = serve_bob(&replay).await;
    let http = vectors("http.json");
    // bob's policy has connect requests on, so alice's wallet delivers her version 3 as a
    // stranger: the copy the vectors' switch holds.
    let at = "2026-01-01T00:09:00.000Z";
    set_time(&replay.clock, at);
    let path = format!("/v1/{bob}/peers");
    let first = other_request(
        "wallet",
        BOB_ORIGIN,
        "PUT",
        &path,
        delivery(&doc("alice identity.json")),
        None,
        ms(at),
    );
    let answer = replay.service.handle(first).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(body(&answer), json!({ "known_version": 3, "version": 3 }));
    // The same body again: a no-op, byte for byte.
    let expected = named(
        &http["responses"],
        "app of another identity: the version held again with the same body, a no-op",
    );
    set_time(
        &replay.clock,
        expected["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let request = vector_request(named(
        &http["requests"],
        "app of another identity: identity.json at the version the switch holds, the same body",
    ));
    assert_matches(&replay.service.handle(request).await, expected);
    // Another body at the version held: equivocation, with the held copy and no
    // known_version. The vector's key order (code, current, message) isn't the order of
    // this service's error bodies, so the body is compared as JSON.
    let expected = named(
        &http["responses"],
        "app of another identity: 409 stale_identity, another body at the version held, \
         current the held copy",
    );
    set_time(
        &replay.clock,
        expected["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let request = vector_request(named(
        &http["requests"],
        "app of another identity: identity.json at the version the switch holds, another body",
    ));
    let answer = replay.service.handle(request).await;
    assert_eq!(answer.status, 409);
    let expected_body: Value =
        serde_json::from_str(expected["body"].as_str().expect("body")).expect("json");
    assert_eq!(body(&answer), expected_body);
    assert_eq!(
        header_text(&answer, "switch-server-time"),
        expected["headers"]["switch-server-time"].as_str()
    );
    replay.db.drop_database().await.expect("drop");
}

/// alice's wallet, holding `lists.manage`, adds `pubky` as a kept peer.
async fn keep_peer(replay: &Replay, pubky: [u8; 32], batch: u8, at: &str) {
    wallet_op(
        replay,
        OpKind::AllowPut {
            pubky,
            reason: PeerReason::Kept,
        },
        batch,
        at,
    )
    .await;
}

/// A batch of `op` from alice's wallet.
async fn wallet_op(replay: &Replay, op: OpKind, batch: u8, at: &str) {
    let alice = identity("alice");
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let wallet_keys = pubky_switch_core::keys::AppKeys::from_secrets(
        hex32(&wallet["signing_secret_hex"]),
        hex32(&wallet["bundle_secret_hex"]),
    );
    let app_id = pubky_switch_core::enc::app_id_decode(wallet["app_id"].as_str().expect("id"))
        .expect("app id");
    let ops = sign_batch(
        &wallet_keys,
        &hex32(&alice["public_hex"]),
        Some(app_id),
        1,
        [batch; 16],
        vec![(Vec::new(), op)],
    )
    .expect("batch");
    let path = format!("/v1/{}/ops", alice["pubky_id"].as_str().expect("id"));
    let answer = replay
        .service
        .handle(app_request(
            wallet,
            "POST",
            &path,
            OpsRequest::new(&ops, None).to_json(),
            ms(at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

fn alice_path() -> String {
    format!(
        "/v1/{}/peers",
        identity("alice")["pubky_id"].as_str().expect("id")
    )
}

async fn from_shop(replay: &Replay, doc: &SignedDoc, at: &str) -> SwitchResponse {
    let request = other_request(
        "shop",
        ORIGIN,
        "PUT",
        &alice_path(),
        delivery(doc),
        None,
        ms(at),
    );
    replay.service.handle(request).await
}

async fn from_wallet(replay: &Replay, doc: &SignedDoc, at: &str) -> SwitchResponse {
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "PUT",
        &alice_path(),
        delivery(doc),
        ms(at),
    );
    replay.service.handle(request).await
}

#[tokio::test]
async fn test_peers_admission_and_own_apps() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob_v1 = doc("bob identity.json");
    // alice admits nobody yet and takes no connect requests: bob's shop is refused, and so
    // is a delivery of another identity's document.
    assert_eq!(
        status_and_code(&from_shop(&replay, &bob_v1, &at).await),
        (403, json!("not_admitted"))
    );
    keep_peer(&replay, hex32(&identity("bob")["public_hex"]), 51, &at).await;
    let answer = from_shop(&replay, &bob_v1, &at).await;
    assert_eq!(body(&answer), json!({ "known_version": 1, "version": 1 }));
    // An answer to another identity's app carries no head.
    assert!(header_text(&answer, "switch-head").is_none());
    assert_eq!(
        status_and_code(&from_shop(&replay, &doc("alice identity.json"), &at).await),
        (403, json!("not_admitted"))
    );
    // Not even another admitted identity's: only its own identity's document.
    let (carol, carol_v1) = stranger_doc(79);
    keep_peer(&replay, carol, 52, &at).await;
    assert_eq!(
        status_and_code(&from_shop(&replay, &carol_v1, &at).await),
        (403, json!("not_admitted"))
    );
    // A newer version is kept; the older one is then stale, another body at the version
    // held is equivocation.
    let bob_v2 = changed("bob", &bob_v1, |body| body.version = 2);
    assert_eq!(
        body(&from_shop(&replay, &bob_v2, &at).await),
        json!({ "known_version": 2, "version": 2 })
    );
    let stale = from_shop(&replay, &bob_v1, &at).await;
    assert_eq!(stale.status, 409);
    assert_eq!(
        (
            body(&stale)["code"].clone(),
            body(&stale)["current"].clone()
        ),
        (json!("stale_identity"), json!({ "version": 2 }))
    );
    let other = changed("bob", &bob_v1, |body| {
        body.version = 2;
        body.data_epoch = 2;
    });
    let equivocation = body(&from_shop(&replay, &other, &at).await);
    assert_eq!(
        equivocation["current"],
        json!({ "version": 2, "identity": bob_v2 })
    );
    // An own app delivers counterparties' documents, never its own identity's; its answer
    // has no known_version and carries the head.
    let answer = from_wallet(&replay, &bob_v2, &at).await;
    assert_eq!(body(&answer), json!({ "version": 2 }));
    assert!(header_text(&answer, "switch-head").is_some());
    assert_eq!(
        from_wallet(&replay, &doc("alice identity.json"), &at)
            .await
            .status,
        400
    );
    // The signer delivers none.
    let signer = signer_request("PUT", &alice_path(), delivery(&bob_v2), ms(&at));
    assert_eq!(
        status_and_code(&replay.service.handle(signer).await),
        (403, json!("permission_missing"))
    );
    replay.db.drop_database().await.expect("drop");
}

/// A first document of a new identity from `seed`, signed by it.
fn stranger_doc(seed: u8) -> ([u8; 32], SignedDoc) {
    let key = IdentityKey::from_secret([seed; 32]);
    let body = IdentityBody::first(
        key.public(),
        [seed; 16],
        Inbox {
            url: "https://inbox.other.example".into(),
            service_key: [seed; 32],
        },
        IdentityPolicy::default(),
    );
    (
        key.public(),
        IdentityDoc::sign(&key, body)
            .expect("sign")
            .signed()
            .clone(),
    )
}

/// alice's account's count of changed commits and her mark's.
async fn counts(replay: &Replay) -> (u64, u64) {
    let id = identity("alice")["pubky_id"]
        .as_str()
        .expect("id")
        .to_string();
    let mark = match replay.marks.read(&id).await.expect("read") {
        pubky_switch::marks::MarkRead::Mark(mark) => mark.state_version,
        other => panic!("no mark: {other:?}"),
    };
    (state_version_of(replay, &id).await, mark)
}

#[tokio::test]
async fn test_peers_removal_lost_to_a_restore_is_behind_the_mark() {
    use pubky_switch_core::records::RemovedApp;
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob_v1 = doc("bob identity.json");
    keep_peer(&replay, hex32(&identity("bob")["public_hex"]), 51, &at).await;
    // bob's shop is admitted, and delivers bob's version 1.
    assert_eq!(
        body(&from_shop(&replay, &bob_v1, &at).await),
        json!({ "known_version": 1, "version": 1 })
    );
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let held: String = sqlx::query_scalar("SELECT to_jsonb(p)::text FROM peer_copies p")
        .fetch_one(&mut conn)
        .await
        .expect("copy");
    let (count, marked) = counts(&replay).await;
    assert_eq!(marked, count, "the mark covers the shop's delivery");
    // alice's wallet delivers bob's version 2, which removes the shop: acknowledged with
    // the head, and covered by the mark before the answer goes out (Switch wire 7.3).
    let removed = changed("bob", &bob_v1, |body| {
        let app = body.apps.remove(0);
        body.removed.push(RemovedApp {
            app_id: app.app_id,
            distrust_from: ms(&at),
        });
        body.version = 2;
    });
    assert_eq!(
        body(&from_wallet(&replay, &removed, &at).await),
        json!({ "version": 2 })
    );
    assert_eq!(counts(&replay).await, (count + 1, count + 1));
    assert_eq!(
        status_and_code(&from_shop(&replay, &bob_v1, &at).await),
        (403, json!("not_admitted"))
    );
    // A restore that loses only that write: bob's copy back at version 1, the count back,
    // the mark as it was left.
    sqlx::query(
        "UPDATE peer_copies p SET doc = r.doc, version = r.version, generation = r.generation, \
         body_hash = r.body_hash, removed = r.removed, delivered = r.delivered \
         FROM jsonb_populate_record(NULL::peer_copies, $1::jsonb) r \
         WHERE p.account_id = r.account_id AND p.identity = r.identity",
    )
    .bind(&held)
    .execute(&mut conn)
    .await
    .expect("restore the copy");
    sqlx::query("UPDATE accounts SET state_version = $1")
        .bind(i64::try_from(count).expect("count"))
        .execute(&mut conn)
        .await
        .expect("restore the count");
    conn.close().await.expect("close");
    // The removed shop isn't admitted on the older list: the account answers the notice,
    // `behind` (Switch wire 7.3, Table 1).
    let answer = from_shop(&replay, &bob_v1, &at).await;
    assert_eq!(
        (
            answer.status,
            body(&answer)["code"].clone(),
            body(&answer)["current"]["reason"].clone()
        ),
        (503, json!("recovery_required"), json!("behind"))
    );
    assert_eq!(counts(&replay).await, (count, count + 1), "nothing counted");
    replay.db.drop_database().await.expect("drop");
}

async fn held_copies(replay: &Replay) -> Vec<Vec<u8>> {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query_scalar("SELECT identity FROM peer_copies ORDER BY identity")
        .fetch_all(&mut conn)
        .await
        .expect("copies")
}

#[tokio::test]
async fn test_peers_limit_drops_strangers_first_and_leaves_floors() {
    let limits = Limits {
        max_peers: 1,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob = hex32(&identity("bob")["public_hex"]);
    keep_peer(&replay, bob, 61, &at).await;
    let bob_v1 = doc("bob identity.json");
    assert_eq!(from_wallet(&replay, &bob_v1, &at).await.status, 200);
    // A stranger's new copy never pushes out an admitted identity's: it drops itself.
    let (carol, carol_v1) = stranger_doc(77);
    assert_eq!(from_wallet(&replay, &carol_v1, &at).await.status, 200);
    assert_eq!(held_copies(&replay).await, vec![bob.to_vec()]);
    // Admitted, carol's copy pushes out bob's, the least recently delivered, which leaves
    // a floor: another body at its version is refused, its own document held again.
    keep_peer(&replay, carol, 62, &at).await;
    assert_eq!(from_wallet(&replay, &carol_v1, &at).await.status, 200);
    assert_eq!(held_copies(&replay).await, vec![carol.to_vec()]);
    let other = changed("bob", &bob_v1, |body| body.data_epoch = 2);
    let stale = from_wallet(&replay, &other, &at).await;
    assert_eq!(
        (stale.status, body(&stale)["current"].clone()),
        (409, json!({ "version": 1 }))
    );
    assert_eq!(from_wallet(&replay, &bob_v1, &at).await.status, 200);
    assert_eq!(held_copies(&replay).await, vec![bob.to_vec()]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_peers_certificates_invite_codes_and_removed_apps() {
    use pubky_switch_core::{ident::invite_code_hash, ops::InviteCodePut, records::RemovedApp};
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob_v1 = doc("bob identity.json");
    // No Switch-Cert: 400. A certificate of another app than Switch-App: 401.
    let mut request = other_request(
        "shop",
        ORIGIN,
        "PUT",
        &alice_path(),
        delivery(&bob_v1),
        None,
        ms(&at),
    );
    request.headers.remove("switch-cert");
    assert_eq!(replay.service.handle(request).await.status, 400);
    let mut request = other_request(
        "shop",
        ORIGIN,
        "PUT",
        &alice_path(),
        delivery(&bob_v1),
        None,
        ms(&at),
    );
    let wallet_cert = doc("wallet certificate").compact();
    request
        .headers
        .insert("switch-cert", wallet_cert.parse().expect("header value"));
    assert_eq!(
        status_and_code(&replay.service.handle(request).await),
        (401, json!("bad_signature"))
    );
    // An invite code admits the shop, without using it.
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    wallet_op(
        &replay,
        OpKind::InviteCodePut(InviteCodePut {
            code_hash: invite_code_hash(code).expect("hash"),
            expires_at: ms(&at) + 3_600_000,
            max_uses: 1,
        }),
        71,
        &at,
    )
    .await;
    let with_code = |doc: &SignedDoc| {
        other_request(
            "shop",
            ORIGIN,
            "PUT",
            &alice_path(),
            delivery(doc),
            Some(code),
            ms(&at),
        )
    };
    assert_eq!(
        body(&replay.service.handle(with_code(&bob_v1)).await),
        json!({ "known_version": 1, "version": 1 })
    );
    // bob's version 2 lists the shop as removed: answered like a stranger, the version it
    // delivered whatever is held, and kept only while newer.
    let removed = changed("bob", &bob_v1, |body| {
        let app = body.apps.remove(0);
        body.removed.push(RemovedApp {
            app_id: app.app_id,
            distrust_from: ms(&at),
        });
        body.version = 2;
    });
    assert_eq!(
        body(&replay.service.handle(with_code(&removed)).await),
        json!({ "known_version": 2, "version": 2 })
    );
    assert_eq!(
        body(&replay.service.handle(with_code(&bob_v1)).await),
        json!({ "known_version": 1, "version": 1 })
    );
    // Without the code a removed app counts nothing else.
    assert_eq!(
        status_and_code(&from_shop(&replay, &removed, &at).await),
        (403, json!("not_admitted"))
    );
    // The newer document stayed held: an own app's delivery of version 1 is stale.
    assert_eq!(
        body(&from_wallet(&replay, &bob_v1, &at).await)["current"],
        json!({ "version": 2 })
    );
    replay.db.drop_database().await.expect("drop");
}

async fn insert_invite(replay: &Replay, account: &str, code: &str, expires_at_ms: u64) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "INSERT INTO invite_codes (account_id, code_hash, max_uses, uses, writer, \
         expires_at_ms) VALUES ($1, $2, 1, 0, $3, $4)",
    )
    .bind(account)
    .bind(
        pubky_switch_core::ident::invite_code_hash(code)
            .expect("hash")
            .as_slice(),
    )
    .bind([1u8; 16].as_slice())
    .bind(i64::try_from(expires_at_ms).expect("time"))
    .execute(&mut conn)
    .await
    .expect("invite");
}

const CODE: &str = "IRrC78oNIjZ4hcet2fYnJQ";

#[tokio::test]
async fn test_peers_invite_code_expiry_and_trusted_time() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let alice = identity("alice")["pubky_id"]
        .as_str()
        .expect("id")
        .to_string();
    // An expired code admits nobody.
    insert_invite(&replay, &alice, CODE, ms(&at)).await;
    let request = other_request(
        "shop",
        ORIGIN,
        "PUT",
        &alice_path(),
        delivery(&doc("bob identity.json")),
        Some(CODE),
        ms(&at),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(status_and_code(&answer), (403, json!("not_admitted")));
    assert!(header_text(&answer, "switch-head").is_none());
    replay.db.drop_database().await.expect("drop");

    // Without trusted time, a delivery that only a code admits waits for it (Switch wire
    // 7.3): at bob's switch, which takes connect requests, the code comes first.
    let Some(bob_switch) = replay_at(BOB_ORIGIN, "service/bob", Limits::default(), true).await
    else {
        return;
    };
    let bob = serve_bob(&bob_switch).await;
    let at = "2026-01-01T00:09:00.000Z";
    set_time(&bob_switch.clock, at);
    insert_invite(&bob_switch, &bob, CODE, ms(at) + 3_600_000).await;
    let deliver = |now| {
        other_request(
            "wallet",
            BOB_ORIGIN,
            "PUT",
            &format!("/v1/{bob}/peers"),
            delivery(&doc("alice identity.json")),
            Some(CODE),
            now,
        )
    };
    let expiry = ms(at) + 3_600_000;
    for now in [ms(at), expiry] {
        bob_switch.clock.set_wall_ms(now);
        assert_eq!(
            status_and_code(&bob_switch.service.handle(deliver(now)).await),
            (503, json!("unavailable"))
        );
    }
    assert_eq!(bob_switch.service.time_refusals(), 2);
    // Once time is verified the expired code drops out. This account allows a
    // stranger to deliver its document through its connect-request policy.
    bob_switch.time.note(
        pubky_switch::time::TimeSample {
            utc_ms: expiry,
            uncertainty_ms: 0,
        },
        0,
    );
    assert_eq!(bob_switch.service.handle(deliver(expiry)).await.status, 200);
    bob_switch.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_peers_invite_and_stranger_rates() {
    // The invite code's rate.
    let limits = Limits {
        invite_reads_per_min: 1,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let alice = identity("alice")["pubky_id"]
        .as_str()
        .expect("id")
        .to_string();
    insert_invite(&replay, &alice, CODE, ms(&at) + 3_600_000).await;
    let deliver = || {
        other_request(
            "shop",
            ORIGIN,
            "PUT",
            &alice_path(),
            delivery(&doc("bob identity.json")),
            Some(CODE),
            ms(&at),
        )
    };
    assert_eq!(replay.service.handle(deliver()).await.status, 200);
    assert_eq!(
        status_and_code(&replay.service.handle(deliver()).await),
        (429, json!("rate_limited"))
    );
    replay.db.drop_database().await.expect("drop");

    // The account's stranger rate, at bob's switch, which takes connect requests.
    let limits = Limits {
        stranger_per_min: 1,
        ..Limits::default()
    };
    let Some(bob_switch) = replay_at(BOB_ORIGIN, "service/bob", limits, false).await else {
        return;
    };
    let bob = serve_bob(&bob_switch).await;
    let at = "2026-01-01T00:09:00.000Z";
    set_time(&bob_switch.clock, at);
    let deliver = || {
        other_request(
            "wallet",
            BOB_ORIGIN,
            "PUT",
            &format!("/v1/{bob}/peers"),
            delivery(&doc("alice identity.json")),
            None,
            ms(at),
        )
    };
    assert_eq!(bob_switch.service.handle(deliver()).await.status, 200);
    assert_eq!(
        status_and_code(&bob_switch.service.handle(deliver()).await),
        (429, json!("rate_limited"))
    );
    bob_switch.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_peers_limit_drops_a_strangers_copy_before_an_admitted_one() {
    let limits = Limits {
        max_peers: 2,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob = hex32(&identity("bob")["public_hex"]);
    keep_peer(&replay, bob, 81, &at).await;
    // bob's copy (admitted) first, then carol's (a stranger): both held.
    assert_eq!(
        from_wallet(&replay, &doc("bob identity.json"), &at)
            .await
            .status,
        200
    );
    let (carol, carol_v1) = stranger_doc(77);
    assert_eq!(from_wallet(&replay, &carol_v1, &at).await.status, 200);
    // dave, admitted, is one too many: carol's goes, the stranger's, though bob's is older.
    let (dave, dave_v1) = stranger_doc(78);
    keep_peer(&replay, dave, 82, &at).await;
    assert_eq!(from_wallet(&replay, &dave_v1, &at).await.status, 200);
    let mut held = vec![bob.to_vec(), dave.to_vec()];
    held.sort();
    assert_eq!(held_copies(&replay).await, held);
    let _ = carol;
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_peers_certificate_checks_in_order() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob_v1 = delivery(&doc("bob identity.json"));
    let send = |cert: &str, signer: &str, at_ms: u64| {
        other_request_as(
            "shop",
            cert,
            signer,
            ORIGIN,
            "PUT",
            &alice_path(),
            bob_v1.clone(),
            None,
            at_ms,
        )
    };
    // A certificate of bob's for another of his apps, the request signed with that app's
    // key: it verifies, but doesn't name Switch-App.
    assert_eq!(
        status_and_code(
            &replay
                .service
                .handle(send(
                    "cap certificate, extension scope tasks_ext:tasks-cap",
                    "cap",
                    ms(&at)
                ))
                .await
        ),
        (401, json!("bad_signature"))
    );
    // The shop's certificate, but the request signed with another key.
    assert_eq!(
        status_and_code(
            &replay
                .service
                .handle(send("shop certificate", "cap", ms(&at)))
                .await
        ),
        (401, json!("bad_signature"))
    );
    // At the certificate's expiry, by the identity's service time: 403 cert_expired.
    let expired = "2026-12-01T00:00:00.000Z";
    set_time(&replay.clock, expired);
    assert_eq!(
        status_and_code(
            &replay
                .service
                .handle(send("shop certificate", "shop", ms(expired)))
                .await
        ),
        (403, json!("cert_expired"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_peers_document_that_doesnt_verify_is_400_for_every_caller() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let mut tampered = doc("bob identity.json");
    tampered.sig = doc("alice identity.json").sig;
    // The shop isn't admitted, and still gets the same 400 an own app gets: the check comes
    // before admission and reads nothing held.
    assert_eq!(from_shop(&replay, &tampered, &at).await.status, 400);
    assert_eq!(from_wallet(&replay, &tampered, &at).await.status, 400);
    replay.db.drop_database().await.expect("drop");
}

/// alice's own `identity.json`, version 1 naming this service with connect requests on.
fn alice_doc_here(replay: &Replay) -> IdentityDoc {
    let key = IdentityKey::from_secret(hex32(&identity("alice")["secret_hex"]));
    let mut policy = IdentityPolicy::default();
    policy.connect_requests.enabled = true;
    let body = IdentityBody::first(
        key.public(),
        [4; 16],
        Inbox::new(ORIGIN, service_public(replay)),
        policy,
    );
    IdentityDoc::sign(&key, body).expect("sign")
}

/// alice enrolled with an `identity.json` that names this service: serving before her
/// first chain item. Her ID, her document and the time.
async fn serving_without_a_chain(replay: &Replay) -> (String, IdentityDoc, String) {
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    set_time(&replay.clock, &at);
    let id = identity("alice")["pubky_id"]
        .as_str()
        .expect("id")
        .to_string();
    let doc = alice_doc_here(replay);
    let body = alice_enrollment_body(replay, 5, None, Some(doc.signed().clone()), ms(&at)).await;
    let answer = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, ms(&at)))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let mark = mark_now(replay, &id).await;
    assert_eq!((mark.generation, mark.seq, mark.state_version), (0, 0, 0));
    (id, doc, at)
}

async fn mark_now(replay: &Replay, id: &str) -> pubky_switch::marks::AccountMark {
    match replay.marks.read(id).await.expect("read") {
        pubky_switch::marks::MarkRead::Mark(mark) => mark,
        other => panic!("no mark: {other:?}"),
    }
}

/// alice's last given-out `seq`.
async fn last_seq(replay: &Replay, id: &str) -> i64 {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let seq = sqlx::query_scalar("SELECT last_seq FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&mut conn)
        .await
        .expect("seq");
    conn.close().await.expect("close");
    seq
}

fn notice_reason(answer: &SwitchResponse) -> (u16, Value, Value) {
    (
        answer.status,
        body(answer)["code"].clone(),
        body(answer)["current"]["reason"].clone(),
    )
}

#[tokio::test]
async fn test_peers_copy_at_a_serving_account_without_a_chain_lost_to_a_restore_is_behind() {
    // Serving before its first chain item, the account acknowledges a stranger's copy: a
    // counted write, which moves the mark to the account's generation, `seq` 0 and its count
    // (Switch wire 7.3, "The mark"). A restore that loses it is behind, so no `seq` the
    // account gives out from then on can repeat one given out after the backup.
    let Some(replay) = replay().await else { return };
    let (id, own, at) = serving_without_a_chain(&replay).await;
    save_image(&replay, &id, "before_copy").await;
    let answer = from_shop(&replay, &doc("bob identity.json"), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let mark = mark_now(&replay, &id).await;
    let count = state_version_of(&replay, &id).await;
    assert!(count > 0);
    assert_eq!(
        (mark.generation, mark.seq, mark.chain_hash),
        (1, 0, pubky_switch_core::chain::ZERO_HASH),
        "a mark before the first head"
    );
    assert_eq!(
        (mark.state_version, mark.state_tag),
        (count, state_tag_of(&replay, &id).await)
    );
    assert_eq!(last_seq(&replay, &id).await, 0);
    restore_image(&replay, &id, "before_copy").await;
    assert_eq!(
        notice_reason(&from_shop(&replay, &doc("bob identity.json"), &at).await),
        (503, json!("recovery_required"), json!("behind"))
    );
    // The signer's next version would take `seq` 1: it gets the notice, and no `seq` goes.
    let mut next = own.body().clone();
    next.version += 1;
    let next = IdentityDoc::sign(
        &IdentityKey::from_secret(hex32(&identity("alice")["secret_hex"])),
        next,
    )
    .expect("sign");
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: next.signed().clone(),
        prev: Some(own.hash()),
    };
    let put = signer_request_at_creation(
        "PUT",
        &format!("/v1/{id}/identity"),
        delivery.to_json(),
        ms(&at),
        Some(mark.created_at_ms),
    );
    assert_eq!(
        notice_reason(&replay.service.handle(put).await),
        (503, json!("recovery_required"), json!("behind"))
    );
    assert_eq!(last_seq(&replay, &id).await, 0, "seq 1 not given out again");
    assert_eq!(mark_now(&replay, &id).await, mark, "the mark stays");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_peers_account_without_a_chain_lost_entirely_is_lost() {
    // The account took a counted write before its first chain item, then is lost entirely:
    // its mark records a count, so the identity is lost, not unknown here (Switch wire 7.3,
    // Table 1, row "None").
    let Some(replay) = replay().await else { return };
    let (id, _, at) = serving_without_a_chain(&replay).await;
    let answer = from_shop(&replay, &doc("bob identity.json"), &at).await;
    assert_eq!(answer.status, 200);
    assert!(mark_now(&replay, &id).await.state_version > 0);
    assert_eq!(
        sql_on(&replay, &id, "DELETE FROM accounts WHERE id = $1").await,
        1
    );
    assert_eq!(
        notice_reason(&from_shop(&replay, &doc("bob identity.json"), &at).await),
        (503, json!("recovery_required"), json!("behind"))
    );
    replay.db.drop_database().await.expect("drop");
}
