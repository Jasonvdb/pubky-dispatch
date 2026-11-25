//! `GET /v1/{id}/allow` (Dispatch wire 7.4.6) on `chain.json`'s account: every list present,
//! each whole; a service-written reply grant with its code and last use;
//! flagged senders from `flag_after`; live invite codes only; who may read it; and the
//! answer's service time as the time of the state it shows.
//!
//! Set `PUBKY_DISPATCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_dispatch::http::{DispatchResponse, Handler};
use pubky_dispatch_core::{
    admission::PeerReason,
    enc::unb64,
    envelope::{Recipient, seal},
    keys::AppKeys,
    ops::{InviteCodePut, OpKind, OpsRequest, sign_batch},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

const CODE: &str = "IRrC78oNIjZ4hcet2fYnJQ";

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn at() -> String {
    item_time(chain_item(&vectors("chain.json"), 9))
}

fn body(answer: &DispatchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn code_of(answer: &DispatchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

fn doc(name: &str) -> SignedDoc {
    serde_json::from_value(named(&vectors("documents.json")["documents"], name)["signed"].clone())
        .expect("document")
}

fn identity_named(name: &str) -> Value {
    vectors("keys.json")["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == name)
        .cloned()
        .expect("identity")
}

fn bob_public() -> [u8; 32] {
    hex32(&identity_named("bob")["public_hex"])
}

fn allow_path() -> String {
    format!("/v1/{}/allow", alice_id())
}

/// `GET /allow` as alice's app `name` at `at`.
async fn read_as(replay: &Replay, name: &str, at: &str) -> DispatchResponse {
    let keys = vectors("keys.json");
    replay
        .service
        .handle(app_request(
            app(&keys, name),
            "GET",
            &allow_path(),
            Vec::new(),
            ms(at),
        ))
        .await
}

async fn sql(replay: &Replay, query: &str) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(query)
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("sql");
}

/// A batch of `op` from alice's wallet.
async fn wallet_op(replay: &Replay, op: OpKind, batch: u8) {
    let answer = wallet_ops(replay, vec![op], batch).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

async fn wallet_ops(replay: &Replay, kinds: Vec<OpKind>, batch: u8) -> DispatchResponse {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let ops = sign_batch(
        &AppKeys::from_secrets(
            hex32(&wallet["signing_secret_hex"]),
            hex32(&wallet["bundle_secret_hex"]),
        ),
        &hex32(&alice(&keys)["public_hex"]),
        Some(
            pubky_dispatch_core::enc::app_id_decode(wallet["app_id"].as_str().expect("id"))
                .expect("app id"),
        ),
        1,
        [batch; 16],
        kinds.into_iter().map(|op| (Vec::new(), op)).collect(),
    )
    .expect("batch");
    replay
        .service
        .handle(app_request(
            wallet,
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&ops, None).to_json(),
            ms(&at()),
        ))
        .await
}

fn put_code(code: &str, expires_at: u64, max_uses: u64) -> OpKind {
    OpKind::InviteCodePut(InviteCodePut {
        code_hash: pubky_dispatch_core::ident::invite_code_hash(code).expect("hash"),
        expires_at,
        max_uses,
    })
}

/// An envelope for alice's wallet's receive key.
fn to_wallet(byte: u8) -> Vec<u8> {
    let keys = vectors("keys.json");
    let public: [u8; 32] = unb64(
        app(&keys, "wallet")["receive_key"]["public"]
            .as_str()
            .expect("public"),
    )
    .expect("b64")
    .try_into()
    .expect("32");
    seal(
        &hex32(&alice(&keys)["public_hex"]),
        &[Recipient::new(public)],
        &[byte; 100],
        false,
    )
    .expect("seal")
}

async fn from_shop(
    replay: &Replay,
    method: &str,
    path: &str,
    body: Vec<u8>,
    code: Option<&str>,
) -> DispatchResponse {
    let request = other_request("shop", ORIGIN, method, path, body, code, ms(&at()));
    replay.service.handle(request).await
}

#[tokio::test]
async fn test_allow_every_list_present_and_empty() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let answer = read_as(&replay, "wallet", &at()).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // All four, in the table's order, even when empty.
    assert_eq!(
        String::from_utf8_lossy(&answer.body),
        "{\"peers\":[],\"deny\":[],\"flagged\":[],\"invite_codes\":[]}"
    );
    assert!(header_text(&answer, "dispatch-head").is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_shows_each_list_whole() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let keys = vectors("keys.json");
    let wallet_id = app(&keys, "wallet")["app_id"].clone();
    // A kept peer, a deny entry, and three invite codes: one live, one expired, one used up.
    let stranger = [7u8; 32];
    wallet_op(
        &replay,
        OpKind::AllowPut {
            pubky: bob_public(),
            reason: PeerReason::Kept,
        },
        60,
    )
    .await;
    wallet_op(&replay, OpKind::DenyPut { pubky: stranger }, 61).await;
    wallet_op(&replay, put_code(CODE, ms(&at()) + 3_600_000, 2), 62).await;
    wallet_op(
        &replay,
        put_code("AAAAAAAAAAAAAAAAAAAAAA", ms(&at()) + 1, 1),
        63,
    )
    .await;
    wallet_op(
        &replay,
        put_code("BBBBBBBBBBBBBBBBBBBBBA", ms(&at()) + 3_600_000, 1),
        64,
    )
    .await;
    // The second expired, the third used up.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for (code, change) in [
        ("AAAAAAAAAAAAAAAAAAAAAA", "expires_at_ms = 0"),
        ("BBBBBBBBBBBBBBBBBBBBBA", "uses = max_uses"),
    ] {
        sqlx::query(&format!(
            "UPDATE invite_codes SET {change} WHERE account_id = $1 AND code_hash = $2"
        ))
        .bind(alice_id())
        .bind(
            pubky_dispatch_core::ident::invite_code_hash(code)
                .expect("hash")
                .as_slice(),
        )
        .execute(&mut conn)
        .await
        .expect("code");
    }
    // A reply grant the service writes when the code admits bob's shop, then used
    // by a second append: it carries the original code hash and its last use.
    wallet_op(
        &replay,
        OpKind::AllowDelete {
            pubky: bob_public(),
            reason: PeerReason::Kept,
        },
        65,
    )
    .await;
    let peers = format!("/v1/{}/peers", alice_id());
    let delivery = serde_json::to_vec(&doc("bob identity.json")).expect("body");
    assert_eq!(
        from_shop(&replay, "PUT", &peers, delivery, Some(CODE))
            .await
            .status,
        200
    );
    let version: i64 = {
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query_scalar("SELECT apps_version FROM accounts WHERE id = $1")
            .bind(alice_id())
            .fetch_one(&mut conn)
            .await
            .expect("version")
    };
    let inbox = format!("/v1/{}/inbox?apps_version={version}", alice_id());
    let first = from_shop(&replay, "POST", &inbox, to_wallet(1), Some(CODE)).await;
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    let second = from_shop(&replay, "POST", &inbox, to_wallet(2), None).await;
    assert_eq!(
        second.status,
        200,
        "{}",
        String::from_utf8_lossy(&second.body)
    );
    // Two senders flagged, one below flag_after.
    sql(
        &replay,
        "INSERT INTO sender_flags (account_id, pubky, hits, last_hit_ms) VALUES \
         ($1, decode(repeat('11', 32), 'hex'), 3, 0), ($1, decode(repeat('22', 32), 'hex'), 2, 0)",
    )
    .await;

    let answer = read_as(&replay, "wallet", &at()).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let lists = body(&answer);
    let bob_id = identity_named("bob")["pubky_id"].clone();
    assert_eq!(lists["peers"][0]["kept"], false);
    assert_eq!(
        lists["deny"],
        json!([pubky_dispatch_core::enc::pubky_id(&stranger)])
    );
    let row = &lists["peers"][0];
    let reply = &row["reply"];
    assert_eq!(row["pubky"], bob_id);
    assert_eq!(reply["written_by"], "service");
    assert_eq!(
        reply["code_hash"],
        pubky_dispatch_core::enc::b64(
            &pubky_dispatch_core::ident::invite_code_hash(CODE).expect("hash")
        )
    );
    assert_eq!(reply["at"], at());
    assert_eq!(reply["last_used"], at());
    assert_eq!(lists["peers"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        lists["flagged"],
        json!([{ "pubky": pubky_dispatch_core::enc::pubky_id(&[0x11; 32]), "hits": 3 }])
    );
    // Only the live code, used once by the append that redeemed it.
    let codes = lists["invite_codes"].as_array().expect("codes");
    assert_eq!(codes.len(), 1, "{codes:?}");
    assert_eq!(
        codes[0],
        json!({
            "code_hash": pubky_dispatch_core::enc::b64(
                &pubky_dispatch_core::ident::invite_code_hash(CODE).expect("hash")
            ),
            "expires_at": pubky_dispatch_core::time::rfc3339(ms(&at()) + 3_600_000),
            "max_uses": 2,
            "uses": 1,
            "written_by": wallet_id,
        })
    );
    // An explicit keep and a repeated grant preserve the service's original grant.
    let peer = bob_public();
    for (reason, id) in [(PeerReason::Kept, 80), (PeerReason::Reply, 81)] {
        wallet_op(
            &replay,
            OpKind::AllowPut {
                pubky: peer,
                reason,
            },
            id,
        )
        .await;
    }
    let both = body(&read_as(&replay, "wallet", &at()).await);
    assert_eq!(both["peers"].as_array().expect("peers").len(), 1);
    assert_eq!(both["peers"][0]["kept"], true);
    assert_eq!(both["peers"][0]["reply"], *reply);
    wallet_op(
        &replay,
        OpKind::AllowDelete {
            pubky: peer,
            reason: PeerReason::Kept,
        },
        82,
    )
    .await;
    let reply_only = body(&read_as(&replay, "wallet", &at()).await);
    assert_eq!(reply_only["peers"][0]["kept"], false);
    assert_eq!(reply_only["peers"][0]["reply"], *reply);

    // Each regrant begins a new lifetime, even when all operations use one service time.
    let keep = OpKind::AllowPut {
        pubky: peer,
        reason: PeerReason::Kept,
    };
    let grant = OpKind::AllowPut {
        pubky: peer,
        reason: PeerReason::Reply,
    };
    let prune = OpKind::AllowDelete {
        pubky: peer,
        reason: PeerReason::Reply,
    };
    let answer = wallet_ops(&replay, vec![keep, prune.clone(), grant], 83).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let restored = body(&read_as(&replay, "wallet", &at()).await);
    assert_eq!(restored["peers"][0]["kept"], true);
    assert_eq!(
        restored["peers"][0]["reply"],
        json!({"written_by": wallet_id, "at": at()})
    );
    wallet_op(&replay, prune, 84).await;
    let kept_only = body(&read_as(&replay, "wallet", &at()).await);
    assert_eq!(
        kept_only["peers"],
        json!([{"pubky":bob_id, "kept":true,"reply":null}])
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_answer_time_is_the_state_read() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    // Read a minute later: the answer is signed at that service time, and shows the state
    // committed by then.
    let later = pubky_dispatch_core::time::rfc3339(ms(&at()) + 60_000);
    set_time(&replay.clock, &later);
    let answer = read_as(&replay, "wallet", &later).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        header_text(&answer, "dispatch-server-time"),
        Some(later.as_str())
    );
    // An expiry is judged at that time too: a code is live until the instant it expires,
    // and not at it.
    let expires = ms(&later) + 30_000;
    wallet_op(&replay, put_code(CODE, expires, 1), 70).await;
    let just_before = pubky_dispatch_core::time::rfc3339(expires - 1);
    set_time(&replay.clock, &just_before);
    let answer = read_as(&replay, "wallet", &just_before).await;
    assert_eq!(
        body(&answer)["invite_codes"].as_array().map(Vec::len),
        Some(1)
    );
    let at_expiry = pubky_dispatch_core::time::rfc3339(expires);
    set_time(&replay.clock, &at_expiry);
    let answer = read_as(&replay, "wallet", &at_expiry).await;
    assert_eq!(
        header_text(&answer, "dispatch-server-time"),
        Some(at_expiry.as_str())
    );
    assert_eq!(body(&answer)["invite_codes"], json!([]));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_needs_lists_read() {
    let Some(replay) = replay().await else { return };
    let chain = vectors("chain.json");
    serve_alice(&replay).await;
    replay_batch(&replay, &chain, &[3, 4]).await;
    assert_eq!(replay.db.give_out_seq(&alice_id()).await.expect("seq"), 5);
    replay_batch(&replay, &chain, &[6]).await;
    replay_batch(&replay, &chain, &[7, 8]).await;
    set_time(&replay.clock, &at());
    // The executor registers; its certificate has no lists.read.
    let keys = vectors("keys.json");
    let executor = app(&keys, "executor");
    let ops = sign_batch(
        &AppKeys::from_secrets(
            hex32(&executor["signing_secret_hex"]),
            hex32(&executor["bundle_secret_hex"]),
        ),
        &hex32(&alice(&keys)["public_hex"]),
        Some(
            pubky_dispatch_core::enc::app_id_decode(executor["app_id"].as_str().expect("id"))
                .expect("app id"),
        ),
        1,
        [80; 16],
        vec![(
            Vec::new(),
            OpKind::AppPut {
                record: doc("executor app record"),
            },
        )],
    )
    .expect("batch");
    let answer = replay
        .service
        .handle(app_request(
            executor,
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&ops, None).to_json(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let answer = read_as(&replay, "executor", &at()).await;
    assert_eq!(code_of(&answer), (403, json!("permission_missing")));
    assert!(
        header_text(&answer, "dispatch-head").is_some(),
        "a verified own app"
    );
    // The signer reads its own lists through its apps, not here.
    let answer = replay
        .service
        .handle(signer_request("GET", &allow_path(), Vec::new(), ms(&at())))
        .await;
    assert_eq!(code_of(&answer), (403, json!("permission_missing")));
    // An app of another identity: refused, with no head.
    let answer = from_shop(&replay, "GET", &allow_path(), Vec::new(), None).await;
    assert_eq!(code_of(&answer), (403, json!("permission_missing")));
    assert!(header_text(&answer, "dispatch-head").is_none());
    replay.db.drop_database().await.expect("drop");
}

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

#[tokio::test]
async fn test_allow_long_read_holds_no_lock_and_shows_the_stamped_state() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    // Read the full reply inventory while a second request writes to the account.
    sql(
        &replay,
        "INSERT INTO peer_admissions (account_id, kept, pubky, reply_at_ms, reply_code_hash) \
         SELECT $1, FALSE, decode(lpad(to_hex(g), 64, '0'), 'hex'), 0, \
         decode(repeat('cd', 32), 'hex') \
         FROM generate_series(1, 100000) g",
    )
    .await;
    let read_at = pubky_dispatch_core::time::rfc3339(ms(&at()) + 60_000);
    set_time(&replay.clock, &read_at);
    let read_ms = i64::try_from(ms(&read_at)).expect("time");
    let phone = app(&vectors("keys.json"), "phone")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    // The read waits once its request has committed its stamp, so its lock is gone.
    let pause = replay.db.pause_next_snapshot_read();
    let (answer, ()) = tokio::join!(read_as(&replay, "wallet", &read_at), async {
        tokio::time::timeout(std::time::Duration::from_secs(10), pause.reached.notified())
            .await
            .expect("the read reached its pause once its request committed");
        assert_eq!(
            stamped_time(&replay).await,
            read_ms,
            "the read's stamp is committed"
        );
        // A revocation by the signer and a write by an own app each take the lock: they
        // don't wait for the read, which goes on only once they are done.
        let ten = std::time::Duration::from_secs(10);
        let revoke = tokio::time::timeout(
            ten,
            replay.service.handle(signer_request(
                "POST",
                &format!("/v1/{}/apps/{phone}/revoke", alice_id()),
                Vec::new(),
                ms(&read_at),
            )),
        )
        .await
        .expect("the revocation doesn't wait for the read");
        assert_eq!(
            revoke.status,
            200,
            "{}",
            String::from_utf8_lossy(&revoke.body)
        );
        tokio::time::timeout(
            ten,
            wallet_op(&replay, put_code(CODE, ms(&read_at) + 3_600_000, 1), 90),
        )
        .await
        .expect("the write doesn't wait for the read");
        pause.resume.notify_one();
    });
    assert_eq!(answer.status, 200);
    // The answer is the state at its stamped time: the code written after it isn't in it.
    let lists = body(&answer);
    assert_eq!(lists["invite_codes"], json!([]));
    let peers = lists["peers"].as_array().expect("peer rows");
    assert_eq!(peers.len(), 100_000);
    assert!(
        peers
            .iter()
            .map(|row| row["pubky"].as_str().expect("encoded Pubky ID"))
            .is_sorted_by(|left, right| left < right)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_reads_the_state_under_the_lock_not_after() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let read_at = pubky_dispatch_core::time::rfc3339(ms(&at()) + 60_000);
    set_time(&replay.clock, &read_at);
    // The read waits once its request has committed; a code committed then isn't in it,
    // since it reads the state under the lock, at the stamped time. The whole exchange is
    // bounded: a read that paused under the lock would hold the row the insert waits for.
    let pause = replay.db.pause_next_snapshot_read();
    let exchange = async {
        tokio::join!(read_as(&replay, "wallet", &read_at), async {
            tokio::time::timeout(std::time::Duration::from_secs(10), pause.reached.notified())
                .await
                .expect("the read reached its pause once its request committed");
            sql(
                &replay,
                "INSERT INTO invite_codes (account_id, code_hash, max_uses, uses, writer, \
             expires_at_ms) VALUES ($1, decode(repeat('ee', 32), 'hex'), 1, 0, \
             decode(repeat('ab', 16), 'hex'), 9000000000000)",
            )
            .await;
            pause.resume.notify_one();
        })
    };
    let (answer, ()) = tokio::time::timeout(std::time::Duration::from_secs(30), exchange)
        .await
        .expect("the read and the insert ended");
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(
        header_text(&answer, "dispatch-server-time"),
        Some(read_at.as_str())
    );
    assert_eq!(body(&answer)["invite_codes"], json!([]));
    replay.db.drop_database().await.expect("drop");
}

/// The executor registers at alice's account: an own app without `lists.read`.
async fn register_executor(replay: &Replay) {
    let keys = vectors("keys.json");
    let executor = app(&keys, "executor");
    let ops = sign_batch(
        &AppKeys::from_secrets(
            hex32(&executor["signing_secret_hex"]),
            hex32(&executor["bundle_secret_hex"]),
        ),
        &hex32(&alice(&keys)["public_hex"]),
        Some(
            pubky_dispatch_core::enc::app_id_decode(executor["app_id"].as_str().expect("id"))
                .expect("app id"),
        ),
        1,
        [80; 16],
        vec![(
            Vec::new(),
            OpKind::AppPut {
                record: doc("executor app record"),
            },
        )],
    )
    .expect("batch");
    let answer = replay
        .service
        .handle(app_request(
            executor,
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&ops, None).to_json(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// Wait, at most ten seconds, until `n` reads of alice's account hold or wait for its turn.
async fn until_queued(replay: &Replay, n: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while replay.db.queued_reads(&alice_id()) != n {
        assert!(
            std::time::Instant::now() < deadline,
            "{n} reads never queued"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn test_allow_reads_of_an_account_wait_their_turn() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    register_executor(&replay).await;
    let keys = vectors("keys.json");
    let now = at();
    let pause = replay.db.pause_next_snapshot_read();
    let exchange = async {
        tokio::join!(
            read_as(&replay, "wallet", &now),
            async {
                tokio::time::timeout(std::time::Duration::from_secs(10), pause.reached.notified())
                    .await
                    .expect("the first read reached its pause");
                // While it is in flight, another app's read of the account waits its turn.
                read_as(&replay, "executor", &now).await
            },
            async {
                // The first holds the account's turn, the second waits for it.
                until_queued(&replay, 2).await;
                // The wallet holds its one place: its second read is refused at once.
                let again = read_as(&replay, "wallet", &now).await;
                assert_eq!(code_of(&again), (503, json!("unavailable")));
                // Neither an app of another identity, nor the signer, nor the directory
                // waits behind it or takes a place in the queue.
                let foreign = from_shop(&replay, "GET", &allow_path(), Vec::new(), None).await;
                assert_eq!(code_of(&foreign), (403, json!("permission_missing")));
                let signer = replay
                    .service
                    .handle(signer_request("GET", &allow_path(), Vec::new(), ms(&now)))
                    .await;
                assert_eq!(code_of(&signer), (403, json!("permission_missing")));
                let directory = replay
                    .service
                    .handle(app_request(
                        app(&keys, "wallet"),
                        "GET",
                        &format!("/v1/{}/directory", alice_id()),
                        Vec::new(),
                        ms(&now),
                    ))
                    .await;
                assert_eq!(directory.status, 200);
                assert_eq!(replay.db.queued_reads(&alice_id()), 2);
                pause.resume.notify_one();
            }
        )
    };
    let (first, second, ()) = tokio::time::timeout(std::time::Duration::from_secs(30), exchange)
        .await
        .expect("both reads ended");
    assert_eq!(first.status, 200);
    // The executor's turn came, and under the lock it is refused: it lacks lists.read.
    assert_eq!(code_of(&second), (403, json!("permission_missing")));
    assert_eq!(replay.db.queued_reads(&alice_id()), 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_waits_for_a_reader_without_the_lock() {
    let config = pubky_dispatch::store::DatabaseConfig {
        snapshot_readers: 1,
        ..Default::default()
    };
    let Some(replay) = replay_with_database(&config).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    // Another account's read holds the one reader.
    let other = pubky_dispatch::store::NewAccount {
        activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
        id: "other".into(),
        identity_key: [9; 32],
        generation: 1,
        created_at_ms: 0,
        limits: pubky_dispatch_core::records::Limits::default(),
        identity_doc: None,
        revoked_apps: Vec::new(),
        enrollment_hash: [0; 32],
        enrollment_store_id: replay.marks.identity().await.expect("store identity"),
        stamped_time_ms: 0,
        stamped_by: replay.service.run().id(),
    };
    assert!(
        replay
            .db
            .store()
            .create_account(&other)
            .await
            .expect("create")
    );
    let held = replay
        .db
        .store()
        .begin_reading("other", [7; 16])
        .await
        .expect("begin")
        .expect("account");
    let now = at();
    let (answer, ()) = tokio::join!(read_as(&replay, "wallet", &now), async {
        until_queued(&replay, 1).await;
        // Let the read reach its wait for a reader.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // It waits holding no lock: a write to the account goes on.
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            wallet_op(&replay, put_code(CODE, ms(&now) + 3_600_000, 1), 91),
        )
        .await
        .expect("the write doesn't wait for the read's reader");
        held.commit().await.expect("release the reader");
    });
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_and_directory_reads_go_on_while_strangers_loop() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let keys = vectors("keys.json");
    let now = at();
    let stop = std::sync::atomic::AtomicBool::new(false);
    // Apps of another identity read the directory and the lists back to back.
    let stranger = |path: String| {
        let (stop, replay) = (&stop, &replay);
        async move {
            let mut sent = 0u32;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                from_shop(replay, "GET", &path, Vec::new(), None).await;
                sent += 1;
            }
            sent
        }
    };
    let own = async {
        let mut statuses = Vec::new();
        for _ in 0..30 {
            statuses.push(read_as(&replay, "wallet", &now).await.status);
            let directory = replay
                .service
                .handle(app_request(
                    app(&keys, "wallet"),
                    "GET",
                    &format!("/v1/{}/directory", alice_id()),
                    Vec::new(),
                    ms(&now),
                ))
                .await;
            statuses.push(directory.status);
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        statuses
    };
    let (sent_directory, sent_allow, statuses) =
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            tokio::join!(
                stranger(format!("/v1/{}/directory", alice_id())),
                stranger(allow_path()),
                own
            )
        })
        .await
        .expect("the reads ended");
    assert!(
        sent_directory > 0 && sent_allow > 0,
        "the strangers sent reads"
    );
    assert_eq!(statuses, vec![200; 60], "the account's own reads all go on");
    replay.db.drop_database().await.expect("drop");
}

/// The executor's reads hold one place of alice's queue at most. With `revoke`, the signer
/// revokes it first; its request still verifies before the lock, so it takes a place and is
/// refused under the lock. Without, it stays current but lacks `lists.read`.
///
/// Its first read is held where it waits for the account's lock, which the test holds from
/// a connection of its own. Meanwhile every further read of the executor is refused at
/// once, and the wallet's read takes a place of its own and waits its turn; once the lock
/// is free, the executor's read is refused, the wallet's answered, and the queue is empty.
async fn refused_reads_hold_one_place(revoke: bool) {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    register_executor(&replay).await;
    let keys = vectors("keys.json");
    let now = at();
    if revoke {
        let id = app(&keys, "executor")["app_id"]
            .as_str()
            .expect("id")
            .to_string();
        let answer = replay
            .service
            .handle(signer_request(
                "POST",
                &format!("/v1/{}/apps/{id}/revoke", alice_id()),
                Vec::new(),
                ms(&now),
            ))
            .await;
        assert_eq!(
            answer.status,
            200,
            "{}",
            String::from_utf8_lossy(&answer.body)
        );
    }
    let mut holder = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let mut lock = sqlx::Connection::begin(&mut holder).await.expect("tx");
    sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(alice_id())
        .execute(&mut *lock)
        .await
        .expect("the account's lock");
    let exchange = async {
        tokio::join!(
            read_as(&replay, "executor", &now),
            async {
                until_queued(&replay, 1).await;
                // Every further read of the executor is refused at once.
                for _ in 0..12 {
                    let again = read_as(&replay, "executor", &now).await;
                    assert_eq!(code_of(&again), (503, json!("unavailable")));
                }
                assert_eq!(replay.db.queued_reads(&alice_id()), 1);
                read_as(&replay, "wallet", &now).await
            },
            async {
                // The wallet's read takes a place of its own, then the lock goes.
                until_queued(&replay, 2).await;
                lock.rollback().await.expect("release the lock");
            }
        )
    };
    let (first, wallet, ()) = tokio::time::timeout(std::time::Duration::from_secs(60), exchange)
        .await
        .expect("the reads ended");
    let refused = if revoke {
        "not_current"
    } else {
        "permission_missing"
    };
    assert_eq!(code_of(&first), (403, json!(refused)));
    assert_eq!(
        wallet.status,
        200,
        "{}",
        String::from_utf8_lossy(&wallet.body)
    );
    assert_eq!(
        replay.db.queued_reads(&alice_id()),
        0,
        "every place is free"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_a_revoked_app_holds_one_place_at_most() {
    refused_reads_hold_one_place(true).await;
}

#[tokio::test]
async fn test_allow_an_app_without_lists_read_holds_one_place_at_most() {
    refused_reads_hold_one_place(false).await;
}
