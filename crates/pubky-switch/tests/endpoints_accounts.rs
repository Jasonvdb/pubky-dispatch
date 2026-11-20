//! The account endpoints' rules on the service, against PostgreSQL: enrollment (Switch wire
//! 3.7, 7.4.1), `identity.json` delivery (7.4.2), the public read (7.4.15), authentication
//! (7.2), and the account's mark (7.3, "Accounts and marks", Tables 1 to 3).
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::{
    http::{Handler, SwitchResponse},
    limits::Limits,
    marks::{AccountMark, MarkRead},
};
use pubky_switch_core::{
    chain::ChainTip,
    enc::b64,
    http::{IdentityDelivery, header},
    keys::IdentityKey,
    records::{Enrollment, EnrollmentBody},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

fn json(response: &SwitchResponse) -> Value {
    serde_json::from_slice(&response.body).expect("json body")
}

fn code(response: &SwitchResponse) -> String {
    json(response)["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn signature_key(response: &SwitchResponse) -> Option<String> {
    response
        .headers
        .iter()
        .find(|(name, _)| name.as_str() == header::SERVICE_SIGNATURE)
        .and_then(|(_, value)| value.to_str().ok())
        .map(str::to_string)
}

struct Alice {
    id: String,
    key: IdentityKey,
}

fn alice_keys() -> Alice {
    let keys = vectors("keys.json");
    let alice = alice(&keys);
    Alice {
        id: alice["pubky_id"].as_str().expect("id").into(),
        key: IdentityKey::from_secret(hex32(&alice["secret_hex"])),
    }
}

/// The vector enrollment's body, with another nonce or origin, signed by alice.
async fn enrollment_body(replay: &Replay, nonce: u8, origin: &str) -> Vec<u8> {
    enrollment_with(replay, nonce, origin, None).await
}

/// The vector enrollment's body with another nonce, origin and `identity_doc`.
async fn enrollment_with(
    replay: &Replay,
    nonce: u8,
    origin: &str,
    identity_doc: Option<SignedDoc>,
) -> Vec<u8> {
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
    fields.origin = origin.into();
    fields.identity_doc = identity_doc;
    fields.intent = if origin == ORIGIN {
        new_alice_enrollment_intent(replay, ms(T)).await
    } else {
        let other = replay_at(origin, "service/alice", Limits::default(), false)
            .await
            .expect("service");
        set_time(&other.clock, T);
        let observation = account_observation_at(&other, &alice_keys().key, origin, ms(T)).await;
        other.db.drop_database().await.expect("drop");
        pubky_switch_core::records::EnrollmentIntent::Create { observation }
    };
    let enrollment = Enrollment::sign(&alice_keys().key, fields).expect("sign");
    serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).expect("json")
}

const T: &str = "2026-01-01T00:00:00.000Z";

/// Enroll alice from current account evidence, then deliver her version 1 at `T`.
async fn serving(replay: &Replay) -> (Vec<u8>, Vec<u8>) {
    let http = vectors("http.json");
    set_time(&replay.clock, "2025-12-30T00:00:00.040Z");
    let request = fresh_alice_enrollment(replay, alice_created()).await;
    let enrollment = request.body.to_vec();
    let enrolled = replay.service.handle(request).await;
    assert_eq!(enrolled.status, 200);
    let wrapper: Value = serde_json::from_slice(&enrollment).expect("enrollment request");
    let signed: SignedDoc =
        serde_json::from_value(wrapper["enrollment"].clone()).expect("enrollment");
    let expected = named(
        &http["responses"],
        "signer: enrollment answer, signed with the service key",
    );
    let mut expected: Value = serde_json::from_str(expected["body"].as_str().expect("answer body"))
        .expect("enrollment answer");
    expected["enrollment"] = json!(b64(&signed.doc_hash().expect("enrollment hash")));
    assert_eq!(json(&enrolled), expected);
    let first_answer = enrolled.body.to_vec();
    set_time(&replay.clock, "2025-12-30T00:00:02.000Z");
    let delivered = replay
        .service
        .handle(vector_request(named(
            &http["requests"],
            "signer: identity.json delivery",
        )))
        .await;
    assert_eq!(
        delivered.status,
        200,
        "{}",
        String::from_utf8_lossy(&delivered.body)
    );
    set_time(&replay.clock, T);
    (enrollment, first_answer)
}

fn version(name: &str) -> SignedDoc {
    let documents = vectors("documents.json");
    serde_json::from_value(named(&documents["documents"], name)["signed"].clone()).expect("doc")
}

fn delivery(doc: SignedDoc, prev: Option<[u8; 32]>) -> Vec<u8> {
    IdentityDelivery {
        identity: doc,
        prev,
    }
    .to_json()
}

#[tokio::test]
async fn test_enroll_same_enrollment_same_answer() {
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    set_time(&replay.clock, T);
    let body = enrollment_body(&replay, 1, ORIGIN).await;
    let first = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body.clone(), ms(T)))
        .await;
    assert_eq!(first.status, 200);
    let again = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
        .await;
    assert_eq!(
        again.body, first.body,
        "the same enrollment, the same answer"
    );
    // Another enrollment while staged: the same key, its own nonce and hash.
    let other = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(&replay, 2, ORIGIN).await,
            ms(T),
        ))
        .await;
    assert_eq!(json(&other)["service_key"], json(&first)["service_key"]);
    assert_ne!(json(&other)["enrollment"], json(&first)["enrollment"]);
    assert_eq!(json(&first)["identity"], alice.id.as_str());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_serving_account_answers_the_current_key() {
    // Another enrollment at a serving account gets the service's current key, the one the
    // account is answered with, and changes nothing by itself (Switch wire 3.7, 7.4.1).
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let account_key = vectors("keys.json")["service_keys"][0]["public"].clone();
    for nonce in [3, 4] {
        let request = signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(&replay, nonce, ORIGIN).await,
            ms(T),
        );
        let sent = Sent::of(&request);
        let answer = replay.service.handle(request).await;
        assert_eq!(answer.status, 200);
        assert_eq!(json(&answer)["service_key"], account_key, "nonce {nonce}");
        assert!(signed_with(&answer, &service_public(&replay), &sent));
        assert!(header_of(&answer, header::HEAD).is_none(), "no head");
    }
    // The account still serves at its head, its mark where the delivery left it.
    let alice = alice_keys();
    let read = replay
        .service
        .handle(request(
            "GET",
            &format!("/v1/{}/identity", alice.id),
            &[],
            Vec::new(),
        ))
        .await;
    assert_eq!(read.status, 200);
    let mark = mark_of(&replay, &alice.id).await;
    assert_eq!((mark.generation, mark.seq), (1, 1));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_refusals() {
    let Some(replay) = replay().await else { return };
    set_time(&replay.clock, T);
    // Another origin.
    let wrong_origin = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(&replay, 5, "https://other.example").await,
            ms(T),
        ))
        .await;
    assert_eq!(
        (wrong_origin.status, code(&wrong_origin).as_str()),
        (400, "bad_request")
    );
    // A request signature over another body.
    let mut tampered = signer_request(
        "POST",
        "/v1/enroll",
        enrollment_body(&replay, 6, ORIGIN).await,
        ms(T),
    );
    tampered.body = enrollment_body(&replay, 7, ORIGIN).await.into();
    let refused = replay.service.handle(tampered).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (401, "bad_signature")
    );
    assert!(
        signature_key(&refused).is_some(),
        "signed with the service key"
    );
    // An app of the identity.
    let mut app = signer_request(
        "POST",
        "/v1/enroll",
        enrollment_body(&replay, 8, ORIGIN).await,
        ms(T),
    );
    app.headers.insert(
        header::APP,
        "wejf37ngr7qizej3eoijn3hq4c".parse().expect("value"),
    );
    let refused = replay.service.handle(app).await;
    assert_eq!(code(&refused), "permission_missing");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_identity_retry_and_stale_prev() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    let version_1 = version("alice identity.json, first delivery (version 1)");
    let version_3 = version("alice identity.json");

    // Version 1 again, whatever prev it names: the original proof, no new item.
    let retry = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            delivery(version_1.clone(), Some([9; 32])),
            ms(T),
        ))
        .await;
    assert_eq!(retry.status, 200);
    let retried = json(&retry);
    assert_eq!(retried["proofs"].as_array().expect("proofs").len(), 1);
    assert_eq!(retried["head"]["seq"], 1, "no new chain item");

    // Version 3 on a prev that isn't the newest held: the held copy comes back.
    let stale = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            delivery(version_3, Some([9; 32])),
            ms(T),
        ))
        .await;
    assert_eq!(
        (stale.status, code(&stale).as_str()),
        (409, "stale_identity")
    );
    let current = &json(&stale)["current"];
    assert_eq!(current["version"], 1);
    assert_eq!(current["hash"], b64(&version_1.doc_hash().expect("hash")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_identity_callers_and_timestamps() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    let body = delivery(version("alice identity.json"), None);

    // An own app isn't current before app records are served.
    let app = app_request(
        app(&vectors("keys.json"), "wallet"),
        "PUT",
        &path,
        body.clone(),
        ms(T),
    );
    assert_eq!(code(&replay.service.handle(app).await), "not_current");

    // A timestamp 5 minutes and a second off: 401, counted against the network source.
    let mut stale = signer_request("PUT", &path, body, ms(T) - 301_000);
    let source = Some(pubky_switch::http::source::NetworkSource::of(
        "203.0.113.9".parse().expect("ip"),
    ));
    stale.source = source;
    let refused = replay.service.handle(stale).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (401, "stale_timestamp")
    );
    let claimed = (alice.id.clone(), alice.id.clone(), None);
    assert_eq!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, ms(T)),
        1
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_public_identity_staged_and_limits() {
    let Some(replay) = replay_with(Limits {
        identity_reads_per_source_per_min: 2,
        identity_reads_per_min: 3,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    set_time(&replay.clock, T);
    let read = |source: &str| {
        let mut request = request("GET", &path, &[], Vec::new());
        request.source = Some(pubky_switch::http::source::NetworkSource::of(
            source.parse().expect("ip"),
        ));
        request
    };

    // Enrolled without a document: nothing to read.
    let enrolled = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(&replay, 1, ORIGIN).await,
            ms(T),
        ))
        .await;
    assert_eq!(enrolled.status, 200);
    assert_eq!(
        code(&replay.service.handle(read("203.0.113.1")).await),
        "not_found"
    );

    replay.db.drop_database().await.expect("drop");

    // Enrolled by a new provider with a document naming another service: the account
    // holds it, and stays staged until a document names it.
    let Some(replay) = replay_with(Limits::default()).await else {
        return;
    };
    set_time(&replay.clock, T);
    let elsewhere = version(
        "alice identity.json after the move to the next service (version 7, generation 2), \
         keeping generation 1's service key in service_keys",
    );
    let enrolled = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_with(&replay, 2, ORIGIN, Some(elsewhere)).await,
            ms(T),
        ))
        .await;
    assert_eq!(
        enrolled.status,
        200,
        "{}",
        String::from_utf8_lossy(&enrolled.body)
    );
    let staged = replay.service.handle(read("203.0.113.1")).await;
    assert_eq!((staged.status, code(&staged).as_str()), (503, "staged"));
    replay.db.drop_database().await.expect("drop");

    // The limits, on a serving account: 2 per source, a backstop of 3 for the account, and
    // a source's refused reads don't count against the backstop.
    let Some(replay) = replay_with(Limits {
        identity_reads_per_source_per_min: 2,
        identity_reads_per_min: 3,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    serving(&replay).await;
    let read = |source: &str| {
        let mut request = request("GET", &path, &[], Vec::new());
        request.source = Some(pubky_switch::http::source::NetworkSource::of(
            source.parse().expect("ip"),
        ));
        request
    };
    for _ in 0..2 {
        assert_eq!(replay.service.handle(read("203.0.113.1")).await.status, 200);
    }
    let limited = replay.service.handle(read("203.0.113.1")).await;
    assert_eq!(
        (limited.status, code(&limited).as_str()),
        (429, "rate_limited")
    );
    assert!(json(&limited)["retry_after"].is_u64());
    // The backstop has 1 read left: the refused one didn't count.
    assert_eq!(replay.service.handle(read("203.0.113.2")).await.status, 200);
    assert_eq!(
        code(&replay.service.handle(read("203.0.113.3")).await),
        "rate_limited",
        "the account's backstop"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_state_behind_the_mark_fails_stop() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    // A backup from before the first delivery is restored: the account's mark is at seq 1.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "UPDATE accounts SET last_seq = 0, chain_seq = NULL, chain_hash = NULL WHERE id = $1",
    )
    .bind(&alice.id)
    .execute(&mut conn)
    .await
    .expect("restore");
    conn.close().await.expect("close");
    let read = request(
        "GET",
        &format!("/v1/{}/identity", alice.id),
        &[],
        Vec::new(),
    );
    let refused = replay.service.handle(read).await;
    assert_notice(&refused, 1, "behind");
    let put = replay
        .service
        .handle(signer_request(
            "PUT",
            &format!("/v1/{}/identity", alice.id),
            delivery(version("alice identity.json"), None),
            ms(T),
        ))
        .await;
    assert_notice(&put, 1, "behind");
    // Each refusal is counted, for the operator's alert (Switch spec 6.5).
    assert_eq!(replay.service.mark_refusals(), 2);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_calls_not_served_yet() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    for (method, suffix) in [
        ("POST", "freeze"),
        ("POST", "unfreeze"),
        ("GET", "export"),
        ("GET", "export/chunks/1"),
        ("POST", "import"),
        ("PUT", "import/chunks/1"),
        ("POST", "import/activate"),
    ] {
        let path = format!("/v1/{}/{suffix}", alice.id);
        let unserved = replay
            .service
            .handle(request(method, &path, &[], Vec::new()))
            .await;
        assert_eq!(
            (unserved.status, code(&unserved).as_str()),
            (503, "unavailable"),
            "{method} {path}"
        );
        assert!(signature_key(&unserved).is_some(), "{method} {path}");
    }
    replay.db.drop_database().await.expect("drop");
}

/// alice's version 1 with `change` applied, signed by her identity key.
fn alice_version(change: impl FnOnce(&mut pubky_switch_core::records::IdentityBody)) -> SignedDoc {
    let version_1 = version("alice identity.json, first delivery (version 1)");
    let mut body: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&version_1.body_bytes().expect("body")).expect("identity body");
    change(&mut body);
    pubky_switch_core::records::IdentityDoc::sign(&alice_keys().key, body)
        .expect("sign")
        .signed()
        .clone()
}

fn header_of<'a>(response: &'a SwitchResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header, _)| header.as_str() == name)
        .and_then(|(_, value)| value.to_str().ok())
}

#[tokio::test]
async fn test_authentication_takes_no_account_lock() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    // Another request holds the account's lock.
    let held = replay
        .db
        .store()
        .begin(&alice.id)
        .await
        .expect("begin")
        .expect("account");
    let mut garbage = signer_request(
        "PUT",
        &path,
        delivery(version("alice identity.json"), None),
        ms(T),
    );
    garbage
        .headers
        .insert(header::SIGNATURE, b64(&[7u8; 64]).parse().expect("value"));
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        replay.service.handle(garbage),
    )
    .await
    .expect("answered without waiting for the lock");
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (401, "bad_signature")
    );
    drop(held);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_authentication_refusals_at_put_identity() {
    let Some(replay) = replay_with(Limits {
        auth_failures_per_source_per_min: 2,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    serving(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    let body = delivery(version("alice identity.json"), None);
    let source = Some(pubky_switch::http::source::NetworkSource::of(
        "203.0.113.9".parse().expect("ip"),
    ));

    // Signed with another key than alice's identity key.
    let keys = vectors("keys.json");
    let bob = keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .expect("bob");
    let mut wrong_key = signer_request("PUT", &path, body.clone(), ms(T));
    let bob_key = ed25519_dalek::SigningKey::from_bytes(&hex32(&bob["secret_hex"]));
    let timestamp = pubky_switch_core::time::rfc3339_seconds(ms(T));
    let forged = pubky_switch_core::http::sign_request(
        &bob_key,
        &pubky_switch_core::http::RequestTarget {
            method: "PUT",
            path_and_query: &path,
            body: &body,
            origin: ORIGIN,
        },
        &pubky_switch_core::http::RequestHeaders {
            timestamp,
            identity: alice.id.clone(),
            ..Default::default()
        },
    );
    wrong_key
        .headers
        .insert(header::SIGNATURE, b64(&forged).parse().expect("value"));
    wrong_key.source = source;
    let refused = replay.service.handle(wrong_key).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (401, "bad_signature")
    );

    // Another identity's signer.
    let mut other = signer_request("PUT", &path, body.clone(), ms(T));
    other.headers.insert(
        header::IDENTITY,
        bob["pubky_id"]
            .as_str()
            .expect("id")
            .parse()
            .expect("value"),
    );
    assert_eq!(code(&replay.service.handle(other).await), "not_admitted");

    // The second failure from the source fills its limit of 2; the next request from it is
    // refused before any signature work, even a correctly signed one.
    let mut stale = signer_request("PUT", &path, body.clone(), ms(T) - 301_000);
    stale.source = source;
    assert_eq!(code(&replay.service.handle(stale).await), "stale_timestamp");
    let mut good = signer_request("PUT", &path, body, ms(T));
    good.source = source;
    let limited = replay.service.handle(good).await;
    assert_eq!(
        (limited.status, code(&limited).as_str()),
        (429, "rate_limited")
    );
    assert!(header_of(&limited, header::RETRY_AFTER).is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_signer_error_answers_carry_the_head() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let stale = replay
        .service
        .handle(signer_request(
            "PUT",
            &format!("/v1/{}/identity", alice.id),
            delivery(version("alice identity.json"), Some([9; 32])),
            ms(T),
        ))
        .await;
    assert_eq!(code(&stale), "stale_identity");
    let head = pubky_switch_core::chain::SignedHead::from_header(
        header_of(&stale, header::HEAD).expect("a head on the signer's error answer"),
    )
    .expect("head");
    let service_key: [u8; 32] = pubky_switch_core::enc::unb64(
        vectors("keys.json")["service_keys"][0]["public"]
            .as_str()
            .expect("public"),
    )
    .expect("b64")
    .try_into()
    .expect("32 bytes");
    head.verify(&service_key, &alice.key.public())
        .expect("the head verifies");
    assert_eq!(head.seq, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_delivery_away_from_this_service_moves_the_mark() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let version_1 = version("alice identity.json, first delivery (version 1)");
    let away = alice_version(|body| {
        body.version = 2;
        body.inbox.url = "https://other.example".into();
    });
    let answer = replay
        .service
        .handle(signer_request(
            "PUT",
            &format!("/v1/{}/identity", alice.id),
            delivery(away, Some(version_1.doc_hash().expect("hash"))),
            ms(T),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(json(&answer)["head"]["seq"], 2);
    let mark = mark_of(&replay, &alice.id).await;
    assert_eq!(
        (mark.generation, mark.seq),
        (1, 2),
        "the head the answer carried is marked"
    );
    assert_eq!(mark.key, service_public(&replay));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enrollment_answer_keeps_its_limits_after_a_config_change() {
    let Some(replay) = replay().await else { return };
    set_time(&replay.clock, T);
    let body = enrollment_body(&replay, 1, ORIGIN).await;
    let first = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body.clone(), ms(T)))
        .await;
    assert_eq!(first.status, 200);
    let restarted = replay.restarted_with(Limits {
        app_limit: 40,
        quota_bytes: 2 * Limits::default().quota_bytes,
        ..Limits::default()
    });
    let again = restarted
        .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
        .await;
    assert_eq!(
        String::from_utf8_lossy(&again.body),
        String::from_utf8_lossy(&first.body),
        "the same enrollment, the same answer"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_commit_failure_answer_keeps_the_committed_time() {
    let Some(replay) = replay().await else { return };
    set_time(&replay.clock, T);
    let enrolled = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(&replay, 1, ORIGIN).await,
            ms(T),
        ))
        .await;
    assert_eq!(enrolled.status, 200);
    // Every commit that changes the account now fails, at the commit itself.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for statement in [
        "CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'refused at commit'; END $$",
        "CREATE CONSTRAINT TRIGGER refuse_at_commit AFTER UPDATE ON accounts \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    conn.close().await.expect("close");
    let later = ms(T) + 60_000;
    set_time(&replay.clock, &pubky_switch_core::time::rfc3339(later));
    let http = vectors("http.json");
    let mut put = vector_request(named(&http["requests"], "signer: identity.json delivery"));
    put = signer_request_at_creation(
        "PUT",
        &put.path_and_query,
        put.body.to_vec(),
        later,
        Some(ms(T)),
    );
    let failed = replay.service.handle(put).await;
    assert_eq!(code(&failed), "unavailable");
    assert_eq!(
        header_of(&failed, header::SERVER_TIME),
        Some(pubky_switch_core::time::rfc3339(ms(T)).as_str()),
        "the answer shows the committed time, not the stamp that didn't commit"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_concurrent_first_enrollments_share_one_account() {
    let Some(replay) = replay().await else { return };
    set_time(&replay.clock, T);
    let body = enrollment_body(&replay, 1, ORIGIN).await;
    let (a, b) = tokio::join!(
        replay
            .service
            .handle(signer_request("POST", "/v1/enroll", body.clone(), ms(T))),
        replay
            .service
            .handle(signer_request("POST", "/v1/enroll", body, ms(T))),
    );
    assert_eq!((a.status, b.status), (200, 200));
    assert_eq!(json(&a)["service_key"], json(&b)["service_key"]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_refused_delivery_leaves_nothing_to_build_on() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    // A backup from before the first delivery is restored: no document and no chain, while
    // the account's mark is at the first delivery's seq 1: the account is bounded (Switch
    // wire 7.3, Table 1).
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for statement in [
        "UPDATE accounts SET last_seq = 0, chain_seq = NULL, chain_hash = NULL, \
         identity_doc = NULL, identity_proof = NULL WHERE id = $1",
        "DELETE FROM chain_items WHERE account_id = $1",
    ] {
        sqlx::query(statement)
            .bind(&alice.id)
            .execute(&mut conn)
            .await
            .expect("restore");
    }
    // Version 1 again, at another time: a seq 1 beside the mark, which no head may show.
    // It starts no generation above the mark's, so it gets the notice (Table 2).
    let path = format!("/v1/{}/identity", alice.id);
    let version_1 = version("alice identity.json, first delivery (version 1)");
    let refused = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            delivery(version_1.clone(), None),
            ms(T),
        ))
        .await;
    assert_notice(&refused, 1, "behind");
    // Nothing of the refused delivery was kept, so a later one can't extend it.
    let (last_seq, doc): (i64, Option<Vec<u8>>) =
        sqlx::query_as("SELECT last_seq, identity_doc FROM accounts WHERE id = $1")
            .bind(&alice.id)
            .fetch_one(&mut conn)
            .await
            .expect("account");
    assert_eq!((last_seq, doc), (0, None));
    let extended = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            delivery(
                version("alice identity.json"),
                Some(version_1.doc_hash().expect("hash")),
            ),
            ms(T),
        ))
        .await;
    assert_ne!(
        extended.status,
        200,
        "{}",
        String::from_utf8_lossy(&extended.body)
    );
    assert!(header_of(&extended, header::HEAD).is_none());
    conn.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_identity_first_delivery_refuses_an_enrolled_revoked_app() {
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    set_time(&replay.clock, T);
    // An enrollment without identity_doc whose revoked_apps names the wallet, which version 1
    // lists as current.
    let keys = vectors("keys.json");
    let wallet: [u8; 16] = hex::decode(
        keys["apps"]
            .as_array()
            .expect("apps")
            .iter()
            .find(|app| app["name"] == "wallet")
            .expect("the wallet")["app_id_bytes_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex")
    .try_into()
    .expect("16 bytes");
    let http = vectors("http.json");
    let vector = named(&http["requests"], "signer: enrollment");
    let body: Value = serde_json::from_slice(
        &pubky_switch_core::enc::unb64(vector["body_b64"].as_str().expect("body")).expect("b64"),
    )
    .expect("json");
    let signed: SignedDoc = serde_json::from_value(body["enrollment"].clone()).expect("signed");
    let mut fields: EnrollmentBody =
        serde_json::from_slice(&signed.body_bytes().expect("body")).expect("enrollment body");
    fields.identity_doc = None;
    fields.revoked_apps = Some(vec![wallet]);
    fields.intent = new_alice_enrollment_intent(&replay, ms(T)).await;
    let enrollment = Enrollment::sign(&alice.key, fields).expect("sign");
    let body = serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).expect("json");
    let enrolled = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
        .await;
    assert_eq!(
        enrolled.status,
        200,
        "{}",
        String::from_utf8_lossy(&enrolled.body)
    );
    let path = format!("/v1/{}/identity", alice.id);
    let delivered = replay
        .service
        .handle(signer_request_at_creation(
            "PUT",
            &path,
            delivery(
                version("alice identity.json, first delivery (version 1)"),
                None,
            ),
            ms(T),
            Some(ms(T)),
        ))
        .await;
    assert_eq!(
        (delivered.status, code(&delivered).as_str()),
        (400, "bad_request"),
        "{}",
        String::from_utf8_lossy(&delivered.body)
    );
    let read = replay
        .service
        .handle(request("GET", &path, &[], Vec::new()))
        .await;
    assert_eq!(read.status, 404, "nothing is served");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_retry_after_serving_gets_the_first_answer() {
    let Some(replay) = replay().await else { return };
    let (body, first_answer) = serving(&replay).await;
    // The same signed enrollment, under a fresh request signature, once the account
    // serves: the answer it got first.
    let again = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
        .await;
    assert_eq!(again.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&again.body),
        String::from_utf8_lossy(&first_answer),
        "the same enrollment, the same answer"
    );
    // A new enrollment gets the current key, the account's.
    let other = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(&replay, 5, ORIGIN).await,
            ms(T),
        ))
        .await;
    assert_eq!(
        json(&other)["service_key"],
        vectors("keys.json")["service_keys"][0]["public"]
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_stale_timestamp_gives_a_time_to_retry_with() {
    let Some(replay) = replay().await else { return };
    // The account last committed on December 30, and is idle until January 1.
    serving(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    let body = delivery(version("alice identity.json"), None);
    let last_committed = "2025-12-30T00:00:02.000Z";
    let stale = signer_request("PUT", &path, body.clone(), ms(last_committed));
    let refused = replay.service.handle(stale).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (401, "stale_timestamp")
    );
    // The refusal commits nothing: its signed time is the last time the service committed
    // for the identity, which it doesn't move; the body gives the time base (Switch wire
    // 7.1 Timestamp).
    assert_eq!(
        header_of(&refused, header::SERVER_TIME),
        Some(last_committed)
    );
    assert_eq!(
        replay
            .db
            .store()
            .lookup(&alice.id)
            .await
            .expect("lookup")
            .expect("account")
            .stamped_time_ms,
        ms(last_committed),
        "the refusal stamps nothing"
    );
    let retry_at = json(&refused)["current"]["server_time"]
        .as_str()
        .expect("current.server_time")
        .to_string();
    assert_eq!(retry_at, T);
    let retried = replay
        .service
        .handle(signer_request("PUT", &path, body, ms(&retry_at)))
        .await;
    assert_ne!(code(&retried), "stale_timestamp");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_answers_keep_the_creating_one_and_drop_the_oldest() {
    let limits = Limits {
        max_enrollments: 2,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    let (body, first_answer) = serving(&replay).await;
    let alice = alice_keys();
    // Three more enrollments, all at one time.
    let mut newest = [0; 32];
    for nonce in 11..=13 {
        let body = enrollment_body(&replay, nonce, ORIGIN).await;
        let value: Value = serde_json::from_slice(&body).expect("json");
        let signed: SignedDoc = serde_json::from_value(value["enrollment"].clone()).expect("doc");
        newest = signed.doc_hash().expect("hash");
        let answer = replay
            .service
            .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
            .await;
        assert_eq!(answer.status, 200);
    }
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let kept: Vec<(Vec<u8>, bool)> = sqlx::query_as(
        "SELECT enrollment_hash, creating FROM enrollment_answers WHERE account_id = $1 \
         ORDER BY kept_order",
    )
    .bind(&alice.id)
    .fetch_all(&mut conn)
    .await
    .expect("answers");
    conn.close().await.expect("close");
    // The creating answer stays for good; of the others, the newest two.
    // The creating answer counts towards the bound: with it, the newest of the others.
    assert_eq!(kept.len(), 2);
    assert!(kept[0].1, "the creating enrollment's answer stays");
    assert_eq!(kept[1].0, newest.to_vec(), "the newest of the others stays");
    // The creating enrollment again: its own answer, byte for byte.
    let again = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
        .await;
    assert_eq!(
        String::from_utf8_lossy(&again.body),
        String::from_utf8_lossy(&first_answer)
    );
    replay.db.drop_database().await.expect("drop");
}

/// An enrollment at alice's account, by its nonce.
async fn enroll(replay: &Replay, nonce: u8) -> pubky_switch::http::SwitchResponse {
    replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(replay, nonce, ORIGIN).await,
            ms(T),
        ))
        .await
}

#[tokio::test]
async fn test_enroll_answer_dropped_past_the_bound_is_built_again() {
    // At most `max_enrollments` answers are kept, the creating one for good and the oldest
    // of the others dropping; an enrollment whose answer dropped gets the same answer,
    // built again, since every answer names the current key (Switch wire 3.7, 9.1).
    let Some(replay) = replay().await else { return };
    set_time(&replay.clock, T);
    // The creating enrollment, then a second while the account is staged: the service key.
    let first = enroll(&replay, 20).await;
    let second_body = enrollment_body(&replay, 21, ORIGIN).await;
    let second = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            second_body.clone(),
            ms(T),
        ))
        .await;
    assert_eq!(second.status, 200);
    assert_eq!(json(&second)["service_key"], json(&first)["service_key"]);
    // The account serves, and 16 fresh enrollments get the current key.
    let alice = alice_keys();
    let delivered = replay
        .service
        .handle(signer_request_at_creation(
            "PUT",
            &format!("/v1/{}/identity", alice.id),
            delivery(
                version("alice identity.json, first delivery (version 1)"),
                None,
            ),
            ms(T),
            Some(ms(T)),
        ))
        .await;
    assert_eq!(
        delivered.status,
        200,
        "{}",
        String::from_utf8_lossy(&delivered.body)
    );
    for nonce in 30..46 {
        let answer = enroll(&replay, nonce).await;
        assert_eq!(json(&answer)["service_key"], json(&first)["service_key"]);
    }
    let value: Value = serde_json::from_slice(&second_body).expect("json");
    let signed: SignedDoc = serde_json::from_value(value["enrollment"].clone()).expect("doc");
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let held: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM enrollment_answers WHERE account_id = $1 AND enrollment_hash = $2",
    )
    .bind(&alice.id)
    .bind(signed.doc_hash().expect("hash").as_slice())
    .fetch_one(&mut conn)
    .await
    .expect("answers");
    conn.close().await.expect("close");
    assert_eq!(held, 0, "the second answer dropped");
    // The second enrollment again: its own answer, byte for byte.
    let again = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", second_body, ms(T)))
        .await;
    assert_eq!(
        again.body, second.body,
        "the same enrollment, the same answer"
    );
    replay.db.drop_database().await.expect("drop");
}

/// Run `sql` on the replay's database.
async fn run_sql(replay: &Replay, sql: &str) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::raw_sql(sql).execute(&mut conn).await.expect("sql");
    conn.close().await.expect("close");
}

/// The database refuses every write of `when` on `accounts`.
async fn refuse(replay: &Replay, when: &str) {
    run_sql(
        replay,
        &format!(
            "CREATE FUNCTION refuse_write() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'refused'; END $$; \
             CREATE CONSTRAINT TRIGGER refuse AFTER {when} ON accounts \
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_write()"
        ),
    )
    .await;
}

/// alice's mark, which must read as one.
async fn mark_of(replay: &Replay, id: &str) -> AccountMark {
    match replay.marks.read(id).await.expect("the mark store") {
        MarkRead::Mark(mark) => mark,
        other => panic!("no mark: {other:?}"),
    }
}

/// The notice `503 recovery_required` at `generation` with `reason`, not permanent, without
/// a head (Switch wire 7.3, Table 2; 7.6).
fn assert_notice(response: &SwitchResponse, generation: u64, reason: &str) {
    assert_notice_of(response, generation, reason, false);
}

/// [`assert_notice`], `permanent` as given.
fn assert_notice_of(response: &SwitchResponse, generation: u64, reason: &str, permanent: bool) {
    assert_eq!(
        (response.status, code(response).as_str()),
        (503, "recovery_required"),
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(
        json(response)["current"],
        json!({ "generation": generation, "reason": reason, "permanent": permanent })
    );
    assert!(header_of(response, header::HEAD).is_none(), "no head");
}

/// How many accounts the database holds for `id`.
async fn accounts_of(replay: &Replay, id: &str) -> i64 {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&mut conn)
        .await
        .expect("count");
    conn.close().await.expect("close");
    count
}

/// The creation time the database holds for `id`'s account.
async fn created_at_of(replay: &Replay, id: &str) -> u64 {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let at: i64 = sqlx::query_scalar("SELECT created_at_ms FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&mut conn)
        .await
        .expect("created_at_ms");
    conn.close().await.expect("close");
    u64::try_from(at).expect("a time")
}

fn assert_fresh_creation_mark(mark: AccountMark, key: [u8; 32], created: u64, committed: bool) {
    let anchor = mark
        .creation_anchor
        .for_creation(created)
        .expect("fresh creation commitment");
    assert_ne!(anchor, [0; 32]);
    assert!(matches!(
        mark.creation_anchor,
        pubky_switch::marks::CreationAnchor::Bound { confirmed, .. } if confirmed == committed
    ));
    assert_eq!(
        mark,
        AccountMark {
            creation_anchor: mark.creation_anchor,
            ..AccountMark::zero(key, created)
        }
    );
}

#[tokio::test]
async fn test_enroll_writes_the_zero_mark_before_the_account() {
    // An enrollment that creates an account writes (0, 0) durably first, with the current
    // key and the creation time, and only then creates the account (Switch wire 7.3, Table
    // 3): where the account's creation doesn't commit, the mark is there all the same.
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    let key = service_public(&replay);
    set_time(&replay.clock, T);
    refuse(&replay, "INSERT").await;
    let refused = enroll(&replay, 1).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (503, "unavailable")
    );
    assert_eq!(accounts_of(&replay, &alice.id).await, 0, "no account");
    assert_fresh_creation_mark(mark_of(&replay, &alice.id).await, key, ms(T), false);
    replay.db.drop_database().await.expect("drop");

    // A durable account confirms its opening and retains the same creation time.
    let Some(replay) = support::replay().await else {
        return;
    };
    set_time(&replay.clock, T);
    let enrolled = enroll(&replay, 1).await;
    assert_eq!(enrolled.status, 200);
    assert_fresh_creation_mark(mark_of(&replay, &alice.id).await, key, ms(T), true);
    assert_eq!(created_at_of(&replay, &alice.id).await, ms(T));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_takes_a_zero_mark_left_without_an_account() {
    // A creation cut short between the mark and the account leaves a (0, 0) mark and no
    // account: the next enrollment creates the account, which takes that mark with the
    // current key and its own creation time (Switch wire 7.3, Table 3).
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    set_time(&replay.clock, T);
    refuse(&replay, "INSERT").await;
    assert_eq!(enroll(&replay, 1).await.status, 503);
    assert_eq!(accounts_of(&replay, &alice.id).await, 0);
    let previous = mark_of(&replay, &alice.id).await.creation_anchor;
    assert!(previous.for_creation(ms(T)).is_some());
    run_sql(&replay, "DROP TRIGGER refuse ON accounts").await;
    let later = ms(T) + 60_000;
    set_time(&replay.clock, &pubky_switch_core::time::rfc3339(later));
    let enrolled = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(&replay, 2, ORIGIN).await,
            later,
        ))
        .await;
    assert_eq!(
        enrolled.status,
        200,
        "{}",
        String::from_utf8_lossy(&enrolled.body)
    );
    assert_eq!(accounts_of(&replay, &alice.id).await, 1);
    assert_eq!(created_at_of(&replay, &alice.id).await, later);
    assert_eq!(
        mark_of(&replay, &alice.id).await,
        AccountMark {
            creation_anchor: previous,
            ..AccountMark::zero(service_public(&replay), later)
        },
        "taken, with the new creation time"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_takes_over_a_lost_accounts_mark() {
    // alice's account is lost: her mark records a head at generation 1, and there is no
    // account and no erasure's record. Every call gets the notice `behind` at the mark's
    // generation. An enrollment creates a staged account that takes the mark over: its head
    // and retirements stay, its key and creation time are the new account's; the account
    // is bounded. Only a start above both generations, with `recovery_from` its generation
    // less one, serves it (Switch wire 7.3, Tables 1 to 3).
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    let key = service_public(&replay);
    let lost_at = ms(T) - 86_400_000;
    replay
        .marks
        .create_zero(&alice.id, key, lost_at)
        .await
        .expect("a mark");
    let head = ChainTip {
        generation: 1,
        seq: 5,
        chain_hash: [9; 32],
    };
    replay
        .marks
        .advance(
            &alice.id,
            keeping_count(&replay.marks, &alice.id, head).await,
            key,
            mark_created_at(&replay, &alice.id).await,
        )
        .await
        .expect("a head");
    set_time(&replay.clock, T);
    let path = format!("/v1/{}/identity", alice.id);
    let read = request("GET", &path, &[], Vec::new());
    let sent = Sent::of(&read);
    let answer = replay.service.handle(read).await;
    assert_notice(&answer, 1, "behind");
    assert!(signed_with(&answer, &key, &sent), "the key in the mark");
    let apps = signer_request_at_creation(
        "GET",
        &format!("/v1/{}/apps", alice.id),
        Vec::new(),
        ms(T),
        Some(lost_at),
    );
    assert_notice(&replay.service.handle(apps).await, 1, "behind");
    let first = delivery(
        version("alice identity.json, first delivery (version 1)"),
        None,
    );
    let put = signer_request_at_creation("PUT", &path, first.clone(), ms(T), Some(lost_at));
    assert_notice(&replay.service.handle(put).await, 1, "behind");
    // Retired by the operator: the notice is permanent, and the retirement outlives the
    // take-over.
    replay.marks.retire(&alice.id, 1).await.expect("retire");
    let apps = signer_request_at_creation(
        "GET",
        &format!("/v1/{}/apps", alice.id),
        Vec::new(),
        ms(T),
        Some(lost_at),
    );
    assert_notice_of(&replay.service.handle(apps).await, 1, "behind", true);

    let enrolled = enroll(&replay, 1).await;
    assert_eq!(
        enrolled.status,
        200,
        "{}",
        String::from_utf8_lossy(&enrolled.body)
    );
    assert_eq!(json(&enrolled)["service_key"], b64(&key));
    assert_eq!(
        mark_of(&replay, &alice.id).await,
        AccountMark {
            state_tag: [0; 16],
            generation: 1,
            seq: 5,
            chain_hash: [9; 32],
            creation_anchor: Default::default(),
            state_version: 0,
            time_floor_ms: 0,
            key,
            created_at_ms: ms(T),
        },
        "the head stays; the key and the creation time are the new account's"
    );
    assert_eq!(replay.marks.retired(&alice.id).await.expect("retired"), [1]);
    assert_eq!(created_at_of(&replay, &alice.id).await, ms(T));
    // Staged and bounded by the mark.
    let apps = signer_request_at_creation(
        "GET",
        &format!("/v1/{}/apps", alice.id),
        Vec::new(),
        ms(T),
        Some(ms(T)),
    );
    assert_notice_of(&replay.service.handle(apps).await, 1, "behind", true);
    let put = signer_request_at_creation("PUT", &path, first, ms(T), Some(ms(T)));
    assert_notice_of(&replay.service.handle(put).await, 1, "behind", true);
    for (generation, recovery_from) in [(2, None), (2, Some(0)), (1, Some(0))] {
        let doc = alice_version(|body| {
            body.version = 2;
            body.generation = generation;
            body.recovery_from = recovery_from;
        });
        let put = signer_request_at_creation("PUT", &path, delivery(doc, None), ms(T), Some(ms(T)));
        assert_notice_of(&replay.service.handle(put).await, 1, "behind", true);
    }
    // The start above both generations serves it.
    let start = alice_version(|body| {
        body.version = 2;
        body.generation = 2;
        body.recovery_from = Some(1);
    });
    let put = signer_request_at_creation("PUT", &path, delivery(start, None), ms(T), Some(ms(T)));
    let sent = Sent::of(&put);
    let started = replay.service.handle(put).await;
    assert_eq!(
        started.status,
        200,
        "{}",
        String::from_utf8_lossy(&started.body)
    );
    assert!(signed_with(&started, &key, &sent));
    assert_eq!(json(&started)["head"]["generation"], 2);
    let mark = mark_of(&replay, &alice.id).await;
    assert_eq!(
        (mark.generation, mark.seq, mark.created_at_ms),
        (2, 2, ms(T))
    );
    let apps = signer_request_at_creation(
        "GET",
        &format!("/v1/{}/apps", alice.id),
        Vec::new(),
        ms(T),
        Some(ms(T)),
    );
    assert_eq!(replay.service.handle(apps).await.status, 200, "serving");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_while_the_mark_store_cant_be_read_is_503() {
    // An enrollment that creates an account writes its mark first, so while the mark store
    // can't be read it is `503 unavailable`, without a head, and creates neither a mark nor
    // an account (Switch wire 7.3, Table 2; 7.4.1).
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    set_time(&replay.clock, T);
    let request = signer_request(
        "POST",
        "/v1/enroll",
        enrollment_body(&replay, 1, ORIGIN).await,
        ms(T),
    );
    let store_id = replay.key_dir().join("accounts").join("store-id");
    let id = std::fs::read(&store_id).expect("store-id");
    std::fs::remove_file(&store_id).expect("remove");
    let sent = Sent::of(&request);
    let refused = replay.service.handle(request).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (503, "unavailable")
    );
    assert!(header_of(&refused, header::HEAD).is_none());
    assert!(signed_with(&refused, &service_public(&replay), &sent));
    assert_eq!(accounts_of(&replay, &alice.id).await, 0, "no account");
    // The store read again: no mark was made, and the enrollment now creates both.
    std::fs::write(&store_id, id).expect("restore");
    assert_eq!(
        replay.marks.read(&alice.id).await.expect("read"),
        MarkRead::Missing,
        "no mark"
    );
    assert_eq!(enroll(&replay, 1).await.status, 200);
    assert_fresh_creation_mark(
        mark_of(&replay, &alice.id).await,
        service_public(&replay),
        ms(T),
        true,
    );
    replay.db.drop_database().await.expect("drop");
}

/// alice served, then her mark deleted through the store: her account fails stop,
/// `mark_lost` (Switch wire 7.3, Table 1).
async fn serving_without_a_mark(replay: &Replay) {
    serving(replay).await;
    replay
        .marks
        .delete(&alice_keys().id)
        .await
        .expect("lose the mark");
}

/// The start of `generation` with `recovery_from` its generation less one, at `version`.
fn start_at(version: u64, generation: u64) -> SignedDoc {
    alice_version(|body| {
        body.version = version;
        body.generation = generation;
        body.recovery_from = Some(generation - 1);
    })
}

#[tokio::test]
async fn test_identity_start_afresh_needs_a_higher_version_than_the_one_held() {
    // The start a failing account takes is exempt from the compare-and-swap of `prev` only:
    // it still needs a higher version than the one held, else `409 stale_identity` with
    // that copy, and nothing changes (Switch wire 3.3).
    let Some(replay) = replay().await else { return };
    serving_without_a_mark(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    let held = version("alice identity.json, first delivery (version 1)");
    // Another body at the version held: generation 2, `recovery_from` 1.
    let again = start_at(1, 2);
    let put = signer_request("PUT", &path, delivery(again, None), ms(T));
    let refused = replay.service.handle(put).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (409, "stale_identity"),
        "{}",
        String::from_utf8_lossy(&refused.body)
    );
    assert_eq!(json(&refused)["current"]["version"], 1);
    assert_eq!(
        json(&refused)["current"]["identity"],
        serde_json::to_value(&held).expect("held")
    );
    assert!(header_of(&refused, header::HEAD).is_none(), "no head");
    assert!(
        matches!(
            replay.marks.read(&alice.id).await.expect("read"),
            MarkRead::Missing
        ),
        "nothing started"
    );
    // A higher version starts the account afresh.
    let put = signer_request("PUT", &path, delivery(start_at(2, 2), None), ms(T));
    let started = replay.service.handle(put).await;
    assert_eq!(
        started.status,
        200,
        "{}",
        String::from_utf8_lossy(&started.body)
    );
    assert_eq!(mark_of(&replay, &alice.id).await.generation, 2);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_identity_start_at_a_mark_lost_account_whose_mark_write_fails_is_not_rearmed() {
    // A generation start where the mark is lost commits, then writes the mark anew; where
    // that write fails the answer is `503 unavailable`. Its retry meets the account as it
    // now stands, at the started generation with its mark still lost: the notice
    // `mark_lost`, never the restored state armed again by a retry. The signer then signs
    // above it (Switch wire 7.3, Table 3 and below it; 7.4.2).
    use std::os::unix::fs::PermissionsExt;
    let Some(replay) = replay().await else { return };
    serving_without_a_mark(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    let marks_dir = replay.key_dir().join("accounts").join("marks");
    std::fs::set_permissions(&marks_dir, std::fs::Permissions::from_mode(0o500))
        .expect("read-only");
    let start = delivery(start_at(2, 2), None);
    let put = signer_request("PUT", &path, start.clone(), ms(T));
    let failed = replay.service.handle(put).await;
    std::fs::set_permissions(&marks_dir, std::fs::Permissions::from_mode(0o700)).expect("writable");
    assert_eq!(
        (failed.status, code(&failed).as_str()),
        (503, "unavailable"),
        "{}",
        String::from_utf8_lossy(&failed.body)
    );
    assert!(header_of(&failed, header::HEAD).is_none(), "no head");
    assert!(matches!(
        replay.marks.read(&alice.id).await.expect("read"),
        MarkRead::Missing
    ));
    let retry = signer_request("PUT", &path, start, ms(T));
    assert_notice(&replay.service.handle(retry).await, 2, "mark_lost");
    let above = signer_request("PUT", &path, delivery(start_at(3, 3), None), ms(T));
    let started = replay.service.handle(above).await;
    assert_eq!(
        started.status,
        200,
        "{}",
        String::from_utf8_lossy(&started.body)
    );
    let mark = mark_of(&replay, &alice.id).await;
    assert_eq!(
        mark.generation, 3,
        "written anew at the generation signed above"
    );
    replay.db.drop_database().await.expect("drop");
}

/// Wait until an account's insert is in progress, slowed by the `slow_insert` trigger.
async fn insert_in_progress(replay: &Replay) {
    let mut watcher = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for _ in 0..500 {
        let inserting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() \
             AND state = 'active' AND query LIKE 'INSERT INTO accounts%'",
        )
        .fetch_one(&mut watcher)
        .await
        .expect("activity");
        if inserting == 1 {
            watcher.close().await.expect("close");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the insert never ran");
}

#[tokio::test]
async fn test_enroll_concurrent_creations_answer_one_creation_time() {
    // Two enrollments of one identity, the second while the first's account insert is not
    // committed yet: the identity's lock holds the second until the first commits, so it
    // never takes the first's fresh (0, 0) mark for a crash's leftover. Both answer the
    // creation time the account and the mark hold, and an erasure naming it goes through
    // (Switch wire 3.7, 7.3 Table 3, 7.4.16).
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    set_time(&replay.clock, T);
    run_sql(
        &replay,
        "CREATE FUNCTION slow_insert() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN PERFORM pg_sleep(0.5); RETURN NEW; END $$; \
         CREATE TRIGGER slow_insert BEFORE INSERT ON accounts \
         FOR EACH ROW EXECUTE FUNCTION slow_insert()",
    )
    .await;
    let (first, second) = tokio::join!(enroll(&replay, 1), async {
        insert_in_progress(&replay).await;
        // Later by the clock too, so a take of the first's mark would move its time.
        set_time(&replay.clock, "2026-01-01T00:00:00.007Z");
        enroll(&replay, 2).await
    });
    run_sql(&replay, "DROP TRIGGER slow_insert ON accounts").await;
    for answer in [&first, &second] {
        assert_eq!(
            answer.status,
            200,
            "{}",
            String::from_utf8_lossy(&answer.body)
        );
    }
    let created = created_at_of(&replay, &alice.id).await;
    let created_text = json!(pubky_switch_core::time::rfc3339(created));
    assert_eq!(json(&first)["created"], created_text);
    assert_eq!(json(&second)["created"], created_text);
    assert_eq!(mark_of(&replay, &alice.id).await.created_at_ms, created);
    assert_eq!(accounts_of(&replay, &alice.id).await, 1);
    let erase = signer_request_at_creation(
        "POST",
        &format!("/v1/{}/erase", alice.id),
        pubky_switch_core::http::erase_body(Some(created), None),
        ms(T) + 10,
        Some(created),
    );
    let erased = replay.service.handle(erase).await;
    assert_eq!(
        erased.status,
        200,
        "{}",
        String::from_utf8_lossy(&erased.body)
    );
    assert_eq!(accounts_of(&replay, &alice.id).await, 0);
    replay.db.drop_database().await.expect("drop");
}

/// A service on `replay` whose instance lock was last confirmed three checks ago.
fn with_stale_lock(replay: &Replay) -> pubky_switch::service::Service {
    use pubky_switch::store::{LockFreshness, LockTiming};
    let timing = LockTiming::checking_every(std::time::Duration::from_secs(5));
    replay
        .restarted_with(Limits::default())
        .with_lock_freshness(LockFreshness::confirmed_ago(
            std::time::Duration::from_secs(15),
            timing,
        ))
}

#[tokio::test]
async fn test_enroll_under_a_stale_instance_lock_writes_nothing() {
    // An enrollment creates or re-keys a mark: a service whose instance lock is stale
    // answers `503 unavailable` and writes no mark and no account, at a new identity and at
    // a staged account alike (Switch spec 6.5, wire 7.3 Table 3).
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    set_time(&replay.clock, T);
    let stale = with_stale_lock(&replay);
    let request = signer_request(
        "POST",
        "/v1/enroll",
        enrollment_body(&replay, 1, ORIGIN).await,
        ms(T),
    );
    let refused = stale.handle(request).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (503, "unavailable")
    );
    assert_eq!(accounts_of(&replay, &alice.id).await, 0, "no account");
    assert_eq!(
        replay.marks.read(&alice.id).await.expect("read"),
        MarkRead::Missing,
        "no mark"
    );
    assert_eq!(enroll(&replay, 1).await.status, 200);
    let mark = mark_of(&replay, &alice.id).await;
    let request = signer_request(
        "POST",
        "/v1/enroll",
        enrollment_body(&replay, 2, ORIGIN).await,
        ms(T),
    );
    let refused = stale.handle(request).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (503, "unavailable")
    );
    assert_eq!(
        mark_of(&replay, &alice.id).await,
        mark,
        "the mark unchanged"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_lost_identity_under_a_stale_instance_lock_writes_nothing() {
    // The erasure at a lost identity writes a record and deletes the mark: under a stale
    // instance lock it is `503 unavailable` and does neither; under a fresh one it erases
    // (Switch spec 6.5, wire 7.3 Table 3, 7.4.16).
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    let key = service_public(&replay);
    let lost_at = ms(T) - 86_400_000;
    replay
        .marks
        .create_zero(&alice.id, key, lost_at)
        .await
        .expect("a mark");
    let head = ChainTip {
        generation: 1,
        seq: 5,
        chain_hash: [9; 32],
    };
    replay
        .marks
        .advance(
            &alice.id,
            keeping_count(&replay.marks, &alice.id, head).await,
            key,
            mark_created_at(&replay, &alice.id).await,
        )
        .await
        .expect("a head");
    let mark = mark_of(&replay, &alice.id).await;
    set_time(&replay.clock, T);
    let erase = || {
        signer_request_at_creation(
            "POST",
            &format!("/v1/{}/erase", alice.id),
            pubky_switch_core::http::erase_body(Some(lost_at), None),
            ms(T),
            Some(lost_at),
        )
    };
    let refused = with_stale_lock(&replay).handle(erase()).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (503, "unavailable"),
        "{}",
        String::from_utf8_lossy(&refused.body)
    );
    assert_eq!(mark_of(&replay, &alice.id).await, mark, "the mark stays");
    assert_eq!(
        replay.marks.erasure(&alice.id).await.expect("records"),
        None
    );
    let erased = replay.service.handle(erase()).await;
    assert_eq!(
        erased.status,
        200,
        "{}",
        String::from_utf8_lossy(&erased.body)
    );
    assert_eq!(
        replay.marks.read(&alice.id).await.expect("read"),
        MarkRead::Missing
    );
    assert_eq!(
        replay.marks.erasure(&alice.id).await.expect("records"),
        Some(ms(T))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_null_members_read_as_missing() {
    // Null cannot agree with the required creation header. The malformed erasure is
    // refused before any destructive action (Switch account binding 1).
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let erase = signer_request(
        "POST",
        &format!("/v1/{}/erase", alice.id),
        br#"{"created":null,"identity_hash":null}"#.to_vec(),
        ms(T),
    );
    let refused = replay.service.handle(erase).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (400, "bad_request"),
        "{}",
        String::from_utf8_lossy(&refused.body)
    );
    assert!(header_text(&refused, pubky_switch_core::http::header::HEAD).is_none());
    assert_eq!(accounts_of(&replay, &alice.id).await, 1, "nothing erased");
    replay.db.drop_database().await.expect("drop");
}
