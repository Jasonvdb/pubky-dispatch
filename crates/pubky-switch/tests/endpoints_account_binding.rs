//! Public account discovery, enrollment intents and creation-bound signer calls.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::{
    http::{Handler, SwitchRequest, SwitchResponse},
    marks::{MarkRead, MarkStore},
    time::{Clock, TimeSample},
};
use pubky_switch_core::{
    enc::{b64, unb64_array},
    http::{self, RequestHeaders, RequestTarget, header},
    keys::IdentityKey,
    records::{
        AccountAssociation, AccountObservationBody, CarriedAccountObservation, Enrollment,
        EnrollmentBody, EnrollmentIntent, IdentityPolicy,
    },
    sig::SignedDoc,
    time::{parse_rfc3339, rfc3339, rfc3339_seconds},
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::{ORIGIN, Replay};

const NOW: u64 = 1_767_225_600_000;

fn key() -> IdentityKey {
    IdentityKey::from_secret(support::hex32(
        &support::alice(&support::vectors("keys.json"))["secret_hex"],
    ))
}

fn path(suffix: &str) -> String {
    format!("/v1/{}/{suffix}", key().id())
}

fn signed(method: &str, path: &str, body: Vec<u8>, created: Option<u64>, at: u64) -> SwitchRequest {
    let headers = RequestHeaders {
        timestamp: rfc3339_seconds(at),
        identity: key().id(),
        created: created.map(rfc3339),
        ..RequestHeaders::default()
    };
    let signature = b64(&http::sign_request(
        &key(),
        &RequestTarget {
            method,
            path_and_query: path,
            body: &body,
            origin: ORIGIN,
        },
        &headers,
    ));
    let mut fields = vec![
        (header::IDENTITY, headers.identity.as_str()),
        (header::TIMESTAMP, headers.timestamp.as_str()),
        (header::SIGNATURE, signature.as_str()),
    ];
    if let Some(created) = headers.created.as_deref() {
        fields.push((header::CREATED, created));
    }
    support::request(method, path, &fields, body)
}

fn value(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body).unwrap()
}

fn status(answer: &SwitchResponse, expected: u16) {
    assert_eq!(
        answer.status,
        expected,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

async fn discover(replay: &Replay, at: u64) -> CarriedAccountObservation {
    replay.clock.set_wall_ms(at);
    let request = signed("GET", &path("account"), vec![], None, at);
    let headers = request.signed_headers();
    let request_timestamp = headers.text(header::TIMESTAMP).unwrap().to_string();
    let request_signature = unb64_array(headers.text(header::SIGNATURE).unwrap()).unwrap();
    let answer = replay.service.handle(request).await;
    status(&answer, 200);
    assert!(support::header_text(&answer, header::HEAD).is_none());
    let carried = CarriedAccountObservation {
        body: answer.body.to_vec(),
        sig: unb64_array(support::header_text(&answer, header::SERVICE_SIGNATURE).unwrap())
            .unwrap(),
        request_timestamp,
        request_signature,
    };
    let observation = carried.verify(&key().public(), ORIGIN).unwrap();
    assert_eq!(
        support::header_text(&answer, header::SERVER_TIME),
        Some(rfc3339(observation.body().observed_at).as_str())
    );
    carried
}

fn make_enrollment(intent: EnrollmentIntent, nonce: u8) -> Enrollment {
    Enrollment::sign(
        &key(),
        EnrollmentBody {
            identity: key().public(),
            origin: ORIGIN.into(),
            nonce: [nonce; 16],
            intent,
            policy: IdentityPolicy::default(),
            identity_doc: None,
            revoked_apps: None,
        },
    )
    .unwrap()
}

fn enrollment_request(enrollment: &Enrollment, at: u64) -> SwitchRequest {
    signed(
        "POST",
        "/v1/enroll",
        serde_json::to_vec(&json!({"enrollment": enrollment.signed()})).unwrap(),
        enrollment.body().intent.created(),
        at,
    )
}

async fn create(replay: &Replay, at: u64, nonce: u8) -> (Enrollment, u64) {
    let observation = discover(replay, at).await;
    assert_eq!(
        AccountObservationBody::from_json(&observation.body)
            .unwrap()
            .created,
        None
    );
    let enrollment = make_enrollment(EnrollmentIntent::Create { observation }, nonce);
    let answer = replay
        .service
        .handle(enrollment_request(&enrollment, at))
        .await;
    status(&answer, 200);
    let created = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    (enrollment, created)
}

async fn trusted_replay() -> Option<Replay> {
    let replay = support::replay_with_time(pubky_switch::limits::Limits::default(), true).await?;
    replay.clock.set_wall_ms(NOW);
    replay.time.note(
        TimeSample {
            utc_ms: NOW,
            uncertainty_ms: 0,
        },
        replay.clock.monotonic_ms(),
    );
    assert!(replay.time.read().trusted);
    Some(replay)
}

#[tokio::test]
async fn test_account_binding_expiry_uses_authenticated_elapsed_time() {
    let Some(replay) = trusted_replay().await else {
        return;
    };
    let observation = discover(&replay, NOW).await;
    let enrollment = make_enrollment(EnrollmentIntent::Create { observation }, 61);
    replay.clock.advance_ms(300_000);
    replay.clock.set_wall_ms(NOW + 299_999);
    let reading = replay.time.read();
    assert!(reading.trusted);
    assert_eq!(reading.base_ms, NOW + 299_999);
    let answer = replay
        .service
        .handle(enrollment_request(&enrollment, NOW + 299_999))
        .await;
    status(&answer, 409);
    assert_eq!(value(&answer)["current"]["binding"], "expired");
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        replay.marks.read(&key().id()).await.unwrap(),
        MarkRead::Missing
    );
}

#[tokio::test]
async fn test_account_binding_valid_observation_ignores_small_wall_advance() {
    let Some(replay) = trusted_replay().await else {
        return;
    };
    let observation = discover(&replay, NOW).await;
    let enrollment = make_enrollment(EnrollmentIntent::Create { observation }, 62);
    replay.clock.advance_ms(299_999);
    replay.clock.set_wall_ms(NOW + 300_000);
    assert_eq!(replay.time.read().base_ms, NOW + 300_000);
    let answer = replay
        .service
        .handle(enrollment_request(&enrollment, NOW + 300_000))
        .await;
    status(&answer, 200);
    assert_eq!(value(&answer)["created"], rfc3339(NOW + 299_999));
    assert_eq!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .unwrap()
            .created_at_ms,
        NOW + 299_999
    );
}

#[tokio::test]
async fn test_account_binding_observation_uses_authenticated_sample_time() {
    let Some(replay) = trusted_replay().await else {
        return;
    };
    replay.clock.set_wall_ms(NOW + 299_999);
    assert_eq!(replay.time.read().base_ms, NOW + 299_999);
    let observation = discover(&replay, NOW + 299_999).await;
    let body = AccountObservationBody::from_json(&observation.body).unwrap();
    assert_eq!(body.observed_at, NOW);
    assert_eq!(body.expires_at, NOW + 300_000);
    assert_eq!(body.created, None);
    let enrollment = make_enrollment(EnrollmentIntent::Create { observation }, 63);
    let answer = replay
        .service
        .handle(enrollment_request(&enrollment, NOW + 299_999))
        .await;
    status(&answer, 200);
    assert_eq!(value(&answer)["created"], rfc3339(NOW));
}

async fn erase(replay: &Replay, created: u64, identity_hash: Option<&[u8; 32]>, at: u64) {
    replay.clock.set_wall_ms(at);
    let answer = replay
        .service
        .handle(signed(
            "POST",
            &path("erase"),
            http::erase_body(Some(created), identity_hash),
            Some(created),
            at,
        ))
        .await;
    status(&answer, 200);
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_account_binding_discovery_and_expired_receipt_are_read_only() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (enrollment, created) = create(&replay, NOW, 1).await;
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    let mark = replay.marks.read(&key().id()).await.unwrap();
    let observed = discover(&replay, NOW + 1).await;
    assert_eq!(
        AccountObservationBody::from_json(&observed.body)
            .unwrap()
            .created,
        Some(created)
    );
    replay.clock.set_wall_ms(NOW + 300_000);
    let answer = replay
        .service
        .handle(enrollment_request(&enrollment, NOW + 300_000))
        .await;
    status(&answer, 200);
    assert_eq!(value(&answer)["created"], rfc3339(created));
    let after = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.stamped_time_ms, before.stamped_time_ms);
    assert_eq!(after.chain, before.chain);
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), mark);
}

#[tokio::test]
async fn test_account_binding_saved_delivery_cannot_activate_recreated_account() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (_, first) = create(&replay, NOW, 2).await;
    let doc: SignedDoc = serde_json::from_value(
        support::named(
            &support::vectors("documents.json")["documents"],
            "alice identity.json, first delivery (version 1)",
        )["signed"]
            .clone(),
    )
    .unwrap();
    let body = http::IdentityDelivery {
        identity: doc.clone(),
        prev: None,
    }
    .to_json();
    let saved = signed("PUT", &path("identity"), body.clone(), Some(first), NOW);
    let saved_headers = saved.signed_headers();
    status(&replay.service.handle(saved).await, 200);
    erase(&replay, first, Some(&doc.doc_hash().unwrap()), NOW + 1000).await;
    let (_, second) = create(&replay, NOW + 2000, 3).await;
    assert!(second > first);
    let before = replay.marks.read(&key().id()).await.unwrap();
    let replayed = signed("PUT", &path("identity"), body.clone(), Some(first), NOW);
    assert_eq!(replayed.signed_headers(), saved_headers);
    assert_eq!(replayed.body.as_ref(), body.as_slice());
    let answer = replay.service.handle(replayed).await;
    status(&answer, 409);
    assert_eq!(value(&answer)["current"]["created"], rfc3339(second));
    assert!(support::header_text(&answer, header::HEAD).is_none());
    let held = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert!(held.identity_doc.is_none());
    assert!(held.chain.is_none());
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), before);
    status(
        &replay
            .service
            .handle(signed(
                "PUT",
                &path("identity"),
                body,
                Some(second),
                NOW + 2000,
            ))
            .await,
        200,
    );
}

#[tokio::test]
async fn test_account_binding_saved_existing_enrollment_cannot_recreate() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (_, created) = create(&replay, NOW, 4).await;
    let existing = make_enrollment(EnrollmentIntent::Existing { created }, 5);
    let saved = enrollment_request(&existing, NOW);
    let headers = saved.signed_headers();
    let body = saved.body.clone();
    status(&replay.service.handle(saved).await, 200);
    erase(&replay, created, None, NOW + 1000).await;
    let request = enrollment_request(&existing, NOW);
    assert_eq!(request.signed_headers(), headers);
    assert_eq!(request.body, body);
    let answer = replay.service.handle(request).await;
    status(&answer, 404);
    assert_eq!(value(&answer)["current"]["hosted"], false);
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        replay.marks.read(&key().id()).await.unwrap(),
        MarkRead::Missing
    );
    let (_, later) = create(&replay, NOW + 2000, 6).await;
    assert!(later > created);
}

#[tokio::test]
async fn test_account_binding_fresh_creation_expiry_is_exact() {
    for (age, expected) in [(299_999, 200), (300_000, 409), (300_001, 409)] {
        let Some(replay) = support::replay().await else {
            return;
        };
        let observation = discover(&replay, NOW).await;
        let enrollment = make_enrollment(EnrollmentIntent::Create { observation }, 7);
        replay.clock.set_wall_ms(NOW + age);
        let answer = replay
            .service
            .handle(enrollment_request(&enrollment, NOW + age))
            .await;
        status(&answer, expected);
        if expected == 409 {
            assert_eq!(value(&answer)["current"]["binding"], "expired");
            assert!(
                replay
                    .db
                    .store()
                    .lookup(&key().id())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                replay.marks.read(&key().id()).await.unwrap(),
                MarkRead::Missing
            );
        }
    }
}

#[tokio::test]
async fn test_account_binding_future_or_unusable_time_never_creates() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let observation = discover(&replay, NOW).await;
    let enrollment = make_enrollment(EnrollmentIntent::Create { observation }, 8);
    replay.clock.set_wall_ms(NOW - 1);
    status(
        &replay
            .service
            .handle(enrollment_request(&enrollment, NOW))
            .await,
        503,
    );
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
    let service = replay.without_trusted_time();
    status(
        &service
            .handle(signed("GET", &path("account"), vec![], None, NOW))
            .await,
        503,
    );
    status(
        &service.handle(enrollment_request(&enrollment, NOW)).await,
        503,
    );
    assert_eq!(
        replay.marks.read(&key().id()).await.unwrap(),
        MarkRead::Missing
    );
    replay.clock.set_wall_ms(NOW);
    status(
        &replay
            .service
            .handle(enrollment_request(&enrollment, NOW))
            .await,
        200,
    );
}

#[tokio::test]
async fn test_account_binding_replaced_store_rejects_old_authority() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let observation = discover(&replay, NOW).await;
    let old = AccountObservationBody::from_json(&observation.body).unwrap();
    let enrollment = make_enrollment(EnrollmentIntent::Create { observation }, 9);
    let intent_bytes = enrollment.signed().clone();
    std::fs::rename(
        replay.key_dir().join("accounts"),
        replay.key_dir().join("accounts.saved"),
    )
    .unwrap();
    let replacement = MarkStore::open(replay.key_dir()).unwrap();
    assert_ne!(replacement.identity().await.unwrap(), old.store_id);
    status(
        &replay
            .service
            .handle(signed("GET", &path("account"), vec![], None, NOW))
            .await,
        503,
    );
    let current = discover(&replay, NOW).await;
    assert_ne!(
        AccountObservationBody::from_json(&current.body)
            .unwrap()
            .store_id,
        old.store_id
    );
    let refused = replay
        .service
        .handle(enrollment_request(&enrollment, NOW))
        .await;
    status(&refused, 409);
    assert_eq!(value(&refused)["current"]["binding"], "changed");
    assert_eq!(enrollment.signed(), &intent_bytes);
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
    let distinct = make_enrollment(
        EnrollmentIntent::Create {
            observation: current,
        },
        10,
    );
    status(
        &replay
            .service
            .handle(enrollment_request(&distinct, NOW))
            .await,
        200,
    );
}

async fn sql(replay: &Replay, statement: &str) {
    let mut connection = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .unwrap();
    sqlx::raw_sql(statement)
        .execute(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();
}

#[tokio::test]
async fn test_account_binding_corrupt_mark_observation_requires_a_readable_account() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (_, created) = create(&replay, NOW, 51).await;
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    let mark = replay
        .key_dir()
        .join("accounts")
        .join("marks")
        .join(key().id());
    std::fs::write(&mark, b"not a mark").unwrap();
    assert_eq!(
        replay.marks.read(&key().id()).await.unwrap(),
        MarkRead::NotAMark
    );
    let carried = discover(&replay, NOW).await;
    assert_eq!(
        AccountObservationBody::from_json(&carried.body)
            .unwrap()
            .created,
        Some(created)
    );
    let after = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (after.stamped_time_ms, after.chain),
        (before.stamped_time_ms, before.chain)
    );
    assert_eq!(std::fs::read(&mark).unwrap(), b"not a mark");

    // Losing the account leaves no readable creation or proof of absence.
    sql(&replay, "DELETE FROM accounts").await;
    let answer = replay
        .service
        .handle(signed("GET", &path("account"), vec![], None, NOW))
        .await;
    status(&answer, 503);
    assert_eq!(value(&answer)["code"], "unavailable");
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(std::fs::read(&mark).unwrap(), b"not a mark");
}

#[tokio::test]
async fn test_account_binding_zero_mark_requires_distinct_takeover() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let observation = discover(&replay, NOW).await;
    let original = make_enrollment(EnrollmentIntent::Create { observation }, 11);
    sql(&replay, "CREATE FUNCTION refuse_creation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$; CREATE CONSTRAINT TRIGGER refuse_creation AFTER INSERT ON accounts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_creation()").await;
    status(
        &replay
            .service
            .handle(enrollment_request(&original, NOW))
            .await,
        503,
    );
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
    let MarkRead::Mark(before) = replay.marks.read(&key().id()).await.unwrap() else {
        panic!("the mark preceded insertion")
    };
    assert_eq!((before.generation, before.seq), (0, 0));
    sql(&replay, "DROP TRIGGER refuse_creation ON accounts").await;
    let repeated = replay
        .service
        .handle(enrollment_request(&original, NOW))
        .await;
    status(&repeated, 409);
    assert_eq!(value(&repeated)["current"]["binding"], "changed");
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
    let observation = discover(&replay, NOW).await;
    assert_eq!(
        AccountObservationBody::from_json(&observation.body)
            .unwrap()
            .created,
        Some(before.created_at_ms)
    );
    let takeover = make_enrollment(
        EnrollmentIntent::Takeover {
            created: before.created_at_ms,
            observation,
        },
        12,
    );
    replay.clock.set_wall_ms(NOW + 1);
    let answer = replay
        .service
        .handle(enrollment_request(&takeover, NOW + 1))
        .await;
    status(&answer, 200);
    let created = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    assert!(created > before.created_at_ms);
    let MarkRead::Mark(after) = replay.marks.read(&key().id()).await.unwrap() else {
        panic!("taken mark")
    };
    assert_eq!(
        (after.generation, after.seq, after.chain_hash),
        (before.generation, before.seq, before.chain_hash)
    );
    replay.clock.set_wall_ms(NOW + 300_000);
    let retried = replay
        .service
        .handle(enrollment_request(&takeover, NOW + 300_000))
        .await;
    status(&retried, 200);
    assert_eq!(value(&retried)["created"], rfc3339(created));
    assert_eq!(
        replay.marks.read(&key().id()).await.unwrap(),
        MarkRead::Mark(after)
    );
}

#[tokio::test]
async fn test_account_binding_surviving_account_keeps_lost_mark_and_rejects_old_receipt() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (original, created) = create(&replay, NOW, 13).await;
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    std::fs::rename(
        replay.key_dir().join("accounts"),
        replay.key_dir().join("accounts.saved"),
    )
    .unwrap();
    let replacement = MarkStore::open(replay.key_dir()).unwrap();
    status(
        &replay
            .service
            .handle(signed("GET", &path("account"), vec![], None, NOW))
            .await,
        503,
    );
    let carried = discover(&replay, NOW).await;
    let observed = AccountObservationBody::from_json(&carried.body).unwrap();
    assert_eq!(observed.created, Some(created));
    assert_eq!(observed.store_id, replacement.identity().await.unwrap());
    let refused = replay
        .service
        .handle(enrollment_request(&original, NOW))
        .await;
    status(&refused, 409);
    assert_eq!(value(&refused)["current"]["binding"], "changed");
    let notice = replay
        .service
        .handle(signed("GET", &path("apps"), vec![], Some(created), NOW))
        .await;
    status(&notice, 503);
    assert_eq!(value(&notice)["current"]["reason"], "mark_lost");
    let wrong = replay
        .service
        .handle(signed("GET", &path("apps"), vec![], Some(created - 1), NOW))
        .await;
    status(&wrong, 409);
    assert_eq!(value(&wrong)["current"]["created"], rfc3339(created));
    let restarted = replay.restarted_with(pubky_switch::limits::Limits::default());
    let answer = restarted
        .handle(signed("GET", &path("account"), vec![], None, NOW))
        .await;
    status(&answer, 200);
    assert_eq!(
        AccountObservationBody::from_json(&answer.body)
            .unwrap()
            .created,
        Some(created)
    );
    let after = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (after.stamped_time_ms, after.chain),
        (before.stamped_time_ms, before.chain)
    );
    assert_eq!(
        replay.marks.read(&key().id()).await.unwrap(),
        MarkRead::Missing
    );
}

#[tokio::test]
async fn test_account_binding_discovery_does_not_resolve_erasure() {
    use pubky_switch::service::ErasureOutcome;
    for outcome in [
        ErasureOutcome::Unresolved,
        ErasureOutcome::UnresolvedAbsent,
        ErasureOutcome::Committed,
        ErasureOutcome::Rejected,
    ] {
        let Some(replay) = support::replay().await else {
            return;
        };
        let (_, created) = create(&replay, NOW, 14).await;
        replay.service.erasure_faults().next(outcome);
        let erasure = signed(
            "POST",
            &path("erase"),
            http::erase_body(Some(created), None),
            Some(created),
            NOW,
        );
        status(&replay.service.handle(erasure).await, 503);
        let attempt = pending_bytes(&replay).unwrap();
        let mark = replay.marks.read(&key().id()).await.unwrap();
        let present = replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_some();
        let response = replay
            .service
            .handle(signed("GET", &path("account"), vec![], None, NOW))
            .await;
        status(&response, 503);
        assert!(support::header_text(&response, header::HEAD).is_none());
        assert_eq!(pending_bytes(&replay), Some(attempt));
        assert_eq!(replay.marks.read(&key().id()).await.unwrap(), mark);
        assert_eq!(
            replay
                .db
                .store()
                .lookup(&key().id())
                .await
                .unwrap()
                .is_some(),
            present
        );
        assert_eq!(replay.marks.erasure(&key().id()).await.unwrap(), None);
    }
}

#[tokio::test]
async fn test_account_binding_header_and_erasure_body_refuse_before_state_changes() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (_, created) = create(&replay, NOW, 15).await;
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    replay.clock.set_wall_ms(NOW + 1000);
    let missing = replay
        .service
        .handle(signed("GET", &path("apps"), vec![], None, NOW + 1000))
        .await;
    status(&missing, 400);
    let disagreement = replay
        .service
        .handle(signed(
            "POST",
            &path("erase"),
            http::erase_body(Some(created - 1), None),
            Some(created),
            NOW + 1000,
        ))
        .await;
    status(&disagreement, 400);
    let discovery = replay
        .service
        .handle(signed(
            "GET",
            &path("account"),
            vec![],
            Some(created),
            NOW + 1000,
        ))
        .await;
    status(&discovery, 400);
    assert!(pending_bytes(&replay).is_none());
    let after = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.stamped_time_ms, before.stamped_time_ms);
    erase(&replay, created, None, NOW + 1000).await;
}

fn pending_bytes(replay: &Replay) -> Option<Vec<u8>> {
    match std::fs::read(
        replay
            .key_dir()
            .join("accounts/erasure-attempts")
            .join(key().id()),
    ) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot read pending erasure: {error}"),
    }
}

async fn mark_only_conflict(activate: bool) {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (_, created) = create(&replay, NOW, 81).await;
    if activate {
        let doc: SignedDoc = serde_json::from_value(
            support::named(
                &support::vectors("documents.json")["documents"],
                "alice identity.json, first delivery (version 1)",
            )["signed"]
                .clone(),
        )
        .unwrap();
        let body = http::IdentityDelivery {
            identity: doc,
            prev: None,
        }
        .to_json();
        status(
            &replay
                .service
                .handle(signed("PUT", &path("identity"), body, Some(created), NOW))
                .await,
            200,
        );
    }
    sql(&replay, "DELETE FROM accounts").await;
    let mark = replay.marks.read(&key().id()).await.unwrap();
    replay.clock.set_wall_ms(NOW + 1000);
    let answer = replay
        .service
        .handle(signed(
            "GET",
            &path("apps"),
            vec![],
            Some(created - 1),
            NOW + 1000,
        ))
        .await;
    status(&answer, 409);
    assert_eq!(
        value(&answer)["current"],
        json!({"created": rfc3339(created)})
    );
    assert_eq!(
        support::header_text(&answer, header::SERVER_TIME),
        Some(rfc3339(NOW + 1000).as_str())
    );
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), mark);
    let matching = replay
        .service
        .handle(signed(
            "GET",
            &path("apps"),
            vec![],
            Some(created),
            NOW + 1000,
        ))
        .await;
    status(&matching, if activate { 503 } else { 404 });
    assert_eq!(
        value(&matching)["code"],
        if activate {
            "recovery_required"
        } else {
            "not_found"
        }
    );
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), mark);
}

#[tokio::test]
async fn test_account_binding_zero_mark_creation_conflict_precedes_not_hosted() {
    mark_only_conflict(false).await;
}

#[tokio::test]
async fn test_account_binding_lost_mark_creation_conflict_precedes_notice() {
    mark_only_conflict(true).await;
}

#[tokio::test]
async fn test_account_binding_creation_conflict_uses_current_time_without_stamping() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (_, created) = create(&replay, NOW, 82).await;
    sql(
        &replay,
        "UPDATE accounts SET stamped_time_ms = stamped_time_ms + 10000",
    )
    .await;
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    let mark = replay.marks.read(&key().id()).await.unwrap();
    replay.clock.set_wall_ms(NOW + 1000);
    let answer = replay
        .service
        .handle(signed(
            "GET",
            &path("apps"),
            vec![],
            Some(created - 1),
            NOW + 1000,
        ))
        .await;
    status(&answer, 409);
    assert_eq!(
        support::header_text(&answer, header::SERVER_TIME),
        Some(rfc3339(NOW + 1000).as_str())
    );
    assert!(support::header_text(&answer, header::HEAD).is_none());
    let after = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.stamped_time_ms, before.stamped_time_ms);
    assert_eq!(after.chain, before.chain);
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), mark);
}

async fn observe_directional_account(sql_created: u64, expected: AccountAssociation) {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (_, mark_created) = create(&replay, NOW, 71).await;
    sql(
        &replay,
        &format!("UPDATE accounts SET created_at_ms = {sql_created}"),
    )
    .await;
    let before = replay.db.store().lookup(&key().id()).await.unwrap();
    let mark = replay.marks.read(&key().id()).await.unwrap();
    let observation = discover(&replay, NOW + 2000).await;
    let checked = observation.verify(&key().public(), ORIGIN).unwrap();
    assert_eq!(
        (checked.body().association, checked.body().created),
        (expected, Some(sql_created.max(mark_created)))
    );
    assert_eq!(replay.db.store().lookup(&key().id()).await.unwrap(), before);
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), mark);
    let selected = checked.enrollment_intent().unwrap();
    assert!(matches!(
        (expected, selected),
        (
            AccountAssociation::Account,
            EnrollmentIntent::Existing { .. }
        ) | (AccountAssociation::Mark, EnrollmentIntent::Takeover { .. })
    ));
}

#[tokio::test]
async fn test_account_discovery_older_sql_selects_mark_without_effects() {
    observe_directional_account(NOW - 1000, AccountAssociation::Mark).await;
}

#[tokio::test]
async fn test_account_discovery_newer_sql_selects_account_without_effects() {
    observe_directional_account(NOW + 1000, AccountAssociation::Account).await;
}

#[tokio::test]
async fn test_account_discovery_covered_older_sql_refuses_without_cleanup() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (_, first) = create(&replay, NOW, 72).await;
    erase(&replay, first, None, NOW + 1000).await;
    let (_, current) = create(&replay, NOW + 2000, 73).await;
    assert!(current > first);
    sql(
        &replay,
        &format!("UPDATE accounts SET created_at_ms = {first}"),
    )
    .await;
    let before = replay.db.store().lookup(&key().id()).await.unwrap();
    let mark = replay.marks.read(&key().id()).await.unwrap();
    let erased = replay.marks.erasure(&key().id()).await.unwrap();
    let answer = replay
        .service
        .handle(signed("GET", &path("account"), vec![], None, NOW + 2000))
        .await;
    status(&answer, 503);
    assert_eq!(value(&answer)["code"], "unavailable");
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert_eq!(replay.db.store().lookup(&key().id()).await.unwrap(), before);
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), mark);
    assert_eq!(replay.marks.erasure(&key().id()).await.unwrap(), erased);
}

#[tokio::test]
async fn test_account_discovery_covered_older_mark_refuses_without_cleanup() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (_, first) = create(&replay, NOW, 74).await;
    let mark_path = replay
        .key_dir()
        .join("accounts")
        .join("marks")
        .join(key().id());
    let old_mark = std::fs::read(&mark_path).unwrap();
    erase(&replay, first, None, NOW + 1000).await;
    let (_, current) = create(&replay, NOW + 2000, 75).await;
    assert!(current > first);
    std::fs::write(&mark_path, &old_mark).unwrap();
    let reopened = MarkStore::open(replay.key_dir()).unwrap();
    assert!(
        matches!(reopened.read(&key().id()).await.unwrap(), MarkRead::Mark(mark) if mark.created_at_ms == first)
    );
    let service = pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        reopened.clone(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    );
    let before = replay.db.store().lookup(&key().id()).await.unwrap();
    let erased = replay.marks.erasure(&key().id()).await.unwrap();
    let answer = service
        .handle(signed("GET", &path("account"), vec![], None, NOW + 2000))
        .await;
    status(&answer, 503);
    assert_eq!(value(&answer)["code"], "unavailable");
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert_eq!(replay.db.store().lookup(&key().id()).await.unwrap(), before);
    assert_eq!(std::fs::read(&mark_path).unwrap(), old_mark);
    assert_eq!(replay.marks.erasure(&key().id()).await.unwrap(), erased);
}

async fn staged_lifetimes() -> Option<(Replay, Enrollment, u64, u64, Vec<u8>)> {
    let replay = support::replay().await?;
    let (_, first) = create(&replay, NOW, 81).await;
    let mark_path = replay
        .key_dir()
        .join("accounts")
        .join("marks")
        .join(key().id());
    let first_mark = std::fs::read(mark_path).unwrap();
    sql(
        &replay,
        "CREATE TABLE prior_account AS TABLE accounts; DELETE FROM accounts",
    )
    .await;
    let observation = discover(&replay, NOW + 1000).await;
    assert_eq!(
        AccountObservationBody::from_json(&observation.body)
            .unwrap()
            .association,
        AccountAssociation::Mark
    );
    let takeover = make_enrollment(
        EnrollmentIntent::Takeover {
            created: first,
            observation,
        },
        82,
    );
    let answer = replay
        .service
        .handle(enrollment_request(&takeover, NOW + 1000))
        .await;
    status(&answer, 200);
    let current = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    assert!(current > first);
    Some((replay, takeover, first, current, first_mark))
}

fn service_with_restored_mark(replay: &Replay, bytes: &[u8]) -> pubky_switch::service::Service {
    let mark_path = replay
        .key_dir()
        .join("accounts")
        .join("marks")
        .join(key().id());
    std::fs::write(mark_path, bytes).unwrap();
    pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        MarkStore::open(replay.key_dir()).unwrap(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    )
}

#[tokio::test]
async fn test_account_association_existing_does_not_apply_to_superseded_sql() {
    let Some((replay, _, first, current, _)) = staged_lifetimes().await else {
        return;
    };
    sql(
        &replay,
        "DELETE FROM accounts; INSERT INTO accounts SELECT * FROM prior_account",
    )
    .await;
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.created_at_ms, first);
    let mark = replay.marks.read(&key().id()).await.unwrap();
    assert!(matches!(mark, MarkRead::Mark(mark) if mark.created_at_ms == current));
    let enrollment = make_enrollment(EnrollmentIntent::Existing { created: current }, 83);
    replay.clock.set_wall_ms(NOW + 2000);
    let answer = replay
        .service
        .handle(enrollment_request(&enrollment, NOW + 2000))
        .await;
    status(&answer, 404);
    assert_eq!(value(&answer)["current"]["hosted"], false);
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert_eq!(
        replay.db.store().lookup(&key().id()).await.unwrap(),
        Some(before)
    );
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), mark);
}

#[tokio::test]
async fn test_account_association_newer_sql_binds_ordinary_requests() {
    let Some((replay, _, first, current, first_mark)) = staged_lifetimes().await else {
        return;
    };
    let service = service_with_restored_mark(&replay, &first_mark);
    let reopened = MarkStore::open(replay.key_dir()).unwrap();
    assert!(
        matches!(reopened.read(&key().id()).await.unwrap(), MarkRead::Mark(mark) if mark.created_at_ms == first)
    );
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.created_at_ms, current);
    replay.clock.set_wall_ms(NOW + 2000);
    let answer = service
        .handle(signed(
            "GET",
            &path("apps"),
            vec![],
            Some(current),
            NOW + 2000,
        ))
        .await;
    status(&answer, 503);
    assert_eq!(value(&answer)["current"]["reason"], "mark_lost");
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert_eq!(
        replay.db.store().lookup(&key().id()).await.unwrap(),
        Some(before)
    );
    assert_eq!(
        std::fs::read(
            replay
                .key_dir()
                .join("accounts")
                .join("marks")
                .join(key().id())
        )
        .unwrap(),
        first_mark
    );
}

#[tokio::test]
async fn test_account_association_newer_sql_keeps_its_exact_receipt() {
    let Some((replay, takeover, first, current, first_mark)) = staged_lifetimes().await else {
        return;
    };
    let service = service_with_restored_mark(&replay, &first_mark);
    let reopened = MarkStore::open(replay.key_dir()).unwrap();
    assert!(
        matches!(reopened.read(&key().id()).await.unwrap(), MarkRead::Mark(mark) if mark.created_at_ms == first)
    );
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.created_at_ms, current);
    replay.clock.set_wall_ms(NOW + 600_000);
    let answer = service
        .handle(enrollment_request(&takeover, NOW + 600_000))
        .await;
    status(&answer, 200);
    assert_eq!(value(&answer)["created"], rfc3339(current));
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert_eq!(
        replay.db.store().lookup(&key().id()).await.unwrap(),
        Some(before)
    );
    assert_eq!(
        std::fs::read(
            replay
                .key_dir()
                .join("accounts")
                .join("marks")
                .join(key().id())
        )
        .unwrap(),
        first_mark
    );
}

async fn retained_lifetimes() -> Option<(Replay, pubky_switch_core::records::IdentityDoc, u64, u64)>
{
    retained_lifetimes_with_mark(false).await
}

async fn retained_lifetimes_with_mark(
    activate_mark: bool,
) -> Option<(Replay, pubky_switch_core::records::IdentityDoc, u64, u64)> {
    use pubky_switch_core::records::{IdentityBody, IdentityDoc, Inbox};
    let replay = support::replay().await?;
    let observation = discover(&replay, NOW).await;
    let service_key = observation
        .verify(&key().public(), ORIGIN)
        .unwrap()
        .body()
        .service_key;
    let mut body = IdentityBody::first(
        key().public(),
        [12; 16],
        Inbox::new(ORIGIN, service_key),
        IdentityPolicy::default(),
    );
    body.version = 8;
    body.generation = 8;
    body.recovery_from = Some(7);
    body.removed.push(pubky_switch_core::records::RemovedApp {
        app_id: [41; 16],
        distrust_from: NOW - 2000,
    });
    body.removed.push(pubky_switch_core::records::RemovedApp {
        app_id: [44; 16],
        distrust_from: NOW - 1000,
    });
    let doc = IdentityDoc::sign(&key(), body).unwrap();
    let mut initial = make_enrollment(EnrollmentIntent::Create { observation }, 91)
        .body()
        .clone();
    initial.identity_doc = Some(doc.signed().clone());
    initial.revoked_apps = Some(vec![[41; 16]]);
    let initial = Enrollment::sign(&key(), initial).unwrap();
    let answer = replay
        .service
        .handle(enrollment_request(&initial, NOW))
        .await;
    status(&answer, 200);
    let first = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    replay.clock.set_wall_ms(NOW + 2000);
    let mut existing = make_enrollment(EnrollmentIntent::Existing { created: first }, 92)
        .body()
        .clone();
    existing.revoked_apps = Some(vec![[42; 16]]);
    let existing = Enrollment::sign(&key(), existing).unwrap();
    status(
        &replay
            .service
            .handle(enrollment_request(&existing, NOW + 2000))
            .await,
        200,
    );
    let original = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.identity_doc.as_ref(), Some(doc.signed()));
    assert_eq!(
        (original.generation, original.stamped_time_ms),
        (8, NOW + 2000)
    );
    sql(&replay, "CREATE TABLE prior_account AS TABLE accounts; CREATE TABLE prior_kept AS TABLE kept_app_ids; CREATE TABLE prior_held AS TABLE held_revoked_apps; CREATE TABLE prior_receipts AS TABLE enrollment_answers; DELETE FROM accounts").await;
    let observation = discover(&replay, NOW + 3000).await;
    let takeover = make_enrollment(
        EnrollmentIntent::Takeover {
            created: first,
            observation,
        },
        93,
    );
    let answer = replay
        .service
        .handle(enrollment_request(&takeover, NOW + 3000))
        .await;
    status(&answer, 200);
    let current = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    assert!(current > first);
    if activate_mark {
        let first_doc = IdentityDoc::sign(
            &key(),
            IdentityBody::first(
                key().public(),
                [13; 16],
                Inbox::new(ORIGIN, service_key),
                IdentityPolicy::default(),
            ),
        )
        .unwrap();
        status(
            &replay
                .service
                .handle(delivered(&first_doc, current, NOW + 3000))
                .await,
            200,
        );
    }
    sql(&replay, "DELETE FROM accounts; INSERT INTO accounts SELECT * FROM prior_account; INSERT INTO kept_app_ids SELECT * FROM prior_kept; INSERT INTO held_revoked_apps SELECT * FROM prior_held; INSERT INTO enrollment_answers OVERRIDING SYSTEM VALUE SELECT * FROM prior_receipts").await;
    Some((replay, doc, first, current))
}

#[tokio::test]
async fn test_account_takeover_replaces_older_sql_with_recovery_requirement() {
    let Some((replay, doc, first, current)) = retained_lifetimes().await else {
        return;
    };
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.created_at_ms, first);
    let MarkRead::Mark(mark) = replay.marks.read(&key().id()).await.unwrap() else {
        panic!("readable mark");
    };
    assert_eq!(
        (mark.created_at_ms, mark.generation, mark.seq),
        (current, 0, 0)
    );
    let observation = discover(&replay, NOW + 4000).await;
    let enrollment = make_enrollment(
        EnrollmentIntent::Takeover {
            created: current,
            observation,
        },
        91,
    );
    let answer = replay
        .service
        .handle(enrollment_request(&enrollment, NOW + 4000))
        .await;
    status(&answer, 200);
    let created = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    assert!(created > current);
    assert!(support::header_text(&answer, header::HEAD).is_none());
    let held = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.created_at_ms, created);
    assert_eq!(held.generation, 8);
    assert_eq!(held.identity_doc.as_ref(), Some(doc.signed()));
    assert!(held.stamped_time_ms >= before.stamped_time_ms);
    assert!(held.chain.is_none());
    let mut connection = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .unwrap();
    let requirement: String = sqlx::query_scalar("SELECT activation_requirement FROM accounts")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(requirement, "recovery");
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM enrollment_answers")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(receipts, 1);
    let proof: Option<Vec<u8>> = sqlx::query_scalar("SELECT identity_proof FROM accounts")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert!(proof.is_none());
    let excluded: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT app_id FROM kept_app_ids ORDER BY app_id")
            .fetch_all(&mut connection)
            .await
            .unwrap();
    assert_eq!(excluded, vec![vec![41; 16], vec![42; 16], vec![44; 16]]);
    let metadata: Vec<(String, Option<i64>)> =
        sqlx::query_as("SELECT reason, at_ms FROM kept_app_ids ORDER BY app_id")
            .fetch_all(&mut connection)
            .await
            .unwrap();
    assert_eq!(
        metadata,
        vec![
            ("enrolled".into(), Some(NOW as i64)),
            ("enrolled".into(), Some(created as i64)),
            ("document".into(), None)
        ]
    );
    connection.close().await.unwrap();
    let answer = replay
        .service
        .handle(signed(
            "GET",
            &path("apps"),
            vec![],
            Some(created),
            NOW + 4000,
        ))
        .await;
    status(&answer, 503);
    assert!(support::header_text(&answer, header::HEAD).is_none());
}

#[tokio::test]
async fn test_account_association_create_refuses_superseded_sql_with_binding_conflict() {
    let Some(replay) = support::replay().await else {
        return;
    };
    let (initial, first) = create(&replay, NOW, 91).await;
    let distinct_create = make_enrollment(initial.body().intent.clone(), 92);
    sql(
        &replay,
        "CREATE TABLE prior_account AS TABLE accounts; DELETE FROM accounts",
    )
    .await;
    let observation = discover(&replay, NOW + 1000).await;
    assert_eq!(
        AccountObservationBody::from_json(&observation.body)
            .unwrap()
            .association,
        AccountAssociation::Mark
    );
    let takeover = make_enrollment(
        EnrollmentIntent::Takeover {
            created: first,
            observation,
        },
        93,
    );
    let answer = replay
        .service
        .handle(enrollment_request(&takeover, NOW + 1000))
        .await;
    status(&answer, 200);
    let current = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    assert!(current > first);
    sql(
        &replay,
        "DELETE FROM accounts; INSERT INTO accounts SELECT * FROM prior_account",
    )
    .await;
    assert_eq!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .unwrap()
            .created_at_ms,
        first
    );
    assert!(
        matches!(replay.marks.read(&key().id()).await.unwrap(), MarkRead::Mark(mark) if mark.created_at_ms == current && mark.generation == 0 && mark.seq == 0)
    );
    replay.clock.set_wall_ms(NOW + 2000);
    let answer = replay
        .service
        .handle(enrollment_request(&distinct_create, NOW + 2000))
        .await;
    status(&answer, 409);
    assert_eq!(value(&answer)["current"], json!({"binding": "changed"}));
}

async fn replacement_account() -> Option<(Replay, pubky_switch_core::records::IdentityDoc, u64)> {
    let (replay, doc, _, marked) = retained_lifetimes().await?;
    let observation = discover(&replay, NOW + 4000).await;
    let enrollment = make_enrollment(
        EnrollmentIntent::Takeover {
            created: marked,
            observation,
        },
        94,
    );
    let answer = replay
        .service
        .handle(enrollment_request(&enrollment, NOW + 4000))
        .await;
    status(&answer, 200);
    let created = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    Some((replay, doc, created))
}

fn delivered(
    doc: &pubky_switch_core::records::IdentityDoc,
    created: u64,
    at: u64,
) -> SwitchRequest {
    let body = http::IdentityDelivery {
        identity: doc.signed().clone(),
        prev: None,
    }
    .to_json();
    signed("PUT", &path("identity"), body, Some(created), at)
}

#[tokio::test]
async fn test_account_activation_requirement_survives_restart_and_receipt_eviction() {
    let Some((replay, doc, created)) = replacement_account().await else {
        return;
    };
    sql(&replay, "DELETE FROM enrollment_answers").await;
    let reopened = pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        MarkStore::open(replay.key_dir()).unwrap(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    );
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    let retry = reopened.handle(delivered(&doc, created, NOW + 4000)).await;
    status(&retry, 503);
    assert_eq!(value(&retry)["code"], "recovery_required");
    assert!(support::header_text(&retry, header::HEAD).is_none());
    for (method, route) in [
        ("GET", "apps"),
        ("POST", "recovery/upload"),
        ("POST", "import"),
        ("POST", "import/activate"),
        ("POST", "unfreeze"),
    ] {
        let answer = reopened
            .handle(signed(
                method,
                &path(route),
                b"{}".to_vec(),
                Some(created),
                NOW + 4000,
            ))
            .await;
        status(&answer, 503);
        assert_eq!(value(&answer)["code"], "recovery_required");
        assert!(support::header_text(&answer, header::HEAD).is_none());
    }
    assert_eq!(
        replay.db.store().lookup(&key().id()).await.unwrap(),
        Some(before)
    );
}

#[tokio::test]
async fn test_account_activation_requires_higher_version_and_generation() {
    use pubky_switch_core::records::{AccountActivation, IdentityDoc};
    let Some((replay, doc, created)) = replacement_account().await else {
        return;
    };
    let before = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    let mut body = doc.body().clone();
    body.generation = 9;
    body.recovery_from = Some(8);
    let same_version = IdentityDoc::sign(&key(), body.clone()).unwrap();
    let answer = replay
        .service
        .handle(delivered(&same_version, created, NOW + 4000))
        .await;
    status(&answer, 409);
    assert_eq!(value(&answer)["code"], "stale_identity");
    assert_eq!(
        replay.db.store().lookup(&key().id()).await.unwrap(),
        Some(before.clone())
    );
    body.version = 9;
    body.generation = 8;
    body.recovery_from = Some(7);
    let same_generation = IdentityDoc::sign(&key(), body.clone()).unwrap();
    let answer = replay
        .service
        .handle(delivered(&same_generation, created, NOW + 4000))
        .await;
    status(&answer, 503);
    assert_eq!(value(&answer)["code"], "recovery_required");
    assert_eq!(
        replay.db.store().lookup(&key().id()).await.unwrap(),
        Some(before)
    );
    body.generation = 9;
    body.recovery_from = Some(8);
    let higher = IdentityDoc::sign(&key(), body).unwrap();
    let answer = replay
        .service
        .handle(delivered(&higher, created, NOW + 4000))
        .await;
    status(&answer, 200);
    assert!(support::header_text(&answer, header::HEAD).is_some());
    let after = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.activation, AccountActivation::Ordinary);
    assert_eq!(after.generation, 9);
    assert!(after.chain.is_some());
    assert_eq!(after.identity_doc.as_ref(), Some(higher.signed()));
    status(
        &replay
            .service
            .handle(signed(
                "GET",
                &path("apps"),
                vec![],
                Some(created),
                NOW + 4000,
            ))
            .await,
        200,
    );
}

#[tokio::test]
async fn test_account_association_newer_sql_recovery_replaces_exact_older_mark() {
    use pubky_switch_core::records::{IdentityBody, IdentityDoc, Inbox};
    let Some((replay, _, first, current, first_mark)) = staged_lifetimes().await else {
        return;
    };
    let observation = discover(&replay, NOW + 2000).await;
    let service_key = observation
        .verify(&key().public(), ORIGIN)
        .unwrap()
        .body()
        .service_key;
    let service = service_with_restored_mark(&replay, &first_mark);
    let before = MarkStore::open(replay.key_dir())
        .unwrap()
        .read(&key().id())
        .await
        .unwrap();
    assert!(matches!(before, MarkRead::Mark(mark) if mark.created_at_ms == first));
    let mut body = IdentityBody::first(
        key().public(),
        [12; 16],
        Inbox::new(ORIGIN, service_key),
        IdentityPolicy::default(),
    );
    body.version = 2;
    body.generation = 2;
    body.recovery_from = Some(1);
    let doc = IdentityDoc::sign(&key(), body).unwrap();
    let answer = service.handle(delivered(&doc, current, NOW + 2000)).await;
    status(&answer, 200);
    assert!(support::header_text(&answer, header::HEAD).is_some());
    let MarkRead::Mark(mark) = MarkStore::open(replay.key_dir())
        .unwrap()
        .read(&key().id())
        .await
        .unwrap()
    else {
        panic!("readable mark");
    };
    assert_eq!((mark.created_at_ms, mark.generation), (current, 2));
    status(
        &service
            .handle(signed(
                "GET",
                &path("apps"),
                vec![],
                Some(current),
                NOW + 2000,
            ))
            .await,
        200,
    );
}

async fn marked_lifetime_with_older_sql() -> Option<(Replay, u64, u64)> {
    let (replay, retained, older, current) = retained_lifetimes_with_mark(true).await?;
    let row = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.created_at_ms, older);
    assert_eq!(row.identity_doc.as_ref(), Some(retained.signed()));
    assert!(
        matches!(replay.marks.read(&key().id()).await.unwrap(), MarkRead::Mark(mark) if mark.created_at_ms == current && mark.generation == 1)
    );
    Some((replay, older, current))
}

#[tokio::test]
async fn test_account_association_erasure_deletes_physical_older_sql() {
    let Some((replay, _, current)) = marked_lifetime_with_older_sql().await else {
        return;
    };
    let answer = replay
        .service
        .handle(signed(
            "POST",
            &path("erase"),
            http::erase_body(Some(current), None),
            Some(current),
            NOW + 3000,
        ))
        .await;
    status(&answer, 200);
    assert_eq!(value(&answer)["erased"], true);
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        replay.marks.read(&key().id()).await.unwrap(),
        MarkRead::Missing
    );
    assert!(replay.marks.erasure(&key().id()).await.unwrap().is_some());
}

#[tokio::test]
async fn test_account_association_erasure_preserves_older_sql_on_delete_failure() {
    let Some((replay, _, current)) = marked_lifetime_with_older_sql().await else {
        return;
    };
    let before = replay.db.store().lookup(&key().id()).await.unwrap();
    let marked = replay.marks.read(&key().id()).await.unwrap();
    sql(&replay, "CREATE FUNCTION reject_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'delete unavailable'; END $$; CREATE TRIGGER reject_delete BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION reject_delete()").await;
    let request = || {
        signed(
            "POST",
            &path("erase"),
            http::erase_body(Some(current), None),
            Some(current),
            NOW + 3000,
        )
    };
    let answer = replay.service.handle(request()).await;
    status(&answer, 503);
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert_eq!(replay.db.store().lookup(&key().id()).await.unwrap(), before);
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), marked);
    assert!(replay.marks.erasure(&key().id()).await.unwrap().is_none());
    sql(&replay, "DROP TRIGGER reject_delete ON accounts").await;
    status(&replay.service.handle(request()).await, 200);
    assert!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_account_enrollment_removed_app_stays_excluded_after_recovery() {
    use pubky_switch_core::records::{IdentityBody, IdentityDoc, Inbox, ListedApp, RemovedApp};
    let Some(replay) = support::replay().await else {
        return;
    };
    let observation = discover(&replay, NOW).await;
    let service_key = observation
        .verify(&key().public(), ORIGIN)
        .unwrap()
        .body()
        .service_key;
    let mut body = IdentityBody::first(
        key().public(),
        [12; 16],
        Inbox::new(ORIGIN, service_key),
        IdentityPolicy::default(),
    );
    body.removed.push(RemovedApp {
        app_id: [44; 16],
        distrust_from: NOW - 1000,
    });
    let initial = IdentityDoc::sign(&key(), body.clone()).unwrap();
    let mut enrollment = make_enrollment(EnrollmentIntent::Create { observation }, 95)
        .body()
        .clone();
    enrollment.identity_doc = Some(initial.signed().clone());
    let enrollment = Enrollment::sign(&key(), enrollment).unwrap();
    let answer = replay
        .service
        .handle(enrollment_request(&enrollment, NOW))
        .await;
    status(&answer, 200);
    let created = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    body.version = 2;
    body.generation = 2;
    body.recovery_from = Some(1);
    body.removed.clear();
    let recovered = IdentityDoc::sign(&key(), body.clone()).unwrap();
    let delivery = http::IdentityDelivery {
        identity: recovered.signed().clone(),
        prev: Some(initial.hash()),
    };
    status(
        &replay
            .service
            .handle(signed(
                "PUT",
                &path("identity"),
                delivery.to_json(),
                Some(created),
                NOW,
            ))
            .await,
        200,
    );
    body.version = 3;
    body.apps.push(ListedApp {
        app_id: [44; 16],
        cert: [45; 32],
    });
    let relisted = IdentityDoc::sign(&key(), body).unwrap();
    let delivery = http::IdentityDelivery {
        identity: relisted.signed().clone(),
        prev: Some(recovered.hash()),
    };
    let before = replay.db.store().lookup(&key().id()).await.unwrap();
    sql(&replay, "DELETE FROM enrollment_answers").await;
    let reopened = pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        MarkStore::open(replay.key_dir()).unwrap(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    );
    let answer = reopened
        .handle(signed(
            "PUT",
            &path("identity"),
            delivery.to_json(),
            Some(created),
            NOW,
        ))
        .await;
    status(&answer, 400);
    assert_eq!(value(&answer)["code"], "bad_request");
    assert_eq!(replay.db.store().lookup(&key().id()).await.unwrap(), before);
    let apps = reopened
        .handle(signed("GET", &path("apps"), vec![], Some(created), NOW))
        .await;
    status(&apps, 200);
    let value = value(&apps);
    let app = value["apps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|app| app["app_id"] == pubky_switch_core::enc::zbase32_encode(&[44; 16]))
        .unwrap();
    assert_eq!(app["current"], false);
    assert!(app["revoked_at"].is_null());
    assert!(app["departed_at"].is_null());
}

#[tokio::test]
async fn test_account_takeover_failed_commit_keeps_older_sql() {
    let Some((replay, _, first, marked)) = retained_lifetimes().await else {
        return;
    };
    let before = replay.db.store().lookup(&key().id()).await.unwrap();
    let observation = discover(&replay, NOW + 4000).await;
    let enrollment = make_enrollment(
        EnrollmentIntent::Takeover {
            created: marked,
            observation,
        },
        96,
    );
    sql(&replay, "CREATE FUNCTION reject_creation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'creation unavailable'; END $$; CREATE CONSTRAINT TRIGGER reject_creation AFTER INSERT ON accounts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_creation()").await;
    let answer = replay
        .service
        .handle(enrollment_request(&enrollment, NOW + 4000))
        .await;
    status(&answer, 503);
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert_eq!(replay.db.store().lookup(&key().id()).await.unwrap(), before);
    let MarkRead::Mark(mark) = replay.marks.read(&key().id()).await.unwrap() else {
        panic!("readable mark");
    };
    assert_eq!(mark.created_at_ms, NOW + 4000);
    assert!(mark.created_at_ms > marked && marked > first);
    sql(&replay, "DROP TRIGGER reject_creation ON accounts").await;
    let retry = replay
        .service
        .handle(enrollment_request(&enrollment, NOW + 4000))
        .await;
    status(&retry, 409);
    assert_eq!(value(&retry)["current"], json!({"binding":"changed"}));
    assert_eq!(replay.db.store().lookup(&key().id()).await.unwrap(), before);
    let observation = discover(&replay, NOW + 5000).await;
    let distinct = make_enrollment(
        EnrollmentIntent::Takeover {
            created: mark.created_at_ms,
            observation,
        },
        97,
    );
    status(
        &replay
            .service
            .handle(enrollment_request(&distinct, NOW + 5000))
            .await,
        200,
    );
    assert_eq!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .unwrap()
            .activation,
        pubky_switch_core::records::AccountActivation::Recovery
    );
}

#[tokio::test]
async fn test_account_activation_failed_recovery_commit_keeps_requirement() {
    use pubky_switch_core::records::{AccountActivation, IdentityDoc};
    let Some((replay, doc, created)) = replacement_account().await else {
        return;
    };
    let before = replay.db.store().lookup(&key().id()).await.unwrap();
    let marked = replay.marks.read(&key().id()).await.unwrap();
    let mut body = doc.body().clone();
    body.version = 9;
    body.generation = 9;
    body.recovery_from = Some(8);
    let recovered = IdentityDoc::sign(&key(), body).unwrap();
    sql(&replay, "CREATE FUNCTION reject_recovery() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.activation_requirement = 'ordinary' THEN RAISE EXCEPTION 'recovery unavailable'; END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER reject_recovery AFTER UPDATE ON accounts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_recovery()").await;
    let answer = replay
        .service
        .handle(delivered(&recovered, created, NOW + 4000))
        .await;
    status(&answer, 503);
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert_eq!(replay.db.store().lookup(&key().id()).await.unwrap(), before);
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), marked);
    sql(&replay, "DROP TRIGGER reject_recovery ON accounts").await;
    status(
        &replay
            .service
            .handle(delivered(&recovered, created, NOW + 4000))
            .await,
        200,
    );
    assert_eq!(
        replay
            .db
            .store()
            .lookup(&key().id())
            .await
            .unwrap()
            .unwrap()
            .activation,
        AccountActivation::Ordinary
    );
}

#[tokio::test]
async fn test_account_takeover_committed_without_answer_retries_after_restart() {
    let Some((replay, doc, _, marked)) = retained_lifetimes().await else {
        return;
    };
    let observation = discover(&replay, NOW + 4000).await;
    let enrollment = make_enrollment(
        EnrollmentIntent::Takeover {
            created: marked,
            observation,
        },
        111,
    );
    let request = enrollment_request(&enrollment, NOW + 4000);
    let exact_body = request.body.clone();
    let exact_headers = request.headers.clone();
    drop(replay.service.handle(request).await);
    let committed = replay
        .db
        .store()
        .lookup(&key().id())
        .await
        .unwrap()
        .unwrap();
    assert!(committed.created_at_ms > marked, "replacement committed");
    assert_eq!(
        committed.activation,
        pubky_switch_core::records::AccountActivation::Recovery
    );
    assert_eq!(committed.identity_doc.as_ref(), Some(doc.signed()));
    let mark = replay.marks.read(&key().id()).await.unwrap();
    assert!(matches!(mark, MarkRead::Mark(mark) if mark.created_at_ms == committed.created_at_ms));
    let mut connection = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .unwrap();
    let receipts: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(e) FROM enrollment_answers e")
        .fetch_all(&mut connection)
        .await
        .unwrap();
    assert_eq!(receipts.len(), 1, "committed exact enrollment receipt");
    let restarted = replay.restarted_with(pubky_switch::limits::Limits::default());
    let retry = enrollment_request(&enrollment, NOW + 4000);
    assert_eq!(retry.body, exact_body);
    assert_eq!(retry.headers, exact_headers);
    let answer = restarted.handle(retry).await;
    status(&answer, 200);
    assert_eq!(value(&answer)["created"], rfc3339(committed.created_at_ms));
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert_eq!(
        replay.db.store().lookup(&key().id()).await.unwrap(),
        Some(committed)
    );
    assert_eq!(replay.marks.read(&key().id()).await.unwrap(), mark);
    let after: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(e) FROM enrollment_answers e")
        .fetch_all(&mut connection)
        .await
        .unwrap();
    assert_eq!(after, receipts);
}

#[tokio::test]
async fn test_account_recovery_committed_before_older_mark_write_failure() {
    use pubky_switch_core::records::{IdentityBody, IdentityDoc, Inbox};
    use std::os::unix::fs::PermissionsExt;
    let Some((replay, _, first, current, first_mark)) = staged_lifetimes().await else {
        return;
    };
    let service_key = discover(&replay, NOW + 2000)
        .await
        .verify(&key().public(), ORIGIN)
        .unwrap()
        .body()
        .service_key;
    let service = service_with_restored_mark(&replay, &first_mark);
    let marks = MarkStore::open(replay.key_dir()).unwrap();
    let old_mark = marks.read(&key().id()).await.unwrap();
    assert!(matches!(old_mark, MarkRead::Mark(mark) if mark.created_at_ms == first));
    let mut body = IdentityBody::first(
        key().public(),
        [12; 16],
        Inbox::new(ORIGIN, service_key),
        IdentityPolicy::default(),
    );
    body.version = 2;
    body.generation = 2;
    body.recovery_from = Some(1);
    let doc = IdentityDoc::sign(&key(), body.clone()).unwrap();
    let pause = service.pause_next_mark_move();
    let directory = replay.key_dir().join("accounts").join("marks");
    let permissions = std::fs::metadata(&directory).unwrap().permissions();
    let (answer, committed) = tokio::join!(
        Box::pin(service.handle(delivered(&doc, current, NOW + 2000))),
        async {
            tokio::time::timeout(std::time::Duration::from_secs(10), pause.reached())
                .await
                .unwrap();
            let committed = replay
                .db
                .store()
                .lookup(&key().id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(committed.created_at_ms, current);
            assert_eq!(
                committed.generation, 2,
                "recovery SQL is durable before mark replacement"
            );
            assert_eq!(committed.identity_doc.as_ref(), Some(doc.signed()));
            assert!(committed.chain.is_some());
            assert_eq!(marks.read(&key().id()).await.unwrap(), old_mark);
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
            pause.release();
            committed
        }
    );
    std::fs::set_permissions(&directory, permissions).unwrap();
    status(&answer, 503);
    assert_eq!(value(&answer)["code"], "unavailable");
    assert!(support::header_text(&answer, header::HEAD).is_none());
    assert_eq!(
        replay.db.store().lookup(&key().id()).await.unwrap(),
        Some(committed)
    );
    assert_eq!(marks.read(&key().id()).await.unwrap(), old_mark);
    let ordinary = service
        .handle(signed(
            "GET",
            &path("apps"),
            vec![],
            Some(current),
            NOW + 2000,
        ))
        .await;
    status(&ordinary, 503);
    assert_eq!(value(&ordinary)["code"], "recovery_required");
    assert_eq!(value(&ordinary)["current"]["reason"], "mark_lost");
    assert!(support::header_text(&ordinary, header::HEAD).is_none());
    body.version = 3;
    body.generation = 3;
    body.recovery_from = Some(2);
    let next = IdentityDoc::sign(&key(), body).unwrap();
    let recovered = service.handle(delivered(&next, current, NOW + 2000)).await;
    status(&recovered, 200);
    assert!(support::header_text(&recovered, header::HEAD).is_some());
    assert!(
        matches!(MarkStore::open(replay.key_dir()).unwrap().read(&key().id()).await.unwrap(), MarkRead::Mark(mark) if mark.created_at_ms == current && mark.generation == 3)
    );
}
