//! Signed account observations, exact enrollment retries and explicit mark takeover.

#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use pubky_switch_client::{
    clock::TestClock,
    testing::{ErasureOutcome, SWITCH_ORIGIN, ScriptedSwitch},
    transport::{Header, Request, Response, Transport},
};
use pubky_switch_core::{
    enc::{b64, unb64_array},
    http::{self, RequestHeaders, RequestTarget, header},
    keys::IdentityKey,
    records::{
        AccountAssociation, AccountObservationBody, CarriedAccountObservation, Enrollment,
        EnrollmentBody, EnrollmentIntent, IdentityPolicy,
    },
    time::{parse_rfc3339, rfc3339, rfc3339_seconds},
};
use serde_json::{Value, json};

const NOW: u64 = 1_767_225_600_000;

struct Account {
    key: IdentityKey,
    clock: Arc<TestClock>,
    switch: Arc<ScriptedSwitch>,
}

impl Account {
    fn new() -> Self {
        let key = IdentityKey::from_secret([1; 32]);
        let clock = Arc::new(TestClock::new(NOW));
        let switch = ScriptedSwitch::unenrolled(&key, [2; 32], Arc::clone(&clock));
        Self { key, clock, switch }
    }

    fn path(&self, suffix: &str) -> String {
        format!("/v1/{}/{suffix}", self.key.id())
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        created: Option<u64>,
        at: u64,
    ) -> Request {
        let fields = RequestHeaders {
            timestamp: rfc3339_seconds(at),
            identity: self.key.id(),
            created: created.map(rfc3339),
            ..RequestHeaders::default()
        };
        let signature = http::sign_request(
            &self.key,
            &RequestTarget {
                method,
                path_and_query: path,
                body: &body,
                origin: SWITCH_ORIGIN,
            },
            &fields,
        );
        let mut headers = vec![
            Header::new(header::IDENTITY, &fields.identity),
            Header::new(header::TIMESTAMP, &fields.timestamp),
            Header::new(header::SIGNATURE, &b64(&signature)),
        ];
        if let Some(created) = fields.created {
            headers.push(Header::new(header::CREATED, &created));
        }
        Request {
            method: method.into(),
            origin: SWITCH_ORIGIN.into(),
            path_and_query: path.into(),
            headers,
            body,
            timeout: pubky_switch_client::transport::TimeoutClass::Bulk,
        }
    }

    async fn send(&self, request: Request) -> Response {
        self.switch.transport().send(request).await.unwrap()
    }

    async fn observe(&self, at: u64) -> CarriedAccountObservation {
        self.clock.set_ms(at);
        let request = self.request("GET", &self.path("account"), vec![], None, at);
        let request_timestamp = request.header(header::TIMESTAMP).unwrap().to_owned();
        let request_signature = unb64_array(request.header(header::SIGNATURE).unwrap()).unwrap();
        let answer = self.send(request).await;
        status(&answer, 200);
        assert!(answer.header(header::HEAD).is_none());
        let carried = CarriedAccountObservation {
            body: answer.body.clone(),
            sig: unb64_array(answer.header(header::SERVICE_SIGNATURE).unwrap()).unwrap(),
            request_timestamp,
            request_signature,
        };
        let verified = carried.verify(&self.key.public(), SWITCH_ORIGIN).unwrap();
        assert_eq!(verified.body().service_key, self.switch.service_key());
        carried
    }

    fn enrollment(&self, intent: EnrollmentIntent, nonce: u8) -> Enrollment {
        Enrollment::sign(
            &self.key,
            EnrollmentBody {
                identity: self.key.public(),
                origin: SWITCH_ORIGIN.into(),
                nonce: [nonce; 16],
                intent,
                policy: IdentityPolicy::default(),
                identity_doc: None,
                revoked_apps: None,
            },
        )
        .unwrap()
    }

    fn enrollment_request(&self, enrollment: &Enrollment, at: u64) -> Request {
        self.request(
            "POST",
            "/v1/enroll",
            serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).unwrap(),
            enrollment.body().intent.created(),
            at,
        )
    }

    async fn create(&self, at: u64, nonce: u8) -> (Enrollment, u64) {
        let observation = self.observe(at).await;
        assert_eq!(
            AccountObservationBody::from_json(&observation.body)
                .unwrap()
                .created,
            None
        );
        let enrollment = self.enrollment(EnrollmentIntent::Create { observation }, nonce);
        let answer = self.send(self.enrollment_request(&enrollment, at)).await;
        status(&answer, 200);
        (
            enrollment,
            parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap(),
        )
    }

    async fn erase(&self, created: u64, at: u64) -> Response {
        self.clock.set_ms(at);
        self.send(self.request(
            "POST",
            &self.path("erase"),
            http::erase_body(Some(created), None),
            Some(created),
            at,
        ))
        .await
    }
}

fn value(response: &Response) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}
fn status(response: &Response, expected: u16) {
    assert_eq!(
        response.status,
        expected,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
}

#[tokio::test]
async fn test_account_binding_scripted_expired_receipt_is_read_only() {
    let account = Account::new();
    let (enrollment, created) = account.create(NOW, 1).await;
    let before = (account.switch.mark(), account.switch.seq());
    let first = account
        .send(account.enrollment_request(&enrollment, NOW))
        .await;
    let observed = account.observe(NOW + 300_000).await;
    assert_eq!(
        AccountObservationBody::from_json(&observed.body)
            .unwrap()
            .created,
        Some(created)
    );
    let retried = account
        .send(account.enrollment_request(&enrollment, NOW + 300_000))
        .await;
    status(&retried, 200);
    assert_eq!(retried.body, first.body);
    assert_eq!(
        retried.header(header::SERVER_TIME),
        first.header(header::SERVER_TIME)
    );
    assert_eq!((account.switch.mark(), account.switch.seq()), before);
}

#[tokio::test]
async fn test_account_binding_scripted_existing_intent_does_not_recreate() {
    let account = Account::new();
    let (_, created) = account.create(NOW, 2).await;
    let enrollment = account.enrollment(EnrollmentIntent::Existing { created }, 3);
    let saved = account.enrollment_request(&enrollment, NOW);
    status(&account.send(saved.clone()).await, 200);
    status(&account.erase(created, NOW + 1000).await, 200);
    let replayed = saved.clone();
    assert_eq!(replayed, saved);
    let answer = account.send(replayed).await;
    status(&answer, 404);
    assert_eq!(value(&answer)["current"]["hosted"], false);
    assert!(account.switch.erased());
    assert!(account.switch.mark().is_none());
    let (_, newer) = account.create(NOW + 2000, 4).await;
    assert!(newer > created);
}

#[tokio::test]
async fn test_account_binding_scripted_zero_mark_requires_takeover() {
    let account = Account::new();
    let (original, created) = account.create(NOW, 5).await;
    let before = account.switch.mark().unwrap();
    account.switch.lose_account();
    let refused = account
        .send(account.enrollment_request(&original, NOW))
        .await;
    status(&refused, 409);
    assert_eq!(value(&refused)["current"]["binding"], "changed");
    assert_eq!(account.switch.mark(), Some(before));
    let observation = account.observe(NOW + 1000).await;
    let takeover = account.enrollment(
        EnrollmentIntent::Takeover {
            created,
            observation,
        },
        6,
    );
    let answer = account
        .send(account.enrollment_request(&takeover, NOW + 1000))
        .await;
    status(&answer, 200);
    assert!(parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap() > created);
    assert_eq!(account.switch.mark(), Some(before));
    account.clock.set_ms(NOW + 301_000);
    status(
        &account
            .send(account.enrollment_request(&takeover, NOW + 301_000))
            .await,
        200,
    );
}

#[tokio::test]
async fn test_account_binding_scripted_observation_time_is_exact() {
    for (offset, expected) in [(-1, 503), (299_999, 200), (300_000, 409), (300_001, 409)] {
        let account = Account::new();
        let observation = account.observe(NOW).await;
        let enrollment = account.enrollment(EnrollmentIntent::Create { observation }, 7);
        let at = NOW.checked_add_signed(offset).unwrap();
        account.clock.set_ms(at);
        let answer = account
            .send(account.enrollment_request(&enrollment, at))
            .await;
        status(&answer, expected);
        if expected != 200 {
            assert!(account.switch.mark().is_none());
        }
    }
}

#[tokio::test]
async fn test_account_binding_scripted_discovery_preserves_pending_erasure() {
    for outcome in [
        ErasureOutcome::Unresolved,
        ErasureOutcome::UnresolvedAbsent,
        ErasureOutcome::Committed,
        ErasureOutcome::Rejected,
    ] {
        let account = Account::new();
        let (_, created) = account.create(NOW, 8).await;
        account.switch.fail_next_erasure(outcome);
        status(&account.erase(created, NOW + 1000).await, 503);
        let before = (
            account.switch.mark(),
            account.switch.erased(),
            account.switch.seq(),
        );
        for _ in 0..2 {
            let answer = account
                .send(account.request("GET", &account.path("account"), vec![], None, NOW + 1000))
                .await;
            status(&answer, 503);
            assert_eq!(
                (
                    account.switch.mark(),
                    account.switch.erased(),
                    account.switch.seq()
                ),
                before
            );
            assert!(answer.header(header::HEAD).is_none());
        }
    }
}

#[tokio::test]
async fn test_account_binding_scripted_corrupt_mark_needs_readable_account() {
    let account = Account::new();
    let (_, created) = account.create(NOW, 9).await;
    account.switch.corrupt_mark();
    let observed = account.observe(NOW).await;
    assert_eq!(
        AccountObservationBody::from_json(&observed.body)
            .unwrap()
            .created,
        Some(created)
    );
    account.switch.lose_account();
    let answer = account
        .send(account.request("GET", &account.path("account"), vec![], None, NOW))
        .await;
    status(&answer, 503);
    assert_eq!(value(&answer)["code"], "unavailable");
}

#[tokio::test]
async fn test_account_binding_scripted_saved_delivery_cannot_activate_recreated_account() {
    use pubky_switch_core::records::{IdentityBody, IdentityDoc, Inbox};
    let account = Account::new();
    let (_, first) = account.create(NOW, 41).await;
    let doc = IdentityDoc::sign(
        &account.key,
        IdentityBody::first(
            account.key.public(),
            [3; 16],
            Inbox::new(SWITCH_ORIGIN, account.switch.service_key()),
            IdentityPolicy::default(),
        ),
    )
    .unwrap();
    let body = http::IdentityDelivery {
        identity: doc.signed().clone(),
        prev: None,
    }
    .to_json();
    let saved = account.request(
        "PUT",
        &account.path("identity"),
        body.clone(),
        Some(first),
        NOW,
    );
    status(&account.send(saved.clone()).await, 200);
    account.clock.set_ms(NOW + 1000);
    let erased = account
        .send(account.request(
            "POST",
            &account.path("erase"),
            http::erase_body(Some(first), Some(&doc.hash())),
            Some(first),
            NOW + 1000,
        ))
        .await;
    status(&erased, 200);
    assert!(account.switch.erased());
    let (_, second) = account.create(NOW + 2000, 42).await;
    assert!(second > first);
    let before = (account.switch.mark(), account.switch.seq());
    assert!(account.switch.identity_doc().is_none());
    let replayed = saved.clone();
    assert_eq!(replayed, saved);
    let answer = account.send(replayed).await;
    status(&answer, 409);
    assert_eq!(value(&answer)["current"]["created"], rfc3339(second));
    assert!(answer.header(header::HEAD).is_none());
    assert!(account.switch.identity_doc().is_none());
    assert_eq!((account.switch.mark(), account.switch.seq()), before);
    status(
        &account
            .send(account.request(
                "PUT",
                &account.path("identity"),
                body,
                Some(second),
                NOW + 2000,
            ))
            .await,
        200,
    );
}

async fn pending_erasure_header(header: Option<u64>) {
    let account = Account::new();
    let (_, created) = account.create(NOW, 51).await;
    account
        .switch
        .fail_next_erasure(ErasureOutcome::UnresolvedAbsent);
    status(&account.erase(created, NOW + 1000).await, 503);
    let before = (
        account.switch.mark(),
        account.switch.erased(),
        account.switch.seq(),
    );
    let body = http::erase_body(Some(created), None);
    let request = account.request("POST", &account.path("erase"), body, header, NOW + 1000);
    let answer = account.send(request).await;
    status(&answer, 400);
    assert_eq!(
        (
            account.switch.mark(),
            account.switch.erased(),
            account.switch.seq()
        ),
        before
    );
    let discovery = account
        .send(account.request("GET", &account.path("account"), vec![], None, NOW + 1000))
        .await;
    status(&discovery, 503);
    status(&account.erase(created, NOW + 1000).await, 200);
    assert!(account.switch.mark().is_none());
}

#[tokio::test]
async fn test_account_binding_scripted_pending_erasure_requires_creation() {
    pending_erasure_header(None).await;
}

#[tokio::test]
async fn test_account_binding_scripted_pending_erasure_matches_body() {
    pending_erasure_header(Some(NOW + 1)).await;
}

async fn scripted_mark_only_conflict(activate: bool) {
    use pubky_switch_core::records::{IdentityBody, IdentityDoc, Inbox};
    let account = Account::new();
    let (_, created) = account.create(NOW, 91).await;
    if activate {
        let doc = IdentityDoc::sign(
            &account.key,
            IdentityBody::first(
                account.key.public(),
                [4; 16],
                Inbox::new(SWITCH_ORIGIN, account.switch.service_key()),
                IdentityPolicy::default(),
            ),
        )
        .unwrap();
        let body = http::IdentityDelivery {
            identity: doc.signed().clone(),
            prev: None,
        }
        .to_json();
        status(
            &account
                .send(account.request("PUT", &account.path("identity"), body, Some(created), NOW))
                .await,
            200,
        );
    }
    account.switch.lose_account();
    let before = (account.switch.mark(), account.switch.seq());
    account.clock.set_ms(NOW + 1000);
    let answer = account
        .send(account.request(
            "GET",
            &account.path("apps"),
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
        answer.header(header::SERVER_TIME),
        Some(rfc3339(NOW + 1000).as_str())
    );
    assert!(answer.header(header::HEAD).is_none());
    assert_eq!((account.switch.mark(), account.switch.seq()), before);
    let same = account
        .send(account.request(
            "GET",
            &account.path("apps"),
            vec![],
            Some(created),
            NOW + 1000,
        ))
        .await;
    status(&same, if activate { 503 } else { 404 });
    assert_eq!((account.switch.mark(), account.switch.seq()), before);
}

#[tokio::test]
async fn test_account_binding_scripted_zero_mark_compares_creation() {
    scripted_mark_only_conflict(false).await;
}

#[tokio::test]
async fn test_account_binding_scripted_lost_mark_compares_creation() {
    scripted_mark_only_conflict(true).await;
}

async fn failed_account_signature_precedence(unreadable: bool) {
    use pubky_switch_core::records::{IdentityBody, IdentityDoc, Inbox};
    let account = Account::new();
    let (_, created) = account.create(NOW, 101).await;
    let doc = IdentityDoc::sign(
        &account.key,
        IdentityBody::first(
            account.key.public(),
            [8; 16],
            Inbox::new(SWITCH_ORIGIN, account.switch.service_key()),
            IdentityPolicy::default(),
        ),
    )
    .unwrap();
    let body = http::IdentityDelivery {
        identity: doc.signed().clone(),
        prev: None,
    }
    .to_json();
    status(
        &account
            .send(account.request("PUT", &account.path("identity"), body, Some(created), NOW))
            .await,
        200,
    );
    if unreadable {
        account.switch.set_mark_store_unreadable(true);
    } else {
        account.switch.lose_account();
    }
    let before = (
        account.switch.mark(),
        account.switch.seq(),
        account.switch.identity_doc(),
    );
    let mut request = account.request("GET", &account.path("apps"), vec![], Some(created), NOW);
    let mut signature: [u8; 64] = unb64_array(request.header(header::SIGNATURE).unwrap()).unwrap();
    signature[0] ^= 1;
    for field in &mut request.headers {
        if field.name == header::SIGNATURE {
            field.value = b64(&signature);
        }
    }
    let answer = account.send(request.clone()).await;
    let after = (
        account.switch.mark(),
        account.switch.seq(),
        account.switch.identity_doc(),
    );
    let body = value(&answer);
    let expected = if unreadable {
        "unavailable"
    } else {
        "recovery_required"
    };
    assert_eq!(
        (
            answer.status,
            body["code"].as_str(),
            answer.header(header::HEAD).is_some(),
            after == before,
        ),
        (503, Some(expected), false, true),
        "request={request:?}; response={answer:?}; before={before:?}; after={after:?}",
    );
}

#[tokio::test]
async fn test_account_binding_lost_notice_precedes_bad_signature() {
    failed_account_signature_precedence(false).await;
}

#[tokio::test]
async fn test_account_binding_unreadable_store_precedes_bad_signature() {
    failed_account_signature_precedence(true).await;
}

async fn observe_directional_account(sql_created: u64, expected: AccountAssociation) {
    let account = Account::new();
    let (_, mark_created) = account.create(NOW, 71).await;
    account.switch.restore_account_creation(sql_created);
    let before = (
        account.switch.mark(),
        account.switch.seq(),
        account.switch.stored_creation(),
        account.switch.erasure_record(),
    );
    let observation = account.observe(NOW + 2000).await;
    let checked = observation
        .verify(&account.key.public(), SWITCH_ORIGIN)
        .unwrap();
    assert_eq!(
        (checked.body().association, checked.body().created),
        (expected, Some(sql_created.max(mark_created)))
    );
    assert_eq!(
        (
            account.switch.mark(),
            account.switch.seq(),
            account.switch.stored_creation(),
            account.switch.erasure_record()
        ),
        before
    );
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
async fn test_account_discovery_scripted_older_sql_selects_mark_without_effects() {
    observe_directional_account(NOW - 1000, AccountAssociation::Mark).await;
}

#[tokio::test]
async fn test_account_discovery_scripted_newer_sql_selects_account_without_effects() {
    observe_directional_account(NOW + 1000, AccountAssociation::Account).await;
}

#[tokio::test]
async fn test_account_discovery_scripted_covered_older_sql_refuses_without_cleanup() {
    let account = Account::new();
    let (_, first) = account.create(NOW, 72).await;
    status(&account.erase(first, NOW + 1000).await, 200);
    let (_, current) = account.create(NOW + 2000, 73).await;
    assert!(current > first);
    account.switch.restore_account_creation(first);
    let before = (
        account.switch.mark(),
        account.switch.seq(),
        account.switch.stored_creation(),
        account.switch.erasure_record(),
    );
    let answer = account
        .send(account.request("GET", &account.path("account"), vec![], None, NOW + 2000))
        .await;
    status(&answer, 503);
    assert_eq!(value(&answer)["code"], "unavailable");
    assert!(answer.header(header::HEAD).is_none());
    assert_eq!(
        (
            account.switch.mark(),
            account.switch.seq(),
            account.switch.stored_creation(),
            account.switch.erasure_record()
        ),
        before
    );
}

#[tokio::test]
async fn test_account_association_scripted_existing_refuses_superseded_sql() {
    let account = Account::new();
    let (_, created) = account.create(NOW, 81).await;
    account.switch.restore_account_creation(NOW - 1000);
    let before = (
        account.switch.mark(),
        account.switch.seq(),
        account.switch.stored_creation(),
    );
    let enrollment = account.enrollment(EnrollmentIntent::Existing { created }, 82);
    let answer = account
        .send(account.enrollment_request(&enrollment, NOW))
        .await;
    status(&answer, 404);
    assert!(answer.header(header::HEAD).is_none());
    assert_eq!(
        (
            account.switch.mark(),
            account.switch.seq(),
            account.switch.stored_creation()
        ),
        before
    );
}

#[tokio::test]
async fn test_account_association_scripted_newer_sql_binds_ordinary_requests() {
    let account = Account::new();
    account.create(NOW, 83).await;
    let created = NOW + 1000;
    account.switch.restore_account_creation(created);
    account.clock.set_ms(NOW + 2000);
    let before = (
        account.switch.mark(),
        account.switch.seq(),
        account.switch.stored_creation(),
    );
    let answer = account
        .send(account.request(
            "GET",
            &account.path("apps"),
            vec![],
            Some(created),
            NOW + 2000,
        ))
        .await;
    status(&answer, 503);
    assert_eq!(value(&answer)["current"]["reason"], "mark_lost");
    assert!(answer.header(header::HEAD).is_none());
    assert_eq!(
        (
            account.switch.mark(),
            account.switch.seq(),
            account.switch.stored_creation()
        ),
        before
    );
}

#[tokio::test]
async fn test_account_activation_scripted_replacement_keeps_baseline_until_recovery() {
    use pubky_switch_core::records::{IdentityBody, IdentityDoc, Inbox};
    let account = Account::new();
    let observation = account.observe(NOW).await;
    let mut body = IdentityBody::first(
        account.key.public(),
        [12; 16],
        Inbox::new(SWITCH_ORIGIN, account.switch.service_key()),
        IdentityPolicy::default(),
    );
    body.version = 8;
    body.generation = 8;
    body.recovery_from = Some(7);
    let doc = IdentityDoc::sign(&account.key, body.clone()).unwrap();
    let mut enrollment = account
        .enrollment(EnrollmentIntent::Create { observation }, 81)
        .body()
        .clone();
    enrollment.identity_doc = Some(doc.signed().clone());
    enrollment.revoked_apps = Some(vec![[41; 16]]);
    let enrollment = Enrollment::sign(&account.key, enrollment).unwrap();
    status(
        &account
            .send(account.enrollment_request(&enrollment, NOW))
            .await,
        200,
    );
    assert_eq!(
        account.switch.mark(),
        Some((0, 0, pubky_switch_core::chain::ZERO_HASH))
    );
    account.switch.restore_account_creation(NOW - 1000);
    let observation = account.observe(NOW + 1000).await;
    assert_eq!(
        AccountObservationBody::from_json(&observation.body)
            .unwrap()
            .association,
        AccountAssociation::Mark
    );
    let takeover = account.enrollment(
        EnrollmentIntent::Takeover {
            created: NOW,
            observation,
        },
        82,
    );
    let answer = account
        .send(account.enrollment_request(&takeover, NOW + 1000))
        .await;
    status(&answer, 200);
    let created = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    assert_eq!(account.switch.identity_doc().unwrap(), doc);
    assert_eq!(account.switch.generation(), 8);
    let ordinary = account
        .send(account.request(
            "GET",
            &account.path("apps"),
            vec![],
            Some(created),
            NOW + 1000,
        ))
        .await;
    status(&ordinary, 503);
    assert_eq!(value(&ordinary)["code"], "recovery_required");
    let delivery = |doc: &IdentityDoc| {
        http::IdentityDelivery {
            identity: doc.signed().clone(),
            prev: None,
        }
        .to_json()
    };
    let retry = account
        .send(account.request(
            "PUT",
            &account.path("identity"),
            delivery(&doc),
            Some(created),
            NOW + 1000,
        ))
        .await;
    status(&retry, 503);
    assert!(retry.header(header::HEAD).is_none());
    body.version = 9;
    body.generation = 9;
    body.recovery_from = Some(8);
    let higher = IdentityDoc::sign(&account.key, body).unwrap();
    let recovered = account
        .send(account.request(
            "PUT",
            &account.path("identity"),
            delivery(&higher),
            Some(created),
            NOW + 1000,
        ))
        .await;
    status(&recovered, 200);
    assert!(recovered.header(header::HEAD).is_some());
    assert_eq!(account.switch.identity_doc().unwrap(), higher);
    status(
        &account
            .send(account.request(
                "GET",
                &account.path("apps"),
                vec![],
                Some(created),
                NOW + 1000,
            ))
            .await,
        200,
    );
}

#[tokio::test]
async fn test_account_scripted_removed_app_stays_excluded_after_recovery() {
    use pubky_switch_core::records::{IdentityBody, IdentityDoc, Inbox, ListedApp, RemovedApp};
    let account = Account::new();
    let observation = account.observe(NOW).await;
    let mut body = IdentityBody::first(
        account.key.public(),
        [12; 16],
        Inbox::new(SWITCH_ORIGIN, account.switch.service_key()),
        IdentityPolicy::default(),
    );
    body.removed.push(RemovedApp {
        app_id: [44; 16],
        distrust_from: NOW - 1000,
    });
    let initial = IdentityDoc::sign(&account.key, body.clone()).unwrap();
    let mut enrollment = account
        .enrollment(EnrollmentIntent::Create { observation }, 95)
        .body()
        .clone();
    enrollment.identity_doc = Some(initial.signed().clone());
    let enrollment = Enrollment::sign(&account.key, enrollment).unwrap();
    let answer = account
        .send(account.enrollment_request(&enrollment, NOW))
        .await;
    status(&answer, 200);
    let created = parse_rfc3339(value(&answer)["created"].as_str().unwrap()).unwrap();
    body.version = 2;
    body.generation = 2;
    body.recovery_from = Some(1);
    body.removed.clear();
    let recovered = IdentityDoc::sign(&account.key, body.clone()).unwrap();
    let delivery = http::IdentityDelivery {
        identity: recovered.signed().clone(),
        prev: Some(initial.hash()),
    };
    status(
        &account
            .send(account.request(
                "PUT",
                &account.path("identity"),
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
    let relisted = IdentityDoc::sign(&account.key, body).unwrap();
    let delivery = http::IdentityDelivery {
        identity: relisted.signed().clone(),
        prev: Some(recovered.hash()),
    };
    let before = (account.switch.seq(), account.switch.identity_doc());
    let answer = account
        .send(account.request(
            "PUT",
            &account.path("identity"),
            delivery.to_json(),
            Some(created),
            NOW,
        ))
        .await;
    status(&answer, 400);
    assert_eq!(
        (account.switch.seq(), account.switch.identity_doc()),
        before
    );
    let apps = account
        .send(account.request("GET", &account.path("apps"), vec![], Some(created), NOW))
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
async fn test_account_observation_scripted_accounts_share_service_store() {
    let store_id = pubky_switch_core::enc::random_bytes().unwrap();
    let make = |seed| {
        let key = IdentityKey::from_secret([seed; 32]);
        let clock = Arc::new(TestClock::new(NOW));
        let switch = ScriptedSwitch::unenrolled_at_in_store(
            &key,
            [2; 32],
            clock.clone(),
            SWITCH_ORIGIN,
            store_id,
        );
        Account { key, clock, switch }
    };
    let alice = make(71);
    let bob = make(72);
    for account in [&alice, &bob] {
        let observed = account.observe(NOW).await;
        assert_eq!(
            observed
                .verify(&account.key.public(), SWITCH_ORIGIN)
                .unwrap()
                .body()
                .store_id,
            store_id
        );
    }
    let (_, created) = alice.create(NOW, 1).await;
    let (_, bob_created) = bob.create(NOW, 2).await;
    status(&alice.erase(created, NOW + 1000).await, 200);
    let alice_observed = alice.observe(NOW + 2000).await;
    let bob_observed = bob.observe(NOW + 2000).await;
    let alice_body = alice_observed
        .verify(&alice.key.public(), SWITCH_ORIGIN)
        .unwrap();
    let bob_body = bob_observed
        .verify(&bob.key.public(), SWITCH_ORIGIN)
        .unwrap();
    assert_eq!(alice_body.body().store_id, store_id);
    assert_eq!(bob_body.body().store_id, store_id);
    assert_eq!(alice_body.body().association, AccountAssociation::Absent);
    assert_eq!(bob_body.body().created, Some(bob_created));
    assert_eq!(bob_body.body().association, AccountAssociation::Account);
    let distinct = Account::new();
    let other = distinct.observe(NOW).await;
    assert_ne!(
        other
            .verify(&distinct.key.public(), SWITCH_ORIGIN)
            .unwrap()
            .body()
            .store_id,
        store_id
    );
}
