//! Unit tests of the client against a scripted switch.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use pubky_switch_core::chain::{
    ChainTip, ItemType, ProofBody, ProofState, TransitionProof, item_hash,
};
use pubky_switch_core::enc::{b64, pubky_id};
use pubky_switch_core::http::{self, ErrorCode, IdentityDelivery, header, sign_response};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::ops::{AllowKind, Condition, OpKind, OpsRequest, Position, SignedOp};
use pubky_switch_core::records::{
    AppCert, AppCertBody, DEFAULT_CERT_LIFETIME_MS, Enrollment, EnrollmentAnswer, EnrollmentBody,
    IdentityBody, IdentityDoc, IdentityPolicy, Inbox, Limits,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::{Value, json};

use super::answers::{FeedItem, FeedPage};
use super::read::Obj;
use super::*;
use crate::clock::TestClock;
use crate::transport::MockTransport;

const ORIGIN: &str = "https://switch.example";
const NOW: u64 = 1_767_225_900_000;

fn identity() -> IdentityKey {
    IdentityKey::from_secret([1; 32])
}

fn service_key() -> SigningKey {
    SigningKey::from_bytes(&[5; 32])
}

fn service_public() -> [u8; 32] {
    service_key().verifying_key().to_bytes()
}

fn app_keys() -> AppKeys {
    AppKeys::from_secrets([2; 32], [3; 32])
}

fn cert_of(identity: &IdentityKey, keys: &AppKeys) -> AppCert {
    let body = AppCertBody::new(
        identity.public(),
        keys.signing_public(),
        keys.bundle_public(),
        vec!["sample".into()],
        &[Permission::ListsRead],
        NOW,
        NOW + DEFAULT_CERT_LIFETIME_MS,
    );
    AppCert::issue(identity, body).unwrap()
}

fn signer() -> Credentials {
    Credentials::Signer {
        identity: identity().public(),
        key: Arc::new(identity()),
    }
}

/// The identity key behind a request-only interface, as the signer's request credential
/// holds it.
struct RequestsOnly(IdentityKey);

impl pubky_switch_core::signing::SignsRequests for RequestsOnly {
    fn public_key(&self) -> [u8; 32] {
        self.0.public()
    }

    fn sign_request_fields(&self, fields: &[&[u8]]) -> [u8; 64] {
        self.0.sign(pubky_switch_core::labels::sig::HTTP, fields)
    }
}

fn signer_requests() -> Credentials {
    Credentials::SignerRequests {
        identity: identity().public(),
        key: Arc::new(RequestsOnly(identity())),
    }
}

fn app() -> Credentials {
    Credentials::App {
        identity: identity().public(),
        keys: app_keys(),
        cert: cert_of(&identity(), &app_keys()),
    }
}

fn client_with(
    credentials: Credentials,
    pinned: Option<[u8; 32]>,
    transport: Arc<MockTransport>,
) -> SwitchClient {
    SwitchClient::new(
        ORIGIN,
        identity().public(),
        credentials,
        pinned,
        transport,
        Arc::new(TestClock::new(NOW)),
    )
    .unwrap()
}

/// A response to `request`, signed with `key` as the switch signs it (Switch wire 7.1).
fn respond(key: &SigningKey, request: &Request, status: u16, body: &[u8]) -> Response {
    respond_with_head(key, request, status, body, None)
}

/// A response to `request` carrying `head` as its `Switch-Head`, signed with `key` as the
/// switch signs it (Switch wire 7.1).
fn respond_with_head(
    key: &SigningKey,
    request: &Request,
    status: u16,
    body: &[u8],
    head: Option<&str>,
) -> Response {
    let server_time = rfc3339(NOW);
    let sent = SentRequest::of(request);
    let signature = sign_response(
        key,
        &http::ResponseParts {
            status,
            request: sent.received(true),
            server_time: &server_time,
            head,
            body,
        },
    );
    let mut headers = vec![
        Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
        Header::new(header::SERVER_TIME, &server_time),
        Header::new("content-type", "application/json"),
    ];
    if let Some(head) = head {
        headers.push(Header::new(header::HEAD, head));
    }
    Response {
        status,
        headers,
        body: body.to_vec(),
    }
}

/// A switch that answers every request with `status` and `body`, signed with `key`.
fn fixed(key: SigningKey, status: u16, body: Value) -> Arc<MockTransport> {
    let bytes = body.to_string().into_bytes();
    Arc::new(MockTransport::with_handler(move |request| {
        Ok(respond(&key, request, status, &bytes))
    }))
}

/// The proofs a switch writes for the batch in `body`, each a `deny.put` or `allow.put`
/// chained after `seq` 4, signed with `key`, and the head after them.
fn proofs_for(key: &SigningKey, body: &[u8]) -> (Vec<SignedDoc>, SignedHead) {
    let request = OpsRequest::parse(body).unwrap();
    let account = identity().public();
    let mut tip = ChainTip {
        generation: 1,
        seq: 4,
        chain_hash: [9; 32],
    };
    let mut proofs = Vec::new();
    for signed in request.signed() {
        let op = SignedOp::peek(signed).unwrap();
        let (stub, next) = tip
            .append(
                tip.seq + 1,
                NOW,
                ItemType::Op,
                op.item_hash().unwrap(),
                Some(op.body().batch),
            )
            .unwrap();
        tip = next;
        let state = match &op.body().kind {
            OpKind::DenyPut { .. } => ProofState::Deny { denied: true },
            OpKind::AllowPut { kind, .. } => ProofState::Allow {
                kind: *kind,
                present: true,
            },
            _ => unreachable!("the tests write lists only"),
        };
        let object = op
            .body()
            .kind
            .proof_object(op.body().app_id.as_ref())
            .unwrap();
        let proof =
            TransitionProof::sign(key, &account, ProofBody::new(stub, object, &state)).unwrap();
        proofs.push(proof.signed().clone());
    }
    (proofs, SignedHead::sign(key, &account, &tip))
}

/// A switch that answers `POST /ops` with the batch's proofs, passed through `edit`.
fn ops_switch(edit: fn(&mut Vec<SignedDoc>)) -> Arc<MockTransport> {
    ops_switch_with(edit, |_| {})
}

/// [`ops_switch`], with the answer's body then passed through `edit_body`.
fn ops_switch_with(edit: fn(&mut Vec<SignedDoc>), edit_body: fn(&mut Value)) -> Arc<MockTransport> {
    let key = service_key();
    Arc::new(MockTransport::with_handler(move |request| {
        let (mut proofs, head) = proofs_for(&key, &request.body);
        edit(&mut proofs);
        let mut body = json!({ "proofs": proofs, "head": head.to_value() });
        edit_body(&mut body);
        Ok(respond(&key, request, 200, body.to_string().as_bytes()))
    }))
}

/// The two edits that leave out an answer's `proofs`: missing, and `null`.
const WITHOUT_PROOFS: [fn(&mut Value); 2] = [
    |body| {
        body.as_object_mut().unwrap().remove("proofs");
    },
    |body| body["proofs"] = Value::Null,
];

fn two_lists() -> Vec<(Vec<Condition>, OpKind)> {
    vec![
        (Vec::new(), OpKind::DenyPut { pubky: [7; 32] }),
        (
            Vec::new(),
            OpKind::AllowPut {
                pubky: [8; 32],
                kind: AllowKind::Contact,
            },
        ),
    ]
}

fn enrollment(nonce: [u8; 16]) -> Enrollment {
    Enrollment::sign(
        &identity(),
        EnrollmentBody {
            identity: identity().public(),
            origin: ORIGIN.into(),
            nonce,
            policy: IdentityPolicy::default(),
            identity_doc: None,
            revoked_apps: None,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn test_unpinned_client_sends_nothing() {
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(app(), None, Arc::clone(&transport));
    assert_eq!(client.allow().await.unwrap_err(), ClientError::Unpinned);
    let batch = client.sign_batch(1, two_lists(), None).unwrap();
    assert_eq!(
        client.submit(&batch).await.unwrap_err(),
        ClientError::Unpinned
    );
    let signed = client
        .sign_request("GET", "/v1/x/feed", Vec::new(), None)
        .unwrap();
    assert_eq!(
        client.send(signed).await.unwrap_err(),
        ClientError::Unpinned
    );
    assert!(transport.requests().is_empty(), "nothing went out");
}

#[tokio::test]
async fn test_unpinned_signer_enrolls_and_pins_the_answers_key() {
    let enrollment = enrollment([4; 16]);
    let answer = EnrollmentAnswer::new(&enrollment, service_public(), Limits::default());
    let body = answer.to_json().unwrap();
    let key = service_key();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        Ok(respond(&key, request, 200, &body))
    }));
    let client = client_with(signer(), None, Arc::clone(&transport));
    assert_eq!(client.enroll(&enrollment).await.unwrap(), answer);
    assert_eq!(client.pinned_key(), Some(service_public()));
    // The enrollment carries no Switch-App.
    let sent = transport.last_request().unwrap();
    assert_eq!(sent.path_and_query, "/v1/enroll");
    assert!(sent.header(header::APP).is_none());

    // A client that holds a key keeps it: the answer may name a pending key.
    let pending = SigningKey::from_bytes(&[6; 32]);
    let answer = EnrollmentAnswer::new(
        &enrollment,
        pending.verifying_key().to_bytes(),
        Limits::default(),
    );
    let body = answer.to_json().unwrap();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        Ok(respond(&pending, request, 200, &body))
    }));
    let client = client_with(signer(), Some(service_public()), transport);
    client.enroll(&enrollment).await.unwrap();
    assert_eq!(client.pinned_key(), Some(service_public()));
}

#[tokio::test]
async fn test_enrollment_answer_signed_by_another_key_is_refused() {
    let enrollment = enrollment([4; 16]);
    let answer = EnrollmentAnswer::new(&enrollment, service_public(), Limits::default());
    let other = SigningKey::from_bytes(&[6; 32]);
    let body = answer.to_json().unwrap();
    let forged = Arc::new(MockTransport::with_handler(move |request| {
        Ok(respond(&other, request, 200, &body))
    }));
    let client = client_with(signer(), None, forged);
    assert_eq!(
        client.enroll(&enrollment).await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
    assert_eq!(client.pinned_key(), None);
    // An operator-signed error before the account exists is unauthenticated.
    let client = client_with(
        signer(),
        None,
        fixed(
            service_key(),
            400,
            json!({ "code": "bad_request", "message": "m" }),
        ),
    );
    assert_eq!(
        client.enroll(&enrollment).await.unwrap_err(),
        ClientError::BadServiceSignature { status: 400 }
    );
}

#[tokio::test]
async fn test_enrollment_unreadable_signed_header_fails_authentication() {
    for pin in [None, Some(service_public())] {
        for status in [200, 503] {
            let transport = Arc::new(MockTransport::new());
            transport.push_error(TransportError::UnreadableSignedHeader { status });
            let client = client_with(signer(), pin, transport);
            assert_eq!(
                client.enroll(&enrollment([4; 16])).await.unwrap_err(),
                ClientError::BadServiceSignature { status }
            );
            assert_eq!(client.pinned_key(), pin);
        }
    }
}

#[tokio::test]
async fn test_enrollment_answer_for_another_enrollment_is_refused() {
    let sent = enrollment([4; 16]);
    let other = enrollment([5; 16]);
    let answer = EnrollmentAnswer::new(&other, service_public(), Limits::default());
    let transport = fixed(
        service_key(),
        200,
        serde_json::from_slice(&answer.to_json().unwrap()).unwrap(),
    );
    let client = client_with(signer(), None, transport);
    assert!(matches!(
        client.enroll(&sent).await.unwrap_err(),
        ClientError::Core(_)
    ));
    assert_eq!(client.pinned_key(), None);
    // Only the signer enrolls.
    let app_client = client_with(app(), None, fixed(service_key(), 200, json!({})));
    assert!(matches!(
        app_client.enroll(&sent).await.unwrap_err(),
        ClientError::Usage(_)
    ));
}

#[tokio::test]
async fn test_answer_checked_with_the_pinned_key() {
    let body = json!({ "pending": true, "known_version": 3 });
    let client = client_with(
        app(),
        Some(service_public()),
        fixed(service_key(), 200, body.clone()),
    );
    let answer = client.connect().await.unwrap();
    assert_eq!(answer.known_version, Some(3));

    // Pinned to another key, the same answer is refused.
    let client = client_with(app(), Some([3; 32]), fixed(service_key(), 200, body));
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
}

#[tokio::test]
async fn test_answer_with_a_bad_or_missing_signature_is_refused() {
    let key = service_key();
    let tampered = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(&key, request, 200, br#"{"pending":true}"#);
        response.body = br#"{"pending":false}"#.to_vec();
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), tampered);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
    let key = service_key();
    let unsigned = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(&key, request, 200, br#"{"pending":true}"#);
        response
            .headers
            .retain(|h| h.name != header::SERVICE_SIGNATURE);
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), unsigned);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
}

/// A request the client sent, as the response signature covers it.
fn sent_request(method: &str, path_and_query: &str, headers: &[(&str, &str)]) -> SentRequest {
    SentRequest::of(&Request {
        method: method.into(),
        origin: "https://switch.example".into(),
        path_and_query: path_and_query.into(),
        headers: headers
            .iter()
            .map(|(name, value)| Header::new(name, value))
            .collect(),
        body: Vec::new(),
        timeout: TimeoutClass::default(),
    })
}

/// The request the head tests' answers are checked against.
fn head_request() -> SentRequest {
    sent_request(
        "GET",
        &format!("/v1/{}/apps", pubky_id(&identity().public())),
        &[(header::SIGNATURE, &b64(&[9; 64]))],
    )
}

/// A `200` to [`head_request`] carrying `head`, signed with the service key.
fn head_response(head: &str) -> Response {
    let bytes = br#"{"pending":true}"#;
    let server_time = rfc3339(NOW);
    let sent = head_request();
    let signature = sign_response(
        &service_key(),
        &http::ResponseParts {
            status: 200,
            request: sent.received(true),
            server_time: &server_time,
            head: Some(head),
            body: bytes,
        },
    );
    Response {
        status: 200,
        headers: vec![
            Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
            Header::new(header::SERVER_TIME, &server_time),
            Header::new(header::HEAD, head),
        ],
        body: bytes.to_vec(),
    }
}

#[tokio::test]
async fn test_head_header_is_verified() {
    let account = identity().public();
    let tip = ChainTip {
        generation: 1,
        seq: 3,
        chain_hash: [2; 32],
    };
    let good = SignedHead::sign(&service_key(), &account, &tip);
    let key = service_key();
    let header_value = good.to_header();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        Ok(respond_with_head(
            &key,
            request,
            200,
            br#"{"pending":true}"#,
            Some(&header_value),
        ))
    }));
    let client = client_with(app(), Some(service_public()), transport);
    client.connect().await.unwrap();
    // The head is kept only when it verifies with the service key.
    let checked = check_response(
        &service_public(),
        &account,
        &head_request(),
        &head_response(&good.to_header()),
    );
    assert_eq!(checked.unwrap().head, Some(good));
}

#[tokio::test]
async fn test_head_header_that_fails_fails_the_response() {
    // A head the response signature covers but that doesn't verify as a head for the
    // account, or doesn't read, fails the response as a signature that doesn't verify, so
    // a head the client reads is always the account's (Switch wire 6.7, 7.1).
    let account = identity().public();
    let tip = ChainTip {
        generation: 1,
        seq: 3,
        chain_hash: [2; 32],
    };
    let forged = SignedHead::sign(&SigningKey::from_bytes(&[6; 32]), &account, &tip);
    for head in [forged.to_header(), "not a head".to_owned()] {
        let key = service_key();
        let header_value = head.clone();
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            Ok(respond_with_head(
                &key,
                request,
                200,
                br#"{"pending":true}"#,
                Some(&header_value),
            ))
        }));
        let client = client_with(app(), Some(service_public()), transport);
        assert_eq!(
            client.connect().await.unwrap_err(),
            ClientError::BadServiceSignature { status: 200 },
            "{head}"
        );
        assert_eq!(
            check_response(
                &service_public(),
                &account,
                &head_request(),
                &head_response(&head),
            )
            .unwrap_err(),
            ClientError::BadServiceSignature { status: 200 }
        );
    }
}

#[tokio::test]
async fn test_head_header_moved_or_added_fails_the_signature() {
    // The response signature covers the head field, so a head added, dropped or
    // changed on the way fails it (Switch wire 7.1).
    let account = identity().public();
    let tip = ChainTip {
        generation: 1,
        seq: 3,
        chain_hash: [2; 32],
    };
    let good = SignedHead::sign(&service_key(), &account, &tip);
    let key = service_key();
    let header_value = good.to_header();
    let added = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(&key, request, 200, br#"{"pending":true}"#);
        response
            .headers
            .push(Header::new(header::HEAD, &header_value));
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), added);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
    let mut dropped = head_response(&good.to_header());
    dropped.headers.retain(|h| h.name != header::HEAD);
    assert_eq!(
        check_response(&service_public(), &account, &head_request(), &dropped).unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
    // An empty head added to a headless answer fails it (Switch wire 7.1).
    let key = service_key();
    let emptied = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(
            &key,
            request,
            403,
            br#"{"code":"not_current","message":"m"}"#,
        );
        response.headers.push(Header::new(header::HEAD, ""));
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), emptied);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 403 }
    );
    // A request other than the one sent fails it too: another method, path, query, origin,
    // or a signed header added or sent twice.
    let response = head_response(&good.to_header());
    let path = format!("/v1/{}/apps", pubky_id(&identity().public()));
    let signature = b64(&[9; 64]);
    let twice = SentRequest::of(&Request {
        method: "GET".into(),
        origin: "https://switch.example".into(),
        path_and_query: path.clone(),
        headers: vec![
            Header::new(header::SIGNATURE, &signature),
            Header::new(header::SIGNATURE, &signature),
        ],
        body: Vec::new(),
        timeout: TimeoutClass::default(),
    });
    let other_origin = SentRequest::of(&Request {
        method: "GET".into(),
        origin: "https://other.example".into(),
        path_and_query: path.clone(),
        headers: vec![Header::new(header::SIGNATURE, &signature)],
        body: Vec::new(),
        timeout: TimeoutClass::default(),
    });
    for sent in [
        sent_request("POST", &path, &[(header::SIGNATURE, &signature)]),
        sent_request("get", &path, &[(header::SIGNATURE, &signature)]),
        sent_request(
            "GET",
            &format!("/v1/{}/apps", pubky_id(&[7; 32])),
            &[(header::SIGNATURE, &signature)],
        ),
        sent_request(
            "GET",
            &format!("{path}?x=1"),
            &[(header::SIGNATURE, &signature)],
        ),
        sent_request(
            "GET",
            &path,
            &[(header::SIGNATURE, &signature), (header::INVITE_CODE, "")],
        ),
        sent_request("GET", &path, &[]),
        twice,
        other_origin,
    ] {
        assert_eq!(
            check_response(&service_public(), &account, &sent, &response).unwrap_err(),
            ClientError::BadServiceSignature { status: 200 }
        );
    }
}

#[tokio::test]
async fn test_error_bodies_parse_for_every_code() {
    for code in ErrorCode::ALL {
        let mut body = json!({ "code": code.as_str(), "message": "m" });
        match code {
            ErrorCode::RateLimited => body["retry_after"] = json!(37),
            ErrorCode::IdentityNeeded => {
                body["current"] = json!({ "version": 2 });
                body["known_version"] = json!(2);
            }
            ErrorCode::Conflict => body["current"] = json!({ "server_time": "x" }),
            _ => {}
        }
        let client = client_with(
            app(),
            Some(service_public()),
            fixed(service_key(), code.status(), body),
        );
        let error = client.connect().await.unwrap_err();
        let ClientError::Switch {
            status,
            code: parsed,
            message,
            current,
            known_version,
            retry_after,
        } = &error
        else {
            panic!("{code}: {error:?}");
        };
        assert_eq!((*status, *parsed), (code.status(), code), "{code}");
        assert_eq!(message, "m");
        assert_eq!(error.retry(), Some(code.retry()), "{code}");
        assert_eq!(retry_after.is_some(), code == ErrorCode::RateLimited);
        assert_eq!(*known_version == Some(2), code == ErrorCode::IdentityNeeded);
        assert_eq!(
            current.is_null(),
            !matches!(code, ErrorCode::IdentityNeeded | ErrorCode::Conflict)
        );
    }
}

#[tokio::test]
async fn test_error_bodies_that_dont_read_are_refused() {
    for (status, body) in [
        (409, json!({ "code": "teapot", "message": "m" })),
        (400, json!({ "code": "stale_key", "message": "m" })),
        (409, json!({ "message": "m" })),
        (409, json!({ "code": "conflict" })),
    ] {
        let client = client_with(
            app(),
            Some(service_public()),
            fixed(service_key(), status, body),
        );
        assert!(
            matches!(
                client.connect().await.unwrap_err(),
                ClientError::InvalidResponse(_)
            ),
            "{status}"
        );
    }
}

#[tokio::test]
async fn test_batch_retry_resends_the_same_bytes() {
    let transport = ops_switch(|_| {});
    let clock = Arc::new(TestClock::new(NOW));
    let client = SwitchClient::new(
        ORIGIN,
        identity().public(),
        app(),
        Some(service_public()),
        Arc::clone(&transport) as Arc<dyn Transport>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .unwrap();
    let cursor = Position {
        generation: 1,
        seq: 4,
    };
    let batch = client.sign_batch(1, two_lists(), Some(cursor)).unwrap();
    let first = client.submit(&batch).await.unwrap();
    assert_eq!(first.proofs.len(), 2);
    clock.advance_ms(2_000);
    // Read back from its stored body, the batch is the same batch.
    let resumed = Batch::from_body(batch.body().to_vec()).unwrap();
    assert_eq!(resumed, batch);
    let second = client.submit(&resumed).await.unwrap();
    assert_eq!(second, first);
    let sent = transport.requests();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].body, sent[1].body, "the same body bytes");
    assert_eq!(sent[0].body, batch.body());
    assert_ne!(
        sent[0].header(header::SIGNATURE),
        sent[1].header(header::SIGNATURE),
        "a new request signature with a new timestamp"
    );
}

#[tokio::test]
async fn test_batch_answer_binding_refuses_missing_and_reordered_proofs() {
    let edits: [fn(&mut Vec<SignedDoc>); 4] = [
        |proofs| {
            proofs.pop();
        },
        |proofs| proofs.reverse(),
        |proofs| {
            let first = proofs[0].clone();
            proofs.push(first);
        },
        |proofs| proofs.clear(),
    ];
    for edit in edits {
        let client = client_with(app(), Some(service_public()), ops_switch(edit));
        let batch = client.sign_batch(1, two_lists(), None).unwrap();
        assert!(
            matches!(
                client.submit(&batch).await.unwrap_err(),
                ClientError::Chain(_)
            ),
            "an answer that doesn't bind the batch"
        );
    }
}

#[tokio::test]
async fn test_batch_answer_signed_by_another_key_is_refused() {
    let other = SigningKey::from_bytes(&[6; 32]);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        // The proofs and the head are another key's; the response is the pinned key's.
        let (proofs, head) = proofs_for(&other, &request.body);
        let body = json!({ "proofs": proofs, "head": head.to_value() });
        Ok(respond(
            &service_key(),
            request,
            200,
            body.to_string().as_bytes(),
        ))
    }));
    let client = client_with(app(), Some(service_public()), transport);
    let batch = client.sign_batch(1, two_lists(), None).unwrap();
    assert!(matches!(
        client.submit(&batch).await.unwrap_err(),
        ClientError::Chain(_)
    ));
}

#[tokio::test]
async fn test_cursor_only_batch_takes_no_proofs() {
    let client = client_with(app(), Some(service_public()), ops_switch(|_| {}));
    let batch = Batch::cursor_only(Position {
        generation: 1,
        seq: 9,
    });
    assert_eq!(batch.id(), None);
    let answer = client.submit(&batch).await.unwrap();
    assert!(answer.proofs.is_empty());
}

#[tokio::test]
async fn test_batch_answer_requires_proofs() {
    // A cursor-only batch is answered `{ "proofs": [], "head" }`, so a missing list would
    // read as that answer.
    let batch = Batch::cursor_only(Position {
        generation: 1,
        seq: 9,
    });
    for edit in WITHOUT_PROOFS {
        let switch = ops_switch_with(|_| {}, edit);
        let client = client_with(app(), Some(service_public()), switch);
        let error = client.submit(&batch).await.unwrap_err();
        assert!(
            matches!(error, ClientError::InvalidResponse(_)),
            "{error:?}"
        );
    }
}

#[test]
fn test_batch_refuses_too_many_entries() {
    let client = client_with(
        app(),
        Some(service_public()),
        fixed(service_key(), 200, json!({})),
    );
    let deny = |n: u8| (Vec::new(), OpKind::DenyPut { pubky: [n; 32] });
    assert!(
        client
            .sign_batch(1, (0..9).map(deny).collect(), None)
            .is_err()
    );
    let ops = client
        .sign_batch(1, (0..8).map(deny).collect(), None)
        .unwrap()
        .ops()
        .to_vec();
    // Eight operations and a cursor are nine entries.
    assert!(matches!(
        Batch::new(ops, Some(Position::default())),
        Err(ClientError::Usage(_))
    ));
    assert!(Batch::from_body(b"{\"ops\":[]}".to_vec()).is_err());
}

#[test]
fn test_requests_carry_the_cert_only_to_another_identity() {
    let transport = fixed(service_key(), 200, json!({}));
    let own = client_with(app(), Some(service_public()), Arc::clone(&transport));
    let request = own
        .sign_request("GET", "/v1/x/feed", Vec::new(), None)
        .unwrap();
    assert!(request.request.header(header::CERT).is_none());
    assert!(request.request.header(header::APP).is_some());

    let other = IdentityKey::from_secret([9; 32]);
    let foreign = SwitchClient::new(
        ORIGIN,
        other.public(),
        app(),
        Some(service_public()),
        transport,
        Arc::new(TestClock::new(NOW)),
    )
    .unwrap();
    assert!(foreign.is_foreign());
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    let request = foreign
        .sign_request("GET", "/v1/x/directory", Vec::new(), Some(code))
        .unwrap();
    let cert = request.request.header(header::CERT).unwrap();
    assert_eq!(cert, cert_of(&identity(), &app_keys()).signed().compact());
    assert_eq!(request.request.header(header::INVITE_CODE), Some(code));
    // An invite code that isn't a token isn't sent.
    assert!(matches!(
        foreign.sign_request("GET", "/v1/x/directory", Vec::new(), Some("a b")),
        Err(ClientError::Usage(_))
    ));
    // Operations are written only at the caller's own account.
    assert!(foreign.sign_batch(1, two_lists(), None).is_err());
}

#[test]
fn test_credentials_must_match_their_keys() {
    let transport: Arc<dyn Transport> = fixed(service_key(), 200, json!({}));
    let wrong_signer = Credentials::Signer {
        identity: [1; 32],
        key: Arc::new(identity()),
    };
    let new = |credentials| {
        SwitchClient::new(
            ORIGIN,
            identity().public(),
            credentials,
            None,
            Arc::clone(&transport),
            Arc::new(TestClock::new(NOW)),
        )
    };
    assert!(matches!(new(wrong_signer), Err(ClientError::Usage(_))));
    let wrong_app = Credentials::App {
        identity: identity().public(),
        keys: AppKeys::from_secrets([8; 32], [9; 32]),
        cert: cert_of(&identity(), &app_keys()),
    };
    assert!(matches!(new(wrong_app), Err(ClientError::Usage(_))));
    assert!(new(app()).is_ok());
    assert!(new(signer()).is_ok());
    assert!(new(signer_requests()).is_ok());
    let wrong_requests = Credentials::SignerRequests {
        identity: [1; 32],
        key: Arc::new(RequestsOnly(identity())),
    };
    assert!(matches!(new(wrong_requests), Err(ClientError::Usage(_))));
}

#[test]
fn test_signer_requests_credential_signs_a_request_that_verifies() {
    let transport = fixed(service_key(), 200, json!({}));
    let requests = client_with(
        signer_requests(),
        Some(service_public()),
        Arc::clone(&transport),
    );
    requests.signer_only().unwrap();
    let signed = requests
        .sign_request("GET", "/v1/x/apps", Vec::new(), None)
        .unwrap();
    let signature = signed.signature.unwrap();
    let target = http::RequestTarget {
        method: "GET",
        path_and_query: "/v1/x/apps",
        body: &[],
        origin: ORIGIN,
    };
    let headers = http::RequestHeaders {
        timestamp: pubky_switch_core::time::rfc3339_seconds(NOW),
        identity: pubky_id(&identity().public()),
        ..http::RequestHeaders::default()
    };
    http::verify_request(&identity().public(), &target, &headers, &signature).unwrap();
    // The same request, headers and signature as the signer's full credential gives.
    let full = client_with(signer(), Some(service_public()), transport);
    assert_eq!(
        full.sign_request("GET", "/v1/x/apps", Vec::new(), None)
            .unwrap(),
        signed
    );
}

#[test]
fn test_signer_requests_credential_signs_no_batch() {
    let transport = fixed(service_key(), 200, json!({}));
    let requests = client_with(signer_requests(), Some(service_public()), transport);
    let refused = requests.sign_batch(1, two_lists(), None).unwrap_err();
    assert!(
        matches!(&refused, ClientError::Usage(why) if why.contains("requests only")),
        "{refused:?}"
    );
}

#[test]
fn test_credentials_debug_shows_no_key() {
    let text = format!("{:?} {:?} {:?}", signer(), signer_requests(), app());
    assert!(text.contains(&pubky_id(&identity().public())), "{text}");
    for secret in [[1u8; 32], [2; 32], [3; 32]] {
        assert!(!text.contains(&b64(&secret)), "{text}");
        assert!(!text.contains(&format!("{secret:?}")), "{text}");
    }
}

/// A public-read answer holding the account's `identity.json`, naming `origin` and
/// `named` as its inbox, signed by `signing` as the switch signs it.
fn public_read_switch(origin: &str, named: [u8; 32], signing: SigningKey) -> Arc<MockTransport> {
    let body = IdentityBody::first(
        identity().public(),
        [0; 16],
        Inbox::new(origin, named),
        IdentityPolicy::default(),
    );
    let doc = IdentityDoc::sign(&identity(), body).unwrap();
    fixed(signing, 200, json!({ "identity": doc.signed() }))
}

#[tokio::test]
async fn test_public_read_unreadable_signed_header_fails_authentication() {
    for pin in [None, Some(service_public())] {
        for status in [200, 503] {
            let transport = Arc::new(MockTransport::new());
            transport.push_error(TransportError::UnreadableSignedHeader { status });
            let client = client_with(app(), pin, transport);
            assert_eq!(
                client.public_identity().await.unwrap_err(),
                ClientError::BadServiceSignature { status }
            );
            assert_eq!(client.pinned_key(), pin);
            assert_eq!(client.last_server_time(), None);
        }
    }
}

#[tokio::test]
async fn test_public_read_unpinned_pins_the_named_key() {
    let transport = public_read_switch(ORIGIN, service_public(), service_key());
    let client = client_with(app(), None, Arc::clone(&transport));
    let public = client.public_identity().await.unwrap();
    assert_eq!(public.identity.inbox().service_key, service_public());
    assert_eq!(client.pinned_key(), Some(service_public()));
    let sent = transport.last_request().unwrap();
    assert!(sent.headers.iter().all(|h| !h.name.starts_with("switch-")));
}

#[tokio::test]
async fn test_public_read_unpinned_refuses_what_it_cant_check() {
    let other = SigningKey::from_bytes(&[6; 32]);
    let cases = [
        // Signed with another key than the document names.
        public_read_switch(ORIGIN, service_public(), other.clone()),
        // A document naming another origin.
        public_read_switch("https://other.example", service_public(), service_key()),
        // An error answer: nothing names a key.
        fixed(
            service_key(),
            404,
            json!({ "code": "not_found", "message": "m" }),
        ),
    ];
    for transport in cases {
        let client = client_with(app(), None, Arc::clone(&transport));
        let error = client.public_identity().await.unwrap_err();
        assert!(
            matches!(error, ClientError::BadServiceSignature { .. }),
            "{error:?}"
        );
        assert_eq!(client.pinned_key(), None);
        assert_eq!(client.last_server_time(), None);
    }
}

/// A delivery of the account's `identity.json` naming `named` as its service key here.
fn delivery_naming(named: [u8; 32]) -> IdentityDelivery {
    let mut body = IdentityBody::first(
        identity().public(),
        [0; 16],
        Inbox::new(ORIGIN, named),
        IdentityPolicy::default(),
    );
    body.generation = 2;
    body.version = 2;
    IdentityDelivery {
        identity: IdentityDoc::sign(&identity(), body)
            .unwrap()
            .signed()
            .clone(),
        prev: Some([4; 32]),
    }
}

/// A switch that answers a delivery `200` with its proof, signed with `key`.
fn delivery_switch(key: SigningKey) -> Arc<MockTransport> {
    Arc::new(MockTransport::with_handler(move |request| {
        let delivery = IdentityDelivery::parse(&request.body).unwrap();
        let doc = IdentityDoc::verify(&delivery.identity, &identity().public()).unwrap();
        let tip = ChainTip {
            generation: 2,
            seq: 4,
            chain_hash: [9; 32],
        };
        let bytes = delivery.identity.doc_bytes().unwrap();
        let (stub, next) = tip
            .append(
                5,
                NOW,
                ItemType::Identity,
                item_hash(ItemType::Identity, &bytes),
                None,
            )
            .unwrap();
        let state = ProofState::Identity {
            version: doc.version(),
            generation: doc.generation(),
            data_epoch: doc.data_epoch(),
        };
        let account = identity().public();
        let proof = TransitionProof::sign(
            &key,
            &account,
            ProofBody::new(stub, "identity".into(), &state),
        )
        .unwrap();
        let head = SignedHead::sign(&key, &account, &next);
        let body = json!({ "proofs": [proof.signed()], "head": head.to_value() });
        Ok(respond(&key, request, 200, body.to_string().as_bytes()))
    }))
}

#[tokio::test]
async fn test_put_identity_starting_a_generation_pins_the_pending_key() {
    let pending = SigningKey::from_bytes(&[6; 32]);
    let pending_public = pending.verifying_key().to_bytes();
    let transport = delivery_switch(pending);
    let client = client_with(signer(), Some(service_public()), transport);
    let answer = client
        .put_identity(&delivery_naming(pending_public))
        .await
        .unwrap();
    assert_eq!(answer.proofs.len(), 1);
    assert_eq!(client.pinned_key(), Some(pending_public));
}

#[tokio::test]
async fn test_put_identity_starting_a_generation_keeps_the_pin_on_errors() {
    let pending = SigningKey::from_bytes(&[6; 32]);
    let pending_public = pending.verifying_key().to_bytes();
    // A refusal comes under the old key, and keeps its pin.
    let refusal = fixed(
        service_key(),
        409,
        json!({ "code": "conflict", "message": "m" }),
    );
    let client = client_with(signer(), Some(service_public()), refusal);
    let error = client
        .put_identity(&delivery_naming(pending_public))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    assert_eq!(client.pinned_key(), Some(service_public()));
    // A refusal signed with the pending key doesn't verify.
    let refusal = fixed(
        pending.clone(),
        409,
        json!({ "code": "conflict", "message": "m" }),
    );
    let client = client_with(signer(), Some(service_public()), refusal);
    let error = client
        .put_identity(&delivery_naming(pending_public))
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::BadServiceSignature { .. }));
    // A `200` signed with the old key doesn't verify either.
    let client = client_with(
        signer(),
        Some(service_public()),
        delivery_switch(service_key()),
    );
    let error = client
        .put_identity(&delivery_naming(pending_public))
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::BadServiceSignature { .. }));
    assert_eq!(client.pinned_key(), Some(service_public()));
}

/// A feed page holding `items`, with a head, as the client reads it.
fn feed_page_with(items: Value) -> Result<FeedPage, ClientError> {
    let head = SignedHead::sign(
        &service_key(),
        &identity().public(),
        &ChainTip {
            generation: 1,
            seq: 9,
            chain_hash: [9; 32],
        },
    );
    let value = json!({ "items": items, "next": "1:9", "scanned_through": 9, "more": false,
                        "cursor": 0, "head": head.to_value() });
    FeedPage::read(
        Obj::of(&value, "a feed page").unwrap(),
        &identity().public(),
    )
}

#[test]
fn test_feed_item_of_an_unknown_type_is_skipped_and_its_stub_kept() {
    let tip = ChainTip {
        generation: 1,
        seq: 4,
        chain_hash: [9; 32],
    };
    let (stub, _) = tip
        .append(5, NOW, ItemType::Service, [3; 32], None)
        .unwrap();
    let page = feed_page_with(json!([
        { "type": "later_kind", "seq": 5, "stub": stub.to_value(), "extra": 1 },
        { "type": "later_kind", "seq": 6 },
        { "type": "stub", "seq": 7, "stub": stub.to_value() },
    ]))
    .unwrap();
    assert_eq!(
        page.items,
        vec![
            FeedItem::Stub {
                seq: 5,
                stub: stub.clone()
            },
            FeedItem::Stub { seq: 7, stub },
        ]
    );
}

#[test]
fn test_feed_item_of_an_unknown_type_with_a_bad_stub_is_refused() {
    let items = json!([{ "type": "later_kind", "seq": 5, "stub": "not a stub" }]);
    let error = feed_page_with(items).unwrap_err();
    assert!(
        matches!(error, ClientError::InvalidResponse(_)),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_public_read_sends_no_switch_header() {
    let transport = fixed(
        service_key(),
        404,
        json!({ "code": "not_found", "message": "m" }),
    );
    let client = client_with(app(), Some(service_public()), Arc::clone(&transport));
    let error = client.public_identity().await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotFound));
    let sent = transport.last_request().unwrap();
    assert!(sent.headers.iter().all(|h| !h.name.starts_with("switch-")));
}

#[tokio::test]
async fn test_operator_signed_404_reads_as_unauthenticated() {
    // A key no client knows signs answers for accounts the service doesn't host.
    let operator = SigningKey::from_bytes(&[42; 32]);
    let client = client_with(
        signer(),
        Some(service_public()),
        fixed(
            operator,
            404,
            json!({ "code": "not_found", "message": "no such account" }),
        ),
    );
    assert_eq!(
        client.erase(None).await.unwrap_err(),
        ClientError::BadServiceSignature { status: 404 }
    );
}

#[tokio::test]
async fn test_signer_and_app_calls_refuse_the_other_caller() {
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(app(), Some(service_public()), Arc::clone(&transport));
    assert!(matches!(client.apps().await, Err(ClientError::Usage(_))));
    assert!(matches!(
        client.erase(None).await,
        Err(ClientError::Usage(_))
    ));
    let client = client_with(signer(), Some(service_public()), Arc::clone(&transport));
    assert!(matches!(client.keys().await, Err(ClientError::Usage(_))));
    assert!(matches!(client.leave().await, Err(ClientError::Usage(_))));
    assert!(matches!(
        client.export_chunk("../x").await,
        Err(ClientError::Usage(_))
    ));
    assert!(transport.requests().is_empty());
}

/// A switch that answers a leave with a proof naming `object`, or the caller's App ID.
fn leave_switch(object: Option<&'static str>) -> Arc<MockTransport> {
    leave_switch_with(object, |_| {})
}

/// [`leave_switch`], with the answer's body passed through `edit_body`.
fn leave_switch_with(
    object: Option<&'static str>,
    edit_body: fn(&mut Value),
) -> Arc<MockTransport> {
    let key = service_key();
    let account = identity().public();
    Arc::new(MockTransport::with_handler(move |request| {
        let tip = ChainTip {
            generation: 1,
            seq: 1,
            chain_hash: [0; 32],
        };
        let (stub, tip) = tip
            .append(2, NOW, ItemType::Service, [3; 32], None)
            .unwrap();
        // `/v1/{id}/apps/{app_id}/leave`
        let app = request.path_and_query.split('/').nth(4).unwrap().to_owned();
        let object = object.map_or(app, str::to_owned);
        let state = ProofState::Service(json!({ "type": "leave" }));
        let proof =
            TransitionProof::sign(&key, &account, ProofBody::new(stub, object, &state)).unwrap();
        let mut body = json!({
            "proofs": [proof.signed()],
            "head": SignedHead::sign(&key, &account, &tip).to_value(),
        });
        edit_body(&mut body);
        Ok(respond(&key, request, 200, body.to_string().as_bytes()))
    }))
}

#[tokio::test]
async fn test_write_answer_requires_proofs() {
    // A revoke of a revoked app is answered `{ "proofs": [], "head" }`, so a missing list
    // would read as a write that wrote nothing.
    for edit in WITHOUT_PROOFS {
        let client = client_with(app(), Some(service_public()), leave_switch_with(None, edit));
        let error = client.leave().await.unwrap_err();
        assert!(
            matches!(error, ClientError::InvalidResponse(_)),
            "{error:?}"
        );
    }
}

#[tokio::test]
async fn test_write_answer_proof_must_be_the_transition_written() {
    let client = client_with(app(), Some(service_public()), leave_switch(None));
    let answer = client.leave().await.unwrap();
    assert_eq!(answer.proofs.len(), 1);
    assert_eq!(answer.head.seq, 2);
    // A proof of another app's leave doesn't answer this one.
    let client = client_with(app(), Some(service_public()), leave_switch(Some("other")));
    assert!(matches!(
        client.leave().await.unwrap_err(),
        ClientError::Chain(_)
    ));
}

#[tokio::test]
async fn test_last_server_time_follows_checked_answers_only() {
    let transport = fixed(
        service_key(),
        200,
        json!({ "contacts": [], "conversations": [], "deny": [], "flagged": [],
                "invite_codes": [] }),
    );
    let client = client_with(app(), Some(service_public()), Arc::clone(&transport));
    assert_eq!(client.last_server_time(), None);
    client.allow().await.unwrap();
    assert_eq!(client.last_server_time(), Some(NOW));
    // An answer the pinned key didn't sign leaves the time as it was.
    let other = SigningKey::from_bytes(&[6; 32]);
    let forged = fixed(other, 200, json!({}));
    let client = client_with(app(), Some(service_public()), forged);
    assert!(client.allow().await.is_err());
    assert_eq!(client.last_server_time(), None);
    // A refusal answered before the request verified, without a head, carries no stamped
    // time (Switch wire 7.1).
    let early = fixed(
        service_key(),
        401,
        json!({ "code": "bad_signature", "message": "7.2" }),
    );
    let client = client_with(app(), Some(service_public()), early);
    assert!(client.allow().await.is_err());
    assert_eq!(client.last_server_time(), None);
    assert_eq!(client.latest_server_time(), None);
}

/// A batch of one shared record write.
fn record_write() -> Vec<(Vec<Condition>, OpKind)> {
    use pubky_switch_core::ident::{Policy, collection_id};
    use pubky_switch_core::ops::{RecordPut, RecordVersion};
    use pubky_switch_core::sealed::SealedValue;
    let identity = identity().public();
    let policy = Policy::new("sample", &["sample"]);
    let key = [2; 32];
    let put = RecordPut {
        key,
        collection: collection_id("sample.items", &identity),
        policy,
        expected_version: RecordVersion::new(1, 4),
        value_sealed: SealedValue::seal(&[3; 32], &identity, 1, "sample", &key, b"{}").unwrap(),
        id_inputs: None,
    };
    vec![(Vec::new(), OpKind::RecordPut(put))]
}

#[tokio::test]
async fn test_calls_pick_their_timeout_class() {
    // A switch whose answers don't read: every call fails, after its request went.
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(app(), Some(service_public()), Arc::clone(&transport));
    // The class of the `n`th request, which the call just made must have sent.
    let class = |n: usize| {
        let sent = transport.requests();
        assert_eq!(sent.len(), n, "the call sent no request");
        sent[n - 1].timeout
    };
    let feed = |limit, wait| answers::FeedQuery {
        after: None,
        limit,
        wait,
    };
    // A feed page with no items, the read of the service time, is small.
    let _ = client.feed(feed(Some(0), None)).await;
    assert_eq!(class(1), TimeoutClass::Ordinary);
    // A page is bulk, and a long poll carries its wait.
    let _ = client.feed(feed(Some(100), None)).await;
    assert_eq!(class(2), TimeoutClass::Bulk);
    let _ = client.feed(feed(None, Some(0))).await;
    assert_eq!(class(3), TimeoutClass::Bulk);
    let _ = client.feed(feed(Some(1), Some(25))).await;
    assert_eq!(class(4), TimeoutClass::LongPoll { wait_s: 25 });
    // Listings, a record's view and an append are bulk.
    let _ = client.directory(None).await;
    assert_eq!(class(5), TimeoutClass::Bulk);
    let _ = client.allow().await;
    assert_eq!(class(6), TimeoutClass::Bulk);
    let _ = client.record(&[1; 32]).await;
    assert_eq!(class(7), TimeoutClass::Bulk);
    let _ = client.claim(&[1; 32]).await;
    assert_eq!(class(8), TimeoutClass::Bulk);
    let _ = client.append(vec![0; 16], 1, None).await;
    assert_eq!(class(9), TimeoutClass::Bulk);
    // A small write and the public read are ordinary.
    let _ = client.connect().await;
    assert_eq!(class(10), TimeoutClass::Ordinary);
    let _ = client.public_identity().await;
    assert_eq!(class(11), TimeoutClass::Ordinary);
    // A batch that writes no shared record is ordinary.
    let lists = client.sign_batch(1, two_lists(), None).unwrap();
    let _ = client.submit(&lists).await;
    assert_eq!(class(12), TimeoutClass::Ordinary);
    // One that writes a shared record is bulk, on its first send and read back from its
    // kept body for a resend: its refusal can carry the record's view.
    let record = client.sign_batch(1, record_write(), None).unwrap();
    let _ = client.submit(&record).await;
    assert_eq!(class(13), TimeoutClass::Bulk);
    let kept = Batch::from_body(record.body().to_vec()).unwrap();
    let _ = client.submit(&kept).await;
    assert_eq!(class(14), TimeoutClass::Bulk);
    // A request signed for the caller to send is ordinary until the caller says otherwise.
    let signed = client
        .sign_request("GET", "/v1/x/feed", Vec::new(), None)
        .unwrap();
    assert_eq!(signed.request.timeout, TimeoutClass::Ordinary);
}

/// A response to `request` signed with `key` over the empty body field, as the service
/// signs an answer it gives before it reads the body (Switch wire 7.1).
fn respond_unread(
    key: &SigningKey,
    request: &Request,
    status: u16,
    body: &[u8],
    head: Option<&str>,
) -> Response {
    let mut response = respond_with_head(key, request, status, body, head);
    let server_time = rfc3339(NOW);
    let signature = sign_response(
        key,
        &http::ResponseParts {
            status,
            request: SentRequest::of(request).received(false),
            server_time: &server_time,
            head,
            body,
        },
    );
    for header in &mut response.headers {
        if header.name == header::SERVICE_SIGNATURE {
            header.value = b64(&signature);
        }
    }
    response
}

#[tokio::test]
async fn test_response_before_the_body_is_read_is_final_for_nothing() {
    // A `413`, a `429` and a `404` that verify only with the empty body field may answer a
    // request whose length was changed on the way: verified, but final for nothing (Switch
    // wire 7.1).
    for (status, code) in [
        (413, ErrorCode::TooLarge),
        (429, ErrorCode::RateLimited),
        (404, ErrorCode::NotFound),
    ] {
        let body = json!({ "code": code.as_str(), "message": "m", "retry_after": 5 })
            .to_string()
            .into_bytes();
        let key = service_key();
        let unread = body.clone();
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            Ok(respond_unread(&key, request, status, &unread, None))
        }));
        let client = client_with(app(), Some(service_public()), transport);
        let error = client.connect().await.unwrap_err();
        assert_eq!(
            error,
            ClientError::BodyUnread {
                status,
                code,
                retry_after: Some(5),
            }
        );
        assert_eq!(error.code(), None);
        assert_eq!(error.retry(), None);
        // Signed over the body, the same answer is the service's refusal of these bytes.
        let key = service_key();
        let read = body.clone();
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            Ok(respond(&key, request, status, &read))
        }));
        let client = client_with(app(), Some(service_public()), transport);
        assert_eq!(client.connect().await.unwrap_err().code(), Some(code));
    }
}

#[tokio::test]
async fn test_response_with_the_empty_body_field_fails_unless_before_the_body() {
    // Any other answer that verifies only with the empty body field, a `200` above all,
    // fails as a signature that doesn't verify, and so does one of those three with a head
    // (Switch wire 7.1).
    let account = identity().public();
    let tip = ChainTip {
        generation: 1,
        seq: 3,
        chain_hash: [2; 32],
    };
    let head = SignedHead::sign(&service_key(), &account, &tip).to_header();
    for (status, body, head) in [
        (200, json!({ "pending": true }), None),
        (
            401,
            json!({ "code": "bad_signature", "message": "m" }),
            None,
        ),
        (403, json!({ "code": "not_current", "message": "m" }), None),
        (
            413,
            json!({ "code": "too_large", "message": "m" }),
            Some(head.clone()),
        ),
        (
            404,
            json!({ "code": "not_found", "message": "m" }),
            Some(head.clone()),
        ),
    ] {
        let key = service_key();
        let bytes = body.to_string().into_bytes();
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            Ok(respond_unread(
                &key,
                request,
                status,
                &bytes,
                head.as_deref(),
            ))
        }));
        let client = client_with(app(), Some(service_public()), transport);
        assert_eq!(
            client.connect().await.unwrap_err(),
            ClientError::BadServiceSignature { status },
            "{status}"
        );
    }
}

#[tokio::test]
async fn test_response_with_a_repeated_signed_header_fails() {
    // `Switch-Service-Signature`, `Switch-Server-Time` and `Switch-Head` each come once
    // (Switch wire 7.1).
    let account = identity().public();
    let tip = ChainTip {
        generation: 1,
        seq: 3,
        chain_hash: [2; 32],
    };
    let head = SignedHead::sign(&service_key(), &account, &tip).to_header();
    let good = head_response(&head);
    assert!(check_response(&service_public(), &account, &head_request(), &good).is_ok());
    for name in [header::SERVICE_SIGNATURE, header::SERVER_TIME, header::HEAD] {
        let mut repeated = good.clone();
        let copy = repeated
            .headers
            .iter()
            .find(|h| h.name == name)
            .unwrap()
            .clone();
        repeated
            .headers
            .push(Header::new(&name.to_uppercase(), &copy.value));
        assert_eq!(
            check_response(&service_public(), &account, &head_request(), &repeated).unwrap_err(),
            ClientError::BadServiceSignature { status: 200 },
            "{name}"
        );
    }
    // A head sent twice on a headless answer fails it too, rather than reading as no head.
    let key = service_key();
    let doubled = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(&key, request, 200, br#"{"pending":true}"#);
        response.headers.push(Header::new(header::HEAD, &head));
        response.headers.push(Header::new(header::HEAD, &head));
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), doubled);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
}

#[tokio::test]
async fn test_response_replayed_as_the_answer_to_another_call_fails() {
    // A verified answer to one call, sent back as the answer to another, or to the same
    // call signed a second later, fails: it binds the request it answered (Switch wire 7.1).
    let key = service_key();
    let recorded: Arc<std::sync::Mutex<Option<Response>>> = Arc::default();
    let held = recorded.clone();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        let mut held = held.lock().unwrap();
        Ok(held
            .get_or_insert_with(|| respond(&key, request, 200, br#"{"pending":true}"#))
            .clone())
    }));
    let clock = Arc::new(TestClock::new(NOW));
    let client = SwitchClient::new(
        ORIGIN,
        identity().public(),
        app(),
        Some(service_public()),
        transport,
        clock.clone(),
    )
    .unwrap();
    client.connect().await.unwrap();
    // The same call within the same second is the same request (Switch wire 7.1).
    client.connect().await.unwrap();
    assert!(matches!(
        client.connect_requests().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    ));
    clock.advance_ms(1_000);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
    assert!(recorded.lock().unwrap().is_some());
}

#[tokio::test]
async fn test_body_over_its_cap_is_never_sent() {
    // A body over its call's cap is refused before it is sent, for good: the service would
    // answer it before reading it, an answer final for nothing (Switch wire 7.1 Body caps).
    let transport = Arc::new(MockTransport::new());
    let client = client_with(app(), Some(service_public()), transport.clone());
    assert_eq!(
        client.append(vec![0; 65_537], 1, None).await.unwrap_err(),
        ClientError::BodyOverCap { cap: 65_536 }
    );
    assert!(transport.last_request().is_none(), "nothing was sent");
}
