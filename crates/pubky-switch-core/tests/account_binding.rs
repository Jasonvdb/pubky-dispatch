//! Account-bound request bytes, authenticated observations and strict enrollment intents.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use http::{
    BodyField, ReceivedHeaders, ReceivedRequest, RequestHeaders, RequestTarget, ResponseParts,
};
use pubky_switch_core::{enc, http, json, keys::IdentityKey, labels, records::*, time};

const ORIGIN: &str = "https://inbox.example";
const NOW: u64 = 1_767_225_600_123;

fn identity() -> IdentityKey {
    IdentityKey::from_secret([4; 32])
}
fn service() -> IdentityKey {
    IdentityKey::from_secret([7; 32])
}
fn path() -> String {
    format!("/v1/{}/account", identity().id())
}
fn headers() -> RequestHeaders {
    RequestHeaders {
        timestamp: "2020-01-01T00:00:00Z".into(),
        identity: identity().id(),
        app: None,
        cert: None,
        invite_code: None,
        created: None,
    }
}
fn body(created: Option<u64>) -> AccountObservationBody {
    AccountObservationBody {
        identity: identity().public(),
        origin: ORIGIN.into(),
        service_key: service().public(),
        store_id: [9; 16],
        association: if created.is_some() {
            AccountAssociation::Mark
        } else {
            AccountAssociation::Absent
        },
        created,
        erased_at: Some(NOW - 1000),
        observed_at: NOW,
        expires_at: NOW + ACCOUNT_OBSERVATION_VALIDITY_MS,
    }
}
fn response_signature(
    carried: &CarriedAccountObservation,
    status: u16,
    head: Option<&str>,
    path: &str,
    field: BodyField,
) -> [u8; 64] {
    let value: serde_json::Value = json::parse_json(&carried.body).unwrap();
    let origin = value["origin"].as_str().unwrap();
    let identity = identity().id();
    let signature = enc::b64(&carried.request_signature);
    let received = ReceivedHeaders::of([
        (http::header::IDENTITY, identity.as_bytes()),
        (
            http::header::TIMESTAMP,
            carried.request_timestamp.as_bytes(),
        ),
        (http::header::SIGNATURE, signature.as_bytes()),
    ]);
    http::sign_response(
        &service(),
        &ResponseParts {
            status,
            request: ReceivedRequest {
                method: "GET",
                path_and_query: path,
                body: field,
                origin,
                headers: &received,
            },
            server_time: &time::rfc3339(NOW),
            head,
            body: &carried.body,
        },
    )
}
fn carried(body: AccountObservationBody) -> CarriedAccountObservation {
    let headers = headers();
    let signature = http::sign_request(
        &identity(),
        &RequestTarget {
            method: "GET",
            path_and_query: &path(),
            body: &[],
            origin: &body.origin,
        },
        &headers,
    );
    let mut carried = CarriedAccountObservation {
        body: body.to_json().unwrap(),
        sig: [0; 64],
        request_timestamp: headers.timestamp,
        request_signature: signature,
    };
    carried.sig = response_signature(&carried, 200, None, &path(), BodyField::read(&[]));
    carried
}
fn enrollment(intent: EnrollmentIntent) -> EnrollmentBody {
    EnrollmentBody {
        identity: identity().public(),
        origin: ORIGIN.into(),
        nonce: [8; 16],
        intent,
        policy: IdentityPolicy::default(),
        identity_doc: None,
        revoked_apps: None,
    }
}

fn longest_origin() -> String {
    format!(
        "https://{}.{}.{}.{}:65535",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    )
}

fn resign_response(carried: &mut CarriedAccountObservation) {
    carried.sig = response_signature(carried, 200, None, &path(), BodyField::read(&[]));
}

#[test]
fn test_account_association_is_required_and_consistent() {
    let original = carried(body(None));
    let value: serde_json::Value = json::parse_json(&original.body).unwrap();
    for association in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!("other")),
        Some(serde_json::json!("account")),
        Some(serde_json::json!("mark")),
    ] {
        let mut value = value.clone();
        value.as_object_mut().unwrap().remove("association");
        if let Some(association) = association {
            value["association"] = association;
        }
        let mut changed = original.clone();
        changed.body = serde_json::to_vec(&value).unwrap();
        resign_response(&mut changed);
        assert!(matches!(
            changed.verify(&identity().public(), ORIGIN),
            Err(pubky_switch_core::Error::Invalid(_))
        ));
    }
    let mut value = value;
    value["created"] = serde_json::json!(time::rfc3339(NOW - 500));
    let mut changed = original;
    changed.body = serde_json::to_vec(&value).unwrap();
    resign_response(&mut changed);
    assert!(matches!(
        changed.verify(&identity().public(), ORIGIN),
        Err(pubky_switch_core::Error::Invalid(_))
    ));
}

#[test]
fn test_account_association_selects_existing_account() {
    let mut value = body(Some(NOW - 500));
    value.association = AccountAssociation::Account;
    let observation = carried(value).verify(&identity().public(), ORIGIN).unwrap();
    assert_eq!(
        observation.enrollment_intent().unwrap(),
        EnrollmentIntent::Existing { created: NOW - 500 }
    );
}

#[test]
fn test_account_association_selects_mark_takeover() {
    let carried = carried(body(Some(NOW - 500)));
    let observation = carried.verify(&identity().public(), ORIGIN).unwrap();
    assert_eq!(
        observation.enrollment_intent().unwrap(),
        EnrollmentIntent::Takeover {
            created: NOW - 500,
            observation: carried
        }
    );
}

#[test]
fn test_account_association_selects_absent_creation() {
    let carried = carried(body(None));
    let observation = carried.verify(&identity().public(), ORIGIN).unwrap();
    assert_eq!(
        observation.enrollment_intent().unwrap(),
        EnrollmentIntent::Create {
            observation: carried
        }
    );
}

#[test]
fn test_account_association_takeover_requires_mark_evidence() {
    let mut value = body(Some(NOW - 500));
    value.association = AccountAssociation::Account;
    let intent = EnrollmentIntent::Takeover {
        created: NOW - 500,
        observation: carried(value),
    };
    let signed = identity().sign_doc(
        labels::sig::ENROLL,
        &[],
        enrollment(intent).to_json().unwrap(),
    );
    assert!(matches!(
        Enrollment::verify(&signed, &identity().public(), ORIGIN),
        Err(pubky_switch_core::Error::Invalid(_))
    ));
}

#[test]
fn test_account_observation_exact_body_limit() {
    let mut carried = carried(body(None));
    carried.body.resize(MAX_ACCOUNT_OBSERVATION_BYTES, b' ');
    resign_response(&mut carried);
    let checked = carried.verify(&identity().public(), ORIGIN).unwrap();
    assert_eq!(checked.carried(), &carried);
    let mut excess = carried;
    excess.body.push(b' ');
    resign_response(&mut excess);
    assert!(matches!(
        excess.verify(&identity().public(), ORIGIN),
        Err(pubky_switch_core::Error::Invalid(_))
    ));
}

#[test]
fn test_account_observation_carried_decode_bounds_encoded_body() {
    let mut carried = carried(body(None));
    carried.body.resize(MAX_ACCOUNT_OBSERVATION_BYTES, b' ');
    resign_response(&mut carried);
    let bytes = serde_json::to_vec(&carried).unwrap();
    assert_eq!(
        json::parse_json::<CarriedAccountObservation>(&bytes).unwrap(),
        carried
    );
    let mut excess = serde_json::to_value(&carried).unwrap();
    // Malformed base64 beyond the bound must be refused by length, before decoding.
    excess["body"] = serde_json::json!("!".repeat(1367));
    let bytes = serde_json::to_vec(&excess).unwrap();
    assert!(json::parse_json::<CarriedAccountObservation>(&bytes).is_err());
    let error = serde_json::from_slice::<CarriedAccountObservation>(&bytes).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("discovery body exceeds its byte limit"),
        "{error}"
    );
}

#[test]
fn test_account_observation_carried_writer_refuses_excess() {
    let mut carried = carried(body(None));
    carried.body.resize(MAX_ACCOUNT_OBSERVATION_BYTES + 1, b' ');
    resign_response(&mut carried);
    assert!(serde_json::to_vec(&carried).is_err());
}

#[test]
fn test_account_observation_response_cap_is_shared_with_classification() {
    for path in [path(), format!("{}?extra=1", path())] {
        assert_eq!(
            http::response_body_cap("GET", &path, 200),
            Some(MAX_ACCOUNT_OBSERVATION_BYTES)
        );
        assert_eq!(
            http::uncompared("GET", &path, BodyField::read(&[]), 200, None, None, false),
            Some(http::Uncompared::AccountDiscovery)
        );
        for status in [201, 400, 404, 409, 503] {
            assert_eq!(http::response_body_cap("GET", &path, status), None);
        }
    }
    for (method, path) in [
        ("POST", path()),
        ("GET", "/v1//account".into()),
        ("GET", "/v1/id/account/".into()),
        ("GET", "/other/id/account".into()),
        ("GET", "/v1/id/identity".into()),
        ("GET", "//v1/id/account".into()),
    ] {
        assert_eq!(http::response_body_cap(method, &path, 200), None);
    }
}

#[test]
fn test_account_origin_domain_and_total_bounds() {
    use pubky_switch_core::net::{MAX_DOMAIN_LEN, MAX_ORIGIN_LEN, UrlUse, check_url};
    let origin = longest_origin();
    assert_eq!(origin.len(), MAX_ORIGIN_LEN);
    assert!(is_origin(&origin));
    check_url(
        &origin,
        &UrlUse::SwitchOrigin {
            extra_ports: vec![65535],
        },
    )
    .unwrap();
    let mut value = body(Some(NOW - 500));
    value.association = AccountAssociation::Account;
    value.origin = origin.clone();
    assert_eq!(value.to_json().unwrap().len(), 659);
    carried(value)
        .verify(&identity().public(), &origin)
        .unwrap();
    let excess_domain = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    assert_eq!(excess_domain.len(), MAX_DOMAIN_LEN + 1);
    assert!(!is_origin(&format!("https://{excess_domain}")));
    assert!(!is_origin(&format!("https://{excess_domain}:65535")));
}

#[test]
fn test_account_origin_label_bound() {
    let maximum = format!("https://{}.example", "a".repeat(63));
    assert!(is_origin(&maximum));
    let excess = format!("https://{}.example", "a".repeat(64));
    assert!(!is_origin(&excess));
    let mut value = body(None);
    value.origin = excess;
    assert!(value.to_json().is_err());
}

fn enrollment_with_body_bytes(bytes: usize) -> EnrollmentBody {
    let mut body = enrollment(EnrollmentIntent::Existing { created: NOW - 500 });
    body.revoked_apps = Some(vec![[0; 16]]);
    let first = body.to_json().unwrap().len();
    let count = 1 + (bytes - first) / 29;
    let mut revoked: Vec<_> = (0..count).map(|n| (n as u128).to_be_bytes()).collect();
    revoked.sort_by_cached_key(|id| enc::zbase32_encode(id));
    body.revoked_apps = Some(revoked);
    let extra = bytes - body.to_json().unwrap().len();
    body.origin = format!("https://{}inbox.example", "a".repeat(extra));
    assert_eq!(body.to_json().unwrap().len(), bytes);
    body
}

#[test]
fn test_enrollment_signing_bounds_complete_envelope() {
    let boundary = enrollment_with_body_bytes(196_517);
    let signed = Enrollment::sign(&identity(), boundary).unwrap();
    let request = signed.to_request_json().unwrap();
    assert_eq!(request.len(), MAX_ENROLLMENT_BYTES);
    Enrollment::from_request(&request, &identity().public(), &signed.body().origin).unwrap();
    let excess = enrollment_with_body_bytes(196_518);
    assert!(matches!(
        Enrollment::sign(&identity(), excess),
        Err(pubky_switch_core::Error::Invalid(_))
    ));
}

#[test]
fn test_enrollment_signed_reader_bounds_complete_envelope() {
    let boundary = enrollment_with_body_bytes(196_517);
    let signed = identity().sign_doc(labels::sig::ENROLL, &[], boundary.to_json().unwrap());
    Enrollment::verify(&signed, &identity().public(), &boundary.origin).unwrap();
    let body = enrollment_with_body_bytes(196_518);
    let signed = identity().sign_doc(labels::sig::ENROLL, &[], body.to_json().unwrap());
    assert!(matches!(
        Enrollment::verify(&signed, &identity().public(), &body.origin),
        Err(pubky_switch_core::Error::Invalid(_))
    ));
}

#[test]
fn test_enrollment_request_reader_counts_outer_whitespace() {
    let signed = Enrollment::sign(
        &identity(),
        enrollment(EnrollmentIntent::Existing { created: NOW - 500 }),
    )
    .unwrap();
    let mut bytes = signed.to_request_json().unwrap();
    bytes.resize(MAX_ENROLLMENT_BYTES, b' ');
    assert_eq!(
        Enrollment::from_request(&bytes, &identity().public(), ORIGIN)
            .unwrap()
            .signed(),
        signed.signed()
    );
    bytes.push(b' ');
    assert!(matches!(
        Enrollment::from_request(&bytes, &identity().public(), ORIGIN),
        Err(pubky_switch_core::Error::Invalid(_))
    ));
}

#[test]
fn test_enrollment_request_size_matches_real_wrapper_rounding() {
    for len in [0, 1, 2, 3, 4, 5, 196_516, 196_517, 196_518] {
        let signed = identity().sign_doc(labels::sig::ENROLL, &[], vec![b' '; len]);
        let actual = serde_json::to_vec(&serde_json::json!({"enrollment":signed})).unwrap();
        assert_eq!(enrollment_request_len(len).unwrap(), actual.len());
    }
    assert!(enrollment_request_len(usize::MAX).is_err());
}

#[test]
fn test_enrollment_future_bound_uses_maximum_real_intent() {
    let origin = longest_origin();
    let mut value = body(Some(NOW - 500));
    value.origin = origin.clone();
    let mut carried = carried(value);
    carried.body.resize(MAX_ACCOUNT_OBSERVATION_BYTES, b' ');
    resign_response(&mut carried);
    carried.verify(&identity().public(), &origin).unwrap();
    assert_eq!(
        serde_json::to_vec(&carried).unwrap().len(),
        MAX_CARRIED_ACCOUNT_OBSERVATION_BYTES
    );
    let intent = EnrollmentIntent::Takeover {
        created: NOW - 500,
        observation: carried,
    };
    assert_eq!(
        serde_json::to_vec(&intent).unwrap().len(),
        MAX_ENROLLMENT_INTENT_BYTES
    );
    assert_eq!(MAX_ENROLLMENT_INTENT_BYTES, 1695);
    let document = IdentityDoc::sign(
        &identity(),
        IdentityBody::first(
            identity().public(),
            [5; 16],
            Inbox::new(&origin, service().public()),
            IdentityPolicy::default(),
        ),
    )
    .unwrap();
    for (doc, revoked) in [
        (None, vec![]),
        (Some(document.signed().clone()), vec![[3; 16], [4; 16]]),
    ] {
        let mut body = enrollment(intent.clone());
        body.origin = origin.clone();
        body.identity_doc = doc;
        body.revoked_apps = (!revoked.is_empty()).then_some(revoked.clone());
        let bound = Enrollment::max_request_len(&body.policy, body.identity_doc.as_ref(), &revoked)
            .unwrap();
        let signed = Enrollment::sign(&identity(), body).unwrap();
        assert_eq!(bound, signed.to_request_json().unwrap().len());
    }
}

#[test]
fn test_account_binding_request_creation_is_signed_last() {
    let mut headers = headers();
    headers.created = Some(time::rfc3339(NOW));
    let path = format!("/v1/{}/identity", identity().id());
    let target = RequestTarget {
        method: "PUT",
        path_and_query: &path,
        body: b"{}",
        origin: ORIGIN,
    };
    let fields = http::request_fields(&target, &headers);
    assert_eq!(fields.len(), 10);
    assert_eq!(
        fields.last().unwrap(),
        headers.created.as_ref().unwrap().as_bytes()
    );
    let sig = http::sign_request(&identity(), &target, &headers);
    http::verify_request(&identity().public(), &target, &headers, &sig).unwrap();
    for created in [None, Some(time::rfc3339(NOW + 1))] {
        let other = RequestHeaders {
            created,
            ..headers.clone()
        };
        assert!(http::verify_request(&identity().public(), &target, &other, &sig).is_err());
    }
}

#[test]
fn test_account_binding_received_creation_preserves_presence() {
    let variants: Vec<Vec<&[u8]>> = vec![
        vec![],
        vec![b""],
        vec![b"one"],
        vec![b"one", b"two"],
        vec![b"two", b"one"],
        vec![b"\xff"],
    ];
    let mut encodings = Vec::new();
    for values in variants {
        let received = ReceivedHeaders::of(values.iter().map(|value| ("SwItCh-CrEaTeD", *value)));
        assert_eq!(
            received.values(http::header::CREATED),
            values.iter().map(|v| v.to_vec()).collect::<Vec<_>>()
        );
        let request = ReceivedRequest {
            method: "POST",
            path_and_query: "/v1/id/ops",
            body: BodyField::read(&[]),
            origin: ORIGIN,
            headers: &received,
        };
        let encoded = http::received_request(&request);
        let fields = enc::split_lp(&encoded).unwrap();
        assert_eq!(fields.len(), 12);
        assert_eq!(
            fields.last().unwrap(),
            &if values.is_empty() {
                vec![]
            } else {
                enc::lp(&values)
            }
        );
        assert!(!encodings.contains(&encoded));
        encodings.push(encoded);
        let public = http::received_request(&ReceivedRequest {
            method: "GET",
            path_and_query: "/v1/id/identity",
            ..request
        });
        assert!(
            enc::split_lp(&public).unwrap()[4..]
                .iter()
                .all(Vec::is_empty)
        );
        assert_eq!(
            received.broken_rule().is_some(),
            values.len() > 1 || values.iter().any(|v| v.is_empty() || !v.is_ascii())
        );
    }
}

#[test]
fn test_account_binding_creation_time_is_exact() {
    let good = time::rfc3339(NOW);
    assert_eq!(http::parse_created(&good).unwrap(), NOW);
    for bad in [
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00.1Z",
        "2026-01-01T00:00:00.1230Z",
        "2026-01-01T00:00:00.123+00:00",
    ] {
        assert!(http::parse_created(bad).is_err(), "{bad}");
    }
}

#[test]
fn test_account_binding_observation_keeps_exact_bytes_and_time() {
    let mut carried = carried(body(None));
    carried.body = [b" \n".as_slice(), &carried.body, b"\n"].concat();
    carried.sig = response_signature(&carried, 200, None, &path(), BodyField::read(&[]));
    let checked = carried.verify(&identity().public(), ORIGIN).unwrap();
    assert_eq!(checked.carried(), &carried);
    assert_eq!(checked.body(), &body(None));
    assert_eq!(checked.validity(NOW - 1), ObservationValidity::Future);
    assert_eq!(checked.validity(NOW), ObservationValidity::Current);
    assert_eq!(
        checked.validity(NOW + 299_999),
        ObservationValidity::Current
    );
    assert_eq!(
        checked.validity(NOW + 300_000),
        ObservationValidity::Expired
    );
    assert_eq!(
        checked.validity(NOW + 300_001),
        ObservationValidity::Expired
    );
    // The old HTTP timestamp is original authenticated context, not a new wrapper time.
    assert_eq!(checked.carried().request_timestamp, "2020-01-01T00:00:00Z");
}

#[test]
fn test_account_binding_observation_requires_original_request() {
    let original = carried(body(None));
    original.verify(&identity().public(), ORIGIN).unwrap();
    let mut other = original.clone();
    other.request_timestamp = "2020-01-01T00:00:01Z".into();
    // Re-sign the response only: the changed original request still has to authenticate.
    other.sig = response_signature(&other, 200, None, &path(), BodyField::read(&[]));
    assert!(matches!(
        other.verify(&identity().public(), ORIGIN),
        Err(pubky_switch_core::Error::Signature(_))
    ));
    let mut changed = original.clone();
    changed.request_timestamp = "2020-01-01T00:00:00.000Z".into();
    assert!(changed.verify(&identity().public(), ORIGIN).is_err());
    assert!(original.verify(&service().public(), ORIGIN).is_err());
    assert!(
        original
            .verify(&identity().public(), "https://other.example")
            .is_err()
    );
}

#[test]
fn test_account_binding_observation_requires_exact_response_context() {
    let original = carried(body(None));
    original.verify(&identity().public(), ORIGIN).unwrap();
    for (status, head, route, field) in [
        (201, None, path(), BodyField::read(&[])),
        (200, Some(""), path(), BodyField::read(&[])),
        (200, Some("head"), path(), BodyField::read(&[])),
        (
            200,
            None,
            format!("{}?read=1", path()),
            BodyField::read(&[]),
        ),
        (200, None, path(), BodyField::NotRead),
    ] {
        let mut other = original.clone();
        other.sig = response_signature(&other, status, head, &route, field);
        assert!(matches!(
            other.verify(&identity().public(), ORIGIN),
            Err(pubky_switch_core::Error::Signature(_))
        ));
    }
    let mut changed = original;
    changed.body.push(b' ');
    assert!(matches!(
        changed.verify(&identity().public(), ORIGIN),
        Err(pubky_switch_core::Error::Signature(_))
    ));
}

#[test]
fn test_account_binding_observation_body_is_strict() {
    let original: serde_json::Value = json::parse_json(&body(None).to_json().unwrap()).unwrap();
    for field in [
        "v",
        "kind",
        "identity",
        "origin",
        "service_key",
        "store_id",
        "association",
        "created",
        "erased_at",
        "observed_at",
        "expires_at",
    ] {
        let mut changed = original.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(
            AccountObservationBody::from_json(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("extra", serde_json::json!(1)),
        ("v", serde_json::json!(2)),
        ("kind", serde_json::json!("other")),
        ("observed_at", serde_json::Value::Null),
        ("created", serde_json::json!("2026-01-01T00:00:00Z")),
        (
            "expires_at",
            serde_json::json!(time::rfc3339(NOW + 300_001)),
        ),
        ("created", serde_json::json!(time::rfc3339(NOW + 1))),
        ("erased_at", serde_json::json!(time::rfc3339(NOW + 1))),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(
            AccountObservationBody::from_json(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut absent = body(None);
    absent.erased_at = None;
    assert_eq!(
        AccountObservationBody::from_json(&absent.to_json().unwrap()).unwrap(),
        absent
    );
    let mut overflow = absent;
    overflow.observed_at = time::MAX_TIME_MS;
    overflow.expires_at = time::MAX_TIME_MS;
    assert!(overflow.to_json().is_err());
}

#[test]
fn test_account_binding_enrollment_intents_keep_association() {
    for intent in [
        EnrollmentIntent::Create {
            observation: carried(body(None)),
        },
        EnrollmentIntent::Existing { created: NOW - 500 },
        EnrollmentIntent::Takeover {
            created: NOW - 500,
            observation: carried(body(Some(NOW - 500))),
        },
    ] {
        let signed = Enrollment::sign(&identity(), enrollment(intent.clone())).unwrap();
        let verified = Enrollment::verify(signed.signed(), &identity().public(), ORIGIN).unwrap();
        assert_eq!(verified, signed);
        assert_eq!(verified.body().intent, intent);
        assert_eq!(
            verified.observation().is_some(),
            !matches!(intent, EnrollmentIntent::Existing { .. })
        );
    }
    assert!(
        Enrollment::sign(
            &identity(),
            enrollment(EnrollmentIntent::Create {
                observation: carried(body(Some(NOW - 500)))
            })
        )
        .is_err()
    );
    assert!(
        Enrollment::sign(
            &identity(),
            enrollment(EnrollmentIntent::Takeover {
                created: NOW - 400,
                observation: carried(body(Some(NOW - 500)))
            })
        )
        .is_err()
    );
}

#[test]
fn test_account_binding_enrollment_intent_is_required_and_strict() {
    let signed = Enrollment::sign(
        &identity(),
        enrollment(EnrollmentIntent::Existing { created: NOW - 500 }),
    )
    .unwrap();
    let original: serde_json::Value = json::parse_json(&signed.body().to_json().unwrap()).unwrap();
    for intent in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!({"kind":"existing"})),
        Some(
            serde_json::json!({"kind":"existing", "created":time::rfc3339(NOW - 500), "observation":carried(body(None))}),
        ),
        Some(
            serde_json::json!({"kind":"create", "observation":carried(body(None)), "created":time::rfc3339(NOW - 500)}),
        ),
    ] {
        let mut changed = original.clone();
        if let Some(intent) = intent {
            changed["intent"] = intent;
        } else {
            changed.as_object_mut().unwrap().remove("intent");
        }
        let signed = identity().sign_doc(
            labels::sig::ENROLL,
            &[],
            serde_json::to_vec(&changed).unwrap(),
        );
        assert!(Enrollment::verify(&signed, &identity().public(), ORIGIN).is_err());
    }
    let original = serde_json::to_value(carried(body(None))).unwrap();
    for field in ["body", "sig", "request_timestamp", "request_signature"] {
        let mut changed = original.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(
            json::parse_json::<CarriedAccountObservation>(&serde_json::to_vec(&changed).unwrap())
                .is_err()
        );
    }
    let mut changed = original;
    changed["extra"] = serde_json::json!(true);
    assert!(
        json::parse_json::<CarriedAccountObservation>(&serde_json::to_vec(&changed).unwrap())
            .is_err()
    );
}

fn object_association_rejections(
    association: AccountAssociation,
    created: Option<u64>,
) -> (bool, bool) {
    let mut value = body(created);
    value.association = association;
    let mut observation = carried(value.clone());
    assert_eq!(
        AccountObservationBody::from_json(&observation.body).unwrap(),
        value
    );
    observation
        .verify(&identity().public(), ORIGIN)
        .unwrap()
        .enrollment_intent()
        .unwrap();
    let mut encoded: serde_json::Value = json::parse_json(&observation.body).unwrap();
    let name = serde_json::to_value(association).unwrap();
    assert_eq!(encoded["association"], name);
    encoded["association"] = serde_json::json!({name.as_str().unwrap(): null});
    observation.body = serde_json::to_vec(&encoded).unwrap();
    resign_response(&mut observation);
    let body_rejected = AccountObservationBody::from_json(&observation.body).is_err();
    let carried_rejected = observation.verify(&identity().public(), ORIGIN).is_err();
    (body_rejected, carried_rejected)
}

#[test]
fn test_account_association_account_requires_string() {
    assert_eq!(
        object_association_rejections(AccountAssociation::Account, Some(NOW - 500)),
        (true, true)
    );
}

#[test]
fn test_account_association_mark_requires_string() {
    assert_eq!(
        object_association_rejections(AccountAssociation::Mark, Some(NOW - 500)),
        (true, true)
    );
}

#[test]
fn test_account_association_absent_requires_string() {
    assert_eq!(
        object_association_rejections(AccountAssociation::Absent, None),
        (true, true)
    );
}

#[test]
fn test_account_binding_selects_readable_inputs() {
    use AccountAssociation::{Absent, Account, Mark};
    use AccountMarkInput::{Created, Malformed, Missing};
    let cases = [
        (Some(10), Created(10), Account, Some(10)),
        (Some(10), Missing, Account, Some(10)),
        (Some(10), Malformed, Account, Some(10)),
        (None, Created(10), Mark, Some(10)),
        (Some(9), Created(10), Mark, Some(10)),
        (Some(11), Created(10), Account, Some(11)),
        (None, Missing, Absent, None),
    ];
    let actual: Vec<_> = cases
        .iter()
        .map(|(account, mark, _, _)| {
            let binding = AccountBinding::select(*account, *mark).unwrap();
            (binding.association(), binding.created())
        })
        .collect();
    let expected: Vec<_> = cases
        .iter()
        .map(|(_, _, association, created)| (*association, *created))
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn test_account_binding_refuses_unestablished_inputs() {
    let actual = [
        AccountBinding::select(None, AccountMarkInput::Unreadable).is_err(),
        AccountBinding::select(Some(NOW), AccountMarkInput::Unreadable).is_err(),
        AccountBinding::select(None, AccountMarkInput::Malformed).is_err(),
    ];
    assert_eq!(actual, [true; 3]);
}

#[test]
fn test_account_binding_checks_both_creation_times() {
    assert!(
        AccountBinding::select(
            Some(time::MAX_TIME_MS),
            AccountMarkInput::Created(time::MAX_TIME_MS)
        )
        .is_ok()
    );
    let actual = [
        AccountBinding::select(Some(time::MAX_TIME_MS + 1), AccountMarkInput::Created(NOW))
            .is_err(),
        AccountBinding::select(Some(NOW), AccountMarkInput::Created(time::MAX_TIME_MS + 1))
            .is_err(),
    ];
    assert_eq!(actual, [true; 2]);
}
