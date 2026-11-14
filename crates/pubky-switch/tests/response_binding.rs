//! The response signature binds the request as the service received it (Switch wire 7.1):
//! its method as sent, its path and query, its body field, and each request header with its
//! presence; the public read binds no header, by its call.
//!
//! The vectors fix the service key and the times; set `PUBKY_SWITCH_TEST_DATABASE_URL` to run
//! them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use axum::http::{HeaderName, HeaderValue};
use pubky_switch::http::{Handler, Refusal, SwitchRequest, SwitchResponse, route::route};
use pubky_switch_core::http::header;
use serde_json::{Value, json};
use support::*;

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn revoke_time() -> String {
    item_time(chain_item(&vectors("chain.json"), 9))
}

/// alice's service key, from `keys.json`.
fn alice_service_key() -> [u8; 32] {
    let keys = vectors("keys.json");
    let service = keys["service_keys"]
        .as_array()
        .expect("service keys")
        .iter()
        .find(|s| s["account"] == alice_id().as_str())
        .expect("alice's service key")
        .clone();
    pubky_switch_core::enc::unb64(service["public"].as_str().expect("public"))
        .expect("key")
        .try_into()
        .expect("32 bytes")
}

fn code_of(answer: &SwitchResponse) -> (u16, Value) {
    let body: Value = serde_json::from_slice(&answer.body).expect("json");
    (answer.status, body["code"].clone())
}

/// The signer's `GET /apps` at the revoke's time: answered `200` with the head.
fn honest_apps() -> SwitchRequest {
    signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    )
}

/// `request`'s method, path and query, headers and body, as another request of the same
/// route.
fn copy_of(request: &SwitchRequest) -> SwitchRequest {
    let mut copy = support::request(
        &request.method,
        &request.path_and_query,
        &[],
        request.body.to_vec(),
    );
    copy.headers = request.headers.clone();
    copy
}

/// `answer` with `Switch-Head` replaced by `head`, or taken off.
fn with_head(answer: &SwitchResponse, head: Option<&str>) -> SwitchResponse {
    let mut headers: Vec<_> = answer
        .headers
        .iter()
        .filter(|(name, _)| name.as_str() != header::HEAD)
        .cloned()
        .collect();
    if let Some(head) = head {
        headers.push((
            HeaderName::from_static(header::HEAD),
            HeaderValue::from_str(head).expect("value"),
        ));
    }
    SwitchResponse {
        status: answer.status,
        headers,
        body: answer.body.clone(),
    }
}

#[tokio::test]
async fn test_response_binding_forged_query_refusal_isnt_the_honest_answer() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let honest = honest_apps();
    let sent = Sent::of(&honest);
    // The honest headers, its signature among them, on another query: refused before the
    // signature verifies.
    let mut forged = support::request(
        "GET",
        &format!("{}?x=1", honest.path_and_query),
        &[],
        Vec::new(),
    );
    forged.headers = honest.headers.clone();
    let forged_sent = Sent::of(&forged);
    let answer = replay.service.handle(forged).await;
    assert_eq!(code_of(&answer), (401, json!("bad_signature")));
    assert!(signed_with(&answer, &alice_service_key(), &forged_sent));
    assert!(!signed_with(&answer, &alice_service_key(), &sent));
    // The honest request is still served.
    let answer = replay.service.handle(honest).await;
    assert_eq!(answer.status, 200);
    assert!(signed_with(&answer, &alice_service_key(), &sent));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_response_binding_changed_timestamp_refusal_isnt_the_honest_answer() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let honest = honest_apps();
    let sent = Sent::of(&honest);
    let mut forged = copy_of(&honest);
    forged.headers.insert(
        HeaderName::from_static(header::TIMESTAMP),
        HeaderValue::from_static("2025-01-01T00:00:00Z"),
    );
    let forged_sent = Sent::of(&forged);
    let answer = replay.service.handle(forged).await;
    assert_eq!(code_of(&answer), (401, json!("stale_timestamp")));
    assert!(signed_with(&answer, &alice_service_key(), &forged_sent));
    assert!(!signed_with(&answer, &alice_service_key(), &sent));
    replay.db.drop_database().await.expect("drop");
}

/// The head of alice's account, from the signer's `GET /apps`.
async fn head_now(replay: &Replay) -> String {
    let answer = replay.service.handle(honest_apps()).await;
    assert_eq!(answer.status, 200);
    header_text(&answer, header::HEAD).expect("head").to_owned()
}

#[tokio::test]
async fn test_response_binding_repeated_signed_header_is_refused() {
    // A signed request header sent twice is `400 bad_request`, before any signature work:
    // the service never chooses between two signed values. Its answer binds the request as
    // it arrived, so it doesn't pass for the honest one (Switch wire 7.1).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet")["app_id"]
        .as_str()
        .expect("id")
        .to_owned();
    let path = format!("/v1/{}/apps/{wallet}/revoke", alice_id());
    let honest = signer_request("POST", &path, Vec::new(), ms(&revoke_time()));
    let sent = Sent::of(&honest);
    let before = head_now(&replay).await;
    let signature = honest
        .headers
        .get(header::SIGNATURE)
        .expect("signature")
        .clone();
    for (name, value) in [
        (header::APP, HeaderValue::from_str(&wallet).expect("value")),
        (header::SIGNATURE, signature),
    ] {
        let mut repeated = copy_of(&honest);
        repeated
            .headers
            .append(HeaderName::from_static(name), value.clone());
        repeated
            .headers
            .append(HeaderName::from_static(name), value);
        let repeated_sent = Sent::of(&repeated);
        let answer = replay.service.handle(repeated).await;
        assert_eq!(code_of(&answer), (400, json!("bad_request")), "{name}");
        assert!(
            signed_with(&answer, &service_public(&replay), &repeated_sent),
            "{name}"
        );
        assert!(
            !signed_with(&answer, &service_public(&replay), &sent),
            "{name}"
        );
        // Nothing was committed.
        assert_eq!(head_now(&replay).await, before, "{name}");
    }
    // The honest write is served.
    let answer = replay.service.handle(honest).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(signed_with(&answer, &alice_service_key(), &sent));
    assert_ne!(head_now(&replay).await, before);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_response_binding_empty_or_unreadable_signed_header_is_refused() {
    // A signed request header present with an empty value, or with one that isn't printable
    // ASCII, is `400 bad_request` before any signature work, as a repeated one is: the
    // service never reads a value otherwise than its answer binds it (Switch wire 7.1).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let honest = honest_apps();
    let sent = Sent::of(&honest);
    let before = head_now(&replay).await;
    for (name, value) in [
        (header::INVITE_CODE, HeaderValue::from_static("")),
        (header::APP, HeaderValue::from_static("")),
        (header::CERT, HeaderValue::from_static("")),
        (header::TRANSFER, HeaderValue::from_static("")),
        (
            header::APP,
            HeaderValue::from_bytes(b"\xff\xfe").expect("value"),
        ),
        (header::INVITE_CODE, HeaderValue::from_static("a\tb")),
    ] {
        let mut odd = copy_of(&honest);
        odd.headers.insert(HeaderName::from_static(name), value);
        let odd_sent = Sent::of(&odd);
        let answer = replay.service.handle(odd).await;
        assert_eq!(code_of(&answer), (400, json!("bad_request")), "{name}");
        assert!(header_text(&answer, header::HEAD).is_none(), "{name}");
        assert!(
            signed_with(&answer, &service_public(&replay), &odd_sent),
            "{name}"
        );
        assert!(
            !signed_with(&answer, &service_public(&replay), &sent),
            "{name}"
        );
        assert_eq!(head_now(&replay).await, before, "{name}");
    }
    // A header no received request covers is no signed header.
    let mut other = copy_of(&honest);
    other
        .headers
        .insert(HeaderName::from_static("x-other"), HeaderValue::from_static(""));
    assert_eq!(replay.service.handle(other).await.status, 200);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_response_binding_lower_case_method_is_an_unknown_route() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let honest = honest_apps();
    let sent = Sent::of(&honest);
    // Routes name their methods in upper case: `get` has none (Switch wire 7.1, 7.3 step 1).
    assert!(route("get", &honest.path_and_query).is_none());
    let mut lower = copy_of(&honest);
    lower.method = "get".into();
    let lower_sent = Sent::of(&lower);
    let answer = replay
        .service
        .refuse(Refusal::UnknownRoute {
            method: lower.method,
            path_and_query: lower.path_and_query,
            headers: lower.headers,
            body: lower.body,
        })
        .await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(signed_with(&answer, &service_public(&replay), &lower_sent));
    assert!(!signed_with(&answer, &service_public(&replay), &sent));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_response_binding_too_large_binds_the_empty_body_field() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let path = format!("/v1/{}/ops", alice_id());
    let request = signer_request("POST", &path, b"{}".to_vec(), ms(&revoke_time()));
    let sent = Sent::of(&request);
    let answer = replay
        .service
        .refuse(Refusal::TooLarge {
            route: route("POST", &path),
            method: request.method,
            path_and_query: request.path_and_query,
            headers: request.headers,
            cap: 1,
        })
        .await;
    assert_eq!(code_of(&answer), (413, json!("too_large")));
    // The body wasn't read: the answer binds the empty body field, never the body's hash.
    assert!(signed_with(
        &answer,
        &service_public(&replay),
        &sent.clone().unread()
    ));
    assert!(!signed_with(&answer, &service_public(&replay), &sent));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_response_binding_head_is_bound() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let honest = honest_apps();
    let sent = Sent::of(&honest);
    let answer = replay.service.handle(honest).await;
    assert!(header_text(&answer, header::HEAD).is_some(), "head");
    assert!(signed_with(&answer, &alice_service_key(), &sent));
    // Stripped, emptied or moved, the head breaks the signature.
    for other in [None, Some(""), Some("aGVhZA")] {
        assert!(
            !signed_with(&with_head(&answer, other), &alice_service_key(), &sent),
            "{other:?}"
        );
    }
    // An empty head added to a headless answer breaks it too.
    let honest = honest_apps();
    let mut forged = support::request(
        "GET",
        &format!("{}?x=1", honest.path_and_query),
        &[],
        Vec::new(),
    );
    forged.headers = honest.headers.clone();
    let forged_sent = Sent::of(&forged);
    let refused = replay.service.handle(forged).await;
    assert!(header_text(&refused, header::HEAD).is_none());
    assert!(signed_with(&refused, &alice_service_key(), &forged_sent));
    assert!(!signed_with(
        &with_head(&refused, Some("")),
        &alice_service_key(),
        &forged_sent
    ));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_response_binding_public_read_binds_no_header() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = ms(&revoke_time());
    let bob = vectors("keys.json")["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|i| i["name"] == "bob")
        .expect("bob")["pubky_id"]
        .as_str()
        .expect("id")
        .to_owned();
    // At an account it hosts and at one it doesn't, the answer to a signed read, and to one
    // with headers that decode to nothing, is the answer to the unsigned read, byte for byte.
    for (id, key) in [
        (alice_id(), alice_service_key()),
        (bob, service_public(&replay)),
    ] {
        let path = format!("/v1/{id}/identity");
        let bare = support::request("GET", &path, &[], Vec::new());
        let bare_sent = Sent::of(&bare);
        let unsigned = replay.service.handle(bare).await;
        assert!(signed_with(&unsigned, &key, &bare_sent), "{id}");
        let signed = replay
            .service
            .handle(signer_request("GET", &path, Vec::new(), at))
            .await;
        let junk = replay
            .service
            .handle(support::request(
                "GET",
                &path,
                &[
                    (header::SIGNATURE, "junk"),
                    (header::INVITE_CODE, ""),
                    (header::TIMESTAMP, "never"),
                ],
                Vec::new(),
            ))
            .await;
        // Nor is it refused by the header rule every other call has: a header sent twice,
        // empty or not printable ASCII (Switch wire 7.1 "Each header once, as text").
        let mut twice = signer_request("GET", &path, Vec::new(), at);
        let timestamp = twice.headers.get(header::TIMESTAMP).expect("ts").clone();
        twice
            .headers
            .append(HeaderName::from_static(header::TIMESTAMP), timestamp);
        let twice = replay.service.handle(twice).await;
        let mut unreadable = support::request("GET", &path, &[], Vec::new());
        unreadable.headers.insert(
            HeaderName::from_static(header::APP),
            HeaderValue::from_bytes(b"\xff").expect("value"),
        );
        let unreadable = replay.service.handle(unreadable).await;
        for answer in [&signed, &junk, &twice, &unreadable] {
            assert_eq!(answer.status, unsigned.status, "{id}");
            assert_eq!(answer.headers, unsigned.headers, "{id}");
            assert_eq!(answer.body, unsigned.body, "{id}");
        }
    }
    replay.db.drop_database().await.expect("drop");
}
