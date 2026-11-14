//! `http.json`: request and response signatures of every caller kind, and the push webhook
//! (Switch wire 7.1, 7.2, 8.2).

use pubky_switch_core::http::{
    self, BodyField, ReceivedHeaders, ReceivedRequest, RequestHeaders, RequestTarget,
    TransferHeaders,
};
use pubky_switch_core::records::{
    Enrollment, EnrollmentAnswer, IdentityDoc, Limits, SignerHandover,
};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::{labels, sig};
use serde_json::Value;

use crate::common::*;

fn header<'a>(v: &'a Value, name: &str) -> Option<&'a str> {
    v["headers"].get(name).and_then(Value::as_str)
}

fn handover_of(v: &Value) -> SignerHandover {
    let envelopes = arr(v, "envelopes")
        .iter()
        .map(|e| b64(e.as_str().unwrap()))
        .collect();
    SignerHandover::from_parts(envelopes, b64n::<64>(st(v, "sig")))
}

fn fields_of(v: &Value) -> Vec<Vec<u8>> {
    arr(v, "fields").iter().map(|f| hx(st(f, "hex"))).collect()
}

fn refs(fields: &[Vec<u8>]) -> Vec<&[u8]> {
    fields.iter().map(Vec::as_slice).collect()
}

/// The names of a request's signed fields, of a response's and of a received request's
/// (Switch wire 7.1), as the files write them.
const REQUEST_FIELDS: [&str; 9] = [
    "method",
    "path and query",
    "BLAKE3(body)",
    "Switch-Timestamp",
    "switch origin",
    "Switch-Identity",
    "Switch-App",
    "Switch-Cert",
    "Switch-Invite-Code",
];
const RESPONSE_FIELDS: [&str; 5] = [
    "u64(status)",
    "BLAKE3(received request)",
    "server time",
    "head field",
    "BLAKE3(body)",
];
const RECEIVED_FIELDS: [&str; 11] = [
    "method",
    "path and query",
    "body field",
    "switch origin",
    "H(Switch-Identity)",
    "H(Switch-App)",
    "H(Switch-Cert)",
    "H(Switch-Invite-Code)",
    "H(Switch-Transfer)",
    "H(Switch-Timestamp)",
    "H(Switch-Signature)",
];

/// The origin every request of the file is signed for but bob's switch's.
const ORIGIN: &str = "https://inbox.example";

/// The responses to an unsigned public read (Switch wire 7.4.15), which no request case
/// gives: each answers `GET /v1/{id}/identity` with no header, read whole, at the account
/// whose service key signs it, or, for the not-hosted `404` ([`NOT_HOSTED`]), at bob, whom
/// that service doesn't host (Switch wire 7.3 step 2).
const UNSIGNED_READS: [(&str, bool); 3] = [
    ("anyone: the public identity.json read", false),
    (
        "anyone: a frozen service's public identity.json read",
        false,
    ),
    (NOT_HOSTED, true),
];

/// The `404 not_found` to an unsigned read of an identity the service doesn't host (Switch
/// wire 7.3 step 2, 7.6), signed with the service key, the public read binding no header.
const NOT_HOSTED: &str = "anyone: an identity the service doesn't host, 404 not_found with hosted false, signed with the service key, no head";

/// A request as the service received it (Switch wire 7.1), owned.
pub struct Received {
    method: String,
    path_and_query: String,
    body: BodyField,
    origin: String,
    headers: ReceivedHeaders,
}

impl Received {
    /// The request case `r` as the service received it: its body read whole, its headers
    /// those the case writes.
    fn of_request(r: &Value) -> Self {
        let headers = r["headers"].as_object().unwrap();
        Received {
            method: st(r, "method").to_owned(),
            path_and_query: st(r, "path").to_owned(),
            body: BodyField::read(&b64(st(r, "body_b64"))),
            origin: st(r, "origin").to_owned(),
            headers: ReceivedHeaders::of(
                headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str().unwrap().as_bytes())),
            ),
        }
    }

    /// The core's view of it.
    pub fn request(&self) -> ReceivedRequest<'_> {
        ReceivedRequest {
            method: &self.method,
            path_and_query: &self.path_and_query,
            body: self.body,
            origin: &self.origin,
            headers: &self.headers,
        }
    }
}

/// The request a response case answers, as the service received it (Switch wire 7.1): the
/// request case of `file` its `request` names, else the unsigned read [`UNSIGNED_READS`]
/// gives it.
pub fn answered(keys: &Keys, file: &Value, case: &Value) -> Received {
    let name = st(case, "name");
    if let Some(request) = case["request"].as_str() {
        let request = arr(file, "requests")
            .iter()
            .find(|r| r["name"] == request)
            .unwrap_or_else(|| panic!("{name}: no request {request}"));
        return Received::of_request(request);
    }
    let (_, at_bob) = UNSIGNED_READS
        .iter()
        .find(|(prefix, _)| name.starts_with(prefix))
        .unwrap_or_else(|| panic!("{name}: no request case and no unsigned read"));
    let account = if *at_bob {
        pubky_switch_core::enc::pubky_id(&keys.identity("bob"))
    } else {
        let public = b64n::<32>(st(case, "public_key"));
        keys.service
            .iter()
            .find(|(_, key)| **key == public)
            .map(|(account, _)| account.clone())
            .unwrap_or_else(|| panic!("{name}: no account for its key"))
    };
    Received {
        method: "GET".into(),
        path_and_query: format!("/v1/{account}/identity"),
        body: BodyField::read(b""),
        origin: ORIGIN.into(),
        headers: ReceivedHeaders::default(),
    }
}

/// The response parts of `case`, answering `received`.
pub fn parts_of<'a>(case: &'a Value, received: &'a Received) -> http::ResponseParts<'a> {
    http::ResponseParts {
        status: u16::try_from(int(case, "status")).unwrap(),
        request: received.request(),
        server_time: header(case, http::header::SERVER_TIME).unwrap(),
        head: header(case, http::header::HEAD),
        body: st(case, "body").as_bytes(),
    }
}

/// The received request's fields, as the file writes them, and its bytes.
fn received_member(received: &Received) -> Value {
    let bytes = http::received_request(&received.request());
    let fields = pubky_switch_core::enc::split_lp(&bytes).unwrap();
    serde_json::json!({
        "bytes_hex": hex::encode(&bytes),
        "fields": named_fields(&RECEIVED_FIELDS, &fields),
    })
}

/// `case` with the members its response signature decides, written again: the received
/// request, the signed fields and bytes, the signature and `Switch-Service-Signature`,
/// signed with the fixed secret of its `public_key` over what it holds (Switch wire 7.1).
fn signed_case(keys: &Keys, file: &Value, case: Value) -> Value {
    let received = answered(keys, file, &case);
    signed_for(keys, case, &received)
}

/// `case` signed as the answer to `received` ([`signed_case`]).
fn signed_for(keys: &Keys, mut case: Value, received: &Received) -> Value {
    let public = b64n::<32>(st(&case, "public_key"));
    let name = st(&case, "name").to_owned();
    let secret = keys
        .secret(&public)
        .unwrap_or_else(|| panic!("{name}: no fixed key"));
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let fields = http::response_fields(&parts_of(&case, received));
    let signature = sig::sign(&key, labels::sig::HTTP_RESPONSE, &refs(&fields));
    let b64 = pubky_switch_core::enc::b64;
    case["received_request"] = received_member(received);
    case["fields"] = named_fields(&RESPONSE_FIELDS, &fields);
    case["headers"][http::header::SERVICE_SIGNATURE] = Value::String(b64(&signature));
    case["signature"] = Value::String(b64(&signature));
    case["signed_bytes_hex"] = Value::String(hex::encode(sig::signed_bytes(
        labels::sig::HTTP_RESPONSE,
        &refs(&fields),
    )));
    case
}

/// A request case signed with `key` over `target` and `headers` (Switch wire 7.1), in the
/// file's form.
fn request_case(
    name: &str,
    key: &ed25519_dalek::SigningKey,
    target: &RequestTarget<'_>,
    headers: &RequestHeaders,
) -> Value {
    use pubky_switch_core::enc;
    let fields = http::request_fields(target, headers);
    let signature = sig::sign(key, labels::sig::HTTP, &refs(&fields));
    let mut sent = serde_json::json!({
        "switch-identity": headers.identity,
        "switch-signature": enc::b64(&signature),
        "switch-timestamp": headers.timestamp,
    });
    for (name, value) in [
        (http::header::APP, &headers.app),
        (http::header::CERT, &headers.cert),
        (http::header::INVITE_CODE, &headers.invite_code),
    ] {
        if let Some(value) = value {
            sent[name] = Value::String(value.clone());
        }
    }
    serde_json::json!({
        "body_b64": enc::b64(target.body),
        "fields": named_fields(&REQUEST_FIELDS, &fields),
        "headers": sent,
        "label": labels::sig::HTTP,
        "method": target.method,
        "name": name,
        "origin": target.origin,
        "path": target.path_and_query,
        "public_key": enc::b64(&key.verifying_key().to_bytes()),
        "signature": enc::b64(&signature),
        "signed_bytes_hex": hex::encode(sig::signed_bytes(labels::sig::HTTP, &refs(&fields))),
        "signer": name,
    })
}

/// The requests of the three responses the reference prototype wrote without theirs, which
/// `pubky-switch-core` generates (README "How the files were generated") with the fixed keys
/// of `keys.json`, each at the second of its answer's time: bob's shop reading alice's
/// directory with its certificate, alice's wallet reading her feed after `1:4`, and the
/// wallet sending the batch of `chain.json` `seq` 7 and 8, the operations in the order the
/// chain holds them. Each request signature is the one that answer named.
fn answered_requests(keys: &Keys) {
    let alice_id = pubky_switch_core::enc::pubky_id(&keys.identity("alice"));
    let bob_id = pubky_switch_core::enc::pubky_id(&keys.identity("bob"));
    let app_key =
        |name: &str| ed25519_dalek::SigningKey::from_bytes(&keys.app(name).signing_secret);
    let chain = load("chain.json");
    let item = |seq: u64| {
        arr(&chain, "items")
            .iter()
            .find(|i| i["seq"] == seq)
            .unwrap()["item"]
            .clone()
    };
    let ops = serde_json::to_vec(&serde_json::json!({ "ops": [item(7), item(8)] })).unwrap();
    let directory = format!("/v1/{alice_id}/directory");
    let feed = format!("/v1/{alice_id}/feed?after=1:4&limit=100");
    let batch = format!("/v1/{alice_id}/ops");
    let wallet = |timestamp: &str| RequestHeaders {
        timestamp: timestamp.to_owned(),
        identity: alice_id.clone(),
        app: Some(keys.app("wallet").app_id.clone()),
        ..RequestHeaders::default()
    };
    let cases = [
        request_case(
            "app of another identity: directory read with its certificate",
            &app_key("shop"),
            &RequestTarget {
                method: "GET",
                path_and_query: &directory,
                body: b"",
                origin: ORIGIN,
            },
            &RequestHeaders {
                timestamp: "2026-01-01T00:05:00Z".to_owned(),
                identity: bob_id,
                app: Some(keys.app("shop").app_id.clone()),
                cert: Some(document("shop certificate").compact()),
                invite_code: None,
            },
        ),
        request_case(
            "own app: feed read after 1:4",
            &app_key("wallet"),
            &RequestTarget {
                method: "GET",
                path_and_query: &feed,
                body: b"",
                origin: ORIGIN,
            },
            &wallet("2026-01-01T00:05:02Z"),
        ),
        request_case(
            "own app: POST /ops of the batch at seq 7 and 8",
            &app_key("wallet"),
            &RequestTarget {
                method: "POST",
                path_and_query: &batch,
                body: &ops,
                origin: ORIGIN,
            },
            &wallet("2026-01-01T00:00:03Z"),
        ),
    ];
    let cases: Vec<(Place<'_>, Value)> = cases
        .into_iter()
        .map(|case| (Place::Case("/requests"), case))
        .collect();
    generated("http.json", &cases);
}

/// Every response's signature over its status, the request it answers as the service
/// received it, the server time, the head field and the body (Switch wire 7.1), which
/// `pubky-switch-core` writes (README "How the files were generated"), with the fixed keys
/// of `keys.json`; among them the not-hosted `404` ([`NOT_HOSTED`]), to an unsigned `GET`
/// of bob's `identity.json`, its `current` `{ "hosted": false }`, signed with the service
/// key that signs alice's answers.
fn response_signatures(keys: &Keys) {
    let file = load("http.json");
    let alice_id = pubky_switch_core::enc::pubky_id(&keys.identity("alice"));
    let not_hosted_at = arr(&file, "responses")
        .iter()
        .position(|c| c["status"] == 404 && c["request"].is_null())
        .unwrap();
    let held = &arr(&file, "responses")[not_hosted_at];
    let body = format!(
        r#"{{"code":"not_found","message":"no such account","current":{}}}"#,
        http::not_hosted_current()
    );
    let not_hosted = serde_json::json!({
        "body": body,
        "headers": {
            "switch-server-time": header(held, http::header::SERVER_TIME).unwrap(),
        },
        "label": labels::sig::HTTP_RESPONSE,
        "name": NOT_HOSTED,
        "public_key": pubky_switch_core::enc::b64(&keys.service_key(&alice_id)),
        "request": null,
        "signer": "service key",
        "status": 404,
    });
    let pointer = format!("/responses/{not_hosted_at}");
    let not_hosted = signed_case(keys, &file, not_hosted);
    let description = "Request and response signatures (wire 7.1) and the push webhook (wire 8.2). Request fields are the exact header texts, empty when absent, and the method as sent; the timestamp is RFC 3339 UTC to the second. Each response names the request case it answers in request (null for an unsigned public read) and gives the request as the service received it in received_request: lp(method, path and query, body field, switch origin, H(Switch-Identity), H(Switch-App), H(Switch-Cert), H(Switch-Invite-Code), H(Switch-Transfer), H(Switch-Timestamp), H(Switch-Signature)), the body field BLAKE3(body) once the body is read, each H empty when the header is absent and lp of its values when present, every H empty for the public read. Response signatures cover u64(status), BLAKE3 of the received request, the exact Switch-Server-Time text, the head field (empty without Switch-Head, BLAKE3 of its exact text with one) and BLAKE3(body).";
    generated(
        "http.json",
        &[
            (Place::Element(&pointer), not_hosted),
            (
                Place::Member("/description"),
                Value::String(description.into()),
            ),
        ],
    );
    let file = load("http.json");
    let cases: Vec<(Place<'_>, Value)> = arr(&file, "responses")
        .iter()
        .map(|case| {
            (
                Place::Case("/responses"),
                signed_case(keys, &file, case.clone()),
            )
        })
        .collect();
    generated("http.json", &cases);
}

fn named_fields(names: &[&str], fields: &[Vec<u8>]) -> Value {
    assert_eq!(names.len(), fields.len());
    names
        .iter()
        .zip(fields)
        .map(|(name, field)| serde_json::json!({ "hex": hex::encode(field), "name": name }))
        .collect()
}

/// The enrollment, as `http.json`'s request carries it.
fn vector_enrollment(file: &Value, alice: &[u8; 32]) -> Enrollment {
    let request = arr(file, "requests")
        .iter()
        .find(|r| st(r, "path") == "/v1/enroll")
        .unwrap();
    let value: Value = serde_json::from_slice(&b64(st(request, "body_b64"))).unwrap();
    let signed: SignedDoc = serde_json::from_value(value["enrollment"].clone()).unwrap();
    Enrollment::verify(&signed, alice, st(request, "origin")).unwrap()
}

/// The position of the enrollment answer in `http.json`'s responses.
fn enrollment_answer_at(file: &Value) -> usize {
    arr(file, "responses")
        .iter()
        .position(|c| st(c, "name").starts_with("signer: enrollment answer"))
        .unwrap()
}

/// The account's creation time (Switch wire 3.7, 7.3): the time the enrollment that created
/// it was answered at, which its answer names in `created`.
fn created_of(file: &Value) -> u64 {
    let answer = &arr(file, "responses")[enrollment_answer_at(file)];
    pubky_switch_core::time::parse_rfc3339(header(answer, http::header::SERVER_TIME).unwrap())
        .unwrap()
}

/// The enrollment answer (Switch wire 3.7), which `pubky-switch-core` writes (README "How
/// the files were generated"): the answer to the enrollment of the file, with its service
/// key and limits, naming in `created` the time it was answered at, when the account was
/// created; signed with the service key, under the name that says so.
fn enrollment_answer(keys: &Keys) {
    let file = load("http.json");
    let alice = keys.identity("alice");
    let enrollment = vector_enrollment(&file, &alice);
    let at = enrollment_answer_at(&file);
    let held = arr(&file, "responses")[at].clone();
    let body: Value = serde_json::from_str(st(&held, "body")).unwrap();
    let limits: Limits = serde_json::from_value(body["limits"].clone()).unwrap();
    let alice_id = pubky_switch_core::enc::pubky_id(&alice);
    let answer = EnrollmentAnswer::new(
        &enrollment,
        keys.service_key(&alice_id),
        limits,
        created_of(&file),
    );
    let mut case = held;
    case["name"] = Value::String("signer: enrollment answer, signed with the service key".into());
    case["body"] = Value::String(String::from_utf8(answer.to_json().unwrap()).unwrap());
    let case = signed_case(keys, &file, case);
    let pointer = format!("/responses/{at}");
    generated("http.json", &[(Place::Element(&pointer), case)]);
}

/// The erasures (Switch wire 7.4.16), which `pubky-switch-core` writes (README "How the files
/// were generated"), each naming the account's creation time, the `created` of its
/// enrollment answer: one at alice's account before its first delivery, which holds no
/// `identity.json`, so it names none; one naming the hash of her version 3, the version her
/// account holds; both answered `{"erased":true}`; and one naming her version 1, refused `409
/// conflict` with `current.created`, the creation time it was checked against. Each is
/// signed with her identity key, and each answer with the service key, without a head, over
/// the request as the service received it. They take the places of the erasure requests and
/// answers in the file, in order.
fn erasures(keys: &Keys) {
    use pubky_switch_core::enc;
    let file = load("http.json");
    let alice = keys.identity("alice");
    let alice_id = enc::pubky_id(&alice);
    let identity = ed25519_dalek::SigningKey::from_bytes(&keys.identity_secrets[&alice]);
    let service = keys.service_key(&alice_id);
    let created = created_of(&file);
    let timestamp = "2026-01-01T00:07:00Z";
    let server_time = "2026-01-01T00:07:00.030Z";
    let refused = format!(
        r#"{{"code":"conflict","message":"7.4.16: the account holds another identity.json","current":{{"created":"{}"}}}}"#,
        pubky_switch_core::time::rfc3339(created)
    );
    let cases = [
        (
            "signer: account erasure, naming the account's creation time",
            None,
            200,
            http::ERASED_BODY,
            "signer: account erasure answer, signed with the service key, no head",
        ),
        (
            "signer: account erasure, naming the account's creation time and the identity.json it follows",
            Some("alice identity.json"),
            200,
            http::ERASED_BODY,
            "signer: account erasure answer to the request naming its identity.json, signed with the service key, no head",
        ),
        (
            "signer: account erasure naming an identity.json the account doesn't hold",
            Some("alice identity.json, first delivery (version 1)"),
            409,
            refused.as_bytes(),
            "signer: account erasure refused, the account holds another identity.json, 409 conflict with current.created, no head",
        ),
    ];
    let erasure = |c: &Value| st(c, "path").ends_with("/erase");
    let requests_at: Vec<usize> = (0..arr(&file, "requests").len())
        .filter(|i| erasure(&arr(&file, "requests")[*i]))
        .collect();
    let responses_at: Vec<usize> = (0..arr(&file, "responses").len())
        .filter(|i| {
            let case = &arr(&file, "responses")[*i];
            st(case, "name").starts_with("signer: account erasure")
        })
        .collect();
    assert_eq!((requests_at.len(), responses_at.len()), (3, 3));
    let pointers: Vec<(String, String)> = requests_at
        .iter()
        .zip(&responses_at)
        .map(|(request, response)| {
            (
                format!("/requests/{request}"),
                format!("/responses/{response}"),
            )
        })
        .collect();
    let mut generated_cases = Vec::new();
    for ((name, document_name, status, answer, answer_name), (request_at, response_at)) in
        cases.into_iter().zip(&pointers)
    {
        let hash = document_name.map(|name| document(name).doc_hash().unwrap());
        let body = http::erase_body(Some(created), hash.as_ref());
        let path = format!("/v1/{alice_id}/erase");
        let target = RequestTarget {
            method: "POST",
            path_and_query: &path,
            body: &body,
            origin: ORIGIN,
        };
        let headers = RequestHeaders {
            timestamp: timestamp.to_owned(),
            identity: alice_id.clone(),
            ..RequestHeaders::default()
        };
        let request = request_case(name, &identity, &target, &headers);
        let received = Received::of_request(&request);
        generated_cases.push((Place::Element(request_at), request));
        let answer = serde_json::json!({
            "body": std::str::from_utf8(answer).unwrap(),
            "headers": { "switch-server-time": server_time },
            "label": labels::sig::HTTP_RESPONSE,
            "name": answer_name,
            "public_key": enc::b64(&service),
            "request": name,
            "signer": "service key",
            "status": status,
        });
        generated_cases.push((
            Place::Element(response_at),
            signed_for(keys, answer, &received),
        ));
    }
    generated("http.json", &generated_cases);
}

/// The page `body` with each record write that a later write of the same key in the page
/// supersedes shown as its stub (Switch wire 7.5, "Feed items and visibility"): the item
/// `{"type":"stub","seq":<seq>,"stub":<its stub>}`, the stub's bytes as the page held them.
fn superseded_as_stubs(body: &str) -> String {
    let page: Value = serde_json::from_str(body).unwrap();
    let writes: Vec<(u64, String)> = arr(&page, "items")
        .iter()
        .filter(|item| item["type"] == "chain" && item["item_type"] == "op")
        .filter_map(|item| {
            let op: Value = serde_json::from_slice(&b64(st(&item["item"], "body"))).unwrap();
            (op["op"] == "record.put")
                .then(|| (item["seq"].as_u64().unwrap(), st(&op, "key").to_owned()))
        })
        .collect();
    let mut out = body.to_owned();
    for (seq, key) in &writes {
        if !writes.iter().any(|(later, k)| later > seq && k == key) {
            continue;
        }
        let start = out
            .find(&format!("{{\"type\":\"chain\",\"seq\":{seq},"))
            .unwrap();
        let end = start
            + out[start..]
                .find(",{\"type\":")
                .or_else(|| out[start..].find("],\"next\""))
                .unwrap();
        let item = &out[start..end];
        let stub_at = item.find("\"stub\":").unwrap() + "\"stub\":".len();
        let stub_end = item.find(",\"item_type\":").unwrap();
        let stub_item = format!(
            "{{\"type\":\"stub\",\"seq\":{seq},\"stub\":{}}}",
            &item[stub_at..stub_end]
        );
        out.replace_range(start..end, &stub_item);
    }
    out
}

/// The `cursor` of the two feed pages (Switch wire 7.4.4), which `pubky-switch-core` added to
/// the prototype's pages (README "How the files were generated"): alice's wallet after `1:4`,
/// before its first cursor move, holds 0, and the long-poll's page at `1:41` an app whose
/// cursor is at the head. Each page holds the member before its `head`, and a record write
/// that a later write in the page supersedes shows as its stub ([`superseded_as_stubs`]).
/// Its answer is signed again with her account's fixed service key, answering the page's own
/// request, at its server time and head ([`signed_case`]).
fn feed_page_cursors(keys: &Keys) {
    use pubky_switch_core::enc;
    let alice_id = enc::pubky_id(&keys.identity("alice"));
    let service = keys.service_key(&alice_id);
    let file = load("http.json");
    let mut generated_cases = Vec::new();
    let mut signature_case = None;
    for (name, cursor) in [
        ("own app: feed page with an entry and chain items", 0),
        ("own app: feed page, with the head header", 41),
    ] {
        let mut case = arr(&file, "responses")
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("{name}"))
            .clone();
        assert_eq!(st(&case, "public_key"), enc::b64(&service), "{name}");
        // The page as the prototype wrote it, then with the member before its `head`, the
        // last `"head":` of the body, since a page's items come before it.
        let held = st(&case, "body");
        let page = match held.find("\"cursor\":") {
            Some(start) => {
                let end = start + held[start..].find(',').unwrap() + 1;
                format!("{}{}", &held[..start], &held[end..])
            }
            None => held.to_owned(),
        };
        let page = superseded_as_stubs(&page);
        let at = page.rfind("\"head\":{").unwrap();
        let body = format!("{}\"cursor\":{cursor},{}", &page[..at], &page[at..]);
        case["body"] = Value::String(body);
        let case = signed_case(keys, &file, case);
        if cursor == 41 {
            signature_case = Some(serde_json::json!({
                "fields": case["fields"].clone(),
                "label": labels::sig::HTTP_RESPONSE,
                "public_key": enc::b64(&service),
                "signature": case["signature"].clone(),
                "signed_bytes_hex": case["signed_bytes_hex"].clone(),
                "signer": "service key",
            }));
        }
        generated_cases.push((Place::Case("/responses"), case));
    }
    generated("http.json", &generated_cases);
    // `signatures.json`'s one response signature is the long-poll page's.
    let signatures = load("signatures.json");
    let index = arr(&signatures, "signatures")
        .iter()
        .position(|c| c["label"] == labels::sig::HTTP_RESPONSE)
        .unwrap();
    let pointer = format!("/signatures/{index}");
    generated(
        "signatures.json",
        &[(Place::Element(&pointer), signature_case.unwrap())],
    );
}

#[test]
fn test_vectors_http() {
    let keys = keys();
    answered_requests(&keys);
    enrollment_answer(&keys);
    erasures(&keys);
    feed_page_cursors(&keys);
    response_signatures(&keys);
    let v = load("http.json");
    let mut transfer_requests = 0;
    for r in arr(&v, "requests") {
        let name = st(r, "name");
        let body = b64(st(r, "body_b64"));
        let target = RequestTarget {
            method: st(r, "method"),
            path_and_query: st(r, "path"),
            body: &body,
            origin: st(r, "origin"),
        };
        let signature =
            http::decode_signature(header(r, http::header::SIGNATURE).unwrap()).unwrap();
        assert_eq!(b64n::<64>(st(r, "signature")), signature, "{name}");
        let public = b64n::<32>(st(r, "public_key"));
        let label = st(r, "label");
        let fields = if let Some(transfer) = header(r, http::header::TRANSFER) {
            transfer_requests += 1;
            assert_eq!(label, labels::sig::TRANSFER_REQUEST, "{name}");
            assert!(
                header(r, http::header::APP).is_none(),
                "{name}: no Switch-App"
            );
            let headers = TransferHeaders {
                timestamp: header(r, http::header::TIMESTAMP).unwrap().to_owned(),
                identity: header(r, http::header::IDENTITY).unwrap().to_owned(),
                transfer: transfer.to_owned(),
            };
            http::verify_transfer_request(&public, &target, &headers, &signature)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            // Under the label of an ordinary request it doesn't verify.
            let ordinary = RequestHeaders {
                timestamp: headers.timestamp.clone(),
                identity: headers.identity.clone(),
                ..RequestHeaders::default()
            };
            assert!(http::verify_request(&public, &target, &ordinary, &signature).is_err());
            http::transfer_request_fields(&target, &headers)
        } else {
            assert_eq!(label, labels::sig::HTTP, "{name}");
            let headers = RequestHeaders {
                timestamp: header(r, http::header::TIMESTAMP).unwrap().to_owned(),
                identity: header(r, http::header::IDENTITY).unwrap().to_owned(),
                app: header(r, http::header::APP).map(str::to_owned),
                cert: header(r, http::header::CERT).map(str::to_owned),
                invite_code: header(r, http::header::INVITE_CODE).map(str::to_owned),
            };
            http::verify_request(&public, &target, &headers, &signature)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            // Another body, path or origin breaks it.
            let other_body = RequestTarget {
                body: b"x",
                ..target
            };
            assert!(http::verify_request(&public, &other_body, &headers, &signature).is_err());
            let other_origin = RequestTarget {
                origin: "https://other.example",
                ..target
            };
            assert!(http::verify_request(&public, &other_origin, &headers, &signature).is_err());
            // A signer call carries no Switch-App; an app's does.
            assert_eq!(
                headers.app.is_some(),
                !name.starts_with("signer"),
                "{name}: Switch-App"
            );
            http::request_fields(&target, &headers)
        };
        assert_eq!(fields, fields_of(r), "{name}: fields");
        assert_eq!(
            hex::encode(sig::signed_bytes(label, &refs(&fields))),
            st(r, "signed_bytes_hex"),
            "{name}: signed bytes"
        );
        assert!(
            reproduce(&keys, &public, label, &refs(&fields), &signature),
            "{name}: no fixed key for the signer"
        );
        // The timestamp is written to the second (Switch wire 1.6).
        let timestamp = header(r, http::header::TIMESTAMP).unwrap();
        let ms = pubky_switch_core::time::parse_rfc3339(timestamp).unwrap();
        assert_eq!(
            pubky_switch_core::time::rfc3339_seconds(ms),
            timestamp,
            "{name}"
        );
        // Every body fits its call's cap.
        let cap = http::body_cap(target.method, target.path_and_query)
            .unwrap_or_else(|| panic!("{name}: a call of the cap table"));
        assert!(body.len() <= cap, "{name}: body over its cap");
    }
    assert_eq!(transfer_requests, 1);

    // What the bodies carry, read through the records' API.
    let alice = keys.identity("alice");
    let created = created_of(&v);
    let mut enrollment = None;
    for r in arr(&v, "requests") {
        let name = st(r, "name");
        let body = b64(st(r, "body_b64"));
        let path = st(r, "path");
        let call = path.split('?').next().unwrap();
        if call == "/v1/enroll" {
            let value: Value = serde_json::from_slice(&body).unwrap();
            let signed: SignedDoc = serde_json::from_value(value["enrollment"].clone()).unwrap();
            enrollment = Some(
                Enrollment::verify(&signed, &alice, st(r, "origin"))
                    .unwrap_or_else(|e| panic!("{name}: {e}")),
            );
        } else if call.ends_with("/identity") && st(r, "method") == "PUT" {
            let delivery = http::IdentityDelivery::parse(&body).unwrap();
            assert_eq!(delivery.to_json(), body, "{name}: the body as written");
            let doc = IdentityDoc::verify(&delivery.identity, &alice)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            // The account's first delivery builds on nothing.
            assert_eq!(delivery.prev.is_none(), doc.version() == 1, "{name}: prev");
        } else if call.ends_with("/peers") {
            // A peer copy is the signed document itself.
            let signed: SignedDoc = serde_json::from_slice(&body).unwrap();
            let doc =
                IdentityDoc::verify(&signed, &alice).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(doc.version(), 3, "{name}");
        } else if call.ends_with("/handover") && st(r, "method") == "PUT" {
            // The hand-over the signer stores for its target app (Switch wire 7.4.17).
            let value: Value = serde_json::from_slice(&body).unwrap();
            let target = keys.app_by_id(st(&value, "app_id"));
            let handover = handover_of(&value["handover"]);
            let target_id = pubky_switch_core::enc::app_id_decode(&target.app_id).unwrap();
            handover
                .check_stored(&alice, &target_id, &target.bundle_public)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            // Stored for another app, it fails.
            let other = keys.app("wallet");
            let other_id = pubky_switch_core::enc::app_id_decode(&other.app_id).unwrap();
            assert!(
                handover
                    .check_stored(&alice, &other_id, &other.bundle_public)
                    .is_err()
            );
        } else if call.ends_with("/erase") {
            // Each names the account's creation time, the one its enrollment answer gives
            // (Switch wire 7.4.16, 3.7).
            let parsed = http::parse_erase_body(&body).unwrap();
            assert_eq!(parsed.created, Some(created), "{name}");
            // The body as written, the hash, when named, after the time.
            assert_eq!(
                http::erase_body(parsed.created, parsed.identity_hash.as_ref()),
                body,
                "{name}"
            );
        }
    }
    let enrollment = enrollment.expect("an enrollment request");

    for r in arr(&v, "responses") {
        let name = st(r, "name");
        let status = u16::try_from(int(r, "status")).unwrap();
        let body = st(r, "body").as_bytes();
        let signature =
            http::decode_signature(header(r, http::header::SERVICE_SIGNATURE).unwrap()).unwrap();
        assert_eq!(b64n::<64>(st(r, "signature")), signature, "{name}");
        let public = b64n::<32>(st(r, "public_key"));
        assert_eq!(st(r, "label"), labels::sig::HTTP_RESPONSE);
        // The request it answers, as the service received it (Switch wire 7.1).
        let received = answered(&keys, &v, r);
        let request = received.request();
        let bytes = http::received_request(&request);
        assert_eq!(
            hex::encode(&bytes),
            st(&r["received_request"], "bytes_hex"),
            "{name}: received request"
        );
        assert_eq!(
            pubky_switch_core::enc::split_lp(&bytes).unwrap(),
            fields_of(&r["received_request"]),
            "{name}: received request fields"
        );
        let parts = parts_of(r, &received);
        let fields = http::response_fields(&parts);
        assert_eq!(fields, fields_of(r), "{name}: fields");
        assert_eq!(
            hex::encode(sig::signed_bytes(
                labels::sig::HTTP_RESPONSE,
                &refs(&fields)
            )),
            st(r, "signed_bytes_hex")
        );
        http::verify_response(&public, &parts, &signature)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        // Another status, server time, head or body breaks it, and so does another received
        // request: another method, query, body field, origin, or a header added, changed or
        // sent twice.
        let other_head = match parts.head {
            Some(_) => None,
            None => Some(""),
        };
        for other in [
            http::ResponseParts {
                status: status + 1,
                ..parts
            },
            http::ResponseParts {
                server_time: "2000-01-01T00:00:00.000Z",
                ..parts
            },
            http::ResponseParts {
                head: other_head,
                ..parts
            },
            http::ResponseParts {
                body: b"{}",
                ..parts
            },
        ] {
            assert!(
                http::verify_response(&public, &other, &signature).is_err(),
                "{name}"
            );
        }
        let query = format!("{}?x=1", request.path_and_query);
        let mut sent: Vec<(&str, &[u8])> = Vec::new();
        let mut twice: Vec<(&str, &[u8])> = Vec::new();
        for covered in http::RECEIVED_HEADERS {
            for value in request.headers.values(covered) {
                sent.push((covered, value));
                twice.push((covered, value));
                twice.push((covered, value));
            }
        }
        sent.push((http::header::TRANSFER, b"".as_slice()));
        let added = ReceivedHeaders::of(sent);
        let twice = ReceivedHeaders::of(twice);
        let mut others = vec![
            ReceivedRequest {
                method: "DELETE",
                ..request
            },
            ReceivedRequest {
                path_and_query: &query,
                ..request
            },
            ReceivedRequest {
                body: BodyField::NotRead,
                ..request
            },
            ReceivedRequest {
                origin: "https://other.example",
                ..request
            },
        ];
        // The public read binds no header, so only another read's headers change nothing.
        if !http::is_public_read(request.method, request.path_and_query) {
            others.push(ReceivedRequest {
                headers: &added,
                ..request
            });
            others.push(ReceivedRequest {
                headers: &twice,
                ..request
            });
        } else {
            assert_eq!(
                bytes,
                http::received_request(&ReceivedRequest {
                    headers: &added,
                    ..request
                }),
                "{name}"
            );
        }
        for other in others {
            let other = http::ResponseParts {
                request: other,
                ..parts
            };
            assert!(
                http::verify_response(&public, &other, &signature).is_err(),
                "{name}"
            );
        }
        // Signed by the service key, for an account it hosts and for one it doesn't.
        assert!(
            reproduce(
                &keys,
                &public,
                labels::sig::HTTP_RESPONSE,
                &refs(&fields),
                &signature
            ),
            "{name}: no fixed key for the service"
        );
        if name == NOT_HOSTED {
            let parsed: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(parsed["current"], http::not_hosted_current(), "{name}");
            assert!(header(r, http::header::HEAD).is_none(), "{name}: no head");
        }
        if name.starts_with("signer: enrollment answer") {
            let answer = EnrollmentAnswer::from_json(body).unwrap();
            answer
                .check(&enrollment)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                answer.to_json().unwrap(),
                body,
                "{name}: the answer as written"
            );
            // The account's creation time, the time it was answered at (Switch wire 3.7).
            assert_eq!(answer.created, created, "{name}");
        }
        if name.starts_with("signer: account erasure refused") {
            // Every `409` to an erasure carries the creation time it was checked against
            // (Switch wire 7.4.16).
            let parsed: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(
                parsed["current"]["created"],
                pubky_switch_core::time::rfc3339(created),
                "{name}"
            );
        }
        if name.starts_with("own app: the hand-over the switch stores") {
            // The fetch answers the stored body as it was put.
            let value: Value = serde_json::from_slice(body).unwrap();
            let target = keys.app_by_id(st(&value, "app_id"));
            let target_id = pubky_switch_core::enc::app_id_decode(&target.app_id).unwrap();
            handover_of(&value["handover"])
                .verify(&alice, &target_id)
                .unwrap();
        }
        if name.starts_with("signer: account erasure answer") {
            assert_eq!(body, http::ERASED_BODY);
        }
        // No answer to an enrollment or an erasure carries a head (Switch wire 7.1).
        if name.starts_with("signer: enrollment answer")
            || name.starts_with("signer: account erasure")
        {
            assert!(header(r, http::header::HEAD).is_none(), "{name}: no head");
        }
        // Errors name a code of the table with its status.
        if status >= 400 {
            let parsed: Value = serde_json::from_slice(body).unwrap();
            let code = http::ErrorCode::parse(st(&parsed, "code"))
                .unwrap_or_else(|| panic!("{name}: an unknown code"));
            assert_eq!(code.status(), status, "{name}");
            if code == http::ErrorCode::RateLimited {
                // The body repeats the wait that `Retry-After` carries (Switch wire 7.1).
                assert!(parsed["retry_after"].is_u64(), "{name}: retry_after");
            }
        }
    }

    let w = &v["webhook"];
    let relay_url = st(w, "relay_url");
    assert_eq!(
        http::relay_origin(relay_url).unwrap(),
        st(w, "relay_origin")
    );
    let body = st(w, "body").as_bytes();
    let signature = http::decode_signature(header(w, http::header::SIGNATURE).unwrap()).unwrap();
    let key = b64n::<32>(st(w, "service_key"));
    http::verify_webhook(&key, relay_url, body, &signature).unwrap();
    let origin = http::relay_origin(relay_url).unwrap();
    assert!(reproduce(
        &keys,
        &key,
        labels::sig::PUSH,
        &[origin.as_bytes(), body],
        &signature
    ));
    // The body as the switch writes it, from its handle, time and nonce.
    let parsed: Value = serde_json::from_slice(body).unwrap();
    let rebuilt = http::webhook_body(
        st(&parsed, "handle"),
        pubky_switch_core::time::parse_rfc3339(st(&parsed, "ts")).unwrap(),
        &b64n::<16>(st(&parsed, "nonce")),
    );
    assert_eq!(rebuilt, body);
    assert!(
        http::verify_webhook(&key, "https://elsewhere.example/v1/hook", body, &signature).is_err()
    );
}
