//! `http.json`: request and response signatures of every caller kind, and the push webhook
//! (Dispatch wire 7.1, 7.2, 8.2).

use super::export::ExportCases;
use ed25519_dalek::SigningKey;
use pubky_dispatch_core::admission::{PeerEntry, ReplyGrant, ReplyOrigin};
use pubky_dispatch_core::chain::{ChainTip, ItemType, SignedHead};
use pubky_dispatch_core::enc;
use pubky_dispatch_core::http::{
    self, BodyField, ReceivedHeaders, ReceivedRequest, RequestHeaders, RequestTarget,
    TransferHeaders,
};
use pubky_dispatch_core::ops::Position;
use pubky_dispatch_core::records::{
    Enrollment, EnrollmentAnswer, IdentityDoc, Limits, SignerHandover,
};
use pubky_dispatch_core::sig::SignedDoc;
use pubky_dispatch_core::time::rfc3339;
use pubky_dispatch_core::{labels, sig};
use serde_json::{Value, json};
use std::collections::HashMap;

use super::chain::{Chain, Item};

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

/// Signed field descriptions display wire header names in title case (Dispatch wire 7.1).
fn field_label(name: &str) -> String {
    if !http::RECEIVED_HEADERS.contains(&name) {
        return name.to_owned();
    }
    let mut title = String::with_capacity(name.len());
    let mut initial = true;
    for c in name.chars() {
        title.push(if initial { c.to_ascii_uppercase() } else { c });
        initial = c == '-';
    }
    title
}

const REQUEST_FIELDS: [&str; 10] = [
    "method",
    "path and query",
    "BLAKE3(body)",
    http::header::TIMESTAMP,
    "dispatch origin",
    http::header::IDENTITY,
    http::header::APP,
    http::header::CERT,
    http::header::INVITE_CODE,
    http::header::CREATED,
];
const TRANSFER_FIELDS: [&str; 7] = [
    "method",
    "path and query",
    "BLAKE3(body)",
    http::header::TIMESTAMP,
    "dispatch origin",
    http::header::IDENTITY,
    http::header::TRANSFER,
];
const RESPONSE_FIELDS: [&str; 5] = [
    "u64(status)",
    "BLAKE3(received request)",
    "server time",
    "head field",
    "BLAKE3(body)",
];

fn hashed_header(name: &str) -> String {
    format!("H({})", field_label(name))
}

/// The `404 not_found` to an unsigned read of an identity the service doesn't host (Dispatch
/// wire 7.3 step 2, 7.6), signed with the service key, the public read binding no header.
const NOT_HOSTED: &str = "anyone: an identity the service doesn't host, 404 not_found with hosted false, signed with the service key, no head";

/// A request as the service received it (Dispatch wire 7.1), owned.
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

/// The named request or the unsigned public read as the service received it (Dispatch wire 7.1).
pub fn answered(keys: &Keys, file: &Value, case: &Value) -> Received {
    let name = st(case, "name");
    if let Some(request) = case["request"].as_str() {
        let request = arr(file, "requests")
            .iter()
            .find(|r| r["name"] == request)
            .unwrap_or_else(|| panic!("{name}: no request {request}"));
        return Received::of_request(request);
    }
    unsigned_read(keys, case)
}

fn unsigned_read(keys: &Keys, case: &Value) -> Received {
    let account = enc::pubky_id(&keys.identity(st(case, "read_account")));
    Received {
        method: "GET".into(),
        path_and_query: format!("/v1/{account}/identity"),
        body: BodyField::read(b""),
        origin: st(case, "read_origin").into(),
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
    let fields = pubky_dispatch_core::enc::split_lp(&bytes).unwrap();
    let mut names =
        Vec::from(["method", "path and query", "body field", "dispatch origin"].map(str::to_owned));
    names.extend(http::RECEIVED_HEADERS.map(hashed_header));
    serde_json::json!({
        "bytes_hex": hex::encode(&bytes),
        "fields": named_fields(&names, &fields),
    })
}

/// Bind the exact received request to the response signature.
fn signed_for(key: &SigningKey, mut case: Value, received: &Received) -> Value {
    let fields = http::response_fields(&parts_of(&case, received));
    let signature = sig::sign(key, labels::sig::HTTP_RESPONSE, &refs(&fields));
    let b64 = pubky_dispatch_core::enc::b64;
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

/// A request case signed with `key` over `target` and `headers` (Dispatch wire 7.1), in the
/// file's form.
fn request_case(
    input: &Value,
    key: &ed25519_dalek::SigningKey,
    target: &RequestTarget<'_>,
    headers: &RequestHeaders,
) -> Value {
    use pubky_dispatch_core::enc;
    let fields = http::request_fields(target, headers);
    let signature = sig::sign(key, labels::sig::HTTP, &refs(&fields));
    let mut sent = serde_json::json!({
        (http::header::IDENTITY): headers.identity,
        (http::header::SIGNATURE): enc::b64(&signature),
        (http::header::TIMESTAMP): headers.timestamp,
    });
    for (name, value) in [
        (http::header::APP, &headers.app),
        (http::header::CERT, &headers.cert),
        (http::header::INVITE_CODE, &headers.invite_code),
        (http::header::CREATED, &headers.created),
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
        "name": st(input, "name"),
        "origin": target.origin,
        "path": target.path_and_query,
        "public_key": enc::b64(&key.verifying_key().to_bytes()),
        "signature": enc::b64(&signature),
        "signed_bytes_hex": hex::encode(sig::signed_bytes(labels::sig::HTTP, &refs(&fields))),
    })
}

fn signature_case(case: &Value) {
    let names: Vec<_> = arr(case, "fields").iter().map(|f| st(f, "name")).collect();
    let fields = fields_of(case);
    crate::signatures::generated_case(
        st(case, "label"),
        &names,
        &refs(&fields),
        &b64n::<64>(st(case, "signature")),
    );
}

/// The request the named fixture response answers.
fn request_for<'a>(file: &'a Value, response: &str) -> &'a Value {
    let case = arr(file, "responses")
        .iter()
        .find(|r| r["name"] == response)
        .expect(response);
    arr(file, "requests")
        .iter()
        .find(|r| r["name"] == case["request"])
        .expect("answered request")
}

fn feed_after(request: &Value) -> Position {
    let (_, query) = st(request, "path").split_once('?').unwrap();
    Position::parse(
        query
            .split('&')
            .find_map(|p| p.strip_prefix("after="))
            .expect("feed after"),
    )
    .unwrap()
}

/// The request case `r` as `received` says the service received it (Dispatch wire 7.1): the
/// body not read where it says `"body": "not read"`, and the headers it lists, each a
/// `[name, value]` in the order received, in place of the case's own.
fn received_as(r: &Value, received: &Value) -> Received {
    let mut as_received = Received::of_request(r);
    if received["body"] == "not read" {
        as_received.body = BodyField::NotRead;
    }
    if let Some(headers) = received["headers"].as_array() {
        as_received.headers = ReceivedHeaders::of(headers.iter().map(|pair| {
            (
                pair[0].as_str().unwrap(),
                pair[1].as_str().unwrap().as_bytes(),
            )
        }));
    }
    as_received
}

/// The `[name, value]` pairs of the request case `r`'s headers, in the order the file
/// writes them, with `extra` after them.
fn header_pairs(r: &Value, extra: &[(&str, &str)]) -> Value {
    let mut pairs: Vec<Value> = r["headers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| serde_json::json!([name, value]))
        .collect();
    pairs.extend(
        extra
            .iter()
            .map(|(name, value)| serde_json::json!([name, value])),
    );
    Value::Array(pairs)
}

fn named_fields(names: &[impl AsRef<str>], fields: &[Vec<u8>]) -> Value {
    assert_eq!(names.len(), fields.len());
    names
        .iter()
        .zip(fields)
        .map(|(name, field)| {
            serde_json::json!({
                "hex": hex::encode(field),
                "name": field_label(name.as_ref()),
            })
        })
        .collect()
}

/// The account's creation time (Dispatch wire 3.7, 7.3): the time the enrollment that created
/// it was answered at, which its answer names in `created`.
fn created_of() -> u64 {
    time_of(&load("envelopes.json"), "account_created")
}

/// A later request signs an invite header over the original sender's envelope. The
/// service reports the invitation reference from the entry's acceptance (Dispatch wire 7.4.3).
#[test]
fn test_invitation_retry_preserves_original_entry_reference() {
    let http = load("http.json");
    let response = arr(&http, "responses")
        .iter()
        .find(|r| r["name"] == "own app: feed page with an entry and chain items")
        .unwrap();
    let page: Value = serde_json::from_str(st(response, "body")).unwrap();
    let entry = arr(&page, "items")
        .iter()
        .find(|e| e["type"] == "entry")
        .unwrap();
    let retry = arr(&http, "requests")
        .iter()
        .find(|r| {
            r["name"] == "app of another identity: append with an invite code and apps_version"
        })
        .unwrap();
    assert_eq!(retry["headers"][http::header::IDENTITY], entry["sender"]);
    assert_eq!(retry["body_b64"], entry["envelope"]);
    assert_eq!(
        retry["headers"][http::header::INVITE_CODE],
        super::identifiers::invite(&keys()).code
    );
    let accepted = pubky_dispatch_core::time::parse_rfc3339(st(entry, "accepted_at")).unwrap();
    let retried =
        pubky_dispatch_core::time::parse_rfc3339(st(&retry["headers"], http::header::TIMESTAMP))
            .unwrap();
    assert!(accepted < retried);
    assert_eq!(entry.get("invite_code_hash"), Some(&Value::Null));
}

/// The signed page binds each redeemed code to one entry from the same peer (Dispatch wire
/// 7.5). Open each envelope as the target, verify its sender, and reproduce the sealing.
#[test]
fn test_invitation_delivery_references() {
    use pubky_dispatch_core::enc;
    use pubky_dispatch_core::envelope::{Recipient, seal_with};
    use pubky_dispatch_core::export::Part;
    use pubky_dispatch_core::message::{MessagePlaintext, VerifiedSender};
    use pubky_dispatch_core::records::AppCert;

    let keys = keys();
    let http = load("http.json");
    let case = arr(&http, "responses")
        .iter()
        .find(|r| st(r, "name").contains("two invitations"))
        .unwrap();
    let wallet = keys.app("wallet");
    let received = answered(&keys, &http, case);
    let service = keys.service_key(&enc::pubky_id(&wallet.identity));
    let signature = b64n::<64>(st(case, "signature"));
    http::verify_response(&service, &parts_of(case, &received), &signature).unwrap();
    let page: Value = serde_json::from_str(st(case, "body")).unwrap();
    let head = pubky_dispatch_core::chain::SignedHead::from_value(&page["head"]).unwrap();
    head.verify(&service, &wallet.identity).unwrap();
    assert_eq!(head.to_header(), st(&case["headers"], http::header::HEAD));
    let after = feed_after(request_for(&http, st(case, "name")));
    assert_eq!((head.generation, head.seq), (after.generation, after.seq));
    let last = int(arr(&page, "items").last().unwrap(), "seq");
    assert_eq!(page["next"], format!("{}:{last}", head.generation));
    assert_eq!(int(&page, "scanned_through"), last);
    let answered_at =
        pubky_dispatch_core::time::parse_rfc3339(st(&case["headers"], http::header::SERVER_TIME))
            .unwrap();
    let entries = arr(&page, "items");
    let export = load("export.json");
    let pending_input = &export["pending_entry"];
    let chain = load("chain.json");
    let invite = arr(&chain["peer_admission"], "items")
        .iter()
        .find(|row| int(row, "seq") == int(pending_input, "invite_seq"))
        .unwrap();
    let inputs = arr(case, "items");
    assert_eq!(entries.len(), inputs.len());
    let mut messages = std::collections::HashSet::new();
    for (entry, input) in entries.iter().zip(inputs) {
        let (entry_input, message, expected) = match st(input, "source") {
            "message" => (
                input,
                &input["message"],
                input
                    .get("invite_seed_label")
                    .map(|_| enc::b64(&code_hash(input))),
            ),
            "pending entry" => (
                pending_input,
                pending_input,
                Some(enc::b64(&enc::hash(&seed16(invite, "code_seed_label")))),
            ),
            other => panic!("unknown invitation page item {other}"),
        };
        assert_eq!(int(entry, "seq"), int(entry_input, "seq"));
        assert_eq!(
            entry.get("invite_code_hash"),
            Some(&serde_json::json!(expected))
        );
        let sender = pubky(st(entry, "sender"));
        assert_eq!(sender, keys.identity("bob"));
        let cert = AppCert::verify(
            &serde_json::from_value(entry["cert"].clone()).unwrap(),
            &sender,
        )
        .unwrap();
        let accepted_at =
            pubky_dispatch_core::time::parse_rfc3339(st(entry, "accepted_at")).unwrap();
        assert!(accepted_at <= answered_at);
        assert!(!cert.expired_at(accepted_at));
        let bytes = b64(st(entry, "envelope"));
        let plaintext =
            MessagePlaintext::open(&bytes, &wallet.identity, &wallet.receive_secret).unwrap();
        let msg = plaintext
            .check(
                &wallet.identity,
                &sender,
                &VerifiedSender::from_cert(&cert),
                &[],
            )
            .unwrap();
        assert!(messages.insert(msg.msg_id));
        assert_eq!(
            st(entry, "entry_id"),
            enc::b64(&seed16(entry_input, "entry_seed_label"))
        );
        let fixed = fixed_from_seeds(st(message, "seal_seed_label"));
        let sealed = seal_with(
            &wallet.identity,
            &[Recipient::new(wallet.receive_public)],
            &plaintext.encode(),
            message["notify"].as_bool().unwrap(),
            &fixed.content_key,
            &fixed.nonce,
            &[fixed.ikm_e],
        )
        .unwrap();
        assert_eq!(bytes, sealed);
    }

    let honest = st(case, "body");
    let mut references = entries
        .iter()
        .filter_map(|e| e["invite_code_hash"].as_str());
    let first = references.next().unwrap();
    let second = references.next().unwrap();
    assert_ne!(first, second);
    assert!(references.next().is_none());
    let altered = honest.replacen(first, second, 1);
    let mut response = parts_of(case, &received);
    response.body = altered.as_bytes();
    assert!(http::verify_response(&service, &response, &signature).is_err());

    // The export carries the same entry ID, sender, envelope and invitation (Dispatch wire 10.3).
    let pending_json = st(pending_input, "json");
    let pending = Part::read(&serde_json::from_str(pending_json).unwrap()).unwrap();
    assert_eq!(pending.to_json().unwrap(), pending_json.as_bytes());
    let Part::Entry(pending) = pending else {
        panic!("an inbox entry");
    };
    let second = entries
        .iter()
        .find(|e| int(e, "seq") == pending.seq)
        .unwrap();
    assert_eq!(pending.seq, int(second, "seq"));
    assert_eq!(pending.sender, pubky(st(second, "sender")));
    assert_eq!(
        pending.targets,
        [enc::app_id_decode(&wallet.app_id).unwrap()]
    );
    assert_eq!(pending.result.entry_id, b64n::<16>(st(second, "entry_id")));
    assert_eq!(pending.envelope, b64(st(second, "envelope")));
    assert_eq!(
        pending.invite_code_hash,
        Some(b64n::<32>(st(second, "invite_code_hash")))
    );
}

/// The inputs shared by the enrollment answer and the records in a signer hand-over.
pub(super) fn enrollment_limits() -> Limits {
    let file = load("http.json");
    let answer = arr(&file, "responses")
        .iter()
        .find(|r| r["answer"] == "enrollment")
        .unwrap();
    serde_json::from_value(answer["limits"].clone()).unwrap()
}

struct Exchanges<'a> {
    keys: &'a Keys,
    docs: &'a HashMap<String, SignedDoc>,
    chain: &'a Chain,
    export: &'a ExportCases,
    handover: &'a SignerHandover,
    handover_app: &'a AppKeys,
    created: u64,
    saved: ChainTip,
}

/// Publish the wire members, keeping the case metadata, timestamp and expected status as inputs.
fn emit_exchange(path: &str, case: &Value) {
    let mut members = Vec::new();
    for (member, value) in case.as_object().unwrap() {
        match member.as_str() {
            "name" | "request" | "status" | "method" | "origin" => {}
            "headers" => {
                for (name, text) in value.as_object().unwrap() {
                    if !matches!(
                        name.as_str(),
                        http::header::TIMESTAMP | http::header::SERVER_TIME
                    ) {
                        members.push((format!("headers/{name}"), text.clone()));
                    }
                }
            }
            "path" | "label" | "body_b64" | "signature" | "signed_bytes_hex" | "public_key"
            | "fields" | "received" | "body" | "received_request" => {
                members.push((member.clone(), value.clone()))
            }
            other => panic!("unknown HTTP member {other}"),
        }
    }
    let members: Vec<_> = members
        .iter()
        .map(|(name, value)| (name.as_str(), value.clone()))
        .collect();
    generated_members("http.json", path, &members);
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
}

fn code_hash(input: &Value) -> [u8; 32] {
    pubky_dispatch_core::ident::invite_code_hash(&enc::b64(&seed16(input, "invite_seed_label")))
        .unwrap()
}

impl Exchanges<'_> {
    fn envelope(&self, input: &Value) -> Vec<u8> {
        use pubky_dispatch_core::envelope;
        let sender = self.keys.app(st(input, "sender"));
        let target = self.keys.app(st(input, "recipient"));
        let msg = signed_message(sender, target.identity, input);
        let random = fixed_from_seeds(st(input, "seal_seed_label"));
        envelope::seal_with(
            &target.identity,
            &[envelope::Recipient::new(target.receive_public)],
            &msg.encode(),
            input["notify"].as_bool().unwrap(),
            &random.content_key,
            &random.nonce,
            &[random.ikm_e],
        )
        .unwrap()
    }

    fn identity(&self, input: &Value) -> IdentityDoc {
        let doc = &self.docs[st(input, "document")];
        let identity = pubky(st(&doc.peek().unwrap(), "identity"));
        IdentityDoc::verify(doc, &identity).unwrap()
    }

    /// Apply only the changes selected for this delivery.
    fn delivery(&self, input: &Value) -> SignedDoc {
        let original = self.identity(input);
        let mut body = original.body().clone();
        if let Some(version) = input.get("version") {
            body.version = version.as_u64().unwrap();
        }
        assert_eq!(
            input.get("generation").is_some(),
            input.get("service_seed_label").is_some()
        );
        if input.get("service_seed_label").is_some() {
            body.generation = int(input, "generation");
            body.inbox.service_key =
                self.keys.http_signers.services[st(input, "service_seed_label")];
            body.service_keys.clear();
        }
        if input.get("signer_seed_label").is_some() {
            body.signer = seed16(input, "signer_seed_label");
        }
        if let Some(enabled) = input.get("enable_connect_requests") {
            body.policy.connect_requests.enabled = enabled.as_bool().unwrap();
        }
        IdentityDoc::sign(&self.keys.identity_key(&body.identity), body)
            .unwrap()
            .signed()
            .clone()
    }

    fn batch<'a>(&'a self, input: &Value) -> Vec<&'a Item> {
        strings(&input["operations"])
            .iter()
            .map(|source| self.chain.by_source(source))
            .collect()
    }

    fn request(&self, input: &Value) -> Value {
        let resource = st(input, "resource");
        let account = self.keys.identity(st(input, "account"));
        let account_id = enc::pubky_id(&account);
        let method = st(input, "method");
        let mut path = format!("/v1/{account_id}/{resource}");
        let mut body = Vec::new();
        match resource {
            "feed" => {
                let after = Position::parse(st(input, "after")).unwrap();
                path.push_str(&format!("?after={after}&limit={}", int(input, "limit")));
                if let Some(wait) = input.get("wait") {
                    path.push_str(&format!("&wait={}", wait.as_u64().unwrap()));
                }
            }
            "inbox" => {
                path.push_str(&format!("?apps_version={}", int(input, "apps_version")));
                body = self.envelope(&input["message"]);
            }
            "enroll" => {
                path = "/v1/enroll".into();
                body = Enrollment::verify(
                    &self.docs[st(input, "document")],
                    &account,
                    st(input, "origin"),
                )
                .unwrap()
                .to_request_json()
                .unwrap();
            }
            "identity" => {
                let previous = input
                    .get("previous_document")
                    .expect("previous identity")
                    .as_str()
                    .map(|name| enc::b64(&self.docs[name].doc_hash().unwrap()));
                body = serde_json::to_vec(&json!({
                    "identity": self.delivery(input),
                    "prev": previous,
                }))
                .unwrap();
            }
            "peers" => body = serde_json::to_vec(&self.delivery(input)).unwrap(),
            "erase" => {
                let followed = input
                    .get("document")
                    .map(|d| self.docs[d.as_str().unwrap()].doc_hash().unwrap());
                body = http::erase_body(Some(self.created), followed.as_ref());
            }
            "handover" if method == "PUT" => {
                body = serde_json::to_vec(&json!({
                    "app_id": self.handover_app.app_id,
                    "handover": self.handover,
                }))
                .unwrap()
            }
            "ops" => {
                body = serde_json::to_vec(&json!({
                    "ops": self.batch(input).iter().map(|r| &r.item).collect::<Vec<_>>(),
                }))
                .unwrap()
            }
            "chunk" => path = format!("/v1/{account_id}/export/chunks/{}", self.export.chunk.id),
            "directory" | "allow" | "handover" => {}
            other => panic!("unknown request resource {other}"),
        }
        let target = RequestTarget {
            method,
            path_and_query: &path,
            origin: st(input, "origin"),
            body: &body,
        };
        let timestamp = st(&input["headers"], http::header::TIMESTAMP);
        let caller = st(input, "caller");
        if caller == "transfer" {
            assert_eq!(resource, "chunk");
            let transfer = &self.export.transfer;
            assert_eq!(target.origin, transfer.body().from.url);
            let signer = &transfer.body().to.service_key;
            let headers = TransferHeaders {
                identity: account_id,
                timestamp: timestamp.into(),
                transfer: transfer.signed().compact(),
            };
            let fields = http::transfer_request_fields(&target, &headers);
            let key = SigningKey::from_bytes(&self.keys.secret(signer).unwrap());
            let signature = enc::b64(&sig::sign(
                &key,
                labels::sig::TRANSFER_REQUEST,
                &refs(&fields),
            ));
            return json!({
                "name": st(input, "name"),
                "label": labels::sig::TRANSFER_REQUEST,
                "method": method,
                "path": path,
                "origin": target.origin,
                "body_b64": enc::b64(&body),
                "headers": {
                    (http::header::IDENTITY): headers.identity,
                    (http::header::TRANSFER): headers.transfer,
                    (http::header::TIMESTAMP): timestamp,
                    (http::header::SIGNATURE): signature,
                },
                "public_key": enc::b64(signer),
                "signature": signature,
                "signed_bytes_hex": hex::encode(sig::signed_bytes(labels::sig::TRANSFER_REQUEST, &refs(&fields))),
                "fields": named_fields(&TRANSFER_FIELDS, &fields),
            });
        }
        let mut headers = RequestHeaders {
            timestamp: timestamp.into(),
            ..RequestHeaders::default()
        };
        let secret = if caller == "identity" {
            headers.identity = account_id;
            if resource != "enroll" {
                headers.created = Some(rfc3339(self.created));
            }
            self.keys.identity_secrets[&account]
        } else {
            let app = self.keys.app(caller);
            headers.identity = enc::pubky_id(&app.identity);
            headers.app = Some(app.app_id.clone());
            headers.cert = input
                .get("certificate")
                .map(|name| self.docs[name.as_str().unwrap()].compact());
            if input.get("invite_seed_label").is_some() {
                headers.invite_code = Some(enc::b64(&seed16(input, "invite_seed_label")));
            }
            app.signing_secret
        };
        request_case(input, &SigningKey::from_bytes(&secret), &target, &headers)
    }

    fn head(&self, case: &Value) -> Option<SignedHead> {
        let source = case.get("head_source")?.as_str().unwrap();
        let tip = match source {
            "saved" => self.saved,
            "chain" => self.chain.items.last().unwrap().tip(),
            "admission" => self.chain.peers.last().unwrap().tip(),
            other => panic!("unknown head {other}"),
        };
        let identity = self.keys.identity(st(case, "service_account"));
        Some(SignedHead::sign(
            &service_signer(self.keys, &identity),
            &identity,
            &tip,
        ))
    }

    fn feed_item(&self, item: &Value, requests: &HashMap<String, Value>) -> Value {
        match st(item, "source") {
            "chain" => {
                let row = self.chain.by_source(st(item, "operation"));
                let mut value = json!({
                    "type": "stub",
                    "seq": row.seq,
                    "stub": row.stub.to_value(),
                });
                if !self.chain.superseded_writes().contains(&row.seq) {
                    value["type"] = "chain".into();
                    value["item_type"] = row.item_type.as_str().into();
                    value["item"] = json!(row.item);
                    if row.item_type == ItemType::Op {
                        value["proof"] = json!(self.chain.proofs[&row.seq].signed());
                    }
                }
                value
            }
            "pending entry" => {
                let p = &self.export.pending;
                json!({
                    "type": "entry",
                    "seq": p.seq,
                    "entry_id": enc::b64(&p.result.entry_id),
                    "sender": enc::pubky_id(&p.sender),
                    "cert": p.cert,
                    "accepted_at": rfc3339(p.accepted_at_ms),
                    "invite_code_hash": p.invite_code_hash.map(|h| enc::b64(&h)),
                    "envelope": enc::b64(&p.envelope),
                })
            }
            source @ ("request" | "message") => {
                let (sender, cert, envelope) = if source == "request" {
                    let r = &requests[st(item, "request")];
                    (
                        st(&r["headers"], http::header::IDENTITY).to_owned(),
                        SignedDoc::from_compact(st(&r["headers"], http::header::CERT)).unwrap(),
                        st(r, "body_b64").to_owned(),
                    )
                } else {
                    let input = &item["message"];
                    let app = self.keys.app(st(input, "sender"));
                    (
                        enc::pubky_id(&app.identity),
                        self.docs[&format!("{} certificate", app.name)].clone(),
                        enc::b64(&self.envelope(input)),
                    )
                };
                json!({
                    "type": "entry",
                    "seq": int(item, "seq"),
                    "entry_id": enc::b64(&seed16(item, "entry_seed_label")),
                    "sender": sender,
                    "cert": cert,
                    "accepted_at": st(item, "accepted_at"),
                    "invite_code_hash": item.get("invite_seed_label").map(|_| enc::b64(&code_hash(item))),
                    "envelope": envelope,
                })
            }
            other => panic!("unknown feed item source {other}"),
        }
    }

    fn peer(&self, row: &Value) -> PeerEntry {
        let pubky = if row.get("identity_seed_label").is_some() {
            self.keys.http_signers.peers[st(row, "identity_seed_label")]
        } else {
            match st(row, "account") {
                "claims" => self.keys.claims.identity.public(),
                account => self.keys.identity(account),
            }
        };
        let reply = row
            .get("reply")
            .expect("reply grant")
            .as_str()
            .map(|writer| ReplyGrant {
                origin: if writer == "service" {
                    ReplyOrigin::Invite(code_hash(row))
                } else {
                    ReplyOrigin::App(enc::app_id_decode(&self.keys.app(writer).app_id).unwrap())
                },
                at: time_of(row, "at"),
                last_used: row.get("last_used").map(|_| time_of(row, "last_used")),
            });
        PeerEntry {
            pubky,
            kept: row["kept"].as_bool().unwrap(),
            reply,
        }
    }

    fn answer_body(
        &self,
        c: &Value,
        request: Option<&Value>,
        requests: &HashMap<String, Value>,
        head: Option<&SignedHead>,
    ) -> String {
        use http::ErrorCode;
        let name = st(c, "answer");
        let body = match name {
            "directory" => json!({
                "apps": strings(&c["apps"]).iter().map(|name| json!({
                    "app_id": self.keys.app(name).app_id,
                    "record": self.docs[&format!("{name} app record")],
                    "receive_key": self.docs[&format!("{name} receive key record")],
                })).collect::<Vec<_>>(),
                "apps_version": int(c, "apps_version"),
                "directory_version": int(c, "directory_version"),
                "identity": self.docs[st(c, "document")],
                "known_version": int(c, "known_version"),
            })
            .to_string(),
            "feed" => {
                let head = head.unwrap();
                let after = feed_after(request.unwrap());
                let mut items: Vec<_> = arr(c, "items")
                    .iter()
                    .map(|item| self.feed_item(item, requests))
                    .collect();
                items.sort_by_key(|item| int(item, "seq"));
                let scanned = int(c, "scanned_through");
                let mut last = after.seq;
                for item in &items {
                    let seq = int(item, "seq");
                    assert!(seq > last && seq <= scanned);
                    last = seq;
                }
                assert!(scanned >= after.seq);
                super::record_current::feed_page(&json!({
                    "items": items,
                    "next": Position { generation: after.generation, seq: scanned }.to_string(),
                    "scanned_through": scanned,
                    "more": c["more"].as_bool().unwrap(),
                    "cursor": int(c, "cursor"),
                    "head": head.to_value(),
                }))
            }
            "proofs" => {
                let bytes = b64(st(request.unwrap(), "body_b64"));
                let ops = pubky_dispatch_core::ops::OpsRequest::parse(&bytes).unwrap();
                let proofs: Vec<_> = ops
                    .signed()
                    .map(|op| {
                        let row = self.chain.items.iter().find(|row| &row.item == op).unwrap();
                        self.chain.proofs[&row.seq].signed()
                    })
                    .collect();
                super::record_current::write_answer(&json!({
                    "proofs": proofs,
                    "head": head.unwrap().to_value(),
                }))
            }
            "chunk" => text(self.export.chunk.to_json()),
            "enrollment" => {
                let r = request.unwrap();
                let enrollment = Enrollment::from_request(
                    &b64(st(r, "body_b64")),
                    &pubky(st(&r["headers"], http::header::IDENTITY)),
                    st(r, "origin"),
                )
                .unwrap();
                let service = self.keys.service_key(&enc::pubky_id(
                    &self.keys.identity(st(c, "service_account")),
                ));
                text(
                    EnrollmentAnswer::new(
                        &enrollment,
                        service,
                        serde_json::from_value(c["limits"].clone()).unwrap(),
                        self.created,
                    )
                    .to_json()
                    .unwrap(),
                )
            }
            "public identity" => {
                let mut body = json!({
                    "identity": self.docs[st(c, "document")],
                });
                if let Some(freeze) = c.get("freeze") {
                    body["freeze"] = json!(self.docs[freeze.as_str().unwrap()]);
                }
                body.to_string()
            }
            "erased" => text(http::ERASED_BODY.to_vec()),
            "known version" => {
                let held = self.identity(c);
                let delivered: SignedDoc =
                    serde_json::from_slice(&b64(st(request.unwrap(), "body_b64"))).unwrap();
                assert_eq!(held.signed(), &delivered);
                json!({
                    "known_version": held.version(),
                    "version": held.version(),
                })
                .to_string()
            }
            "handover" => json!({
                "app_id": self.handover_app.app_id,
                "handover": self.handover,
            })
            .to_string(),
            "stored handover" => json!({
                "app_id": self.handover_app.app_id,
                "parts": self.handover.envelopes().len(),
            })
            .to_string(),
            "peers" | "admission history" => {
                let rows = if name == "peers" {
                    let mut rows: Vec<_> =
                        arr(c, "peers").iter().map(|row| self.peer(row)).collect();
                    rows.sort_by_key(|row| enc::pubky_id(&row.pubky));
                    rows
                } else {
                    self.export.peers.clone()
                };
                let peers: Vec<_> = rows.iter().map(|p| text(p.to_json().unwrap())).collect();
                let mut fields = vec![("peers", format!("[{}]", peers.join(",")))];
                for list in ["deny", "flagged", "invite_codes"] {
                    let entries = arr(c, list);
                    assert!(entries.is_empty(), "{name}: peer grants only");
                    fields.push((list, serde_json::to_string(entries).unwrap()));
                }
                super::record_current::ordered_object(fields)
            }
            "stale key" => {
                let receive = |name: String| {
                    json!({
                        "app_id": self.keys.app(&name).app_id,
                        "record": self.docs[&format!("{name} receive key record")],
                    })
                };
                let added: Vec<_> = strings(&c["added_apps"])
                    .into_iter()
                    .map(|name| {
                        let record = &self.docs[&format!("{name} app record")];
                        let mut value = receive(name);
                        value["app_record"] = json!(record);
                        value
                    })
                    .collect();
                let current = json!({
                    "added_apps": added,
                    "apps_version": int(c, "apps_version"),
                    "not_current": strings(&c["not_current_apps"]).iter().map(|a| &self.keys.app(a).app_id).collect::<Vec<_>>(),
                    "receive_keys": strings(&c["receive_apps"]).into_iter().map(receive).collect::<Vec<_>>(),
                    "unknown_kids": strings(&c["unknown_kid_seed_labels"]).iter().map(|label| enc::b64(&seed(label)[..8])).collect::<Vec<_>>(),
                });
                return error_body(c, ErrorCode::StaleKey, Some(("current", current)));
            }
            "rate limit" => {
                return error_body(
                    c,
                    ErrorCode::RateLimited,
                    Some(("retry_after", json!(int(c, "retry_after")))),
                );
            }
            "not hosted" => {
                return error_body(
                    c,
                    ErrorCode::NotFound,
                    Some(("current", http::not_hosted_current())),
                );
            }
            "missing service key" | "stale peer" => {
                let (code, current) = if name == "missing service key" {
                    let mut generations: Vec<_> = arr(c, "proof_generations")
                        .iter()
                        .map(|v| v.as_u64().unwrap())
                        .collect();
                    generations.sort_unstable();
                    (
                        ErrorCode::Conflict,
                        json!({ "proof_generations": generations }),
                    )
                } else {
                    let held = self.identity(c);
                    (
                        ErrorCode::StaleIdentity,
                        json!({
                            "identity": held.signed(),
                            "version": held.version(),
                        }),
                    )
                };
                check_error(c, code);
                return json!({
                    "code": code.as_str(),
                    "current": current,
                    "message": st(c, "message"),
                })
                .to_string();
            }
            "stale delivery" => {
                let held = self.identity(c);
                let current = json!({
                    "generation": held.generation(),
                    "hash": enc::b64(&held.hash()),
                    "identity": held.signed(),
                    "version": held.version(),
                });
                return error_body(c, ErrorCode::StaleIdentity, Some(("current", current)));
            }
            "stale erasure" => {
                return error_body(
                    c,
                    ErrorCode::Conflict,
                    Some((
                        "current",
                        json!({
                            "created": rfc3339(self.created),
                        }),
                    )),
                );
            }
            other => panic!("unknown response {other}"),
        };
        assert_eq!(int(c, "status"), 200, "{name}");
        body
    }
}

fn check_error(c: &Value, code: http::ErrorCode) {
    assert_eq!(st(c, "code"), code.as_str(), "{}", st(c, "name"));
    assert_eq!(
        int(c, "status"),
        u64::from(code.status()),
        "{}",
        st(c, "name")
    );
}

/// The refusal encoder writes the code and message before its optional detail.
fn error_body(c: &Value, code: http::ErrorCode, detail: Option<(&str, Value)>) -> String {
    check_error(c, code);
    let mut fields = vec![
        ("code", json!(code.as_str()).to_string()),
        ("message", json!(st(c, "message")).to_string()),
    ];
    if let Some((name, value)) = detail {
        fields.push((name, value.to_string()));
    }
    super::record_current::ordered_object(fields)
}

impl Exchanges<'_> {
    fn response(&self, c: &Value, requests: &HashMap<String, Value>, received_case: bool) -> Value {
        let request = c
            .get("request")
            .expect("answered request")
            .as_str()
            .map(|name| &requests[name]);
        let mut received =
            request.map_or_else(|| unsigned_read(self.keys, c), Received::of_request);
        let mut headers = json!({
            (http::header::SERVER_TIME): st(&c["headers"], http::header::SERVER_TIME),
        });
        let mut change = None;
        if c["answer"] == "public identity" {
            // Wire 7.4.15: "a `200` carries `Cache-Control: public, max-age=60, must-revalidate`."
            assert_eq!(
                st(&c["headers"], "cache-control"),
                "public, max-age=60, must-revalidate"
            );
        }
        let body = if received_case {
            use http::ErrorCode;
            let request = request.unwrap();
            let (fault, code) = match st(c, "fault") {
                // Wire 7.1: "a larger one is `413 too_large`, before the body is read".
                "unread body" => (
                    json!({
                        "body": "not read",
                    }),
                    ErrorCode::TooLarge,
                ),
                // Wire 7.1: a header "more than once, or ... with an empty value or with a byte
                // outside printable ASCII (0x20 to 0x7E), is `400 bad_request`".
                "empty header" | "duplicate header" => {
                    let name = st(c, "header");
                    let value = if c["fault"] == "empty header" {
                        ""
                    } else {
                        st(&request["headers"], name)
                    };
                    (
                        json!({
                            "headers": header_pairs(request, &[(name, value)]),
                        }),
                        ErrorCode::BadRequest,
                    )
                }
                // Wire 7.6 gives 503 unavailable for "a temporary failure". The empty
                // head is the independent wire 7.1 fault on that signed answer.
                "empty head" => {
                    headers[http::header::HEAD] = "".into();
                    (json!({}), ErrorCode::Unavailable)
                }
                other => panic!("unknown received request fault {other}"),
            };
            received = received_as(request, &fault);
            change = Some(fault);
            error_body(c, code, None)
        } else {
            let head = self.head(c);
            if let Some(head) = &head {
                headers[http::header::HEAD] = head.to_header().into();
            }
            self.answer_body(c, request, requests, head.as_ref())
        };
        let service = service_signer(self.keys, &self.keys.identity(st(c, "service_account")));
        let mut case = json!({
            "body": body,
            "headers": headers,
            "label": labels::sig::HTTP_RESPONSE,
            "name": st(c, "name"),
            "public_key": enc::b64(&service.verifying_key().to_bytes()),
            "request": c["request"],
            "status": int(c, "status"),
        });
        if let Some(change) = change {
            case["received"] = change;
        }
        signed_for(&service, case, &received)
    }
}

fn webhook(keys: &Keys, case: &Value) {
    let key = service_signer(keys, &keys.identity(st(case, "account")));
    let url = st(case, "relay_url");
    let body = http::webhook_body(
        &enc::b64(&seed16(case, "handle_seed_label")),
        time_of(case, "timestamp"),
        &seed16(case, "nonce_seed_label"),
    );
    let signature = http::sign_webhook(&key, url, &body).unwrap();
    generated_members(
        "http.json",
        "/webhook",
        &[
            ("body", json!(text(body))),
            (
                "service_key",
                json!(enc::b64(&key.verifying_key().to_bytes())),
            ),
            ("relay_origin", json!(http::relay_origin(url).unwrap())),
            ("headers/content-type", json!("application/json")),
            (
                &format!("headers/{}", http::header::SIGNATURE),
                json!(enc::b64(&signature)),
            ),
        ],
    );
}

pub(super) fn http_cases(
    keys: &Keys,
    docs: &HashMap<String, SignedDoc>,
    chain: &Chain,
    export: &ExportCases,
    handover: &SignerHandover,
) {
    let file = load("http.json");
    super::generation::check_annotations("http.json", &file);
    super::documents::enrollment_cases(keys, docs);
    let env = load("envelopes.json");
    let saved = &file["saved_head"];
    let position = Position::parse(st(saved, "position")).unwrap();
    let exchanges = Exchanges {
        keys,
        docs,
        chain,
        export,
        handover,
        handover_app: keys.app(st(&env["signer_handover"], "app")),
        created: time_of(&env, "account_created"),
        saved: ChainTip {
            generation: position.generation,
            seq: position.seq,
            chain_hash: seed(st(saved, "hash_seed_label")),
        },
    };
    let mut requests = HashMap::new();
    for (i, input) in arr(&file, "requests").iter().enumerate() {
        let case = exchanges.request(input);
        emit_exchange(&format!("/requests/{i}"), &case);
        if case["name"] == "own app: long-poll feed read" {
            signature_case(&case);
        }
        assert!(
            requests
                .insert(st(input, "name").to_owned(), case)
                .is_none()
        );
    }
    for group in ["responses", "received_cases"] {
        for (i, input) in arr(&file, group).iter().enumerate() {
            let case = exchanges.response(input, &requests, group == "received_cases");
            emit_exchange(&format!("/{group}/{i}"), &case);
            if case["name"] == "own app: feed page, with the head header" {
                signature_case(&case);
            }
        }
    }
    webhook(keys, &file["webhook"]);
}

#[test]
fn test_vectors_http() {
    let keys = keys();
    let docs = super::documents::issue_documents();
    let chain = super::chain::chain_cases(&keys, &docs);
    let export = super::export::export_cases(&keys, &docs, &chain);
    let (handover, _) = super::envelopes::envelope_cases();
    http_cases(&keys, &docs, &chain, &export, &handover);
    let v = load("http.json");
    // The answers to a request received otherwise than sent: each verifies for the request
    // as received, never for the request case as sent (Dispatch wire 7.1).
    let received = arr(&v, "received_cases");
    assert_eq!(
        received.len(),
        4,
        "http.json: /received_cases, one per fault"
    );
    for r in received {
        let name = st(r, "name");
        let sent = arr(&v, "requests")
            .iter()
            .find(|q| q["name"] == r["request"])
            .unwrap();
        let as_received = received_as(sent, &r["received"]);
        // The core's own header check, the one a service and a client run, decides the two
        // header faults: `400 bad_request` (Dispatch wire 7.1 "Each header once, as text").
        let broken = as_received.headers.broken_rule();
        match st(r, "fault") {
            "duplicate header" | "empty header" => {
                let rule = if r["fault"] == "duplicate header" {
                    "7.1: a signed request header sent more than once"
                } else {
                    "7.1: a signed request header with an empty value"
                };
                assert_eq!(broken, Some(rule), "{name}");
                let refused = http::ErrorCode::BadRequest;
                assert_eq!(st(r, "code"), refused.as_str(), "{name}");
                assert_eq!(int(r, "status"), u64::from(refused.status()), "{name}");
            }
            "unread body" | "empty head" => assert_eq!(broken, None, "{name}"),
            other => panic!("{name}: unknown received fault {other}"),
        }
        let bytes = http::received_request(&as_received.request());
        assert_eq!(
            hex::encode(&bytes),
            st(&r["received_request"], "bytes_hex"),
            "{name}"
        );
        assert_eq!(
            pubky_dispatch_core::enc::split_lp(&bytes).unwrap(),
            fields_of(&r["received_request"]),
            "{name}"
        );
        let signature =
            http::decode_signature(header(r, http::header::SERVICE_SIGNATURE).unwrap()).unwrap();
        let public = b64n::<32>(st(r, "public_key"));
        let parts = parts_of(r, &as_received);
        assert_eq!(http::response_fields(&parts), fields_of(r), "{name}");
        http::verify_response(&public, &parts, &signature)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let honest = Received::of_request(sent);
        let as_sent = parts_of(r, &honest);
        let differs = bytes != http::received_request(&honest.request());
        assert_eq!(
            http::verify_response(&public, &as_sent, &signature).is_ok(),
            !differs,
            "{name}"
        );
    }
    // The fields an independent implementation most often gets wrong: the empty body field,
    // a header present with an empty value, a header sent twice, a present empty head.
    let fault = |name: &str| received.iter().find(|case| case["fault"] == name).unwrap();
    let field = |carrier: &Value, name: &str| {
        let f = arr(carrier, "fields")
            .iter()
            .find(|f| f["name"] == name)
            .unwrap();
        hx(st(f, "hex"))
    };
    assert!(field(&fault("unread body")["received_request"], "body field").is_empty());
    assert_eq!(
        field(
            &fault("empty header")["received_request"],
            &hashed_header(http::header::INVITE_CODE)
        ),
        vec![0; 4]
    );
    assert_eq!(
        enc::split_lp(&field(
            &fault("duplicate header")["received_request"],
            &hashed_header(http::header::TIMESTAMP)
        ))
        .unwrap()
        .len(),
        2
    );
    assert_eq!(field(fault("empty head"), "head field"), enc::hash(b""));
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
                "{name}: no Dispatch-App"
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
                created: header(r, http::header::CREATED).map(str::to_owned),
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
            // A signer call carries no Dispatch-App; an app's does.
            assert_eq!(
                headers.app.is_some(),
                !name.starts_with("signer"),
                "{name}: Dispatch-App"
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
        // The timestamp is written to the second (Dispatch wire 1.6).
        let timestamp = header(r, http::header::TIMESTAMP).unwrap();
        let ms = pubky_dispatch_core::time::parse_rfc3339(timestamp).unwrap();
        assert_eq!(
            pubky_dispatch_core::time::rfc3339_seconds(ms),
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
    let created = created_of();
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
            // The hand-over the signer stores for its target app (Dispatch wire 7.4.17).
            let value: Value = serde_json::from_slice(&body).unwrap();
            let target = keys.app_by_id(st(&value, "app_id"));
            let handover = handover_of(&value["handover"]);
            let target_id = pubky_dispatch_core::enc::app_id_decode(&target.app_id).unwrap();
            handover
                .check_stored(&alice, &target_id, &target.bundle_public)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            // Stored for another app, it fails.
            let other = keys.app("wallet");
            let other_id = pubky_dispatch_core::enc::app_id_decode(&other.app_id).unwrap();
            assert!(
                handover
                    .check_stored(&alice, &other_id, &other.bundle_public)
                    .is_err()
            );
        } else if call.ends_with("/erase") {
            // Each names the account's creation time, the one its enrollment answer gives
            // (Dispatch wire 7.4.16, 3.7).
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
        // The request it answers, as the service received it (Dispatch wire 7.1).
        let received = answered(&keys, &v, r);
        let request = received.request();
        let bytes = http::received_request(&request);
        assert_eq!(
            hex::encode(&bytes),
            st(&r["received_request"], "bytes_hex"),
            "{name}: received request"
        );
        assert_eq!(
            pubky_dispatch_core::enc::split_lp(&bytes).unwrap(),
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
            // The account's creation time, the time it was answered at (Dispatch wire 3.7).
            assert_eq!(answer.created, created, "{name}");
        }
        if name.starts_with("signer: account erasure refused") {
            // Every `409` to an erasure carries the creation time it was checked against
            // (Dispatch wire 7.4.16).
            let parsed: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(
                parsed["current"]["created"],
                pubky_dispatch_core::time::rfc3339(created),
                "{name}"
            );
        }
        if name.starts_with("own app: the hand-over the dispatch stores") {
            // The fetch answers the stored body as it was put.
            let value: Value = serde_json::from_slice(body).unwrap();
            let target = keys.app_by_id(st(&value, "app_id"));
            let target_id = pubky_dispatch_core::enc::app_id_decode(&target.app_id).unwrap();
            handover_of(&value["handover"])
                .verify(&alice, &target_id)
                .unwrap();
        }
        if name.starts_with("signer: account erasure answer") {
            assert_eq!(body, http::ERASED_BODY);
        }
        // No answer to an enrollment or an erasure carries a head (Dispatch wire 7.1).
        if name.starts_with("signer: enrollment answer")
            || name.starts_with("signer: account erasure")
        {
            assert!(header(r, http::header::HEAD).is_none(), "{name}: no head");
        }
        if matches!(st(r, "answer"), "peers" | "admission history") {
            let page: Value = serde_json::from_slice(body).unwrap();
            assert!(
                arr(&page, "peers")
                    .windows(2)
                    .all(|pair| st(&pair[0], "pubky") < st(&pair[1], "pubky")),
                "{name}: peer order"
            );
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
    // The body as the Dispatch writes it, from its handle, time and nonce.
    let parsed: Value = serde_json::from_slice(body).unwrap();
    let rebuilt = http::webhook_body(
        st(&parsed, "handle"),
        pubky_dispatch_core::time::parse_rfc3339(st(&parsed, "ts")).unwrap(),
        &b64n::<16>(st(&parsed, "nonce")),
    );
    assert_eq!(rebuilt, body);
    assert!(
        http::verify_webhook(&key, "https://elsewhere.example/v1/hook", body, &signature).is_err()
    );
}
