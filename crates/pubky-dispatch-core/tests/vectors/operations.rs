//! `operations.json`: every operation type signed by its writer, the `POST /ops` body, the
//! operations to refuse for an unknown member at any depth, the batch entries to refuse, the
//! integer bounds and the attempt deadlines (Dispatch wire 6.1 to 6.4).
//!
//! Every operation is verified for its writer, read, written again from what was read and
//! signed again from the fixed keys, byte for byte; its shape and its writer's permission
//! are checked, and every sealed value opens with the identity's scope key.

mod bodies;

use std::collections::HashMap;

use pubky_dispatch_core::claims::{ClaimEntry, EntryKind, attempt_deadline};
use pubky_dispatch_core::enc::{app_id_decode, b64 as b64e};
use pubky_dispatch_core::keys::{AppKeys as DispatchAppKeys, IdentityKey};
use pubky_dispatch_core::labels;
use pubky_dispatch_core::ops::{
    self, Entry, OpKind, OpsRequest, Refusal, SignedOp, Writer, check_batch, check_permission,
    check_shape,
};
use pubky_dispatch_core::records::AppCert;
use pubky_dispatch_core::sealed::{NONCE_LEN, RecordValue, SealedValue};
use pubky_dispatch_core::sig::SignedDoc;
use pubky_dispatch_core::time::{parse_rfc3339, rfc3339};
use serde_json::{Value, json};

use crate::common::*;

/// The writer's verifying key and App ID: an app's signing key, or the identity key for the
/// signer.
fn writer_of(keys: &Keys, writer: &str, identity: &[u8; 32]) -> ([u8; 32], Option<[u8; 16]>) {
    if writer == "signer" {
        return (*identity, None);
    }
    let app = keys.app(writer);
    (
        app.signing_public,
        Some(app_id_decode(&app.app_id).unwrap()),
    )
}

fn signed_of(value: &Value) -> SignedDoc {
    serde_json::from_value(value.clone()).unwrap()
}

#[test]
pub(super) fn test_vectors_operations() {
    let keys = keys();
    let v = load("operations.json");
    let operations = arr(&v, "operations");
    assert!(!operations.is_empty());
    let mut by_name: HashMap<String, SignedOp> = HashMap::new();
    let mut identity = None;
    for o in operations {
        let name = st(o, "name");
        let body_text = st(o, "body");
        let signed = signed_of(&o["signed"]);
        assert_eq!(
            signed.body,
            b64e(body_text.as_bytes()),
            "{name}: carrying body"
        );
        let raw: Value = serde_json::from_str(body_text).unwrap();
        let id = pubky(st(&raw, "identity"));
        identity = Some(id);
        let (writer_key, app_id) = writer_of(&keys, st(o, "writer"), &id);

        // Verified for its writer (Dispatch wire 6.4 step 3), read, and written again.
        let op = SignedOp::verify(&signed, &writer_key, &id, app_id.as_ref())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            op.body().to_json().unwrap(),
            body_text.as_bytes(),
            "{name}: body rebuilt"
        );
        assert_eq!(op.body().kind.name(), st(&raw, "op"), "{name}: type");
        // Signed again from the fixed key, byte for byte.
        assert!(reproduce(
            &keys,
            &writer_key,
            labels::sig::OP,
            &[&id, body_text.as_bytes()],
            &signed.sig_bytes().unwrap()
        ));
        let secret = keys.secret(&writer_key).unwrap();
        let again = if app_id.is_some() {
            let app = keys.app(st(o, "writer"));
            let dispatch_keys =
                DispatchAppKeys::from_secrets(app.signing_secret, app.bundle_secret);
            SignedOp::sign(&dispatch_keys, op.body().clone()).unwrap()
        } else {
            SignedOp::sign(&IdentityKey::from_secret(secret), op.body().clone()).unwrap()
        };
        assert_eq!(again.signed(), &signed, "{name}: signed again");
        assert!(op.carrying_len() <= ops::MAX_OP_BYTES);

        // Its shape (Dispatch wire 6.4 step 9) holds: keys derive, bundles and certificates
        // verify, claim entries are well formed.
        check_shape(op.body()).unwrap_or_else(|e| panic!("{name}: shape: {e}"));
        if let OpKind::Claim(fields) = &op.body().kind {
            fields.check().unwrap();
        }
        // A sealed value opens with the identity's scope key of its data epoch.
        if let OpKind::RecordPut(put) = &op.body().kind {
            let sealed = &put.value_sealed;
            let key = IdentityKey::from_secret(keys.identity_secrets[&id])
                .scope_key(sealed.data_epoch, &sealed.scope);
            let value = sealed.open(&key, &id, &put.key).unwrap();
            assert_eq!(
                matches!(value, RecordValue::Delete),
                name.contains("delete"),
                "{name}: delete"
            );
        }
        by_name.insert(name.to_owned(), op);
    }
    let identity = identity.unwrap();
    let docs = super::documents::issue_documents();
    check_permissions(&keys, &docs, &by_name, &identity);
    check_batches(&by_name);
    let chain = super::chain::chain_cases(&keys, &docs);
    let (_, bundle) = super::envelopes::envelope_cases();
    let ids = super::identifiers::identifier_cases(&keys);
    operation_cases(&keys, &chain, &docs, &bundle, &ids);
}

/// Read each published carrier under its writer's grant (Dispatch wire 6.2, 6.4).
#[test]
fn test_vectors_record_operation_scopes() {
    let docs = super::documents::IssuedDocuments::from_fixture(&keys());
    for case in arr(&load("operations.json")["record_scopes"], "cases") {
        let name = st(case, "name");
        let cert = &docs.certs[st(case, "writer")];
        let signed = signed_of(&case["signed"]);
        let op = SignedOp::verify(
            &signed,
            &cert.signing_key(),
            &cert.identity(),
            Some(&cert.app_id()),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            op.body().to_json().unwrap(),
            st(case, "body").as_bytes(),
            "{name}"
        );
        check_record_submission(case, &op, cert);
    }
}

fn check_record_submission(case: &Value, op: &SignedOp, cert: &AppCert) {
    let name = st(case, "name");
    match ops::check_submission(op.body(), Writer::App(cert), cert.issued_at()) {
        Ok(()) => {
            assert_eq!(case["expect"], json!({"valid": true}), "{name}");
            assert_eq!(int(case, "success_status"), 200, "{name}");
        }
        Err(refused) => assert_eq!(
            case["expect"],
            json!({
                "status": refused.status(),
                "code": refused.code.as_str(),
            }),
            "{name}",
        ),
    }
}

/// The operation text and its two carrying members (Dispatch wire 6.1).
pub(super) fn emit_signed(path: &str, signed: &SignedDoc) {
    generated_members(
        "operations.json",
        path,
        &[(
            "body",
            json!(String::from_utf8(signed.body_bytes().unwrap()).unwrap()),
        )],
    );
    generated_members(
        "operations.json",
        &format!("{path}/signed"),
        &[("body", json!(signed.body)), ("sig", json!(signed.sig))],
    );
}

fn deny_cases(v: &Value) {
    use pubky_dispatch_core::{enc::pubky_id, ops::MAX_DENY, recovery::check_deny_room};
    for (i, c) in arr(&v["deny_room"], "cases").iter().enumerate() {
        let path = format!("/deny_room/cases/{i}");
        let peers = |input: &str, member: &str| -> Vec<[u8; 32]> {
            let peers: Vec<_> = arr(c, input)
                .iter()
                .map(|n| [u8::try_from(n.as_u64().unwrap()).unwrap(); 32])
                .collect();
            let ids = peers.iter().map(|p| json!(pubky_id(p))).collect();
            generated_members("operations.json", &path, &[(member, ids)]);
            peers
        };
        let held = peers("held_bytes", "held");
        let uploaded = peers("uploaded_bytes", "uploaded");
        // How far the held list is below the limit is the case's choice; the count follows MAX_DENY.
        let held_count = MAX_DENY - int(c, "free_slots");
        generated_members(
            "operations.json",
            &path,
            &[
                ("max_deny", json!(MAX_DENY)),
                ("held_count", json!(held_count)),
            ],
        );
        match check_deny_room(held_count, &uploaded, |p| held.contains(p)) {
            Ok(()) => assert_eq!(int(&c["expect"], "status"), 200),
            Err(refusal) => {
                expect_refusal(c, &refusal, st(c, "name"));
                assert_eq!(refusal.current.as_ref(), Some(&c["expect"]["current"]));
            }
        }
    }
}

/// Source of the record bytes shared by the shape and permanent-policy examples.
struct RecordCases<'a> {
    keys: &'a Keys,
    create: &'a ops::OpBody,
    name: &'a str,
    natural: Vec<u8>,
}

impl RecordCases<'_> {
    fn put(&self) -> ops::RecordPut {
        let OpKind::RecordPut(put) = &self.create.kind else {
            panic!("record create")
        };
        put.clone()
    }

    fn key(&self, policy: &pubky_dispatch_core::ident::Policy) -> [u8; 32] {
        record_address(
            self.keys,
            &self.create.identity,
            self.name,
            &self.natural,
            policy,
        )
        .1
    }

    fn seal(&self, put: &mut ops::RecordPut, case: &Value, value: &[u8]) {
        let sealed = &put.value_sealed;
        put.value_sealed = seal_record(
            &self.keys.identity_key(&self.create.identity),
            sealed.data_epoch,
            &sealed.scope,
            &put.key,
            case,
            value,
        );
    }
}

fn seal_record(
    identity: &IdentityKey,
    epoch: u64,
    scope: &str,
    key: &[u8; 32],
    case: &Value,
    value: &[u8],
) -> SealedValue {
    let nonce = seed(st(case, "nonce_seed_label"))[..NONCE_LEN]
        .try_into()
        .unwrap();
    let scope_key = identity.scope_key(epoch, scope);
    let id = identity.public();
    SealedValue::seal_with_nonce(&scope_key, &id, epoch, scope, key, value, &nonce).unwrap()
}

fn shape_cases(v: &Value, records: &RecordCases<'_>, bundle: &ops::KeyBundlePut) {
    for (i, c) in arr(&v["shape_rejections"], "cases").iter().enumerate() {
        let name = st(c, "name");
        let base = arr(v, "operations")
            .iter()
            .find(|op| op["name"] == c["based_on"])
            .unwrap();
        let mut body = records.create.clone();
        body.kind = match st(base, "name") {
            "key_bundle.put" => {
                let mut put = bundle.clone();
                match name {
                    "key_bundle.put: first_epoch 0" => put.first_epoch = 0,
                    "key_bundle.put: first_epoch above last_epoch" => {
                        put.first_epoch = put.last_epoch;
                        put.last_epoch -= 1;
                    }
                    other => panic!("unknown bundle shape {other}"),
                }
                body.app_id = None;
                body.batch.id = seed16(base, "batch_seed_label");
                OpKind::KeyBundlePut(put)
            }
            "record.put create" | "record.put delete" => {
                assert_eq!(
                    base["name"] == "record.put delete",
                    name == "record.put: a delete at a permanent policy"
                );
                let mut put = records.put();
                match name {
                    "record.put: read_scope with a NUL character" => {
                        put.policy.read_scope.push('\0');
                        put.value_sealed.scope.clone_from(&put.policy.read_scope);
                    }
                    "record.put: read_scope in upper case" => {
                        put.policy.read_scope = put.policy.read_scope.to_uppercase();
                        put.value_sealed.scope.clone_from(&put.policy.read_scope);
                    }
                    "record.put: a write_scopes entry that isn't a scope" => {
                        put.policy
                            .write_scopes
                            .push(format!("{}:", put.policy.write_scopes.first().unwrap()));
                    }
                    "record.put: a delete at a permanent policy" => {
                        // Wire 6.4 checks conditions before shapes. This delete has no claim guard.
                        put.id_inputs = None;
                        put.expected_version =
                            ops::RecordVersion::new(body.generation, int(base, "previous_version"));
                        records.seal(&mut put, base, b"");
                        body.batch.id = seed16(base, "batch_seed_label");
                        put.policy = put.policy.permanent(None);
                    }
                    "record.put: a create at a permanent policy of another generation" => {
                        put.policy = put.policy.permanent(Some(body.generation + 1));
                    }
                    other => panic!("unknown record shape {other}"),
                }
                put.key = records.key(&put.policy);
                OpKind::RecordPut(put)
            }
            other => panic!("unknown shape source {other}"),
        };
        assert_eq!(c["writer"], base["writer"]);
        let (public, app_id) = writer_of(records.keys, st(c, "writer"), &body.identity);
        let signer = ed25519_dalek::SigningKey::from_bytes(&records.keys.secret(&public).unwrap());
        let op = SignedOp::sign(&signer, body).unwrap();
        let read =
            SignedOp::verify(op.signed(), &public, &op.body().identity, app_id.as_ref()).unwrap();
        let refused = check_shape(read.body()).expect_err(name);
        expect_refusal(c, &refused, name);
        assert_eq!(quoted(&refused.reason), st(c, "rule"));
        emit_signed(&format!("/shape_rejections/cases/{i}"), op.signed());
    }
}

fn permanent_cases(v: &Value, records: &RecordCases<'_>) {
    let section = &v["permanent_policies"];
    let identity = &records.create.identity;
    let base = records.put();
    let sealed = &base.value_sealed;
    let scope_key = records
        .keys
        .identity_key(identity)
        .scope_key(sealed.data_epoch, &sealed.scope);
    let RecordValue::Json(value) = sealed.open(&scope_key, identity, &base.key).unwrap() else {
        panic!("the create writes a value")
    };
    let mut accepted = HashMap::new();
    for (i, c) in arr(section, "cases").iter().enumerate() {
        assert_eq!(c["based_on"], "record.put create");
        let mut body = records.create.clone();
        let mut put = base.clone();
        let generation = serde_json::from_value(c["generation"].clone()).unwrap();
        put.policy = put.policy.permanent(generation);
        put.key = records.key(&put.policy);
        records.seal(&mut put, c, &value);
        assert_eq!(
            put.value_sealed
                .open(&scope_key, identity, &put.key)
                .unwrap(),
            RecordValue::Json(value.clone())
        );
        body.kind = OpKind::RecordPut(put);
        body.batch.id = seed16(c, "batch_seed_label");
        let (public, app_id) = writer_of(records.keys, st(c, "writer"), identity);
        let signer = ed25519_dalek::SigningKey::from_bytes(&records.keys.secret(&public).unwrap());
        let op = SignedOp::sign(&signer, body).unwrap();
        let read = SignedOp::verify(op.signed(), &public, identity, app_id.as_ref()).unwrap();
        assert_eq!(
            check_shape(read.body()).is_ok(),
            c["expect"]["valid"].as_bool().unwrap()
        );
        emit_signed(&format!("/permanent_policies/cases/{i}"), op.signed());
        assert!(accepted.insert(st(c, "name"), (op, generation)).is_none());
    }
    for (i, c) in arr(section, "rejections").iter().enumerate() {
        let (op, generation) = &accepted[st(c, "based_on")];
        let text = String::from_utf8(op.body().to_json().unwrap()).unwrap();
        let member = format!(r#""permanent":{{"generation":{}}}"#, json!(generation));
        assert_eq!(text.matches(&member).count(), 1);
        let written = format!(r#""permanent":{}"#, st(c, "permanent"));
        let body = text.replace(&member, &written);
        let path = format!("/permanent_policies/rejections/{i}");
        let refused =
            signed_variant(records.keys, c, identity, op, body.into_bytes(), &path).unwrap_err();
        expect_refusal(c, &refused, st(c, "name"));
    }
}

fn opened_record(keys: &Keys, identity: &[u8; 32], put: &ops::RecordPut) -> Value {
    let sealed = &put.value_sealed;
    let scope = keys
        .identity_key(identity)
        .scope_key(sealed.data_epoch, &sealed.scope);
    let RecordValue::Json(bytes) = sealed.open(&scope, identity, &put.key).unwrap() else {
        panic!("expected a stored record");
    };
    serde_json::from_slice(&bytes).unwrap()
}

pub(super) fn operation_cases(
    keys: &Keys,
    chain: &super::chain::Chain,
    docs: &HashMap<String, SignedDoc>,
    bundle: &ops::KeyBundlePut,
    ids: &super::identifiers::Identifiers,
) {
    let v = load("operations.json");
    super::generation::check_annotations("operations.json", &v);
    let chain_file = load("chain.json");
    let source = arr(&chain_file, "items")
        .iter()
        .find(|row| row["source"] == "record.put create")
        .unwrap();
    let create = chain.by_source(st(source, "source")).op();
    let account = keys
        .identities
        .iter()
        .find(|(_, id)| **id == create.body().identity)
        .unwrap()
        .0;
    let description = format!(
        "Every operation type (wire 6.1-6.4) for {account}'s account at generation {}, signed by its writer over lp(\"{}\", \
         identity, body). Signer operations carry app_id null. Batches share one batch ID and count; cursor.set is unsigned and \
         outside the count. Each record.put value opens with {account}'s scope key to a record value of the sample protocol tasks, \
         which the switch treats as opaque.",
        create.body().generation,
        labels::sig::OP
    );
    generated_members(
        "operations.json",
        "",
        &[("description", json!(description))],
    );
    let shop = keys.app("shop");
    let OpKind::RecordPut(put) = &create.body().kind else {
        panic!("expected record create")
    };
    let value = opened_record(keys, &create.body().identity, put);
    let [assignment] = arr(&value, "messages").as_slice() else {
        panic!("expected the assignment")
    };
    let assignment =
        pubky_dispatch_core::message::message_hash(&b64(st(&assignment["plaintext"], "json")));
    let records = RecordCases {
        keys,
        create: create.body(),
        name: st(source, "record_name"),
        natural: pubky_dispatch_core::enc::lp(&[&shop.identity, &assignment]),
    };
    let operations = bodies::signed_operations(&v, chain, docs, bundle, ids, &records, assignment);
    let identity = &create.body().identity;
    let request = ops_request(&v, &operations);
    unknown_members(keys, &v, identity, &operations);
    batch_entries(&v, &request);
    integer_bounds(keys, &v, identity, &operations);
    attempt_deadlines(&v, &operations, &source["message"]["body"]);
    shape_cases(&v, &records, bundle);
    permanent_cases(&v, &records);
    bodies::record_scope_cases(&v["record_scopes"], keys, docs, ids);
    deny_cases(&v);
    super::record_current::condition_case(keys, chain);
}

/// Each app's operation is one its certificate allows; the signer's only the signer writes
/// (Dispatch wire 6.2, 6.4 step 9).
fn check_permissions(
    keys: &Keys,
    docs: &HashMap<String, SignedDoc>,
    ops: &HashMap<String, SignedOp>,
    identity: &[u8; 32],
) {
    let certs: HashMap<_, _> = keys
        .apps
        .iter()
        .filter(|app| app.identity == *identity)
        .map(|app| {
            let cert =
                AppCert::verify(&docs[&format!("{} certificate", app.name)], identity).unwrap();
            (cert.app_id(), cert)
        })
        .collect();
    for (name, op) in ops {
        let body = op.body();
        match body.app_id {
            None => {
                check_permission(&body.kind, Writer::Signer).unwrap();
                let some_cert = certs.values().next().unwrap();
                let refused = check_permission(&body.kind, Writer::App(some_cert)).unwrap_err();
                assert_eq!(refused.status(), 403, "{name}");
            }
            Some(app) => {
                let cert = &certs[&app];
                check_permission(&body.kind, Writer::App(cert))
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(
                    check_permission(&body.kind, Writer::Signer).is_err(),
                    "{name}"
                );
            }
        }
    }
}

/// The operations of one batch share its ID and count, and pass the batch rules (Dispatch wire
/// 6.4 step 4); the record written twice is refused.
fn check_batches(ops: &HashMap<String, SignedOp>) {
    let mut batches: HashMap<[u8; 16], Vec<&SignedOp>> = HashMap::new();
    for op in ops.values() {
        batches.entry(op.body().batch.id).or_default().push(op);
    }
    for group in batches.values() {
        let mut group: Vec<SignedOp> = group.iter().map(|o| (*o).clone()).collect();
        // The order within a batch doesn't matter to these rules.
        group.sort_by_key(|o| o.signed().sig.clone());
        assert_eq!(group[0].body().batch.count as usize, group.len());
        check_batch(&group).unwrap();
        if group.len() == 1 {
            assert!(check_batch(&[group[0].clone(), group[0].clone()]).is_err());
        }
    }
    // Two writes of one record in one batch: the create and the update share a key.
    let create = ops["record.put create"].clone();
    let update = ops["record.put update"].clone();
    let mut body = update.body().clone();
    body.batch = ops::BatchRef {
        id: [9; 16],
        count: 2,
    };
    let mut first = create.body().clone();
    first.batch = body.batch;
    let resigned = |b: pubky_dispatch_core::ops::OpBody| {
        let bytes = b.to_json().unwrap();
        SignedOp::peek(&SignedDoc::from_parts(&bytes, &[0; 64])).unwrap()
    };
    let refused = check_batch(&[resigned(first), resigned(body)]).unwrap_err();
    assert_eq!(refused.status(), 400);
}

/// The registration batch's `POST /ops` body (Dispatch wire 6.4): read, its operations
/// verified, and written again byte for byte.
fn ops_request(v: &Value, base: &HashMap<String, SignedOp>) -> Vec<u8> {
    let case = &v["ops_request"];
    let ops: Vec<_> = strings(&case["operations"])
        .iter()
        .map(|name| base[name].clone())
        .collect();
    check_batch(&ops).unwrap();
    let cursor = ops::Position::parse(st(case, "cursor")).unwrap();
    let body = OpsRequest::new(&ops, Some(cursor)).to_json();
    let request = OpsRequest::parse(&body).unwrap();
    assert!(request.signed().eq(ops.iter().map(SignedOp::signed)));
    assert!(matches!(request.entries.last(), Some(Entry::Cursor(p)) if *p == cursor));
    assert_eq!(request.to_json(), body);
    emit_body("/ops_request", &body);
    body
}

fn emit_body(path: &str, body: &[u8]) {
    generated_members(
        "operations.json",
        path,
        &[("body", json!(std::str::from_utf8(body).unwrap()))],
    );
}

/// Add the chosen member to the named object. A numeric path component selects an array element.
fn with_unknown_member(body: &[u8], case: &Value) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(body).unwrap();
    let mut node = &mut value;
    let mut parts = st(case, "member").split('.');
    let member = parts.next_back().unwrap();
    for part in parts {
        node = if node.is_array() {
            node.get_mut(part.parse::<usize>().unwrap()).unwrap()
        } else {
            node.get_mut(part).unwrap()
        };
    }
    let replaced = node
        .as_object_mut()
        .unwrap()
        .insert(member.to_owned(), case.get("value").unwrap().clone());
    assert!(replaced.is_none(), "{} already exists", st(case, "member"));
    serde_json::to_vec(&value).unwrap()
}

fn signed_variant(
    keys: &Keys,
    c: &Value,
    identity: &[u8; 32],
    base: &SignedOp,
    body: Vec<u8>,
    path: &str,
) -> Result<SignedOp, Refusal> {
    let (public, app_id) = writer_of(keys, st(c, "writer"), identity);
    assert_eq!(base.body().app_id, app_id, "base writer for {}", c["name"]);
    let signer = ed25519_dalek::SigningKey::from_bytes(&keys.secret(&public).unwrap());
    let signed = SignedDoc::sign_bytes(&signer, labels::sig::OP, &[identity], body);
    signed
        .verify(&public, labels::sig::OP, &[identity])
        .unwrap();
    emit_signed(path, &signed);
    SignedOp::verify(&signed, &public, identity, app_id.as_ref())
}

/// An unknown member at any depth is refused after the signature verifies.
fn unknown_members(keys: &Keys, v: &Value, identity: &[u8; 32], base: &HashMap<String, SignedOp>) {
    for (i, c) in arr(&v["unknown_members"], "cases").iter().enumerate() {
        let op = &base[st(c, "based_on")];
        let body = with_unknown_member(&op.body().to_json().unwrap(), c);
        let path = format!("/unknown_members/cases/{i}");
        let refused = signed_variant(keys, c, identity, op, body, &path).unwrap_err();
        expect_refusal(c, &refused, st(c, "name"));
        assert!(refused.reason.contains("unknown member"), "{refused}");
    }
}

fn expect_refusal(case: &Value, refused: &Refusal, name: &str) {
    let expect = &case["expect"];
    assert_eq!(
        u64::from(refused.status()),
        int(expect, "status"),
        "{name}: {refused}"
    );
    assert_eq!(
        refused.code.as_str(),
        st(expect, "code"),
        "{name}: {refused}"
    );
}

/// `POST /ops` bodies with a member beside a batch entry's own (Dispatch wire 6.4 step 2):
/// every signature still verifies, and the body is refused `400 bad_request` before any
/// signature is checked.
fn batch_entries(v: &Value, request: &[u8]) {
    for (i, c) in arr(&v["unknown_members"]["batch_entries"], "cases")
        .iter()
        .enumerate()
    {
        assert_eq!(st(c, "based_on"), "ops_request");
        let body = with_unknown_member(request, c);
        let refused = OpsRequest::parse(&body).unwrap_err();
        expect_refusal(c, &refused, st(c, "name"));
        emit_body(&format!("/unknown_members/batch_entries/cases/{i}"), &body);
    }
}

/// Preserve each number's written sign, fraction and exponent in the signed bytes.
fn integer_bounds(keys: &Keys, v: &Value, identity: &[u8; 32], base: &HashMap<String, SignedOp>) {
    for (i, c) in arr(&v["integer_bounds"], "cases").iter().enumerate() {
        let op = &base[st(c, "based_on")];
        let body = String::from_utf8(op.body().to_json().unwrap()).unwrap();
        let raw: Value = serde_json::from_str(&body).unwrap();
        let member = st(c, "member");
        let key = serde_json::to_string(member).unwrap();
        let original = format!("{key}:{}", int(&raw, member));
        assert_eq!(body.matches(&original).count(), 1, "{member}");
        let changed = body.replace(&original, &format!("{key}:{}", st(c, "number")));
        let result = signed_variant(
            keys,
            c,
            identity,
            op,
            changed.clone().into_bytes(),
            &format!("/integer_bounds/cases/{i}"),
        );
        if let Some(valid) = c["expect"].get("valid") {
            assert_eq!(
                result.is_ok(),
                valid.as_bool().unwrap(),
                "{}",
                st(c, "name")
            );
            assert_eq!(
                result.unwrap().body().to_json().unwrap(),
                changed.as_bytes()
            );
        } else {
            expect_refusal(c, &result.unwrap_err(), st(c, "name"));
        }
    }
}

/// A claim carries the deadline computed from the chosen instant at millisecond precision.
fn attempt_deadlines(v: &Value, ops: &HashMap<String, SignedOp>, assignment: &Value) {
    let OpKind::Claim(fields) = &ops["claim attempt"].body().kind else {
        panic!("expected attempt")
    };
    let first = fields.check().unwrap();
    let EntryKind::Attempt { orphan_after, .. } = first.kind else {
        panic!("expected attempt")
    };
    let cases = arr(&v["attempt_deadlines"], "cases");
    assert!(cases.iter().any(|c| c["d"] == assignment["due"]));
    for (i, c) in cases.iter().enumerate() {
        let d: Option<&str> = serde::Deserialize::deserialize(c.get("d").unwrap()).unwrap();
        let deadline = d.map(|time| attempt_deadline(parse_rfc3339(time).unwrap()));
        let entry = ClaimEntry {
            kind: EntryKind::Attempt {
                orphan_after,
                deadline,
            },
            ..first
        };
        assert_eq!(entry.fields().deadline, deadline);
        if c["d"] == assignment["due"] {
            assert_eq!(deadline, fields.deadline);
        }
        generated_members(
            "operations.json",
            &format!("/attempt_deadlines/cases/{i}"),
            &[("deadline", json!(deadline.map(rfc3339)))],
        );
    }
}
