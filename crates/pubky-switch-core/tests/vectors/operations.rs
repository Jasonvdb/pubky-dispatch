//! `operations.json`: every operation type signed by its writer, the `POST /ops` body, the
//! operations to refuse for an unknown member at any depth, the batch entries to refuse, the
//! integer bounds and the attempt deadlines (Switch wire 6.1 to 6.4).
//!
//! Every operation is verified for its writer, read, written again from what was read and
//! signed again from the fixed keys, byte for byte; its shape and its writer's permission
//! are checked, and every sealed value opens with the identity's scope key.

use std::collections::HashMap;

use pubky_switch_core::claims::{ClaimEntry, EntryKind, attempt_deadline};
use pubky_switch_core::enc::{app_id_decode, b64 as b64e};
use pubky_switch_core::keys::{AppKeys as SwitchAppKeys, IdentityKey};
use pubky_switch_core::labels;
use pubky_switch_core::ops::{
    self, Entry, OpKind, OpsRequest, Refusal, SignedOp, Writer, check_batch, check_permission,
    check_shape,
};
use pubky_switch_core::records::AppCert;
use pubky_switch_core::sealed::RecordValue;
use pubky_switch_core::sig::{self, SignedDoc};
use pubky_switch_core::time::{parse_rfc3339, rfc3339};
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

/// The certificates of `documents.json`, by App ID: the first one of each app, which the
/// operations here are written under.
fn certificates(identity: &[u8; 32]) -> HashMap<[u8; 16], AppCert> {
    let docs = load("documents.json");
    let mut certs = HashMap::new();
    for d in arr(&docs, "documents") {
        if st(d, "label") != labels::sig::APP_CERT {
            continue;
        }
        if let Ok(cert) = AppCert::verify(&signed_of(&d["signed"]), identity) {
            certs.entry(cert.app_id()).or_insert(cert);
        }
    }
    certs
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

        // Verified for its writer (Switch wire 6.4 step 3), read, and written again.
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
            let switch_keys = SwitchAppKeys::from_secrets(app.signing_secret, app.bundle_secret);
            SignedOp::sign(&switch_keys, op.body().clone()).unwrap()
        } else {
            SignedOp::sign(&IdentityKey::from_secret(secret), op.body().clone()).unwrap()
        };
        assert_eq!(again.signed(), &signed, "{name}: signed again");
        assert!(op.carrying_len() <= ops::MAX_OP_BYTES);

        // Its shape (Switch wire 6.4 step 9) holds: keys derive, bundles and certificates
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
    check_permissions(&by_name, &identity);
    check_batches(&by_name);
    check_ops_request(&keys, &v, &identity);
    check_unknown_members(&keys, &v, &identity, &by_name);
    check_batch_entries(&keys, &v, &identity);
    check_integer_bounds(&keys, &v, &identity, &by_name);
    check_attempt_deadlines(&v, &by_name);
    let docs = super::documents::issue_documents();
    let chain = super::chain::chain_cases(&keys, &docs);
    let (_, bundle) = super::envelopes::envelope_cases();
    operation_cases(&keys, &chain, &bundle);
}

/// The operation text and its two carrying members (Switch wire 6.1).
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
    use pubky_switch_core::{enc::pubky_id, ops::MAX_DENY, recovery::check_deny_room};
    for (i, c) in arr(&v["deny_room"], "cases").iter().enumerate() {
        let path = format!("/deny_room/cases/{i}");
        let peers = |input: &str, member: &str| -> Vec<[u8; 32]> {
            arr(c, input)
                .iter()
                .enumerate()
                .map(|(j, n)| {
                    let id = [u8::try_from(n.as_u64().unwrap()).unwrap(); 32];
                    generated(
                        "operations.json",
                        &[(&format!("{path}/{member}/{j}"), json!(pubky_id(&id)))],
                    );
                    id
                })
                .collect()
        };
        let held = peers("held_bytes", "held");
        let uploaded = peers("uploaded_bytes", "uploaded");
        generated_members("operations.json", &path, &[("max_deny", json!(MAX_DENY))]);
        match check_deny_room(int(c, "held_count"), &uploaded, |p| held.contains(p)) {
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

    fn key(&self, policy: &pubky_switch_core::ident::Policy) -> [u8; 32] {
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
        let scope = self
            .keys
            .identity_key(&self.create.identity)
            .scope_key(sealed.data_epoch, &sealed.scope);
        let nonce = seed(st(case, "nonce_seed_label"))[..24].try_into().unwrap();
        put.value_sealed = pubky_switch_core::sealed::SealedValue::seal_with_nonce(
            &scope,
            &self.create.identity,
            sealed.data_epoch,
            &sealed.scope,
            &put.key,
            value,
            &nonce,
        )
        .unwrap();
    }
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
        let (public, app_id) = writer_of(records.keys, st(c, "writer"), identity);
        let signer = ed25519_dalek::SigningKey::from_bytes(&records.keys.secret(&public).unwrap());
        let fields: &[&[u8]] = &[identity, body.as_bytes()];
        let sig = sig::sign(&signer, labels::sig::OP, fields);
        let signed = SignedDoc::from_parts(body.as_bytes(), &sig);
        sig::verify(&public, labels::sig::OP, fields, &sig).unwrap();
        let refused = SignedOp::verify(&signed, &public, identity, app_id.as_ref()).unwrap_err();
        expect_refusal(c, &refused, st(c, "name"));
        emit_signed(&format!("/permanent_policies/rejections/{i}"), &signed);
    }
}

pub(super) fn operation_cases(
    keys: &Keys,
    chain: &super::chain::Chain,
    bundle: &ops::KeyBundlePut,
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
    let (_, assignment) =
        super::chain::record_message(&source["message"], shop, keys.app("wallet"), vec![]);
    let records = RecordCases {
        keys,
        create: create.body(),
        name: st(source, "record_name"),
        natural: pubky_switch_core::enc::lp(&[&shop.identity, &assignment.hash()]),
    };
    shape_cases(&v, &records, bundle);
    permanent_cases(&v, &records);
    deny_cases(&v);
    super::record_current::condition_case(keys, chain);
}

/// Each app's operation is one its certificate allows; the signer's only the signer writes
/// (Switch wire 6.2, 6.4 step 9).
fn check_permissions(ops: &HashMap<String, SignedOp>, identity: &[u8; 32]) {
    let certs = certificates(identity);
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

/// The operations of one batch share its ID and count, and pass the batch rules (Switch wire
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
    let resigned = |b: pubky_switch_core::ops::OpBody| {
        let bytes = b.to_json().unwrap();
        SignedOp::peek(&SignedDoc::from_parts(&bytes, &[0; 64])).unwrap()
    };
    let refused = check_batch(&[resigned(first), resigned(body)]).unwrap_err();
    assert_eq!(refused.status(), 400);
}

/// The registration batch's `POST /ops` body (Switch wire 6.4): read, its operations
/// verified, and written again byte for byte.
fn check_ops_request(keys: &Keys, v: &Value, identity: &[u8; 32]) {
    let body = st(&v["ops_request"], "body");
    let request = OpsRequest::parse(body.as_bytes()).unwrap();
    assert_eq!(request.to_json(), body.as_bytes(), "ops_request rebuilt");
    let wallet = keys.app("wallet");
    let app_id = app_id_decode(&wallet.app_id).unwrap();
    let signed: Vec<SignedOp> = request
        .signed()
        .map(|d| SignedOp::verify(d, &wallet.signing_public, identity, Some(&app_id)).unwrap())
        .collect();
    assert_eq!(signed.len(), 2);
    assert!(matches!(signed[0].body().kind, OpKind::AppPut { .. }));
    assert!(matches!(
        signed[1].body().kind,
        OpKind::ReceiveKeyPut { .. }
    ));
    check_batch(&signed).unwrap();
    let cursor = request.cursor().unwrap();
    assert_eq!(cursor.to_string(), "1:0");
    assert_eq!(
        OpsRequest::new(&signed, Some(cursor)).to_json(),
        body.as_bytes()
    );
    assert!(matches!(request.entries.last(), Some(Entry::Cursor(_))));
}

/// The cases refused for an unknown member at the top level or nested (Switch wire 1.1,
/// 6.1): each signature verifies, and only the member check refuses it, `400 bad_request`.
fn check_unknown_members(
    keys: &Keys,
    v: &Value,
    identity: &[u8; 32],
    base: &HashMap<String, SignedOp>,
) {
    let cases = arr(&v["unknown_members"], "cases");
    assert!(cases.len() >= 9);
    for c in cases {
        let name = st(c, "name");
        let signed = signed_of(&c["signed"]);
        assert_eq!(signed.body, b64e(st(c, "body").as_bytes()), "{name}");
        let (key, app_id) = writer_of(keys, st(c, "writer"), identity);
        sig::verify(
            &key,
            labels::sig::OP,
            &[identity, st(c, "body").as_bytes()],
            &signed.sig_bytes().unwrap(),
        )
        .unwrap_or_else(|e| panic!("{name}: the signature verifies: {e}"));
        let refused = SignedOp::verify(&signed, &key, identity, app_id.as_ref()).unwrap_err();
        expect_refusal(c, &refused, name);
        assert!(
            refused.reason.contains("unknown member"),
            "{name}: {refused}"
        );
        // The same body without the member reads.
        let mut value: Value = serde_json::from_str(st(c, "body")).unwrap();
        remove_at(&mut value, st(c, "member"));
        let cleaned = ops::OpBody::parse(&serde_json::to_vec(&value).unwrap())
            .unwrap_or_else(|e| panic!("{name}: without the member: {e}"));
        assert_eq!(&cleaned, base[st(c, "based_on")].body(), "{name}");
    }
}

/// Remove the member at a dotted path, numbers indexing arrays.
fn remove_at(value: &mut Value, path: &str) {
    let mut parts: Vec<&str> = path.split('.').collect();
    let last = parts.pop().unwrap();
    let mut node = value;
    for p in parts {
        node = match p.parse::<usize>() {
            Ok(i) => &mut node[i],
            Err(_) => &mut node[p],
        };
    }
    node.as_object_mut().unwrap().remove(last).unwrap();
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

/// `POST /ops` bodies with a member beside a batch entry's own (Switch wire 6.4 step 2):
/// every signature still verifies, and the body is refused `400 bad_request` before any
/// signature is checked.
fn check_batch_entries(keys: &Keys, v: &Value, identity: &[u8; 32]) {
    let wallet = keys.app("wallet");
    let cases = arr(&v["unknown_members"]["batch_entries"], "cases");
    assert!(cases.len() >= 2);
    for c in cases {
        let name = st(c, "name");
        let body = st(c, "body");
        let refused = OpsRequest::parse(body.as_bytes()).unwrap_err();
        expect_refusal(c, &refused, name);
        let raw: Value = serde_json::from_str(body).unwrap();
        for entry in raw["ops"].as_array().unwrap() {
            if let (Some(b), Some(s)) = (entry["body"].as_str(), entry["sig"].as_str()) {
                let doc = SignedDoc {
                    body: b.into(),
                    sig: s.into(),
                };
                let app_id = app_id_decode(&wallet.app_id).unwrap();
                SignedOp::verify(&doc, &wallet.signing_public, identity, Some(&app_id))
                    .unwrap_or_else(|e| panic!("{name}: an entry's operation verifies: {e}"));
            }
        }
        let mut cleaned = raw;
        remove_at(&mut cleaned, st(c, "member"));
        let original: Value = serde_json::from_str(st(&v[st(c, "based_on")], "body")).unwrap();
        assert_eq!(cleaned, original, "{name}");
        OpsRequest::parse(&serde_json::to_vec(&cleaned).unwrap())
            .unwrap_or_else(|e| panic!("{name}: without the member: {e}"));
    }
}

/// Integers at and beyond the bounds of Switch wire 1.1: 2^53 - 1 is taken; 2^53, a fraction,
/// an exponent and a sign are refused `400 bad_request`, whose signatures verify.
fn check_integer_bounds(
    keys: &Keys,
    v: &Value,
    identity: &[u8; 32],
    base: &HashMap<String, SignedOp>,
) {
    let cases = arr(&v["integer_bounds"], "cases");
    assert!(cases.len() >= 6);
    for c in cases {
        let name = st(c, "name");
        let body = st(c, "body");
        let original = base[st(c, "based_on")].body();
        let OpKind::Claim(claim) = &original.kind else {
            panic!("{name}: claim attempt")
        };
        let field = format!(r#""orphan_after":{}"#, claim.orphan_after.unwrap());
        let original = String::from_utf8(original.to_json().unwrap()).unwrap();
        assert_eq!(original.matches(&field).count(), 1);
        assert_eq!(
            body,
            original.replace(&field, &format!(r#""orphan_after":{}"#, st(c, "number"))),
            "{name}"
        );
        let signed = signed_of(&c["signed"]);
        assert_eq!(signed.body, b64e(body.as_bytes()), "{name}");
        let (key, app_id) = writer_of(keys, st(c, "writer"), identity);
        let outcome = SignedOp::verify(&signed, &key, identity, app_id.as_ref());
        if c["expect"]["valid"] == Value::Bool(true) {
            let op = outcome.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(op.body().to_json().unwrap(), body.as_bytes(), "{name}");
        } else {
            sig::verify(
                &key,
                labels::sig::OP,
                &[identity, body.as_bytes()],
                &signed.sig_bytes().unwrap(),
            )
            .unwrap();
            expect_refusal(c, &outcome.unwrap_err(), name);
        }
    }
}

/// The attempt deadlines (Switch wire 6.2): which instant `d` a request names is the
/// protocol's, so here each deadline is checked as the Switch's part of the rule: `d + 1 ms`
/// for an instant the case names, read at millisecond precision with further digits
/// truncated, written with three fraction digits, and carried by an `attempt` as written; no
/// deadline is carried as no member. The claim attempt carries the deadline for the assignment's due time.
fn check_attempt_deadlines(v: &Value, ops: &HashMap<String, SignedOp>) {
    let cases = arr(&v["attempt_deadlines"], "cases");
    assert!(!cases.is_empty());
    for c in cases {
        let name = st(c, "name");
        let entry = |deadline: Option<u64>| ClaimEntry {
            claim_key: [1; 32],
            attempt_id: [2; 16],
            expected_step: 0,
            kind: EntryKind::Attempt {
                orphan_after: 60,
                deadline,
            },
        };
        let Some(text) = c["deadline"].as_str() else {
            assert!(c["deadline"].is_null(), "{name}");
            assert!(c["d"].is_null(), "{name}: no deadline only without a d");
            assert_eq!(entry(None).fields().deadline, None);
            continue;
        };
        let deadline = parse_rfc3339(text).unwrap();
        assert_eq!(rfc3339(deadline), text, "{name}: three fraction digits");
        assert_eq!(entry(Some(deadline)).fields().deadline, Some(deadline));
        // d is read at millisecond precision, and the attempt carries d + 1 ms.
        let d = parse_rfc3339(st(c, "d")).unwrap();
        assert_eq!(attempt_deadline(d), deadline, "{name}: d + 1 ms");
    }
    let chain = load("chain.json");
    let create = arr(&chain, "items")
        .iter()
        .find(|row| row["source"] == "record.put create")
        .unwrap();
    let due = &create["message"]["body"]["due"];
    let assignment = cases.iter().find(|c| c["d"] == *due).unwrap();
    let deadline = time_of(assignment, "deadline");
    let OpKind::Claim(attempt) = &ops["claim attempt"].body().kind else {
        panic!("the claim attempt is a claim");
    };
    assert_eq!(attempt.deadline, Some(deadline));
}
