//! `operations.json`: every operation type signed by its writer, the `POST /ops` body, the
//! operations to refuse for an unknown member at any depth, the batch entries to refuse, the
//! integer bounds and the attempt deadlines (Dispatch wire 6.1 to 6.4).
//!
//! Every operation is verified for its writer, read, written again from what was read and
//! signed again from the fixed keys, byte for byte; its shape and its writer's permission
//! are checked, and every sealed value opens with the identity's scope key.

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
use pubky_dispatch_core::sealed::RecordValue;
use pubky_dispatch_core::sig::{self, SignedDoc};
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
    check_permissions(&by_name, &identity);
    check_batches(&by_name);
    check_ops_request(&keys, &v, &identity);
    check_unknown_members(&keys, &v, &identity);
    check_batch_entries(&keys, &v, &identity);
    check_integer_bounds(&keys, &v, &identity);
    check_attempt_deadlines(&v, &by_name);
    check_shape_rejections(&keys, &v, &identity);
    check_permanent_policies(&keys, &identity, &by_name["record.put create"]);
    check_deny_room();
}

/// `deny_room` (Dispatch wire 7.4.14 "Lists"), which `pubky-dispatch-core` generates: a recovery
/// upload's deny entries against the deny list N holds. With H the entries held and U the
/// distinct uploaded entries not held, the upload fits while H + U is at most `max_deny`,
/// and is otherwise refused whole with `over` = H + U - `max_deny`; repeats and entries
/// held already take no room.
fn check_deny_room() {
    use pubky_dispatch_core::enc::pubky_id;
    use pubky_dispatch_core::ops::MAX_DENY;
    use pubky_dispatch_core::recovery::check_deny_room;
    let peer = |n: u8| pubky_id(&[n; 32]);
    let case = |name: &str, held_count: u64, held: &[u8], uploaded: &[u8]| {
        let held_ids: Vec<String> = held.iter().map(|n| peer(*n)).collect();
        let uploaded_ids: Vec<String> = uploaded.iter().map(|n| peer(*n)).collect();
        let keys: Vec<[u8; 32]> = uploaded.iter().map(|n| [*n; 32]).collect();
        let held_keys: Vec<[u8; 32]> = held.iter().map(|n| [*n; 32]).collect();
        let expect = match check_deny_room(held_count, &keys, |p| held_keys.contains(p)) {
            Ok(()) => json!({ "status": 200 }),
            Err(refusal) => json!({
                "status": refusal.status(),
                "code": refusal.code.as_str(),
                "current": refusal.current,
            }),
        };
        json!({
            "name": name,
            "max_deny": MAX_DENY,
            "held_count": held_count,
            "held": held_ids,
            "uploaded": uploaded_ids,
            "expect": expect,
        })
    };
    let cases = vec![
        case(
            "fits: a repeat and an entry held take no room",
            MAX_DENY - 1,
            &[1],
            &[1, 2, 2],
        ),
        case(
            "refused whole: two entries over, after a repeat and a held entry",
            MAX_DENY - 1,
            &[1],
            &[1, 2, 2, 3, 4],
        ),
        case(
            "refused whole: a full list and one new entry",
            MAX_DENY,
            &[1],
            &[1, 5],
        ),
    ];
    generated(
        "operations.json",
        &[(Place::Member("/deny_room"), json!({ "cases": cases }))],
    );
    let file = load("operations.json");
    for c in arr(&file["deny_room"], "cases") {
        let name = st(c, "name");
        let ids = |member: &str| -> Vec<[u8; 32]> {
            arr(c, member)
                .iter()
                .map(|id| pubky_dispatch_core::enc::pubky_key(id.as_str().unwrap()).unwrap())
                .collect()
        };
        let held = ids("held");
        let answer = check_deny_room(int(c, "held_count"), &ids("uploaded"), |p| held.contains(p));
        match answer {
            Ok(()) => assert_eq!(int(&c["expect"], "status"), 200, "{name}"),
            Err(refusal) => {
                expect_refusal(c, &refusal, name);
                assert_eq!(
                    refusal.current.as_ref(),
                    Some(&c["expect"]["current"]),
                    "{name}"
                );
            }
        }
    }
}

/// One case of `shape_rejections`: the operation `based_on` with each `(from, to)` of
/// `changes` made in its signed body, signed again by its writer, so its signature verifies
/// and only the shape check (Dispatch wire 6.4 step 9) decides.
fn shape_case(
    keys: &Keys,
    v: &Value,
    identity: &[u8; 32],
    name: &str,
    based_on: &str,
    changes: &[(&str, &str)],
) -> Value {
    let base = arr(v, "operations")
        .iter()
        .find(|o| st(o, "name") == based_on)
        .unwrap();
    let mut body = st(base, "body").to_owned();
    for (from, to) in changes {
        assert_eq!(body.matches(from).count(), 1, "{name}: {from}");
        body = body.replace(from, to);
    }
    let (writer_key, _) = writer_of(keys, st(base, "writer"), identity);
    let secret = keys.secret(&writer_key).unwrap();
    let sig = sig::sign(
        &ed25519_dalek::SigningKey::from_bytes(&secret),
        labels::sig::OP,
        &[identity, body.as_bytes()],
    );
    let signed = SignedDoc::from_parts(body.as_bytes(), &sig);
    let (key, app_id) = writer_of(keys, st(base, "writer"), identity);
    let op = SignedOp::verify(&signed, &key, identity, app_id.as_ref())
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    let refused = check_shape(op.body()).expect_err(name);
    json!({
        "name": name,
        "based_on": based_on,
        "writer": st(base, "writer"),
        "body": body,
        "signed": signed,
        "expect": { "status": refused.status(), "code": refused.code.as_str() },
        "rule": quoted(&refused.reason),
    })
}

/// `shape_rejections`, which `pubky-dispatch-core` generates (README "How the files were
/// generated"): the `record.put create` of `operations` with its policy changed so that its
/// shape (Dispatch wire 6.2, 6.4 step 9) fails, its key derived again for that policy (wire
/// 1.5), so only the scope rule decides, and signed again by its writer: a `read_scope`,
/// with the sealed value's `scope`, or a `write_scopes` entry that isn't a scope (wire 3.1
/// "Scope names"); and the signer's `key_bundle.put` with a range from data epoch 0, or one
/// whose first epoch is above its last (wire 3.5, 6.2).
fn check_shape_rejections(keys: &Keys, v: &Value, identity: &[u8; 32]) {
    let based_on = "record.put create";
    let base = arr(v, "operations")
        .iter()
        .find(|o| st(o, "name") == based_on)
        .unwrap();
    let body: Value = serde_json::from_str(st(base, "body")).unwrap();
    let read = st(&body, "read_scope").to_owned();
    let writes = strings(&body["write_scopes"]);
    let key = st(&body, "key").to_owned();
    let collection = st(&body["id_inputs"], "collection").to_owned();
    let blinded: [u8; 32] = b64n(st(&body["id_inputs"], "blinded_key"));
    let text = |value: &Value| serde_json::to_string(value).unwrap();
    // The changes that give the operation `new_read` and `new_writes`, with the key they
    // derive.
    let changes = |new_read: &str, new_writes: &[String]| -> Vec<(String, String)> {
        let refs: Vec<&str> = new_writes.iter().map(String::as_str).collect();
        let policy = pubky_dispatch_core::ident::Policy::new(new_read, &refs);
        let new_key = pubky_dispatch_core::ident::record_key_from_blinded(
            &collection,
            &blinded,
            &policy.hash().unwrap(),
        );
        vec![
            (
                format!(r#""key":{}"#, text(&json!(key))),
                format!(r#""key":{}"#, text(&json!(b64e(&new_key)))),
            ),
            (
                format!(r#""read_scope":{}"#, text(&json!(read))),
                format!(r#""read_scope":{}"#, text(&json!(new_read))),
            ),
            (
                format!(r#""write_scopes":{}"#, text(&json!(writes))),
                format!(r#""write_scopes":{}"#, text(&json!(new_writes))),
            ),
            (
                format!(r#""scope":{},"nonce""#, text(&json!(read))),
                format!(r#""scope":{},"nonce""#, text(&json!(new_read))),
            ),
        ]
    };
    let case = |name: &str, new_read: &str, new_writes: &[String]| {
        let changes = changes(new_read, new_writes);
        let pairs: Vec<(&str, &str)> = changes
            .iter()
            .filter(|(from, to)| from != to)
            .map(|(from, to)| (from.as_str(), to.as_str()))
            .collect();
        shape_case(keys, v, identity, name, based_on, &pairs)
    };
    let mut more_writes = writes.clone();
    more_writes.push(format!("{}:", writes[0]));
    let cases = vec![
        case(
            "record.put: read_scope with a NUL character",
            &format!("{read}\u{0}"),
            &writes,
        ),
        case(
            "record.put: read_scope in upper case",
            &read.to_uppercase(),
            &writes,
        ),
        case(
            "record.put: a write_scopes entry that isn't a scope",
            &read,
            &more_writes,
        ),
    ];
    // The signer's key_bundle.put with its range changed: data epochs start at 1 (wire 3.5,
    // spec 4.3), and a range's first epoch is at most its last.
    let bundle_base = "key_bundle.put";
    let bundle: Value = serde_json::from_str(st(
        arr(v, "operations")
            .iter()
            .find(|o| st(o, "name") == bundle_base)
            .unwrap(),
        "body",
    ))
    .unwrap();
    let range = |first: u64, last: u64| format!(r#""first_epoch":{first},"last_epoch":{last}"#);
    let held = range(int(&bundle, "first_epoch"), int(&bundle, "last_epoch"));
    let last = int(&bundle, "last_epoch");
    let mut cases = cases;
    cases.push(shape_case(
        keys,
        v,
        identity,
        "key_bundle.put: first_epoch 0",
        bundle_base,
        &[(&held, &range(0, last))],
    ));
    cases.push(shape_case(
        keys,
        v,
        identity,
        "key_bundle.put: first_epoch above last_epoch",
        bundle_base,
        &[(&held, &range(last, last - 1))],
    ));
    // A permanent policy's rule (wire 6.2 "Permanent policies", spec 10.3.1), the policy
    // made permanent by its member after `write_scopes`, each key derived again for its
    // policy: the `record.put delete`, at a policy naming no generation, and the `record.put
    // create`, of generation 1, at a policy naming generation 2.
    let scopes = format!(
        r#""write_scopes":{},"expected_version""#,
        text(&json!(writes))
    );
    let made_permanent = |generation: &str| {
        format!(
            r#""write_scopes":{},"permanent":{{"generation":{generation}}},"expected_version""#,
            text(&json!(writes))
        )
    };
    let refs: Vec<&str> = writes.iter().map(String::as_str).collect();
    let named = pubky_dispatch_core::ident::Policy::new(&read, &refs).permanent(Some(2));
    let named_key = pubky_dispatch_core::ident::record_key_from_blinded(
        &collection,
        &blinded,
        &named.hash().unwrap(),
    );
    let unnamed = pubky_dispatch_core::ident::Policy::new(&read, &refs).permanent(None);
    let unnamed_key = pubky_dispatch_core::ident::record_key_from_blinded(
        &collection,
        &blinded,
        &unnamed.hash().unwrap(),
    );
    let (old_key, new_key, delete_key) = (
        format!(r#""key":{}"#, text(&json!(key))),
        format!(r#""key":{}"#, text(&json!(b64e(&named_key)))),
        format!(r#""key":{}"#, text(&json!(b64e(&unnamed_key)))),
    );
    // The delete without its claim condition: a service checks conditions before shapes
    // (wire 6.4 steps 8 and 9), so a failing condition would answer first.
    let delete = arr(v, "operations")
        .iter()
        .find(|o| st(o, "name") == "record.put delete")
        .unwrap();
    let delete = st(delete, "body");
    let start = delete.find(r#""conditions":"#).unwrap();
    let conditions = &delete[start..start + delete[start..].find(r#""op":"#).unwrap()];
    cases.push(shape_case(
        keys,
        v,
        identity,
        "record.put: a delete at a permanent policy",
        "record.put delete",
        &[
            (conditions, ""),
            (&old_key, &delete_key),
            (&scopes, &made_permanent("null")),
        ],
    ));
    cases.push(shape_case(
        keys,
        v,
        identity,
        "record.put: a create at a permanent policy of another generation",
        based_on,
        &[(&old_key, &new_key), (&scopes, &made_permanent("2"))],
    ));
    generated(
        "operations.json",
        &[(Place::Member("/shape_rejections/cases"), json!(cases))],
    );
    let file = load("operations.json");
    for c in arr(&file["shape_rejections"], "cases") {
        let name = st(c, "name");
        let signed = signed_of(&c["signed"]);
        assert_eq!(signed.body, b64e(st(c, "body").as_bytes()), "{name}");
        let (key, app_id) = writer_of(keys, st(c, "writer"), identity);
        let op = SignedOp::verify(&signed, &key, identity, app_id.as_ref())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        expect_refusal(c, &check_shape(op.body()).unwrap_err(), name);
    }
}

/// The `permanent` members `permanent_policies.rejections` writes in place of `{"generation":1}`
/// (Dispatch wire 1.1, 6.2): a generation named twice, out of the integer rule or of another
/// type, a `null` or empty member, an unknown member beside `generation`, and a member that
/// isn't an object.
const PERMANENT_REJECTIONS: [(&str, &str); 11] = [
    (
        "generation named twice",
        r#"{"generation":1,"generation":1}"#,
    ),
    ("a negative generation", r#"{"generation":-1}"#),
    ("a fraction", r#"{"generation":4.5}"#),
    ("a fraction of zero", r#"{"generation":4.0}"#),
    (
        "2^53, one above the largest",
        r#"{"generation":9007199254740992}"#,
    ),
    ("a boolean", r#"{"generation":true}"#),
    ("a string", r#"{"generation":"1"}"#),
    ("no generation", "{}"),
    (
        "an unknown member",
        r#"{"generation":1,"future_restriction":1}"#,
    ),
    ("null", "null"),
    ("an array", "[1]"),
];

/// `permanent_policies`, which `pubky-dispatch-core` generates (README "How the files were
/// generated"): `cases`, the `record.put create` of `operations` at its policy made
/// permanent, naming no generation and naming generation 1, the account's, so the service
/// takes each (wire 6.2, spec 10.3.1). Each key is derived again for its policy (wire 1.5),
/// its value sealed again for that key with the seed `operations/permanent/<g>/nonce`, and
/// each is a batch of its own, of the batch ID of the seed `operations/permanent/<g>/batch`,
/// signed again by the wallet. And `rejections`: the case naming generation 1 with its
/// `permanent` member written as [`PERMANENT_REJECTIONS`] gives, signed again by the
/// wallet, so its signature verifies and only the member's form refuses it, `400
/// bad_request`, as the operation is read.
fn check_permanent_policies(keys: &Keys, identity: &[u8; 32], create: &SignedOp) {
    let wallet = keys.app("wallet");
    let app_id = app_id_decode(&wallet.app_id).unwrap();
    let signer = DispatchAppKeys::from_secrets(wallet.signing_secret, wallet.bundle_secret);
    let OpKind::RecordPut(base) = &create.body().kind else {
        panic!("record.put create is a record.put");
    };
    let inputs = base.id_inputs.as_ref().unwrap();
    let sealed = &base.value_sealed;
    let scope_key = IdentityKey::from_secret(keys.identity_secrets[identity])
        .scope_key(sealed.data_epoch, &sealed.scope);
    let RecordValue::Json(value) = sealed.open(&scope_key, identity, &base.key).unwrap() else {
        panic!("the create writes a value");
    };
    let accepted = |label: &str, generation: Option<u64>| -> Value {
        let mut put = base.clone();
        put.policy = put.policy.permanent(generation);
        put.key = pubky_dispatch_core::ident::record_key_from_blinded(
            &inputs.collection,
            &inputs.blinded_key,
            &put.policy.hash().unwrap(),
        );
        let nonce: [u8; 24] = seed(&format!("operations/permanent/{label}/nonce"))[..24]
            .try_into()
            .unwrap();
        put.value_sealed = pubky_dispatch_core::sealed::SealedValue::seal_with_nonce(
            &scope_key,
            identity,
            sealed.data_epoch,
            &sealed.scope,
            &put.key,
            &value,
            &nonce,
        )
        .unwrap();
        let batch: [u8; 16] = seed(&format!("operations/permanent/{label}/batch"))[..16]
            .try_into()
            .unwrap();
        let op = ops::sign_batch(
            &signer,
            identity,
            Some(app_id),
            create.body().generation,
            batch,
            vec![(create.body().conditions.clone(), OpKind::RecordPut(put))],
        )
        .unwrap()
        .remove(0);
        let body = String::from_utf8(op.body().to_json().unwrap()).unwrap();
        json!({
            "name": format!("record.put create at a permanent policy naming {}", match generation {
                Some(g) => format!("generation {g}"),
                None => "no generation".to_owned(),
            }),
            "based_on": "record.put create",
            "writer": "wallet",
            "generation": generation,
            "body": body,
            "signed": op.signed(),
            "expect": { "valid": true },
        })
    };
    let cases = vec![accepted("null", None), accepted("1", Some(1))];
    let named = st(&cases[1], "body").to_owned();
    let member = r#""permanent":{"generation":1}"#;
    assert_eq!(named.matches(member).count(), 1);
    let rejections: Vec<Value> = PERMANENT_REJECTIONS
        .iter()
        .map(|(name, written)| {
            let body = named.replace(member, &format!(r#""permanent":{written}"#));
            let sig = sig::sign(
                &ed25519_dalek::SigningKey::from_bytes(&wallet.signing_secret),
                labels::sig::OP,
                &[identity, body.as_bytes()],
            );
            let signed = SignedDoc::from_parts(body.as_bytes(), &sig);
            let refused =
                SignedOp::verify(&signed, &wallet.signing_public, identity, Some(&app_id))
                    .expect_err(name);
            json!({
                "name": format!("permanent: {name}"),
                "based_on": st(&cases[1], "name"),
                "writer": "wallet",
                "permanent": written,
                "body": body,
                "signed": signed,
                "expect": { "status": refused.status(), "code": refused.code.as_str() },
            })
        })
        .collect();
    generated(
        "operations.json",
        &[
            (Place::Member("/permanent_policies/cases"), json!(cases)),
            (
                Place::Member("/permanent_policies/rejections"),
                json!(rejections),
            ),
        ],
    );
    let file = load("operations.json");
    let section = &file["permanent_policies"];
    let cases = arr(section, "cases");
    assert_eq!(cases.len(), 2);
    for c in cases {
        let name = st(c, "name");
        let body = st(c, "body");
        let signed = signed_of(&c["signed"]);
        assert_eq!(signed.body, b64e(body.as_bytes()), "{name}");
        let op = SignedOp::verify(&signed, &wallet.signing_public, identity, Some(&app_id))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(op.body().to_json().unwrap(), body.as_bytes(), "{name}");
        check_shape(op.body()).unwrap_or_else(|e| panic!("{name}: shape: {e}"));
        let OpKind::RecordPut(put) = &op.body().kind else {
            panic!("{name}: a record.put");
        };
        let named = put.policy.permanent.map(|p| p.generation);
        assert_eq!(named, Some(c["generation"].as_u64()), "{name}");
        assert_eq!(
            put.value_sealed
                .open(&scope_key, identity, &put.key)
                .unwrap(),
            RecordValue::Json(value.clone()),
            "{name}"
        );
    }
    let rejections = arr(section, "rejections");
    assert_eq!(rejections.len(), PERMANENT_REJECTIONS.len());
    for c in rejections {
        let name = st(c, "name");
        let body = st(c, "body");
        let signed = signed_of(&c["signed"]);
        assert_eq!(signed.body, b64e(body.as_bytes()), "{name}");
        sig::verify(
            &wallet.signing_public,
            labels::sig::OP,
            &[identity, body.as_bytes()],
            &signed.sig_bytes().unwrap(),
        )
        .unwrap_or_else(|e| panic!("{name}: the signature verifies: {e}"));
        let refused =
            SignedOp::verify(&signed, &wallet.signing_public, identity, Some(&app_id)).unwrap_err();
        expect_refusal(c, &refused, name);
        // The member written as the case it is based on reads.
        let written = format!(r#""permanent":{}"#, st(c, "permanent"));
        assert_eq!(body.matches(&written).count(), 1, "{name}");
        ops::OpBody::parse(body.replace(&written, member).as_bytes())
            .unwrap_or_else(|e| panic!("{name}: with the member as based_on: {e}"));
    }
}

/// Each app's operation is one its certificate allows; the signer's only the signer writes
/// (Dispatch wire 6.2, 6.4 step 9).
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

/// The cases refused for an unknown member at the top level or nested (Dispatch wire 1.1,
/// 6.1): each signature verifies, and only the member check refuses it, `400 bad_request`.
fn check_unknown_members(keys: &Keys, v: &Value, identity: &[u8; 32]) {
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
        ops::OpBody::parse(&serde_json::to_vec(&value).unwrap())
            .unwrap_or_else(|e| panic!("{name}: without the member: {e}"));
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

/// `POST /ops` bodies with a member beside a batch entry's own (Dispatch wire 6.4 step 2):
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
        let mut cleaned = raw.clone();
        remove_at(&mut cleaned, st(c, "member"));
        OpsRequest::parse(&serde_json::to_vec(&cleaned).unwrap())
            .unwrap_or_else(|e| panic!("{name}: without the member: {e}"));
    }
}

/// Integers at and beyond the bounds of Dispatch wire 1.1: 2^53 - 1 is taken; 2^53, a fraction,
/// an exponent and a sign are refused `400 bad_request`, whose signatures verify.
fn check_integer_bounds(keys: &Keys, v: &Value, identity: &[u8; 32]) {
    let cases = arr(&v["integer_bounds"], "cases");
    assert!(cases.len() >= 6);
    for c in cases {
        let name = st(c, "name");
        let body = st(c, "body");
        assert!(
            body.contains(&format!("\"orphan_after\":{}", st(c, "number"))),
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

/// The attempt deadlines (Dispatch wire 6.2): which instant `d` a request names is the
/// protocol's, so here each deadline is checked as the Dispatch's part of the rule: `d + 1 ms`
/// for an instant the case names, read at millisecond precision with further digits
/// truncated, written with three fraction digits, and carried by an `attempt` as written; no
/// deadline is carried as no member. The claim attempt of the operations carries the first
/// case's deadline.
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
    let first = parse_rfc3339(st(&cases[0], "deadline")).unwrap();
    let OpKind::Claim(attempt) = &ops["claim attempt"].body().kind else {
        panic!("the claim attempt is a claim");
    };
    assert_eq!(attempt.deadline, Some(first));
}
