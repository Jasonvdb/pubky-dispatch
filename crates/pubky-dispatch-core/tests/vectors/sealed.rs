//! `sealed.json`: sealed shared record values, with their key, AAD, nonce, padded length and
//! ciphertext (Dispatch wire 6.2, Dispatch spec 13.4).

use pubky_dispatch_core::enc::{self, lp, pubky_id};
use pubky_dispatch_core::ident::Policy;
use pubky_dispatch_core::keys::{AppKeys as SigningApp, IdentityKey, ScopeKeys};
use pubky_dispatch_core::message::{Message, MessagePlaintext, Sender};
use pubky_dispatch_core::records::{AppCert, AppCertBody};
use pubky_dispatch_core::sealed::{self, RecordValue, SealedValue, TAG_LEN};
use pubky_dispatch_core::{labels, scopes, time};
use serde_json::{Value, json};

use crate::common::*;

/// Issue the app's certificate from its keys and the chosen validity interval.
pub(super) fn certificate(keys: &Keys, app: &AppKeys) -> AppCert {
    let docs = load("documents.json");
    let name = format!("{} certificate", app.name);
    let case = arr(&docs, "documents")
        .iter()
        .find(|c| c["name"] == name)
        .expect("app certificate");
    let body = AppCertBody::new(
        app.identity,
        app.signing_public,
        app.bundle_public,
        app.scopes.clone(),
        &scopes::check_permissions(&app.permissions).expect("certificate permissions"),
        time::parse_rfc3339(st(case, "issued_at")).expect("issue date"),
        time::parse_rfc3339(st(case, "expires_at")).expect("expiry date"),
    );
    AppCert::issue(
        &IdentityKey::from_secret(keys.identity_secrets[&app.identity]),
        body,
    )
    .expect("issue certificate")
}

/// Sign the chosen message body and time with its seeded ID and the shop's keys for Alice.
fn record_message(
    keys: &Keys,
    input: &Value,
    msg_id_seed_label: &str,
) -> (Message, MessagePlaintext) {
    let app = keys.app("shop");
    let signer = SigningApp::from_secrets(app.signing_secret, app.bundle_secret);
    let message = Message {
        from: Sender::of_app(app.identity, &signer),
        to: keys.identity("alice"),
        msg_id: uuid_from_seed(msg_id_seed_label),
        kind: st(input, "kind").into(),
        created_at_ms: time::parse_rfc3339(st(input, "created_at")).expect("message time"),
        body: input["body"].as_object().expect("message body").clone(),
        refs: strings(&input["refs"]).iter().map(|r| b64n(r)).collect(),
    };
    let signed = message.sign(&signer).expect("sign message");
    (message, signed)
}

/// The assignment whose record key the delete marker uses.
fn assignment_case() -> Value {
    let file = load("sealed.json");
    let case = arr(&file, "cases")
        .iter()
        .find(|c| c["name"] == "task_items record of an assignment")
        .expect("assignment record");
    case.clone()
}

/// The assignment message signed for Alice.
pub(super) fn assignment(keys: &Keys) -> MessagePlaintext {
    let case = assignment_case();
    record_message(keys, &case["message"], st(&case, "msg_id_seed_label")).1
}

/// Rebuild the record's plaintext and natural key together, before binding them to its policy.
fn record(keys: &Keys, case: &Value) -> (String, [u8; 32]) {
    let name = st(case, "name");
    let scope = st(case, "scope");
    let shop = keys.app("shop");
    let (source, text, natural) = if name == "delete marker" {
        (
            "task_items record of an assignment",
            String::new(),
            lp(&[&shop.identity, &assignment(keys).hash()]),
        )
    } else {
        let list = name == "task_lists record";
        let input = &case["message"];
        let (message, signed) = record_message(keys, input, st(case, "msg_id_seed_label"));
        let sender = pubky_id(&shop.identity);
        let entry = json!({
            "accepted_at": st(input, "accepted_at"),
            "cert": certificate(keys, shop).signed(),
            "plaintext": {
                "json": enc::b64(signed.json()),
                "sender_app": enc::b64(&signed.sender_app_id()),
                "signature": enc::b64(&signed.signature()),
            },
            "sender": sender,
        });
        let (source, value, natural) = if list {
            (
                "task_lists record of the shop app",
                json!({
                    "app_id": shop.app_id,
                    "list": entry,
                    "msg_ids": [message.msg_id],
                    "owner": sender,
                    "v": int(case, "record_version"),
                }),
                lp(&[&shop.identity, &signed.sender_app_id()]),
            )
        } else {
            (
                name,
                json!({
                    "counterparty": sender,
                    "messages": [entry],
                    "msg_ids": [message.msg_id],
                    "status": st(case, "record_status"),
                    "v": int(case, "record_version"),
                }),
                lp(&[&shop.identity, &signed.hash()]),
            )
        };
        (
            source,
            serde_json::to_string(&value).expect("record JSON"),
            natural,
        )
    };
    let (_, key, _) = record_address(
        keys,
        &keys.identity("alice"),
        source,
        &natural,
        &Policy::new(scope, &[scope]),
    );
    (text, key)
}

/// Seal each rebuilt record and check its padding, carrying form and opening rules.
#[test]
pub(super) fn test_vectors_sealed() {
    let keys = keys();
    let v = load("sealed.json");
    let description = format!(
        "Sealed shared record values (wire 6.2): XChaCha20-Poly1305 under the scope key with AAD lp(\"{}\", identity, scope, record key). \
         The scope key is alice's scope_key(2, \"tasks\") from keys.json, and record keys are blinded with alice's naming key (identifiers.json). \
         The plaintext sealed is u32_be(len(JSON)) || JSON || zero padding, padded_len bytes long, the smallest of the buckets \
         512, 768, 1024, 1536, ..., 196608, 262144 (2^k for k 9 to 18 and 3 * 2^k for k 8 to 16) that holds it. \
         A delete is a sealed empty plaintext, unpadded, so ct is the 16-byte tag only. The values sealed are records of the sample protocol tasks, \
         which the Dispatch treats as opaque.",
        labels::derive::SEALED,
    );
    generated("sealed.json", &[("/description", json!(description))]);
    let cases = arr(&v, "cases");
    assert!(!cases.is_empty());
    let mut deletes = 0;
    for (index, c) in cases.iter().enumerate() {
        let name = st(c, "name");
        let identity = keys.identity("alice");
        let scope = st(c, "scope");
        let data_epoch = int(c, "data_epoch");
        let identity_key = IdentityKey::from_secret(keys.identity_secrets[&identity]);
        let scope_key = identity_key.scope_key(data_epoch, scope);
        let (plaintext, record_key) = record(&keys, c);
        let aad = sealed::aad(&identity, scope, &record_key);
        let nonce = seed(st(c, "nonce_seed_label"))[..24].try_into().unwrap();
        let json = plaintext.as_bytes();
        let padded = sealed::pad(json).expect("record padding");
        assert_eq!(
            sealed::padded_len(json.len()),
            Some(padded.len()),
            "{name}: padded_len"
        );
        let sealed = SealedValue::seal_with_nonce(
            &scope_key,
            &identity,
            data_epoch,
            scope,
            &record_key,
            json,
            &nonce,
        )
        .expect("seal record");
        let wire = json!(sealed);
        let carried: SealedValue = serde_json::from_value(wire.clone()).expect("read sealed value");
        assert_eq!(sealed, carried, "{name}: ciphertext");
        assert_eq!(carried.ct.len(), padded.len() + TAG_LEN, "{name}: ct_len");
        carried
            .check_shape(scope)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(carried.check_shape("another-scope").is_err());
        generated_members(
            "sealed.json",
            &format!("/cases/{index}"),
            &[
                ("identity_hex", json!(hex::encode(identity))),
                ("record_key", json!(enc::b64(&record_key))),
                ("scope_key_hex", json!(hex::encode(scope_key))),
                ("aad_hex", json!(hex::encode(aad))),
                ("nonce_hex", json!(hex::encode(nonce))),
                ("plaintext", json!(plaintext)),
                ("sealed", wire.clone()),
                ("ct_len", json!(carried.ct.len())),
                ("padded_len", json!(padded.len())),
                ("is_delete", json!(json.is_empty())),
            ],
        );

        // It opens to the value, or to a delete, with the scope key the reader holds.
        let opened = carried.open(&scope_key, &identity, &record_key).unwrap();
        let is_delete = json.is_empty();
        assert_eq!(carried.looks_like_delete(), is_delete, "{name}");
        if is_delete {
            deletes += 1;
            assert_eq!(opened, RecordValue::Delete, "{name}");
            assert_eq!(
                carried.ct.len(),
                TAG_LEN,
                "{name}: a delete is the tag alone"
            );
        } else {
            assert_eq!(opened, RecordValue::Json(json.to_vec()), "{name}");
            assert!(sealed::BUCKETS.contains(&padded.len()), "{name}");
        }
        let held = ScopeKeys::derive_range(&identity_key, &[scope.to_owned()], 1, data_epoch);
        assert_eq!(
            carried.open_with(&held, &identity, &record_key).unwrap(),
            opened,
            "{name}"
        );

        // The AAD binds the record key, the scope and the identity; another key fails.
        assert!(carried.open(&scope_key, &identity, &[0; 32]).is_err());
        assert!(carried.open(&scope_key, &[0; 32], &record_key).is_err());
        let mut moved = carried.clone();
        moved.scope = "another-scope".into();
        assert!(moved.open(&scope_key, &identity, &record_key).is_err());
        let other_epoch = identity_key.scope_key(data_epoch + 1, scope);
        assert!(carried.open(&other_epoch, &identity, &record_key).is_err());
        let earlier = ScopeKeys::derive_range(&identity_key, &[scope.to_owned()], 1, 1);
        if data_epoch > 1 {
            assert!(carried.open_with(&earlier, &identity, &record_key).is_err());
        }

        // A value with a member beside the four is refused.
        let mut extra = wire;
        extra["deleted"] = Value::Bool(true);
        assert!(serde_json::from_value::<SealedValue>(extra).is_err());
    }
    assert!(deletes > 0, "a delete marker");
}
