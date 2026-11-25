//! `documents.json`: every signed document of Dispatch wire 3 but the key bundle, the signer
//! hand-over and the signer backup, with the permission and scope rules, the conflict of two
//! app records, the unfreeze and the discard answer, the auth request an app request binds,
//! and the approval with its companion claim (Dispatch wire 2.2, 3).
//!
//! Every document is checked in its carrying and compact forms, its document bytes and hash,
//! verified, signed again from the fixed keys, read through the records API, and written
//! again from what was read, byte for byte.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use pubky_dispatch_core::enc::{app_id_decode, b64 as b64e, x25519_low_order};
use pubky_dispatch_core::keys::AppKeys as DispatchAppKeys;
use pubky_dispatch_core::records::{
    self, ACCOUNT_OBSERVATION_VALIDITY_MS, AccountBinding, AccountMarkInput,
    AccountObservationBody, AccountView, AppCert, AppRecord, AppRequest, AuthRequest,
    CLOCK_TOLERANCE_MS, CarriedAccountObservation, DAY_MS, Delivery, DiscardAnswer, Enrollment,
    EnrollmentBody, ExportTransfer, Freeze, IdentityBody, IdentityDoc, KeptProofs, ListedApp,
    ReceiveKeyRecord, RecordOrder, RecordView, RenewedCert, ServiceKeyEntry, SignerView, Standing,
    Unfreeze, UnfreezeAt, VersionOrder,
};
use pubky_dispatch_core::sig::SignedDoc;
use pubky_dispatch_core::time::parse_rfc3339;
use pubky_dispatch_core::{Error, labels};
use serde_json::{Value, json};

use crate::common::*;

/// The static vectors' start time (README "Times").
const START: &str = "2026-01-01T00:00:00.000Z";

/// One document of `documents`: its entry and its carrying form.
struct Doc {
    entry: Value,
    signed: SignedDoc,
}

fn signed_of(value: &Value) -> SignedDoc {
    serde_json::from_value(value.clone()).unwrap()
}

fn app_keys(app: &AppKeys) -> DispatchAppKeys {
    DispatchAppKeys::from_secrets(app.signing_secret, app.bundle_secret)
}

/// The app a document of `documents` is about, by the first word of its name.
fn app_of<'a>(keys: &'a Keys, name: &str) -> &'a AppKeys {
    keys.app(name.split(' ').next().unwrap())
}

/// The public key named by a document's signer input.
pub(super) fn document_signer(keys: &Keys, entry: &Value) -> [u8; 32] {
    let signer = st(entry, "signer");
    if let Some(name) = signer.strip_suffix(" identity key") {
        keys.identity(name)
    } else {
        keys.app(signer.strip_suffix(" app").expect("document signer"))
            .signing_public
    }
}

/// Sign `value`'s JSON again under `label` with `secret`, for refusals built from a vector.
fn resign(secret: &[u8; 32], label: &str, value: &Value) -> SignedDoc {
    SignedDoc::sign_bytes(
        &SigningKey::from_bytes(secret),
        label,
        &[],
        serde_json::to_vec(value).unwrap(),
    )
}

fn body_value(signed: &SignedDoc) -> Value {
    serde_json::from_slice(&signed.body_bytes().unwrap()).unwrap()
}

/// A document's exact bytes and signature, in every published representation.
pub(super) fn emit_document(index: usize, label: &str, signed: &SignedDoc) {
    generated_members(
        "documents.json",
        &format!("/documents/{index}"),
        &[
            ("label", json!(label)),
            (
                "body",
                json!(String::from_utf8(signed.body_bytes().unwrap()).unwrap()),
            ),
            ("signed", json!(signed)),
            ("compact", json!(signed.compact())),
            (
                "doc_bytes_hex",
                json!(hex::encode(signed.doc_bytes().unwrap())),
            ),
            ("doc_hash", json!(b64e(&signed.doc_hash().unwrap()))),
        ],
    );
}

/// The auth session and capabilities the wallet binds in its app request.
fn auth_request(input: &Value, app: &AppKeys) -> AuthRequest {
    let auth = AuthRequest {
        client_id: st(input, "client_id").into(),
        client_key: pubky_dispatch_core::sig::public_of(&seed(st(input, "client_seed_label"))),
        secret: seed(st(input, "secret_seed_label")),
        caps: format!(
            "{}:rw",
            records::app_record_path(&app_id_decode(&app.app_id).unwrap())
        ),
    };
    generated_members(
        "documents.json",
        "/auth_request",
        &[
            ("caps", json!(auth.caps)),
            ("client_key", json!(b64e(&auth.client_key))),
            ("secret", json!(b64e(&auth.secret))),
        ],
    );
    auth
}

/// The identity's listed certificates and removed app, with the service key for its inbox.
fn identity_body(
    keys: &Keys,
    owner: &str,
    c: &Value,
    certs: &HashMap<String, AppCert>,
) -> IdentityBody {
    let public = keys.identity(owner);
    let mut body = IdentityBody::first(
        public,
        seed16(c, "signer_seed_label"),
        records::Inbox::new(
            st(c, "origin"),
            keys.service_key(&pubky_dispatch_core::enc::pubky_id(&public)),
        ),
        serde_json::from_value(c["policy"].clone()).unwrap(),
    );
    body.version = int(c, "version");
    body.data_epoch = int(c, "data_epoch");
    for app in strings(&c["listed_apps"]) {
        let cert = &certs[&app];
        body.apps.push(ListedApp {
            app_id: cert.app_id(),
            cert: cert.hash(),
        });
    }
    if owner == "alice" {
        body.removed.push(records::RemovedApp {
            app_id: keys.removed_app,
            distrust_from: parse_rfc3339(st(c, "distrust_from")).unwrap(),
        });
    }
    body
}

/// Issue an app certificate for the selected scopes and validity interval.
fn issue_certificate(keys: &Keys, app: &AppKeys, c: &Value, renewed: bool) -> AppCert {
    use records::AppCertBody;
    let (scopes, permissions) = if renewed {
        (strings(&c["scopes"]), strings(&c["permissions"]))
    } else {
        (app.scopes.clone(), app.permissions.clone())
    };
    let (issued_at, expires_at) = (
        parse_rfc3339(st(c, "issued_at")).unwrap(),
        parse_rfc3339(st(c, "expires_at")).unwrap(),
    );
    let body = AppCertBody::new(
        app.identity,
        app.signing_public,
        app.bundle_public,
        scopes,
        &pubky_dispatch_core::scopes::check_permissions(&permissions).unwrap(),
        issued_at,
        expires_at,
    );
    AppCert::issue(&keys.identity_key(&app.identity), body).unwrap()
}

/// A chosen timestamp or an explicit null in the fixture.
fn optional_time(input: &Value, member: &str) -> Option<u64> {
    match input.get(member).expect(member) {
        Value::Null => None,
        time => Some(parse_rfc3339(time.as_str().expect(member)).unwrap()),
    }
}

/// Apply the chosen renewal, move, age limit or version to Alice's current identity.
fn identity_variant(
    base: &IdentityDoc,
    c: &Value,
    certs: &HashMap<String, AppCert>,
    inbox: &records::Inbox,
) -> IdentityBody {
    let name = st(c, "name");
    let mut body = base.body().clone();
    body.version = int(c, "version");
    if name.contains("wallet renewal") {
        let old = &certs["wallet"];
        let new = &certs["wallet certificate, renewed"];
        body.apps
            .iter_mut()
            .find(|a| a.app_id == old.app_id())
            .unwrap()
            .cert = new.hash();
        body.renewed.push(RenewedCert {
            app_id: old.app_id(),
            cert: old.hash(),
            until: optional_time(c, "until"),
        });
        body.data_epoch = int(c, "data_epoch");
    } else if name.contains("after the move") {
        body.service_keys.push(ServiceKeyEntry {
            generation: body.generation,
            key: body.inbox.service_key,
        });
        body.generation = int(c, "generation");
        body.inbox = inbox.clone();
    } else if name.contains("record age limit") {
        body.record_max_age = Some(int(c, "record_max_age"));
    } else if name.contains("first delivery") {
        body.data_epoch = int(c, "data_epoch");
    } else {
        assert!(name.contains("hand-over abort"));
    }
    body
}

/// The certificates and identities used to sign documents and seal bundles.
pub(super) struct IssuedDocuments {
    pub certs: HashMap<String, AppCert>,
    pub identities: HashMap<String, IdentityDoc>,
    next_inbox: records::Inbox,
}

fn certificate_key(name: &str) -> Option<&str> {
    let (app, kind) = name.split_once(' ')?;
    kind.starts_with("certificate")
        .then_some(if kind.ends_with(", renewed") {
            name
        } else {
            app
        })
}

impl IssuedDocuments {
    pub fn from_fixture(keys: &Keys) -> Self {
        Self::new(keys, arr(&load("documents.json"), "documents"))
    }

    fn new(keys: &Keys, entries: &[Value]) -> Self {
        let next_inbox = records::Inbox::new(
            st(&load("keys.json")["next_service_key"], "origin"),
            keys.next_service_key,
        );
        let mut certs = HashMap::new();
        for c in entries {
            let name = st(c, "name");
            if let Some(key) = certificate_key(name) {
                let cert =
                    issue_certificate(keys, app_of(keys, name), c, name.ends_with(", renewed"));
                assert!(certs.insert(key.to_owned(), cert).is_none(), "{name}");
            }
        }
        let mut identities = HashMap::new();
        for c in entries {
            let name = st(c, "name");
            if let Some(owner) = name.strip_suffix(" identity.json") {
                let body = identity_body(keys, owner, c, &certs);
                let doc = IdentityDoc::sign(&keys.identity_key(&body.identity), body).unwrap();
                identities.insert(name.to_owned(), doc);
            }
        }
        for c in entries {
            let name = st(c, "name");
            if name.starts_with("alice identity.json") && name != "alice identity.json" {
                let base = &identities["alice identity.json"];
                let body = identity_variant(base, c, &certs, &next_inbox);
                let doc = IdentityDoc::sign(&keys.identity_key(&body.identity), body).unwrap();
                identities.insert(name.to_owned(), doc);
            }
        }
        Self {
            certs,
            identities,
            next_inbox,
        }
    }
}

/// Keep the quoted seeds beside the values they describe.
fn descriptions(file: &Value, entries: &[Value]) {
    let signer_seed = |name: &str| {
        let identity = entries.iter().find(|c| c["name"] == name).unwrap();
        st(identity, "signer_seed_label")
    };
    let text = format!(
        "Signed documents (wire 2.2, 3): carried as {{ \"body\": base64url of the exact JSON bytes, \"sig\": base64url \
         }}, in headers as \"<body>.<sig>\". Signed document bytes are lp(body bytes, signature); every hash over a \
         document (certificate hashes in identity.json, chain item hashes, the freeze hash) is BLAKE3 of those \
         bytes. Each identity.json names its signing install in signer, a 16-byte signer ID (seeds {} and {}).",
        signer_seed("alice identity.json"),
        signer_seed("bob identity.json"),
    );
    generated_members("documents.json", "", &[("description", json!(text))]);
    let [cek, nonce, ikm_e] = seal_seed_labels(st(&file["approval"], "seal_seed_label"));
    let text = format!(
        "Wire 3.10: the wallet's approval, the companion claim of its grant approval: the hash of its app request, \
         its certificate, alice's identity.json version 3 listing it, and its full key bundle (data epochs 1 and 2 \
         and the naming key), one part sealed with fixed randomness (seeds {cek}, {nonce}, \
         {ikm_e}) to its bundle key and signed by alice's identity key. It holds no key in the clear.",
    );
    generated_members(
        "documents.json",
        "/approval",
        &[("description", json!(text))],
    );
    let text = format!(
        "Wire 3.6: the next service's signed answer that it discarded the import bound to the freeze, with the \
         service key the freeze names (seed {}), and the unfreeze as the signer then sends it to the old service.",
        st(&load("keys.json")["next_service_key"], "seed_label"),
    );
    generated_members(
        "documents.json",
        "/discarded",
        &[("description", json!(text))],
    );
}

/// Issue the named documents in dependency order and use their signed values for related cases.
#[test]
pub(super) fn test_vectors_documents() {
    issue_documents();
}

/// The signed carriers issued from the document inputs, indexed by name.
pub(super) fn issue_documents() -> HashMap<String, SignedDoc> {
    use records::{AppRecordBody, AppRequestBody, FreezeBody, ReceiveKeyBody};
    let file = load("documents.json");
    super::generation::check_annotations("documents.json", &file);
    let entries = arr(&file, "documents");
    let keys = keys();
    let alice = keys.identity("alice");
    let key = keys.identity_key(&alice);
    let wallet = keys.app("wallet");
    let auth = auth_request(&file["auth_request"], wallet);
    let issued = IssuedDocuments::new(&keys, entries);
    let certs = &issued.certs;
    let base = &issued.identities["alice identity.json"];
    let mut docs = HashMap::new();
    let emit = |docs: &mut HashMap<String, SignedDoc>, i: usize, label, signed: &SignedDoc| {
        let public = document_signer(&keys, &entries[i]);
        signed.verify(&public, label, &[]).unwrap();
        emit_document(i, label, signed);
        assert!(
            docs.insert(st(&entries[i], "name").into(), signed.clone())
                .is_none()
        );
    };
    for (i, c) in entries.iter().enumerate() {
        let name = st(c, "name");
        let (owner, kind) = name.split_once(' ').unwrap();
        if let Some(key) = certificate_key(name) {
            emit(&mut docs, i, labels::sig::APP_CERT, certs[key].signed());
        } else if let Some(doc) = issued.identities.get(name) {
            emit(&mut docs, i, labels::sig::IDENTITY, doc.signed());
        } else if kind.starts_with("enrollment") {
            let enrollment = sign_enrollment(&keys, c, base, &issued.next_inbox);
            emit(&mut docs, i, labels::sig::ENROLL, enrollment.signed());
        } else if kind.starts_with("app record") {
            let app = keys.app(owner);
            let mut body = AppRecordBody::new(
                &certs[owner],
                strings(&c["accepts"]),
                parse_rfc3339(st(c, "updated_at")).unwrap(),
            );
            body.protocols = serde_json::from_value(c["protocols"].clone()).unwrap();
            body.expires_at = optional_time(c, "expires_at");
            let record = AppRecord::sign(&app_keys(app), body).unwrap();
            emit(&mut docs, i, labels::sig::APP_RECORD, record.signed());
        } else if kind == "receive key record" {
            let app = keys.app(owner);
            let body = ReceiveKeyBody {
                identity: app.identity,
                app_id: certs[owner].app_id(),
                n: app.receive_n,
                kid: app.receive_kid,
                x25519: app.receive_public,
                suite_keys: None,
            };
            let record = ReceiveKeyRecord::sign(&app_keys(app), &certs[owner], body).unwrap();
            emit(&mut docs, i, labels::sig::RECEIVE_KEY, record.signed());
        } else if kind == "freeze" {
            let freeze = Freeze::sign(
                &key,
                FreezeBody {
                    identity: alice,
                    inbox: issued.next_inbox.clone(),
                    next_generation: int(c, "next_generation"),
                    issued_at: parse_rfc3339(st(c, "issued_at")).unwrap(),
                    nonce: seed16(c, "nonce_seed_label"),
                },
            )
            .unwrap();
            emit(&mut docs, i, labels::sig::FREEZE, freeze.signed());
            check_freeze_and_unfreeze(&keys, freeze.signed());
        } else if kind == "app request" {
            let signer = app_keys(wallet);
            let request = AppRequest::sign(
                &signer,
                AppRequestBody::new(&signer, wallet.scopes.clone(), &auth),
            )
            .unwrap();
            emit(&mut docs, i, labels::sig::APP_REQUEST, request.signed());
        } else {
            assert_eq!(name, "alice export transfer, for export.json's manifest");
            assert_eq!(st(c, "signer"), "alice identity key");
        }
    }
    let cert = &certs["wallet"];
    document_variants(&keys, &file, cert, &docs);
    check_identity_rejections(&keys, &file, base.signed());
    approval_cases(&keys, &file, &docs["wallet app request"], cert, base);
    descriptions(&file, entries);
    docs
}

/// Sign a variant with one wire member changed, retaining the encoder's field order.
fn changed_member(
    base: &SignedDoc,
    member: &str,
    value: &Value,
    key: &[u8; 32],
    label: &str,
) -> SignedDoc {
    let text = String::from_utf8(base.body_bytes().unwrap()).unwrap();
    let before = format!("\"{member}\":{}", body_value(base)[member]);
    assert_eq!(text.matches(&before).count(), 1);
    let text = text.replace(&before, &format!("\"{member}\":{value}"));
    SignedDoc::sign_bytes(&SigningKey::from_bytes(key), label, &[], text.into_bytes())
}

/// The wire body and carrying form of a document variant.
fn emit_variant(path: &str, signed: &SignedDoc) {
    generated_members(
        "documents.json",
        path,
        &[
            (
                "body",
                json!(String::from_utf8(signed.body_bytes().unwrap()).unwrap()),
            ),
            ("signed", json!(signed)),
        ],
    );
}

/// Change the certificate or app record at the one field named by each case.
fn document_variants(keys: &Keys, file: &Value, cert: &AppCert, docs: &HashMap<String, SignedDoc>) {
    let wallet = keys.app("wallet");
    let secret = &keys.identity_secrets[&wallet.identity];
    for (group, list, field) in [
        ("permission_rejections", "cases", "permissions"),
        ("scope_rule", "refused", "scopes"),
        ("scope_rule", "accepted", "scopes"),
    ] {
        for (i, c) in arr(&file[group], list).iter().enumerate() {
            let path = format!("/{group}/{list}/{i}");
            let value = if field == "permissions" {
                let mut permissions = wallet.permissions.clone();
                match st(c, "name") {
                    "duplicate: claims.read twice" => permissions.insert(0, permissions[0].clone()),
                    "reordered: claims.write before claims.read" => permissions.swap(0, 1),
                    "a name that isn't a Dispatch permission: claims.admin" => {
                        permissions.push(st(c, "extra_permission").into())
                    }
                    name => panic!("unknown permission rejection {name}"),
                }
                generated_members("documents.json", &path, &[("scopes", json!(cert.scopes()))]);
                json!(permissions)
            } else {
                let mut scopes = cert.scopes().to_vec();
                scopes.extend(strings(&c["extra_scopes"]));
                json!(scopes)
            };
            let signed =
                changed_member(cert.signed(), field, &value, secret, labels::sig::APP_CERT);
            generated_members("documents.json", &path, &[(field, value)]);
            emit_variant(&path, &signed);
            let verified = AppCert::verify(&signed, &wallet.identity);
            if list == "accepted" {
                verified.unwrap();
            } else {
                assert!(
                    verified
                        .unwrap_err()
                        .to_string()
                        .contains(rule_of(st(c, "reason"))),
                    "{}",
                    st(c, "name")
                );
            }
        }
    }
    let base = &docs["wallet app record"];
    for list in ["accepted", "refused"] {
        for (i, c) in arr(&file["app_record_protocols"], list).iter().enumerate() {
            let protocols = if st(c, "name") == "protocols that isn't an object" {
                c.get("protocols").expect("replacement protocols").clone()
            } else {
                let mut protocols = body_value(base)["protocols"].clone();
                protocols[st(c, "protocol")] =
                    c.get("member").expect("chosen protocol member").clone();
                generated_members(
                    "documents.json",
                    &format!("/app_record_protocols/{list}/{i}"),
                    &[("protocols", protocols.clone())],
                );
                protocols
            };
            let signed = changed_member(
                base,
                "protocols",
                &protocols,
                &wallet.signing_secret,
                labels::sig::APP_RECORD,
            );
            emit_variant(&format!("/app_record_protocols/{list}/{i}"), &signed);
            let result = AppRecord::verify(&signed, &wallet.identity);
            if list == "accepted" {
                result.unwrap();
            } else {
                let why = st(c, "reason");
                let rule = if why.contains("isn't a protocol name") {
                    "isn't a scope name"
                } else if why.contains("isn't an object") {
                    "isn't an object"
                } else {
                    assert!(why.contains("wrong type or value"));
                    "wrong type or value"
                };
                let error = result.unwrap_err().to_string();
                assert!(error.contains(rule), "{}: {error}", st(c, "name"));
            }
        }
    }
    let conflict = &file["app_record_conflict"];
    let kept = AppRecord::verify(&docs[st(conflict, "kept")], &wallet.identity).unwrap();
    let mut records = Vec::new();
    for (i, c) in arr(conflict, "records").iter().enumerate() {
        let mut body = kept.body().clone();
        body.updated_at = parse_rfc3339(st(conflict, "updated_at")).unwrap();
        body.protocols.get_mut("tasks").unwrap()["features"]["board_kinds"] =
            json!([st(c, "board_kind")]);
        let record = AppRecord::sign(&app_keys(wallet), body).unwrap();
        emit_variant(
            &format!("/app_record_conflict/records/{i}"),
            record.signed(),
        );
        records.push(record);
    }
    let [a, b] = records.as_slice() else {
        panic!("two app records")
    };
    assert_eq!(
        a.order(b) == RecordOrder::Conflict,
        conflict["conflict"].as_bool().unwrap()
    );
}

/// Seal the approval for the wallet and the part whose range exceeds its identity's epoch.
fn approval_cases(
    keys: &Keys,
    file: &Value,
    request: &SignedDoc,
    cert: &AppCert,
    identity: &IdentityDoc,
) {
    use records::{Approval, BundlePart, KeyBundle, KeyBundleContents};
    let request = AppRequest::verify(request).unwrap();
    let key = keys.identity_key(&cert.identity());
    let scopes = keyed_scopes(&file["approval"]);
    let has_keys = |s: &str| scopes.contains(s);
    let approval = &file["approval"];
    let part = |input: &Value, last| {
        let contents = KeyBundleContents::derive(&key, cert, 1, last, &has_keys).unwrap();
        let bundle = KeyBundle::seal_json_with(
            &key,
            &cert.app_id(),
            &cert.bundle_key(),
            &contents.to_json().unwrap(),
            &fixed_from_seeds(st(input, "seal_seed_label")),
        )
        .unwrap();
        BundlePart {
            bundle,
            first_epoch: 1,
            last_epoch: last,
        }
    };
    let good = Approval::new(
        &request,
        cert.clone(),
        identity.clone(),
        vec![part(approval, identity.data_epoch())],
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&good.to_json().unwrap()).unwrap();
    generated_members("documents.json", "/approval", &[("approval", value)]);
    for (i, c) in arr(approval, "rejections").iter().enumerate() {
        let last = int(c, "last_epoch");
        let value = json!({
            "v": 1,
            "kind": records::APPROVAL_KIND,
            "request": b64e(&request.hash()),
            "cert": cert.signed(),
            "identity": identity.signed(),
            "bundles": [part(c, last)],
        });
        let error = Approval::read(
            &serde_json::to_vec(&value).unwrap(),
            &request,
            &cert.identity(),
            &keys.app("wallet").bundle_secret,
            &has_keys,
        )
        .unwrap_err()
        .to_string();
        let (_, wire) = error.split_once("Dispatch wire ").unwrap();
        let (step, reason) = wire
            .strip_prefix("3.10 step ")
            .unwrap()
            .split_once(": ")
            .unwrap();
        assert_eq!(
            step.parse::<u64>().unwrap(),
            int(c, "step"),
            "{}",
            st(c, "name")
        );
        assert_eq!(reason, st(c, "error"), "{}", st(c, "rule"));
        generated_members(
            "documents.json",
            &format!("/approval/rejections/{i}"),
            &[("approval", value)],
        );
    }
}

/// Verify the published documents through the reader APIs.
#[test]
fn test_vectors_documents_readers() {
    let keys = keys();
    let v = load("documents.json");
    let docs: HashMap<String, Doc> = arr(&v, "documents")
        .iter()
        .map(|entry| {
            let signed = signed_of(&entry["signed"]);
            (
                st(entry, "name").to_owned(),
                Doc {
                    entry: entry.clone(),
                    signed,
                },
            )
        })
        .collect();
    assert_eq!(docs.len(), arr(&v, "documents").len(), "names are unique");
    let doc = |name: &str| -> &SignedDoc {
        &docs
            .get(name)
            .unwrap_or_else(|| panic!("no document {name}"))
            .signed
    };
    let alice = keys.identity("alice");

    // Every document: its forms, bytes and hash, its signature from the fixed keys, and a
    // tampered body refused.
    for entry in arr(&v, "documents") {
        let name = st(entry, "name");
        let label = st(entry, "label");
        let signed = doc(name);
        let body = signed.body_bytes().unwrap();
        assert_eq!(body, st(entry, "body").as_bytes(), "{name}: body");
        assert_eq!(signed.compact(), st(entry, "compact"), "{name}: compact");
        assert_eq!(
            &SignedDoc::from_compact(st(entry, "compact")).unwrap(),
            signed
        );
        assert_eq!(
            serde_json::to_value(signed).unwrap(),
            entry["signed"],
            "{name}"
        );
        assert_eq!(
            hex::encode(signed.doc_bytes().unwrap()),
            st(entry, "doc_bytes_hex"),
            "{name}: document bytes"
        );
        assert_eq!(
            b64e(&signed.doc_hash().unwrap()),
            st(entry, "doc_hash"),
            "{name}"
        );
        let signer = document_signer(&keys, entry);
        assert!(
            reproduce(
                &keys,
                &signer,
                label,
                &[&body],
                &signed.sig_bytes().unwrap()
            ),
            "{name}: no fixed key"
        );
        signed.verify(&signer, label, &[]).unwrap();
        let mut tampered = body.clone();
        tampered[10] ^= 1;
        let tampered = SignedDoc::from_parts(&tampered, &signed.sig_bytes().unwrap());
        assert!(tampered.verify(&signer, label, &[]).is_err(), "{name}");
    }

    let certs = check_certificates(&keys, &v, &docs);
    check_app_records(&keys, &docs, &certs);
    check_receive_keys(&keys, &docs, &certs);
    check_identity_docs(&keys, &docs, &certs);
    check_enrollments(&keys, &docs);
    check_app_request(&keys, &v, &docs, &certs);
    check_export_transfer(&keys, &docs);
    check_app_record_conflict(&keys, &v, &docs);
    check_app_record_protocols(&keys, &v);
    check_approval(&keys, &v, &docs, &certs);
    // Bob's certificate is refused for Alice.
    assert!(AppCert::verify(doc("shop certificate"), &alice).is_err());
}

/// The certificates (Dispatch wire 3.1): read, issued again byte for byte, and their members
/// checked against `keys.json` and the README's lifetimes.
fn check_certificates(
    keys: &Keys,
    v: &Value,
    docs: &HashMap<String, Doc>,
) -> HashMap<String, AppCert> {
    let start = parse_rfc3339(START).unwrap();
    let mut certs = HashMap::new();
    for entry in arr(v, "documents") {
        if st(entry, "label") != labels::sig::APP_CERT {
            continue;
        }
        let name = st(entry, "name");
        let signed = &docs[name].signed;
        let app = app_of(keys, name);
        let cert = AppCert::verify(signed, &app.identity).unwrap_or_else(|e| panic!("{name}: {e}"));
        let again = AppCert::issue(&keys.identity_key(&app.identity), cert.body().clone()).unwrap();
        assert_eq!(again.signed(), signed, "{name}: issued again");
        assert_eq!(cert.hash(), signed.doc_hash().unwrap());
        assert_eq!(cert.app_id(), app_id_decode(&app.app_id).unwrap(), "{name}");
        assert_eq!(cert.signing_key(), app.signing_public, "{name}");
        assert_eq!(cert.bundle_key(), app.bundle_public, "{name}");
        assert!(!x25519_low_order(&cert.bundle_key()));
        assert!(
            cert.body().suite_keys.is_none(),
            "{name}: writers write no suite_keys"
        );
        let permissions: Vec<&str> = cert.permissions().iter().map(|p| p.as_str()).collect();
        if name.contains("renewed") {
            assert!(
                cert.scopes().iter().all(|s| app.scopes.contains(s)),
                "{name}"
            );
        } else {
            assert_eq!(cert.scopes(), app.scopes.as_slice(), "{name}");
            assert_eq!(permissions, app.permissions, "{name}");
        }
        // README "Certificate lifetimes".
        let expires = if name == "phone certificate" {
            start + 365 * DAY_MS
        } else if name.contains("renewed") {
            start + 90 * DAY_MS
        } else {
            assert_eq!(cert.issued_at(), start - 31 * DAY_MS, "{name}: issued_at");
            cert.issued_at() + 365 * DAY_MS
        };
        assert_eq!(cert.expires_at(), expires, "{name}: expires_at");
        assert!(!cert.expired_at(start) && cert.expired_at(expires));
        certs.insert(name.to_owned(), cert);
    }
    // The hierarchy on the vectors' own scopes: a sub-scope's certificate holds only it.
    for cert in certs.values() {
        for scope in cert.scopes() {
            assert!(cert.holds_scope(scope));
            if let Some(name) = pubky_dispatch_core::scopes::parent(scope) {
                assert!(!cert.holds_scope(name), "{scope} covers nothing but itself");
            } else {
                assert!(
                    cert.holds_scope(&format!("{scope}:any")),
                    "{scope} covers its subs"
                );
            }
        }
    }
    certs
}

/// The app records (Dispatch wire 3.2): read, signed again byte for byte, carrying their app's
/// certificate, with their protocols' members read as written.
fn check_app_records(keys: &Keys, docs: &HashMap<String, Doc>, certs: &HashMap<String, AppCert>) {
    for (name, d) in docs {
        if st(&d.entry, "label") != labels::sig::APP_RECORD {
            continue;
        }
        let app = app_of(keys, name);
        let record =
            AppRecord::verify(&d.signed, &app.identity).unwrap_or_else(|e| panic!("{name}: {e}"));
        let again = AppRecord::sign(&app_keys(app), record.body().clone()).unwrap();
        assert_eq!(again.signed(), &d.signed, "{name}: signed again");
        let cert = certs
            .iter()
            .find(|(n, c)| {
                n.starts_with(&app.name)
                    && !n.contains("renewed")
                    && c.app_id() == record.cert().app_id()
            })
            .map(|(_, c)| c)
            .unwrap_or_else(|| panic!("{name}: no certificate"));
        assert_eq!(record.cert().hash(), cert.hash(), "{name}");
        assert!(record.carries(cert));
        assert!(!record.body().accepts.is_empty());
        for kind in &record.body().accepts {
            assert!(record.accepts(kind));
        }
        // The protocols' members are read as written, opaque to the Dispatch; `protocols` is
        // always written, `{}` when they add nothing.
        let written = body_value(&d.signed);
        assert!(
            written["protocols"].is_object(),
            "{name}: protocols written"
        );
        for (protocol, member) in written["protocols"].as_object().unwrap() {
            assert_eq!(
                record
                    .body()
                    .protocol(protocol)
                    .map(|m| Value::Object(m.clone()))
                    .as_ref(),
                Some(member),
                "{name}: {protocol}"
            );
        }
        // The Dispatch requires no `expires_at`, but it is always written.
        assert!(
            written.get("expires_at").is_some(),
            "{name}: expires_at written"
        );
        // A record verifies only for its own identity.
        let other = keys
            .identities
            .values()
            .find(|i| **i != app.identity)
            .unwrap();
        assert!(AppRecord::verify(&d.signed, other).is_err());
    }
    // A renewed certificate of the same app and keys: the wallet's record carries an earlier
    // one, which check 6 of Dispatch wire 3.8 takes.
    let wallet =
        AppRecord::verify(&docs["wallet app record"].signed, &keys.identity("alice")).unwrap();
    assert!(wallet.carries(&certs["wallet certificate, renewed"]));
    assert!(!wallet.carries(&certs["phone certificate"]));
}

/// The receive key records (Dispatch wire 3.4): read against their app's certificate, signed
/// again byte for byte, naming the fixed receive keys.
fn check_receive_keys(keys: &Keys, docs: &HashMap<String, Doc>, certs: &HashMap<String, AppCert>) {
    for (name, d) in docs {
        if st(&d.entry, "label") != labels::sig::RECEIVE_KEY {
            continue;
        }
        let app = app_of(keys, name);
        let cert = &certs[&format!("{} certificate", app.name)];
        let record =
            ReceiveKeyRecord::verify(&d.signed, cert).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(record.kid(), app.receive_kid, "{name}");
        assert_eq!(record.x25519(), app.receive_public, "{name}");
        assert_eq!(record.n(), 0, "{name}: its first key");
        assert!(record.follows(None));
        let again = ReceiveKeyRecord::sign(&app_keys(app), cert, record.body().clone()).unwrap();
        assert_eq!(again.signed(), &d.signed, "{name}: signed again");
        // Unknown members are refused here.
        let mut extra = body_value(&d.signed);
        extra["future"] = json!(1);
        let forged = resign(&app.signing_secret, labels::sig::RECEIVE_KEY, &extra);
        assert!(ReceiveKeyRecord::verify(&forged, cert).is_err());
        // Another app's certificate doesn't verify it.
        let other = certs
            .values()
            .find(|c| c.app_id() != cert.app_id())
            .unwrap();
        assert!(ReceiveKeyRecord::verify(&d.signed, other).is_err());
    }
}

/// The `identity.json` documents (Dispatch wire 3.3, 3.8): read, signed again byte for byte,
/// each rebuilt from alice's version 3 by the change it makes, and the rules of versions,
/// delivery, standing, renewal and equivocation on them.
fn check_identity_docs(keys: &Keys, docs: &HashMap<String, Doc>, certs: &HashMap<String, AppCert>) {
    let alice = keys.identity("alice");
    let alice_key = keys.identity_key(&alice);
    let read = |name: &str| {
        let d = &docs[name];
        let id = document_signer(keys, &d.entry);
        let doc = IdentityDoc::verify(&d.signed, &id).unwrap_or_else(|e| panic!("{name}: {e}"));
        let again = IdentityDoc::sign(&keys.identity_key(&id), doc.body().clone()).unwrap();
        assert_eq!(again.signed(), &d.signed, "{name}: signed again");
        assert_eq!(IdentityDoc::verify_named(&d.signed).unwrap(), doc);
        doc
    };
    for (name, d) in docs {
        if st(&d.entry, "label") != labels::sig::IDENTITY {
            continue;
        }
        let doc = read(name);
        let account = pubky_dispatch_core::enc::pubky_id(&doc.identity());
        if name.contains("after the move") {
            continue;
        }
        assert_eq!(
            doc.inbox().service_key,
            keys.service_key(&account),
            "{name}"
        );
        assert!(doc.body().service_keys.is_empty(), "{name}");
    }
    let v1 = read("alice identity.json, first delivery (version 1)");
    let v3 = read("alice identity.json");
    let v4 = read("alice identity.json, wallet renewal in progress");
    let v5 = read("alice identity.json, wallet renewal closed");
    let v6 = read("alice identity.json, record age limit (version 6)");
    let moved = read(
        "alice identity.json after the move to the next service (version 7, generation 2), \
         keeping generation 1's service key in service_keys",
    );
    let abort = read("alice identity.json, hand-over abort (version 5)");
    let sign = |body: IdentityBody| IdentityDoc::sign(&alice_key, body).unwrap();

    // Version 3 lists each app's certificate by its document hash, and the removed app.
    for app in ["wallet", "phone", "executor"] {
        let id = app_id_decode(&keys.app(app).app_id).unwrap();
        assert_eq!(
            v3.listed_cert(&id),
            Some(certs[&format!("{app} certificate")].hash())
        );
        assert_eq!(
            v3.standing(&id, &certs[&format!("{app} certificate")].hash()),
            Standing::Listed
        );
    }
    let removed = keys.removed_app;
    assert!(v3.lists_removed(&removed));
    let distrust = parse_rfc3339(st(&docs["alice identity.json"].entry, "distrust_from")).unwrap();
    assert!(v3.counts_at(&removed, &[0; 32], distrust - CLOCK_TOLERANCE_MS));
    assert!(!v3.counts_at(&removed, &[0; 32], distrust - CLOCK_TOLERANCE_MS + 1));
    assert!(!v3.current_now(&removed, &[0; 32]));
    let bob = read("bob identity.json");
    let shop = &certs["shop certificate"];
    assert!(bob.current_now(&shop.app_id(), &shop.hash()));
    assert_eq!(
        bob.record_max_age_ms(),
        records::DEFAULT_RECORD_MAX_AGE_S * 1000
    );

    // Each version is version 3 with one change, written again byte for byte.
    let mut b1 = v3.body().clone();
    b1.version = 1;
    b1.data_epoch = 1;
    assert_eq!(sign(b1).signed(), v1.signed(), "version 1");
    let mut b6 = v3.body().clone();
    b6.version = 6;
    b6.record_max_age = Some(30 * 86_400);
    assert_eq!(sign(b6).signed(), v6.signed(), "version 6");
    assert_eq!(v6.record_max_age_ms(), 30 * DAY_MS);
    let mut b5 = v3.body().clone();
    b5.version = 5;
    assert_eq!(sign(b5).signed(), abort.signed(), "the hand-over abort");
    let next = load("keys.json")["next_service_key"].clone();
    let next_key = keys.next_service_key;
    let mut b7 = v3.body().clone();
    b7.version = 7;
    b7.generation = 2;
    b7.inbox = records::Inbox::new(st(&next, "origin"), next_key);
    b7.service_keys = vec![ServiceKeyEntry {
        generation: 1,
        key: v3.inbox().service_key,
    }];
    assert_eq!(sign(b7.clone()).signed(), moved.signed(), "after the move");
    assert_eq!(moved.service_key_of(1), Some(v3.inbox().service_key));
    assert_eq!(moved.service_key_of(2), Some(next_key));
    assert_eq!(moved.service_key_of(3), None);
    let (old, new) = (
        &certs["wallet certificate"],
        &certs["wallet certificate, renewed"],
    );
    let wallet = old.app_id();
    let mut b4 = v3.body().clone();
    b4.version = 4;
    b4.data_epoch = 3;
    for app in &mut b4.apps {
        if app.app_id == wallet {
            *app = ListedApp {
                app_id: wallet,
                cert: new.hash(),
            };
        }
    }
    b4.renewed.push(RenewedCert {
        app_id: wallet,
        cert: old.hash(),
        until: None,
    });
    assert_eq!(sign(b4.clone()).signed(), v4.signed(), "version 4");
    let until = parse_rfc3339(st(
        &docs["alice identity.json, wallet renewal closed"].entry,
        "until",
    ))
    .unwrap();
    let mut b5 = b4.clone();
    b5.version = 5;
    assert_eq!(b5.close_renewals(&wallet, until), 1);
    assert_eq!(sign(b5).signed(), v5.signed(), "version 5");

    // The first-document rule, and versions only increasing.
    v1.check_first().unwrap();
    assert!(v3.check_first().is_err());
    for (earlier, later) in [
        (&v1, &v3),
        (&v3, &v4),
        (&v4, &v5),
        (&v3, &v6),
        (&v3, &moved),
    ] {
        earlier.check_successor(later).unwrap();
        assert_eq!(earlier.compare(later), VersionOrder::Newer);
        assert!(later.check_successor(earlier).is_err());
    }
    // Two bodies at version 5: equivocation, for every reader that sees both.
    assert_eq!(v5.compare(&abort), VersionOrder::Equivocation);
    assert!(v5.check_successor(&abort).is_err());
    let mut seen = records::SeenBodies::new();
    seen.see(&v5).unwrap();
    seen.see(&v5).unwrap();
    assert!(seen.see(&abort).is_err());
    assert!(seen.equivocates(&alice));
    assert!(!seen.equivocates(&keys.identity("bob")));

    // Delivery to the own Dispatch: version 1 first, then each building on the one before.
    let origin = v3.inbox().url.clone();
    let view = |held| account_view(held, &origin);
    assert_eq!(
        records::check_delivery(&view(None), &v1, None),
        Ok(Delivery::New(None))
    );
    assert!(
        records::check_delivery(&view(None), &v3, None).is_err(),
        "not a first document"
    );
    for (held, next) in [(&v1, &v3), (&v3, &v4), (&v4, &v5)] {
        assert_eq!(
            records::check_delivery(&view(Some(held)), next, Some(&held.hash())),
            Ok(Delivery::New(None))
        );
        assert!(records::check_delivery(&view(Some(held)), next, None).is_err());
        assert_eq!(
            records::check_delivery(&view(Some(next)), next, None),
            Ok(Delivery::Retry)
        );
    }
    assert!(
        records::check_delivery(&view(Some(&v5)), &abort, Some(&v4.hash())).is_err(),
        "another body at the version held"
    );
    // The move keeps generation 1's service key, which the Dispatch checks.
    let kept = [(1, v3.inbox().service_key)];
    let kept = KeptProofs {
        records: &kept,
        claim_entries: &[],
    };
    records::check_kept_service_keys(&moved, &kept).unwrap();
    let mut without = b7.clone();
    without.service_keys.clear();
    assert_eq!(
        records::check_kept_service_keys(&sign(without), &kept),
        Err(vec![1])
    );
    assert_eq!(
        records::signer_service_keys(
            Some(&[1, 2]),
            &[],
            ServiceKeyEntry {
                generation: 1,
                key: v3.inbox().service_key,
            },
            &[],
            2,
            None,
        )
        .unwrap(),
        moved.body().service_keys
    );

    // The renewal (Dispatch wire 3.8): same app and keys, a later issued_at, and a reduction
    // that rotates the data epoch, closed at once at the delivery's time plus the tolerance.
    assert!(records::is_renewal(old, new));
    assert!(records::is_reduction(old, new));
    assert!(records::reduction_rotates(old, new, |_| true));
    assert!(!records::reduction_rotates(old, new, |_| false));
    let (bundle_last, epoch) = records::renewal_epochs(true, v3.data_epoch()).unwrap();
    assert_eq!((bundle_last, epoch), (v4.data_epoch(), v4.data_epoch()));
    let delivered_at = until - CLOCK_TOLERANCE_MS;
    assert_eq!(
        records::closing_until(true, delivered_at, None),
        Some(until)
    );
    let find = |h: &[u8; 32]| certs.values().find(|c| &c.hash() == h);
    assert_eq!(records::owed_closings(&v4, find), vec![wallet]);
    assert!(records::owed_closings(&v5, find).is_empty());
    assert_eq!(v4.standing(&wallet, &new.hash()), Standing::Listed);
    assert_eq!(v4.standing(&wallet, &old.hash()), Standing::RenewedOpen);
    assert!(v4.current_now(&wallet, &old.hash()));
    assert_eq!(
        v5.standing(&wallet, &old.hash()),
        Standing::RenewedClosed { until }
    );
    assert!(!v5.current_now(&wallet, &old.hash()));
    assert!(v5.counts_at(&wallet, &old.hash(), delivered_at - 1));
    assert!(!v5.counts_at(&wallet, &old.hash(), delivered_at));
    assert!(!v5.counts_at(&wallet, &old.hash(), until - 1));
    assert!(v5.counts_at(&wallet, &new.hash(), until + DAY_MS));
}

/// What a Dispatch at `origin` holds for alice's account, holding `held`.
fn account_view<'a>(held: Option<&'a IdentityDoc>, origin: &'a str) -> AccountView<'a> {
    AccountView {
        held,
        app_limit: 32,
        staged: false,
        origin,
        enrollment_key: None,
        kept_app_ids: &[],
        kept_proofs: KeptProofs::default(),
    }
}

/// The freeze, the unfreeze and the discard answer (Dispatch wire 3.6).
fn check_freeze_and_unfreeze(keys: &Keys, signed: &SignedDoc) {
    let alice = keys.identity("alice");
    let alice_key = keys.identity_key(&alice);
    let freeze = Freeze::verify(signed, &alice).unwrap();
    assert_eq!(
        Freeze::sign(&alice_key, freeze.body().clone())
            .unwrap()
            .signed(),
        signed
    );
    let next_key = keys.next_service_key;
    assert_eq!(freeze.body().next_generation, 2);
    assert!(Freeze::verify(signed, &keys.identity("bob")).is_err());

    let unfreeze = Unfreeze::sign(&alice_key, &freeze.hash());
    generated_members("documents.json", "", &[("unfreeze", json!(unfreeze))]);
    unfreeze.verify(&alice, &freeze, UnfreezeAt::Next).unwrap();
    assert!(
        unfreeze.verify(&alice, &freeze, UnfreezeAt::Old).is_err(),
        "O needs the answer"
    );
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::UNFREEZE,
        &[&alice, &freeze.hash()],
        &unfreeze.sig
    ));
    let next_secret = SigningKey::from_bytes(&keys.secret(&next_key).unwrap());
    let answer = DiscardAnswer::sign(&next_secret, &alice, &freeze.hash());
    answer.verify(&alice, &freeze.hash(), &next_key).unwrap();
    assert!(reproduce(
        keys,
        &next_key,
        labels::sig::DISCARDED,
        &[&alice, &freeze.hash()],
        &answer.sig
    ));
    let old_key = keys.service_key(&pubky_dispatch_core::enc::pubky_id(&alice));
    assert!(
        answer.verify(&alice, &freeze.hash(), &old_key).is_err(),
        "only the key the freeze names"
    );
    let at_old = unfreeze.with_discarded(answer.clone());
    generated_members(
        "documents.json",
        "/discarded",
        &[
            ("answer", json!(answer)),
            ("next_service_key", json!(b64e(&next_key))),
            ("unfreeze_at_old_service", json!(at_old)),
        ],
    );
    at_old.verify(&alice, &freeze, UnfreezeAt::Old).unwrap();
    assert!(at_old.verify(&alice, &freeze, UnfreezeAt::Next).is_err());
}

/// Verify the two enrollment carriers before building their HTTP exchanges.
pub(super) fn enrollment_cases(keys: &Keys, docs: &HashMap<String, SignedDoc>) {
    let alice = keys.identity("alice");
    let current = IdentityDoc::verify(&docs["alice identity.json"], &alice).unwrap();
    let freeze = Freeze::verify(&docs["alice freeze"], &alice).unwrap();
    for (name, inbox) in [
        ("alice enrollment", current.inbox()),
        (
            "alice enrollment at the next service, naming a revoked app",
            freeze.next(),
        ),
    ] {
        Enrollment::verify(&docs[name], &alice, &inbox.url).unwrap();
    }
}

/// Bind the enrollment to its signed account observation at the selected service.
fn sign_enrollment(
    keys: &Keys,
    case: &Value,
    current: &IdentityDoc,
    next: &records::Inbox,
) -> Enrollment {
    let moved = st(case, "name") != "alice enrollment";
    let inbox = if moved { next } else { current.inbox() };
    let alice = current.identity();
    let at = parse_rfc3339(st(case, "observed_at")).unwrap();
    let observation = enrollment_observation(
        keys,
        &inbox.url,
        inbox.service_key,
        at,
        seed16(case, "store_id_seed_label"),
    );
    Enrollment::sign(
        &keys.identity_key(&alice),
        EnrollmentBody {
            identity: alice,
            origin: inbox.url.clone(),
            nonce: seed16(case, "nonce_seed_label"),
            intent: observation
                .verify(&alice, &inbox.url)
                .unwrap()
                .enrollment_intent()
                .unwrap(),
            policy: current.body().policy,
            identity_doc: moved.then(|| current.signed().clone()),
            revoked_apps: moved.then(|| current.body().removed.iter().map(|r| r.app_id).collect()),
        },
    )
    .unwrap()
}

/// Sign the absent-account observation over the exact account request.
fn enrollment_observation(
    keys: &Keys,
    origin: &str,
    service: [u8; 32],
    at: u64,
    store_id: [u8; 16],
) -> CarriedAccountObservation {
    use pubky_dispatch_core::{http, time};
    let identity = keys.identity("alice");
    let key = keys.identity_key(&identity);
    let binding = AccountBinding::select(None, AccountMarkInput::Missing).unwrap();
    let body = AccountObservationBody {
        identity,
        origin: origin.into(),
        service_key: service,
        store_id,
        association: binding.association(),
        created: binding.created(),
        erased_at: None,
        observed_at: at,
        expires_at: at + ACCOUNT_OBSERVATION_VALIDITY_MS,
    }
    .to_json()
    .unwrap();
    let path = format!("/v1/{}/account", key.id());
    let headers = http::RequestHeaders {
        identity: key.id(),
        timestamp: time::rfc3339_seconds(at),
        ..http::RequestHeaders::default()
    };
    let target = http::RequestTarget {
        method: "GET",
        origin,
        path_and_query: &path,
        body: &[],
    };
    let request_signature = http::sign_request(&key, &target, &headers);
    let signature = b64e(&request_signature);
    let received = http::ReceivedHeaders::of([
        (http::header::IDENTITY, headers.identity.as_bytes()),
        (http::header::TIMESTAMP, headers.timestamp.as_bytes()),
        (http::header::SIGNATURE, signature.as_bytes()),
    ]);
    let sig = http::sign_response(
        &SigningKey::from_bytes(&keys.secret(&service).unwrap()),
        &http::ResponseParts {
            status: 200,
            request: http::ReceivedRequest {
                method: "GET",
                origin,
                path_and_query: &path,
                body: http::BodyField::read(&[]),
                headers: &received,
            },
            server_time: &time::rfc3339(at),
            head: None,
            body: &body,
        },
    );
    CarriedAccountObservation {
        body,
        sig,
        request_timestamp: headers.timestamp,
        request_signature,
    }
}

/// The enrollments (Dispatch wire 3.7): for their origin only, and at the next service with
/// the current `identity.json` and the revoked App ID.
fn check_enrollments(keys: &Keys, docs: &HashMap<String, Doc>) {
    let alice = keys.identity("alice");
    let alice_key = keys.identity_key(&alice);
    let v3 = IdentityDoc::verify(&docs["alice identity.json"].signed, &alice).unwrap();
    let freeze = Freeze::verify(&docs["alice freeze"].signed, &alice).unwrap();
    for (name, origin) in [
        ("alice enrollment", v3.inbox().url.as_str()),
        (
            "alice enrollment at the next service, naming a revoked app",
            freeze.next().url.as_str(),
        ),
    ] {
        let signed = &docs[name].signed;
        let e =
            Enrollment::verify(signed, &alice, origin).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(Enrollment::verify(signed, &alice, "https://other.example").is_err());
        assert_eq!(
            Enrollment::sign(&alice_key, e.body().clone())
                .unwrap()
                .signed(),
            signed
        );
        assert_eq!(e.body().policy, v3.body().policy);
        if name == "alice enrollment" {
            assert!(e.identity_doc().is_none() && e.revoked_apps().is_empty());
        } else {
            assert_eq!(e.identity_doc(), Some(&v3));
            let removed = keys.removed_app;
            assert_eq!(e.revoked_apps(), [removed]);
        }
        // An answer for it, checked as the signer checks it.
        let answer = records::EnrollmentAnswer::new(
            &e,
            e.observation().unwrap().body().service_key,
            records::Limits::default(),
            e.observation().unwrap().body().observed_at,
        );
        answer.check(&e).unwrap();
    }
}

/// The wallet's app request (Dispatch wire 3.9) and the auth request it binds.
fn check_app_request(
    keys: &Keys,
    v: &Value,
    docs: &HashMap<String, Doc>,
    certs: &HashMap<String, AppCert>,
) {
    let alice = keys.identity("alice");
    let wallet = keys.app("wallet");
    let signed = &docs["wallet app request"].signed;
    let request = AppRequest::verify(signed).unwrap();
    assert_eq!(
        AppRequest::sign(&app_keys(wallet), request.body().clone())
            .unwrap()
            .signed(),
        signed
    );
    let body = request.body();
    assert_eq!(body.app_id, app_id_decode(&wallet.app_id).unwrap());
    assert_eq!(
        (body.signing_key, body.bundle_key),
        (wallet.signing_public, wallet.bundle_public)
    );
    assert_eq!(body.scopes, wallet.scopes);
    assert!(
        !body_value(signed)
            .as_object()
            .unwrap()
            .contains_key("identity"),
        "it names no identity"
    );

    let auth = auth_request(&v["auth_request"], wallet);
    assert!(request.binds(&auth));
    assert_eq!(body.secret_hash, auth.secret_hash());
    records::check_caps(&body.caps, &body.app_id, &[]).unwrap();

    let v3 = IdentityDoc::verify(&docs["alice identity.json"].signed, &alice).unwrap();
    let mut without = v3.body().clone();
    without.apps.retain(|a| a.app_id != body.app_id);
    let without = IdentityDoc::sign(&keys.identity_key(&alice), without).unwrap();
    let listed: Vec<AppCert> = [
        "wallet certificate",
        "phone certificate",
        "executor certificate",
    ]
    .iter()
    .map(|n| certs[*n].clone())
    .collect();
    let knows = |s: &str| wallet.scopes.iter().any(|w| w == s);
    let check = |identity: &IdentityDoc, auth: &AuthRequest, revoked: &[[u8; 16]]| {
        let view = SignerView {
            revoked,
            identity,
            listed: &listed,
            app_limit: 32,
            extra_paths: &[],
            knows_scope: &knows,
        };
        records::check_app_request(signed, auth, &view).map(|(_, approve)| approve)
    };
    // Listed with exactly these keys, approving renews; unlisted, it is a new app.
    assert_eq!(check(&v3, &auth, &[]).unwrap(), records::Approve::Renew);
    assert_eq!(check(&without, &auth, &[]).unwrap(), records::Approve::New);
    let mut other_secret = auth.clone();
    other_secret.secret[0] ^= 1;
    let error = check(&without, &other_secret, &[]).unwrap_err();
    assert!(error.to_string().contains("step 2"), "{error}");
    let error = check(&without, &auth, &[body.app_id]).unwrap_err();
    assert!(error.to_string().contains("step 4"), "{error}");
}

/// Alice's export transfer (Dispatch wire 3.11), for `export.json`'s manifest.
fn check_export_transfer(keys: &Keys, docs: &HashMap<String, Doc>) {
    let alice = keys.identity("alice");
    let signed = &docs["alice export transfer, for export.json's manifest"].signed;
    let transfer = ExportTransfer::verify(signed, &alice).unwrap();
    assert_eq!(
        ExportTransfer::sign(&keys.identity_key(&alice), transfer.body().clone())
            .unwrap()
            .signed(),
        signed
    );
    let freeze = Freeze::verify(&docs["alice freeze"].signed, &alice).unwrap();
    let v3 = IdentityDoc::verify(&docs["alice identity.json"].signed, &alice).unwrap();
    let manifest = signed_of(&load("export.json")["manifest"]["signed"])
        .doc_hash()
        .unwrap();
    let (origin, key) = (&v3.inbox().url, v3.inbox().service_key);
    transfer
        .check_names(&freeze, origin, &key, &manifest)
        .unwrap();
    assert!(
        transfer
            .check_names(&freeze, origin, &key, &[1; 32])
            .is_err()
    );
    assert!(
        transfer
            .check_names(&freeze, "https://o.example", &key, &manifest)
            .is_err()
    );
    assert!(
        transfer
            .check_names(&freeze, origin, &freeze.next().service_key, &manifest)
            .is_err()
    );
    assert!(ExportTransfer::verify(signed, &keys.identity("bob")).is_err());
    let secret = keys.identity_secrets[&alice];
    for f in [
        (|b: &mut Value| b["future"] = json!(1)) as fn(&mut Value),
        |b| b["from"]["future"] = json!(1),
        |b| b["kind"] = json!(pubky_dispatch_core::export::MANIFEST_KIND),
    ] {
        let mut b = body_value(signed);
        f(&mut b);
        let forged = resign(&secret, labels::sig::EXPORT_TRANSFER, &b);
        assert!(matches!(
            ExportTransfer::verify(&forged, &alice),
            Err(Error::Invalid(_))
        ));
    }
}

/// The rule a vector's `reason` names, as this crate words it.
fn rule_of(reason: &str) -> &'static str {
    if reason.contains("isn't a Dispatch permission") {
        "isn't a Dispatch permission"
    } else if reason.contains("not each once in the fixed order") {
        "not each once in the fixed order"
    } else if reason.contains("isn't a scope name or name:<sub>") {
        "isn't a name or name:<sub>"
    } else if reason.contains("covers every") {
        "beside one of its sub-scopes"
    } else if reason.contains("more than 32 scopes") {
        "more than 32 scopes"
    } else {
        panic!("no rule for {reason}")
    }
}

/// `app_record_conflict` (Dispatch wire 3.2, "Equal times"): two records of the wallet at one
/// `updated_at` with different bodies conflict for every reader, which keeps the earlier
/// record it holds until a strictly later one.
fn check_app_record_conflict(keys: &Keys, v: &Value, docs: &HashMap<String, Doc>) {
    let alice = keys.identity("alice");
    let c = &v["app_record_conflict"];
    assert_eq!(c["conflict"], true);
    let kept = AppRecord::verify(&docs[st(c, "kept")].signed, &alice).unwrap();
    let updated_at = parse_rfc3339(st(c, "updated_at")).unwrap();
    let wallet = keys.app("wallet");
    let records: Vec<AppRecord> = arr(c, "records")
        .iter()
        .map(|r| {
            let signed = signed_of(&r["signed"]);
            assert_eq!(signed.body_bytes().unwrap(), st(r, "body").as_bytes());
            let record = AppRecord::verify(&signed, &alice).unwrap();
            assert_eq!(record.cert().app_id(), kept.cert().app_id(), "the wallet's");
            assert_eq!(record.updated_at(), updated_at);
            assert!(reproduce(
                keys,
                &wallet.signing_public,
                labels::sig::APP_RECORD,
                &[&signed.body_bytes().unwrap()],
                &signed.sig_bytes().unwrap()
            ));
            let again = AppRecord::sign(&app_keys(wallet), record.body().clone()).unwrap();
            assert_eq!(again.signed(), &signed);
            record
        })
        .collect();
    let [a, b] = &records[..] else {
        panic!("two records");
    };
    assert!(kept.updated_at() < updated_at, "the kept record is earlier");
    assert_eq!(a.order(b), RecordOrder::Conflict);
    assert_eq!(a.order(a), RecordOrder::Same);
    assert_eq!(a.order(&kept), RecordOrder::Later);
    let now = updated_at + 60_000;
    for (x, y) in [(a, b), (b, a)] {
        let mut view = RecordView::new();
        assert!(!view.see(&kept, now));
        assert!(!view.see(x, now));
        assert_eq!(view.used(), Some(x));
        assert!(!view.see(x, now), "the same body again is one record");
        assert!(view.see(y, now), "a conflict");
        assert_eq!(view.used(), Some(&kept), "the earlier record it holds");
        let mut later_body = x.body().clone();
        later_body.updated_at = updated_at + 1;
        let later = AppRecord::sign(&app_keys(wallet), later_body).unwrap();
        let mut ahead_body = x.body().clone();
        ahead_body.updated_at = now + CLOCK_TOLERANCE_MS + 1;
        let ahead = AppRecord::sign(&app_keys(wallet), ahead_body).unwrap();
        assert!(
            view.see(&ahead, now),
            "too far ahead: no part in the comparison"
        );
        assert!(!view.see(&later, now));
        assert_eq!(view.used(), Some(&later));
    }
    let mut fresh = RecordView::new();
    fresh.see(a, now);
    assert!(fresh.see(b, now));
    assert_eq!(fresh.used(), None, "no earlier record to use");
}

/// `approval` (Dispatch wire 3.10): the wallet's approval, read by the app's checks, rebuilt
/// byte for byte where it is deterministic, refused at each step, and carried in its
/// companion claim, whose signed bytes come from `auth_request`.
fn check_approval(
    keys: &Keys,
    v: &Value,
    docs: &HashMap<String, Doc>,
    certs: &HashMap<String, AppCert>,
) {
    use pubky_dispatch_core::records::{
        Approval, ApprovalClaim, BundlePart, KeyBundle, KeyBundleContents,
    };
    use sha2::{Digest as _, Sha256};

    let keyed = keyed_scopes(&v["approval"]);
    let has_keys = |scope: &str| keyed.contains(scope);
    let alice = keys.identity("alice");
    let wallet = keys.app("wallet");
    let wallet_id = app_id_decode(&wallet.app_id).unwrap();
    let request = AppRequest::verify(&docs["wallet app request"].signed).unwrap();
    let auth = auth_request(&v["auth_request"], wallet);
    let ap = &v["approval"]["approval"];
    let json = serde_json::to_vec(ap).unwrap();
    let read =
        |json: &[u8], secret: &[u8; 32]| Approval::read(json, &request, &alice, secret, &has_keys);

    // The app's checks pass, and it keeps every key of the wallet's keyed scopes.
    let got = read(&json, &wallet.bundle_secret).unwrap();
    let cert = &certs["wallet certificate"];
    assert_eq!(got.cert, *cert);
    assert_eq!(
        st(ap, "request"),
        b64e(&request.hash()),
        "the request's hash"
    );
    assert_eq!(got.identity.signed(), &docs["alice identity.json"].signed);
    assert_eq!(got.naming_key, keys.naming(&alice));
    let keyed_scopes: Vec<&String> = cert.scopes().iter().filter(|s| has_keys(s)).collect();
    assert_eq!(
        got.keys.keys.len(),
        keyed_scopes.len() * got.identity.data_epoch() as usize,
        "every keyed scope, every epoch from 1"
    );
    let root = keys.root(&alice);
    for k in &got.keys.keys {
        assert_eq!(
            k.key,
            pubky_dispatch_core::ident::key_of_scope(&root, k.data_epoch, &k.scope)
        );
    }
    let text = serde_json::to_string(ap).unwrap();
    for k in &got.keys.keys {
        assert!(!text.contains(&b64e(&k.key)), "no key in the clear");
    }
    assert!(!text.contains(&b64e(&got.naming_key.to_bytes())));

    // Its one part, rebuilt from the identity key and the fixed randomness.
    let parts: Vec<BundlePart> = serde_json::from_value(ap["bundles"].clone()).unwrap();
    assert_eq!(parts.len(), 1);
    let part = &parts[0];
    assert_eq!(part.range(), (1, got.identity.data_epoch()));
    let key = keys.identity_key(&alice);
    let contents =
        KeyBundleContents::derive(&key, cert, 1, got.identity.data_epoch(), &has_keys).unwrap();
    let plaintext = contents.to_json().unwrap();
    let opened = pubky_dispatch_core::envelope::open_framed(
        part.bundle.envelope(),
        &alice,
        &wallet.bundle_secret,
    )
    .unwrap();
    assert!(*opened == *plaintext, "the part's plaintext derived again");
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::KEY_BUNDLE,
        &[&alice, &wallet_id, part.bundle.envelope()],
        &part.bundle.sig()
    ));
    // The approval rebuilt from its parts: the same JSON value.
    let v3 = IdentityDoc::verify(&docs["alice identity.json"].signed, &alice).unwrap();
    let approval = Approval::new(&request, cert.clone(), v3.clone(), parts.clone()).unwrap();
    let written: Value = serde_json::from_slice(&approval.to_json().unwrap()).unwrap();
    assert_eq!(&written, ap, "the approval rebuilt");

    // The companion claim: the identity key signs the claim prefix, the SHA-256 of the auth
    // request's secret, and the approval's JSON bytes.
    let claim = ApprovalClaim::sign(&key, &auth, &approval).unwrap();
    let signed = records::claim_signed_bytes(&auth.secret, claim.json());
    let prefix = format!(
        "{}|{}|",
        records::CLAIM_PARAMETER,
        records::APPROVAL_CLAIM_TYPE
    );
    let digest: [u8; 32] = Sha256::digest(auth.secret).into();
    let mut expected = prefix.into_bytes();
    expected.extend_from_slice(&digest);
    expected.extend_from_slice(&approval.to_json().unwrap());
    assert_eq!(signed, expected);
    // The auth secret's hash in the request is BLAKE3; the claim's is SHA-256.
    assert_ne!(digest, request.body().secret_hash);
    let plaintext = claim.plaintext();
    let received = ApprovalClaim::from_plaintext(&plaintext).unwrap();
    let approval_json = received.verify(&alice, &auth).unwrap();
    assert_eq!(read(approval_json, &wallet.bundle_secret).unwrap(), got);
    let signer = SigningKey::from_bytes(&keys.identity_secrets[&alice]);
    assert_eq!(
        ed25519_dalek::Signer::sign(&signer, &expected).to_bytes(),
        received.sig(),
        "deterministic, over exactly those bytes"
    );
    let mut other = auth.clone();
    other.secret[0] ^= 1;
    assert!(
        received.verify(&alice, &other).is_err(),
        "another auth secret"
    );
    assert!(received.verify(&keys.identity("bob"), &auth).is_err());

    // One refusal per step.
    let step = |value: &Value, secret: &[u8; 32]| {
        let error = read(&serde_json::to_vec(value).unwrap(), secret).unwrap_err();
        let text = error.to_string();
        (1..=4)
            .find(|n| text.contains(&format!("Dispatch wire 3.10 step {n}")))
            .unwrap_or_else(|| panic!("no step in {text}"))
    };
    let changed = |change: &dyn Fn(&mut Value)| {
        let mut value = ap.clone();
        change(&mut value);
        step(&value, &wallet.bundle_secret)
    };
    assert_eq!(changed(&|a| a["request"] = json!(b64e(&[1; 32]))), 1);
    assert_eq!(changed(&|a| a["kind"] = json!(records::CERT_KIND)), 1);
    assert_eq!(changed(&|a| a["v"] = json!(2)), 1);
    let phone_cert = serde_json::to_value(&docs["phone certificate"].signed).unwrap();
    assert_eq!(changed(&|a| a["cert"] = phone_cert.clone()), 2);
    let bob_cert = serde_json::to_value(&docs["shop certificate"].signed).unwrap();
    assert_eq!(changed(&|a| a["cert"] = bob_cert.clone()), 2);
    let renewing =
        serde_json::to_value(&docs["alice identity.json, wallet renewal in progress"].signed)
            .unwrap();
    assert_eq!(changed(&|a| a["identity"] = renewing.clone()), 3);
    assert_eq!(changed(&|a| a["bundles"] = json!([])), 4);
    assert_eq!(changed(&|a| a["bundles"][0]["first_epoch"] = json!(2)), 4);
    let mut extra = ap["bundles"][0].clone();
    extra["first_epoch"] = json!(3);
    extra["last_epoch"] = json!(3);
    extra["bundle"]["sig"] = json!(b64e(&[0; 64]));
    assert_eq!(
        changed(&|a| a["bundles"].as_array_mut().unwrap().push(extra.clone())),
        4,
        "every part must be taken"
    );
    assert_eq!(
        step(ap, &keys.app("phone").bundle_secret),
        4,
        "another bundle key"
    );
    // A part made for another certificate, the renewed one, isn't the approval's.
    let renewed = &certs["wallet certificate, renewed"];
    let for_renewed = KeyBundleContents::derive(&key, renewed, 1, 2, &has_keys).unwrap();
    let stale = BundlePart {
        bundle: KeyBundle::seal(&key, renewed, &for_renewed).unwrap(),
        first_epoch: 1,
        last_epoch: 2,
    };
    let stale = serde_json::to_value(vec![stale]).unwrap();
    assert_eq!(changed(&|a| a["bundles"] = stale.clone()), 4);
    // Unknown members are ignored.
    let mut future = ap.clone();
    future["future"] = json!({"x": 1});
    read(&serde_json::to_vec(&future).unwrap(), &wallet.bundle_secret).unwrap();

    let file = load("documents.json");
    for case in arr(&file["approval"], "rejections") {
        let name = st(case, "name");
        let approval = serde_json::to_vec(&case["approval"]).unwrap();
        assert_eq!(
            step(&case["approval"], &wallet.bundle_secret),
            int(case, "step") as usize,
            "{name}"
        );
        let error = read(&approval, &wallet.bundle_secret).unwrap_err();
        assert!(
            error.to_string().contains("past data_epoch"),
            "{name}: {error}"
        );
        // Its parts verify, open and carry their keys: only the epoch refuses them.
        let parts: Vec<BundlePart> =
            serde_json::from_value(case["approval"]["bundles"].clone()).unwrap();
        for part in &parts {
            part.bundle.verify(&alice, &wallet_id).unwrap();
            pubky_dispatch_core::envelope::open_framed(
                part.bundle.envelope(),
                &alice,
                &wallet.bundle_secret,
            )
            .unwrap();
        }
    }
}

/// Break one connect request rule in the current identity and check the pinned error.
fn check_identity_rejections(keys: &Keys, file: &Value, base: &SignedDoc) {
    let alice = keys.identity("alice");
    for (i, c) in arr(&file["identity_rejections"], "cases")
        .iter()
        .enumerate()
    {
        let mut connect = body_value(base)["policy"]["connect_requests"].clone();
        match st(c, "name") {
            "connect_requests without its members" => connect = json!({}),
            "connect_requests with push null" => connect["push"] = Value::Null,
            other => panic!("unknown identity rejection {other}"),
        }
        let text = String::from_utf8(base.body_bytes().unwrap()).unwrap();
        let before = format!(
            "\"connect_requests\":{}",
            body_value(base)["policy"]["connect_requests"]
        );
        assert_eq!(text.matches(&before).count(), 1);
        let text = text.replace(&before, &format!("\"connect_requests\":{connect}"));
        let signed =
            keys.identity_key(&alice)
                .sign_doc(labels::sig::IDENTITY, &[], text.into_bytes());
        signed.verify(&alice, labels::sig::IDENTITY, &[]).unwrap();
        let Error::Invalid(error) = IdentityDoc::verify(&signed, &alice).unwrap_err() else {
            panic!("identity form")
        };
        let why = error.trim_end_matches(" at line 0 column 0");
        assert_eq!(
            why.strip_prefix("json: ").unwrap_or(why),
            st(c, "error"),
            "{}",
            st(c, "rule")
        );
        emit_variant(&format!("/identity_rejections/cases/{i}"), &signed);
    }
}

/// `app_record_protocols` (Dispatch wire 3.2, "Protocols' members"): the wallet's record with a
/// member added, signed again. Every reader refuses the `refused` ones by the form check
/// alone, and takes the `accepted` ones, ignoring a protocol it doesn't know.
fn check_app_record_protocols(keys: &Keys, v: &Value) {
    let cases = &v["app_record_protocols"];
    let wallet = keys.app("wallet");
    let accepted = arr(cases, "accepted");
    assert_eq!(accepted.len(), 2);
    for c in accepted {
        let signed: SignedDoc = serde_json::from_value(c["signed"].clone()).unwrap();
        assert_eq!(
            signed.body_bytes().unwrap(),
            st(c, "body").as_bytes(),
            "{}",
            st(c, "name")
        );
        let record = AppRecord::verify(&signed, &wallet.identity)
            .unwrap_or_else(|e| panic!("{}: {e}", st(c, "name")));
        let written = body_value(&signed);
        assert_eq!(written["protocols"], c["protocols"]);
        for (protocol, member) in c["protocols"].as_object().unwrap() {
            // A null member is no member; any other is read as written.
            let read = record
                .body()
                .protocol(protocol)
                .map(|m| Value::Object(m.clone()));
            if member.is_null() {
                assert!(read.is_none(), "{}: a null member", st(c, "name"));
            } else {
                assert_eq!(read.as_ref(), Some(member), "{}", st(c, "name"));
            }
        }
    }
    let refused = arr(cases, "refused");
    assert!(!refused.is_empty());
    for c in refused {
        let signed: SignedDoc = serde_json::from_value(c["signed"].clone()).unwrap();
        assert_eq!(body_value(&signed)["protocols"], c["protocols"]);
        // The signature holds; only the form check refuses it.
        assert!(
            signed
                .verify(&wallet.signing_public, labels::sig::APP_RECORD, &[])
                .is_ok()
        );
        let error = AppRecord::verify(&signed, &wallet.identity)
            .expect_err(&format!("{}: accepted", st(c, "name")));
        assert!(
            matches!(error, pubky_dispatch_core::Error::Invalid(_)),
            "{}: {error}",
            st(c, "name")
        );
    }
}
