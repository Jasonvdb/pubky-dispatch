//! The old signer's cases of the Dispatch vector set (`spec/vectors/`): the hand-over to the
//! phone (`envelopes.json` `signer_handover`), the abort and the version after it, and the
//! wallet's renewal (`documents.json`, `envelopes.json` `reduction_key_bundle`), and the
//! account's erasure (`http.json`).
//!
//! Those vectors are alice's signer at her version 3, under the signer ID her documents name.
//! A signer draws its own ID at random, so this module, alone, writes that signer's records
//! into the store, taken from the records the vector's hand-over seals; every step after that
//! goes through the public API. The new signer's and the restore's cases, which need no such
//! set-up, are in `tests/vectors.rs`.

// Test code reading fixed vector files: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pubky_dispatch_client::clock::TestClock;
use pubky_dispatch_client::store::{MemoryStore, StoreHandle};
use pubky_dispatch_client::testing::{Fault, ScriptedDispatch};
use pubky_dispatch_client::transport::{BoxFuture, Header, MockTransport, Response};
use pubky_dispatch_client::{Credentials, DispatchClient, TransportError};
use pubky_dispatch_core::enc::{app_id_decode, unb64, unb64_array};
use pubky_dispatch_core::http::{
    self, BodyField, ReceivedHeaders, ReceivedRequest, RequestHeaders, RequestTarget, ResponseParts,
};
use pubky_dispatch_core::keys::{AppKeys, IdentityKey};
use pubky_dispatch_core::ops::OpKind;
use pubky_dispatch_core::records::{
    ACCOUNT_OBSERVATION_VALIDITY_MS, AccountAssociation, AccountObservationBody, AppCert,
    CarriedAccountObservation, Enrollment, EnrollmentBody, EnrollmentIntent, IDENTITY_PATH,
    IdentityBody, IdentityDoc, Inbox, Limits, MAX_ACCOUNT_OBSERVATION_BYTES,
    MAX_CARRIED_ACCOUNT_OBSERVATION_BYTES, MAX_ENROLLMENT_INTENT_BYTES, RenewedCert,
    SIGNER_BACKUP_PATH, SignerBackup, SignerHandover, SignerRecords, StoredPart,
};
use pubky_dispatch_core::scopes::Permission;
use pubky_dispatch_core::sig::SignedDoc;
use serde_json::Value;

use super::{AbortOutcome, CertChange, Signer, SignerEnv, UserConfirmed};
use crate::alert::Alert;
use crate::error::{Refusal, SignerError, SizedBody};
use crate::homeserver::Homeserver;
use crate::key::{AddOutcome, IdentityKeyring, IdentitySecret, SecretVault, VaultError};
use crate::protocol::{Protocol, Protocols, ScopeDef};
use crate::state::{self, Newest, Service, SignerState};

/// The vectors' start time, `2026-01-01T00:00:00.000Z` (vectors README, "Times").
const VECTOR_START_MS: u64 = 1_767_225_600_000;

fn load(name: &str) -> Value {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn text<'a>(value: &'a Value, member: &str) -> &'a str {
    value[member]
        .as_str()
        .unwrap_or_else(|| panic!("{member} isn't a string"))
}

/// The account's creation time `http.json`'s enrollment answer names (Dispatch wire 3.7).
fn vector_created() -> u64 {
    let http = load("http.json");
    let answer = http["responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| text(r, "name").starts_with("signer: enrollment answer"))
        .unwrap();
    let body: Value = serde_json::from_str(text(answer, "body")).unwrap();
    pubky_dispatch_core::time::parse_rfc3339(text(&body, "created")).unwrap()
}

fn hex32(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}

fn named<'a>(list: &'a Value, name: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("no {name}"))
}

fn document(name: &str) -> SignedDoc {
    serde_json::from_value(named(&load("documents.json")["documents"], name)["signed"].clone())
        .unwrap()
}

/// The vectors' protocol, read from the spec's files so the tests name none: its name and
/// roots as the files give them (`vector_protocol`); keyed are the scopes the vectors give keys for (scope
/// keys, sub-scope keys, the key bundles' keys and the reduction's removed scope); and the
/// Dispatch permissions of a set of scopes are those of the vector certificate with exactly those
/// scopes.
struct VectorScopes {
    name: String,
    roots: Vec<String>,
    keyed: Vec<String>,
    permissions: Vec<(Vec<String>, Vec<Permission>)>,
}

impl VectorScopes {
    fn new() -> Self {
        let (name, roots) = super::vector_protocol::vector_protocol(&load("documents.json"));
        let keys = load("keys.json");
        let envelopes = load("envelopes.json");
        let mut keyed: Vec<String> = keys["scope_keys"]
            .as_array()
            .unwrap()
            .iter()
            .chain(keys["sub_scope_keys"]["keys"].as_array().unwrap())
            .map(|k| text(k, "scope").to_owned())
            .collect();
        for member in ["key_bundle", "reduction_key_bundle"] {
            let plaintext: Value =
                serde_json::from_str(text(&envelopes[member], "plaintext_json")).unwrap();
            for key in plaintext["keys"].as_array().unwrap() {
                keyed.push(text(key, "scope").to_owned());
            }
        }
        keyed.push(text(&envelopes["reduction_key_bundle"], "removed_scope").to_owned());
        let permissions = load("documents.json")["documents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| text(d, "name").contains("certificate"))
            .map(|d| {
                let body: Value = serde_json::from_str(text(d, "body")).unwrap();
                (
                    serde_json::from_value(body["scopes"].clone()).unwrap(),
                    body["permissions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|p| Permission::from_name(p.as_str().unwrap()).unwrap())
                        .collect(),
                )
            })
            .collect();
        Self {
            name,
            roots,
            keyed,
            permissions,
        }
    }
}

impl Protocol for VectorScopes {
    fn name(&self) -> &str {
        &self.name
    }
    fn scopes(&self) -> Vec<ScopeDef> {
        self.roots
            .iter()
            .map(|root| {
                if self.keyed.contains(root) {
                    ScopeDef::keyed(root)
                } else {
                    ScopeDef::unkeyed(root)
                }
            })
            .collect()
    }
    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }
    fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
        self.permissions
            .iter()
            .find(|(of, _)| of.iter().map(String::as_str).eq(scopes.iter().copied()))
            .map(|(_, permissions)| permissions.clone())
            .unwrap_or_default()
    }
}

struct Vault(Mutex<Option<[u8; 32]>>);

impl SecretVault for Vault {
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
        Ok(self.0.lock().unwrap().map(IdentitySecret::from_bytes))
    }
    fn add(&self, secret: &IdentitySecret) -> Result<AddOutcome, VaultError> {
        let mut held = self.0.lock().unwrap();
        if held.is_some() {
            return Ok(AddOutcome::Occupied);
        }
        *held = Some(*secret.as_bytes());
        Ok(AddOutcome::Stored)
    }
    fn delete(&self, expected: &IdentitySecret) -> Result<(), VaultError> {
        let mut held = self.0.lock().unwrap();
        if held.as_ref() == Some(expected.as_bytes()) {
            *held = None;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Files(Mutex<HashMap<String, Vec<u8>>>);

impl Homeserver for Files {
    fn get(&self, path: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        let found = self.0.lock().unwrap().get(path).cloned();
        Box::pin(async move { Ok(found) })
    }
    fn put(&self, path: &str, bytes: Vec<u8>) -> BoxFuture<'_, Result<(), TransportError>> {
        self.0.lock().unwrap().insert(path.to_owned(), bytes);
        Box::pin(async { Ok(()) })
    }
    fn delete(&self, path: &str) -> BoxFuture<'_, Result<(), TransportError>> {
        self.0.lock().unwrap().remove(path);
        Box::pin(async { Ok(()) })
    }
}

/// alice's fixed signer at version 3, built on version 1, with its Dispatch holding both
/// versions and its Homeserver publishing version 3 beside the matching backup.
struct OldSigner {
    key: IdentityKey,
    signer: Signer,
    dispatch: Arc<ScriptedDispatch>,
    transport: Arc<MockTransport>,
    homeserver: Arc<Files>,
    clock: Arc<TestClock>,
    phone: [u8; 16],
    /// The hand-over plaintext of the records held at version 3.
    plaintext: Vec<u8>,
}

async fn old_signer() -> OldSigner {
    old_signer_answering(None).await
}

/// [`old_signer`], whose Dispatch gives `erasure` as its answer to `POST /erase`, when given.
async fn old_signer_answering(erasure: Option<Response>) -> OldSigner {
    let keys = load("keys.json");
    let identity = named(&keys["identities"], "alice");
    let key = IdentityKey::from_secret(hex32(text(identity, "secret_hex")));
    let alice = key.public();
    let service = keys["service_keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["account"] == text(identity, "pubky_id"))
        .unwrap()
        .clone();
    let v1 = IdentityDoc::verify(
        &document("alice identity.json, first delivery (version 1)"),
        &alice,
    )
    .unwrap();
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &alice).unwrap();
    let envelopes = load("envelopes.json");
    let handover = &envelopes["signer_handover"];
    let plaintext = text(handover, "plaintext_json").as_bytes().to_vec();
    let records: Value = serde_json::from_slice(&plaintext).unwrap();
    let limits = serde_json::from_value::<Limits>(records["limits"].clone()).unwrap();
    let created = vector_created();
    assert!(created <= VECTOR_START_MS);
    // Create the actual account at the vector's original time (Dispatch wire 3.7).
    let clock = Arc::new(TestClock::new(created));
    let dispatch = ScriptedDispatch::unenrolled_at(
        &key,
        hex32(text(&service, "secret_hex")),
        clock.clone(),
        &v3.inbox().url,
    );
    dispatch.set_enroll_limits(limits);
    let client = DispatchClient::new(
        &v3.inbox().url,
        alice,
        Credentials::Signer {
            identity: alice,
            key: Arc::new(key.clone()),
        },
        None,
        dispatch.transport(),
        clock.clone(),
    )
    .unwrap();
    let observation = Box::pin(client.observe_account()).await.unwrap();
    assert_eq!(observation.body().association, AccountAssociation::Absent);
    let enrollment = Enrollment::sign(
        &key,
        EnrollmentBody {
            identity: alice,
            origin: v3.inbox().url.clone(),
            nonce: [7; 16],
            intent: EnrollmentIntent::Create {
                observation: observation.carried().clone(),
            },
            policy: v3.body().policy,
            identity_doc: None,
            revoked_apps: None,
        },
    )
    .unwrap();
    let answer = Box::pin(client.enroll(&enrollment)).await.unwrap();
    assert_eq!(answer.origin, v3.inbox().url);
    assert_eq!(answer.service_key, v3.inbox().service_key);
    assert_eq!(answer.created, created);
    assert_eq!(answer.limits, limits);
    let service = Service {
        origin: answer.origin,
        service_key: answer.service_key,
        limits: answer.limits,
        created: answer.created,
    };
    service.check_document(&v1).unwrap();
    service.check_document(&v3).unwrap();
    clock.set_ms(VECTOR_START_MS);
    dispatch.deliver_identity(&v1).unwrap();
    dispatch.deliver_identity(&v3).unwrap();
    // The phone and the wallet registered with their records: the hand-over's target, and
    // the app renewed, must have.
    for app in ["phone", "wallet"] {
        dispatch
            .app_op(
                &app_keys(&keys, app),
                OpKind::AppPut {
                    record: document(&format!("{app} app record")),
                },
            )
            .unwrap();
    }
    let homeserver = Arc::new(Files::default());
    homeserver
        .put(IDENTITY_PATH, serde_json::to_vec(v3.signed()).unwrap())
        .await
        .unwrap();
    homeserver
        .put(
            SIGNER_BACKUP_PATH,
            serde_json::to_vec(&envelopes["signer_backup"]["backup"]).unwrap(),
        )
        .await
        .unwrap();

    // The records of the signer that signed version 3, as its sealed records list them.
    let mut state = SignerState::new(alice, v3.body().signer);
    state.service = Some(service.clone());
    state.newest = Some(Newest {
        doc: v3.signed().clone(),
        account: Some(service),
        prev: Some(v1.hash()),
        published: true,
        delivered_at: Some(VECTOR_START_MS),
    });
    state.signed_through = v3.version();
    state.tombstones = records["revoked_apps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| app_id_decode(id.as_str().unwrap()).unwrap())
        .collect();
    state.certs = serde_json::from_value(records["certs"].clone()).unwrap();
    state.bundle_parts =
        serde_json::from_value::<Vec<StoredPart>>(records["bundle_parts"].clone()).unwrap();
    state.listed_at = v3.body().apps.iter().map(|a| (a.app_id, 0)).collect();
    state.epoch_through = v3.data_epoch();

    let store = Arc::new(MemoryStore::new());
    let transport = match erasure {
        None => dispatch.transport(),
        Some(answer) => {
            let scripted = Arc::clone(&dispatch);
            Arc::new(MockTransport::with_handler(move |request| {
                if request.method == "POST" && request.path_and_query.ends_with("/erase") {
                    Ok(answer.clone())
                } else {
                    scripted.handle(request)
                }
            }))
        }
    };
    let env = SignerEnv {
        store: StoreHandle::inline(store),
        clock: clock.clone(),
        transport: transport.clone(),
        homeserver: homeserver.clone(),
        protocols: Protocols::new(vec![Arc::new(VectorScopes::new())]).unwrap(),
    };
    let mut owned = env
        .store
        .acquire(&state::signer_namespace(&state.identity))
        .await
        .unwrap();
    state::save(&mut owned, &state, None).await.unwrap();
    drop(owned);
    let vault = Arc::new(Vault(Mutex::new(Some(key.secret_bytes()))));
    let mut signer = Signer::open(env, IdentityKeyring::open(vault).unwrap())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert!(signer.alerts().is_empty(), "{:?}", signer.alerts());
    let phone = app_id_decode(text(handover, "app_id")).unwrap();
    OldSigner {
        key,
        signer,
        dispatch,
        transport,
        homeserver,
        clock: Arc::clone(&clock),
        phone,
        plaintext,
    }
}

/// The same fixed install at a genuinely enrolled account for the size cases
/// (Dispatch account binding 2-3, wire 3.12-3.13).
async fn old_signer_at(origin: &str) -> OldSigner {
    assert!(pubky_dispatch_core::records::is_origin(origin));
    let original = Box::pin(old_signer()).await;
    let key = original.key.clone();
    let keys = load("keys.json");
    let service = keys["service_keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["account"] == key.id())
        .unwrap();
    let clock = Arc::new(TestClock::new(VECTOR_START_MS));
    let dispatch = ScriptedDispatch::unenrolled_at(
        &key,
        hex32(text(service, "secret_hex")),
        clock.clone(),
        origin,
    );
    let transport = dispatch.transport();
    let client = DispatchClient::new(
        origin,
        key.public(),
        Credentials::Signer {
            identity: key.public(),
            key: Arc::new(key.clone()),
        },
        None,
        transport.clone(),
        clock.clone(),
    )
    .unwrap();
    let observation = client.observe_account().await.unwrap();
    assert_eq!(observation.body().association, AccountAssociation::Absent);
    let original_v3 = original.signer.identity_doc().unwrap().unwrap();
    let enrollment = Enrollment::sign(
        &key,
        EnrollmentBody {
            identity: key.public(),
            origin: origin.into(),
            nonce: [7; 16],
            intent: EnrollmentIntent::Create {
                observation: observation.carried().clone(),
            },
            policy: original_v3.body().policy,
            identity_doc: None,
            revoked_apps: None,
        },
    )
    .unwrap();
    let answer = client.enroll(&enrollment).await.unwrap();
    let account = Service {
        origin: origin.into(),
        service_key: answer.service_key,
        created: answer.created,
        limits: answer.limits,
    };
    let resign = |mut body: IdentityBody| {
        body.inbox = Inbox::new(origin, account.service_key);
        let doc = IdentityDoc::sign(&key, body).unwrap();
        account.check_document(&doc).unwrap();
        doc
    };
    let v1 = resign(
        IdentityDoc::verify(
            &document("alice identity.json, first delivery (version 1)"),
            &key.public(),
        )
        .unwrap()
        .body()
        .clone(),
    );
    let v3 = resign(original_v3.body().clone());
    dispatch.deliver_identity(&v1).unwrap();
    dispatch.deliver_identity(&v3).unwrap();
    for app in ["phone", "wallet"] {
        dispatch
            .app_op(
                &app_keys(&keys, app),
                OpKind::AppPut {
                    record: document(&format!("{app} app record")),
                },
            )
            .unwrap();
    }
    let mut state = original.signer.state.clone();
    let issued = original.signer.held_certs().unwrap();
    let records = |prev| {
        SignerRecords::new(
            key.clone(),
            v3.clone(),
            answer.created,
            &state.tombstones,
            &issued,
            answer.limits,
            &state.bundle_parts,
            prev,
        )
        .unwrap()
    };
    let plaintext = records(None).to_json().unwrap().to_vec();
    let backup = SignerBackup::seal(&key, &records(Some(v1.hash()))).unwrap();
    let homeserver = Arc::new(Files::default());
    homeserver
        .put(IDENTITY_PATH, serde_json::to_vec(v3.signed()).unwrap())
        .await
        .unwrap();
    homeserver
        .put(SIGNER_BACKUP_PATH, serde_json::to_vec(&backup).unwrap())
        .await
        .unwrap();
    state.service = Some(account.clone());
    state.newest = Some(Newest {
        doc: v3.signed().clone(),
        account: Some(account),
        prev: Some(v1.hash()),
        published: true,
        delivered_at: Some(VECTOR_START_MS),
    });
    let env = SignerEnv {
        store: StoreHandle::inline(Arc::new(MemoryStore::new())),
        clock: clock.clone(),
        transport: transport.clone(),
        homeserver: homeserver.clone(),
        protocols: Protocols::new(vec![Arc::new(VectorScopes::new())]).unwrap(),
    };
    let mut owned = env
        .store
        .acquire(&state::signer_namespace(&state.identity))
        .await
        .unwrap();
    state::save(&mut owned, &state, None).await.unwrap();
    drop(owned);
    let vault = Arc::new(Vault(Mutex::new(Some(key.secret_bytes()))));
    let mut signer = Signer::open(env, IdentityKeyring::open(vault).unwrap())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert!(signer.alerts().is_empty(), "{:?}", signer.alerts());
    OldSigner {
        key,
        signer,
        dispatch,
        transport,
        homeserver,
        clock,
        phone: original.phone,
        plaintext,
    }
}

/// The signing and bundle keys of `keys.json`'s app `name`.
fn app_keys(keys: &Value, name: &str) -> AppKeys {
    let app = named(&keys["apps"], name);
    AppKeys::from_secrets(
        hex32(text(app, "signing_secret_hex")),
        hex32(text(app, "bundle_secret_hex")),
    )
}

/// `signer_handover`'s records with `doc` in place of version 3, and `prev`, as a backup's
/// plaintext in JSON bytes: its own `kind` and no `identity_secret` (Dispatch wire 3.13).
fn records_with(plaintext: &[u8], doc: &SignedDoc, prev: [u8; 32]) -> Vec<u8> {
    let handover: Value = serde_json::from_slice(plaintext).unwrap();
    let v3: SignedDoc = serde_json::from_value(handover["identity_doc"].clone()).unwrap();
    let secret = format!(
        ",\"identity_secret\":\"{}\"",
        text(&handover, "identity_secret")
    );
    let mut records = std::str::from_utf8(plaintext)
        .unwrap()
        .replace(
            "\"kind\":\"pubky-dispatch.signer_handover\"",
            "\"kind\":\"pubky-dispatch.signer_backup\"",
        )
        .replace(&secret, "")
        .replace(&v3.body, &doc.body)
        .replace(&v3.sig, &doc.sig);
    assert_eq!(records.pop(), Some('}'));
    records.push_str(&format!(
        ",\"prev\":\"{}\"}}",
        pubky_dispatch_core::enc::b64(&prev)
    ));
    records.into_bytes()
}

/// `envelopes.json` `signer_handover` (Dispatch wire 3.12): the hand-over alice's signer stores
/// for her phone holds exactly the vector's records, and opens only with the phone's bundle
/// secret; its `PUT /handover` body has `http.json`'s members.
#[tokio::test]
async fn test_vectors_old_signer_hands_over_the_vectors_records() {
    let mut old = old_signer().await;
    old.signer
        .hand_over_to(old.phone, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let (target, body) = old.dispatch.stored_handover_body().unwrap();
    assert_eq!(target, old.phone);
    let http = load("http.json");
    let request = named(
        &http["requests"],
        "signer: store the hand-over to the phone at the dispatch",
    );
    let vector: Value = serde_json::from_slice(&unb64(text(request, "body_b64")).unwrap()).unwrap();
    let members = |v: &Value| -> Vec<String> { v.as_object().unwrap().keys().cloned().collect() };
    assert_eq!(members(&body), members(&vector));
    assert_eq!(body["app_id"], vector["app_id"]);
    let handover: SignerHandover = serde_json::from_value(body["handover"].clone()).unwrap();
    let keys = load("keys.json");
    let phone = named(&keys["apps"], "phone");
    let records = handover
        .open(
            &old.key.public(),
            &old.phone,
            &hex32(text(phone, "bundle_secret_hex")),
        )
        .unwrap();
    assert!(
        *records.to_json().unwrap() == *old.plaintext,
        "the records the vector hands over"
    );
    let wallet = named(&keys["apps"], "wallet");
    assert!(
        handover
            .open(
                &old.key.public(),
                &app_id_decode(text(wallet, "app_id")).unwrap(),
                &hex32(text(wallet, "bundle_secret_hex")),
            )
            .is_err()
    );
}

/// `documents.json`'s hand-over abort (Dispatch wire 3.12): the abort alice's signer delivers is
/// the vector's version 5, byte for byte, built on version 3; once it has won, the backup
/// holds it, and alice's signer signs again: its next change is `documents.json`'s version 6
/// with a 30-day record age limit, byte for byte.
#[tokio::test]
async fn test_vectors_old_signer_abort_is_the_vectors_version_5() {
    let mut old = old_signer().await;
    old.signer
        .hand_over_to(old.phone, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let outcome = old
        .signer
        .abort_hand_over(UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let AbortOutcome::Aborted { .. } = outcome else {
        panic!("the abort wins: {outcome:?}");
    };
    let abort = document("alice identity.json, hand-over abort (version 5)");
    let held = old.dispatch.identity_doc().unwrap();
    assert_eq!(held.signed(), &abort, "the vector's abort");
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let delivery = old
        .transport
        .requests()
        .into_iter()
        .rfind(|r| r.method == "PUT" && r.path_and_query.ends_with("/identity"))
        .unwrap();
    let body: Value = serde_json::from_slice(&delivery.body).unwrap();
    assert_eq!(
        unb64_array::<32>(body["prev"].as_str().unwrap()).unwrap(),
        v3.hash(),
        "built on version 3"
    );
    assert_eq!(old.signer.identity_doc().unwrap().unwrap().signed(), &abort);
    let backup: SignerBackup =
        serde_json::from_slice(&old.homeserver.0.lock().unwrap()[SIGNER_BACKUP_PATH]).unwrap();
    assert_eq!(
        *backup.open(&old.key).unwrap().to_backup_json().unwrap(),
        *records_with(&old.plaintext, &abort, v3.hash()),
        "the vector's records, with the abort built on version 3"
    );
    let six = old
        .signer
        .set_record_max_age(Some(2_592_000))
        .await
        .unwrap();
    assert_eq!(
        six.signed(),
        &document("alice identity.json, record age limit (version 6)")
    );
}

#[test]
fn test_verified_cutoff_requires_the_original_document_and_its_generation() {
    let doc =
        IdentityDoc::verify_named(&document("alice identity.json, wallet renewal in progress"))
            .unwrap();
    let mut read = super::DispatchRead {
        answer: super::AppsAnswer {
            apps: Vec::new(),
            recovery: None,
            proof_generations: Vec::new(),
            identity: Some(doc.signed().clone()),
            server_time: VECTOR_START_MS,
        },
        device_ms: VECTOR_START_MS + 60_000,
        head_generation: Some(doc.generation()),
    };
    assert_eq!(read.cutoff_for(&doc), Some(VECTOR_START_MS));
    read.head_generation = Some(doc.generation() + 1);
    assert_eq!(read.cutoff_for(&doc), None);
    read.head_generation = Some(doc.generation());
    read.answer.identity = Some(document("alice identity.json, wallet renewal closed"));
    assert_eq!(read.cutoff_for(&doc), None);
}

/// `documents.json`'s wallet renewal (Dispatch spec 3.2; Dispatch wire 3.8 Reductions): alice's
/// signer renews the wallet without `tasks_people_admin`, a scope with keys, and expiring earlier,
/// at 00:02. The Dispatch takes the renewing version at 00:03. The renewed certificate, the
/// renewing version 4 at data epoch 3, and the closing version 5 with `until` 00:08 are the
/// vectors' byte for byte, and the full bundle stored for the wallet holds the keys of
/// `reduction_key_bundle`.
#[tokio::test]
async fn test_vectors_old_signer_renews_the_wallet_as_the_vectors_do() {
    let mut old = old_signer().await;
    let keys = load("keys.json");
    let wallet = app_keys(&keys, "wallet");
    let wallet_id = wallet.app_id_bytes();
    let renewed =
        AppCert::verify(&document("wallet certificate, renewed"), &old.key.public()).unwrap();
    const MINUTE_MS: u64 = 60_000;
    old.clock.set_ms(VECTOR_START_MS + 2 * MINUTE_MS);
    old.dispatch.fail_next(Fault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    let change = CertChange {
        scopes: Some(renewed.scopes().to_vec()),
        expires_at: Some(renewed.expires_at()),
    };
    old.signer.renew(wallet_id, change).await.unwrap_err();
    old.clock.set_ms(VECTOR_START_MS + 3 * MINUTE_MS);
    old.signer.resume().await.unwrap();

    assert!(
        old.signer
            .certificates()
            .unwrap()
            .iter()
            .any(|c| c.signed() == renewed.signed()),
        "the renewed certificate"
    );
    let delivered: Vec<SignedDoc> = old
        .transport
        .requests()
        .into_iter()
        .filter(|r| r.method == "PUT" && r.path_and_query.ends_with("/identity"))
        .map(|r| {
            let body: Value = serde_json::from_slice(&r.body).unwrap();
            serde_json::from_value(body["identity"].clone()).unwrap()
        })
        .collect();
    let renewing = document("alice identity.json, wallet renewal in progress");
    let closed = document("alice identity.json, wallet renewal closed");
    assert!(delivered.contains(&renewing), "the renewing version 4");
    assert_eq!(delivered.last(), Some(&closed), "the closing version 5");
    assert_eq!(old.dispatch.identity_doc().unwrap().signed(), &closed);

    let vector = load("envelopes.json");
    let reduction = &vector["reduction_key_bundle"];
    let parts = old.dispatch.bundle_parts_of(&wallet_id);
    assert_eq!(parts.len(), 1);
    let contents = parts[0]
        .bundle
        .open(&old.key.public(), &wallet_id, &wallet.bundle_secret())
        .unwrap();
    assert_eq!(
        *contents.to_json().unwrap(),
        *text(reduction, "plaintext_json").as_bytes(),
        "the reduction's full bundle"
    );
}

/// `http.json`'s account erasure naming the `identity.json` it follows, and its answer (Dispatch
/// wire 7.4.16): at the vector's time, the erasure alice's signer sends is the vector's
/// request, its body naming her account's creation time, from her enrollment answer, and the
/// hash of her version 3, its mark, its headers and signature byte for byte; the vector's
/// answer, signed with the service key and carrying no head, confirms it, and the signer then
/// signs nothing more.
#[tokio::test]
async fn test_vectors_old_signer_erases_the_account_as_the_vectors_do() {
    let http = load("http.json");
    let request = http["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            text(r, "name")
                == "signer: account erasure, naming the account's creation time and the identity.json it follows"
        })
        .unwrap();
    let answer = http["responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["request"] == request["name"])
        .unwrap();
    let response = Response {
        status: u16::try_from(answer["status"].as_u64().unwrap()).unwrap(),
        headers: answer["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| Header::new(name, value.as_str().unwrap()))
            .collect(),
        body: text(answer, "body").as_bytes().to_vec(),
    };
    let mut old = old_signer_answering(Some(response)).await;
    let timestamp = text(&request["headers"], "dispatch-timestamp");
    old.clock
        .set_ms(pubky_dispatch_core::time::parse_rfc3339(timestamp).unwrap());
    old.signer
        .close_account(UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let sent = old
        .transport
        .requests()
        .into_iter()
        .find(|r| r.method == "POST" && r.path_and_query.ends_with("/erase"))
        .unwrap();
    assert_eq!(sent.path_and_query, text(request, "path"));
    assert_eq!(sent.body, unb64(text(request, "body_b64")).unwrap());
    for (name, value) in request["headers"].as_object().unwrap() {
        assert_eq!(
            sent.header(name),
            Some(value.as_str().unwrap()),
            "the {name} header"
        );
    }
    assert_eq!(old.signer.status(), super::SignerStatus::Erased);
    assert!(!old.homeserver.0.lock().unwrap().contains_key(IDENTITY_PATH));
}

/// The size check on a delivered version (Dispatch wire 3.7, 7.1): alice's version 3 with about
/// 1,200 `renewed` entries passes three quarters of the cap a delivery and a move's enrollment
/// share, and the user is told; a smaller version after it clears the alert.
#[tokio::test]
async fn test_vectors_old_signer_tells_of_an_identity_near_the_limit() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let mut body = v3.body().clone();
    body.version = 4;
    let app_id = body.apps[0].app_id;
    body.renewed = (0..1_200u32)
        .map(|n| {
            let mut cert = [0u8; 32];
            cert[..4].copy_from_slice(&n.to_be_bytes());
            RenewedCert {
                app_id,
                cert,
                until: Some(VECTOR_START_MS),
            }
        })
        .collect();
    let large = IdentityDoc::sign(&old.key, body).unwrap();
    old.signer
        .delivered(
            old.signer.service().unwrap(),
            large.signed().clone(),
            Some(v3.hash()),
            None,
        )
        .await
        .unwrap();
    assert!(
        old.signer
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::IdentityNearLimit { .. })),
        "{:?}",
        old.signer.alerts()
    );
    let mut small = v3.body().clone();
    small.version = 5;
    let small = IdentityDoc::sign(&old.key, small).unwrap();
    old.signer
        .delivered(
            old.signer.service().unwrap(),
            small.signed().clone(),
            Some(large.hash()),
            None,
        )
        .await
        .unwrap();
    assert!(
        !old.signer
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::IdentityNearLimit { .. }))
    );
}

/// alice's version 3 as version 4, with `entries` `renewed` entries of the wallet, closed
/// at `until` or open, held by the Dispatch and taken by the old signer as delivered. Each entry
/// names a certificate the signer issued and holds, as a hand-over carries them all (wire
/// 3.12).
async fn with_renewed(old: &mut OldSigner, entries: u32, until: Option<u64>) -> IdentityDoc {
    let v3 = old.signer.identity_doc().unwrap().unwrap();
    assert_eq!(v3.version(), 3);
    let mut body = v3.body().clone();
    body.version = 4;
    let listed = body.apps[0].cert;
    let listed = old
        .signer
        .state
        .certs
        .iter()
        .map(|cert| AppCert::verify(cert, &old.key.public()).unwrap())
        .find(|cert| cert.hash() == listed)
        .unwrap();
    body.renewed = (0..entries)
        .map(|n| {
            let mut earlier = listed.body().clone();
            earlier.issued_at -= u64::from(n) + 1;
            let cert = AppCert::issue(&old.key, earlier).unwrap();
            old.signer.state.certs.push(cert.signed().clone());
            RenewedCert {
                app_id: cert.app_id(),
                cert: cert.hash(),
                until,
            }
        })
        .collect();
    let large = IdentityDoc::sign(&old.key, body).unwrap();
    old.dispatch.deliver_identity(&large).unwrap();
    old.signer
        .delivered(
            old.signer.service().unwrap(),
            large.signed().clone(),
            Some(v3.hash()),
            None,
        )
        .await
        .unwrap();
    large
}

fn near_limit(signer: &Signer) -> bool {
    signer
        .alerts()
        .iter()
        .any(|alert| matches!(alert, Alert::IdentityNearLimit { .. }))
}

/// About 900 `renewed` entries: a delivery carrying the version stays under three quarters of
/// the cap, but a move's enrollment, which carries it encoded twice, is past it, and the user
/// is told (Dispatch wire 3.7, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_measures_the_enrollment_form_too() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let large = with_renewed(&mut old, 900, Some(VECTOR_START_MS)).await;
    let delivery = pubky_dispatch_core::http::IdentityDelivery {
        identity: large.signed().clone(),
        prev: Some(v3.hash()),
    };
    let limit = super::identity_limit().unwrap();
    assert!(
        delivery.to_json().len() * 4 <= limit * 3,
        "the delivery alone is under"
    );
    assert!(near_limit(&old.signer));
}

/// An identity whose delivery fits but whose move's enrollment, which carries it encoded
/// twice, wouldn't: a change that keeps it there is refused before anything is signed, as one
/// over the delivery's cap is, since the identity could never move (Dispatch wire 3.7, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_signs_no_version_that_cant_move() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let large = with_renewed(&mut old, 1_300, Some(VECTOR_START_MS)).await;
    let delivery = pubky_dispatch_core::http::IdentityDelivery {
        identity: large.signed().clone(),
        prev: Some(v3.hash()),
    };
    let limit = super::identity_limit().unwrap();
    assert!(
        delivery.to_json().len() + 1_000 < limit,
        "the delivery alone fits: {}",
        delivery.to_json().len()
    );
    let refused = old.signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(
        old.signer.identity_doc().unwrap().unwrap().hash(),
        large.hash()
    );
}

/// An identity over the size a delivery may carry: a change that keeps it there is refused
/// before anything is signed, and so is the automatic renewal, which the run skips with the
/// near-limit alert. A revocation keeps as many closed entries as fit and goes through
/// (Dispatch wire 7.1, 3.3).
#[tokio::test]
async fn test_vectors_old_signer_signs_nothing_over_the_cap_but_a_removal() {
    let mut old = old_signer().await;
    let parent = with_renewed(&mut old, 1_560, Some(VECTOR_START_MS)).await;
    let puts = |old: &OldSigner| {
        old.transport
            .requests()
            .iter()
            .filter(|r| r.method == "PUT" && r.path_and_query.ends_with("/identity"))
            .count()
    };
    let sent = puts(&old);
    let refused = old.signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge { .. })
        ),
        "{refused:?}"
    );
    // Past half the certificates' lifetimes: a renewal is refused, so the run renews nothing,
    // and says why.
    old.clock.set_ms(VECTOR_START_MS + 200 * 86_400_000);
    let keys = load("keys.json");
    let phone = app_keys(&keys, "phone").app_id_bytes();
    let refused = old
        .signer
        .renew(phone, CertChange::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge { .. })
        ),
        "{refused:?}"
    );
    old.signer.run_due().await.unwrap();
    assert_eq!(puts(&old), sent);
    let warning = old
        .signer
        .alerts()
        .iter()
        .find(|a| matches!(a, Alert::IdentityNearLimit { .. }))
        .unwrap()
        .clone();
    old.signer.clear_alert(&warning).await.unwrap();
    assert!(!near_limit(&old.signer));

    let wallet = app_keys(&keys, "wallet").app_id_bytes();
    let removed = old
        .signer
        .revoke(wallet, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let kept = &removed.body().renewed;
    let before = &parent.body().renewed;
    assert!(!kept.is_empty() && kept.len() < before.len());
    // All closures have the same until and App ID. The lowest decoded hashes go first.
    let mut by_cert = before.clone();
    by_cert.sort_unstable_by_key(|r| r.cert);
    let dropped = before.len() - kept.len();
    let expected: Vec<_> = before
        .iter()
        .copied()
        .filter(|r| r.cert >= by_cert[dropped].cert)
        .collect();
    assert_eq!(kept, &expected);
    let measurements =
        |body| super::measures(&old.signer.state, body, Some(parent.hash())).unwrap();
    let fits = |m: &super::Measure| m.bytes <= m.limit;
    let sized = measurements(removed.body());
    assert_eq!(sized.len(), 2);
    assert!(sized.iter().all(fits));
    let mut one_more = removed.body().clone();
    one_more.renewed.push(by_cert[dropped - 1]);
    assert!(!measurements(&one_more).iter().all(fits));
    assert!(puts(&old) > sent);
    assert_eq!(
        old.dispatch.identity_doc().unwrap().signed(),
        removed.signed()
    );
    assert!(near_limit(&old.signer));
}

/// A removal cannot discard the renewal history of a listed app (Dispatch wire 3.3).
#[tokio::test]
async fn test_removal_refuses_when_only_listed_history_exceeds_cap() {
    let mut old = old_signer().await;
    let before = with_renewed(&mut old, 1_300, Some(VECTOR_START_MS)).await;
    let phone = app_keys(&load("keys.json"), "phone").app_id_bytes();
    let refused = old
        .signer
        .revoke(phone, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap_err();
    assert!(matches!(
        refused,
        SignerError::Refused(Refusal::IdentityTooLarge { .. })
    ));
    assert_eq!(
        old.dispatch.identity_doc().unwrap().signed(),
        before.signed()
    );
    assert!(near_limit(&old.signer));
}

/// A new signer taking over an identity near the size a delivery may carry is told at its
/// take-over, not only at its own next delivery (Dispatch wire 3.7, 3.12, 7.1).
#[tokio::test]
async fn test_vectors_new_signer_is_told_of_a_large_identity_at_its_take_over() {
    let mut old = old_signer().await;
    with_renewed(&mut old, 1_200, Some(VECTOR_START_MS)).await;
    old.signer
        .hand_over_to(old.phone, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let keys = load("keys.json");
    let alice = old.key.public();
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &alice).unwrap();
    let phone = super::ReceivingApp {
        keys: app_keys(&keys, "phone"),
        cert: AppCert::verify(&document("phone certificate"), &alice).unwrap(),
        origin: v3.inbox().url.clone(),
        service_key: v3.inbox().service_key,
    };
    let env = SignerEnv {
        store: StoreHandle::inline(Arc::new(MemoryStore::new())),
        clock: old.clock.clone(),
        transport: old.transport.clone(),
        homeserver: old.homeserver.clone(),
        protocols: Protocols::new(vec![Arc::new(VectorScopes::new())]).unwrap(),
    };
    let new = Signer::receive_hand_over(env, &phone, Arc::new(Vault(Mutex::new(None))))
        .await
        .unwrap();
    assert!(near_limit(&new));
}

/// Open `renewed` entries under the cap that their closings would take over it: a change is
/// refused, since a closing owed past the cap could never be delivered and would stop every
/// later step; the revocation of their app goes through (Dispatch wire 3.3, 3.8, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_counts_the_closings_its_open_renewals_owe() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let large = with_renewed(&mut old, 1_700, None).await;
    let delivery = pubky_dispatch_core::http::IdentityDelivery {
        identity: large.signed().clone(),
        prev: Some(v3.hash()),
    };
    let limit = super::identity_limit().unwrap();
    assert!(delivery.to_json().len() < limit, "the open entries fit");
    let refused = old.signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge { .. })
        ),
        "{refused:?}"
    );
    let keys = load("keys.json");
    let wallet = app_keys(&keys, "wallet").app_id_bytes();
    let removed = old
        .signer
        .revoke(wallet, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(removed.body().renewed.is_empty());
}

/// A version whose delivery would land within the headroom kept under the cap is refused,
/// not only one over it: a later version adds a digit or two, and its closing must still be
/// deliverable (Dispatch wire 7.1).
#[tokio::test]
async fn test_vectors_old_signer_keeps_headroom_under_the_cap() {
    let mut old = old_signer().await;
    let mut future = old.signer.identity_doc().unwrap().unwrap().body().clone();
    future.version = 6;
    future.record_max_age = Some(60);
    future.renewed.clear();
    let (entries, origin) = size_parameters(&old, &future, 0, 7);
    old = Box::pin(old_signer_at(&origin)).await;
    let large = with_renewed(&mut old, entries, Some(VECTOR_START_MS)).await;
    let mut body = large.body().clone();
    body.version = 5;
    let five = IdentityDoc::sign(&old.key, body).unwrap();
    old.dispatch.deliver_identity(&five).unwrap();
    old.signer
        .delivered(
            old.signer.service().unwrap(),
            five.signed().clone(),
            Some(large.hash()),
            None,
        )
        .await
        .unwrap();
    let mut next = five.body().clone();
    next.version = 6;
    next.record_max_age = Some(60);
    let measure = binding(&old.signer, &next, Some(five.hash()));
    assert_eq!(measure.body, SizedBody::Enrollment);
    assert!(measure.bytes <= measure.limit && measure.bytes + 8 > measure.limit);
    let refused = old.signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge {
                body: SizedBody::Enrollment,
                bytes,
                limit,
            }) if bytes <= limit
        ),
        "{refused:?}"
    );
}

/// A reduction's renewing version signed within the cap's headroom of the cap: its closing,
/// which only closes what is signed already, may use the headroom, and is delivered, not
/// refused; refused, it would block every signing step (Dispatch wire 3.8, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_closes_a_reduction_within_the_headroom() {
    let mut old = old_signer().await;
    let alice = old.key.public();
    let renewed = AppCert::verify(&document("wallet certificate, renewed"), &alice).unwrap();
    let renewing = IdentityDoc::verify(
        &document("alice identity.json, wallet renewal in progress"),
        &alice,
    )
    .unwrap();
    let mut closing = renewing.body().clone();
    closing.version += 1;
    for entry in &mut closing.renewed {
        entry.until.get_or_insert(VECTOR_START_MS);
    }
    let (entries, origin) = size_parameters(&old, &closing, 0, 7);
    old = Box::pin(old_signer_at(&origin)).await;
    old.signer.state.certs.push(renewed.signed().clone());
    let v3 = old.signer.identity_doc().unwrap().unwrap();
    // Closed entries remain genuinely issued earlier certificates of the wallet.
    let listed = AppCert::verify(&document("wallet certificate"), &alice).unwrap();
    let filler: Vec<RenewedCert> = (0..entries)
        .map(|n| {
            let mut earlier = listed.body().clone();
            earlier.issued_at -= u64::from(n) + 1;
            let cert = AppCert::issue(&old.key, earlier).unwrap();
            old.signer.state.certs.push(cert.signed().clone());
            RenewedCert {
                app_id: cert.app_id(),
                cert: cert.hash(),
                until: Some(VECTOR_START_MS),
            }
        })
        .collect();
    let mut body = renewing.body().clone();
    body.inbox = v3.inbox().clone();
    body.renewed.extend(filler);
    let four = IdentityDoc::sign(&old.key, body).unwrap();
    let mut closing = four.body().clone();
    closing.version += 1;
    for entry in &mut closing.renewed {
        entry.until.get_or_insert(VECTOR_START_MS);
    }
    let measure = binding(&old.signer, &closing, Some(four.hash()));
    assert_eq!(measure.body, SizedBody::Enrollment);
    assert!(measure.bytes <= measure.limit && measure.bytes + 8 > measure.limit);
    old.dispatch.deliver_identity(&four).unwrap();
    old.signer
        .delivered(
            old.signer.service().unwrap(),
            four.signed().clone(),
            Some(v3.hash()),
            Some(VECTOR_START_MS),
        )
        .await
        .unwrap();
    assert!(!old.signer.owed().unwrap().is_empty(), "a closing is owed");
    old.signer.resume().await.unwrap();
    assert!(
        old.signer.owed().unwrap().is_empty(),
        "the closing was delivered"
    );
    let closed = old.signer.identity_doc().unwrap().unwrap();
    assert_eq!(closed.version(), 5);
    // The closed version still fits every body, its delivery and a move's enrollment.
    for measure in super::measures(&old.signer.state, closed.body(), Some(four.hash())).unwrap() {
        assert!(measure.bytes <= measure.limit, "{measure:?}");
    }
}

/// The measure of `body`, built on `prev`, that comes nearest its cap, as the signer judges
/// it.
fn binding(
    signer: &Signer,
    body: &pubky_dispatch_core::records::IdentityBody,
    prev: Option<[u8; 32]>,
) -> super::Measure {
    super::measures(&signer.state, body, prev)
        .unwrap()
        .into_iter()
        .max_by(|a, b| (a.bytes * b.limit).cmp(&(b.bytes * a.limit)))
        .unwrap()
}

/// How many closed `renewed` entries alice's version 3 can take with the body that binds,
/// a move's enrollment, at least `margin` bytes under its cap, and as few as possible more.
fn entries_near_the_cap(signer: &Signer, margin: usize) -> u32 {
    let v3 = signer.identity_doc().unwrap().unwrap();
    assert_eq!(v3.version(), 3);
    let with = |entries: u32| {
        let mut body = v3.body().clone();
        body.version = 6;
        body.renewed = (0..entries)
            .map(|n| {
                let mut cert = [0u8; 32];
                cert[..4].copy_from_slice(&n.to_be_bytes());
                RenewedCert {
                    app_id: body.apps[0].app_id,
                    cert,
                    until: Some(VECTOR_START_MS),
                }
            })
            .collect();
        let measure = binding(signer, &body, Some(v3.hash()));
        assert_eq!(measure.body, SizedBody::Enrollment);
        measure.bytes + margin <= measure.limit
    };
    (0..2_000).take_while(|n| with(*n)).last().unwrap()
}

/// One valid canonical origin for each permitted domain length (Dispatch wire 3.3, 7.1).
fn size_origin(domain_len: usize) -> String {
    use pubky_dispatch_core::net::{MAX_DOMAIN_LABEL_LEN, MAX_DOMAIN_LEN, MAX_ORIGIN_LEN};
    assert!((1..=MAX_DOMAIN_LEN).contains(&domain_len));
    let count = (domain_len + 1).div_ceil(MAX_DOMAIN_LABEL_LEN + 1);
    let mut remaining = domain_len - (count - 1);
    let mut labels = Vec::new();
    for left in (1..=count).rev() {
        let len = (remaining - (left - 1)).min(MAX_DOMAIN_LABEL_LEN);
        labels.push("a".repeat(len));
        remaining -= len;
    }
    let host = labels.join(".");
    assert_eq!(host.len(), domain_len);
    let origin = format!("https://{host}:65535");
    assert!(origin.len() <= MAX_ORIGIN_LEN);
    assert!(pubky_dispatch_core::records::is_origin(&origin));
    origin
}

/// Select the count and original origin using the actual body/envelope serializers.
/// The selected account and issued history are constructed before the action under test.
fn size_parameters(old: &OldSigner, future: &IdentityBody, lo: usize, hi: usize) -> (u32, String) {
    assert!(lo <= hi);
    let center = entries_near_the_cap(&old.signer, 400);
    let origins: Vec<String> = (1..=pubky_dispatch_core::net::MAX_DOMAIN_LEN)
        .map(size_origin)
        .collect();
    for entries in center.saturating_sub(4)..=(center + 4).min(1_999) {
        let mut body = future.clone();
        let app_id = body.apps[0].app_id;
        body.renewed.extend((0..entries).map(|n| {
            let mut cert = [0; 32];
            cert[..4].copy_from_slice(&n.to_be_bytes());
            RenewedCert {
                app_id,
                cert,
                until: Some(VECTOR_START_MS),
            }
        }));
        let mut measure = |origin: &str| {
            body.inbox.url = origin.into();
            let measured = binding(&old.signer, &body, Some([0; 32]));
            assert_eq!(measured.body, SizedBody::Enrollment);
            measured
        };
        let at = origins.partition_point(|origin| {
            let measured = measure(origin);
            measured.bytes + hi < measured.limit
        });
        if let Some(origin) = origins.get(at) {
            let measured = measure(origin);
            if measured.bytes + lo <= measured.limit && measured.bytes + hi >= measured.limit {
                return (entries, origin.clone());
            }
        }
    }
    panic!("a renewal count and valid original origin within the byte window")
}

/// A maximum-size, authenticated takeover intent (Dispatch account binding 2.1).
fn maximum_move_intent(key: &IdentityKey, origin: &str) -> EnrollmentIntent {
    let service = IdentityKey::from_secret([7; 32]);
    let created = VECTOR_START_MS - 500;
    let mut body = AccountObservationBody {
        identity: key.public(),
        origin: origin.into(),
        service_key: service.public(),
        store_id: [9; 16],
        association: AccountAssociation::Mark,
        created: Some(created),
        erased_at: Some(VECTOR_START_MS - 1_000),
        observed_at: VECTOR_START_MS,
        expires_at: VECTOR_START_MS + ACCOUNT_OBSERVATION_VALIDITY_MS,
    }
    .to_json()
    .unwrap();
    assert!(body.len() <= MAX_ACCOUNT_OBSERVATION_BYTES);
    body.resize(MAX_ACCOUNT_OBSERVATION_BYTES, b' ');
    let path = format!("/v1/{}/account", key.id());
    let headers = RequestHeaders {
        timestamp: pubky_dispatch_core::time::rfc3339_seconds(VECTOR_START_MS),
        identity: key.id(),
        app: None,
        cert: None,
        invite_code: None,
        created: None,
    };
    let request_signature = http::sign_request(
        key,
        &RequestTarget {
            method: "GET",
            path_and_query: &path,
            body: &[],
            origin,
        },
        &headers,
    );
    let signature = pubky_dispatch_core::enc::b64(&request_signature);
    let received = ReceivedHeaders::of([
        (http::header::IDENTITY, headers.identity.as_bytes()),
        (http::header::TIMESTAMP, headers.timestamp.as_bytes()),
        (http::header::SIGNATURE, signature.as_bytes()),
    ]);
    let sig = http::sign_response(
        &service,
        &ResponseParts {
            status: 200,
            request: ReceivedRequest {
                method: "GET",
                path_and_query: &path,
                body: BodyField::read(&[]),
                origin,
                headers: &received,
            },
            server_time: &pubky_dispatch_core::time::rfc3339(VECTOR_START_MS),
            head: None,
            body: &body,
        },
    );
    let observation = CarriedAccountObservation {
        body,
        sig,
        request_timestamp: headers.timestamp,
        request_signature,
    };
    observation.verify(&key.public(), origin).unwrap();
    assert_eq!(
        serde_json::to_vec(&observation).unwrap().len(),
        MAX_CARRIED_ACCOUNT_OBSERVATION_BYTES
    );
    let intent = EnrollmentIntent::Takeover {
        created,
        observation,
    };
    assert_eq!(
        serde_json::to_vec(&intent).unwrap().len(),
        MAX_ENROLLMENT_INTENT_BYTES
    );
    intent
}

/// The body a real move sends for `doc`, built as `DispatchClient::enroll` builds it, at the
/// longest origin a Dispatch may have, naming every App ID the records revoked and `doc`'s
/// `removed`: its length.
fn real_move_request(old: &OldSigner, doc: &IdentityDoc) -> usize {
    let host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(host.len(), pubky_dispatch_core::net::MAX_DOMAIN_LEN);
    let origin = format!("https://{host}:65535");
    assert_eq!(origin.len(), pubky_dispatch_core::net::MAX_ORIGIN_LEN);
    assert!(pubky_dispatch_core::records::is_origin(&origin));
    let mut revoked = old.signer.state.tombstones.clone();
    revoked.extend(doc.body().removed.iter().map(|r| r.app_id));
    let enrollment = pubky_dispatch_core::records::Enrollment::sign(
        &old.key,
        pubky_dispatch_core::records::EnrollmentBody {
            identity: old.key.public(),
            intent: maximum_move_intent(&old.key, &origin),
            origin,
            nonce: [7; 16],
            policy: doc.body().policy,
            identity_doc: Some(doc.signed().clone()),
            revoked_apps: Some(revoked),
        },
    )
    .unwrap();
    enrollment.to_request_json().unwrap().len()
}

/// The signer's measure of a move's enrollment carrying `body`, built on `prev`.
fn enrollment_measure(
    old: &OldSigner,
    body: &pubky_dispatch_core::records::IdentityBody,
    prev: [u8; 32],
) -> super::Measure {
    super::measures(&old.signer.state, body, Some(prev))
        .unwrap()
        .into_iter()
        .find(|m| m.body == SizedBody::Enrollment)
        .unwrap()
}

/// alice at version 5, padded so that the signer's own version 6 (`record_max_age`) lands
/// `lo..=hi` bytes under the enrollment cap, then version 6 signed by the signer. Returns
/// version 6 and the cap.
async fn at_the_edge(old: &mut OldSigner, lo: usize, hi: usize) -> (IdentityDoc, usize) {
    let mut future = old.signer.identity_doc().unwrap().unwrap().body().clone();
    future.version = 6;
    future.record_max_age = Some(60);
    future.renewed.clear();
    let (entries, origin) = size_parameters(old, &future, lo, hi);
    *old = Box::pin(old_signer_at(&origin)).await;
    let large = with_renewed(old, entries, Some(VECTOR_START_MS)).await;
    let mut body = large.body().clone();
    body.version = 5;
    let five = IdentityDoc::sign(&old.key, body).unwrap();
    old.dispatch.deliver_identity(&five).unwrap();
    old.signer
        .delivered(
            old.signer.service().unwrap(),
            five.signed().clone(),
            Some(large.hash()),
            None,
        )
        .await
        .unwrap();
    let mut six = five.body().clone();
    six.version = 6;
    six.record_max_age = Some(60);
    let measure = enrollment_measure(old, &six, five.hash());
    assert!(measure.bytes + lo <= measure.limit && measure.bytes + hi >= measure.limit);
    let six = old.signer.set_record_max_age(Some(60)).await.unwrap();
    (six, super::enrollment_limit().unwrap())
}

/// At the edge, the measure of a move's enrollment is never below the real move's body, and
/// above it by exactly the App IDs of the apps the version lists, counted as revoked already
/// (Dispatch wire 3.7, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_measures_a_real_move_at_the_edge() {
    let mut old = old_signer().await;
    let (six, limit) = at_the_edge(&mut old, 16, 20).await;
    let prev = old.signer.state.newest.as_ref().unwrap().prev.unwrap();
    let measured = enrollment_measure(&old, six.body(), prev);
    let real = real_move_request(&old, &six);
    // Each listed App ID, in `revoked_apps`: a 26-character text, quoted, and its comma, 29
    // bytes of the enrollment's JSON, which travels base64url-encoded (wire 2.2).
    let listed = six
        .body()
        .apps
        .iter()
        .filter(|app| !old.signer.state.tombstones.contains(&app.app_id))
        .count();
    assert!(measured.bytes >= real);
    assert!((measured.bytes - real).abs_diff(listed * 29 * 4 / 3) <= 2);
    assert!(real + 16 <= limit);
}

/// At the edge, revoking an app with no `renewed` entries goes through: its App ID was in the
/// measure already, as a listed app's, so its removal shrinks every body (Dispatch wire 3.7,
/// 7.1, spec 12.2).
#[tokio::test]
async fn test_vectors_old_signer_revokes_an_app_without_renewals_at_the_edge() {
    let mut old = old_signer().await;
    let (six, _) = at_the_edge(&mut old, 16, 30).await;
    let keys = load("keys.json");
    let phone = app_keys(&keys, "phone").app_id_bytes();
    assert!(six.body().renewed.iter().all(|r| r.app_id != phone));
    let removed = old
        .signer
        .revoke(phone, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(removed.listed_cert(&phone).is_none());
    old.signer.set_record_max_age(Some(61)).await.unwrap();
}

/// A reduction signed at the edge closes, and both the renewing version and its closing still
/// fit a real move (Dispatch wire 3.7, 3.8, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_closes_and_moves_a_reduction_at_the_edge() {
    let mut old = old_signer().await;
    let (wallet, change) = reduction_at_the_edge(&mut old).await;
    let six = old.signer.renew(wallet, change).await.unwrap();
    let limit = super::enrollment_limit().unwrap();
    assert!(real_move_request(&old, &six) <= limit);
    old.clock.set_ms(VECTOR_START_MS + 3 * 60_000);
    old.signer.resume().await.unwrap();
    old.signer.run_due().await.unwrap();
    assert!(old.signer.owed().unwrap().is_empty(), "nothing owed");
    let closed = old.signer.identity_doc().unwrap().unwrap();
    assert!(closed.body().renewed.iter().all(|r| r.until.is_some()));
    assert!(real_move_request(&old, &closed) <= limit);
}

/// A reduction signed at the edge whose renewing delivery failed, then a revocation of an app
/// without renewals while the closing is owed: the closing still fits, and the revocation
/// completes after it, nothing wedged (Dispatch wire 3.8, 7.1, spec 12.2).
#[tokio::test]
async fn test_vectors_old_signer_revokes_while_a_closing_is_owed_at_the_edge() {
    let mut old = old_signer().await;
    let (wallet, change) = reduction_at_the_edge(&mut old).await;
    let keys = load("keys.json");
    let phone = app_keys(&keys, "phone").app_id_bytes();
    old.dispatch.fail_next(Fault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    old.signer.renew(wallet, change).await.unwrap_err();
    old.signer
        .revoke(phone, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap_err();
    old.clock.set_ms(VECTOR_START_MS + 3 * 60_000);
    old.signer.resume().await.unwrap();
    old.signer.run_due().await.unwrap();
    assert!(
        old.signer.owed().unwrap().is_empty(),
        "the closing was delivered"
    );
    let newest = old.signer.identity_doc().unwrap().unwrap();
    assert!(
        newest.listed_cert(&phone).is_none(),
        "the revocation completed"
    );
    let limit = super::enrollment_limit().unwrap();
    assert!(real_move_request(&old, &newest) <= limit);
}

/// At the edge, a restore in place after the Dispatch shows a listed app revoked: the restore
/// adds that App ID to the records, which the measure counted already, as a listed app's, so
/// its next version, measured against the cap itself, is signed (Dispatch wire 3.13, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_restores_at_the_edge_after_a_revocation_at_the_dispatch() {
    let mut old = old_signer().await;
    at_the_edge(&mut old, 16, 20).await;
    let keys = load("keys.json");
    let wallet = app_keys(&keys, "wallet").app_id_bytes();
    old.dispatch.revoke(wallet).unwrap();
    let restored = old
        .signer
        .restore(UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(old.signer.state.tombstones.contains(&wallet));
    let limit = super::enrollment_limit().unwrap();
    assert!(real_move_request(&old, &restored) <= limit);
}

/// At the edge, a take-over after the Dispatch shows a listed app revoked: the new signer's
/// records take that App ID, which the measure counted already, and its first version is
/// signed and delivered (Dispatch wire 3.12, 7.1).
#[tokio::test]
async fn test_vectors_new_signer_takes_over_at_the_edge_after_a_revocation_at_the_dispatch() {
    let mut old = old_signer().await;
    let (six, _) = at_the_edge(&mut old, 16, 20).await;
    let keys = load("keys.json");
    let wallet = app_keys(&keys, "wallet").app_id_bytes();
    old.dispatch.revoke(wallet).unwrap();
    old.signer
        .hand_over_to(old.phone, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let alice = old.key.public();
    let account = old.signer.service().unwrap();
    let phone = super::ReceivingApp {
        keys: app_keys(&keys, "phone"),
        cert: AppCert::verify(&document("phone certificate"), &alice).unwrap(),
        origin: six.inbox().url.clone(),
        service_key: account.service_key,
    };
    let env = SignerEnv {
        store: StoreHandle::inline(Arc::new(MemoryStore::new())),
        clock: old.clock.clone(),
        transport: old.transport.clone(),
        homeserver: old.homeserver.clone(),
        protocols: Protocols::new(vec![Arc::new(VectorScopes::new())]).unwrap(),
    };
    let new = Signer::receive_hand_over(env, &phone, Arc::new(Vault(Mutex::new(None))))
        .await
        .unwrap();
    assert!(new.state.tombstones.contains(&wallet));
    let taken = new.identity_doc().unwrap().unwrap();
    assert_eq!(old.dispatch.identity_doc().unwrap().hash(), taken.hash());
    for measure in super::measures(&new.state, taken.body(), None).unwrap() {
        assert!(measure.bytes <= measure.limit, "{measure:?}");
    }
}

/// App IDs no version of alice's ever listed, which a faulty or hostile Dispatch shows revoked.
const NEVER_LISTED: [[u8; 16]; 3] = [[0x41; 16], [0x42; 16], [0x43; 16]];

/// At the edge, a restore in place while the Dispatch shows revoked App IDs no version listed:
/// the signer takes a removal from the Dispatch only for an app its version lists, so its
/// records don't grow and its next version is signed (Dispatch wire 3.13, 7.1, 7.4.12).
#[tokio::test]
async fn test_vectors_old_signer_restores_at_the_edge_ignoring_removals_of_apps_never_listed() {
    let mut old = old_signer().await;
    at_the_edge(&mut old, 16, 20).await;
    for app in NEVER_LISTED {
        old.dispatch.revoke(app).unwrap();
    }
    let restored = old
        .signer
        .restore(UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(
        NEVER_LISTED
            .iter()
            .all(|app| !old.signer.state.tombstones.contains(app))
    );
    let limit = super::enrollment_limit().unwrap();
    assert!(real_move_request(&old, &restored) <= limit);
    old.signer.set_record_max_age(Some(61)).await.unwrap();
}

/// At the edge, a take-over while the Dispatch shows revoked App IDs no version listed: the new
/// signer's records don't take them, and its first version is delivered (Dispatch wire 3.12,
/// 7.1, 7.4.12).
#[tokio::test]
async fn test_vectors_new_signer_takes_over_at_the_edge_ignoring_removals_of_apps_never_listed() {
    let mut old = old_signer().await;
    let (six, _) = at_the_edge(&mut old, 16, 20).await;
    old.signer
        .hand_over_to(old.phone, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    for app in NEVER_LISTED {
        old.dispatch.revoke(app).unwrap();
    }
    let keys = load("keys.json");
    let alice = old.key.public();
    let account = old.signer.service().unwrap();
    let phone = super::ReceivingApp {
        keys: app_keys(&keys, "phone"),
        cert: AppCert::verify(&document("phone certificate"), &alice).unwrap(),
        origin: six.inbox().url.clone(),
        service_key: account.service_key,
    };
    let env = SignerEnv {
        store: StoreHandle::inline(Arc::new(MemoryStore::new())),
        clock: old.clock.clone(),
        transport: old.transport.clone(),
        homeserver: old.homeserver.clone(),
        protocols: Protocols::new(vec![Arc::new(VectorScopes::new())]).unwrap(),
    };
    let new = Signer::receive_hand_over(env, &phone, Arc::new(Vault(Mutex::new(None))))
        .await
        .unwrap();
    assert!(
        NEVER_LISTED
            .iter()
            .all(|app| !new.state.tombstones.contains(app))
    );
    let taken = new.identity_doc().unwrap().unwrap();
    assert_eq!(old.dispatch.identity_doc().unwrap().hash(), taken.hash());
}

/// alice padded so that a reduction of the wallet, as the signer measures its renewing
/// version (one more entry, closed, at the next epoch), lands 16 to 20 bytes under the
/// enrollment cap. Returns the wallet and the reduction to ask for.
async fn reduction_at_the_edge(old: &mut OldSigner) -> ([u8; 16], CertChange) {
    let alice = old.key.public();
    let renewed = AppCert::verify(&document("wallet certificate, renewed"), &alice).unwrap();
    let keys = load("keys.json");
    let wallet = app_keys(&keys, "wallet").app_id_bytes();
    let renewing = |body: &IdentityBody| {
        let mut body = body.clone();
        body.version = 6;
        body.renewed.push(RenewedCert {
            app_id: wallet,
            cert: body.apps[0].cert,
            until: Some(0),
        });
        body.apps[0].cert = renewed.hash();
        body.data_epoch += 1;
        body
    };
    let mut baseline = old.signer.identity_doc().unwrap().unwrap().body().clone();
    baseline.renewed.clear();
    let (entries, origin) = size_parameters(old, &renewing(&baseline), 16, 20);
    *old = Box::pin(old_signer_at(&origin)).await;
    let large = with_renewed(old, entries, Some(VECTOR_START_MS)).await;
    let mut body = large.body().clone();
    body.version = 5;
    let five = IdentityDoc::sign(&old.key, body).unwrap();
    old.dispatch.deliver_identity(&five).unwrap();
    old.signer
        .delivered(
            old.signer.service().unwrap(),
            five.signed().clone(),
            Some(large.hash()),
            None,
        )
        .await
        .unwrap();
    let measure = enrollment_measure(old, &renewing(five.body()), five.hash());
    assert!(measure.bytes + 16 <= measure.limit && measure.bytes + 20 >= measure.limit);
    old.clock.set_ms(VECTOR_START_MS + 2 * 60_000);
    let change = CertChange {
        scopes: Some(renewed.scopes().to_vec()),
        expires_at: Some(renewed.expires_at()),
    };
    (wallet, change)
}

/// alice rotated her key in place before the loss: her version 4, at generation 2, names
/// generation 1's key in `service_keys`. Her service then loses everything, and she recovers
/// there: the version leaves out every generation at or below `recovery_from`, so nothing
/// resolves a lost generation's key (Dispatch wire 3.3, spec 12.6 step 1).
#[tokio::test]
async fn test_vectors_old_signer_recovers_without_the_lost_generations_service_keys() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let mut body = v3.body().clone();
    body.version = 4;
    body.generation = 2;
    body.service_keys
        .push(pubky_dispatch_core::records::ServiceKeyEntry {
            generation: 1,
            key: [0x11; 32],
        });
    let rotated = IdentityDoc::sign(&old.key, body).unwrap();
    old.dispatch.deliver_identity(&rotated).unwrap();
    old.signer
        .delivered(
            old.signer.service().unwrap(),
            rotated.signed().clone(),
            Some(v3.hash()),
            None,
        )
        .await
        .unwrap();
    let origin = old.signer.service().unwrap().origin;
    old.dispatch.lose_identity();
    // At the scripted Dispatch's own origin, which its enrollment names.
    let recovered = old
        .signer
        .declare_provider_loss(&origin, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert_eq!(recovered.generation(), 3);
    assert_eq!(recovered.body().recovery_from, Some(2));
    assert!(recovered.body().service_keys.is_empty());
    assert_eq!(
        old.dispatch.identity_doc().unwrap().hash(),
        recovered.hash()
    );
}

/// A listed app whose certificate this install doesn't hold may hold `lists.manage`, so the
/// recovery leaves the staged admission for its upload, failing closed (Dispatch spec 12.6
/// step 2). The backup's seal refuses such a version before any delivery (Dispatch wire
/// 3.12), so the rule is held here on its own.
#[tokio::test]
async fn test_vectors_old_signer_counts_an_unknown_certificate_as_managing_lists() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let mut body = v3.body().clone();
    let held = old.signer.held_certs().unwrap();
    body.apps.retain(|listed| {
        held.iter()
            .find(|cert| cert.hash() == listed.cert)
            .is_some_and(|cert| !cert.has_permission(Permission::ListsManage))
    });
    assert!(!body.apps.is_empty(), "an app without lists.manage");
    let without = IdentityDoc::sign(&old.key, body).unwrap();
    assert!(!old.signer.listed_may_manage_lists(&without).unwrap());
    old.signer.state.certs.clear();
    assert!(old.signer.listed_may_manage_lists(&without).unwrap());
}

/// A recovery whose version, naming a longer origin, the cap can't take is refused before
/// its enrollment is sent: nothing at the service, and the user may declare it at another
/// origin (Dispatch spec 12.6 step 1, wire 7.1).
#[tokio::test]
async fn test_vectors_old_signer_refuses_a_recovery_over_the_cap_before_enrolling() {
    let mut old = old_signer().await;
    with_renewed(&mut old, 1_560, Some(VECTOR_START_MS)).await;
    old.dispatch.lose_identity();
    let sent = old.transport.requests().len();
    let long = format!("https://{}.example", "a".repeat(200));
    let refused = old
        .signer
        .declare_provider_loss(&long, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(old.transport.requests().len(), sent, "nothing sent");
    assert!(old.signer.flow.is_none());
    assert!(!old.signer.state.recovering);
}
