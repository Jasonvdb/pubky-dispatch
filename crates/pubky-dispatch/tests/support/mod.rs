//! Shared setup for the service's tests: the vectors, a service on a test database with the
//! vectors' fixed keys and a manual clock, and signed requests.

// Test helpers fail the test on any error; not every test file uses every helper.
#![allow(clippy::expect_used, clippy::panic, dead_code)]

use std::{path::PathBuf, sync::Arc};

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use pubky_dispatch::{
    http::Handler,
    http::{DispatchRequest, DispatchResponse, route::route},
    keys::{FileKeyStore, KeyStore},
    limits::Limits,
    marks::MarkStore,
    service::Service,
    store::{
        DatabaseConfig,
        testing::{TestDatabase, test_database, test_database_with},
    },
    time::{ManualClock, TrustedTime, TrustedTimeConfig},
};
use pubky_dispatch_core::{
    enc::{b64, unb64},
    http::{self as wire_http, RequestHeaders, RequestTarget, header},
    ops::{OpsRequest, SignedOp},
    sig::SignedDoc,
    time::{parse_rfc3339, rfc3339_seconds},
};
use serde_json::Value;

pub const ORIGIN: &str = "https://inbox.example";

pub fn vectors(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(name);
    serde_json::from_slice(&std::fs::read(&path).expect("vector file")).expect("json")
}

pub fn named<'a>(list: &'a Value, name: &str) -> &'a Value {
    list.as_array()
        .expect("list")
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

pub fn hex32(text: &Value) -> [u8; 32] {
    hex::decode(text.as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

pub struct Replay {
    pub db: TestDatabase,
    pub clock: Arc<ManualClock>,
    pub service: Service,
    pub keys: Arc<FileKeyStore>,
    pub marks: MarkStore,
    pub time: Arc<TrustedTime>,
    _key_dir: tempfile::TempDir,
}

impl Replay {
    /// The key store's directory, where the service key, the ledger and the marks lie.
    pub fn key_dir(&self) -> &std::path::Path {
        self._key_dir.path()
    }

    /// Another service on the same database, keys and clock, with `limits`, as after the
    /// operator changes its configuration.
    pub fn restarted_with(&self, limits: Limits) -> Service {
        Service::new(
            ORIGIN.into(),
            self.db.service_store(),
            self.keys.clone(),
            self.marks.clone(),
            self.time.clone(),
            limits,
        )
    }

    /// Another service on the same database, keys and clock, that needs trusted time and
    /// has no sample.
    pub fn without_trusted_time(&self) -> Service {
        self.without_trusted_time_with(Limits::default())
    }

    /// [`Replay::without_trusted_time`], with `limits`.
    pub fn without_trusted_time_with(&self, limits: Limits) -> Service {
        Service::new(
            ORIGIN.into(),
            self.db.service_store(),
            self.keys.clone(),
            self.marks.clone(),
            Arc::new(TrustedTime::new(
                TrustedTimeConfig::default(),
                self.clock.clone(),
            )),
            limits,
        )
    }
}

pub async fn replay() -> Option<Replay> {
    replay_with(Limits::default()).await
}

/// A service with `limits`, on a fresh test database.
pub async fn replay_with(limits: Limits) -> Option<Replay> {
    replay_with_time(limits, false).await
}

/// A service with `limits`, on a fresh test database; with `time_required`, it needs
/// trusted time, and has no sample.
pub async fn replay_with_time(limits: Limits, time_required: bool) -> Option<Replay> {
    replay_at(ORIGIN, "service/alice", limits, time_required).await
}

/// bob's Dispatch origin in the vectors.
pub const BOB_ORIGIN: &str = "https://inbox.bob.example";

/// A service at `origin` whose service key is the vectors' service key of
/// `service_label`, on a fresh test database.
pub async fn replay_at(
    origin: &str,
    service_label: &str,
    limits: Limits,
    time_required: bool,
) -> Option<Replay> {
    let db = test_database().await?;
    Some(replay_on(db, origin, service_label, limits, time_required))
}

/// A service on alice's origin with `config`'s pool settings, on a fresh test database.
pub async fn replay_with_database(config: &DatabaseConfig) -> Option<Replay> {
    let db = test_database_with(config).await?;
    Some(replay_on(
        db,
        ORIGIN,
        "service/alice",
        Limits::default(),
        false,
    ))
}

/// A service at `origin` on `db`, as [`replay_at`].
fn replay_on(
    db: TestDatabase,
    origin: &str,
    service_label: &str,
    limits: Limits,
    time_required: bool,
) -> Replay {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let keys = vectors("keys.json");
    let service = keys["service_keys"]
        .as_array()
        .expect("service keys")
        .iter()
        .find(|key| key["seed_label"] == service_label)
        .expect("the service key");
    let key_dir = tempfile::tempdir().expect("key dir");
    let keys = Arc::new(
        FileKeyStore::open_with_service_seed(key_dir.path(), hex32(&service["secret_hex"]))
            .expect("key store"),
    );
    let marks = MarkStore::open(key_dir.path()).expect("mark store");
    let clock = Arc::new(ManualClock::new(0));
    let time = Arc::new(TrustedTime::new(
        TrustedTimeConfig {
            required: time_required,
            ..TrustedTimeConfig::default()
        },
        clock.clone(),
    ));
    let service = Service::new(
        origin.into(),
        db.service_store(),
        keys.clone(),
        marks.clone(),
        time.clone(),
        limits,
    );
    Replay {
        db,
        clock,
        service,
        keys,
        marks,
        time,
        _key_dir: key_dir,
    }
}

/// bob's account at a Dispatch made by `replay_at(BOB_ORIGIN, "service/bob", ..)`, serving,
/// with his `identity.json` version 1 (`documents.json` "bob identity.json") and his mark at
/// (0, 0): his Pubky ID.
pub async fn serve_bob(replay: &Replay) -> String {
    let keys = vectors("keys.json");
    let bob = keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .expect("bob");
    let id = bob["pubky_id"].as_str().expect("id").to_string();
    let doc: pubky_dispatch_core::sig::SignedDoc = serde_json::from_value(
        named(&vectors("documents.json")["documents"], "bob identity.json")["signed"].clone(),
    )
    .expect("document");
    replay
        .db
        .store()
        .create_account(&pubky_dispatch::store::NewAccount {
            activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
            id: id.clone(),
            identity_key: hex32(&bob["public_hex"]),
            generation: 1,
            created_at_ms: 0,
            limits: pubky_dispatch_core::records::Limits::default(),
            identity_doc: Some(doc),
            revoked_apps: Vec::new(),
            enrollment_hash: [0; 32],
            enrollment_store_id: replay.marks.identity().await.expect("store identity"),
            stamped_time_ms: 0,
            stamped_by: replay.service.run().id(),
        })
        .await
        .expect("bob's account");
    replay
        .marks
        .create_zero(&id, service_public(replay), 0)
        .await
        .expect("bob's mark");
    id
}

/// A request from `app` (a `keys.json` app) to another identity's Dispatch at `origin`,
/// carrying its certificate (`documents.json` "<app> certificate") in `Switch-Cert` and,
/// if given, an invite code, signed at `at_ms`.
#[allow(clippy::too_many_arguments)]
pub fn other_request(
    app_name: &str,
    origin: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
    invite_code: Option<&str>,
    at_ms: u64,
) -> DispatchRequest {
    other_request_as(
        app_name,
        &format!("{app_name} certificate"),
        app_name,
        origin,
        method,
        path,
        body,
        invite_code,
        at_ms,
    )
}

/// As [`other_request`], claiming `app_name`'s identity and App ID, but carrying the
/// certificate `cert_name` (a `documents.json` name) and signed with `signing_app`'s key:
/// for the certificate checks of an app of another identity (Dispatch wire 7.2).
#[allow(clippy::too_many_arguments)]
pub fn other_request_as(
    app_name: &str,
    cert_name: &str,
    signing_app: &str,
    origin: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
    invite_code: Option<&str>,
    at_ms: u64,
) -> DispatchRequest {
    let keys = vectors("keys.json");
    let signer = app(&keys, signing_app)["signing_secret_hex"].clone();
    let app = app(&keys, app_name);
    let cert: pubky_dispatch_core::sig::SignedDoc = serde_json::from_value(
        named(&vectors("documents.json")["documents"], cert_name)["signed"].clone(),
    )
    .expect("certificate");
    let identity = app["identity"].as_str().expect("identity").to_string();
    let app_id = app["app_id"].as_str().expect("app id").to_string();
    let timestamp = rfc3339_seconds(at_ms);
    let signed_headers = RequestHeaders {
        timestamp: timestamp.clone(),
        identity: identity.clone(),
        app: Some(app_id.clone()),
        cert: Some(cert.compact()),
        invite_code: invite_code.map(str::to_string),
        created: None,
    };
    let secret = ed25519_dalek::SigningKey::from_bytes(&hex32(&signer));
    let signature = b64(&wire_http::sign_request(
        &secret,
        &RequestTarget {
            method,
            path_and_query: path,
            body: &body,
            origin,
        },
        &signed_headers,
    ));
    let compact = cert.compact();
    let mut headers = vec![
        (header::IDENTITY, identity.as_str()),
        (header::APP, app_id.as_str()),
        (header::CERT, compact.as_str()),
        (header::TIMESTAMP, timestamp.as_str()),
        (header::SIGNATURE, signature.as_str()),
    ];
    if let Some(code) = invite_code {
        headers.push((header::INVITE_CODE, code));
    }
    request(method, path, &headers, body)
}

pub fn request(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> DispatchRequest {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("name"),
            HeaderValue::from_str(value).expect("value"),
        );
    }
    DispatchRequest {
        route: route(method, path).expect("route"),
        method: method.into(),
        path_and_query: path.into(),
        headers: map,
        body: body.into(),
        source: None,
    }
}

pub fn vector_request(case: &Value) -> DispatchRequest {
    let headers: Vec<(String, String)> = case["headers"]
        .as_object()
        .expect("headers")
        .iter()
        .map(|(name, value)| (name.clone(), value.as_str().expect("text").to_string()))
        .collect();
    let refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let body = unb64(case["body_b64"].as_str().unwrap_or_default()).expect("body");
    request(
        case["method"].as_str().expect("method"),
        case["path"].as_str().expect("path"),
        &refs,
        body,
    )
}

pub fn header_text<'a>(response: &'a DispatchResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header, _)| header.as_str() == name)
        .and_then(|(_, value)| value.to_str().ok())
}

/// A request as the service received it, which a response signature covers (Dispatch wire
/// 7.1).
#[derive(Clone, Debug)]
pub struct Sent {
    method: String,
    path_and_query: String,
    body: wire_http::BodyField,
    origin: String,
    headers: wire_http::ReceivedHeaders,
}

impl Sent {
    /// `request` as a service at [`ORIGIN`] receives it, its body read whole.
    pub fn of(request: &DispatchRequest) -> Self {
        Self::at(request, ORIGIN)
    }

    /// `request` as a service at `origin` receives it, its body read whole.
    pub fn at(request: &DispatchRequest, origin: &str) -> Self {
        Sent {
            method: request.method.clone(),
            path_and_query: request.path_and_query.clone(),
            body: wire_http::BodyField::read(&request.body),
            origin: origin.to_owned(),
            headers: wire_http::ReceivedHeaders::of(
                request
                    .headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_bytes())),
            ),
        }
    }

    /// A request with no header and an empty body, read whole, at a path no route takes.
    pub fn unrouted(method: &str, path_and_query: &str) -> Self {
        Sent {
            method: method.to_owned(),
            path_and_query: path_and_query.to_owned(),
            body: wire_http::BodyField::read(b""),
            origin: ORIGIN.to_owned(),
            headers: wire_http::ReceivedHeaders::default(),
        }
    }

    /// The same request with its body not read, as a refusal before the body binds it.
    pub fn unread(mut self) -> Self {
        self.body = wire_http::BodyField::NotRead;
        self
    }

    /// The same request at `path_and_query`.
    pub fn at_path(mut self, path_and_query: String) -> Self {
        self.path_and_query = path_and_query;
        self
    }

    /// The same request with `method`.
    pub fn with_method(mut self, method: &str) -> Self {
        self.method = method.to_owned();
        self
    }

    /// Whether it carries `Switch-Signature`.
    pub fn signed(&self) -> bool {
        !self.headers.values(header::SIGNATURE).is_empty()
    }

    /// The core's view of it.
    pub fn request(&self) -> wire_http::ReceivedRequest<'_> {
        wire_http::ReceivedRequest {
            method: &self.method,
            path_and_query: &self.path_and_query,
            body: self.body,
            origin: &self.origin,
            headers: &self.headers,
        }
    }
}

/// Whether `answer` to `sent` is signed with `key` (Dispatch wire 7.1).
pub fn signed_with(answer: &DispatchResponse, key: &[u8; 32], sent: &Sent) -> bool {
    let Some(signature) = header_text(answer, header::SERVICE_SIGNATURE)
        .and_then(|text| pubky_dispatch_core::enc::unb64_array::<64>(text).ok())
    else {
        return false;
    };
    wire_http::verify_response(
        key,
        &wire_http::ResponseParts {
            status: answer.status,
            request: sent.request(),
            server_time: header_text(answer, header::SERVER_TIME).expect("time"),
            head: header_text(answer, header::HEAD),
            body: &answer.body,
        },
        &signature,
    )
    .is_ok()
}

/// The response matches the vector byte for byte: status, body, server time and signature.
pub fn assert_matches(response: &DispatchResponse, expected: &Value) {
    let name = expected["name"].as_str().expect("name");
    assert_eq!(
        u64::from(response.status),
        expected["status"].as_u64().expect("status"),
        "{name}: status"
    );
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        expected["body"].as_str().expect("body"),
        "{name}: body"
    );
    for (header, value) in expected["headers"].as_object().expect("headers") {
        assert_eq!(
            header_text(response, header),
            value.as_str(),
            "{name}: header {header}"
        );
    }
}

pub fn set_time(clock: &ManualClock, text: &str) {
    clock.set_wall_ms(parse_rfc3339(text).expect("time"));
}

/// The creation of alice's original vector account.
pub fn alice_created() -> u64 {
    let http = vectors("http.json");
    let answer = named(
        &http["responses"],
        "signer: enrollment answer, signed with the service key",
    );
    let body: Value =
        serde_json::from_str(answer["body"].as_str().expect("body")).expect("enrollment answer");
    ms(body["created"].as_str().expect("created"))
}

/// A request from alice's signer, bound to her original vector account where required.
pub fn signer_request(method: &str, path: &str, body: Vec<u8>, at_ms: u64) -> DispatchRequest {
    let created = match route(method, path).expect("route").call {
        pubky_dispatch::http::route::Call::Enroll => {
            let wrapper: Option<Value> = serde_json::from_slice(&body).ok();
            wrapper.and_then(|wrapper| {
                let signed: SignedDoc =
                    serde_json::from_value(wrapper["enrollment"].clone()).ok()?;
                let fields: pubky_dispatch_core::records::EnrollmentBody =
                    serde_json::from_slice(&signed.body_bytes().ok()?).ok()?;
                fields.intent.created()
            })
        }
        pubky_dispatch::http::route::Call::GetAccount => None,
        _ => Some(alice_created()),
    };
    signer_request_at_creation(method, path, body, at_ms, created)
}

/// A signer request carrying exactly `created`, including an intentionally absent binding.
pub fn signer_request_at_creation(
    method: &str,
    path: &str,
    body: Vec<u8>,
    at_ms: u64,
    created: Option<u64>,
) -> DispatchRequest {
    let keys = vectors("keys.json");
    let alice = alice(&keys);
    let alice_id = alice["pubky_id"].as_str().expect("id").to_string();
    let timestamp = rfc3339_seconds(at_ms);
    let signed_headers = RequestHeaders {
        timestamp: timestamp.clone(),
        identity: alice_id.clone(),
        created: created.map(pubky_dispatch_core::time::rfc3339),
        ..RequestHeaders::default()
    };
    let secret = ed25519_dalek::SigningKey::from_bytes(&hex32(&alice["secret_hex"]));
    let signature = b64(&wire_http::sign_request(
        &secret,
        &RequestTarget {
            method,
            path_and_query: path,
            body: &body,
            origin: ORIGIN,
        },
        &signed_headers,
    ));
    let mut headers = vec![
        (header::IDENTITY, alice_id.as_str()),
        (header::TIMESTAMP, timestamp.as_str()),
        (header::SIGNATURE, signature.as_str()),
    ];
    if let Some(created) = signed_headers.created.as_deref() {
        headers.push((header::CREATED, created));
    }
    request(method, path, &headers, body)
}

/// alice's entry in `keys.json`.
pub fn alice(keys: &Value) -> &Value {
    keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "alice")
        .expect("alice")
}

/// The time `text` names, in Unix milliseconds.
pub fn ms(text: &str) -> u64 {
    parse_rfc3339(text).expect("time")
}

/// The app of `keys.json` named `name`.
pub fn app<'a>(keys: &'a Value, name: &str) -> &'a Value {
    keys["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|app| app["name"] == name)
        .unwrap_or_else(|| panic!("no app {name}"))
}

/// A request from alice's own app `app` (a `keys.json` entry), signed with its fixed
/// signing key at `at_ms`.
pub fn app_request(
    app: &Value,
    method: &str,
    path: &str,
    body: Vec<u8>,
    at_ms: u64,
) -> DispatchRequest {
    let keys = vectors("keys.json");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    let app_id = app["app_id"].as_str().expect("app id").to_string();
    let timestamp = rfc3339_seconds(at_ms);
    let signed_headers = RequestHeaders {
        timestamp: timestamp.clone(),
        identity: alice_id.clone(),
        app: Some(app_id.clone()),
        ..RequestHeaders::default()
    };
    let secret = ed25519_dalek::SigningKey::from_bytes(&hex32(&app["signing_secret_hex"]));
    let signature = b64(&wire_http::sign_request(
        &secret,
        &RequestTarget {
            method,
            path_and_query: path,
            body: &body,
            origin: ORIGIN,
        },
        &signed_headers,
    ));
    request(
        method,
        path,
        &[
            (header::IDENTITY, &alice_id),
            (header::APP, &app_id),
            (header::TIMESTAMP, &timestamp),
            (header::SIGNATURE, &signature),
        ],
        body,
    )
}

/// The `server_time` of a `chain.json` item's envelope.
pub fn item_time(item: &Value) -> String {
    let envelope: Value =
        serde_json::from_str(item["envelope_json"].as_str().expect("envelope")).expect("json");
    envelope["server_time"].as_str().expect("time").to_string()
}

/// Read genuine account evidence for a new fixture action, preserving its signed bytes.
pub async fn account_observation(
    replay: &Replay,
    key: &pubky_dispatch_core::keys::IdentityKey,
    at_ms: u64,
) -> pubky_dispatch_core::records::CarriedAccountObservation {
    account_observation_at(replay, key, ORIGIN, at_ms).await
}

/// Read account evidence at the fixture service's explicit origin.
pub async fn account_observation_at(
    replay: &Replay,
    key: &pubky_dispatch_core::keys::IdentityKey,
    origin: &str,
    at_ms: u64,
) -> pubky_dispatch_core::records::CarriedAccountObservation {
    use pubky_dispatch_core::records::CarriedAccountObservation;
    let path = format!("/v1/{}/account", key.id());
    let fields = RequestHeaders {
        timestamp: rfc3339_seconds(at_ms),
        identity: key.id(),
        ..RequestHeaders::default()
    };
    let signature = wire_http::sign_request(
        key,
        &RequestTarget {
            method: "GET",
            path_and_query: &path,
            body: &[],
            origin,
        },
        &fields,
    );
    let encoded = b64(&signature);
    let query = request(
        "GET",
        &path,
        &[
            (header::IDENTITY, fields.identity.as_str()),
            (header::TIMESTAMP, fields.timestamp.as_str()),
            (header::SIGNATURE, encoded.as_str()),
        ],
        Vec::new(),
    );
    let sent = Sent::at(&query, origin);
    let answer = replay.service.handle(query).await;
    assert_eq!(
        answer.status,
        200,
        "account observation: {}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(signed_with(&answer, &service_public(replay), &sent));
    let observation = CarriedAccountObservation {
        body: answer.body.to_vec(),
        sig: pubky_dispatch_core::enc::unb64_array(
            header_text(&answer, header::SERVICE_SIGNATURE).expect("response signature"),
        )
        .expect("signature bytes"),
        request_timestamp: fields.timestamp,
        request_signature: signature,
    };
    let observed = observation
        .verify(&key.public(), origin)
        .expect("observation");
    assert_eq!(
        observed.body().store_id,
        replay.marks.identity().await.expect("store identity")
    );
    observation
}

/// Begin a new fixture enrollment from the current authenticated association. A retry
/// instead keeps the originally signed enrollment and never calls this helper again.
pub async fn new_alice_enrollment_intent(
    replay: &Replay,
    at_ms: u64,
) -> pubky_dispatch_core::records::EnrollmentIntent {
    use pubky_dispatch_core::records::{AccountAssociation, EnrollmentIntent};
    let keys = vectors("keys.json");
    let key =
        pubky_dispatch_core::keys::IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let observation = account_observation(replay, &key, at_ms).await;
    let body = observation
        .verify(&key.public(), ORIGIN)
        .expect("observation")
        .body()
        .clone();
    match body.association {
        AccountAssociation::Account => EnrollmentIntent::Existing {
            created: body.created.expect("account creation"),
        },
        AccountAssociation::Mark => EnrollmentIntent::Takeover {
            created: body.created.expect("mark creation"),
            observation,
        },
        AccountAssociation::Absent => EnrollmentIntent::Create { observation },
    }
}

/// Create alice's enrollment from this service's authenticated absence observation.
pub async fn fresh_alice_enrollment(replay: &Replay, at_ms: u64) -> DispatchRequest {
    use pubky_dispatch_core::records::{AccountAssociation, Enrollment, EnrollmentIntent};
    let keys = vectors("keys.json");
    let key =
        pubky_dispatch_core::keys::IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let observation = account_observation(replay, &key, at_ms).await;
    assert_eq!(
        observation
            .verify(&key.public(), ORIGIN)
            .expect("observation")
            .body()
            .association,
        AccountAssociation::Absent
    );
    let http = vectors("http.json");
    let template = vector_request(named(&http["requests"], "signer: enrollment"));
    let wrapper: Value = serde_json::from_slice(&template.body).expect("enrollment request");
    let signed: SignedDoc =
        serde_json::from_value(wrapper["enrollment"].clone()).expect("signed enrollment");
    let mut body = Enrollment::verify(&signed, &key.public(), ORIGIN)
        .expect("enrollment template")
        .body()
        .clone();
    body.intent = EnrollmentIntent::Create { observation };
    let enrollment = Enrollment::sign(&key, body).expect("enrollment");
    signer_request(
        "POST",
        "/v1/enroll",
        enrollment.to_request_json().expect("request"),
        at_ms,
    )
}

/// The body of alice's enrollment at `at_ms`: the vectors' enrollment with `nonce`,
/// `revoked_apps` and `identity_doc`, under the intent this service's account observation
/// gives now (account binding). The same body sent again is the exact retry.
pub async fn alice_enrollment_body(
    replay: &Replay,
    nonce: u8,
    revoked_apps: Option<Vec<[u8; 16]>>,
    identity_doc: Option<SignedDoc>,
    at_ms: u64,
) -> Vec<u8> {
    use pubky_dispatch_core::records::Enrollment;
    let keys = vectors("keys.json");
    let key =
        pubky_dispatch_core::keys::IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let http = vectors("http.json");
    let template = vector_request(named(&http["requests"], "signer: enrollment"));
    let wrapper: Value = serde_json::from_slice(&template.body).expect("enrollment request");
    let signed: SignedDoc =
        serde_json::from_value(wrapper["enrollment"].clone()).expect("signed enrollment");
    let mut body = Enrollment::verify(&signed, &key.public(), ORIGIN)
        .expect("enrollment template")
        .body()
        .clone();
    body.nonce = [nonce; 16];
    body.revoked_apps = revoked_apps;
    body.identity_doc = identity_doc;
    body.intent = new_alice_enrollment_intent(replay, at_ms).await;
    Enrollment::sign(&key, body)
        .expect("enrollment")
        .to_request_json()
        .expect("request")
}

/// alice's account as `chain.json` starts it: enrolled, then given `identity.json` version
/// 1 at seq 1 and version 3 at seq 2, at the items' times.
pub async fn serve_alice(replay: &Replay) {
    let http = vectors("http.json");
    let chain = vectors("chain.json");
    let documents = vectors("documents.json");
    let keys = vectors("keys.json");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    let enrolled = named(
        &http["responses"],
        "signer: enrollment answer, signed with the service key",
    );
    set_time(
        &replay.clock,
        enrolled["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let enrollment = fresh_alice_enrollment(
        replay,
        ms(enrolled["headers"]["switch-server-time"]
            .as_str()
            .expect("time")),
    )
    .await;
    let answer = replay.service.handle(enrollment).await;
    assert_eq!(answer.status, 200, "enrolled");
    let answer: Value = serde_json::from_slice(&answer.body).expect("enrollment answer");
    assert_eq!(
        ms(answer["created"].as_str().expect("created")),
        alice_created()
    );
    let items = chain["items"].as_array().expect("items");
    set_time(&replay.clock, &item_time(&items[0]));
    let delivery = vector_request(named(&http["requests"], "signer: identity.json delivery"));
    assert_eq!(
        replay.service.handle(delivery).await.status,
        200,
        "version 1"
    );
    let at = item_time(&items[1]);
    set_time(&replay.clock, &at);
    let doc = |name: &str| -> pubky_dispatch_core::sig::SignedDoc {
        serde_json::from_value(named(&documents["documents"], name)["signed"].clone())
            .expect("document")
    };
    let version_1 = doc("alice identity.json, first delivery (version 1)");
    let body = pubky_dispatch_core::http::IdentityDelivery {
        identity: doc("alice identity.json"),
        prev: Some(version_1.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{alice_id}/identity");
    let delivery = signer_request("PUT", &path, body, ms(&at));
    assert_eq!(
        replay.service.handle(delivery).await.status,
        200,
        "version 3"
    );
}

/// A request signed at `at_ms` by `key`, for the identity `identity` (a Pubky ID) and, with
/// `app`, one of its apps (an App ID).
pub fn signed_request(
    key: &ed25519_dalek::SigningKey,
    identity: &str,
    app: Option<&str>,
    method: &str,
    path: &str,
    body: Vec<u8>,
    at_ms: u64,
) -> DispatchRequest {
    let timestamp = rfc3339_seconds(at_ms);
    let signed_headers = RequestHeaders {
        timestamp: timestamp.clone(),
        identity: identity.to_string(),
        app: app.map(str::to_string),
        ..RequestHeaders::default()
    };
    signed_request_with_headers(key, signed_headers, method, path, body)
}

/// Sign the exact fixture headers, including an explicit account creation where required.
pub fn signed_request_with_headers(
    key: &ed25519_dalek::SigningKey,
    headers: RequestHeaders,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> DispatchRequest {
    let signature = b64(&wire_http::sign_request(
        key,
        &RequestTarget {
            method,
            path_and_query: path,
            body: &body,
            origin: ORIGIN,
        },
        &headers,
    ));
    let mut fields = vec![
        (header::IDENTITY, headers.identity.as_str()),
        (header::TIMESTAMP, headers.timestamp.as_str()),
        (header::SIGNATURE, signature.as_str()),
    ];
    if let Some(app) = headers.app.as_deref() {
        fields.push((header::APP, app));
    }
    if let Some(created) = headers.created.as_deref() {
        fields.push((header::CREATED, created));
    }
    request(method, path, &fields, body)
}

/// The fixed secret of a vectors' seed label, by the seed rule `spec/vectors/README.md`
/// states, read from there.
pub fn seed(label: &str) -> [u8; 32] {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/README.md");
    let readme = std::fs::read_to_string(&path).expect("README");
    let rule = readme
        .lines()
        .find(|line| line.starts_with("- **Seeds.** "))
        .expect("the README has a Seeds rule");
    let (_, formula) = rule
        .split_once("BLAKE3(\"")
        .expect("BLAKE3 in the Seeds rule");
    let (prefix, _) = formula.split_once('"').expect("the seed prefix");
    *blake3::hash(format!("{prefix}{label}").as_bytes()).as_bytes()
}

/// The signed operations of `chain.json`'s items at `seqs`.
pub fn ops_at(chain: &Value, seqs: &[u64]) -> Vec<SignedOp> {
    seqs.iter()
        .map(|seq| {
            let item = chain_item(chain, *seq);
            let signed: SignedDoc = serde_json::from_value(item["item"].clone()).expect("op");
            SignedOp::peek(&signed).expect("op")
        })
        .collect()
}

pub fn chain_item(chain: &Value, seq: u64) -> &Value {
    chain["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["seq"].as_u64() == Some(seq))
        .unwrap_or_else(|| panic!("no item {seq}"))
}

/// The transition proof `chain.json` gives the item at `seq`.
pub fn proof_at(chain: &Value, seq: u64) -> SignedDoc {
    let prefix = format!("(seq {seq})");
    let proof = chain["transition_proofs"]
        .as_array()
        .expect("proofs")
        .iter()
        .find(|proof| proof["name"].as_str().is_some_and(|n| n.contains(&prefix)))
        .unwrap_or_else(|| panic!("no proof for seq {seq}"));
    serde_json::from_value(proof["signed"].clone()).expect("proof")
}

/// Send the batch of the items at `seqs` from the wallet at the first item's time, and check
/// its answer: one proof per item, `chain.json`'s, and the head at the last item.
pub async fn replay_batch(replay: &Replay, chain: &Value, seqs: &[u64]) {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    let at = item_time(chain_item(chain, seqs[0]));
    set_time(&replay.clock, &at);
    let body = OpsRequest::new(&ops_at(chain, seqs), None).to_json();
    let request = app_request(
        wallet,
        "POST",
        &format!("/v1/{alice_id}/ops"),
        body,
        ms(&at),
    );
    let answer = replay.service.handle(request).await;
    let text = String::from_utf8_lossy(&answer.body).into_owned();
    assert_eq!(answer.status, 200, "seqs {seqs:?}: {text}");
    let body: Value = serde_json::from_slice(&answer.body).expect("json");
    let proofs: Vec<SignedDoc> = serde_json::from_value(body["proofs"].clone()).expect("proofs");
    let expected: Vec<SignedDoc> = seqs.iter().map(|seq| proof_at(chain, *seq)).collect();
    assert_eq!(proofs, expected, "seqs {seqs:?}: the proofs");
    let last = chain_item(chain, *seqs.last().expect("seq"));
    assert_eq!(
        body["head"]["seq"], last["seq"],
        "seqs {seqs:?}: the head's seq"
    );
    assert_eq!(
        body["head"]["chain_hash"], last["chain_hash"],
        "seqs {seqs:?}: the head's chain hash"
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
}

/// `chain.json` through the revoke at seq 9 (Dispatch wire 7.4.12): alice served, the
/// wallet's registration batch (seqs 3 and 4), the inbox entry's seq 5, the record's create
/// (seq 6), the batch of the attempt and the record's update (seqs 7 and 8), and the
/// signer's revoke of the phone.
pub async fn replay_chain_through_revoke(replay: &Replay) {
    let chain = vectors("chain.json");
    let keys = vectors("keys.json");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    serve_alice(replay).await;
    replay_batch(replay, &chain, &[3, 4]).await;
    assert_eq!(replay.db.give_out_seq(&alice_id).await.expect("seq"), 5);
    replay_batch(replay, &chain, &[6]).await;
    replay_batch(replay, &chain, &[7, 8]).await;
    let at = item_time(chain_item(&chain, 9));
    set_time(&replay.clock, &at);
    let phone = app(&keys, "phone")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let path = format!("/v1/{alice_id}/apps/{phone}/revoke");
    let answer = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), ms(&at)))
        .await;
    assert_eq!(answer.status, 200, "revoked");
}

/// The public key of `replay`'s service key, which signs every answer (Dispatch wire 7.1).
pub fn service_public(replay: &Replay) -> [u8; 32] {
    use pubky_dispatch_core::signing::Signs;
    replay.keys.current().public_key()
}

/// Refuse the insertion of a new service item in this replay's database.
pub async fn refuse_service_items(replay: &Replay, refuse: bool) {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connection");
    let statement = if refuse {
        "ALTER TABLE chain_items ADD CONSTRAINT refuse_service_items \
         CHECK (item_type <> 'service') NOT VALID"
    } else {
        "ALTER TABLE chain_items DROP CONSTRAINT refuse_service_items"
    };
    sqlx::query(statement)
        .execute(&mut conn)
        .await
        .expect("constraint");
}

/// Alice's current chain tip and last allocated sequence, which also counts inbox entries.
pub async fn chain_position(replay: &Replay) -> (pubky_dispatch_core::chain::ChainTip, u64) {
    let keys = vectors("keys.json");
    let id = alice(&keys)["pubky_id"].as_str().expect("identity");
    let account = replay
        .db
        .store()
        .begin(id)
        .await
        .expect("lock")
        .expect("account");
    (account.head().chain_tip(), account.head().last_seq)
}

/// Compare the stored signed item, envelope and hash with the exact bytes the wire requires.
pub async fn assert_service_item(
    replay: &Replay,
    previous: pubky_dispatch_core::chain::ChainTip,
    seq: u64,
    at: u64,
    transition: &pubky_dispatch_core::chain::ServiceTransition,
) -> pubky_dispatch_core::chain::Stub {
    use pubky_dispatch_core::chain::{ItemType, item_hash};
    use sqlx::Connection;
    let keys = vectors("keys.json");
    let identity = alice(&keys);
    let bytes = transition
        .sign(&replay.keys.current(), &hex32(&identity["public_hex"]))
        .expect("sign")
        .doc_bytes()
        .expect("carrying bytes");
    let (expected, _) = previous
        .append(
            seq,
            at,
            ItemType::Service,
            item_hash(ItemType::Service, &bytes),
            None,
        )
        .expect("append");
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("connection");
    let (stored, envelope, hash): (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT item_bytes, envelope, chain_hash FROM chain_items \
         WHERE account_id = $1 AND generation = $2 AND seq = $3 AND server_time_ms = $4 \
         AND item_type = 'service' AND only_for IS NULL AND proof IS NULL",
    )
    .bind(identity["pubky_id"].as_str().expect("identity"))
    .bind(i64::try_from(previous.generation).expect("generation"))
    .bind(i64::try_from(seq).expect("seq"))
    .bind(i64::try_from(at).expect("time"))
    .fetch_one(&mut conn)
    .await
    .expect("service item");
    assert_eq!(stored, bytes);
    assert_eq!(envelope, expected.envelope);
    assert_eq!(hash, expected.chain_hash);
    expected
}

/// The count of changed commits of `id`'s account, as the database holds it (Dispatch wire
/// 7.3, "The state").
pub async fn state_version_of(replay: &Replay, id: &str) -> u64 {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let count: i64 = sqlx::query_scalar("SELECT state_version FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&mut conn)
        .await
        .expect("count");
    conn.close().await.expect("close");
    u64::try_from(count).expect("count")
}

/// The tag of `id`'s account's count, as the database holds it (Dispatch wire 7.3, "The
/// state").
pub async fn state_tag_of(replay: &Replay, id: &str) -> [u8; 16] {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let tag: Vec<u8> = sqlx::query_scalar("SELECT state_tag FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&mut conn)
        .await
        .expect("tag");
    conn.close().await.expect("close");
    tag.try_into().expect("16 bytes")
}

/// Run the statements of `sql` on one connection that may write an account's state
/// directly, as a restore does: its triggers and foreign keys off for the session.
async fn restore_sql(replay: &Replay, sql: &str) {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::raw_sql(&format!(
        "SET session_replication_role = replica; {sql}; SET session_replication_role = origin"
    ))
    .execute(&mut conn)
    .await
    .expect("restore");
    conn.close().await.expect("close");
}

/// The tables of the test database that hold an account's rows, `accounts` first.
const IMAGE_TABLES: &str = "SELECT 'accounts' UNION ALL (SELECT table_name::text \
     FROM information_schema.columns WHERE table_schema = current_schema() \
     AND column_name = 'account_id' ORDER BY 1)";

/// A backup of `id`'s account taken now, under `name`: every row of every table that holds
/// the account's state, as a database backup holds it.
pub async fn save_image(replay: &Replay, id: &str, name: &str) {
    restore_sql(
        replay,
        &format!(
            "CREATE SCHEMA image_{name}; \
             DO $$ DECLARE t TEXT; s TEXT := current_schema(); BEGIN \
             FOR t IN {IMAGE_TABLES} LOOP \
             EXECUTE format('CREATE TABLE image_{name}.%I AS SELECT * FROM %I.%I WHERE %I = %L', \
             t, s, t, CASE WHEN t = 'accounts' THEN 'id' ELSE 'account_id' END, '{id}'); \
             END LOOP; END $$"
        ),
    )
    .await;
}

/// Restore the backup `name` of `id`'s account ([`save_image`]): every row of the account
/// goes back to what it held then, as a database restore leaves it, with the service's own
/// rules off; the mark store, apart from the state, stays.
pub async fn restore_image(replay: &Replay, id: &str, name: &str) {
    restore_sql(
        replay,
        &format!(
            "DO $$ DECLARE t TEXT; s TEXT := current_schema(); k TEXT; c TEXT; BEGIN \
             FOR t IN {IMAGE_TABLES} LOOP \
             k := CASE WHEN t = 'accounts' THEN 'id' ELSE 'account_id' END; \
             SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position) \
             INTO c FROM information_schema.columns WHERE table_schema = s \
             AND table_name = t AND is_generated = 'NEVER'; \
             EXECUTE format('DELETE FROM %I.%I WHERE %I = %L', s, t, k, '{id}'); \
             EXECUTE format('INSERT INTO %I.%I (%s) OVERRIDING SYSTEM VALUE \
             SELECT %s FROM image_{name}.%I', s, t, c, c, t); \
             END LOOP; END $$"
        ),
    )
    .await;
}

/// The move of `id`'s mark in `marks` to `head`, the count it holds kept: a head moved
/// ahead of the state, or to it, by the head alone (Dispatch wire 7.3, "The mark").
pub async fn keeping_count(
    marks: &pubky_dispatch::marks::MarkStore,
    id: &str,
    head: pubky_dispatch_core::chain::ChainTip,
) -> pubky_dispatch::marks::MarkTarget {
    let (state_version, state_tag) = match marks.read(id).await.expect("read") {
        pubky_dispatch::marks::MarkRead::Mark(mark) => (mark.state_version, mark.state_tag),
        _ => (0, [0; 16]),
    };
    pubky_dispatch::marks::MarkTarget {
        head,
        state_version,
        state_tag,
        stamped_ms: 0,
    }
}

/// The move of a mark to `head` with count 0, at or below every state's, stamped at time 0
/// (Dispatch wire 7.3, "The mark").
pub fn at_head(head: pubky_dispatch_core::chain::ChainTip) -> pubky_dispatch::marks::MarkTarget {
    pubky_dispatch::marks::MarkTarget {
        head,
        state_version: 0,
        state_tag: [0; 16],
        stamped_ms: 0,
    }
}

/// The creation time of the mark `replay` holds for `id`, which a test's own move of the
/// mark names (`MarkStore::advance`).
pub async fn mark_created_at(replay: &Replay, id: &str) -> u64 {
    match replay.marks.read(id).await.expect("read the mark") {
        pubky_dispatch::marks::MarkRead::Mark(mark) => mark.created_at_ms,
        other => panic!("no mark to move: {other:?}"),
    }
}

/// Wake requests waiting on an account's changes, as the service's listener does, until
/// the returned sender is used or dropped.
pub async fn listen(
    replay: &Replay,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = pubky_dispatch::changes::ChangeListener::connect(replay.db.store())
        .await
        .expect("listen");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(listener.run(replay.service.changes(), async {
        let _ = stopped.await;
    }));
    (stop, task)
}

/// The App ID of the vectors' app `name`.
pub fn app_id_of(name: &str) -> [u8; 16] {
    let keys = vectors("keys.json");
    pubky_dispatch_core::enc::app_id_decode(app(&keys, name)["app_id"].as_str().expect("id"))
        .expect("app id")
}

/// The wallet's attempt that `chain.json` opens at seq 7: its claim key and attempt ID. Its
/// claim is at step 1.
pub fn wallet_attempt() -> ([u8; 32], [u8; 16]) {
    let chain = vectors("chain.json");
    let op = SignedOp::peek(
        &serde_json::from_value::<SignedDoc>(chain_item(&chain, 7)["item"].clone()).expect("op"),
    )
    .expect("op");
    let body: Value =
        serde_json::from_slice(&op.signed().body_bytes().expect("body")).expect("json");
    let claim_key = unb64(body["claim_key"].as_str().expect("claim key")).expect("b64");
    let attempt_id = unb64(body["attempt_id"].as_str().expect("attempt id")).expect("b64");
    (
        claim_key.try_into().expect("32"),
        attempt_id.try_into().expect("16"),
    )
}

/// A claim entry on the wallet's attempt (`chain.json` seq 7), at `step`.
pub fn on_wallet_attempt(
    kind: pubky_dispatch_core::claims::ClaimType,
    step: u64,
    basis: Option<pubky_dispatch_core::claims::Basis>,
) -> pubky_dispatch_core::ops::OpKind {
    let (claim_key, attempt_id) = wallet_attempt();
    pubky_dispatch_core::ops::OpKind::Claim(pubky_dispatch_core::claims::ClaimFields {
        claim_key: claim_key.to_vec(),
        kind,
        expected_step: step,
        attempt_id: attempt_id.to_vec(),
        orphan_after: None,
        deadline: None,
        evidence_ref: basis
            .filter(|basis| *basis == pubky_dispatch_core::claims::Basis::Evidence)
            .map(|_| vec![5; 32]),
        basis,
    })
}

/// The vectors' app `name` sends a batch of `ops` with ID `[batch; 16]` at `at_ms`.
pub async fn app_batch(
    replay: &Replay,
    name: &str,
    batch: u8,
    ops: Vec<pubky_dispatch_core::ops::OpKind>,
    at_ms: u64,
) -> DispatchResponse {
    let keys = vectors("keys.json");
    let writer = app(&keys, name);
    let signed = pubky_dispatch_core::ops::sign_batch(
        &pubky_dispatch_core::keys::AppKeys::from_secrets(
            hex32(&writer["signing_secret_hex"]),
            hex32(&writer["bundle_secret_hex"]),
        ),
        &hex32(&alice(&keys)["public_hex"]),
        Some(app_id_of(name)),
        1,
        [batch; 16],
        ops.into_iter().map(|op| (Vec::new(), op)).collect(),
    )
    .expect("batch");
    let path = format!("/v1/{}/ops", alice(&keys)["pubky_id"].as_str().expect("id"));
    replay
        .service
        .handle(app_request(
            writer,
            "POST",
            &path,
            OpsRequest::new(&signed, None).to_json(),
            at_ms,
        ))
        .await
}

/// alice's version after `prev`, by `change`, delivered by her signer at `at_ms`: the new
/// document, once the service took it.
pub async fn deliver_next(
    replay: &Replay,
    prev: &SignedDoc,
    at_ms: u64,
    change: impl FnOnce(&mut pubky_dispatch_core::records::IdentityBody),
) -> SignedDoc {
    let keys = vectors("keys.json");
    let mut next: pubky_dispatch_core::records::IdentityBody =
        serde_json::from_slice(&prev.body_bytes().expect("body")).expect("identity body");
    next.version += 1;
    change(&mut next);
    let key =
        pubky_dispatch_core::keys::IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let doc = pubky_dispatch_core::records::IdentityDoc::sign(&key, next)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_dispatch_core::http::IdentityDelivery {
        identity: doc.clone(),
        prev: Some(prev.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!(
        "/v1/{}/identity",
        alice(&keys)["pubky_id"].as_str().expect("id")
    );
    let answer = replay
        .service
        .handle(signer_request("PUT", &path, delivery, at_ms))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    doc
}

/// alice's version 3, the newest `chain.json` delivers.
pub fn alice_version_3() -> SignedDoc {
    serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("document")
}

/// The vectors' chain through the phone's revocation, then the wallet's attempt failed by
/// the wallet, the wallet revoked, moved to `removed` at a higher data epoch, and purged
/// from it (Dispatch wire 9.1): the newest document, which lists it in neither list, and the
/// time of it all.
pub async fn purge_wallet(replay: &Replay) -> (SignedDoc, u64) {
    let at = revoke_wallet(replay).await;
    let wallet = app_id_of("wallet");
    let removing = deliver_next(replay, &alice_version_3(), at, |body| {
        body.apps.retain(|listed| listed.app_id != wallet);
        body.removed.push(pubky_dispatch_core::records::RemovedApp {
            app_id: wallet,
            distrust_from: at,
        });
        body.data_epoch += 1;
    })
    .await;
    let purging = deliver_next(replay, &removing, at, |body| {
        body.removed.retain(|removed| removed.app_id != wallet);
    })
    .await;
    (purging, at)
}

/// The vectors' chain through the phone's revocation, then the wallet's attempt failed by
/// the wallet and the wallet revoked, still listed in `apps`: the time of it all.
pub async fn revoke_wallet(replay: &Replay) -> u64 {
    use pubky_dispatch_core::claims::ClaimType;
    replay_chain_through_revoke(replay).await;
    let at = ms(&item_time(chain_item(&vectors("chain.json"), 9)));
    let failed = app_batch(
        replay,
        "wallet",
        90,
        vec![on_wallet_attempt(ClaimType::Failed, 1, None)],
        at,
    )
    .await;
    assert_eq!(
        failed.status,
        200,
        "{}",
        String::from_utf8_lossy(&failed.body)
    );
    let keys = vectors("keys.json");
    let path = format!(
        "/v1/{}/apps/{}/revoke",
        alice(&keys)["pubky_id"].as_str().expect("id"),
        app(&keys, "wallet")["app_id"].as_str().expect("id"),
    );
    let revoked = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), at))
        .await;
    assert_eq!(
        revoked.status,
        200,
        "{}",
        String::from_utf8_lossy(&revoked.body)
    );
    at
}

/// How many rows `table` holds for alice's account whose `column` is `app`.
pub async fn rows_naming(replay: &Replay, table: &str, column: &str, app: &[u8; 16]) -> i64 {
    use sqlx::Connection;
    let keys = vectors("keys.json");
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let count: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {table} WHERE account_id = $1 AND {column} = $2"
    ))
    .bind(alice(&keys)["pubky_id"].as_str().expect("id"))
    .bind(app.as_slice())
    .fetch_one(&mut conn)
    .await
    .expect("count");
    conn.close().await.expect("close");
    count
}

/// Log, in a table of the test database outside every account, each invite code the
/// minute's sweep deletes (its statement, not an erasure's cascade or a recovery's clear),
/// so a test can tell that a sweep ran.
pub async fn log_swept_invite_codes(replay: &Replay) {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for statement in [
        "CREATE TABLE swept_codes (statement TEXT NOT NULL)",
        "CREATE FUNCTION log_swept_code() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
         IF current_query() LIKE '%code_hash IN%' THEN \
         INSERT INTO swept_codes VALUES (current_query()); END IF; RETURN OLD; END $$",
        "CREATE TRIGGER log_swept_code AFTER DELETE ON invite_codes \
         FOR EACH ROW EXECUTE FUNCTION log_swept_code()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("log");
    }
    conn.close().await.expect("close");
}

/// How many invite codes the minute's sweep deleted since [`log_swept_invite_codes`].
pub async fn swept_invite_codes(replay: &Replay) -> i64 {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let count = sqlx::query_scalar("SELECT count(*) FROM swept_codes")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    conn.close().await.expect("close");
    count
}

/// What the service holds of `app` that a purge of a removed app deletes (Dispatch wire 9.1):
/// its record, receive key records, key bundle parts and listing. Its kids stay
/// ([`rows_naming`] on `receive_keys`).
pub async fn holdings(replay: &Replay, app: &[u8; 16]) -> [i64; 4] {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let records: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM receive_keys WHERE account_id = $1 AND app_id = $2 \
         AND record IS NOT NULL",
    )
    .bind(
        alice(&vectors("keys.json"))["pubky_id"]
            .as_str()
            .expect("id"),
    )
    .bind(app.as_slice())
    .fetch_one(&mut conn)
    .await
    .expect("count");
    conn.close().await.expect("close");
    [
        rows_naming(replay, "apps", "app_id", app).await,
        records,
        rows_naming(replay, "key_bundle_parts", "target_app_id", app).await,
        rows_naming(replay, "app_listings", "app_id", app).await,
    ]
}

/// The signer's `GET /apps` status of the vectors' app `name`.
pub async fn app_status(replay: &Replay, name: &str, at_ms: u64) -> Value {
    let keys = vectors("keys.json");
    let path = format!(
        "/v1/{}/apps",
        alice(&keys)["pubky_id"].as_str().expect("id")
    );
    let answer = replay
        .service
        .handle(signer_request("GET", &path, Vec::new(), at_ms))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let id = pubky_dispatch_core::enc::zbase32_encode(&app_id_of(name));
    let body: Value = serde_json::from_slice(&answer.body).expect("json");
    body["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|status| status["app_id"] == id.as_str())
        .unwrap_or_else(|| panic!("no status for {name}"))
        .clone()
}

/// Whether account `account`'s chain item at `seq` keeps its document, and its proof
/// (Dispatch wire 7.5).
pub async fn chain_document_kept(replay: &Replay, account: &str, seq: u64) -> (bool, bool) {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let kept: (bool, bool) = sqlx::query_as(
        "SELECT item_bytes IS NOT NULL, proof IS NOT NULL FROM chain_items \
         WHERE account_id = $1 AND seq = $2 \
         AND generation = (SELECT generation FROM accounts WHERE id = $1)",
    )
    .bind(account)
    .bind(i64::try_from(seq).expect("seq"))
    .fetch_one(&mut conn)
    .await
    .expect("chain item");
    conn.close().await.expect("close");
    kept
}

/// The documents and proofs account `account`'s chain items keep now, by `seq`, added to
/// `into` where it holds none for that `seq` yet.
pub async fn capture_documents(
    replay: &Replay,
    account: &str,
    into: &mut std::collections::BTreeMap<i64, (Vec<u8>, Option<Vec<u8>>)>,
) {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let rows: Vec<(i64, Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT seq, item_bytes, proof FROM chain_items WHERE account_id = $1 \
         AND item_bytes IS NOT NULL \
         AND generation = (SELECT generation FROM accounts WHERE id = $1)",
    )
    .bind(account)
    .fetch_all(&mut conn)
    .await
    .expect("documents");
    conn.close().await.expect("close");
    for (seq, item, proof) in rows {
        into.entry(seq).or_insert((item, proof));
    }
}

/// Put back the documents `from` holds into account `account`'s chain items that lost
/// theirs; the number put back.
pub async fn restore_documents(
    replay: &Replay,
    account: &str,
    from: &std::collections::BTreeMap<i64, (Vec<u8>, Option<Vec<u8>>)>,
) -> u64 {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let mut restored = 0;
    for (seq, (item, proof)) in from {
        restored += sqlx::query(
            "UPDATE chain_items SET item_bytes = $3, proof = $4 WHERE account_id = $1 \
             AND seq = $2 AND item_bytes IS NULL \
             AND generation = (SELECT generation FROM accounts WHERE id = $1)",
        )
        .bind(account)
        .bind(seq)
        .bind(item)
        .bind(proof)
        .execute(&mut conn)
        .await
        .expect("restore")
        .rows_affected();
    }
    conn.close().await.expect("close");
    restored
}

/// Run `sql` with `$1` bound to `account`; the rows it changed.
pub async fn sql_on(replay: &Replay, account: &str, sql: &str) -> u64 {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let changed = sqlx::query(sql)
        .bind(account)
        .execute(&mut conn)
        .await
        .expect("sql")
        .rows_affected();
    conn.close().await.expect("close");
    changed
}

// --- An account's creation time (Dispatch wire 3.7, 7.4.16) ---

/// The creation time of `account` that its enrollment answer names and an erasure names
/// again (Dispatch wire 3.7, 7.4.16): the mark's, as its file is now, or the account's own
/// where the mark is lost; `None` where there is neither.
pub async fn creation_time(replay: &Replay, account: &str) -> Option<u64> {
    let marked = pubky_dispatch::marks::MarkView::open(replay.key_dir())
        .ok()
        .and_then(|view| view.read(account).ok());
    if let Some(pubky_dispatch::marks::MarkRead::Mark(mark)) = marked {
        return Some(mark.created_at_ms);
    }
    replay
        .db
        .store()
        .lookup(account)
        .await
        .expect("lookup")
        .map(|found| found.created_at_ms)
}

/// The signer's erasure of `account` signed at `at_ms`, naming the account's creation time
/// as [`creation_time`] gives it and `identity_hash` (Dispatch wire 7.4.16).
pub async fn erasure_of(
    replay: &Replay,
    account: &str,
    identity_hash: Option<&[u8; 32]>,
    at_ms: u64,
) -> DispatchRequest {
    let created = creation_time(replay, account).await;
    signer_request_at_creation(
        "POST",
        &format!("/v1/{account}/erase"),
        wire_http::erase_body(created, identity_hash),
        at_ms,
        created,
    )
}
