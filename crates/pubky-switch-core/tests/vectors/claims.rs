//! `claims.json`: the 69-step script through every row of the claim rules, deadline pinning,
//! the reconciliation window, unchanged batches with and without `cursor.set`, and `app.put`
//! of the held record and of a record at its `updated_at`; then the per-app claim limits on
//! a switch of their own (Switch wire 6.2, 6.4, 6.8, 9.3).
//!
//! The script runs through the core's pure functions: every write is built and signed as its
//! app's operation, verified, checked for its writer's permission and its shape, and applied
//! with [`apply_entry`] to the claim held for its key; reads give the claim view; requests of
//! the script are built from the registration and the chosen condition and cursor, then checked by the no-op,
//! condition and `app.put` rules.
//!
//! What a pure core can't have is modelled here as the service would do it, and only that:
//! authentication (a revoked app gets `403 not_current` before anything is read, Switch wire
//! 7.2), the service clock the script advances, the store of claims by key, and the sweep of
//! Switch wire 7.3 step 4, which deletes what [`Claim::deletable`] says, by the time base.

use std::collections::{HashMap, HashSet};

use pubky_switch_core::admission::PeerReason;
use pubky_switch_core::claims::{
    Claim, ClaimLimits, ClaimTally, EntryContext, MAX_CLAIM_AGE_MS, apply_entry,
};
use pubky_switch_core::enc::{b64 as b64e, pubky_id};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::AppKeys as SigningApp;
use pubky_switch_core::ops::{
    BatchEffect, BatchRef, Condition, ConditionState, Held, KeyBundlePut, OpBody, OpKind,
    OpsRequest, Position, RecordVersion, Refusal, SignedOp, Writer, batch_effect, check_app_put,
    check_batch, check_conditions, check_permission, check_shape,
};
use pubky_switch_core::records::{
    AppCert, AppCertBody, AppRecord, AppRecordBody, ReceiveKeyBody, ReceiveKeyRecord,
};
use pubky_switch_core::scopes::{Permission, check_permissions};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::parse_rfc3339;
use serde_json::{Value, json};

use crate::common::*;

/// An app of the script, with its certificate and what it registered.
struct App {
    app_id: [u8; 16],
    key: SigningApp,
    cert: AppCert,
    record: AppRecord,
    receive_key: ReceiveKeyRecord,
}

/// What the switch answers: a body, or a refusal.
type Answer = Result<Value, Refusal>;

/// One switch of the script: the account's apps, the claims it holds by key, and its clock.
struct Switch {
    identity: [u8; 32],
    now: u64,
    apps: HashMap<String, App>,
    revoked: HashSet<[u8; 16]>,
    claims: HashMap<[u8; 32], Claim>,
    limits: ClaimLimits,
    cursors: HashMap<[u8; 16], String>,
    generation: u64,
}

impl Switch {
    fn new(v: &Value, keys: &ClaimKeys, limits: ClaimLimits) -> Self {
        let identity = keys.identity.public();
        generated_members(
            "claims.json",
            "",
            &[("identity", json!(keys.identity.id()))],
        );
        let mut apps = HashMap::new();
        for (name, a) in v["apps"].as_object().unwrap() {
            let (key, receive) = &keys.apps[name];
            let cert = AppCert::issue(
                &keys.identity,
                AppCertBody::new(
                    identity,
                    key.signing_public(),
                    key.bundle_public(),
                    strings(&a["scopes"]),
                    &check_permissions(&strings(&a["inbox_permissions"])).unwrap(),
                    time_of(a, "issued_at"),
                    time_of(a, "expires_at"),
                ),
            )
            .unwrap();
            let mut body =
                AppRecordBody::new(&cert, strings(&a["accepts"]), time_of(a, "updated_at"));
            body.protocols = serde_json::from_value(a["protocols"].clone()).unwrap();
            body.expires_at = match a.get("record_expires_at").expect("record expiry") {
                Value::Null => None,
                value => Some(parse_rfc3339(value.as_str().unwrap()).unwrap()),
            };
            let record = AppRecord::sign(key, body).unwrap();
            let receive_key =
                ReceiveKeyRecord::sign(key, &cert, ReceiveKeyBody::new(&cert, receive)).unwrap();
            generated_members(
                "claims.json",
                &format!("/apps/{name}"),
                &[
                    ("app_id", json!(key.app_id())),
                    ("cert", json!(cert.signed())),
                    ("registered_record", json!(record.signed())),
                    ("registered_receive_key", json!(receive_key.signed())),
                ],
            );
            assert_eq!(AppCert::verify(cert.signed(), &identity).unwrap(), cert);
            assert_eq!(
                AppRecord::verify(record.signed(), &identity).unwrap(),
                record
            );
            assert_eq!(
                ReceiveKeyRecord::verify(receive_key.signed(), &cert).unwrap(),
                receive_key
            );
            apps.insert(
                name.clone(),
                App {
                    app_id: key.app_id_bytes(),
                    key: key.clone(),
                    cert,
                    record,
                    receive_key,
                },
            );
        }
        Self {
            identity,
            now: time_of(v, "start_time"),
            apps,
            revoked: HashSet::new(),
            claims: HashMap::new(),
            limits,
            cursors: HashMap::new(),
            generation: int(v, "generation"),
        }
    }

    /// Current: neither revoked nor departed, with a certificate that hasn't expired. The
    /// script's `identity.json` lists every app with its certificate.
    fn is_current(&self, app_id: &[u8; 16]) -> bool {
        !self.revoked.contains(app_id)
            && self
                .apps
                .values()
                .any(|a| &a.app_id == app_id && !a.cert.expired_at(self.now))
    }

    /// The sweep of Switch wire 7.3 step 4, with trusted time: the script's clock is the
    /// time base.
    fn sweep(&mut self) {
        let now = self.now;
        self.claims
            .retain(|_, claim| !claim.deletable(Some(now), MAX_CLAIM_AGE_MS));
    }

    /// Authentication (Switch wire 7.2): an own app that isn't current is `403 not_current`.
    fn authenticate(&self, name: &str) -> Result<&App, Refusal> {
        let app = &self.apps[name];
        if !self.is_current(&app.app_id) {
            return Err(Refusal::new(ErrorCode::NotCurrent, "not current"));
        }
        Ok(app)
    }

    fn view(&self, claim_key: &[u8; 32]) -> Option<Value> {
        let current = |a: &[u8; 16]| self.is_current(a);
        self.claims
            .get(claim_key)
            .map(|c| c.view(claim_key, self.now, &current).to_value())
    }

    /// `GET /claims/{claim_key}` (Switch wire 7.4.8).
    fn read(&mut self, name: &str, claim_key: &[u8; 32]) -> Answer {
        self.sweep();
        let app = self.authenticate(name)?;
        if !app.cert.has_permission(Permission::ClaimsRead) {
            return Err(Refusal::new(ErrorCode::PermissionMissing, "claims.read"));
        }
        self.view(claim_key)
            .map(|claim| json!({ "claim": claim }))
            .ok_or_else(|| Refusal::new(ErrorCode::NotFound, "no such claim"))
    }

    /// A batch of one claim operation, signed by its app, verified, checked for its writer's
    /// permission and shape, and applied (Switch wire 6.4 steps 3, 4 and 9).
    fn write(&mut self, name: &str, signed: &SignedOp) -> Answer {
        self.sweep();
        let app = self.authenticate(name)?;
        let op = SignedOp::verify(
            signed.signed(),
            &app.key.signing_public(),
            &self.identity,
            Some(&app.app_id),
        )?;
        check_batch(std::slice::from_ref(&op))?;
        check_permission(&op.body().kind, Writer::App(&app.cert))?;
        check_shape(op.body())?;
        let OpKind::Claim(fields) = &op.body().kind else {
            panic!("a claim operation");
        };
        let entry = fields.check()?;
        let writer = app.app_id;
        let can_read = app.cert.has_permission(Permission::ClaimsRead);
        let tally = ClaimTally::count(self.claims.values(), &writer);
        let current = |a: &[u8; 16]| self.is_current(a);
        let cx = EntryContext {
            writer,
            now: self.now,
            can_read,
            is_current: &current,
            limits: self.limits,
            tally,
        };
        let next = apply_entry(self.claims.get(&entry.claim_key), &entry, &cx)?;
        self.claims.insert(entry.claim_key, next);
        Ok(json!({ "claim": self.view(&entry.claim_key) }))
    }

    /// A `POST /ops` body of the file (Switch wire 6.4): read, its operations verified and
    /// written again byte for byte, then decided by the no-op, condition and `app.put` rules.
    fn request(&mut self, name: &str, body: &str) -> Answer {
        self.sweep();
        let app = self.authenticate(name)?;
        let request = OpsRequest::parse(body.as_bytes())?;
        assert_eq!(
            request.to_json(),
            body.as_bytes(),
            "{name}: the request rebuilt"
        );
        let key = app.key.signing_public();
        let ops: Vec<SignedOp> = request
            .signed()
            .map(|d| SignedOp::verify(d, &key, &self.identity, Some(&app.app_id)))
            .collect::<Result<_, _>>()?;
        for op in &ops {
            assert_eq!(&SignedOp::sign(&app.key, op.body().clone()).unwrap(), op);
            assert_eq!(
                op.body().to_json().unwrap(),
                op.signed().body_bytes().unwrap()
            );
        }
        assert_eq!(
            OpsRequest::new(&ops, request.cursor()).to_json(),
            body.as_bytes()
        );
        check_batch(&ops)?;
        let cursor = request.cursor();
        match batch_effect(&ops, self, cursor.is_some()) {
            BatchEffect::NoOp => return Ok(json!({ "proofs": [] })),
            BatchEffect::Unchanged => {
                let state = State {
                    switch: self,
                    reader: name,
                };
                check_conditions(ops.iter().flat_map(|o| &o.body().conditions), &state)?;
                if let Some(position) = cursor {
                    let id = self.apps[name].app_id;
                    self.cursors.insert(id, position.to_string());
                }
                return Ok(json!({ "proofs": [] }));
            }
            BatchEffect::Apply { .. } => {}
        }
        let mut proofs = Vec::new();
        for op in &ops {
            let OpKind::AppPut { record } = &op.body().kind else {
                panic!("{name}: only app.put batches change something here");
            };
            let record = AppRecord::verify(record, &self.identity)?;
            let app = &self.apps[name];
            check_app_put(
                &app.app_id,
                &record,
                Some(app.cert.hash()),
                Some(&app.record),
            )?;
            proofs.push(Value::Null);
        }
        Ok(json!({ "proofs": proofs }))
    }
}

impl Held for Switch {
    fn app_record(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        let app = self.apps.values().find(|a| &a.app_id == app_id)?;
        Some(app.record.signed().clone())
    }
    fn receive_key(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        let app = self.apps.values().find(|a| &a.app_id == app_id)?;
        Some(app.receive_key.signed().clone())
    }
    fn renewed_cert(&self, _: &[u8; 16]) -> Option<SignedDoc> {
        None
    }
    fn record_cert(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        let app = self.apps.values().find(|a| &a.app_id == app_id)?;
        Some(app.cert.signed().clone())
    }
    fn holds_bundle_part(&self, _: &KeyBundlePut) -> bool {
        false
    }
    fn record_live(&self, _: &[u8; 32]) -> bool {
        false
    }
    fn allowed(&self, _: &[u8; 32], _: PeerReason) -> bool {
        false
    }
    fn denied(&self, _: &[u8; 32]) -> bool {
        false
    }
}

/// The state before a batch, as its caller may read it (Switch wire 6.3, 7.6). The script's
/// switch holds no shared records.
struct State<'a> {
    switch: &'a Switch,
    reader: &'a str,
}

impl ConditionState for State<'_> {
    fn record_current(&self, _: &[u8; 32]) -> Option<pubky_switch_core::shared::CurrentRecord> {
        None
    }
    fn record_view(&self, _: &[u8; 32]) -> Option<Value> {
        None
    }

    fn record_version(&self, _: &[u8; 32]) -> RecordVersion {
        RecordVersion::NONE
    }
    fn may_read_record(&self, _: &[u8; 32]) -> bool {
        true
    }
    fn claim_step(&self, claim_key: &[u8; 32]) -> u64 {
        self.switch.claims.get(claim_key).map_or(0, |c| c.step)
    }
    fn claim_view(&self, claim_key: &[u8; 32]) -> Option<Value> {
        self.switch.view(claim_key)
    }
    fn may_read_claims(&self) -> bool {
        self.switch.apps[self.reader]
            .cert
            .has_permission(Permission::ClaimsRead)
    }
    fn server_time(&self) -> u64 {
        self.switch.now
    }
}

/// Emit the expected wire members and use the same values for the replay comparison.
fn expected_members(view: &mut Value, path: &str, members: &[(&str, Value)]) {
    generated_members("claims.json", path, members);
    for (member, value) in members {
        view[*member] = value.clone();
    }
}

/// Copy only the pinned parts of a view. The names beside an attempt select its wire IDs.
fn pinned(input: &Value, fields: &[&str]) -> Value {
    Value::Object(
        fields
            .iter()
            .filter_map(|&field| {
                input
                    .get(field)
                    .map(|value| (field.to_owned(), value.clone()))
            })
            .collect(),
    )
}

fn expected_claim(
    input: &Value,
    path: &str,
    switch: &Switch,
    attempts: &Value,
    key: &Value,
) -> Value {
    let mut view = pinned(
        input,
        &[
            "deadline",
            "divergent",
            "next_possibly_duplicate",
            "state",
            "step",
            "tombstone",
        ],
    );
    expected_members(&mut view, path, &[("claim_key", key.clone())]);
    let mut history = Vec::new();
    for (i, row) in arr(input, "attempts").iter().enumerate() {
        let mut entry = pinned(
            row,
            &[
                "duplicate",
                "opened_at",
                "orphan_after",
                "orphaned",
                "outcome",
                "possibly_duplicate",
            ],
        );
        let id = json!(st(attempts, st(row, "attempt")));
        let owner = json!(switch.apps[st(row, "owner_app")].key.app_id());
        let identity = [("attempt_id", id), ("owner", owner)];
        if st(row, "outcome") == "open" {
            expected_members(&mut view, path, &identity);
        }
        let at = format!("{path}/attempts/{i}");
        expected_members(&mut entry, &at, &identity);
        if let Some(app) = row.get("resolved_by_app") {
            let resolver = &switch.apps[app.as_str().unwrap()].key;
            expected_members(
                &mut entry,
                &at,
                &[("resolved_by", json!(resolver.app_id()))],
            );
        }
        history.push(entry);
    }
    view["attempts"] = Value::Array(history);
    view
}

/// Compare the whole answer, including absent members, with an independently built expectation.
fn expect(
    step: &Value,
    path: &str,
    switch: &Switch,
    attempts: &Value,
    keys: &Value,
    answer: &Answer,
) {
    let input = &step["expect"];
    let mut expected = pinned(input, &["status", "code", "proofs"]);
    if let Some(claim) = input.get("claim") {
        expected["claim"] = expected_claim(
            claim,
            &format!("{path}/claim"),
            switch,
            attempts,
            &keys[st(step, "claim_key")],
        );
    }
    if let Some(current) = input.get("current") {
        expected["current"] = if current.is_null() {
            Value::Null
        } else {
            pinned(current, &["limit", "server_time"])
        };
        let view = &mut expected["current"];
        let at = format!("{path}/current");
        if let Some(claim) = current.get("claim") {
            view["claim"] = if claim.is_null() {
                Value::Null
            } else {
                expected_claim(
                    claim,
                    &format!("{at}/claim"),
                    switch,
                    attempts,
                    &keys[st(step, "claim_key")],
                )
            };
        }
        if let Some(condition) = current.get("claim_step") {
            view["claim_step"] = pinned(condition, &["step"]);
            expected_members(
                &mut view["claim_step"],
                &format!("{at}/claim_step"),
                &[("claim_key", keys[st(step, "condition_claim")].clone())],
            );
        }
        if step["variant"] == "equal_time" {
            let record = switch.apps[st(step, "app")].record.signed();
            expected_members(view, &at, &[("record", json!(record))]);
        }
    }
    let actual = match answer {
        Ok(body) => {
            let mut outcome = body.clone();
            outcome["status"] = json!(200);
            if let Some(proofs) = body.get("proofs") {
                outcome["proofs"] = json!(proofs.as_array().unwrap().len());
            }
            outcome
        }
        Err(refused) => json!({
            "status": refused.status(),
            "code": refused.code.as_str(),
            "current": refused.current,
        }),
    };
    assert_eq!(actual, expected, "{path}");
}

/// Derive the attempt IDs or evidence references named by this script.
fn named_bytes<const N: usize>(inputs: &Value, path: &str) -> Value {
    let mut values = json!({});
    for (name, label) in inputs.as_object().unwrap() {
        let value = b64e(&seed(label.as_str().unwrap())[..N]);
        generated_members("claims.json", path, &[(name, json!(value))]);
        values[name] = value.into();
    }
    values
}

/// Build and sign a single claim operation, including the deliberately malformed entries.
fn claim_op(
    switch: &Switch,
    step: &Value,
    key: &[u8; 32],
    attempts: &Value,
    evidence: &Value,
    start: u64,
) -> (SignedOp, Value) {
    let app = &switch.apps[st(step, "app")];
    let entry = &step["entry"];
    let mut fields = json!({
        "attempt_id": st(attempts, st(entry, "attempt")),
        "claim_key": b64e(key),
        "type": st(entry, "type"),
        "expected_step": int(entry, "expected_step"),
    });
    for field in ["orphan_after", "basis"] {
        if let Some(value) = entry.get(field) {
            fields[field] = value.clone();
        }
    }
    if let Some(seconds) = entry.get("deadline_after_s") {
        fields["deadline"] =
            pubky_switch_core::time::rfc3339(start + seconds.as_u64().unwrap() * 1000).into();
    }
    if let Some(name) = entry.get("evidence") {
        fields["evidence_ref"] = st(evidence, name.as_str().unwrap()).into();
    }
    // Only the claim fields are published for a write. Its script step uniquely identifies
    // the one-operation batch for replay.
    let mut body = json!({
        "identity": pubky_id(&switch.identity),
        "app_id": app.key.app_id(),
        "generation": switch.generation,
        "batch": {
            "id": b64e(&u128::from(int(step, "n")).to_be_bytes()),
            "count": 1,
        },
        "op": "claim",
    });
    body.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    let parsed = OpBody::parse(&serde_json::to_vec(&body).unwrap()).unwrap();
    let signed = SignedOp::sign(&app.key, parsed).unwrap();
    let mut wire: Value = signed.signed().peek().unwrap();
    let members = wire.as_object_mut().unwrap();
    for common in ["identity", "app_id", "generation", "batch", "op"] {
        members.remove(common).expect(common);
    }
    (signed, wire)
}

/// Run a script's steps on a switch.
fn run(script: &Value, switch: &mut Switch, path: &str, evidence: &Value) -> HashSet<String> {
    let start = switch.now;
    let mut actions = HashSet::new();
    let attempts = named_bytes::<16>(&script["attempt_seed_labels"], &format!("{path}/attempts"));
    for (i, step) in arr(script, "steps").iter().enumerate() {
        let base = format!("{path}/steps/{i}");
        let n = int(step, "n");
        let action = st(step, "action");
        actions.insert(action.to_owned());
        let label = format!("step {n} ({action})");
        let key = |s: &Value| b64n::<32>(st(&script["claim_keys"], st(s, "claim_key")));
        let answer = match action {
            "write" => {
                let (signed, fields) =
                    claim_op(switch, step, &key(step), &attempts, evidence, start);
                generated_members("claims.json", &base, &[("op", fields)]);
                switch.write(st(step, "app"), &signed)
            }
            "read" => switch.read(st(step, "app"), &key(step)),
            "advance" => {
                assert!(
                    step.get("expect").is_none(),
                    "{label} only advances the clock"
                );
                switch.now += int(step, "seconds") * 1000;
                continue;
            }
            "revoke" => {
                let id = switch.apps[st(step, "app")].app_id;
                switch.revoked.insert(id);
                Ok(json!({}))
            }
            "noop_batch" | "app_put" => {
                let request = app_request(switch, step, &base, &script["claim_keys"]);
                generated_members("claims.json", &base, &[("request_body", json!(request))]);
                switch.request(st(step, "app"), &request)
            }
            other => panic!("{label}: action {other}"),
        };
        expect(
            step,
            &format!("{base}/expect"),
            switch,
            &attempts,
            &script["claim_keys"],
            &answer,
        );
    }
    actions
}

/// Sign the caller's record and any condition and cursor chosen for this batch.
fn app_request(switch: &Switch, step: &Value, base: &str, claim_keys: &Value) -> String {
    let app = &switch.apps[st(step, "app")];
    let mut conditions = Vec::new();
    let mut cursor = None;
    let mut record = app.record.clone();
    match st(step, "action") {
        "noop_batch" => {
            let condition = step.get("condition_step").expect("condition choice");
            assert_eq!(step.get("condition_claim").is_some(), !condition.is_null());
            if !condition.is_null() {
                conditions.push(Condition::ClaimStep {
                    claim_key: b64n(st(claim_keys, st(step, "condition_claim"))),
                    step: condition.as_u64().unwrap(),
                });
            }
            let move_cursor = step["cursor"].as_bool().unwrap();
            assert_eq!(step.get("cursor_position").is_some(), move_cursor);
            if move_cursor {
                cursor = Some(Position::parse(st(step, "cursor_position")).unwrap());
            }
        }
        "app_put" => {
            match st(step, "variant") {
                "held" => {}
                "equal_time" => {
                    let mut body = record.body().clone();
                    body.protocols = serde_json::from_value(step["protocols"].clone()).unwrap();
                    record = AppRecord::sign(&app.key, body).unwrap();
                    assert_eq!(record.updated_at(), app.record.updated_at());
                    assert_ne!(record.signed().body, app.record.signed().body);
                }
                other => panic!("unknown app.put variant {other}"),
            }
            generated_members("claims.json", base, &[("record", json!(record.signed()))]);
        }
        action => panic!("unknown batch action {action}"),
    }
    let op = SignedOp::sign(
        &app.key,
        OpBody {
            identity: switch.identity,
            app_id: Some(app.app_id),
            generation: switch.generation,
            batch: BatchRef {
                id: seed16(step, "batch_seed_label"),
                count: 1,
            },
            conditions,
            kind: OpKind::AppPut {
                record: record.signed().clone(),
            },
        },
    )
    .unwrap();
    String::from_utf8(OpsRequest::new(&[op], cursor).to_json()).unwrap()
}

#[test]
pub(super) fn test_vectors_claims() {
    let v = load("claims.json");
    super::generation::check_annotations("claims.json", &v);
    let keys = keys();
    let steps = arr(&v, "steps");
    assert_eq!(steps.len(), 69);
    let evidence = named_bytes::<32>(&v["evidence_seed_labels"], "/evidence_refs");
    let mut switch = Switch::new(&v, &keys.claims, ClaimLimits::default());
    let actions = run(&v, &mut switch, "", &evidence);
    for action in [
        "write",
        "read",
        "advance",
        "revoke",
        "noop_batch",
        "app_put",
    ] {
        assert!(actions.contains(action), "the script has {action} steps");
    }
    // Step 61 moved A's cursor; step 60, refused, didn't before it.
    assert_eq!(switch.cursors.len(), 1);
    // Every row of the claim rules was refused or applied along the way.
    let rows: HashSet<&str> = steps.iter().filter_map(|s| s["row"].as_str()).collect();
    for row in ["1", "2", "3", "4", "5", "6", "7"] {
        assert!(rows.contains(row), "row {row}");
    }

    // The per-app limits, on a switch of their own (Switch wire 6.8, 9.3).
    let q = &v["quota"];
    let limits = ClaimLimits {
        max_claims: int(&q["limits"], "max_claims"),
        open_attempts_per_app: int(&q["limits"], "open_attempts_per_app"),
        claim_share_percent: int(&q["limits"], "claim_share_percent"),
        ..ClaimLimits::default()
    };
    assert_eq!(limits.claim_share(), 3);
    let mut quota = Switch::new(&v, &keys.claims, limits);
    let refused = run(q, &mut quota, "/quota", &evidence);
    assert_eq!(refused, HashSet::from(["write".to_owned()]));
    let limit_answers: Vec<&Value> = arr(q, "steps")
        .iter()
        .filter_map(|s| s["expect"]["current"].get("limit"))
        .collect();
    assert_eq!(
        limit_answers,
        [&json!("open_attempts"), &json!("claim_share")]
    );
}
