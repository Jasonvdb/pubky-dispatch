//! Public record lineage metadata encodings and authentication (Switch wire 6.9).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use pubky_switch_core::{
    Error, SizeRefusal,
    chain::{ChainTip, SignedHead},
    enc::b64,
    json::MAX_INT,
    keys::IdentityKey,
    record_authority::{
        ApplicationRef, CurrentApplication, DeletionCapsule, Incarnation, LineageDescriptor,
        LineageDescriptorBody, LineageStatement, LineageStatementBody, MAX_DELETION_CAPSULES,
        MAX_LINEAGE_NODES, MAX_PROTECTED_DESCRIPTOR_BYTES, MAX_PROTECTED_LINEAGE_STATEMENT_BYTES,
    },
    records::{IdentityBody, IdentityDoc, IdentityPolicy, Inbox, ServiceKeyEntry},
    sig::SignedDoc,
    time::MAX_TIME_MS,
};
use serde_json::{Value, json};

const DESCRIPTOR: &str = r#"{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","lineage_id":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","origin":{"generation":1,"seq":1,"item_hash":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"},"incarnation":{"kind":"absent","ref":{"generation":1,"seq":1,"item_hash":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"}},"current":{"ref":{"generation":1,"seq":2,"item_hash":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"},"previous":{"generation":1,"seq":1,"item_hash":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"},"applied_at":"2023-11-14T22:13:20.000Z"},"deleted":false,"truncated":false,"recovered":false,"deletions":[],"nodes":["BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"]}"#;
const STATEMENT_BODY: &str = r#"{"v":1,"kind":"pubky-switch.record_lineage","identity":"yryonyebyryonyebyryonyebyryonyebyryonyebyryonyebyryo","created":"1970-01-01T00:00:00.000Z","identity_hash":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","generation":7,"seq":9,"chain_hash":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","lineage_id":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","current":{"generation":1,"seq":2,"item_hash":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"},"descriptor_hash":"S8wfnH-2mJkh2cLht43_jyxxx7JBzd0S8sfD84E9nMc"}"#;
const SIGNATURE: &str =
    "IT0jrUun8I5aVQ1l8JKxpNIZv6yz5xEoYBowk0V5oQqiTfmIoK1mTsiRNK_m54CtbNI6p7wsgTARtboyGvd8CA";

fn reference(seq: u64, byte: u8) -> ApplicationRef {
    ApplicationRef {
        generation: 1,
        seq,
        item_hash: [byte; 32],
    }
}

fn descriptor_body() -> LineageDescriptorBody {
    LineageDescriptorBody {
        key: [1; 32],
        lineage_id: [2; 32],
        origin: Some(reference(1, 3)),
        incarnation: Some(Incarnation::Absent(reference(1, 3))),
        current: CurrentApplication {
            reference: reference(2, 4),
            previous: Some(reference(1, 3)),
            applied_at: Some(1_700_000_000_000),
        },
        deleted: false,
        truncated: false,
        recovered: false,
        deletions: vec![],
        nodes: vec![[5; 32]],
    }
}

fn statement_body() -> LineageStatementBody {
    LineageStatementBody {
        identity: [1; 32],
        created: 0,
        identity_hash: [2; 32],
        generation: 7,
        seq: 9,
        chain_hash: [3; 32],
        key: [1; 32],
        lineage_id: [2; 32],
        current: reference(2, 4),
        descriptor_hash: hex::decode(
            "4bcc1f9c7fb6989921d9c2e1b78dff8f2c71c7b241cddd12f2c7c3f3813d9cc7",
        )
        .unwrap()
        .try_into()
        .unwrap(),
    }
}

fn parse_value(value: &Value) -> pubky_switch_core::Result<LineageDescriptor> {
    LineageDescriptor::parse(&serde_json::to_vec(value).unwrap())
}

fn maximal() -> LineageDescriptorBody {
    let mut body = descriptor_body();
    body.current.reference = reference(50, 50);
    body.current.previous = Some(reference(49, 49));
    body.incarnation = Some(Incarnation::Replacement(reference(49, 49)));
    body.truncated = true;
    body.deletions = [15, 25, 35, 45]
        .into_iter()
        .map(|n| DeletionCapsule {
            delete: reference(n, u8::try_from(n).unwrap()),
            predecessor: Some(reference(n - 1, u8::try_from(n - 1).unwrap())),
            incarnation: Some(Incarnation::Replacement(reference(
                n - 2,
                u8::try_from(n - 2).unwrap(),
            ))),
        })
        .collect();
    body.nodes = (1..=14).map(|n| [n; 32]).collect();
    body
}

#[test]
fn test_lineage_descriptor_exact_bytes_and_hash() {
    let descriptor = LineageDescriptor::new(descriptor_body()).unwrap();
    assert_eq!(descriptor.bytes(), DESCRIPTOR.as_bytes());
    assert_eq!(
        hex::encode(descriptor.hash()),
        "4bcc1f9c7fb6989921d9c2e1b78dff8f2c71c7b241cddd12f2c7c3f3813d9cc7"
    );
    let parsed = LineageDescriptor::parse(DESCRIPTOR.as_bytes()).unwrap();
    assert_eq!(parsed, descriptor);
    let alternate = format!(" {DESCRIPTOR}");
    let alternate = LineageDescriptor::parse(alternate.as_bytes()).unwrap();
    assert_eq!(alternate.body(), descriptor.body());
    assert_eq!(alternate.bytes(), format!(" {DESCRIPTOR}").as_bytes());
    assert_eq!(
        hex::encode(alternate.hash()),
        "53f5b519e299c290d39dcac8e21e882ccec01f5e38350497fc582a8bed154c1a"
    );
    let value: Value = serde_json::from_str(DESCRIPTOR).unwrap();
    let reordered = serde_json::to_vec_pretty(&value).unwrap();
    let reordered = LineageDescriptor::parse(&reordered).unwrap();
    assert_eq!(reordered.body(), descriptor.body());
    assert_ne!(reordered.hash(), descriptor.hash());
    let changed_time = DESCRIPTOR.replace("20.000Z", "20.000000000Z");
    let changed_time = LineageDescriptor::parse(changed_time.as_bytes()).unwrap();
    assert_eq!(changed_time.body(), descriptor.body());
    assert_ne!(changed_time.hash(), descriptor.hash());
}

#[test]
fn test_lineage_descriptor_required_members_and_current_shapes() {
    let value: Value = serde_json::from_str(DESCRIPTOR).unwrap();
    for key in value.as_object().unwrap().keys() {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(key);
        assert!(parse_value(&changed).is_err(), "missing {key}");
    }
    for path in [
        "/current",
        "/origin",
        "/incarnation",
        "/incarnation/ref",
        "/current/ref",
        "/current/previous",
    ] {
        for key in value.pointer(path).unwrap().as_object().unwrap().keys() {
            let mut changed = value.clone();
            changed
                .pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(parse_value(&changed).is_err(), "missing {path}/{key}");
        }
        let mut changed = value.clone();
        changed
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), Value::Null);
        assert!(parse_value(&changed).is_err(), "extra {path}");
    }
    for (path, replacement) in [
        ("/v", json!(2)),
        ("/key", json!("AA")),
        ("/lineage_id", json!(false)),
        ("/deleted", json!(0)),
        ("/truncated", Value::Null),
        ("/recovered", json!("false")),
        ("/incarnation/kind", json!("other")),
        ("/deletions", Value::Null),
        ("/nodes", json!({})),
        ("/nodes/0", json!("AA")),
        ("/origin/generation", json!(0)),
        ("/current/ref/seq", json!(0)),
        ("/current/previous/generation", json!(MAX_INT + 1)),
        ("/current/applied_at", json!("2023-11-14T22:13:20+00:00")),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(path).unwrap() = replacement;
        assert!(parse_value(&changed).is_err(), "{path}");
    }
    for bad in [
        DESCRIPTOR.replace("\"v\":1", "\"v\":1,\"v\":1"),
        DESCRIPTOR.replace("\"v\":1", "\"v\":1e0"),
        DESCRIPTOR.replace("\"previous\":", "\"extra\":null,\"previous\":"),
    ] {
        assert!(LineageDescriptor::parse(bad.as_bytes()).is_err());
    }
    let mut nullable = descriptor_body();
    nullable.origin = None;
    nullable.incarnation = None;
    nullable.current.previous = None;
    nullable.current.applied_at = None;
    nullable.recovered = true;
    let nullable = LineageDescriptor::new(nullable).unwrap();
    assert_eq!(
        LineageDescriptor::parse(nullable.bytes()).unwrap(),
        nullable
    );
}

#[test]
fn test_lineage_descriptor_capsules_and_reference_union() {
    assert_eq!(MAX_DELETION_CAPSULES, 4);
    assert_eq!(MAX_LINEAGE_NODES, 14);
    let full = maximal();
    assert_eq!(full.required_references().len(), 14);
    assert!(!full.required_references().contains(&reference(1, 3)));
    let encoded = LineageDescriptor::new(full.clone()).unwrap();
    assert_eq!(
        LineageDescriptor::parse(encoded.bytes()).unwrap().body(),
        &full
    );
    let mut alias = full.clone();
    alias.current.reference = alias.deletions[3].delete;
    alias.current.previous = alias.deletions[3].predecessor;
    alias.incarnation = alias.deletions[3].incarnation;
    alias.deleted = true;
    alias.nodes.truncate(12);
    assert_eq!(alias.required_references().len(), 12);
    LineageDescriptor::new(alias).unwrap();
    let mut cases = vec![];
    let mut b = descriptor_body();
    b.origin = None;
    b.incarnation = None;
    b.recovered = true;
    b.current.reference = reference(100, 100);
    b.current.previous = None;
    b.current.applied_at = None;
    b.deletions = [10, 20, 30, 40, 50]
        .into_iter()
        .map(|n| DeletionCapsule {
            delete: reference(n, u8::try_from(n).unwrap()),
            predecessor: None,
            incarnation: None,
        })
        .collect();
    b.nodes = (1..=6).map(|n| [n; 32]).collect();
    assert_eq!(b.required_references().len(), b.nodes.len());
    cases.push(b);
    let mut b = full.clone();
    b.nodes.push([15; 32]);
    cases.push(b);
    let mut b = full.clone();
    b.nodes.pop();
    cases.push(b);
    let mut b = full.clone();
    b.nodes[1] = b.nodes[0];
    cases.push(b);
    let mut b = full.clone();
    b.deletions.swap(0, 1);
    cases.push(b);
    let mut b = full.clone();
    b.deletions[1].delete = b.deletions[0].delete;
    b.nodes.pop();
    cases.push(b);
    for b in cases {
        assert!(LineageDescriptor::new(b).is_err());
    }
    let value: Value = serde_json::from_slice(encoded.bytes()).unwrap();
    for path in [
        "/deletions/0",
        "/deletions/0/delete",
        "/deletions/0/predecessor",
        "/deletions/0/incarnation",
        "/deletions/0/incarnation/ref",
    ] {
        for key in value.pointer(path).unwrap().as_object().unwrap().keys() {
            let mut b = value.clone();
            b.pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(parse_value(&b).is_err());
        }
        let mut b = value.clone();
        b.pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), Value::Null);
        assert!(parse_value(&b).is_err());
    }
    let mut b = value.clone();
    b["deletions"].as_array_mut().unwrap().swap(0, 1);
    assert!(parse_value(&b).is_err());
    let mut b = value.clone();
    b["nodes"][1] = b["nodes"][0].clone();
    assert!(parse_value(&b).is_err());
    let mut b = value;
    b["nodes"].as_array_mut().unwrap().pop();
    assert!(parse_value(&b).is_err());
}

#[test]
fn test_lineage_descriptor_writer_integer_and_time_bounds() {
    for field in [
        "origin",
        "incarnation",
        "current",
        "previous",
        "delete",
        "predecessor",
        "replacement",
    ] {
        let mut b = maximal();
        let invalid = ApplicationRef {
            generation: 0,
            ..reference(1, 1)
        };
        match field {
            "origin" => b.origin = Some(invalid),
            "incarnation" => b.incarnation = Some(Incarnation::Absent(invalid)),
            "current" => b.current.reference = invalid,
            "previous" => b.current.previous = Some(invalid),
            "delete" => b.deletions[0].delete = invalid,
            "predecessor" => b.deletions[0].predecessor = Some(invalid),
            _ => b.deletions[0].incarnation = Some(Incarnation::Replacement(invalid)),
        }
        assert!(LineageDescriptor::new(b).is_err(), "{field}");
    }
    let mut b = descriptor_body();
    b.current.applied_at = Some(MAX_TIME_MS + 1);
    assert!(LineageDescriptor::new(b).is_err());
    let mut b = descriptor_body();
    b.current.reference.seq = MAX_INT + 1;
    assert!(LineageDescriptor::new(b).is_err());
    let mut b = descriptor_body();
    b.current.reference = ApplicationRef {
        generation: MAX_INT,
        seq: MAX_INT,
        item_hash: [255; 32],
    };
    b.current.applied_at = Some(MAX_TIME_MS);
    let b = LineageDescriptor::new(b).unwrap();
    assert_eq!(LineageDescriptor::parse(b.bytes()).unwrap(), b);
}

#[test]
fn test_lineage_protected_descriptor_size_counts_exact_bytes() {
    assert_eq!(MAX_PROTECTED_DESCRIPTOR_BYTES, 16_384);
    let mut at = DESCRIPTOR.as_bytes().to_vec();
    at.resize(16_384, b' ');
    LineageDescriptor::check_protected_size(&at).unwrap();
    let parsed = LineageDescriptor::parse(&at).unwrap();
    assert_eq!(parsed.bytes(), at);
    at.push(b' ');
    assert!(matches!(
        LineageDescriptor::check_protected_size(&at),
        Err(SizeRefusal::TooLarge(_))
    ));
    assert_eq!(LineageDescriptor::parse(&at).unwrap().body(), parsed.body());
}

#[test]
fn test_lineage_statement_exact_signature_fixture() {
    assert_eq!(
        statement_body().to_json().unwrap(),
        STATEMENT_BODY.as_bytes()
    );
    let key = SigningKey::from_bytes(&[22; 32]);
    let statement = LineageStatement::sign(&key, statement_body()).unwrap();
    assert_eq!(statement.signed().sig, SIGNATURE);
    assert_eq!(
        statement.signed().body_bytes().unwrap(),
        STATEMENT_BODY.as_bytes()
    );
    assert_eq!(
        LineageStatement::parse(statement.signed()).unwrap(),
        statement
    );
    assert_eq!(
        LineageStatement::from_json(&statement.to_json()).unwrap(),
        statement
    );
    let body = format!(" \n{STATEMENT_BODY}\n");
    let signed = SignedDoc::sign_bytes(
        &key,
        "pubky-switch/v1/record-lineage-statement",
        &[&[1; 32]],
        body.as_bytes().to_vec(),
    );
    let parsed = LineageStatement::parse(&signed).unwrap();
    assert_eq!(parsed.body(), statement.body());
    assert_eq!(parsed.signed().body_bytes().unwrap(), body.as_bytes());
    assert_ne!(parsed.signed().sig, SIGNATURE);
}

struct Snapshot {
    signer: IdentityKey,
    service: SigningKey,
    identity: IdentityDoc,
    head: SignedHead,
    descriptor: LineageDescriptor,
    body: LineageStatementBody,
}

fn snapshot() -> Snapshot {
    let signer = IdentityKey::from_secret([21; 32]);
    let service = SigningKey::from_bytes(&[22; 32]);
    let mut body = IdentityBody::first(
        signer.public(),
        [23; 16],
        Inbox::new("https://switch.example", service.verifying_key().to_bytes()),
        IdentityPolicy::default(),
    );
    body.generation = 7;
    let identity = IdentityDoc::sign(&signer, body).unwrap();
    let head = SignedHead::sign(
        &service,
        &signer.public(),
        &ChainTip {
            generation: 7,
            seq: 12,
            chain_hash: [24; 32],
        },
    );
    let descriptor = LineageDescriptor::new(descriptor_body()).unwrap();
    let body = LineageStatementBody {
        identity: signer.public(),
        identity_hash: identity.hash(),
        seq: head.seq,
        chain_hash: head.chain_hash,
        ..statement_body()
    };
    Snapshot {
        signer,
        service,
        identity,
        head,
        descriptor,
        body,
    }
}

fn check(s: &Snapshot, statement: &LineageStatement) -> pubky_switch_core::Result<()> {
    statement.check_snapshot(
        &s.identity,
        s.body.created,
        &s.head,
        &s.body.key,
        &s.descriptor,
    )
}

#[test]
fn test_lineage_statement_snapshot_association() {
    let s = snapshot();
    let good = LineageStatement::sign(&s.service, s.body.clone()).unwrap();
    check(&s, &good).unwrap();
    let mut cases = vec![];
    let mut b = s.body.clone();
    b.identity = [11; 32];
    cases.push(b);
    let mut b = s.body.clone();
    b.identity_hash = [12; 32];
    cases.push(b);
    let mut b = s.body.clone();
    b.generation += 1;
    cases.push(b);
    let mut b = s.body.clone();
    b.created += 1;
    cases.push(b);
    let mut b = s.body.clone();
    b.seq += 1;
    cases.push(b);
    let mut b = s.body.clone();
    b.chain_hash = [13; 32];
    cases.push(b);
    let mut b = s.body.clone();
    b.key = [14; 32];
    cases.push(b);
    let mut b = s.body.clone();
    b.lineage_id = [15; 32];
    cases.push(b);
    let mut b = s.body.clone();
    b.current.item_hash = [16; 32];
    cases.push(b);
    let mut b = s.body.clone();
    b.descriptor_hash = [17; 32];
    cases.push(b);
    for b in cases {
        let bad = LineageStatement::sign(&s.service, b).unwrap();
        assert!(matches!(check(&s, &bad), Err(Error::Invalid(_))));
    }
    let mut body = s.descriptor.body().clone();
    body.key = [18; 32];
    let descriptor = LineageDescriptor::new(body).unwrap();
    let mut body = s.body.clone();
    body.descriptor_hash = descriptor.hash();
    let stmt = LineageStatement::sign(&s.service, body).unwrap();
    assert!(
        stmt.check_snapshot(&s.identity, 0, &s.head, &s.body.key, &descriptor)
            .is_err()
    );
    let other = SigningKey::from_bytes(&[33; 32]);
    let bad = LineageStatement::sign(&other, s.body.clone()).unwrap();
    assert!(matches!(check(&s, &bad), Err(Error::Signature(_))));
    let wrong_label = SignedDoc::sign_bytes(
        &s.service,
        "pubky-switch/v1/record-origin-statement",
        &[&s.body.identity],
        s.body.to_json().unwrap(),
    );
    assert!(matches!(
        check(&s, &LineageStatement::parse(&wrong_label).unwrap()),
        Err(Error::Signature(_))
    ));
    let bad_head = SignedHead::sign(
        &other,
        &s.signer.public(),
        &ChainTip {
            generation: 7,
            seq: 12,
            chain_hash: [24; 32],
        },
    );
    assert!(matches!(
        good.check_snapshot(&s.identity, 0, &bad_head, &s.body.key, &s.descriptor),
        Err(Error::Signature(_))
    ));
}

#[test]
fn test_lineage_statement_current_key_and_cached_association() {
    let s = snapshot();
    let old = LineageStatement::sign(&s.service, s.body.clone()).unwrap();
    check(&s, &old).unwrap();
    // The same cached snapshot still authenticates; freshness requires the actual response.
    check(&s, &old).unwrap();
    let next = SigningKey::from_bytes(&[33; 32]);
    let mut identity_body = s.identity.body().clone();
    identity_body.generation = 8;
    identity_body.version += 1;
    identity_body.service_keys.push(ServiceKeyEntry {
        generation: 7,
        key: s.service.verifying_key().to_bytes(),
    });
    identity_body.inbox.service_key = next.verifying_key().to_bytes();
    let identity = IdentityDoc::sign(&s.signer, identity_body).unwrap();
    assert!(old.verify_signature(&identity).is_err());
    let mut body = s.body;
    body.generation = 8;
    body.identity_hash = identity.hash();
    let historical = LineageStatement::sign(&s.service, body.clone()).unwrap();
    assert!(matches!(
        historical.verify_signature(&identity),
        Err(Error::Signature(_))
    ));
    LineageStatement::sign(&next, body)
        .unwrap()
        .verify_signature(&identity)
        .unwrap();
}

#[test]
fn test_lineage_statement_strict_body_and_wrapper() {
    let key = SigningKey::from_bytes(&[22; 32]);
    let value: Value = serde_json::from_str(STATEMENT_BODY).unwrap();
    let parse = |bytes: Vec<u8>| {
        LineageStatement::parse(&SignedDoc::sign_bytes(
            &key,
            "pubky-switch/v1/record-lineage-statement",
            &[&[1; 32]],
            bytes,
        ))
    };
    for field in value.as_object().unwrap().keys() {
        let mut b = value.clone();
        b.as_object_mut().unwrap().remove(field);
        assert!(parse(serde_json::to_vec(&b).unwrap()).is_err());
    }
    for (path, replacement) in [
        ("/v", json!(2)),
        ("/kind", json!("pubky-switch.record_origin")),
        ("/generation", json!(0)),
        ("/seq", json!(MAX_INT + 1)),
        ("/current/seq", json!(0)),
        ("/current/item_hash", json!("AA")),
        ("/created", json!("1970-01-01")),
    ] {
        let mut b = value.clone();
        *b.pointer_mut(path).unwrap() = replacement;
        assert!(parse(serde_json::to_vec(&b).unwrap()).is_err());
    }
    for b in [
        STATEMENT_BODY.replace("\"v\":1", "\"v\":1,\"v\":1"),
        STATEMENT_BODY.replace("\"current\":{", "\"current\":{\"extra\":null,"),
        STATEMENT_BODY.replace("\"v\":1", "\"extra\":null,\"v\":1"),
    ] {
        assert!(parse(b.into_bytes()).is_err());
    }
    let s = LineageStatement::sign(&key, statement_body()).unwrap();
    let wrapper: Value = serde_json::from_slice(&s.to_json()).unwrap();
    for field in ["body", "sig"] {
        let mut b = wrapper.clone();
        b.as_object_mut().unwrap().remove(field);
        assert!(LineageStatement::from_json(&serde_json::to_vec(&b).unwrap()).is_err());
        let mut b = wrapper.clone();
        b[field] = Value::Null;
        assert!(LineageStatement::from_json(&serde_json::to_vec(&b).unwrap()).is_err());
    }
    let mut b = wrapper;
    b["extra"] = Value::Null;
    assert!(LineageStatement::from_json(&serde_json::to_vec(&b).unwrap()).is_err());
    let bad = SignedDoc {
        sig: b64(&[0; 63]),
        ..s.signed().clone()
    };
    assert!(LineageStatement::parse(&bad).is_err());
    for field in ["generation", "seq", "created", "current"] {
        let mut b = statement_body();
        match field {
            "generation" => b.generation = 0,
            "seq" => b.seq = MAX_INT + 1,
            "created" => b.created = MAX_TIME_MS + 1,
            _ => b.current.seq = 0,
        }
        assert!(LineageStatement::sign(&key, b).is_err());
    }
    let mut b = statement_body();
    b.generation = MAX_INT;
    b.seq = MAX_INT;
    b.created = MAX_TIME_MS;
    b.current.seq = MAX_INT;
    let b = LineageStatement::sign(&key, b).unwrap();
    LineageStatement::parse(b.signed()).unwrap();
    let reordered = serde_json::to_vec_pretty(&value).unwrap();
    let reordered = parse(reordered.clone()).unwrap();
    assert_eq!(reordered.body(), s.body());
    assert_eq!(
        reordered.signed().body_bytes().unwrap(),
        serde_json::to_vec_pretty(&value).unwrap()
    );
}

#[test]
fn test_lineage_protected_statement_size_preserves_signed_body() {
    assert_eq!(MAX_PROTECTED_LINEAGE_STATEMENT_BYTES, 4096);
    let key = SigningKey::from_bytes(&[22; 32]);
    // Compact wrapper = 106 + unpadded-base64 body length; 2992 bytes expand to 3990.
    let mut body = STATEMENT_BODY.as_bytes().to_vec();
    body.resize(2992, b' ');
    let at = SignedDoc::sign_bytes(
        &key,
        "pubky-switch/v1/record-lineage-statement",
        &[&[1; 32]],
        body.clone(),
    );
    let parsed = LineageStatement::parse(&at).unwrap();
    assert_eq!(parsed.to_json().len(), 4096);
    assert_eq!(parsed.signed().body_bytes().unwrap(), body);
    LineageStatement::check_protected_size(&at).unwrap();
    body.push(b' ');
    let above = SignedDoc::sign_bytes(
        &key,
        "pubky-switch/v1/record-lineage-statement",
        &[&[1; 32]],
        body,
    );
    assert_eq!(
        LineageStatement::parse(&above).unwrap().to_json().len(),
        4097
    );
    assert!(matches!(
        LineageStatement::check_protected_size(&above),
        Err(SizeRefusal::TooLarge(_))
    ));
    for bad in [
        SignedDoc {
            body: "=".into(),
            sig: SIGNATURE.into(),
        },
        SignedDoc {
            body: b64(b"{}"),
            sig: b64(&[0; 63]),
        },
    ] {
        assert!(matches!(
            LineageStatement::check_protected_size(&bad),
            Err(SizeRefusal::BadRequest(_))
        ));
    }
}

#[test]
fn test_lineage_absent_incarnations_bind_known_origin() {
    let current = descriptor_body();
    let mut capsule = maximal();
    capsule.truncated = false;
    capsule.deletions[0].incarnation = Some(Incarnation::Absent(reference(1, 3)));
    capsule.nodes.pop();
    let mut rejected = Vec::new();
    for (name, valid, path) in [
        ("current", current, "/incarnation/ref"),
        ("capsule", capsule, "/deletions/0/incarnation/ref"),
    ] {
        for recovered in [false, true] {
            let mut valid = valid.clone();
            valid.recovered = recovered;
            let encoded = LineageDescriptor::new(valid.clone()).unwrap();
            assert_eq!(LineageDescriptor::parse(encoded.bytes()).unwrap(), encoded);

            let wrong = reference(1, 33);
            let mut value: Value = serde_json::from_slice(encoded.bytes()).unwrap();
            *value.pointer_mut(path).unwrap() =
                serde_json::from_slice(&wrong.to_json().unwrap()).unwrap();
            let reader_rejected = parse_value(&value).is_err();
            let mut invalid = valid.clone();
            if name == "current" {
                invalid.incarnation = Some(Incarnation::Absent(wrong));
            } else {
                invalid.deletions[0].incarnation = Some(Incarnation::Absent(wrong));
            }
            let writer_rejected = LineageDescriptor::new(invalid).is_err();
            rejected.push((name, recovered, writer_rejected, reader_rejected));

            // An unavailable origin does not assert equality with the retained reference.
            valid.origin = None;
            valid.recovered = true;
            let unavailable = LineageDescriptor::new(valid).unwrap();
            assert_eq!(
                LineageDescriptor::parse(unavailable.bytes()).unwrap(),
                unavailable
            );
        }
    }
    assert!(
        rejected
            .iter()
            .all(|(_, _, writer, reader)| *writer && *reader),
        "{rejected:?}"
    );
}
