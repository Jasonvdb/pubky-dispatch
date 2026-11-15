use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use super::*;
use crate::chain::{ChainTip, SignedHead};
use crate::enc::{b64, pubky_id};
use crate::ident::{Policy, record_key_from_blinded};
use crate::json::MAX_INT;
use crate::keys::IdentityKey;
use crate::records::{IdentityBody, IdentityDoc, IdentityPolicy, Inbox, ServiceKeyEntry};
use crate::sealed::{MAX_CT_LEN, SealedValue};
use crate::sig::{self, SignedDoc};
use crate::time::MAX_TIME_MS;
use crate::{Error, SizeRefusal};

fn reference(generation: u64, seq: u64, byte: u8) -> ApplicationRef {
    ApplicationRef {
        generation,
        seq,
        item_hash: [byte; 32],
    }
}

fn policy(protection: Protection) -> ProtectedPolicy {
    ProtectedPolicy {
        scopes: Policy::new("tasks", &["tasks:edit", "tasks:write"]),
        protection,
    }
}

fn child() -> ChildDeclaration {
    ChildDeclaration {
        slot: [7; 32],
        key: [8; 32],
        policy_hash: [9; 32],
    }
}

fn slot() -> OriginSlot {
    OriginSlot {
        parent_key: [1; 32],
        parent_collection: [2; 32],
        parent_policy_hash: [3; 32],
        birth_generation: Some(7),
        parent_read_scope: Some("tasks".into()),
        state: OriginState::Known(Box::new(KnownOrigin {
            lineage_id: [4; 32],
            original: reference(7, 8, 5),
            binding: [6; 32],
            child: ChildState::Initialized {
                declaration: child(),
                initialization: Initialization {
                    parent_acceptance: reference(7, 9, 10),
                    child_first: reference(7, 10, 11),
                    child_lineage_id: [12; 32],
                    initial_value_hash: [13; 32],
                    binding: [14; 32],
                },
            },
            retired: false,
            recovered: true,
        })),
    }
}

fn known(slot: &mut OriginSlot) -> &mut KnownOrigin {
    match &mut slot.state {
        OriginState::Known(known) => known,
        OriginState::Unknown => panic!("known fixture"),
    }
}

fn max_scope() -> String {
    format!("{}:{}", "a".repeat(32), "b".repeat(32))
}

fn sealed() -> SealedValue {
    SealedValue {
        data_epoch: 7,
        scope: "tasks".into(),
        nonce: [15; 24],
        ct: vec![16; 528],
    }
}

fn body() -> OriginStatementBody {
    OriginStatementBody {
        identity: [1; 32],
        created: 0,
        identity_hash: [2; 32],
        generation: 7,
        seq: 9,
        chain_hash: [3; 32],
        key: [4; 32],
        origin_key: [5; 32],
        slot_hash: [6; 32],
    }
}

struct Snapshot {
    signer: IdentityKey,
    service: SigningKey,
    identity: IdentityDoc,
    head: SignedHead,
    slot: OriginSlot,
    body: OriginStatementBody,
}

fn snapshot() -> Snapshot {
    let signer = IdentityKey::from_secret([21; 32]);
    let service = SigningKey::from_bytes(&[22; 32]);
    let mut identity_body = IdentityBody::first(
        signer.public(),
        [23; 16],
        Inbox::new("https://switch.example", service.verifying_key().to_bytes()),
        IdentityPolicy::default(),
    );
    identity_body.generation = 7;
    let identity = IdentityDoc::sign(&signer, identity_body).unwrap();
    let head = SignedHead::sign(
        &service,
        &signer.public(),
        &ChainTip {
            generation: 7,
            seq: 12,
            chain_hash: [24; 32],
        },
    );
    let slot = slot();
    let body = OriginStatementBody {
        identity: signer.public(),
        created: 1_700_000_000_000,
        identity_hash: identity.hash(),
        generation: 7,
        seq: head.seq,
        chain_hash: head.chain_hash,
        key: slot.parent_key,
        origin_key: slot.parent_key,
        slot_hash: slot.hash().unwrap(),
    };
    Snapshot {
        signer,
        service,
        identity,
        head,
        slot,
        body,
    }
}

fn check(snapshot: &Snapshot, statement: &OriginStatement) -> crate::Result<()> {
    statement.check_snapshot(
        &snapshot.identity,
        snapshot.body.created,
        &snapshot.head,
        &snapshot.body.key,
        &snapshot.slot,
    )
}

#[test]
fn test_reference_exact_bytes_and_order() {
    let value = reference(1, 2, 3);
    let expected = hex::decode(concat!(
        "00000000000000010000000000000002",
        "0303030303030303030303030303030303030303030303030303030303030303"
    ))
    .unwrap();
    assert_eq!(value.to_bytes().unwrap().as_slice(), expected);
    assert_eq!(ApplicationRef::from_bytes(&expected).unwrap(), value);
    assert_eq!(
        String::from_utf8(value.to_json().unwrap()).unwrap(),
        r#"{"generation":1,"seq":2,"item_hash":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"}"#
    );
    assert_eq!(
        ApplicationRef::parse(&value.to_json().unwrap()).unwrap(),
        value
    );
    assert_eq!(ApplicationRef::optional_bytes(None).unwrap(), [0]);
    assert_eq!(
        ApplicationRef::optional_bytes(Some(&value)).unwrap(),
        [&[1][..], expected.as_slice()].concat()
    );
    assert!(reference(1, 2, 254) < reference(1, 2, 255));
    assert!(reference(1, 2, 255) < reference(1, 3, 0));
    assert!(reference(1, 3, 255) < reference(2, 1, 0));
    assert!(reference(MAX_INT, MAX_INT, 0).to_bytes().is_ok());
}

#[test]
fn test_reference_strict_members_and_integer_bounds() {
    let good = reference(1, 2, 3);
    let bytes = good.to_bytes().unwrap();
    for len in 0..48 {
        assert!(ApplicationRef::from_bytes(&bytes[..len]).is_err());
    }
    assert!(ApplicationRef::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
    for field in ["generation", "seq", "item_hash"] {
        let mut value: Value = serde_json::from_slice(&good.to_json().unwrap()).unwrap();
        value.as_object_mut().unwrap().remove(field);
        assert!(ApplicationRef::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    for bad in [
        json!(0),
        json!(MAX_INT + 1),
        json!(-1),
        json!(1.5),
        json!("1"),
        Value::Null,
        json!(true),
    ] {
        for field in ["generation", "seq"] {
            let mut value: Value = serde_json::from_slice(&good.to_json().unwrap()).unwrap();
            value[field] = bad.clone();
            assert!(ApplicationRef::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
    for bad in [0, MAX_INT + 1] {
        assert!(reference(bad, 2, 3).to_json().is_err());
        assert!(reference(1, bad, 3).to_bytes().is_err());
        let mut binary = bytes;
        binary[..8].copy_from_slice(&bad.to_be_bytes());
        assert!(ApplicationRef::from_bytes(&binary).is_err());
    }
    let text = String::from_utf8(good.to_json().unwrap()).unwrap();
    for extra in [r#""generation":1,"#, r#""unknown":null,"#] {
        assert!(ApplicationRef::parse(format!("{{{extra}{}", &text[1..]).as_bytes()).is_err());
    }
    assert!(
        ApplicationRef::parse(
            text.replace("\"generation\":1", "\"generation\":1e0")
                .as_bytes()
        )
        .is_err()
    );
    let mut value: Value = serde_json::from_str(&text).unwrap();
    for hash in [b64(&[0; 31]), b64(&[0; 33]), format!("{}=", b64(&[0; 32]))] {
        value["item_hash"] = json!(hash);
        assert!(ApplicationRef::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn test_protected_policy_fixed_hashes_and_keys() {
    let cases = [
        (
            Protection::Origin {
                birth_generation: None,
            },
            "58eee60fec15921fc787299f6c8ffb7f3061cee348b3688bf793f932b5660060",
            "889097f96d6cb7b45a2e58e59c105ebe1579de37a3619d7d91874f164365b595",
        ),
        (
            Protection::Origin {
                birth_generation: Some(7),
            },
            "92f7d2e6c90b285a0129d3687193acdb75acec5acb9f981b6abd781325cc4c35",
            "ea91222feae11813a16691d9230084aeb2f52c8396ca4b095844f6d7ff5d48cc",
        ),
        (
            Protection::InitializedChild {
                parent_key: [1; 32],
                parent_collection: [2; 32],
                parent_policy_hash: [3; 32],
                slot: [4; 32],
            },
            "a1bd8c3b746a451cd9e934db54b9fa537469f2eaeab5467cad3413dcbfc78f3a",
            "e2ddb99170bfc016d26207fcbd9ac9e8e0ce1a7d8c7a4b91d9dd123feb4e4f61",
        ),
    ];
    for (protection, expected_hash, expected_key) in cases {
        let value = policy(protection);
        let hash = value.hash().unwrap();
        assert_eq!(hex::encode(hash), expected_hash);
        assert_eq!(
            hex::encode(record_key_from_blinded("tasks.items", &[9; 32], &hash)),
            expected_key
        );
        assert_eq!(
            ProtectedPolicy::parse(&value.to_json().unwrap()).unwrap(),
            value
        );
        assert_ne!(hash, value.scopes.hash().unwrap());
    }
    assert_eq!(
        Protection::Origin {
            birth_generation: None
        }
        .to_bytes()
        .unwrap(),
        [1, 0]
    );
    assert_eq!(
        Protection::Origin {
            birth_generation: Some(7)
        }
        .to_bytes()
        .unwrap(),
        hex::decode("01010000000000000007").unwrap()
    );
    let child = Protection::InitializedChild {
        parent_key: [1; 32],
        parent_collection: [2; 32],
        parent_policy_hash: [3; 32],
        slot: [4; 32],
    };
    assert_eq!(
        child.to_bytes().unwrap(),
        [&[2][..], &[1; 32], &[2; 32], &[3; 32], &[4; 32]].concat()
    );
}

#[test]
fn test_protected_policy_commits_every_input_without_cycle() {
    let original = policy(Protection::Origin {
        birth_generation: Some(7),
    });
    let original_hash = original.hash().unwrap();
    let mut changed = original.clone();
    changed.scopes.read_scope = "tasks:read".into();
    assert_ne!(changed.hash().unwrap(), original_hash);
    changed = original.clone();
    changed.scopes.write_scopes.pop();
    assert_ne!(changed.hash().unwrap(), original_hash);
    changed.scopes.write_scopes[0] = "tasks:other".into();
    assert_ne!(changed.hash().unwrap(), original_hash);
    changed = original.clone();
    changed.protection = Protection::Origin {
        birth_generation: Some(8),
    };
    assert_ne!(changed.hash().unwrap(), original_hash);
    let parent_key = record_key_from_blinded("tasks.items", &[9; 32], &original_hash);
    let child = policy(Protection::InitializedChild {
        parent_key,
        parent_collection: [2; 32],
        parent_policy_hash: original_hash,
        slot: [4; 32],
    });
    let child_hash = child.hash().unwrap();
    for field in [
        "parent_key",
        "parent_collection",
        "parent_policy_hash",
        "slot",
    ] {
        let mut json: Value = serde_json::from_slice(&child.to_json().unwrap()).unwrap();
        json["protection"][field] = json!(b64(&[99; 32]));
        assert_ne!(
            ProtectedPolicy::parse(&serde_json::to_vec(&json).unwrap())
                .unwrap()
                .hash()
                .unwrap(),
            child_hash
        );
    }
    let declaration = OriginDeclaration {
        binding: [5; 32],
        child: Some(ChildDeclaration {
            slot: [4; 32],
            key: record_key_from_blinded("tasks.children", &[6; 32], &child_hash),
            policy_hash: child_hash,
        }),
    };
    assert!(OriginDeclaration::parse(&declaration.to_json()).is_ok());
    assert_eq!(original.hash().unwrap(), original_hash);
}

#[test]
fn test_protection_required_nullable_strict_union() {
    for bytes in [
        r#"{"kind":"origin"}"#,
        r#"{"kind":"origin","birth_generation":0}"#,
        r#"{"kind":"origin","birth_generation":1,"slot":null}"#,
        r#"{"kind":"origin","birth_generation":null,"birth_generation":1}"#,
        r#"{"kind":"origin","birth_generation":"1"}"#,
        r#"{"kind":"initialized_child"}"#,
        r#"{"kind":"unknown","birth_generation":null}"#,
        r#"null"#,
        r#"[]"#,
    ] {
        assert!(Protection::parse(bytes.as_bytes()).is_err(), "{bytes}");
    }
    assert_eq!(
        Protection::parse(br#"{"kind":"origin","birth_generation":null}"#).unwrap(),
        Protection::Origin {
            birth_generation: None
        }
    );
    assert!(
        Protection::Origin {
            birth_generation: Some(MAX_INT)
        }
        .to_json()
        .is_ok()
    );
    for n in [0, MAX_INT + 1] {
        let invalid = Protection::Origin {
            birth_generation: Some(n),
        };
        assert!(invalid.to_bytes().is_err());
        assert!(invalid.to_json().is_err());
        assert!(policy(invalid).hash().is_err());
    }
    let valid = Protection::InitializedChild {
        parent_key: [1; 32],
        parent_collection: [2; 32],
        parent_policy_hash: [3; 32],
        slot: [4; 32],
    };
    for field in [
        "parent_key",
        "parent_collection",
        "parent_policy_hash",
        "slot",
    ] {
        let mut json: Value = serde_json::from_slice(&valid.to_json().unwrap()).unwrap();
        json.as_object_mut().unwrap().remove(field);
        assert!(Protection::parse(&serde_json::to_vec(&json).unwrap()).is_err());
        json[field] = Value::Null;
        assert!(Protection::parse(&serde_json::to_vec(&json).unwrap()).is_err());
        json[field] = json!(b64(&[0; 31]));
        assert!(Protection::parse(&serde_json::to_vec(&json).unwrap()).is_err());
    }
}

#[test]
fn test_protected_scope_bounds_and_order() {
    let mut valid = policy(Protection::Origin {
        birth_generation: None,
    });
    valid.scopes.read_scope = max_scope();
    valid.scopes.write_scopes = (0..32).map(|i| format!("tasks:s{i:02}")).collect();
    assert!(valid.hash().is_ok());
    assert!(ProtectedPolicy::parse(&valid.to_json().unwrap()).is_ok());
    for writes in [
        vec![],
        vec!["tasks".into(); 2],
        vec!["tasks:z".into(), "tasks:a".into()],
        (0..33).map(|i| format!("tasks:s{i:02}")).collect(),
    ] {
        let mut bad = valid.clone();
        bad.scopes.write_scopes = writes;
        assert!(bad.hash().is_err());
        assert!(bad.to_json().is_err());
        let json = json!({"read_scope":"tasks", "write_scopes":bad.scopes.write_scopes, "protection":{"kind":"origin","birth_generation":null}});
        assert!(ProtectedPolicy::parse(&serde_json::to_vec(&json).unwrap()).is_err());
    }
    for scope in [
        String::new(),
        "tásks".into(),
        "Tasks".into(),
        "a:b:c".into(),
        "a".repeat(33),
        format!("{}x", max_scope()),
    ] {
        let mut bad = valid.clone();
        bad.scopes.read_scope = scope.clone();
        assert!(bad.hash().is_err());
        bad.scopes.read_scope = "tasks".into();
        bad.scopes.write_scopes = vec![scope];
        assert!(bad.to_json().is_err());
    }
    valid.scopes.write_scopes = vec!["tasks".into(), "tasks:edit".into()];
    assert!(valid.hash().is_ok());
    let bytes = valid.to_json().unwrap();
    for field in ["read_scope", "write_scopes", "protection"] {
        let mut json: Value = serde_json::from_slice(&bytes).unwrap();
        json.as_object_mut().unwrap().remove(field);
        assert!(ProtectedPolicy::parse(&serde_json::to_vec(&json).unwrap()).is_err());
    }
    let mut json: Value = serde_json::from_slice(&bytes).unwrap();
    json["unknown"] = json!(true);
    assert!(ProtectedPolicy::parse(&serde_json::to_vec(&json).unwrap()).is_err());
}

#[test]
fn test_origin_declaration_preserves_child_presence() {
    for child in [None, Some(child())] {
        let declaration = OriginDeclaration {
            binding: [6; 32],
            child,
        };
        let bytes = declaration.to_json();
        assert_eq!(OriginDeclaration::parse(&bytes).unwrap(), declaration);
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value.as_object_mut().unwrap().remove("child");
        assert!(OriginDeclaration::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let good = OriginDeclaration {
        binding: [6; 32],
        child: Some(child()),
    };
    for pointer in [
        "/binding",
        "/child",
        "/child/slot",
        "/child/key",
        "/child/policy_hash",
    ] {
        let mut value: Value = serde_json::from_slice(&good.to_json()).unwrap();
        *value.pointer_mut(pointer).unwrap() = json!(42);
        assert!(OriginDeclaration::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut value: Value = serde_json::from_slice(&good.to_json()).unwrap();
    value["child"]["unknown"] = json!(true);
    assert!(OriginDeclaration::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let text = String::from_utf8(good.to_json()).unwrap();
    assert!(
        OriginDeclaration::parse(
            text.replace("\"slot\":", "\"key\":null,\"slot\":")
                .as_bytes()
        )
        .is_err()
    );
}

#[test]
fn test_origin_slot_fixed_bytes_and_hash() {
    let value = slot();
    let mut expected = vec![1];
    expected.extend([1; 32]);
    expected.extend([2; 32]);
    expected.extend([3; 32]);
    expected.extend(hex::decode("010000000000000007057461736b7301").unwrap());
    expected.extend([4; 32]);
    expected.extend(hex::decode("00000000000000070000000000000008").unwrap());
    expected.extend([5; 32]);
    expected.extend([6; 32]);
    expected.push(1);
    expected.extend([7; 32]);
    expected.extend([8; 32]);
    expected.extend([9; 32]);
    expected.push(1);
    expected.extend(hex::decode("00000000000000070000000000000009").unwrap());
    expected.extend([10; 32]);
    expected.extend(hex::decode("0000000000000007000000000000000a").unwrap());
    expected.extend([11; 32]);
    expected.extend([12; 32]);
    expected.extend([13; 32]);
    expected.extend([14; 32]);
    expected.extend([0, 1]);
    assert_eq!(value.to_bytes().unwrap(), expected);
    assert_eq!(expected.len(), 517);
    assert_eq!(
        hex::encode(value.hash().unwrap()),
        "62e23dc6b293ab2bf1defc0768bd5c0d8a9bbac6bcbd9a9aa1113a71c131deaa"
    );
    assert_eq!(OriginSlot::from_bytes(&expected).unwrap(), value);
    assert_eq!(OriginSlot::from_base64(&b64(&expected)).unwrap(), value);
}

#[test]
fn test_origin_slot_exact_maximum_variants() {
    let mut value = slot();
    value.parent_read_scope = Some(max_scope());
    assert_eq!(value.to_bytes().unwrap().len(), 577);
    assert_eq!(value.to_base64().unwrap().len(), 770);
    value.birth_generation = None;
    assert_eq!(value.to_bytes().unwrap().len(), 569);
    known(&mut value).child = ChildState::Vacant(child());
    assert_eq!(value.to_bytes().unwrap().len(), 377);
    known(&mut value).child = ChildState::Standalone;
    assert_eq!(value.to_bytes().unwrap().len(), 281);
    value.birth_generation = Some(7);
    assert_eq!(value.to_bytes().unwrap().len(), 289);
    value.state = OriginState::Unknown;
    assert_eq!(value.to_bytes().unwrap().len(), 173);
    value.parent_read_scope = None;
    assert_eq!(value.to_bytes().unwrap().len(), 108);
    value.birth_generation = None;
    assert_eq!(value.to_bytes().unwrap().len(), 100);
    assert_eq!(
        OriginSlot::from_bytes(&value.to_bytes().unwrap()).unwrap(),
        value
    );
}

#[test]
fn test_origin_slot_restrictive_states_round_trip() {
    for birth in [None, Some(7)] {
        for child in [
            ChildState::Standalone,
            ChildState::Vacant(child()),
            known(&mut slot()).child.clone(),
        ] {
            for retired in [false, true] {
                for recovered in [false, true] {
                    let mut value = slot();
                    value.birth_generation = birth;
                    let known = known(&mut value);
                    known.child = child.clone();
                    known.retired = retired;
                    known.recovered = recovered;
                    assert_eq!(
                        OriginSlot::from_base64(&value.to_base64().unwrap()).unwrap(),
                        value
                    );
                }
            }
        }
    }
    let mut value = slot();
    value.state = OriginState::Unknown;
    for scope in [None, Some("tasks".into())] {
        value.parent_read_scope = scope;
        assert_eq!(
            OriginSlot::from_bytes(&value.to_bytes().unwrap()).unwrap(),
            value
        );
    }
}

#[test]
fn test_origin_slot_rejects_truncation_tags_and_tails() {
    let bytes = slot().to_bytes().unwrap();
    for len in 0..bytes.len() {
        assert!(
            OriginSlot::from_bytes(&bytes[..len]).is_err(),
            "length {len}"
        );
    }
    for offset in [0, 97, 112, 225, 322, 515, 516] {
        let mut bad = bytes.clone();
        bad[offset] = 2;
        assert!(OriginSlot::from_bytes(&bad).is_err(), "offset {offset}");
    }
    assert!(OriginSlot::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
    let mut standalone = slot();
    known(&mut standalone).child = ChildState::Standalone;
    let mut bad = standalone.to_bytes().unwrap();
    bad[226] = 1;
    assert!(OriginSlot::from_bytes(&bad).is_err());
    for offset in [98, 145, 153, 323, 331, 371, 379] {
        for integer in [0, MAX_INT + 1] {
            let mut bad = bytes.clone();
            bad[offset..offset + 8].copy_from_slice(&integer.to_be_bytes());
            assert!(OriginSlot::from_bytes(&bad).is_err(), "offset {offset}");
        }
    }
    let mut bad = bytes.clone();
    bad[98..106].copy_from_slice(&8u64.to_be_bytes());
    assert!(OriginSlot::from_bytes(&bad).is_err());
    let mut bad = bytes;
    bad[107] = 0xff;
    assert!(OriginSlot::from_bytes(&bad).is_err());
    assert!(OriginSlot::from_base64(&format!("{}=", slot().to_base64().unwrap())).is_err());
    assert!(OriginSlot::from_base64(&"A".repeat(771)).is_err());
}

#[test]
fn test_origin_slot_constructed_invariants_and_caps() {
    let mut bad = slot();
    bad.parent_read_scope = None;
    assert!(bad.to_bytes().is_err());
    for scope in [String::new(), max_scope() + "x", "tásks".into()] {
        bad.parent_read_scope = Some(scope);
        assert!(bad.to_bytes().is_err());
    }
    bad = slot();
    bad.birth_generation = Some(8);
    assert!(bad.to_bytes().is_err());
    bad = slot();
    known(&mut bad).original.seq = 0;
    assert!(bad.hash().is_err());
    assert!(OriginSlot::check_size(&[0; 577]).is_ok());
    assert!(matches!(
        OriginSlot::check_size(&[0; 578]),
        Err(SizeRefusal::TooLarge(_))
    ));
    assert!(OriginSlot::from_bytes(&[0; 578]).is_err());
}

#[test]
fn test_initial_value_fixed_digest_and_each_input() {
    let value = sealed();
    let digest = initial_value_hash(&value, "tasks").unwrap();
    assert_eq!(
        hex::encode(digest),
        "56b9f692c7ab0c79bf42750c1fb8b382d9c08849d9b827207d8b98eb260e52dc"
    );
    let mut changed = value.clone();
    changed.data_epoch += 1;
    assert_ne!(initial_value_hash(&changed, "tasks").unwrap(), digest);
    changed = value.clone();
    changed.scope = "tasks:read".into();
    assert_ne!(initial_value_hash(&changed, "tasks:read").unwrap(), digest);
    changed = value.clone();
    changed.nonce[0] ^= 1;
    assert_ne!(initial_value_hash(&changed, "tasks").unwrap(), digest);
    changed = value;
    changed.ct[0] ^= 1;
    assert_ne!(initial_value_hash(&changed, "tasks").unwrap(), digest);
    assert_ne!(reference(7, 8, 5), reference(7, 9, 5));
}

#[test]
fn test_initial_value_refuses_delete_shape_and_invalid_inputs() {
    let mut value = sealed();
    assert!(matches!(
        initial_value_hash(&value, "tasks:other"),
        Err(SizeRefusal::BadRequest(_))
    ));
    for len in [0, 16, 17, 527, 529] {
        value.ct = vec![0; len];
        assert!(matches!(
            initial_value_hash(&value, "tasks"),
            Err(SizeRefusal::BadRequest(_))
        ));
    }
    value.ct = vec![0; MAX_CT_LEN];
    assert!(initial_value_hash(&value, "tasks").is_ok());
    value.ct.push(0);
    assert!(matches!(
        initial_value_hash(&value, "tasks"),
        Err(SizeRefusal::TooLarge(_))
    ));
    value = sealed();
    value.data_epoch = MAX_INT + 1;
    assert!(initial_value_hash(&value, "tasks").is_err());
    value = sealed();
    value.scope = "bad scope".into();
    assert!(initial_value_hash(&value, "bad scope").is_err());
}

#[test]
fn test_origin_statement_exact_body_and_signature_input() {
    let expected = br#"{"v":1,"kind":"pubky-switch.record_origin","identity":"yryonyebyryonyebyryonyebyryonyebyryonyebyryonyebyryo","created":"1970-01-01T00:00:00.000Z","identity_hash":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","generation":7,"seq":9,"chain_hash":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","key":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ","origin_key":"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU","slot_hash":"BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY"}"#;
    let service = SigningKey::from_bytes(&[22; 32]);
    let statement = OriginStatement::sign(&service, body()).unwrap();
    assert_eq!(statement.signed().body_bytes().unwrap(), expected);
    assert_eq!(
        statement.signed().sig_bytes().unwrap(),
        sig::sign(
            &service,
            "pubky-switch/v1/record-origin-statement",
            &[&[1; 32], expected]
        )
    );
    assert_eq!(
        OriginStatement::parse(statement.signed()).unwrap(),
        statement
    );
    let mut altered = statement.signed().clone();
    altered.sig = b64(&[0; 64]);
    assert!(OriginStatement::parse(&altered).is_ok());
}

#[test]
fn test_origin_statement_snapshot_associations() {
    let snapshot = snapshot();
    let statement = OriginStatement::sign(&snapshot.service, snapshot.body.clone()).unwrap();
    check(&snapshot, &statement).unwrap();
    statement.verify_signature(&snapshot.identity).unwrap();
    let mut child_body = snapshot.body.clone();
    child_body.key = child().key;
    let child_statement = OriginStatement::sign(&snapshot.service, child_body.clone()).unwrap();
    child_statement
        .check_snapshot(
            &snapshot.identity,
            child_body.created,
            &snapshot.head,
            &child_body.key,
            &snapshot.slot,
        )
        .unwrap();
    child_body.key = [99; 32];
    let unrelated = OriginStatement::sign(&snapshot.service, child_body.clone()).unwrap();
    assert!(
        unrelated
            .check_snapshot(
                &snapshot.identity,
                child_body.created,
                &snapshot.head,
                &child_body.key,
                &snapshot.slot
            )
            .is_err()
    );
    let mut unknown = snapshot.slot.clone();
    unknown.state = OriginState::Unknown;
    let mut body = snapshot.body.clone();
    body.slot_hash = unknown.hash().unwrap();
    let statement = OriginStatement::sign(&snapshot.service, body).unwrap();
    statement
        .check_snapshot(
            &snapshot.identity,
            snapshot.body.created,
            &snapshot.head,
            &snapshot.body.key,
            &unknown,
        )
        .unwrap();
    assert!(matches!(unknown.state, OriginState::Unknown));
}

#[test]
fn test_origin_statement_signed_mismatches_fail() {
    let snapshot = snapshot();
    let mut cases = Vec::new();
    let mut changed = snapshot.body.clone();
    changed.identity = [1; 32];
    cases.push(changed);
    let mut changed = snapshot.body.clone();
    changed.created += 1;
    cases.push(changed);
    let mut changed = snapshot.body.clone();
    changed.identity_hash = [2; 32];
    cases.push(changed);
    let mut changed = snapshot.body.clone();
    changed.generation += 1;
    cases.push(changed);
    let mut changed = snapshot.body.clone();
    changed.seq += 1;
    cases.push(changed);
    let mut changed = snapshot.body.clone();
    changed.chain_hash = [3; 32];
    cases.push(changed);
    let mut changed = snapshot.body.clone();
    changed.key = [4; 32];
    cases.push(changed);
    let mut changed = snapshot.body.clone();
    changed.origin_key = [5; 32];
    cases.push(changed);
    let mut changed = snapshot.body.clone();
    changed.slot_hash = [6; 32];
    cases.push(changed);
    for body in cases {
        let statement = OriginStatement::sign(&snapshot.service, body).unwrap();
        assert!(matches!(
            check(&snapshot, &statement),
            Err(Error::Invalid(_))
        ));
    }
    let other = SigningKey::from_bytes(&[33; 32]);
    let statement = OriginStatement::sign(&other, snapshot.body.clone()).unwrap();
    assert!(matches!(
        check(&snapshot, &statement),
        Err(Error::Signature(_))
    ));
    let good = OriginStatement::sign(&snapshot.service, snapshot.body.clone()).unwrap();
    let bad_head = SignedHead::sign(
        &other,
        &snapshot.signer.public(),
        &ChainTip {
            generation: 7,
            seq: snapshot.head.seq,
            chain_hash: snapshot.head.chain_hash,
        },
    );
    assert!(matches!(
        good.check_snapshot(
            &snapshot.identity,
            snapshot.body.created,
            &bad_head,
            &snapshot.body.key,
            &snapshot.slot
        ),
        Err(Error::Signature(_))
    ));
}

#[test]
fn test_origin_statement_rejects_historical_key() {
    let snapshot = snapshot();
    let new_service = SigningKey::from_bytes(&[33; 32]);
    let mut identity_body = snapshot.identity.body().clone();
    identity_body.generation = 8;
    identity_body.version += 1;
    identity_body.service_keys.push(ServiceKeyEntry {
        generation: 7,
        key: snapshot.service.verifying_key().to_bytes(),
    });
    identity_body.inbox.service_key = new_service.verifying_key().to_bytes();
    let identity = IdentityDoc::sign(&snapshot.signer, identity_body).unwrap();
    let old = OriginStatement::sign(&snapshot.service, snapshot.body.clone()).unwrap();
    assert!(old.verify_signature(&identity).is_err());
    let mut body = snapshot.body;
    body.generation = 8;
    body.identity_hash = identity.hash();
    let claimed_current = OriginStatement::sign(&snapshot.service, body.clone()).unwrap();
    assert!(matches!(
        claimed_current.verify_signature(&identity),
        Err(Error::Signature(_))
    ));
    OriginStatement::sign(&new_service, body)
        .unwrap()
        .verify_signature(&identity)
        .unwrap();
}

#[test]
fn test_origin_statement_strict_body_and_preserved_signed_bytes() {
    let service = SigningKey::from_bytes(&[22; 32]);
    let body = body();
    let bytes = body.to_json().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let mut cases = vec![
        format!(" {text}"),
        text.replace("\"v\":1", "\"v\":2"),
        text.replace("\"v\":1", "\"v\":1,\"v\":1"),
        text.replace("\"v\":1", "\"v\":1,\"extra\":null"),
        text.replace("\"generation\":7", "\"generation\":0"),
        text.replace("\"seq\":9", "\"seq\":9e0"),
        text.replace("record_origin", "record_lineage"),
        text.replace(".000Z", "Z"),
    ];
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    for key in value.as_object().unwrap().keys() {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(key);
        cases.push(serde_json::to_string(&changed).unwrap());
    }
    for changed in cases {
        let signed = SignedDoc::sign_bytes(
            &service,
            "pubky-switch/v1/record-origin-statement",
            &[&body.identity],
            changed.into_bytes(),
        );
        assert!(OriginStatement::parse(&signed).is_err());
    }
    let signed = SignedDoc::sign_bytes(
        &service,
        "pubky-switch/v1/record-origin-statement",
        &[&body.identity],
        bytes.clone(),
    );
    assert_eq!(
        OriginStatement::parse(&signed)
            .unwrap()
            .signed()
            .body_bytes()
            .unwrap(),
        bytes
    );
    for field in ["generation", "seq", "created"] {
        let mut changed = body.clone();
        match field {
            "generation" => changed.generation = MAX_INT + 1,
            "seq" => changed.seq = MAX_INT + 1,
            _ => changed.created = MAX_TIME_MS + 1,
        }
        assert!(changed.to_json().is_err());
    }
}

#[test]
fn test_origin_object_strict_wrapper_and_nulls() {
    let snapshot = snapshot();
    let object = OriginEvidence {
        slot: snapshot.slot,
        statement: OriginStatement::sign(&snapshot.service, snapshot.body).unwrap(),
    };
    let bytes = object.to_json().unwrap();
    assert_eq!(OriginEvidence::parse(&bytes).unwrap(), object);
    for pointer in ["/slot", "/statement", "/statement/body", "/statement/sig"] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        *value.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(OriginEvidence::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    for parent in ["", "/statement"] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(0));
        assert!(OriginEvidence::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        OriginEvidence::parse(
            text.replace("\"sig\":", "\"body\":\"\",\"sig\":")
                .as_bytes()
        )
        .is_err()
    );
    let mut value: Value = serde_json::from_str(&text).unwrap();
    value["statement"].as_object_mut().unwrap().remove("sig");
    assert!(OriginEvidence::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn test_origin_component_caps_count_exact_carrying_bytes() {
    let mut signed = SignedDoc::from_parts(&[b' '; 688], &[0; 64]);
    assert_eq!(serde_json::to_vec(&signed).unwrap().len(), 1_024);
    OriginStatement::check_size(&signed).unwrap();
    check_origin_sizes(&b64(&[0; 577]), &signed).unwrap();
    assert!(OriginStatement::parse(&signed).is_err());
    signed = SignedDoc::from_parts(&[b' '; 689], &[0; 64]);
    assert_eq!(serde_json::to_vec(&signed).unwrap().len(), 1_025);
    assert!(matches!(
        OriginStatement::check_size(&signed),
        Err(SizeRefusal::TooLarge(_))
    ));
    assert!(matches!(
        check_origin_sizes(&b64(&[0; 577]), &signed),
        Err(SizeRefusal::TooLarge(_))
    ));
    let good = SignedDoc::from_parts(b"{}", &[0; 64]);
    assert!(matches!(
        check_origin_sizes(&b64(&[0; 578]), &good),
        Err(SizeRefusal::TooLarge(_))
    ));
    assert!(matches!(
        check_origin_sizes("A=", &good),
        Err(SizeRefusal::BadRequest(_))
    ));
    let bad = SignedDoc {
        body: "A=".into(),
        sig: b64(&[0; 64]),
    };
    assert!(matches!(
        OriginStatement::check_size(&bad),
        Err(SizeRefusal::BadRequest(_))
    ));
    let bad = SignedDoc {
        body: b64(b"{}"),
        sig: b64(&[0; 63]),
    };
    assert!(matches!(
        OriginStatement::check_size(&bad),
        Err(SizeRefusal::BadRequest(_))
    ));
}

#[test]
fn test_origin_maximal_canonical_statement_and_object() {
    let mut body = body();
    body.created = MAX_TIME_MS;
    body.generation = MAX_INT;
    body.seq = MAX_INT;
    assert_eq!(body.to_json().unwrap().len(), 489);
    let service = SigningKey::from_bytes(&[22; 32]);
    let statement = OriginStatement::sign(&service, body).unwrap();
    assert_eq!(serde_json::to_vec(statement.signed()).unwrap().len(), 758);
    let mut slot = slot();
    slot.parent_read_scope = Some(max_scope());
    let object = OriginEvidence { slot, statement };
    assert_eq!(object.to_json().unwrap().len(), 1_552);
    assert_eq!(
        OriginEvidence::parse(&object.to_json().unwrap()).unwrap(),
        object
    );
}

#[test]
fn test_origin_malformed_inputs_do_not_panic() {
    for len in 0..=578 {
        for byte in [0, 1, 2, 0xff] {
            assert!(OriginSlot::from_bytes(&vec![byte; len]).is_err());
        }
    }
    for bytes in [
        b"null".as_slice(),
        b"[]",
        b"{}",
        b"true",
        b"1",
        b"\xff",
        b"{",
        b"\xef\xbb\xbf{}",
    ] {
        assert!(OriginEvidence::parse(bytes).is_err());
        assert!(OriginDeclaration::parse(bytes).is_err());
        assert!(ProtectedPolicy::parse(bytes).is_err());
        assert!(ApplicationRef::parse(bytes).is_err());
    }
    assert_eq!(pubky_id(&body().identity).len(), 52);
}
