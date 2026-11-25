//! Identifier derivations and the invitation link (Dispatch wire 1.5, 1.7).

use std::collections::BTreeMap;

use pubky_dispatch_core::enc::{self, app_id, app_id_bytes, b64, hash, kid, lp, suite_kid};
use pubky_dispatch_core::ident::{self, Permanent, Policy};
use pubky_dispatch_core::labels::{derive, policy_tag};
use serde_json::{Value, json};

use crate::common::*;

const FILE: &str = "identifiers.json";

/// The invitation presented by the sender and redeemed at admission.
pub(super) struct Invite {
    pub code: String,
    pub hash: [u8; 32],
}

pub(super) fn invite(keys: &Keys) -> Invite {
    let file = load(FILE);
    let case = &file["invite_code"];
    let bytes = seed16(case, "code_seed_label");
    let code = b64(&bytes);
    let hash = ident::invite_code_hash(&code).unwrap();
    let uri = ident::invite_code_uri(&keys.identity(st(case, "account")), &code);
    generated_members(
        FILE,
        "/invite_code",
        &[
            ("code", json!(code)),
            ("code_bytes_hex", json!(hex::encode(bytes))),
            ("code_hash", json!(b64(&hash))),
            ("uri", json!(uri)),
        ],
    );
    Invite { code, hash }
}

fn policy_cases(file: &Value) -> BTreeMap<String, Policy> {
    let mut policies = BTreeMap::new();
    for (i, c) in arr(file, "policies").iter().enumerate() {
        let policy = Policy {
            read_scope: st(c, "read_scope").into(),
            write_scopes: strings(&c["write_scopes"]),
            create_scope: c.get("create_scope").map(|v| v.as_str().unwrap().into()),
            delete_scope: c.get("delete_scope").map(|v| v.as_str().unwrap().into()),
            permanent: c.get("permanent").map(|p| Permanent {
                generation: serde_json::from_value(p["generation"].clone()).unwrap(),
            }),
        };
        // Wire 1.5: "Each bracketed pair contributes two length-prefixed parts only when
        // its member is present, in the order shown."
        let count = (policy.write_scopes.len() as u64).to_be_bytes();
        let generation = policy
            .permanent
            .map(|p| p.generation.unwrap_or(0).to_be_bytes());
        let mut fields = vec![
            derive::POLICY.as_bytes(),
            policy.read_scope.as_bytes(),
            &count,
        ];
        fields.extend(policy.write_scopes.iter().map(String::as_bytes));
        for (tag, scope) in [
            (policy_tag::CREATE_SCOPE, &policy.create_scope),
            (policy_tag::DELETE_SCOPE, &policy.delete_scope),
        ] {
            if let Some(scope) = scope {
                fields.extend([tag.as_bytes(), scope.as_bytes()]);
            }
        }
        if let Some(bytes) = &generation {
            fields.extend([policy_tag::PERMANENT.as_bytes(), bytes.as_slice()]);
        }
        let bytes = lp(&fields);
        let policy_hash = policy.hash().unwrap();
        assert_eq!(hash(&bytes), policy_hash, "{}", st(c, "name"));
        generated_members(
            FILE,
            &format!("/policies/{i}"),
            &[
                ("hashed_bytes_hex", json!(hex::encode(bytes))),
                ("policy_hash", json!(b64(&policy_hash))),
            ],
        );
        if policy.write_scopes.len() > 1 {
            let mut reversed = policy.clone();
            reversed.write_scopes.reverse();
            assert!(reversed.hash().is_err());
        }
        let mut doubled = policy.clone();
        doubled
            .write_scopes
            .push(policy.write_scopes.last().unwrap().clone());
        assert!(doubled.hash().is_err());
        assert!(policies.insert(st(c, "name").to_owned(), policy).is_none());
    }
    policies
}

/// Natural keys of the sample protocol, before blinding under a record holder's naming key.
fn natural_keys<'a>(
    keys: &Keys,
    file: &'a Value,
    assignment: &[u8; 32],
    share_id: &str,
    policies: &BTreeMap<String, Policy>,
) -> BTreeMap<&'a str, Vec<u8>> {
    let shop = keys.app("shop");
    let mut naturals = BTreeMap::new();
    let records = arr(file, "record_keys");
    for c in records.iter().filter(|c| c.get("natural_from").is_none()) {
        let name = st(c, "name");
        let natural = match name {
            "task_items record of an assignment" => lp(&[&shop.identity, assignment]),
            "task_items record of a round (February)" => lp(&[
                &shop.identity,
                &super::envelopes::recurring_assignment_hash(keys),
                &int(c, "period_start").to_be_bytes(),
            ]),
            "task_items record of a task done without an assignment" => lp(&[
                &keys.identity(st(c, "account")),
                &seed16(c, "attempt_seed_label"),
            ]),
            "task_assignments record of a task done without an assignment" => {
                lp(&[st(c, "board").as_bytes(), st(c, "task").as_bytes()])
            }
            "task_lists record of the shop app" => {
                lp(&[&shop.identity, &app_id_bytes(&shop.signing_public)])
            }
            "shares record" => lp(&[&shop.identity, share_id.as_bytes()]),
            "task_assignments record of the assignment labelled team1" => {
                let input = &c["message"];
                let sender = keys.app(st(input, "sender"));
                let msg = signed_message(sender, keys.identity(st(input, "recipient")), input);
                lp(&[&sender.identity, &msg.hash()])
            }
            other => panic!("unknown natural key {other}"),
        };
        assert!(naturals.insert(name, natural).is_none());
    }
    for c in records.iter().filter(|c| c.get("natural_from").is_some()) {
        let mut natural = naturals[st(c, "natural_from")].clone();
        if st(c, "collection") == "share_counts"
            && let Some(generation) = policies[st(c, "policy")]
                .permanent
                .and_then(|p| p.generation)
        {
            natural.extend(lp(&[&generation.to_be_bytes()]));
        }
        assert!(naturals.insert(st(c, "name"), natural).is_none());
    }
    naturals
}

/// The collection, key and policy carried by a write to an existing record.
pub(super) struct RecordAddress {
    pub natural: Vec<u8>,
    pub collection: [u8; 32],
    pub key: [u8; 32],
    pub policy: Policy,
}

/// Identifier values used by the signed operation cases.
pub(super) struct Identifiers {
    pub policies: BTreeMap<String, Policy>,
    pub records: BTreeMap<String, RecordAddress>,
    pub share_id: String,
    pub invite: Invite,
}

#[test]
pub(super) fn test_vectors_identifiers() {
    identifier_cases(&keys());
}

/// Derive and check the identifiers before handing them to the operation writers.
pub(super) fn identifier_cases(keys: &Keys) -> Identifiers {
    let v = load(FILE);
    super::generation::check_annotations(FILE, &v);
    for (i, c) in arr(&v, "app_id").iter().enumerate() {
        let public = keys.app(st(c, "name")).signing_public;
        generated_members(
            FILE,
            &format!("/app_id/{i}"),
            &[
                ("signing_public", json!(b64(&public))),
                ("blake3_hex", json!(hex::encode(hash(&public)))),
                (
                    "app_id_bytes_hex",
                    json!(hex::encode(app_id_bytes(&public))),
                ),
                ("app_id", json!(app_id(&public))),
            ],
        );
    }
    for (i, c) in arr(&v, "kid").iter().enumerate() {
        let (app, key) = st(c, "name").split_once(' ').unwrap();
        let app = keys.app(app);
        let public = match key {
            "receive key" => app.receive_public,
            "bundle key" => app.bundle_public,
            other => panic!("unknown X25519 key {other}"),
        };
        generated_members(
            FILE,
            &format!("/kid/{i}"),
            &[
                ("x25519_public", json!(b64(&public))),
                (
                    "derive_hex",
                    json!(hex::encode(enc::derive(derive::KID, &[&public]))),
                ),
                ("kid", json!(b64(&kid(&public)))),
            ],
        );
        assert_eq!(
            suite_kid(2, &public).as_slice(),
            &enc::derive(derive::KID, &[&2u64.to_be_bytes(), &public])[..8]
        );
        assert_ne!(suite_kid(2, &public), kid(&public));
        assert_ne!(suite_kid(2, &public), suite_kid(3, &public));
    }
    let policies = policy_cases(&v);
    let assignment = super::sealed::assignment(keys).hash();
    let share = arr(&v, "record_keys")
        .iter()
        .find(|c| c["name"] == "shares record")
        .unwrap();
    let share_id = uuid_from_seed(st(share, "share_seed_label"));
    let naturals = natural_keys(keys, &v, &assignment, &share_id, &policies);
    let mut records = BTreeMap::new();
    for (i, c) in arr(&v, "blinded_inputs").iter().enumerate() {
        let holder = keys.identity(st(c, "account"));
        let naming = keys.naming(&holder);
        let input: &[u8] = match st(c, "name") {
            "counterparty identity" => &keys.app("shop").identity,
            "assignment hash" => &assignment,
            name => &naturals[name.strip_prefix("natural key of the ").expect(name)],
        };
        generated_members(
            FILE,
            &format!("/blinded_inputs/{i}"),
            &[
                ("identity", json!(enc::pubky_id(&holder))),
                ("input_hex", json!(hex::encode(input))),
                ("naming_key", json!(b64(&naming.to_bytes()))),
                (
                    "key_material_hex",
                    json!(hex::encode(lp(&[&naming.to_bytes(), input]))),
                ),
                ("blinded", json!(b64(&naming.blind(input)))),
            ],
        );
    }
    for (i, c) in arr(&v, "collections").iter().enumerate() {
        let identity = keys.identity(st(c, "account"));
        generated_members(
            FILE,
            &format!("/collections/{i}"),
            &[
                ("identity", json!(enc::pubky_id(&identity))),
                (
                    "collection_id",
                    json!(b64(&ident::collection_id(st(c, "name"), &identity))),
                ),
            ],
        );
    }
    for (i, c) in arr(&v, "record_keys").iter().enumerate() {
        let name = st(c, "name");
        let holder = keys.identity(st(c, "account"));
        let natural = &naturals[name];
        let policy = &policies[st(c, "policy")];
        let policy_hash = policy.hash().unwrap();
        let (collection_id, key, inputs) = record_address(keys, &holder, name, natural, policy);
        records.insert(
            name.to_owned(),
            RecordAddress {
                natural: natural.clone(),
                collection: collection_id,
                key,
                policy: policy.clone(),
            },
        );
        let collection = inputs.collection.as_bytes();
        let path = format!("/record_keys/{i}");
        generated_members(
            FILE,
            &path,
            &[
                ("identity", json!(enc::pubky_id(&holder))),
                ("natural_key", json!(b64(natural))),
                ("natural_key_hex", json!(hex::encode(natural))),
                ("blinded_natural_key", json!(b64(&inputs.blinded_key))),
                ("policy_hash", json!(b64(&policy_hash))),
                (
                    "key_material_hex",
                    json!(hex::encode(lp(&[
                        collection,
                        &inputs.blinded_key,
                        &policy_hash
                    ]))),
                ),
                ("record_key", json!(b64(&key))),
            ],
        );
        for other in keys.identities.values().filter(|i| **i != holder) {
            let (_, other_key, _) = record_address(keys, other, name, natural, policy);
            assert_ne!(other_key, key);
        }
    }
    Identifiers {
        policies,
        records,
        share_id,
        invite: invite(keys),
    }
}
