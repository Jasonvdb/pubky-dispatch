//! Record addresses and the signed cases that refer to them (Switch wire 1.5, 6.2, 6.6).

use ed25519_dalek::SigningKey;
use pubky_switch_core::chain::{ChainTip, SignedHead, Stub, TransitionProof, ZERO_HASH, item_hash};
use pubky_switch_core::enc::{b64 as encode, pubky_id};
use pubky_switch_core::ident::collection_id;
use pubky_switch_core::keys::IdentityKey;
use pubky_switch_core::labels;
use pubky_switch_core::ops::{OpBody, SignedOp};
use pubky_switch_core::sealed::{RecordValue, SealedValue, aad};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Value, json};

use super::common::*;
use super::record_current::{record_proof, signed, signed_fields};

const ITEM: &str = "task_items record of an assignment";
const RUN: &str = "share_runs record";

fn address<'a>(ids: &'a Value, name: &str) -> &'a Value {
    arr(ids, "record_keys")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()
}

fn sealed_cases(ids: &Value) {
    for (i, case) in arr(&load("sealed.json"), "cases").iter().enumerate() {
        let name = match st(case, "name") {
            "task_items record of an assignment" | "delete marker" => ITEM,
            "task_lists record" => "task_lists record of the shop app",
            name => panic!("unknown sealed case {name}"),
        };
        let key = b64n(st(address(ids, name), "record_key"));
        let identity = hx32(st(case, "identity_hex"));
        let scope = st(case, "scope");
        let nonce = hx(st(case, "nonce_hex")).try_into().unwrap();
        let value = SealedValue::seal_with_nonce(
            &hx32(st(case, "scope_key_hex")),
            &identity,
            int(case, "data_epoch"),
            scope,
            &key,
            st(case, "plaintext").as_bytes(),
            &nonce,
        )
        .unwrap();
        let mut new = case.clone();
        new["record_key"] = json!(encode(&key));
        new["aad_hex"] = json!(hex::encode(aad(&identity, scope, &key)));
        new["sealed"] = json!(value);
        generated(
            "sealed.json",
            &[(Place::Element(&format!("/cases/{i}")), new)],
        );
    }
}

fn operation_cases(keys: &Keys, ids: &Value) -> Vec<(Value, Value)> {
    let file = load("operations.json");
    let mut documents = Vec::new();
    for case in arr(&file, "operations") {
        let mut raw: Value = serde_json::from_str(st(case, "body")).unwrap();
        let name = st(case, "name");
        let record = raw["op"] == "record.put";
        let conditional = raw["conditions"]
            .as_array()
            .is_some_and(|conditions| conditions.iter().any(|c| c.get("record_version").is_some()));
        if !record && !conditional {
            continue;
        }
        let writer = keys.app(st(case, "writer"));
        let id = &writer.identity;
        let signer = SigningKey::from_bytes(&writer.signing_secret);
        if let Some(conditions) = raw.get_mut("conditions").and_then(Value::as_array_mut) {
            for condition in conditions {
                if let Some(version) = condition.get_mut("record_version") {
                    let target = if name == "executor batch: share_runs record.put" {
                        "shares record"
                    } else {
                        ITEM
                    };
                    version["key"] = address(ids, target)["record_key"].clone();
                }
            }
        }
        if record {
            let target = if name == "executor batch: share_runs record.put" {
                RUN
            } else {
                ITEM
            };
            let case = address(ids, target);
            let collection = collection_id(id, &keys.naming(id), st(case, "collection"));
            let key = b64n(st(case, "record_key"));
            let sealed: SealedValue = serde_json::from_value(raw["value_sealed"].clone()).unwrap();
            let scope_key = IdentityKey::from_secret(keys.identity_secrets[id])
                .scope_key(sealed.data_epoch, &sealed.scope);
            let plaintext = match sealed.open(&scope_key, id, &b64n(st(&raw, "key"))).unwrap() {
                RecordValue::Json(bytes) => bytes,
                RecordValue::Delete => Vec::new(),
            };
            raw["collection"] = json!(encode(&collection));
            raw["key"] = json!(encode(&key));
            raw["id_inputs"] = json!({"blinded_key": case["blinded_natural_key"]});
            raw["value_sealed"] = json!(
                SealedValue::seal_with_nonce(
                    &scope_key,
                    id,
                    sealed.data_epoch,
                    &sealed.scope,
                    &key,
                    &plaintext,
                    &sealed.nonce
                )
                .unwrap()
            );
        }
        let body = OpBody::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
        let op = SignedOp::sign(&signer, body).unwrap();
        pubky_switch_core::ops::check_shape(op.body()).unwrap();
        let mut new = case.clone();
        new["body"] = json!(String::from_utf8(op.signed().body_bytes().unwrap()).unwrap());
        new["signed"] = json!(op.signed());
        documents.push((case["signed"].clone(), new["signed"].clone()));
        generated("operations.json", &[(Place::Case("/operations"), new)]);
    }
    rejection_cases(keys);
    documents
}

fn rejection_cases(keys: &Keys) {
    let file = load("operations.json");
    for group in ["unknown_members", "integer_bounds"] {
        for case in arr(&file[group], "cases") {
            let base = arr(&file, "operations")
                .iter()
                .find(|op| op["name"] == case["based_on"])
                .unwrap();
            let writer = st(case, "writer");
            if base["name"] == "app.put" || base["name"] == "key_bundle.put" {
                continue;
            }
            let base = st(base, "body");
            let body = if group == "unknown_members" {
                let mut raw: Value = serde_json::from_str(base).unwrap();
                let mut at = &mut raw;
                for part in st(case, "member").split('.') {
                    at = if let Ok(i) = part.parse::<usize>() {
                        &mut at[i]
                    } else {
                        &mut at[part]
                    };
                }
                *at = json!(1);
                serde_json::to_string(&raw).unwrap()
            } else {
                let field = "\"orphan_after\":86400";
                assert!(base.contains(field));
                base.replace(field, &format!("\"orphan_after\":{}", st(case, "number")))
            };
            let app = keys.app(writer);
            let signed = SignedDoc::sign_bytes(
                &SigningKey::from_bytes(&app.signing_secret),
                labels::sig::OP,
                &[&app.identity],
                body.as_bytes().to_vec(),
            );
            let mut new = case.clone();
            new["signed"] = json!(signed);
            new["body"] = json!(body);
            generated(
                "operations.json",
                &[(Place::Case(&format!("/{group}/cases")), new)],
            );
        }
    }
}

/// Rebuild one sequence using the fixture's times and sequence numbers (Switch wire 6.6).
fn chain_rows(
    rows: &mut [Value],
    mut previous: [u8; 32],
    replacements: &[(Value, Value)],
) -> [u8; 32] {
    for row in rows {
        let mut env = Stub::from_value(&row["stub"]).unwrap().open().unwrap();
        if let Some((_, new)) = replacements.iter().find(|(old, _)| old == &row["item"]) {
            row["item"] = new.clone();
        }
        let bytes = signed(&row["item"]).doc_bytes().unwrap();
        env.prev_chain_hash = previous;
        env.item_hash = item_hash(env.item_type, &bytes);
        let stub = Stub::of(&env);
        if row.get("item_hash").is_some() {
            row["item_hash"] = json!(encode(&env.item_hash));
            row["prev_chain_hash"] = json!(encode(&previous));
            row["chain_hash"] = json!(encode(&stub.chain_hash));
            row["envelope_json"] = json!(String::from_utf8(env.to_json()).unwrap());
        }
        if row.get("item_bytes_hex").is_some() {
            row["item_bytes_hex"] = json!(hex::encode(bytes));
        }
        row["stub"] = stub.to_value();
        previous = stub.chain_hash;
    }
    previous
}

fn head(keys: &Keys, stub: &Value) -> SignedHead {
    let id = keys.identity("alice");
    let service = SigningKey::from_bytes(&keys.secret(&keys.service_key(&pubky_id(&id))).unwrap());
    let stub = Stub::from_value(stub).unwrap();
    let env = stub.open().unwrap();
    SignedHead::sign(
        &service,
        &id,
        &ChainTip {
            generation: env.generation,
            seq: env.seq,
            chain_hash: stub.chain_hash,
        },
    )
}

/// Bind the same transition state to its rebuilt chain stub (Switch wire 6.5).
pub(super) fn proof_at(keys: &Keys, doc: &Value, stub: &Value) -> TransitionProof {
    let id = keys.identity("alice");
    let service = SigningKey::from_bytes(&keys.secret(&keys.service_key(&pubky_id(&id))).unwrap());
    let mut body = TransitionProof::peek(&signed(doc)).unwrap().body().clone();
    body.chain = Stub::from_value(stub).unwrap();
    TransitionProof::sign(&service, &id, body).unwrap()
}

/// Rebuild the independent chain histories and all receipts over their changed prefixes.
pub(super) fn base_cases(keys: &Keys) -> Vec<(Value, Value)> {
    let ids = load("identifiers.json");
    sealed_cases(&ids);
    let mut replacements = operation_cases(keys, &ids);
    let file = load("chain.json");
    let mut items = arr(&file, "items").to_vec();
    let end = chain_rows(&mut items, ZERO_HASH, &replacements);
    for (old, new) in arr(&file, "items").iter().zip(&items) {
        replacements.push((old["stub"].clone(), new["stub"].clone()));
    }
    generated("chain.json", &[(Place::Member("/items"), json!(items))]);

    for (i, case) in arr(&file, "transition_proofs").iter().enumerate() {
        let seq = TransitionProof::peek(&signed(&case["signed"]))
            .unwrap()
            .envelope()
            .seq;
        let item = items.iter().find(|it| it["seq"] == seq).unwrap();
        let proof = if matches!(seq, 6 | 8) {
            record_proof(item, keys)
        } else {
            proof_at(keys, &case["signed"], &item["stub"])
        };
        let mut new = case.clone();
        new["signed"] = json!(proof.signed());
        new["body"] = json!(String::from_utf8(proof.signed().body_bytes().unwrap()).unwrap());
        replacements.push((case["signed"].clone(), new["signed"].clone()));
        generated(
            "chain.json",
            &[(Place::Element(&format!("/transition_proofs/{i}")), new)],
        );
    }
    for (i, case) in arr(&file, "signed_heads").iter().enumerate() {
        let item = items
            .iter()
            .find(|it| it["seq"] == case["head"]["seq"])
            .unwrap();
        let new = head(keys, &item["stub"]);
        replacements.extend([
            (case["head"].clone(), new.to_value()),
            (case["switch_head_header"].clone(), json!(new.to_header())),
        ]);
        generated(
            "chain.json",
            &[(
                Place::Element(&format!("/signed_heads/{i}")),
                json!({"head": new.to_value(), "switch_head_header":new.to_header()}),
            )],
        );
    }
    for group in ["rejections", "batch_id_window"] {
        for (i, case) in arr(&file, group).iter().enumerate() {
            let mut case = case.clone();
            let Some(rows) = case["items"].as_array_mut() else {
                continue;
            };
            chain_rows(rows, ZERO_HASH, &replacements);
            let stubs: Vec<_> = rows.iter().map(|r| r["stub"].clone()).collect();
            case["stubs"] = json!(stubs);
            generated(
                "chain.json",
                &[(Place::Element(&format!("/{group}/{i}")), case)],
            );
        }
    }
    let mut peers = file["peer_admission"].clone();
    let rows = peers["items"].as_array_mut().unwrap();
    chain_rows(rows, end, &replacements);
    for row in &mut *rows {
        if let Some(doc) = row.get("proof") {
            row["proof"] = json!(proof_at(keys, doc, &row["stub"]).signed());
        }
    }
    let new = head(keys, &rows.last().unwrap()["stub"]);
    let old = SignedHead::from_value(&peers["head"]).unwrap();
    replacements.push((json!(old.to_header()), json!(new.to_header())));
    peers["head"] = new.to_value();
    generated("chain.json", &[(Place::Member("/peer_admission"), peers)]);

    let identity = keys.identity("alice").to_vec();
    let proofs = load("chain.json");
    for (i, case) in arr(&load("signatures.json"), "signatures")
        .iter()
        .enumerate()
    {
        let fields = match st(case, "label") {
            labels::sig::OP => vec![
                identity.clone(),
                signed(&items.iter().find(|it| it["seq"] == 7).unwrap()["item"])
                    .body_bytes()
                    .unwrap(),
            ],
            labels::sig::PROOF => {
                let proof = arr(&proofs, "transition_proofs")
                    .iter()
                    .find(|p| st(p, "name") == "claim attempt (seq 7)")
                    .unwrap();
                vec![identity.clone(), st(proof, "body").as_bytes().to_vec()]
            }
            labels::sig::HEAD => {
                let h = head(keys, &items.last().unwrap()["stub"]);
                vec![
                    identity.clone(),
                    h.chain_version.to_be_bytes().to_vec(),
                    h.generation.to_be_bytes().to_vec(),
                    h.seq.to_be_bytes().to_vec(),
                    h.chain_hash.to_vec(),
                ]
            }
            _ => continue,
        };
        generated(
            "signatures.json",
            &[(
                Place::Element(&format!("/signatures/{i}")),
                signed_fields(keys, case.clone(), fields),
            )],
        );
    }
    replacements
}
