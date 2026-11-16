//! Generate and check the signed dependencies of record applications (Switch wire 6.5).

use ed25519_dalek::SigningKey;
use pubky_switch_core::chain::{ProofBody, SignedHead, Stub, TransitionProof};
use pubky_switch_core::enc::{b64 as b64e, hash, pubky_id};
use pubky_switch_core::export::{
    ChunkAnswer, DEFAULT_CHUNK_TARGET, Manifest, ManifestBody, Part, pack,
};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::ops::{
    Condition, OpKind, RecordVersion, SignedOp, StateAfter, check_shape, proof_state,
};
use pubky_switch_core::records::ExportTransfer;
use pubky_switch_core::sig::{self, SignedDoc};
use pubky_switch_core::{http, labels};
use serde_json::{Value, json};

use super::common::*;

fn signed(value: &Value) -> SignedDoc {
    serde_json::from_value(value.clone()).unwrap()
}

/// Rebuild a record proof from the signed item and its exact chain stub.
fn record_proof(item: &Value, keys: &Keys) -> TransitionProof {
    let raw: Value = signed(&item["item"]).peek().unwrap();
    let writer = keys.app_by_id(st(&raw, "app_id"));
    let op = SignedOp::verify(
        &signed(&item["item"]),
        &writer.signing_public,
        &writer.identity,
        Some(&pubky_switch_core::enc::app_id_decode(&writer.app_id).unwrap()),
    )
    .unwrap();
    let stub = Stub::from_value(&item["stub"]).unwrap();
    let env = stub.open().unwrap();
    assert_eq!(op.item_hash().unwrap(), env.item_hash);
    let state = proof_state(
        &op,
        &StateAfter::Record(RecordVersion::new(env.generation, env.seq)),
    )
    .unwrap();
    let object = op
        .body()
        .kind
        .proof_object(op.body().app_id.as_ref())
        .unwrap();
    let key = keys.service_key(&pubky_id(&writer.identity));
    TransitionProof::sign(
        &SigningKey::from_bytes(&keys.secret(&key).unwrap()),
        &writer.identity,
        ProofBody::new(stub, object, &state),
    )
    .unwrap()
}

fn proof_case(mut case: Value, proof: &TransitionProof) -> Value {
    case["body"] = String::from_utf8(proof.signed().body_bytes().unwrap())
        .unwrap()
        .into();
    case["signed"] = json!(proof.signed());
    case
}

/// The replacement is the output of the core's producer, including its signature.
fn replace_proofs(value: &mut Value, replacements: &[(Value, Value)]) {
    if let Some((_, new)) = replacements.iter().find(|(old, _)| value == old) {
        *value = new.clone();
        return;
    }
    match value {
        Value::Array(values) => values
            .iter_mut()
            .for_each(|v| replace_proofs(v, replacements)),
        Value::Object(values) => values
            .values_mut()
            .for_each(|v| replace_proofs(v, replacements)),
        _ => {}
    }
}

fn chain_cases(keys: &Keys) -> Vec<(Value, Value)> {
    let chain = load("chain.json");
    let mut replacements = Vec::new();
    for (i, case) in arr(&chain, "transition_proofs").iter().enumerate() {
        let proof = TransitionProof::peek(&signed(&case["signed"])).unwrap();
        let item = arr(&chain, "items")
            .iter()
            .find(|i| int(i, "seq") == proof.envelope().seq)
            .unwrap();
        let Ok(op) = SignedOp::peek(&signed(&item["item"])) else {
            continue;
        };
        if !matches!(op.body().kind, OpKind::RecordPut(_)) {
            continue;
        }
        let new = record_proof(item, keys);
        replacements.push((case["signed"].clone(), json!(new.signed())));
        let path = format!("/transition_proofs/{i}");
        generated(
            "chain.json",
            &[(Place::Element(&path), proof_case(case.clone(), &new))],
        );
    }
    let delete = &chain["record_delete"];
    let proof = record_proof(&delete["item"], keys);
    replacements.push((
        delete["transition_proof"]["signed"].clone(),
        json!(proof.signed()),
    ));
    generated(
        "chain.json",
        &[(
            Place::Element("/record_delete/transition_proof"),
            proof_case(delete["transition_proof"].clone(), &proof),
        )],
    );
    replacements
}

fn export_cases(keys: &Keys, replacements: &[(Value, Value)]) -> ChunkAnswer {
    let file = load("export.json");
    let old = Manifest::verify(
        &signed(&file["manifest"]["signed"]),
        &b64n(st(&file, "service_key")),
        &keys.identity("alice"),
    )
    .unwrap();
    let mut chunk: Value = serde_json::from_str(st(&file["chunks"][0], "json")).unwrap();
    replace_proofs(&mut chunk, replacements);
    let parts: Vec<Part> = arr(&chunk, "parts")
        .iter()
        .map(|p| Part::read(p).unwrap())
        .collect();
    let packed = pack(&parts, DEFAULT_CHUNK_TARGET).unwrap();
    assert_eq!(packed.len(), 1);
    let m = old.body();
    let body = ManifestBody::new(
        m.identity,
        m.freeze_hash,
        m.generation,
        m.last_time,
        m.head,
        m.checkpoint,
        packed.iter().map(|(r, _)| r.clone()).collect(),
    )
    .unwrap();
    let key = SigningKey::from_bytes(&keys.secret(&b64n(st(&file, "service_key"))).unwrap());
    let manifest = Manifest::sign(&key, body).unwrap();
    let mut entry = file["manifest"].clone();
    entry["body"] = String::from_utf8(manifest.signed().body_bytes().unwrap())
        .unwrap()
        .into();
    entry["signed"] = json!(manifest.signed());
    entry["compact"] = manifest.signed().compact().into();
    entry["doc_bytes_hex"] = hex::encode(manifest.signed().doc_bytes().unwrap()).into();
    entry["doc_hash"] = b64e(&manifest.hash()).into();
    let bytes = &packed[0].1;
    let chunk_case = json!({"id": packed[0].0.id, "json": String::from_utf8(bytes.clone()).unwrap(),
        "len": bytes.len(), "hash": b64e(&hash(bytes))});
    generated(
        "export.json",
        &[
            (Place::Element("/manifest"), entry),
            (Place::Element("/chunks/0"), chunk_case),
        ],
    );
    let record = arr(&chunk, "parts")
        .iter()
        .find(|p| p["part"] == "record")
        .unwrap()["record"]
        .clone();
    let current = TransitionProof::peek(&signed(&record["proof"])).unwrap();
    let other_key = SigningKey::from_bytes(
        &keys
            .secret(&keys.service_key(&pubky_id(&keys.identity("bob"))))
            .unwrap(),
    );
    let wrong_signature =
        TransitionProof::sign(&other_key, &keys.identity("alice"), current.body().clone()).unwrap();
    let create = record_proof(
        &arr(&load("chain.json"), "items")
            .iter()
            .find(|p| int(p, "seq") == 6)
            .unwrap()
            .clone(),
        keys,
    );
    for (i, case) in arr(&file, "record_rejections").iter().enumerate() {
        let mut case = case.clone();
        case["record"] = record.clone();
        case["record"]["proof"] = match st(&case, "name") {
            "no proof" => Value::Null,
            "a proof whose signature doesn't verify with O's key" => {
                json!(wrong_signature.signed())
            }
            "the proof of another write, the record's first (seq 6)" => json!(create.signed()),
            name => panic!("unrecognized record case: {name}"),
        };
        generated(
            "export.json",
            &[(Place::Element(&format!("/record_rejections/{i}")), case)],
        );
    }
    ChunkAnswer {
        id: packed[0].0.id.clone(),
        data: bytes.clone(),
    }
}

fn signed_fields(keys: &Keys, mut case: Value, fields: Vec<Vec<u8>>) -> Value {
    let public = b64n::<32>(st(&case, "public_key"));
    let key = SigningKey::from_bytes(&keys.secret(&public).unwrap());
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let label = st(&case, "label").to_owned();
    let signature = sig::sign(&key, &label, &refs);
    assert_eq!(arr(&case, "fields").len(), fields.len());
    for (field, bytes) in case["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip(&fields)
    {
        field["hex"] = hex::encode(bytes).into();
    }
    case["signature"] = b64e(&signature).into();
    case["signed_bytes_hex"] = hex::encode(sig::signed_bytes(&label, &refs)).into();
    if case.get("headers").is_some() {
        case["headers"][http::header::SIGNATURE] = b64e(&signature).into();
    }
    case
}

fn transfer_cases(keys: &Keys) {
    let documents = load("documents.json");
    let (index, old) = arr(&documents, "documents")
        .iter()
        .enumerate()
        .find(|(_, d)| st(d, "name") == "alice export transfer, for export.json's manifest")
        .unwrap();
    let identity = keys.identity("alice");
    let transfer = ExportTransfer::verify(&signed(&old["signed"]), &identity).unwrap();
    let mut body = transfer.body().clone();
    body.manifest_hash = b64n(st(&load("export.json")["manifest"], "doc_hash"));
    let transfer = ExportTransfer::sign(
        &IdentityKey::from_secret(keys.identity_secrets[&identity]),
        body,
    )
    .unwrap();
    let mut case = old.clone();
    case["body"] = String::from_utf8(transfer.signed().body_bytes().unwrap())
        .unwrap()
        .into();
    case["signed"] = json!(transfer.signed());
    case["compact"] = transfer.signed().compact().into();
    case["doc_bytes_hex"] = hex::encode(transfer.signed().doc_bytes().unwrap()).into();
    case["doc_hash"] = b64e(&transfer.signed().doc_hash().unwrap()).into();
    generated(
        "documents.json",
        &[(Place::Element(&format!("/documents/{index}")), case)],
    );
    let file = load("http.json");
    for (i, case) in arr(&file, "requests").iter().enumerate() {
        if case["headers"].get(http::header::TRANSFER).is_none() {
            continue;
        }
        let mut case = case.clone();
        case["headers"][http::header::TRANSFER] = transfer.signed().compact().into();
        let bytes = b64(st(&case, "body_b64"));
        let target = http::RequestTarget {
            method: st(&case, "method"),
            path_and_query: st(&case, "path"),
            body: &bytes,
            origin: st(&case, "origin"),
        };
        let headers = http::TransferHeaders {
            timestamp: st(&case["headers"], http::header::TIMESTAMP).into(),
            identity: st(&case["headers"], http::header::IDENTITY).into(),
            transfer: transfer.signed().compact(),
        };
        let fields = http::transfer_request_fields(&target, &headers);
        generated(
            "http.json",
            &[(
                Place::Element(&format!("/requests/{i}")),
                signed_fields(keys, case, fields),
            )],
        );
    }
    let signatures = load("signatures.json");
    for (i, case) in arr(&signatures, "signatures").iter().enumerate() {
        let fields = match st(case, "label") {
            labels::sig::EXPORT_MANIFEST => vec![
                identity.to_vec(),
                st(&load("export.json")["manifest"], "body")
                    .as_bytes()
                    .to_vec(),
            ],
            labels::sig::EXPORT_TRANSFER => {
                vec![transfer.signed().body_bytes().unwrap()]
            }
            labels::sig::TRANSFER_REQUEST => {
                let file = load("http.json");
                let request = arr(&file, "requests")
                    .iter()
                    .find(|r| r["label"] == labels::sig::TRANSFER_REQUEST)
                    .unwrap();
                arr(request, "fields")
                    .iter()
                    .map(|f| hx(st(f, "hex")))
                    .collect()
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
}

fn ordered_object(fields: Vec<(&str, String)>) -> String {
    let members: Vec<_> = fields
        .into_iter()
        .map(|(name, value)| format!("{}:{value}", serde_json::to_string(name).unwrap()))
        .collect();
    format!("{{{}}}", members.join(","))
}

/// Feed members follow wire 7.4.4; signed documents, stubs and heads use core encoders.
fn feed_page(page: &Value) -> String {
    let items: Vec<_> = arr(page, "items")
        .iter()
        .map(|item| {
            let order: &[&str] = match st(item, "type") {
                "entry" => &[
                    "type",
                    "seq",
                    "entry_id",
                    "sender",
                    "cert",
                    "accepted_at",
                    "context",
                    "envelope",
                ],
                "chain" => &[
                    "type",
                    "seq",
                    "stub",
                    "item_type",
                    "item",
                    "context",
                    "proof",
                ],
                "stub" => &["type", "seq", "stub"],
                kind => panic!("unrecognized feed fixture item: {kind}"),
            };
            let fields: Vec<_> = order
                .iter()
                .filter_map(|name| {
                    item.get(*name).map(|value| {
                        let text = match *name {
                            "stub" => String::from_utf8(Stub::from_value(value).unwrap().to_json())
                                .unwrap(),
                            "cert" | "item" | "proof" => {
                                serde_json::to_string(&signed(value)).unwrap()
                            }
                            _ => serde_json::to_string(value).unwrap(),
                        };
                        (*name, text)
                    })
                })
                .collect();
            assert_eq!(fields.len(), item.as_object().unwrap().len());
            ordered_object(fields)
        })
        .collect();
    let text = ordered_object(vec![
        ("items", format!("[{}]", items.join(","))),
        ("next", serde_json::to_string(&page["next"]).unwrap()),
        (
            "scanned_through",
            serde_json::to_string(&page["scanned_through"]).unwrap(),
        ),
        ("more", serde_json::to_string(&page["more"]).unwrap()),
        ("cursor", serde_json::to_string(&page["cursor"]).unwrap()),
        (
            "head",
            String::from_utf8(SignedHead::from_value(&page["head"]).unwrap().to_json()).unwrap(),
        ),
    ]);
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), *page);
    text
}

/// Write answers retain the member order of wire 7.1.
fn write_answer(body: &Value) -> String {
    let proofs: Vec<SignedDoc> = arr(body, "proofs").iter().map(signed).collect();
    let text = ordered_object(vec![
        ("proofs", serde_json::to_string(&proofs).unwrap()),
        (
            "head",
            String::from_utf8(SignedHead::from_value(&body["head"]).unwrap().to_json()).unwrap(),
        ),
    ]);
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), *body);
    text
}

fn http_cases(keys: &Keys, replacements: &[(Value, Value)], chunk: &ChunkAnswer) {
    let file = load("http.json");
    for (i, case) in arr(&file, "responses").iter().enumerate() {
        let mut body: Value = serde_json::from_str(st(case, "body")).unwrap();
        let old = body.clone();
        replace_proofs(&mut body, replacements);
        let text = if st(case, "name").contains("the export chunk") {
            String::from_utf8(chunk.to_json()).unwrap()
        } else if st(case, "name").contains("feed page") {
            feed_page(&body)
        } else if body.get("proofs").is_some() {
            write_answer(&body)
        } else {
            assert_eq!(body, old, "unhandled signed response dependency");
            st(case, "body").to_owned()
        };
        let mut new = case.clone();
        new["body"] = text.into();
        let new = super::http::signed_case(keys, &file, new);
        generated(
            "http.json",
            &[(Place::Element(&format!("/responses/{i}")), new)],
        );
    }
}

fn condition_case(keys: &Keys) {
    let chain = load("chain.json");
    let item = arr(&chain, "items")
        .iter()
        .find(|i| int(i, "seq") == 8)
        .unwrap();
    let op = SignedOp::peek(&signed(&item["item"])).unwrap();
    let proof = record_proof(item, keys);
    let mut body = op.body().clone();
    let OpKind::RecordPut(put) = &mut body.kind else {
        panic!("record operation")
    };
    put.expected_version = RecordVersion::new(1, 8);
    body.conditions = vec![Condition::RecordCurrent {
        key: put.key,
        lineage_id: None,
        revision: proof.record_revision().unwrap(),
        deleted: false,
    }];
    body.batch.id = [70; 16];
    body.batch.count = 1;
    let wallet = keys.app("wallet");
    let op = SignedOp::sign(
        &AppKeys::from_secrets(wallet.signing_secret, wallet.bundle_secret),
        body,
    )
    .unwrap();
    check_shape(op.body()).unwrap();
    let case = json!({"body": String::from_utf8(op.signed().body_bytes().unwrap()).unwrap(),
        "name": "record.put guarded by its current application", "signed": op.signed(), "writer": "wallet"});
    generated(
        "operations.json",
        &[(Place::Member("/record_current"), case)],
    );
    let value = load("operations.json");
    let read = SignedOp::verify(
        &signed(&value["record_current"]["signed"]),
        &wallet.signing_public,
        &wallet.identity,
        Some(&pubky_switch_core::enc::app_id_decode(&wallet.app_id).unwrap()),
    )
    .unwrap();
    assert_eq!(read, op);
}

#[test]
fn test_vectors_record_current_dependencies() {
    let keys = keys();
    let replacements = chain_cases(&keys);
    let chunk = export_cases(&keys, &replacements);
    transfer_cases(&keys);
    http_cases(&keys, &replacements, &chunk);
    condition_case(&keys);
}
