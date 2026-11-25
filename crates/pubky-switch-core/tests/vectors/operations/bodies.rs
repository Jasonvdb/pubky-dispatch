//! The signed operations that continue the registration, assignment and first attempt.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use pubky_switch_core::admission::PeerReason;
use pubky_switch_core::claims::{Basis, ClaimEntry, EntryKind};
use pubky_switch_core::enc;
use pubky_switch_core::message::MessagePlaintext;
use pubky_switch_core::ops::{
    BatchRef, Condition, InviteCodePut, KeyBundlePut, OpBody, OpKind, RecordPut, RecordVersion,
    SignedOp,
};
use pubky_switch_core::records::AppCert;
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Value, json};

use super::{RecordCases, emit_signed, writer_of};
use crate::chain::{Chain, record_message, stored_message};
use crate::common::*;
use crate::identifiers::Identifiers;

struct Evidence<'a> {
    sender: &'a AppKeys,
    id: String,
    plaintext: MessagePlaintext,
    hash: [u8; 32],
}

/// Message references and opaque body members name earlier messages by their fixture names.
fn evidence_messages<'a>(
    keys: &'a Keys,
    file: &Value,
    assignment: [u8; 32],
) -> HashMap<String, Evidence<'a>> {
    let mut hashes = HashMap::from([("assignment", assignment)]);
    let mut messages = HashMap::new();
    for c in arr(file, "messages") {
        let name = st(c, "name");
        let sender = keys.app(st(c, "sender"));
        let refs = strings(&c["refs"])
            .iter()
            .map(|r| hashes[r.as_str()])
            .collect();
        let body = c["body_refs"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(member, source)| {
                (
                    member.clone(),
                    json!(enc::b64(&hashes[source.as_str().unwrap()])),
                )
            })
            .collect();
        let (id, plaintext) =
            record_message(c, sender, keys.identity(st(c, "recipient")), refs, body);
        let hash = plaintext.hash();
        assert!(hashes.insert(name, hash).is_none(), "{name}");
        messages.insert(
            name.to_owned(),
            Evidence {
                sender,
                id,
                plaintext,
                hash,
            },
        );
    }
    messages
}

fn claim(op: &SignedOp) -> ClaimEntry {
    let OpKind::Claim(fields) = &op.body().kind else {
        panic!("expected claim")
    };
    fields.check().unwrap()
}

fn record(op: &SignedOp) -> &RecordPut {
    let OpKind::RecordPut(put) = &op.body().kind else {
        panic!("expected record")
    };
    put
}

fn share_run(
    ids: &Identifiers,
    records: &RecordCases<'_>,
    case: &Value,
    attempt: ClaimEntry,
) -> (OpKind, Vec<Condition>) {
    let address = &ids.records[st(case, "record_name")];
    let generation = records.create.generation;
    let version = |member| RecordVersion::new(generation, int(case, member));
    let start = time_of(case, "start");
    let conditions = vec![
        Condition::RecordVersion {
            key: ids.records[st(case, "condition_record")].key,
            version: version("condition_version"),
        },
        Condition::ServerTimeIn {
            start: Some(start),
            end: Some(time_of(case, "end")),
        },
    ];
    let value = json!({
        "v": int(case, "record_version"),
        "counterparty": enc::pubky_id(&records.keys.identity(st(case, "counterparty"))),
        "share_id": ids.share_id,
        "runs": [{
            "claim": enc::b64(&attempt.claim_key),
            "attempt_id": enc::b64(&attempt.attempt_id),
            "at": pubky_switch_core::time::rfc3339(start),
            "outcome": case.get("outcome").unwrap(),
        }],
    });
    let mut put = records.put();
    put.key = address.key;
    put.collection = address.collection;
    put.policy = address.policy.clone();
    put.value_sealed.scope.clone_from(&put.policy.read_scope);
    put.expected_version = version("previous_version");
    put.id_inputs = None;
    records.seal(&mut put, case, &serde_json::to_vec(&value).unwrap());
    (OpKind::RecordPut(put), conditions)
}

/// The cases reuse chain operations by source and extend their claim and record state.
pub(super) fn signed_operations(
    file: &Value,
    chain: &Chain,
    docs: &HashMap<String, SignedDoc>,
    bundle: &KeyBundlePut,
    ids: &Identifiers,
    records: &RecordCases<'_>,
    assignment: [u8; 32],
) -> HashMap<String, SignedOp> {
    let keys = records.keys;
    let messages = evidence_messages(keys, file, assignment);
    let update = chain.by_source("record.put update");
    let version = RecordVersion::new(update.envelope.generation, update.seq);
    let cases = arr(file, "operations");
    let mut ops: HashMap<String, SignedOp> = HashMap::new();
    for (i, c) in cases.iter().enumerate() {
        let name = st(c, "name");
        let identity = records.create.identity;
        let (public, app_id) = writer_of(keys, st(c, "writer"), &identity);
        let mut conditions = Vec::new();
        let kind = match name {
            "app.put" | "receive_key.put" | "record.put create" | "claim attempt"
            | "record.put update" => None,
            "claim done (owner)" | "claim done (evidence)" | "claim failed" | "claim unknown" => {
                let mut entry = claim(&ops["claim attempt"]);
                entry.expected_step += 1;
                entry.kind = match name {
                    "claim done (owner)" | "claim done (evidence)" => EntryKind::Done {
                        basis: if name == "claim done (owner)" {
                            Basis::Owner
                        } else {
                            Basis::Evidence
                        },
                        evidence_ref: Some(messages[st(c, "evidence")].hash),
                    },
                    "claim failed" => EntryKind::Failed,
                    "claim unknown" => EntryKind::Unknown,
                    other => panic!("unknown claim outcome {other}"),
                };
                Some(OpKind::Claim(entry.fields()))
            }
            "record.put after done" => {
                let mut put = record(&ops["record.put update"]).clone();
                let mut value = super::opened_record(keys, &identity, &put);
                let msg = &messages[st(c, "message")];
                value["status"] = json!(st(c, "record_status"));
                value["msg_ids"].as_array_mut().unwrap().push(json!(msg.id));
                value["messages"]
                    .as_array_mut()
                    .unwrap()
                    .push(stored_message(
                        msg.sender,
                        &docs[&format!("{} certificate", msg.sender.name)],
                        c.get("accepted_at").unwrap(),
                        &msg.plaintext,
                    ));
                records.seal(&mut put, c, &serde_json::to_vec(&value).unwrap());
                put.expected_version = version;
                Some(OpKind::RecordPut(put))
            }
            "record.put delete" => {
                let done = claim(&ops["claim done (owner)"]);
                conditions.push(Condition::ClaimStep {
                    claim_key: done.claim_key,
                    step: done.expected_step + 1,
                });
                let mut put = record(&ops["record.put after done"]).clone();
                put.expected_version =
                    RecordVersion::new(records.create.generation, int(c, "previous_version"));
                records.seal(&mut put, c, b"");
                Some(OpKind::RecordPut(put))
            }
            "executor batch: attempt" => {
                let first = &ops["claim attempt"];
                let OpKind::Claim(fields) = &first.body().kind else {
                    panic!("expected attempt")
                };
                let entry = ClaimEntry {
                    attempt_id: seed16(c, "attempt_seed_label"),
                    expected_step: claim(&ops["claim failed"]).expected_step + 1,
                    kind: EntryKind::Attempt {
                        orphan_after: int(c, "orphan_after"),
                        deadline: fields.deadline,
                    },
                    ..claim(first)
                };
                conditions.push(Condition::RecordVersion {
                    key: record(&ops["record.put update"]).key,
                    version,
                });
                Some(OpKind::Claim(entry.fields()))
            }
            "executor batch: share_runs record.put" => {
                let (kind, guards) = share_run(ids, records, c, claim(&ops[st(c, "batch_from")]));
                conditions = guards;
                Some(kind)
            }
            "allow.put kept" | "allow.put reply" => Some(OpKind::AllowPut {
                pubky: keys.identity(st(c, "peer")),
                reason: PeerReason::parse(st(c, "reason")).unwrap(),
            }),
            "allow.delete" => Some(OpKind::AllowDelete {
                pubky: keys.identity(st(c, "peer")),
                reason: PeerReason::parse(st(c, "reason")).unwrap(),
            }),
            "deny.put" => Some(OpKind::DenyPut {
                pubky: keys.identity(st(c, "peer")),
            }),
            "deny.delete" => Some(OpKind::DenyDelete {
                pubky: keys.identity(st(c, "peer")),
            }),
            "invite_code.put" => Some(OpKind::InviteCodePut(InviteCodePut {
                code_hash: ids.invite.hash,
                expires_at: time_of(c, "expires_at"),
                max_uses: int(c, "max_uses"),
            })),
            "invite_code.delete" => Some(OpKind::InviteCodeDelete {
                code_hash: ids.invite.hash,
            }),
            "cert.put" => {
                let cert = &docs[st(c, "certificate")];
                Some(OpKind::CertPut {
                    target_app_id: AppCert::verify(cert, &identity).unwrap().app_id(),
                    cert: cert.clone(),
                })
            }
            "key_bundle.put" => Some(OpKind::KeyBundlePut(bundle.clone())),
            other => panic!("unknown operation {other}"),
        };
        let op = if let Some(kind) = kind {
            let batch = if let Some(source) = c.get("batch_from") {
                ops[source.as_str().unwrap()].body().batch
            } else {
                BatchRef {
                    id: seed16(c, "batch_seed_label"),
                    count: 1 + cases.iter().filter(|r| r["batch_from"] == name).count() as u64,
                }
            };
            let body = OpBody {
                identity,
                app_id,
                generation: records.create.generation,
                batch,
                conditions,
                kind,
            };
            SignedOp::sign(
                &SigningKey::from_bytes(&keys.secret(&public).unwrap()),
                body,
            )
            .unwrap()
        } else {
            chain.by_source(name).op()
        };
        emit_signed(&format!("/operations/{i}"), op.signed());
        SignedOp::verify(op.signed(), &public, &identity, app_id.as_ref()).unwrap();
        assert!(ops.insert(name.to_owned(), op).is_none(), "{name}");
    }
    ops
}

/// Seal and sign each scoped write with the grant issued to its named app (Switch wire 6.2).
pub(super) fn record_scope_cases(
    section: &Value,
    keys: &Keys,
    docs: &HashMap<String, SignedDoc>,
    ids: &Identifiers,
) {
    let record = st(section, "record_name");
    let natural = &ids.records[record].natural;
    let epoch = int(section, "data_epoch");
    let generation = int(section, "generation");
    for (i, case) in arr(section, "cases").iter().enumerate() {
        let app = keys.app(st(case, "writer"));
        let cert =
            AppCert::verify(&docs[&format!("{} certificate", app.name)], &app.identity).unwrap();
        let mut policy = ids.policies[st(case, "policy")].clone();
        if let Some(scope) = case.get("delete_scope") {
            policy = policy.with_delete_scope(scope.as_str().unwrap());
        }
        let (collection, key, inputs) =
            record_address(keys, &app.identity, record, natural, &policy);
        let value_sealed = super::seal_record(
            &keys.identity_key(&app.identity),
            epoch,
            &policy.read_scope,
            &key,
            case,
            st(case, "plaintext").as_bytes(),
        );
        let previous = case
            .get("previous_version")
            .map_or(RecordVersion::NONE, |v| {
                RecordVersion::new(generation, v.as_u64().unwrap())
            });
        let put = RecordPut {
            key,
            collection,
            policy,
            expected_version: previous,
            value_sealed,
            id_inputs: previous.is_none().then_some(inputs),
        };
        let signer = SigningKey::from_bytes(&app.signing_secret);
        let batch = pubky_switch_core::ops::sign_batch(
            &signer,
            &app.identity,
            Some(cert.app_id()),
            generation,
            seed16(case, "batch_seed_label"),
            vec![(Vec::new(), OpKind::RecordPut(put))],
        )
        .unwrap();
        let [op] = batch.as_slice() else {
            panic!("expected one scoped write")
        };
        super::check_record_submission(case, op, &cert);
        emit_signed(&format!("/record_scopes/cases/{i}"), op.signed());
    }
}
