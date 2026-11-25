//! Record-current operations and the carrying forms of their HTTP answers.

use pubky_dispatch_core::chain::{SignedHead, Stub};
use pubky_dispatch_core::keys::AppKeys;
use pubky_dispatch_core::ops::{Condition, OpKind, RecordVersion, SignedOp, check_shape};
use pubky_dispatch_core::sig::SignedDoc;
use serde_json::Value;

use super::chain::Chain;
use super::common::*;

fn signed(value: &Value) -> SignedDoc {
    serde_json::from_value(value.clone()).unwrap()
}

pub(super) fn ordered_object(fields: Vec<(&str, String)>) -> String {
    let members: Vec<_> = fields
        .into_iter()
        .map(|(name, value)| format!("{}:{value}", serde_json::to_string(name).unwrap()))
        .collect();
    format!("{{{}}}", members.join(","))
}

/// Feed members follow wire 7.4.4; signed documents, stubs and heads use core encoders.
pub(super) fn feed_page(page: &Value) -> String {
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
                    "invite_code_hash",
                    "envelope",
                ],
                "chain" => &["type", "seq", "stub", "item_type", "item", "proof"],
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
pub(super) fn write_answer(body: &Value) -> String {
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

/// Bind the next record write to the revision proved by the current one.
pub(super) fn condition_case(keys: &Keys, chain: &Chain) {
    let current = chain.by_source("record.put update");
    let op = current.op();
    let proof = &chain.proofs[&current.seq];
    let mut body = op.body().clone();
    let OpKind::RecordPut(put) = &mut body.kind else {
        panic!("record operation")
    };
    put.expected_version = RecordVersion::new(current.envelope.generation, current.seq);
    body.conditions = vec![Condition::RecordCurrent {
        key: put.key,
        revision: proof.record_revision().unwrap(),
        deleted: false,
    }];
    let file = load("operations.json");
    let case = &file["record_current"];
    body.batch.id = [u8::try_from(int(case, "batch_byte")).unwrap(); 16];
    body.batch.count = 1;
    let wallet = keys.app(st(case, "writer"));
    let op = SignedOp::sign(
        &AppKeys::from_secrets(wallet.signing_secret, wallet.bundle_secret),
        body,
    )
    .unwrap();
    check_shape(op.body()).unwrap();
    super::operations::emit_signed("/record_current", op.signed());
    let read = SignedOp::verify(
        op.signed(),
        &wallet.signing_public,
        &wallet.identity,
        Some(&pubky_dispatch_core::enc::app_id_decode(&wallet.app_id).unwrap()),
    )
    .unwrap();
    assert_eq!(read, op);
}

#[test]
fn test_vectors_record_current_dependencies() {
    let keys = keys();
    let docs = super::documents::issue_documents();
    let chain = super::chain::chain_cases(&keys, &docs);
    condition_case(&keys, &chain);
}
