//! `chain.json`: one generation's chain with its item bytes and hashes, envelopes, chain
//! hashes, stubs, transition proofs and signed heads, the chains a verifier refuses, and the
//! batch ID window (Switch wire 6.5 to 6.7).
//!
//! The chain is rebuilt item by item from the items and the service's times, every proof is
//! rebuilt from the state the core computes for its item (the claim view from the claim
//! rules, the record's version from its `seq`) and signed again with the fixed service key,
//! and every head is signed again, byte for byte. The record delete after the chain
//! (`record_delete`) is generated here (README "How the files were generated").

use std::collections::{BTreeMap, HashMap, HashSet};

use ed25519_dalek::SigningKey;
use pubky_switch_core::admission::PeerReason;
use pubky_switch_core::claims::{Claim, ClaimFields, ClaimType, attempt_deadline};
use pubky_switch_core::ops::{BatchRef, Condition, InviteCodePut, OpBody};
use pubky_switch_core::{enc, sig};

use pubky_switch_core::chain::{
    ChainEnvelope, ChainError, ChainTip, ItemType, ProofBody, ProofState, ServiceTransition,
    SignedHead, Stub, TransitionProof, Verifier, ZERO_HASH, bind_answer, chain_hash,
    check_attempt_proof, item_hash,
};
use pubky_switch_core::claims::{ClaimLimits, ClaimTally, EntryContext, apply_entry};
use pubky_switch_core::enc::{app_id_decode, b64 as b64e};
use pubky_switch_core::keys::{AppKeys as SwitchAppKeys, IdentityKey};
use pubky_switch_core::ops::{
    OpKind, RecordVersion, SignedOp, StateAfter, ops_hash, proof_state, sign_batch,
};
use pubky_switch_core::records::{AppRecord, IdentityDoc, ReceiveKeyRecord};
use pubky_switch_core::sealed::{RecordValue, SealedValue};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Value, json};

use crate::common::*;

/// One chain item of the file, read and checked.
pub(super) struct Item {
    pub seq: u64,
    pub item_type: ItemType,
    pub item: SignedDoc,
    pub envelope: ChainEnvelope,
    pub stub: Stub,
}

fn signed_of(value: &Value) -> SignedDoc {
    serde_json::from_value(value.clone()).unwrap()
}

fn stub_of(value: &Value) -> Stub {
    Stub::from_value(value).unwrap()
}

fn item_type(text: &str) -> ItemType {
    match text {
        "op" => ItemType::Op,
        "identity" => ItemType::Identity,
        "service" => ItemType::Service,
        other => panic!("item type {other}"),
    }
}

/// Read one item of `items` (or of a rejection's `items`): its bytes and hash, its envelope
/// written again, its chain hash and its stub.
fn read_item(it: &Value) -> Item {
    let seq = int(it, "seq");
    let item_type = item_type(st(it, "item_type"));
    let item = signed_of(&it["item"]);
    let bytes = item.doc_bytes().unwrap();
    if let Some(hex) = it["item_bytes_hex"].as_str() {
        assert_eq!(hex::encode(&bytes), hex, "seq {seq}: item bytes");
    }
    let hash = item_hash(item_type, &bytes);
    assert_eq!(b64e(&hash), st(it, "item_hash"), "seq {seq}: item hash");
    let envelope_json = st(it, "envelope_json");
    let envelope = ChainEnvelope::parse(envelope_json.as_bytes()).unwrap();
    assert_eq!(
        envelope.to_json(),
        envelope_json.as_bytes(),
        "seq {seq}: envelope"
    );
    assert_eq!(envelope.item_hash, hash);
    assert_eq!(b64e(&envelope.prev_chain_hash), st(it, "prev_chain_hash"));
    let ch = chain_hash(&envelope.prev_chain_hash, envelope_json.as_bytes());
    assert_eq!(b64e(&ch), st(it, "chain_hash"), "seq {seq}: chain hash");
    let stub = stub_of(&it["stub"]);
    assert_eq!(stub, Stub::of(&envelope), "seq {seq}: stub");
    assert_eq!(
        serde_json::from_slice::<Value>(&stub.to_json()).unwrap(),
        it["stub"]
    );
    Item {
        seq,
        item_type,
        item,
        envelope,
        stub,
    }
}

/// A service transition read from its signed document, whose key the caller checks.
fn transition_of(signed: &SignedDoc) -> ServiceTransition {
    ServiceTransition::from_value(&signed.peek::<Value>().unwrap()).unwrap()
}

#[test]
pub(super) fn test_vectors_chain() {
    let keys = keys();
    let chain = chain_cases(&keys, &super::documents::issue_documents());
    let v = load("chain.json");
    let generation = int(&v, "generation");
    let items: Vec<Item> = arr(&v, "items").iter().map(read_item).collect();
    assert!(items.len() >= 8);
    let first_body: Value = items[0].item.peek().unwrap();
    let identity = keys.identity("alice");
    assert_eq!(pubky(st(&first_body, "identity")), identity);
    let account = pubky_switch_core::enc::pubky_id(&identity);
    let service_key = keys.service_key(&account);
    let service_secret = keys.secret(&service_key).unwrap();
    let service = ed25519_dalek::SigningKey::from_bytes(&service_secret);

    // The chain, rebuilt item by item from 32 zero bytes, with a gap in seqs where the inbox
    // entry took one.
    let mut tip = ChainTip {
        generation,
        seq: 0,
        chain_hash: ZERO_HASH,
    };
    let mut verifier = Verifier::new(generation);
    let mut ops: HashMap<u64, SignedOp> = HashMap::new();
    let mut records: HashMap<[u8; 16], AppRecord> = HashMap::new();
    let mut gaps = 0;
    for it in &items {
        let env = &it.envelope;
        if it.seq != tip.seq + 1 {
            gaps += 1;
        }
        let (stub, next) = tip
            .append(
                it.seq,
                env.server_time,
                it.item_type,
                env.item_hash,
                env.batch,
            )
            .unwrap();
        assert_eq!(stub, it.stub, "seq {}: appended", it.seq);
        tip = next;
        let checked = verifier.push(&it.stub).unwrap();
        Verifier::check_item(&checked, it.item_type, &it.item.doc_bytes().unwrap()).unwrap();
        // Each item verifies as what it is.
        match it.item_type {
            ItemType::Identity => {
                IdentityDoc::verify(&it.item, &identity).unwrap();
            }
            ItemType::Op => {
                let body: Value = it.item.peek().unwrap();
                let app = app_id_decode(st(&body, "app_id")).unwrap();
                let writer = keys.app_by_id(st(&body, "app_id"));
                let op = SignedOp::verify(&it.item, &writer.signing_public, &identity, Some(&app))
                    .unwrap();
                assert_eq!(env.batch, Some(op.body().batch), "seq {}: batch", it.seq);
                if let OpKind::AppPut { record } = &op.body().kind {
                    records.insert(app, AppRecord::verify(record, &identity).unwrap());
                }
                ops.insert(it.seq, op);
            }
            ItemType::Service => {
                let t = ServiceTransition::verify(&it.item, &service_key, &identity).unwrap();
                assert_eq!(t.to_json().unwrap(), it.item.body_bytes().unwrap());
                assert_eq!(&t.sign(&service, &identity).unwrap(), &it.item);
            }
        }
    }
    assert_eq!(gaps, 1, "the inbox entry's seq is the one gap");
    verifier.end_of_feed().unwrap();

    check_proofs(&v, &chain, &ops, &records, &identity, &service);
    check_heads(&v, &items, &mut verifier, &identity, &service);
    check_rejections(&v, &chain, &identity, &service_key);
    check_batch_id_window(&v);
    check_export_batches(&ops);
}

/// The state the core computes for an operation's item: the claim view after the claim's
/// first entry, the record's version from the stub, the App ID, the receive key's `n` and
/// kid.
fn state_of_op(
    op: &SignedOp,
    proof: &TransitionProof,
    records: &HashMap<[u8; 16], AppRecord>,
) -> ProofState {
    let env = proof.envelope();
    let body = op.body();
    match &body.kind {
        OpKind::Claim(fields) => {
            let entry = fields.check().unwrap();
            let writer = body.app_id.unwrap();
            let current = |_: &[u8; 16]| true;
            let cx = EntryContext {
                writer,
                now: env.server_time,
                can_read: true,
                is_current: &current,
                limits: ClaimLimits::default(),
                tally: ClaimTally::default(),
            };
            assert_eq!(entry.expected_step, 0, "the claim's first entry");
            let claim = apply_entry(None, &entry, &cx).unwrap();
            let view = claim.view(&entry.claim_key, env.server_time, &current);
            // The attempt's proof passes the checks before acting on it.
            let checked = check_attempt_proof(proof, &entry, &writer, env.generation).unwrap();
            assert_eq!(checked, view);
            ProofState::Claim(view.to_value())
        }
        OpKind::RecordPut(put) => ProofState::Record {
            version: RecordVersion::new(env.generation, env.seq),
            deleted: put.value_sealed.looks_like_delete(),
            revision: pubky_switch_core::shared::ApplicationRef {
                generation: env.generation,
                seq: env.seq,
                item_hash: op.item_hash().unwrap(),
            },
        },
        OpKind::AppPut { .. } => ProofState::App {
            app_id: body.app_id.unwrap(),
        },
        OpKind::ReceiveKeyPut { record } => {
            let app = body.app_id.unwrap();
            let r = ReceiveKeyRecord::verify(record, records[&app].cert()).unwrap();
            ProofState::ReceiveKey {
                n: r.n(),
                kid: r.kid(),
            }
        }
        other => panic!("no proof rebuilt for {}", other.name()),
    }
}

/// Every transition proof, verified, bound to its item, and rebuilt from the state the core
/// computes for that item, then signed again with the fixed service key (Switch wire 6.5).
fn check_proofs(
    v: &Value,
    chain: &Chain,
    ops: &HashMap<u64, SignedOp>,
    records: &HashMap<[u8; 16], AppRecord>,
    identity: &[u8; 32],
    service: &ed25519_dalek::SigningKey,
) {
    let key = service.verifying_key().to_bytes();
    let proofs = arr(v, "transition_proofs");
    assert!(proofs.len() >= 8);
    let mut by_proof_seq: HashMap<u64, SignedDoc> = HashMap::new();
    for p in proofs {
        let name = st(p, "name");
        let signed = signed_of(&p["signed"]);
        assert_eq!(signed.body, b64e(st(p, "body").as_bytes()), "{name}");
        let proof = TransitionProof::verify(&signed, &key, identity).unwrap();
        let seq = proof.envelope().seq;
        let item = chain.at(seq);
        assert_eq!(proof.body().chain, item.stub, "{name}: the item's stub");
        let (object, state) = match item.item_type {
            ItemType::Identity => {
                let doc = IdentityDoc::verify(&item.item, identity).unwrap();
                (
                    "identity".to_owned(),
                    ProofState::Identity {
                        version: doc.version(),
                        generation: doc.generation(),
                        data_epoch: doc.data_epoch(),
                    },
                )
            }
            ItemType::Service => {
                let t = transition_of(&item.item);
                (t.proof_object().unwrap(), ProofState::Service(t.to_value()))
            }
            ItemType::Op => {
                let op = &ops[&seq];
                // A proof of an operation binds it, as an app checks a `POST /ops` answer.
                proof.check_binds(op).unwrap();
                let body = op.body();
                let object = body.kind.proof_object(body.app_id.as_ref()).unwrap();
                (object, state_of_op(op, &proof, records))
            }
        };
        assert_eq!(proof.body().object, object, "{name}: object");
        let rebuilt = ProofBody::new(item.stub.clone(), object, &state);
        assert_eq!(
            rebuilt.to_json().unwrap(),
            st(p, "body").as_bytes(),
            "{name}: proof body rebuilt"
        );
        let again = TransitionProof::sign(service, identity, rebuilt).unwrap();
        assert_eq!(again.signed(), &signed, "{name}: signed again");
        by_proof_seq.insert(seq, signed);
    }
    // The attempt batch binds both operations in order.
    let seqs = ["claim attempt", "record.put update"].map(|source| chain.by_source(source).seq);
    let batch = seqs.map(|seq| ops[&seq].clone());
    let answer = seqs.map(|seq| by_proof_seq[&seq].clone());
    assert_eq!(
        bind_answer(&batch, &answer, &key, identity).unwrap().len(),
        2
    );
    let swapped = vec![answer[1].clone(), answer[0].clone()];
    assert!(bind_answer(&batch, &swapped, &key, identity).is_err());
    assert!(bind_answer(&batch, &answer[..1], &key, identity).is_err());
    assert!(
        bind_answer(&batch, &[], &key, identity).is_err(),
        "a claim is never unchanged"
    );
    // The registration batch may be answered without proofs, as an unchanged batch.
    let registration =
        ["app.put", "receive_key.put"].map(|source| ops[&chain.by_source(source).seq].clone());
    assert!(
        bind_answer(&registration, &[], &key, identity)
            .unwrap()
            .is_empty()
    );
}

/// The two heads (Switch wire 6.7): verified, signed again, carried as a header, and
/// matching the verified chain.
fn check_heads(
    v: &Value,
    items: &[Item],
    verifier: &mut Verifier,
    identity: &[u8; 32],
    service: &ed25519_dalek::SigningKey,
) {
    let key = service.verifying_key().to_bytes();
    for h in arr(v, "signed_heads") {
        let head = SignedHead::from_value(&h["head"]).unwrap();
        head.verify(&key, identity).unwrap();
        let at = items.iter().find(|i| i.seq == head.seq).unwrap();
        let tip = ChainTip {
            generation: head.generation,
            seq: head.seq,
            chain_hash: at.stub.chain_hash,
        };
        assert_eq!(SignedHead::sign(service, identity, &tip), head);
        assert_eq!(head.to_header(), st(h, "switch_head_header"));
        assert_eq!(
            SignedHead::from_header(st(h, "switch_head_header")).unwrap(),
            head
        );
        verifier.head(head).unwrap();
    }
}

/// Push stubs until one is refused, then check the end of the feed.
fn run(verifier: &mut Verifier, stubs: &[Stub]) -> Result<(), ChainError> {
    for stub in stubs {
        verifier.push(stub)?;
    }
    verifier.end_of_feed()
}

/// The chains a verifier refuses, each for its rule (Switch wire 6.6, 6.7).
fn check_rejections(v: &Value, chain: &Chain, identity: &[u8; 32], service_key: &[u8; 32]) {
    let rejections = arr(v, "rejections");
    assert!(rejections.len() >= 5);
    for r in rejections {
        let name = st(r, "name");
        let mut verifier = Verifier::new(int(v, "generation"));
        let error = if let Some(head) = r.get("head") {
            // A forked head: after every stub, a verified head at seq 3 with another hash.
            assert_eq!(st(r, "after"), "every stub");
            for it in &chain.items {
                verifier.push(&it.stub).unwrap();
            }
            let head = SignedHead::from_value(head).unwrap();
            head.verify(service_key, identity).unwrap();
            verifier.head(head).unwrap_err()
        } else if r["stubs"].is_string() {
            chain.gap_error(&mut verifier, r)
        } else {
            let stubs: Vec<Stub> = arr(r, "stubs").iter().map(stub_of).collect();
            // The full items, when given, match their stubs, with their links intact, so only
            // the batch rules refuse them.
            if let Some(full) = r["items"].as_array() {
                let read: Vec<Item> = full.iter().map(read_item).collect();
                for (it, stub) in read.iter().zip(&stubs) {
                    assert_eq!(&it.stub, stub, "{name}");
                }
                for pair in read.windows(2) {
                    assert_eq!(pair[1].envelope.prev_chain_hash, pair[0].stub.chain_hash);
                }
            }
            run(&mut verifier, &stubs).unwrap_err()
        };
        let rule = st(r, "rule");
        let matched = match &error {
            ChainError::PartialBatch { batch_id, .. } => {
                rule.contains("consecutive seqs") && st(r, "error").ends_with(&b64e(batch_id))
            }
            ChainError::FeedEndsInBatch { batch_id } => {
                rule.contains("never ends inside a batch")
                    && st(r, "error").ends_with(&b64e(batch_id))
            }
            ChainError::RepeatedBatchId { batch_id, .. } => {
                rule.contains("repeat") && st(r, "error").ends_with(&b64e(batch_id))
            }
            ChainError::Link { .. } => rule.contains("extends the previous chain hash"),
            ChainError::Head { seq } => {
                rule.contains("matches its chain hash") && *seq == int(r, "at_seq")
            }
            _ => false,
        };
        assert!(
            matched,
            "{name}: refused for its rule ({rule}), got {error}"
        );
    }
}

/// The same batch again, 1 ms before, at and 1 ms after 30 days (Switch wire 6.6).
fn check_batch_id_window(v: &Value) {
    let cases = arr(v, "batch_id_window");
    assert_eq!(cases.len(), 3);
    for c in cases {
        let name = st(c, "name");
        let stubs: Vec<Stub> = arr(c, "stubs").iter().map(stub_of).collect();
        let envelopes: Vec<ChainEnvelope> = stubs.iter().map(|s| s.open().unwrap()).collect();
        // The repeat is the last batch; its first stub is `gap_ms` after the earlier one's.
        let mut starts = Vec::new();
        let mut left = 0;
        for e in &envelopes {
            if let Some(batch) = e.batch {
                if left == 0 {
                    starts.push((batch.id, e.server_time));
                    left = batch.count;
                }
                left -= 1;
            }
        }
        let (id, repeat) = *starts.last().unwrap();
        let first = starts.iter().find(|(b, _)| *b == id).unwrap().1;
        assert_eq!(repeat - first, int(c, "gap_ms"), "{name}");
        let outcome = run(&mut Verifier::new(int(v, "generation")), &stubs);
        match st(c, "outcome") {
            "refused" => assert!(
                matches!(outcome, Err(ChainError::RepeatedBatchId { batch_id, .. }) if batch_id == id),
                "{name}: {outcome:?}"
            ),
            "accepted" => outcome.unwrap(),
            other => panic!("{name}: outcome {other}"),
        }
    }
}

/// The operation hashes `export.json` carries for the chain's batches (Switch wire 10.3):
/// `hash(lp(signed document bytes of each operation, in order))`.
fn check_export_batches(ops: &HashMap<u64, SignedOp>) {
    let export = load("export.json");
    let mut parts = Vec::new();
    find_batch_parts(&export, &mut parts);
    assert!(!parts.is_empty(), "export.json has batch parts");
    for part in parts {
        let id = b64n::<16>(st(&part, "id"));
        let mut batch: Vec<(u64, SignedOp)> = ops
            .iter()
            .filter(|(_, o)| o.body().batch.id == id)
            .map(|(s, o)| (*s, o.clone()))
            .collect();
        batch.sort_by_key(|(s, _)| *s);
        let batch: Vec<SignedOp> = batch.into_iter().map(|(_, o)| o).collect();
        assert!(!batch.is_empty());
        assert_eq!(
            b64e(&ops_hash(&batch).unwrap()),
            st(&part["record"], "ops_hash"),
            "the operation hash of batch {}",
            st(&part, "id")
        );
    }
}

/// The `batch` parts of an export, wherever they are, inside JSON texts included.
fn find_batch_parts(value: &Value, out: &mut Vec<Value>) {
    match value {
        Value::Object(m) => {
            if m.get("part").and_then(Value::as_str) == Some("batch") {
                out.push(value.clone());
            }
            m.values().for_each(|x| find_batch_parts(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| find_batch_parts(x, out)),
        Value::String(s) if s.starts_with('{') => {
            if let Ok(inner) = serde_json::from_str::<Value>(s) {
                find_batch_parts(&inner, out);
            }
        }
        _ => {}
    }
}

/// `record_delete`, which `pubky-switch-core` generates (README "How the files were
/// generated"): the wallet deletes the record of seq 8, in a batch of its own chained after
/// seq 9. Its sealed value is the tag alone (wire 6.2), sealed with the seed
/// `chain/record_delete/nonce`, under the batch ID of the seed `chain/record_delete/batch`.
/// The proof's state shows `deleted: true`, as the record rule gives it (wire 6.5).
fn check_record_delete(keys: &Keys, chain: &Chain, service: &SigningKey, case: &Value) {
    let wallet = keys.app("wallet");
    let identity = &wallet.identity;
    let app_id = app_id_decode(&wallet.app_id).unwrap();
    let current = chain.by_source("record.put update");
    let updated = current.op();
    let OpKind::RecordPut(update) = &updated.body().kind else {
        panic!("expected a record update");
    };
    let sealed = &update.value_sealed;
    let scope_key = IdentityKey::from_secret(keys.identity_secrets[identity])
        .scope_key(sealed.data_epoch, &sealed.scope);
    let nonce: [u8; 24] = seed(st(case, "nonce_seed_label"))[..24].try_into().unwrap();
    let mut put = update.clone();
    put.expected_version = RecordVersion::new(current.envelope.generation, current.seq);
    put.value_sealed = SealedValue::seal_with_nonce(
        &scope_key,
        identity,
        sealed.data_epoch,
        &sealed.scope,
        &put.key,
        b"",
        &nonce,
    )
    .unwrap();
    assert!(put.value_sealed.looks_like_delete());
    let batch_id: [u8; 16] = seed16(case, "batch_seed_label");
    let signer = SwitchAppKeys::from_secrets(wallet.signing_secret, wallet.bundle_secret);
    let op = sign_batch(
        &signer,
        identity,
        Some(app_id),
        updated.body().generation,
        batch_id,
        vec![(Vec::new(), OpKind::RecordPut(put.clone()))],
    )
    .unwrap()
    .remove(0);

    // Chained after the chain's last item, a second after it.
    let last = chain.items.last().unwrap();
    let tip = last.tip();
    let seq = last.seq + 1;
    let row = Item::append(
        &tip,
        seq,
        time_of(case, "server_time"),
        ItemType::Op,
        op.signed().clone(),
    );
    let item = row.wire();
    // The proof, with the state the record rule gives a delete.
    let state = proof_state(
        &op,
        &StateAfter::Record(RecordVersion::new(tip.generation, seq)),
    )
    .unwrap();
    assert_eq!(
        state,
        ProofState::Record {
            version: RecordVersion::new(tip.generation, seq),
            deleted: true,
            revision: pubky_switch_core::shared::ApplicationRef {
                generation: tip.generation,
                seq,
                item_hash: row.envelope.item_hash
            },
        }
    );
    let object = op.body().kind.proof_object(Some(&app_id)).unwrap();
    let body = ProofBody::new(row.stub.clone(), object, &state);
    let proof = TransitionProof::sign(service, identity, body).unwrap();
    let body_text = String::from_utf8(proof.signed().body_bytes().unwrap()).unwrap();
    let transition_proof = json!({
        "body": body_text,
        "name": format!("record.put delete (seq {seq}): deleted at version ({}, {seq})", tip.generation),
        "signed": proof.signed(),
    });
    generated(
        "chain.json",
        &[
            (Place::Member("/record_delete/item"), item.clone()),
            (
                Place::Member("/record_delete/transition_proof"),
                transition_proof.clone(),
            ),
        ],
    );

    // Read the emitted item and verify the link, delete marker and proof.
    let read = read_item(&item);
    assert_eq!(read.envelope.prev_chain_hash, last.stub.chain_hash);
    let op = SignedOp::verify(&read.item, &wallet.signing_public, identity, Some(&app_id)).unwrap();
    let OpKind::RecordPut(put) = &op.body().kind else {
        panic!("record_delete is a record.put");
    };
    assert_eq!(
        put.value_sealed
            .open(&scope_key, identity, &put.key)
            .unwrap(),
        RecordValue::Delete
    );
    let p = &transition_proof;
    let signed = signed_of(&p["signed"]);
    assert_eq!(signed.body, b64e(st(p, "body").as_bytes()));
    let proof =
        TransitionProof::verify(&signed, &service.verifying_key().to_bytes(), identity).unwrap();
    proof.check_binds(&op).unwrap();
    assert_eq!(proof.body().chain, read.stub);
    assert_eq!(proof.body().state["deleted"], Value::Bool(true));
}

/// The signed items, receipts and admission history that the export continues.
pub(super) struct Chain {
    pub items: Vec<Item>,
    pub proofs: BTreeMap<u64, TransitionProof>,
    pub peers: Vec<Item>,
    sources: HashMap<String, usize>,
}

impl Chain {
    pub fn by_source(&self, source: &str) -> &Item {
        &self.items[self.sources[source]]
    }

    /// Wire 7.5 drops a record write's document when a later write replaces the same key.
    pub fn superseded_writes(&self) -> HashSet<u64> {
        let mut keys = HashSet::new();
        let mut superseded = HashSet::new();
        for row in self
            .items
            .iter()
            .rev()
            .filter(|r| r.item_type == ItemType::Op)
        {
            if let OpKind::RecordPut(put) = &row.op().body().kind
                && !keys.insert(put.key)
            {
                superseded.insert(row.seq);
            }
        }
        superseded
    }

    fn gap_error(&self, verifier: &mut Verifier, case: &Value) -> ChainError {
        let (first, next) = st(case, "stubs")
            .strip_prefix("chain.json items seq ")
            .unwrap()
            .split_once(", then seq ")
            .unwrap();
        verifier
            .push(&self.at(first.parse().unwrap()).stub)
            .unwrap();
        let next = next.parse().unwrap();
        let error = verifier.push(&self.at(next).stub).unwrap_err();
        assert!(matches!(error, ChainError::Link { seq } if seq == next));
        error
    }

    pub fn at(&self, seq: u64) -> &Item {
        self.items.iter().find(|row| row.seq == seq).unwrap()
    }
}

impl Item {
    pub fn append(tip: &ChainTip, seq: u64, at: u64, item_type: ItemType, item: SignedDoc) -> Self {
        let batch =
            (item_type == ItemType::Op).then(|| SignedOp::peek(&item).unwrap().body().batch);
        let hash = item_hash(item_type, &item.doc_bytes().unwrap());
        let (stub, _) = tip.append(seq, at, item_type, hash, batch).unwrap();
        Self {
            seq,
            item_type,
            item,
            envelope: stub.open().unwrap(),
            stub,
        }
    }

    pub fn tip(&self) -> ChainTip {
        ChainTip {
            generation: self.envelope.generation,
            seq: self.seq,
            chain_hash: self.stub.chain_hash,
        }
    }

    fn wire(&self) -> Value {
        json!({
            "seq": self.seq,
            "item_type": self.item_type.as_str(),
            "item": self.item,
            "item_bytes_hex": hex::encode(self.item.doc_bytes().unwrap()),
            "item_hash": b64e(&self.envelope.item_hash),
            "prev_chain_hash": b64e(&self.envelope.prev_chain_hash),
            "chain_hash": b64e(&self.stub.chain_hash),
            "envelope_json": String::from_utf8(self.envelope.to_json()).unwrap(),
            "stub": self.stub.to_value(),
        })
    }

    pub fn op(&self) -> SignedOp {
        SignedOp::peek(&self.item).unwrap()
    }
}

/// Apply the wallet's first attempt to the empty claim store.
pub(super) fn first_claim(row: &Item) -> ([u8; 32], Claim) {
    let op = row.op();
    let OpKind::Claim(fields) = &op.body().kind else {
        panic!("expected claim at {}", row.seq)
    };
    let entry = fields.check().unwrap();
    let cx = EntryContext {
        writer: op.body().app_id.unwrap(),
        now: row.envelope.server_time,
        can_read: true,
        is_current: &|_| true,
        limits: ClaimLimits::default(),
        tally: ClaimTally::default(),
    };
    (entry.claim_key, apply_entry(None, &entry, &cx).unwrap())
}

/// A signed message as stored in the shared record and named by the claim.
fn record_message(
    input: &Value,
    from: &AppKeys,
    to: &AppKeys,
    refs: Vec<[u8; 32]>,
) -> (String, pubky_switch_core::message::MessagePlaintext) {
    use pubky_switch_core::message::{Message, Sender};
    let signer = SwitchAppKeys::from_secrets(from.signing_secret, from.bundle_secret);
    let message = Message {
        from: Sender::of_app(from.identity, &signer),
        to: to.identity,
        msg_id: uuid_from_seed(st(input, "msg_id_seed_label")),
        kind: st(input, "kind").into(),
        created_at_ms: time_of(input, "created_at"),
        body: input["body"].as_object().unwrap().clone(),
        refs,
    };
    let signed = message.sign(&signer).unwrap();
    (message.msg_id, signed)
}

/// Seal the assignment alone on creation, then with the wallet's signed acceptance.
fn record_put(
    keys: &Keys,
    docs: &HashMap<String, SignedDoc>,
    create: &Value,
    row: &Value,
    generation: u64,
) -> OpKind {
    let shop = keys.app("shop");
    let wallet = keys.app("wallet");
    let update = st(row, "source") == "record.put update";
    let mut refs = Vec::new();
    let mut messages = Vec::new();
    let mut ids = Vec::new();
    for (input, from, to) in [
        (&create["message"], shop, wallet),
        (&row["message"], wallet, shop),
    ]
    .into_iter()
    .take(if update { 2 } else { 1 })
    {
        let (id, signed) = record_message(input, from, to, refs.clone());
        refs.push(signed.hash());
        ids.push(id);
        messages.push(json!({
            "sender": enc::pubky_id(&from.identity),
            "accepted_at": input.get("accepted_at").unwrap(),
            "cert": docs[&format!("{} certificate", from.name)],
            "plaintext": {
                "json": b64e(signed.json()),
                "sender_app": b64e(&signed.sender_app_id()),
                "signature": b64e(&signed.signature()),
            },
        }));
    }
    let natural = enc::lp(&[&shop.identity, &refs[0]]);
    let scope = st(create, "scope");
    let policy = pubky_switch_core::ident::Policy::new(scope, &[scope]);
    let (collection, key, inputs) = record_address(
        keys,
        &wallet.identity,
        st(create, "record_name"),
        &natural,
        &policy,
    );
    let plaintext = json!({
        "v": int(create, "record_version"),
        "status": st(row, "record_status"),
        "counterparty": enc::pubky_id(&shop.identity),
        "messages": messages,
        "msg_ids": ids,
    });
    let epoch = int(create, "data_epoch");
    let nonce = seed(st(row, "nonce_seed_label"))[..24].try_into().unwrap();
    let value_sealed = SealedValue::seal_with_nonce(
        &keys.identity_key(&wallet.identity).scope_key(epoch, scope),
        &wallet.identity,
        epoch,
        scope,
        &key,
        &serde_json::to_vec(&plaintext).unwrap(),
        &nonce,
    )
    .unwrap();
    OpKind::RecordPut(pubky_switch_core::ops::RecordPut {
        collection,
        key,
        policy,
        expected_version: if update {
            RecordVersion::new(generation, int(create, "seq"))
        } else {
            RecordVersion::new(0, 0)
        },
        id_inputs: (!update).then_some(inputs),
        value_sealed,
    })
}

/// Sign the registration, record and claim operations in their service order.
fn operation(
    keys: &Keys,
    docs: &HashMap<String, SignedDoc>,
    file: &Value,
    row: &Value,
    items: &[Item],
) -> SignedOp {
    let wallet = keys.app("wallet");
    let name = st(row, "source");
    let generation = int(file, "generation");
    let mut conditions = Vec::new();
    let creation = || {
        arr(file, "items")
            .iter()
            .find(|r| r["source"] == "record.put create")
            .expect("record create")
    };
    let kind = match name {
        "app.put" => OpKind::AppPut {
            record: docs["wallet app record"].clone(),
        },
        "receive_key.put" => OpKind::ReceiveKeyPut {
            record: docs["wallet receive key record"].clone(),
        },
        "record.put create" | "record.put update" => {
            record_put(keys, docs, creation(), row, generation)
        }
        "claim attempt" => {
            let create = creation();
            let input = &create["message"];
            // The claim key is opaque to the Switch: an app derives it, so it is an input here.
            let fields = ClaimFields {
                claim_key: b64n::<32>(st(row, "claim_key")).to_vec(),
                kind: ClaimType::Attempt,
                expected_step: int(row, "expected_step"),
                attempt_id: seed16(row, "attempt_seed_label").to_vec(),
                orphan_after: Some(int(row, "orphan_after")),
                deadline: Some(attempt_deadline(time_of(&input["body"], "due"))),
                basis: None,
                evidence_ref: None,
            };
            let create_seq = int(create, "seq");
            let create = items
                .iter()
                .find(|row| row.seq == create_seq)
                .expect("record create before the attempt");
            let op = create.op();
            let OpKind::RecordPut(put) = &op.body().kind else {
                panic!("expected create")
            };
            conditions.push(Condition::RecordVersion {
                key: put.key,
                version: RecordVersion::new(generation, create.seq),
            });
            OpKind::Claim(fields)
        }
        other => panic!("unknown chain operation {other}"),
    };
    let batch = match name {
        "receive_key.put" | "record.put update" => items.last().unwrap().op().body().batch,
        "app.put" | "record.put create" | "claim attempt" => BatchRef {
            id: seed16(row, "batch_seed_label"),
            count: int(row, "batch_count"),
        },
        other => panic!("unknown batch operation {other}"),
    };
    let body = OpBody {
        identity: wallet.identity,
        app_id: Some(app_id_decode(&wallet.app_id).unwrap()),
        generation,
        batch,
        conditions,
        kind,
    };
    SignedOp::sign(&SigningKey::from_bytes(&wallet.signing_secret), body).unwrap()
}

fn receipt(row: &Item, keys: &Keys, service: &SigningKey) -> TransitionProof {
    let wallet = keys.app("wallet");
    let (object, state) = match row.item_type {
        ItemType::Identity => {
            let doc = IdentityDoc::verify(&row.item, &wallet.identity).unwrap();
            (
                "identity".to_owned(),
                ProofState::Identity {
                    version: doc.version(),
                    generation: doc.generation(),
                    data_epoch: doc.data_epoch(),
                },
            )
        }
        ItemType::Service => {
            let t = transition_of(&row.item);
            (t.proof_object().unwrap(), ProofState::Service(t.to_value()))
        }
        ItemType::Op => {
            let op = row.op();
            let b = op.body();
            let after = match &b.kind {
                OpKind::Claim(_) => {
                    let (key, claim) = first_claim(row);
                    StateAfter::Claim(claim.view(&key, row.envelope.server_time, &|_| true))
                }
                OpKind::RecordPut(_) => {
                    StateAfter::Record(RecordVersion::new(row.envelope.generation, row.seq))
                }
                OpKind::AppPut { .. } => StateAfter::App {
                    app_id: b.app_id.unwrap(),
                },
                OpKind::ReceiveKeyPut { .. } => StateAfter::ReceiveKey {
                    n: wallet.receive_n,
                    kid: wallet.receive_kid,
                },
                OpKind::InviteCodePut(_) | OpKind::AllowPut { .. } | OpKind::AllowDelete { .. } => {
                    StateAfter::Op
                }
                kind => panic!("unknown proof operation {}", kind.name()),
            };
            (
                b.kind.proof_object(b.app_id.as_ref()).unwrap(),
                proof_state(&op, &after).unwrap(),
            )
        }
    };
    TransitionProof::sign(
        service,
        &wallet.identity,
        ProofBody::new(row.stub.clone(), object, &state),
    )
    .unwrap()
}

fn admission_items(keys: &Keys, c: &Value, mut tip: ChainTip, service: &SigningKey) -> Vec<Item> {
    let wallet = keys.app("wallet");
    let alice = wallet.identity;
    let mut codes = Vec::new();
    let mut rows = Vec::new();
    for (i, r) in arr(c, "items").iter().enumerate() {
        let seq = int(r, "seq");
        let at = time_of(r, "server_time");
        let path = format!("/peer_admission/items/{i}");
        let action = st(r, "action");
        let row = if action == "reply.add" {
            let t = ServiceTransition::ReplyAdd {
                pubky: keys.identity(st(r, "peer")),
                code_hash: codes[0],
                at,
            };
            Item::append(
                &tip,
                seq,
                at,
                ItemType::Service,
                t.sign(service, &alice).unwrap(),
            )
        } else {
            let kind = match action {
                "invite_code.put" => {
                    let code_hash = enc::hash(&seed16(r, "code_seed_label"));
                    codes.push(code_hash);
                    OpKind::InviteCodePut(InviteCodePut {
                        code_hash,
                        expires_at: time_of(r, "expires_at"),
                        max_uses: int(r, "max_uses"),
                    })
                }
                "allow.put" | "allow.delete" => {
                    let pubky = match st(r, "peer") {
                        "claims" => {
                            sig::public_of(&seed(st(&load("claims.json"), "identity_seed_label")))
                        }
                        "kept" => sig::public_of(&seed(st(r, "peer_seed_label"))),
                        name => keys.identity(name),
                    };
                    let reason = PeerReason::parse(st(r, "reason")).unwrap();
                    if action == "allow.delete" {
                        OpKind::AllowDelete { pubky, reason }
                    } else {
                        OpKind::AllowPut { pubky, reason }
                    }
                }
                n => panic!("unknown admission item {n}"),
            };
            let body = OpBody {
                identity: alice,
                app_id: Some(app_id_decode(&wallet.app_id).unwrap()),
                generation: tip.generation,
                batch: BatchRef {
                    id: seed16(r, "batch_seed_label"),
                    count: 1,
                },
                conditions: vec![],
                kind,
            };
            let op = SignedOp::sign(&SigningKey::from_bytes(&wallet.signing_secret), body).unwrap();
            let row = Item::append(&tip, seq, at, ItemType::Op, op.signed().clone());
            generated_members(
                "chain.json",
                &path,
                &[("proof", json!(receipt(&row, keys, service).signed()))],
            );
            row
        };
        generated_members(
            "chain.json",
            &path,
            &[("item", json!(row.item)), ("stub", row.stub.to_value())],
        );
        tip = row.tip();
        rows.push(row);
    }
    generated_members(
        "chain.json",
        "/peer_admission",
        &[("head", SignedHead::sign(service, &alice, &tip).to_value())],
    );
    rows
}

fn alternative(items: &[&Item], repeat_after: u64) -> Vec<Item> {
    let mut tip = ChainTip {
        generation: items[0].envelope.generation,
        seq: 0,
        chain_hash: ZERO_HASH,
    };
    items
        .iter()
        .enumerate()
        .map(|(i, it)| {
            let delay = if i > 0 && items[i - 1].seq == it.seq {
                repeat_after
            } else {
                0
            };
            let row = Item::append(
                &tip,
                i as u64 + 1,
                it.envelope.server_time + delay,
                it.item_type,
                it.item.clone(),
            );
            tip = row.tip();
            row
        })
        .collect()
}

/// The text of each verifier refusal as the fixture states it (README: informative).
fn refusal_text(error: ChainError) -> String {
    match error {
        ChainError::PartialBatch { batch_id, .. } | ChainError::FeedEndsInBatch { batch_id } => {
            format!("incomplete batch: {}", b64e(&batch_id))
        }
        ChainError::RepeatedBatchId { batch_id, .. } => {
            format!("repeated batch ID {}", b64e(&batch_id))
        }
        ChainError::Link { seq } => {
            format!("chain broken: seq {seq} doesn't extend the previous chain hash")
        }
        ChainError::Head { seq } => {
            format!("rollback or fork: head at seq {seq} doesn't match the chain")
        }
        other => panic!("unexpected verifier refusal {other}"),
    }
}

fn alternative_cases(v: &Value, chain: &Chain, service: &SigningKey, alice: &[u8; 32]) {
    for group in ["rejections", "batch_id_window"] {
        for (i, c) in arr(v, group).iter().enumerate() {
            let name = st(c, "name");
            let path = format!("/{group}/{i}");
            let mut verifier = Verifier::new(int(v, "generation"));
            let delay = match name {
                "partial batch" | "batch cut off at the end of a page" => 0,
                "repeated batch ID"
                | "1 ms before 30 days"
                | "exactly 30 days"
                | "1 ms after 30 days" => int(c, "gap_ms"),
                "gap" => {
                    assert_eq!(
                        st(c, "error"),
                        refusal_text(chain.gap_error(&mut verifier, c))
                    );
                    continue;
                }
                "forked head" => {
                    let tip = ChainTip {
                        generation: int(v, "generation"),
                        seq: int(c, "at_seq"),
                        chain_hash: seed(st(c, "hash_seed_label")),
                    };
                    let head = SignedHead::sign(service, alice, &tip);
                    generated_members("chain.json", &path, &[("head", head.to_value())]);
                    assert_eq!(st(c, "after"), "every stub");
                    for row in &chain.items {
                        verifier.push(&row.stub).unwrap();
                    }
                    assert_eq!(
                        st(c, "error"),
                        refusal_text(verifier.head(head).unwrap_err())
                    );
                    continue;
                }
                other => panic!("unknown chain case {other}"),
            };
            let sources: Vec<_> = arr(c, "item_sources")
                .iter()
                .map(|source| chain.by_source(source.as_str().unwrap()))
                .collect();
            let rows = alternative(&sources, delay);
            let stubs = rows.iter().map(|r| r.stub.clone()).collect::<Vec<_>>();
            let outcome = run(&mut verifier, &stubs);
            if group == "batch_id_window" {
                assert_eq!(
                    st(c, "outcome"),
                    if outcome.is_ok() {
                        "accepted"
                    } else {
                        "refused"
                    }
                );
            }
            assert_eq!(
                c.get("error"),
                Some(&json!(outcome.err().map(refusal_text)))
            );
            generated_members(
                "chain.json",
                &path,
                &[(
                    "stubs",
                    json!(stubs.iter().map(Stub::to_value).collect::<Vec<_>>()),
                )],
            );
            if name != "batch cut off at the end of a page" {
                generated_members(
                    "chain.json",
                    &path,
                    &[(
                        "items",
                        json!(rows.iter().map(Item::wire).collect::<Vec<_>>()),
                    )],
                );
            }
        }
    }
}

/// Append the chosen documents, operations and transitions and sign their receipts.
pub(super) fn chain_cases(keys: &Keys, docs: &HashMap<String, SignedDoc>) -> Chain {
    let v = load("chain.json");
    super::generation::check_annotations("chain.json", &v);
    let alice = keys.identity("alice");
    let service = service_signer(keys, &alice);
    let mut tip = ChainTip {
        generation: int(&v, "generation"),
        seq: 0,
        chain_hash: ZERO_HASH,
    };
    let mut items = Vec::new();
    let mut proofs = BTreeMap::new();
    let mut sources = HashMap::new();
    for (i, c) in arr(&v, "items").iter().enumerate() {
        let name = st(c, "source");
        let at = time_of(c, "server_time");
        let (kind, doc) = match name {
            "alice identity.json, first delivery (version 1)" | "alice identity.json" => {
                (ItemType::Identity, docs[name].clone())
            }
            "app.put" | "receive_key.put" | "record.put create" | "claim attempt"
            | "record.put update" => (
                ItemType::Op,
                operation(keys, docs, &v, c, &items).signed().clone(),
            ),
            "revoke" => (
                ItemType::Service,
                ServiceTransition::Revoke {
                    app_id: app_id_decode(&keys.app(st(c, "app")).app_id).unwrap(),
                    at,
                }
                .sign(&service, &alice)
                .unwrap(),
            ),
            other => panic!("unknown chain source {other}"),
        };
        assert!(
            sources.insert(name.to_owned(), i).is_none(),
            "duplicate chain source {name}"
        );
        let row = Item::append(&tip, int(c, "seq"), at, kind, doc);
        let mut wire = row.wire();
        let members = wire.as_object_mut().unwrap();
        members.remove("seq");
        generated_members(
            "chain.json",
            &format!("/items/{i}"),
            &members
                .iter()
                .map(|(k, v)| (k.as_str(), v.clone()))
                .collect::<Vec<_>>(),
        );
        proofs.insert(row.seq, receipt(&row, keys, &service));
        tip = row.tip();
        items.push(row);
    }
    for (i, c) in arr(&v, "transition_proofs").iter().enumerate() {
        let seq = int(c, "at_seq");
        let proof = proofs[&seq].signed();
        generated_members(
            "chain.json",
            &format!("/transition_proofs/{i}"),
            &[
                ("signed", json!(proof)),
                (
                    "body",
                    json!(String::from_utf8(proof.body_bytes().unwrap()).unwrap()),
                ),
            ],
        );
    }
    let peers = admission_items(keys, &v["peer_admission"], tip, &service);
    let chain = Chain {
        items,
        proofs,
        peers,
        sources,
    };
    for (i, c) in arr(&v, "signed_heads").iter().enumerate() {
        let head = SignedHead::sign(&service, &alice, &chain.at(int(c, "at_seq")).tip());
        generated_members(
            "chain.json",
            &format!("/signed_heads/{i}"),
            &[
                ("head", head.to_value()),
                ("switch_head_header", json!(head.to_header())),
            ],
        );
    }
    alternative_cases(&v, &chain, &service, &alice);
    check_record_delete(keys, &chain, &service, &v["record_delete"]);
    chain
}
