//! The upload's body and item checks, on an identity whose generation 3 was lost: one app
//! writing a record built on (3, 10) and an attempt, the lost service's proofs of both.

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use super::*;
use crate::chain::{ChainTip, ProofBody, ProofState};
use crate::claims::{
    Basis, ClaimFields, ClaimLimits, ClaimTally, ClaimType, EntryContext, apply_entry,
};
use crate::enc::{b64, pubky_id};
use crate::ident::Policy;
use crate::keys::{AppKeys, IdentityKey};
use crate::ops::{BatchRef, OpBody};
use crate::records::{AppCertBody, IdentityBody, IdentityPolicy, Inbox};
use crate::recovery::merge_upload_claim;
use crate::sealed::SealedValue;

const NOW: u64 = 1_800_000_000_000;
const SCOPE: &str = "scope-a";
const LOST: u64 = 3;
const CLAIM_KEY: [u8; 32] = [20; 32];
const ATTEMPT: [u8; 16] = [21; 16];

fn identity() -> IdentityKey {
    IdentityKey::from_secret([1; 32])
}

fn app() -> AppKeys {
    AppKeys::from_secrets([2; 32], [3; 32])
}

fn lost_key() -> SigningKey {
    SigningKey::from_bytes(&[5; 32])
}

fn cert_with(scopes: &[&str], permissions: &[Permission]) -> AppCert {
    let keys = app();
    let body = AppCertBody::new(
        identity().public(),
        keys.signing_public(),
        keys.bundle_public(),
        scopes.iter().map(|s| (*s).to_owned()).collect(),
        permissions,
        NOW - 1_000,
        NOW + 1_000_000,
    );
    AppCert::issue(&identity(), body).unwrap()
}

fn cert() -> AppCert {
    cert_with(&[SCOPE], &[Permission::ClaimsWrite])
}

/// An `identity.json` of `generation` naming `key` as its service key.
fn doc(generation: u64, key: &SigningKey) -> SignedDoc {
    let mut body = IdentityBody::first(
        identity().public(),
        [9; 16],
        Inbox::new("https://lost.example", key.verifying_key().to_bytes()),
        IdentityPolicy::default(),
    );
    body.generation = generation;
    IdentityDoc::sign(&identity(), body)
        .unwrap()
        .signed()
        .clone()
}

fn op_at(generation: u64, kind: OpKind) -> SignedOp {
    SignedOp::sign(
        &app(),
        OpBody {
            identity: identity().public(),
            app_id: Some(app().app_id_bytes()),
            generation,
            batch: BatchRef {
                id: [4; 16],
                count: 1,
            },
            conditions: Vec::new(),
            kind,
        },
    )
    .unwrap()
}

fn put(built_on: RecordVersion) -> RecordPut {
    let id = identity();
    let key = [30; 32];
    RecordPut {
        key,
        collection: [31; 32],
        policy: Policy::new(SCOPE, &[SCOPE]),
        expected_version: built_on,
        value_sealed: SealedValue::seal(
            &id.scope_key(1, SCOPE),
            &id.public(),
            1,
            SCOPE,
            &key,
            b"{}",
        )
        .unwrap(),
        id_inputs: None,
    }
}

/// [`put`] on (3, 10), its value sealed under `scope` instead of its read scope.
fn sealed_under(scope: &str) -> RecordPut {
    let id = identity();
    let mut put = put(RecordVersion::new(3, 10));
    put.value_sealed = SealedValue::seal(
        &id.scope_key(1, scope),
        &id.public(),
        1,
        scope,
        &put.key,
        b"{}",
    )
    .unwrap();
    put
}

fn record_op(generation: u64) -> SignedOp {
    op_at(
        generation,
        OpKind::RecordPut(put(RecordVersion::new(3, 10))),
    )
}

fn attempt_fields() -> ClaimFields {
    ClaimFields {
        claim_key: CLAIM_KEY.to_vec(),
        kind: ClaimType::Attempt,
        expected_step: 0,
        attempt_id: ATTEMPT.to_vec(),
        orphan_after: Some(86_400),
        deadline: None,
        basis: None,
        evidence_ref: None,
    }
}

fn done_fields() -> ClaimFields {
    ClaimFields {
        kind: ClaimType::Done,
        expected_step: 1,
        orphan_after: None,
        basis: Some(Basis::Owner),
        ..attempt_fields()
    }
}

/// The lost service's proof of `op`, applied at `seq` and `time`, showing `state`.
fn proof_of(op: &SignedOp, seq: u64, time: u64, object: String, state: &ProofState) -> SignedDoc {
    let tip = ChainTip {
        generation: op.body().generation,
        seq: seq - 1,
        chain_hash: [8; 32],
    };
    let (stub, _) = tip
        .append(
            seq,
            time,
            ItemType::Op,
            op.item_hash().unwrap(),
            Some(op.body().batch),
        )
        .unwrap();
    TransitionProof::sign(
        &lost_key(),
        &identity().public(),
        ProofBody::new(stub, object, state),
    )
    .unwrap()
    .signed()
    .clone()
}

fn record_proof(op: &SignedOp, version: RecordVersion, time: u64) -> SignedDoc {
    let state = ProofState::Record {
        version,
        deleted: false,
        revision: crate::shared::ApplicationRef {
            generation: op.body().generation,
            seq: version.version,
            item_hash: op.item_hash().unwrap(),
        },
    };
    proof_of(op, version.version, time, b64(&[30; 32]), &state)
}

/// The claim after `entries`, as the lost service would show it.
fn view_after(entries: &[ClaimFields]) -> ClaimView {
    let anyone = |_: &[u8; 16]| true;
    let cx = EntryContext {
        writer: app().app_id_bytes(),
        now: NOW,
        can_read: true,
        is_current: &anyone,
        limits: ClaimLimits::default(),
        tally: ClaimTally::default(),
    };
    let mut claim = None;
    for fields in entries {
        claim = Some(apply_entry(claim.as_ref(), &fields.check().unwrap(), &cx).unwrap());
    }
    claim.unwrap().view(&CLAIM_KEY, NOW, &anyone)
}

fn claim_proof(op: &SignedOp, view: &ClaimView, seq: u64) -> SignedDoc {
    proof_of(
        op,
        seq,
        NOW - 5_000,
        b64(&CLAIM_KEY),
        &ProofState::Claim(view.to_value()),
    )
}

fn uploaded(op: &SignedOp, proof: Option<SignedDoc>) -> UploadedOp {
    UploadedOp {
        op: op.signed().clone(),
        cert: cert().signed().clone(),
        proof,
    }
}

fn body_with(records: Vec<UploadedOp>, claims: Vec<UploadedOp>) -> UploadBody {
    UploadBody {
        lost_identity: Some(doc(LOST, &lost_key())),
        records,
        claims,
        ..UploadBody::default()
    }
}

fn check(body: &UploadBody, removed: &[RemovedApp]) -> CheckedUpload {
    let id = identity().public();
    check_upload(
        body,
        &UploadContext {
            identity: &id,
            recovery_from: LOST,
            removed,
        },
    )
}

fn version_of(checked: &CheckedUpload) -> UploadVersion {
    checked.records[0].uploaded.version
}

// The body

fn parse(value: Value) -> Result<UploadBody, Refusal> {
    UploadBody::parse(value.to_string().as_bytes())
}

#[test]
fn test_reused_service_key_keeps_each_generations_receipts_separate() {
    let previous = LOST - 1;
    let mut body = body_with(Vec::new(), Vec::new());
    for gen_no in [previous, LOST] {
        let base = RecordVersion::new(gen_no, 2);
        let op = op_at(gen_no, OpKind::RecordPut(put(base)));
        let receipt = record_proof(&op, RecordVersion::new(gen_no, 9), NOW);
        body.records.push(uploaded(&op, Some(receipt.clone())));
        body.records.push(uploaded(&op, None));
        body.proofs.push(receipt);
        body.heads.push(SignedHead::sign(
            &lost_key(),
            &identity().public(),
            &ChainTip {
                generation: gen_no,
                seq: 9,
                chain_hash: [8; 32],
            },
        ));
    }
    let result = check(&body, &[]);
    assert_eq!((result.heads, result.proofs, result.unverified), (1, 1, 2));
    let versions: Vec<_> = result.records.iter().map(|r| r.uploaded.version).collect();
    let bound = UploadVersion::bound(previous, RecordVersion::new(previous, 2)).unwrap();
    let exact = UploadVersion::proved(RecordVersion::new(LOST, 9));
    assert_eq!(versions, [bound, bound, exact, exact]);
}

#[test]
fn test_upload_body_reads_each_member_and_an_empty_one() {
    let op = record_op(LOST);
    let head = SignedHead::sign(
        &lost_key(),
        &identity().public(),
        &ChainTip {
            generation: LOST,
            seq: 9,
            chain_hash: [8; 32],
        },
    );
    let pubky = pubky_id(&[40; 32]);
    let body = parse(json!({
        "lost_identity": doc(LOST, &lost_key()),
        "records": [{ "op": op.signed(), "cert": cert().signed() }],
        "heads": [head.to_value()],
        "proofs": [record_proof(&op, RecordVersion::new(3, 50), NOW)],
        "lists": { "deny": [pubky] },
    }))
    .unwrap();
    assert_eq!(body.records.len(), 1);
    assert!(body.records[0].proof.is_none());
    assert!(body.claims.is_empty(), "a missing member is empty");
    assert_eq!(body.heads, vec![head]);
    let lists = body.lists.unwrap();
    assert_eq!(lists.kept, None, "kept left out");
    assert_eq!(lists.deny, Some(vec![[40; 32]]));
    assert_eq!(parse(json!({})).unwrap(), UploadBody::default());
}

#[test]
fn test_upload_body_that_doesnt_read_is_400() {
    for body in [
        json!([]),
        json!({ "records": {} }),
        json!({ "records": [{ "op": "x" }] }),
        json!({ "records": [{ "cert": { "body": "a", "sig": "b" } }] }),
        json!({ "heads": [{ "seq": 1 }] }),
        json!({ "lists": { "kept": ["not a pubky"] } }),
        json!({ "lists": { "allow": [] } }),
        json!({ "checkpoint": 1 }),
    ] {
        let refusal = parse(body.clone()).unwrap_err();
        assert_eq!(refusal.status(), 400, "{body}");
    }
}

#[test]
fn test_upload_lists_need_the_callers_permission() {
    let lists = |kept: Option<Vec<[u8; 32]>>, deny: Option<Vec<[u8; 32]>>| UploadBody {
        lists: Some(UploadLists { kept, deny }),
        ..UploadBody::default()
    };
    let none = cert_with(&[SCOPE], &[]);
    let read = cert_with(&[SCOPE], &[Permission::ListsRead]);
    let manage = cert_with(&[SCOPE], &[Permission::ListsManage]);
    let missing = |body: &UploadBody, cert: &AppCert| {
        body.check_permissions(cert).unwrap_err().code == ErrorCode::PermissionMissing
    };
    // Even an empty kept list needs lists.manage.
    let kept = lists(Some(Vec::new()), None);
    assert!(missing(&kept, &read));
    assert!(kept.check_permissions(&manage).is_ok());
    assert!(kept.ends_staged_admission(&manage));
    assert!(
        !kept.ends_staged_admission(&read),
        "not without lists.manage"
    );
    // Deny entries need lists.read or lists.manage, and end nothing.
    let deny = lists(None, Some(vec![[40; 32]]));
    assert!(missing(&deny, &none));
    assert!(deny.check_permissions(&read).is_ok());
    assert!(deny.check_permissions(&manage).is_ok());
    assert!(!deny.ends_staged_admission(&manage));
    assert!(UploadBody::default().check_permissions(&none).is_ok());
}

// Records

#[test]
fn test_upload_record_proof_gives_its_version() {
    let op = record_op(LOST);
    let proof = record_proof(&op, RecordVersion::new(3, 50), NOW);
    let checked = check(
        &body_with(vec![uploaded(&op, Some(proof.clone()))], vec![]),
        &[],
    );
    assert_eq!(
        version_of(&checked),
        UploadVersion::proved(RecordVersion::new(3, 50))
    );
    assert_eq!(
        checked.records[0].uploaded.op_hash,
        op.signed().doc_hash().unwrap()
    );
    // A `proofs` entry whose stub is the operation's gives it as well.
    let mut body = body_with(vec![uploaded(&op, None)], vec![]);
    body.proofs = vec![proof];
    let checked = check(&body, &[]);
    assert_eq!(
        version_of(&checked),
        UploadVersion::proved(RecordVersion::new(3, 50))
    );
    assert_eq!(checked.proofs, 1);
}

#[test]
fn test_upload_record_without_proof_gets_its_bound() {
    let op = record_op(LOST);
    let checked = check(&body_with(vec![uploaded(&op, None)], vec![]), &[]);
    assert_eq!(
        version_of(&checked),
        UploadVersion::bound(LOST, RecordVersion::new(3, 10)).unwrap()
    );
    assert_eq!((checked.unverified, checked.distrusted), (0, 0));
}

#[test]
fn test_upload_out_of_range_proof_counts_as_none() {
    // A proof gives a version only in the operation's own generation and above the version
    // it built on (Dispatch wire 6.2 step 6); any other is as no proof, and the bound stands.
    let op = record_op(LOST);
    let bound = UploadVersion::bound(LOST, RecordVersion::new(3, 10)).unwrap();
    for version in [
        RecordVersion::new(3, 10),
        RecordVersion::new(3, 4),
        RecordVersion::new(2, 50),
        // Above the version it built on, of another generation than its own.
        RecordVersion::new(4, 1),
    ] {
        let state = ProofState::Record {
            version,
            deleted: false,
            revision: crate::shared::ApplicationRef {
                generation: op.body().generation,
                seq: 60,
                item_hash: op.item_hash().unwrap(),
            },
        };
        let proof = proof_of(&op, 60, NOW, b64(&[30; 32]), &state);
        let checked = check(&body_with(vec![uploaded(&op, Some(proof))], vec![]), &[]);
        assert_eq!(version_of(&checked), bound, "{version:?}");
    }
}

#[test]
fn test_upload_proof_of_another_key_or_operation_is_none() {
    let op = record_op(LOST);
    let other = op_at(LOST, OpKind::RecordPut(put(RecordVersion::new(3, 11))));
    let bound = UploadVersion::bound(LOST, RecordVersion::new(3, 10)).unwrap();
    let foreign = {
        let mut doc = record_proof(&op, RecordVersion::new(3, 50), NOW);
        doc.sig = record_proof(&other, RecordVersion::new(3, 50), NOW).sig;
        doc
    };
    for proof in [
        record_proof(&other, RecordVersion::new(3, 50), NOW),
        foreign,
    ] {
        let checked = check(&body_with(vec![uploaded(&op, Some(proof))], vec![]), &[]);
        assert_eq!(version_of(&checked), bound);
    }
}

#[test]
fn test_upload_without_lost_identity_checks_no_proof() {
    let op = record_op(LOST);
    let proof = record_proof(&op, RecordVersion::new(3, 50), NOW);
    let head = SignedHead::sign(
        &lost_key(),
        &identity().public(),
        &ChainTip {
            generation: LOST,
            seq: 9,
            chain_hash: [8; 32],
        },
    );
    let bound = UploadVersion::bound(LOST, RecordVersion::new(3, 10)).unwrap();
    // Missing, of another generation, or signed by another identity.
    let stranger = {
        let mut doc = doc(LOST, &lost_key());
        doc.sig = b64(&[0; 64]);
        doc
    };
    for lost in [None, Some(doc(2, &lost_key())), Some(stranger)] {
        let body = UploadBody {
            lost_identity: lost,
            records: vec![uploaded(&op, Some(proof.clone()))],
            heads: vec![head],
            proofs: vec![proof.clone()],
            ..UploadBody::default()
        };
        let checked = check(&body, &[]);
        assert_eq!(version_of(&checked), bound);
        assert_eq!(
            (checked.heads, checked.proofs, checked.unverified),
            (0, 0, 2)
        );
    }
    let body = UploadBody {
        heads: vec![head],
        ..body_with(vec![], vec![])
    };
    assert_eq!(check(&body, &[]).heads, 1);
}

#[test]
fn test_upload_operation_that_doesnt_verify_is_unverified() {
    let op = record_op(LOST);
    let mut forged = uploaded(&op, None);
    forged.op.sig = b64(&[0; 64]);
    let mut no_scope = uploaded(&op, None);
    no_scope.cert = cert_with(&["scope-b"], &[]).signed().clone();
    let mut bad_cert = uploaded(&op, None);
    bad_cert.cert.sig = b64(&[0; 64]);
    let records = vec![
        forged,
        no_scope,
        bad_cert,
        // Of N's generation: it belongs in `POST /ops`.
        uploaded(&record_op(LOST + 1), None),
        // A claim entry among the records.
        uploaded(&op_at(LOST, OpKind::Claim(attempt_fields())), None),
        // Sealed under another scope than its read scope: a shape no service takes.
        uploaded(
            &op_at(LOST, OpKind::RecordPut(sealed_under("scope-b"))),
            None,
        ),
        // Built on a later generation than its own.
        uploaded(
            &op_at(LOST, OpKind::RecordPut(put(RecordVersion::new(4, 1)))),
            None,
        ),
    ];
    let checked = check(&body_with(records, vec![uploaded(&op, None)]), &[]);
    assert!(checked.records.is_empty() && checked.claims.is_empty());
    assert_eq!(checked.unverified, 8);
    // An earlier generation's operation counts, with its bound.
    let earlier = op_at(2, OpKind::RecordPut(put(RecordVersion::new(2, 10))));
    let checked = check(&body_with(vec![uploaded(&earlier, None)], vec![]), &[]);
    assert_eq!(version_of(&checked).version, RecordVersion::new(2, 11));
}

#[test]
fn test_upload_removed_app_counts_only_dated_before_distrust() {
    let op = record_op(LOST);
    let removed = [RemovedApp {
        app_id: app().app_id_bytes(),
        distrust_from: NOW,
    }];
    let with_proof = |time| {
        let proof = record_proof(&op, RecordVersion::new(3, 50), time);
        check(
            &body_with(vec![uploaded(&op, Some(proof))], vec![]),
            &removed,
        )
    };
    assert_eq!(with_proof(NOW).records.len(), 1, "at distrust_from itself");
    assert_eq!(with_proof(NOW + 1).distrusted, 1);
    let checked = check(&body_with(vec![uploaded(&op, None)], vec![]), &removed);
    assert_eq!((checked.records.len(), checked.distrusted), (0, 1));
    // A claim entry, likewise.
    let attempt = op_at(LOST, OpKind::Claim(attempt_fields()));
    let checked = check(&body_with(vec![], vec![uploaded(&attempt, None)]), &removed);
    assert_eq!((checked.claims.len(), checked.distrusted), (0, 1));
}

// Claims

#[test]
fn test_upload_claim_entries_group_by_key_with_their_proofs() {
    let attempt = op_at(LOST, OpKind::Claim(attempt_fields()));
    let done = op_at(LOST, OpKind::Claim(done_fields()));
    let view = view_after(&[attempt_fields()]);
    let claims = vec![
        uploaded(&done, None),
        uploaded(&attempt, Some(claim_proof(&attempt, &view, 7))),
    ];
    let checked = check(&body_with(vec![], claims), &[]);
    let entries = &checked.claims[&CLAIM_KEY];
    assert_eq!(entries.len(), 2);
    assert!(entries[0].proof.is_none());
    let proof = entries[1].proof.as_ref().unwrap();
    assert_eq!((proof.at, &proof.view), (NOW - 5_000, &view));
    assert_eq!(entries[1].writer, app().app_id_bytes());
}

#[test]
fn test_upload_settled_proof_rebuilds_a_tombstone_only_for_nothing_held() {
    let done = op_at(LOST, OpKind::Claim(done_fields()));
    let view = view_after(&[attempt_fields(), done_fields()]);
    assert_eq!(view.status, ClaimStatus::Settled);
    let mut body = body_with(vec![], vec![]);
    body.proofs = vec![claim_proof(&done, &view, 8)];
    let checked = check(&body, &[]);
    let settled = checked.settled.get(&CLAIM_KEY).unwrap();
    assert_eq!(settled.1, NOW - 5_000);
    let merge = merge_upload_claim(None, Some(settled), &[], NOW, 64);
    let tombstone = merge.claim.unwrap();
    assert!(merge.changed && tombstone.tombstone && tombstone.settled);
    assert!(tombstone.attempts.iter().all(|a| a.from_upload));
    // A claim the service holds settled isn't rebuilt from the proof, nor changed.
    let held = super::super::tombstone_from_proof(&view, NOW - 9_000).unwrap();
    let merge = merge_upload_claim(Some(&held), Some(settled), &[], NOW, 64);
    assert!(!merge.changed);
    // One it holds open and unsettled the proof makes divergent: a change, one step on.
    let anyone = |_: &[u8; 16]| true;
    let cx = EntryContext {
        writer: app().app_id_bytes(),
        now: NOW,
        can_read: true,
        is_current: &anyone,
        limits: ClaimLimits::default(),
        tally: ClaimTally::default(),
    };
    let open = apply_entry(None, &attempt_fields().check().unwrap(), &cx).unwrap();
    let merge = merge_upload_claim(Some(&open), Some(settled), &[], NOW, 64);
    let claim = merge.claim.clone().unwrap();
    assert!(merge.changed && merge.divergent && claim.divergent && claim.rebuilt);
    assert_eq!(claim.step, open.step + 1);
    // Divergent already, it stays so, unchanged.
    let merge = merge_upload_claim(Some(&claim), Some(settled), &[], NOW, 64);
    assert!(!merge.changed);
    // An open claim's proof rebuilds nothing.
    let attempt = op_at(LOST, OpKind::Claim(attempt_fields()));
    body.proofs = vec![claim_proof(&attempt, &view_after(&[attempt_fields()]), 7)];
    assert!(check(&body, &[]).settled.is_empty());
}

#[test]
fn test_recovery_standalone_receipt_dates_only_a_matching_held_write() {
    let op = record_op(LOST);
    let receipt = record_proof(&op, RecordVersion::new(LOST, 50), NOW);
    let mut upload = body_with(vec![], vec![]);
    upload.proofs.push(receipt);
    let checked = check(&upload, &[]);
    assert_eq!(checked.proofs, 1);
    assert!(checked.records.is_empty());
    let mut writes = check(&body_with(vec![uploaded(&op, None)], vec![]), &[]).records;
    let stored = writes.pop().unwrap();
    let applied = checked
        .date_stored_record(&stored, &[])
        .expect("held operation matches the receipt");
    assert_eq!(
        applied.uploaded.version,
        UploadVersion::proved(RecordVersion::new(LOST, 50))
    );
    assert!(checked.date_stored_record(&applied, &[]).is_none());
    assert!(
        checked
            .date_stored_record(&checked_write(11, None), &[])
            .is_none()
    );
    // A later upload starts with no raw receipts carried from an earlier request.
    assert!(
        check(&body_with(vec![], vec![]), &[])
            .date_stored_record(&stored, &[])
            .is_none()
    );
    upload.records.push(uploaded(&op, None));
    assert_eq!(check(&upload, &[]).records, [applied]);
}

/// A signed write on the given base, with its ordinary lost-service receipt if supplied.
fn checked_write(base: u64, applied: Option<u64>) -> CheckedRecord {
    let op = op_at(LOST, OpKind::RecordPut(put(RecordVersion::new(LOST, base))));
    let proof = applied.map(|n| record_proof(&op, RecordVersion::new(LOST, n), NOW));
    check(&body_with(vec![uploaded(&op, proof)], vec![]), &[])
        .records
        .remove(0)
}

fn compare(
    current: &CheckedRecord,
    kept: &[&CheckedRecord],
    incoming: &CheckedRecord,
    limit: usize,
) -> crate::recovery::RecordComparison {
    use crate::recovery::{HeldRecord, merge_checked_record};
    let hashes: Vec<_> = kept.iter().map(|r| r.uploaded.op_hash).collect();
    let held = HeldRecord::FromUpload {
        op_hash: current.uploaded.op_hash,
        built_on: current.uploaded.built_on,
        version: current.uploaded.version,
        divergent: &hashes,
    };
    let state = crate::shared::RecordState::after(
        &current.put,
        LOST,
        current.uploaded.version.version.version,
    );
    merge_checked_record(
        &held,
        Some(&state),
        None,
        kept.iter().copied().enumerate(),
        incoming,
        limit,
    )
}

#[test]
fn test_recovery_a_promoted_successor_frees_space_for_the_displaced_write() {
    use crate::recovery::RecordSource;
    let current = checked_write(9, None);
    let child = checked_write(50, None);
    let other = checked_write(55, None);
    let proved = checked_write(10, Some(50));
    let result = compare(&current, &[&other, &child], &proved, 2);
    assert_eq!(result.install, Some(RecordSource::Retained(1)));
    assert_eq!(result.keep, Some((1, RecordSource::Current)));
    assert!(result.remove.is_empty());
    assert!(result.divergent);
}

#[test]
fn test_recovery_two_ordered_receipts_clear_the_old_conflict_in_either_order() {
    use crate::recovery::RecordSource;
    let older = checked_write(10, Some(30));
    let newer = checked_write(37, Some(50));
    let without_receipt = |r: &CheckedRecord| {
        CheckedRecord::from_storage(r.op.clone(), r.cert.clone(), None).unwrap()
    };
    let promoted = compare(&older, &[&without_receipt(&newer)], &newer, 1);
    assert_eq!(promoted.install, Some(RecordSource::Incoming));
    assert_eq!(promoted.remove, [0]);
    assert!(promoted.keep.is_none() && !promoted.divergent);
    let resolved = compare(&newer, &[&without_receipt(&older)], &older, 1);
    assert_eq!(resolved.install, Some(RecordSource::Current));
    assert_eq!(resolved.remove, [0]);
    assert!(resolved.keep.is_none() && !resolved.divergent);
    let replay = compare(&newer, &[], &older, 1);
    assert_eq!(replay, Default::default());
}

#[test]
fn test_receipt_dates_a_retained_conflict_beside_a_local_write() {
    use crate::recovery::{HeldRecord, RecordComparison, RecordSource, merge_checked_record};
    let exact = checked_write(21, Some(50));
    let bound = CheckedRecord::from_storage(exact.op.clone(), exact.cert.clone(), None).unwrap();
    let hashes = [bound.uploaded.op_hash];
    let held = HeldRecord::WrittenHere {
        upload_base: None,
        divergent: &hashes,
    };
    let state = crate::shared::RecordState::after(&bound.put, LOST + 1, 60);
    let compare = |stored: &CheckedRecord| {
        merge_checked_record(
            &held,
            Some(&state),
            None,
            std::iter::once((0, stored)),
            &exact,
            1,
        )
    };
    assert_eq!(
        compare(&bound),
        RecordComparison {
            keep: Some((0, RecordSource::Incoming)),
            ..RecordComparison::default()
        }
    );
    assert_eq!(compare(&exact), RecordComparison::default());
}

#[test]
fn test_recovery_older_replay_uses_only_evidence_still_available() {
    use crate::recovery::RecordSource;
    let old = checked_write(10, Some(30));
    let new = checked_write(37, Some(50));
    let bound = CheckedRecord::from_storage(old.op.clone(), old.cert.clone(), None).unwrap();
    assert_eq!(compare(&new, &[], &old, 1), Default::default());
    let unresolved = compare(&new, &[], &bound, 1);
    assert!(unresolved.install.is_none() && unresolved.divergent);
    assert_eq!(unresolved.keep, Some((0, RecordSource::Incoming)));
    assert_eq!(compare(&new, &[&bound], &bound, 1), Default::default());
}

#[test]
fn test_later_record_receipt_keeps_unrelated_and_competing_writes() {
    use crate::recovery::{HeldRecord, RecordSource, merge_checked_record};
    use crate::shared::RecordState;
    let first = record_op(LOST);
    let at = RecordVersion::new(LOST, 50);
    let receipt = record_proof(&first, at, NOW);
    let mut uploads = vec![uploaded(&first, None), uploaded(&first, Some(receipt))];
    for base in [at, at, RecordVersion::new(LOST, 51)] {
        let op = op_at(LOST, OpKind::RecordPut(put(base)));
        uploads.push(uploaded(&op, None));
    }
    let checked = check(&body_with(uploads, vec![]), &[]);
    let [current, proved, child, sibling, other] = checked.records.as_slice() else {
        panic!("five valid writes")
    };
    let state = RecordState::after(&current.put, LOST, 11);
    for (kept, selected, removed) in [
        (vec![other, child], RecordSource::Retained(1), Some(1)),
        (vec![child, sibling], RecordSource::Incoming, None),
        (vec![other], RecordSource::Incoming, None),
    ] {
        let hashes: Vec<_> = kept.iter().map(|r| r.uploaded.op_hash).collect();
        let held = HeldRecord::FromUpload {
            op_hash: current.uploaded.op_hash,
            built_on: current.uploaded.built_on,
            version: current.uploaded.version,
            divergent: &hashes,
        };
        let result = merge_checked_record(
            &held,
            Some(&state),
            None,
            kept.into_iter().enumerate(),
            proved,
            hashes.len(),
        );
        assert_eq!(result.install, Some(selected));
        assert_eq!(result.remove, removed.into_iter().collect::<Vec<_>>());
        assert_eq!(result.keep, None);
    }
}

#[test]
fn test_upload_record_of_another_collection_or_policy_is_divergent() {
    use crate::recovery::{HeldRecord, RecordMerge, compare_pair};
    use crate::shared::RecordState;
    let op = record_op(LOST);
    let checked = check(&body_with(vec![uploaded(&op, None)], vec![]), &[]);
    let upload = &checked.records[0];
    let state = RecordState {
        key: [30; 32],
        collection: [31; 32],
        policy: Policy::new(SCOPE, &[SCOPE]),
        version: RecordVersion::new(3, 10),
        deleted: false,
    };
    let held = |divergent: &'static [[u8; 32]]| HeldRecord::FromUpload {
        op_hash: [1; 32],
        built_on: RecordVersion::new(3, 4),
        version: UploadVersion::proved(RecordVersion::new(3, 10)),
        divergent,
    };
    assert_eq!(
        compare_pair(&held(&[]), Some(&state), upload, 8),
        RecordMerge::Replace
    );
    let other_policy = RecordState {
        policy: Policy::new(SCOPE, &[SCOPE, "scope-b"]),
        ..state.clone()
    };
    let other_collection = RecordState {
        collection: [32; 32],
        ..state
    };
    for state in [&other_policy, &other_collection] {
        assert_eq!(
            compare_pair(&held(&[]), Some(state), upload, 8),
            RecordMerge::Divergent { kept: true }
        );
        assert_eq!(
            compare_pair(&held(&[[2; 32]]), Some(state), upload, 1),
            RecordMerge::Divergent { kept: false }
        );
        let kept = [upload.uploaded.op_hash];
        let holding = HeldRecord::FromUpload {
            op_hash: [1; 32],
            built_on: RecordVersion::new(3, 4),
            version: UploadVersion::proved(RecordVersion::new(3, 10)),
            divergent: &kept,
        };
        assert_eq!(
            compare_pair(&holding, Some(state), upload, 8),
            RecordMerge::Unchanged
        );
    }
}

#[test]
fn test_upload_record_that_changes_the_permanent_member_is_divergent() {
    use crate::recovery::{HeldRecord, RecordMerge, compare_pair};
    use crate::shared::RecordState;
    // An upload that drops the member of a permanent record the service holds, or names
    // another generation in it, can't build on that record (Dispatch spec 10.3.1): it is
    // divergent, never the record's replacement, which a later write at its policy could
    // then delete.
    let held = HeldRecord::FromUpload {
        op_hash: [1; 32],
        built_on: RecordVersion::new(3, 4),
        version: UploadVersion::proved(RecordVersion::new(3, 10)),
        divergent: &[],
    };
    let ordinary = Policy::new(SCOPE, &[SCOPE]);
    let mut named = put(RecordVersion::new(3, 10));
    named.policy = ordinary.clone().permanent(Some(1));
    let named = op_at(LOST, OpKind::RecordPut(named));
    for (op, policy) in [
        (record_op(LOST), ordinary.clone().permanent(None)),
        (record_op(LOST), ordinary.clone().permanent(Some(1))),
        (named.clone(), ordinary.clone().permanent(Some(2))),
        (named, ordinary.clone()),
    ] {
        let checked = check(&body_with(vec![uploaded(&op, None)], vec![]), &[]);
        let upload = &checked.records[0];
        let state = RecordState {
            key: [30; 32],
            collection: [31; 32],
            policy: policy.clone(),
            version: RecordVersion::new(3, 10),
            deleted: false,
        };
        assert_eq!(
            compare_pair(&held, Some(&state), upload, 8),
            RecordMerge::Divergent { kept: true },
            "{:?} over {policy:?}",
            upload.put.policy
        );
        // At the record's own policy, the same upload replaces the older one.
        let same = RecordState {
            policy: upload.put.policy.clone(),
            ..state
        };
        assert_eq!(
            compare_pair(&held, Some(&same), upload, 8),
            RecordMerge::Replace
        );
    }
}

#[test]
fn test_upload_settled_proof_at_the_highest_step_is_taken() {
    // Of two SETTLED proofs for one claim, the one at the higher step is the one taken,
    // whatever their order in `proofs`.
    let done = op_at(LOST, OpKind::Claim(done_fields()));
    let view = view_after(&[attempt_fields(), done_fields()]);
    let mut later = view.clone();
    later.step += 1;
    let first = claim_proof(&done, &view, 8);
    let second = proof_of(
        &done,
        9,
        NOW - 1_000,
        b64(&CLAIM_KEY),
        &ProofState::Claim(later.to_value()),
    );
    for proofs in [vec![first.clone(), second.clone()], vec![second, first]] {
        let mut body = body_with(vec![], vec![]);
        body.proofs = proofs;
        let checked = check(&body, &[]);
        assert_eq!(checked.settled[&CLAIM_KEY].0.step, later.step);
    }
}

#[test]
fn test_upload_claim_view_says_rebuilt_only_when_it_is() {
    // A claim an upload changed shows `rebuilt` in its view, written only when true, so a
    // claim never rebuilt reads exactly as before (Dispatch wire 6.8, 7.4.8).
    let view = view_after(&[attempt_fields()]);
    assert!(!view.rebuilt);
    assert!(view.to_value().get("rebuilt").is_none());
    let anyone = |_: &[u8; 16]| true;
    let entry = UploadedEntry {
        entry: ClaimFields {
            attempt_id: vec![22; 16],
            ..attempt_fields()
        }
        .check()
        .unwrap(),
        writer: [9; 16],
        proof: None,
    };
    let merge = merge_upload_claim(None, None, &[entry], NOW, 64);
    let rebuilt = merge.claim.unwrap().view(&CLAIM_KEY, NOW, &anyone);
    assert!(rebuilt.rebuilt);
    let value = rebuilt.to_value();
    assert_eq!(value["rebuilt"], json!(true));
    assert_eq!(ClaimView::from_value(&value).unwrap(), rebuilt);
}

fn record_proofs_with_other_references(original: &TransitionProof) -> Vec<TransitionProof> {
    (0..5)
        .map(|case| {
            let mut body = original.body().clone();
            match case {
                0 => {
                    body.state.as_object_mut().unwrap().remove("revision");
                }
                1 => body.state["revision"]["generation"] = json!(LOST + 1),
                2 => body.state["revision"]["seq"] = json!(49),
                3 => body.state["revision"]["item_hash"] = json!(b64(&[9; 32])),
                _ => body.state["revision"]["extra"] = Value::Null,
            }
            let changed = TransitionProof::sign(&lost_key(), &identity().public(), body).unwrap();
            TransitionProof::verify(
                changed.signed(),
                &lost_key().verifying_key().to_bytes(),
                &identity().public(),
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn test_record_current_proved_version_checks_the_reference() {
    let op = record_op(LOST);
    let proof = record_proof(&op, RecordVersion::new(LOST, 50), NOW);
    let original = TransitionProof::verify(
        &proof,
        &lost_key().verifying_key().to_bytes(),
        &identity().public(),
    )
    .unwrap();
    assert_eq!(
        proved_version(&original, LOST, RecordVersion::new(LOST, 10)),
        Some(RecordVersion::new(LOST, 50))
    );
    for changed in record_proofs_with_other_references(&original) {
        assert_eq!(
            proved_version(&changed, LOST, RecordVersion::new(LOST, 10)),
            None
        );
    }
}

#[test]
fn test_record_current_upload_proof_cannot_supply_another_reference() {
    let op = record_op(LOST);
    let proof = record_proof(&op, RecordVersion::new(LOST, 50), NOW);
    let original = TransitionProof::verify(
        &proof,
        &lost_key().verifying_key().to_bytes(),
        &identity().public(),
    )
    .unwrap();
    let valid = check(&body_with(vec![uploaded(&op, Some(proof))], vec![]), &[]);
    assert_eq!(
        version_of(&valid),
        UploadVersion::proved(RecordVersion::new(LOST, 50))
    );
    for changed in record_proofs_with_other_references(&original) {
        let checked = check(
            &body_with(vec![uploaded(&op, Some(changed.signed().clone()))], vec![]),
            &[],
        );
        assert_eq!(checked.records.len(), 1);
        assert_eq!((checked.unverified, checked.distrusted), (0, 0));
        assert_eq!(
            version_of(&checked),
            UploadVersion::bound(LOST, RecordVersion::new(LOST, 10)).unwrap()
        );
    }
}

#[test]
fn test_deny_room_fits_up_to_the_limit() {
    let peer = |n: u64| {
        let mut key = [3u8; 32];
        key[24..].copy_from_slice(&n.to_be_bytes());
        key
    };
    let full: Vec<_> = (0..MAX_DENY).map(peer).collect();
    assert_eq!(MAX_DENY, 10_000, "every service holds the same deny limit");
    assert_eq!(check_deny_room(0, &[], |_| false), Ok(()));
    assert_eq!(
        check_deny_room(0, &full, |_| false),
        Ok(()),
        "a full copy fits an empty list"
    );
    // Entries held already and repeats take no room.
    let mut again = full.clone();
    again.extend(full.iter().take(5));
    assert_eq!(check_deny_room(MAX_DENY, &again, |_| true), Ok(()));
    assert_eq!(
        check_deny_room(MAX_DENY - 2, &[peer(1), peer(1), peer(2)], |_| false),
        Ok(())
    );
}

#[test]
fn test_deny_room_refuses_the_whole_upload_with_the_overflow() {
    let peer = |n: u64| {
        let mut key = [4u8; 32];
        key[24..].copy_from_slice(&n.to_be_bytes());
        key
    };
    // H = 9,999 held, U = the three new distinct entries (one repeated, one held): over 2.
    let held = peer(0);
    let uploaded = [peer(1), peer(1), peer(2), peer(3), held];
    let refusal = check_deny_room(MAX_DENY - 1, &uploaded, |p| *p == held).unwrap_err();
    assert_eq!(refusal.code, ErrorCode::QuotaExceeded);
    assert_eq!(refusal.status(), 429);
    let current = refusal.current.unwrap();
    assert_eq!(current, json!({ "limit": "deny", "over": 2 }));
    assert_eq!(deny_over(&current), Some(2));
    // An upload that alone passes the limit is refused as no list could hold it.
    let too_many: Vec<_> = (0..=MAX_DENY).map(peer).collect();
    let refusal = check_deny_room(0, &too_many, |_| false).unwrap_err();
    assert_eq!(refusal.code, ErrorCode::BadRequest);
    // Other quota answers carry no deny overflow.
    for other in [
        json!({ "limit": "deny" }),
        json!({ "limit": "kept_peers", "over": 1 }),
        json!({ "limit": "deny", "over": 0 }),
    ] {
        assert_eq!(deny_over(&other), None, "{other}");
    }
}
