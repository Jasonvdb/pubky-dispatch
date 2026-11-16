//! Public recovery witness decisions (Switch record lineage 7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pubky_switch_core::{
    enc::b64,
    http::ErrorCode,
    json::MAX_INT,
    keys::IdentityKey,
    ops::{Position, Refusal},
    record_authority::{RecordRecovery, RecoveryCursor, WitnessExclusions},
    records::{
        IdentityBody, IdentityDoc, IdentityPolicy, Inbox, ListedApp, RemovedApp, RenewedCert,
    },
};
use serde_json::json;

const A: [u8; 16] = [10; 16];
const B: [u8; 16] = [20; 16];
const C: [u8; 16] = [30; 16];

fn signer() -> IdentityKey {
    IdentityKey::from_secret([4; 32])
}

fn signed(body: IdentityBody) -> IdentityDoc {
    let doc = IdentityDoc::sign(&signer(), body).unwrap();
    IdentityDoc::verify(doc.signed(), &signer().public()).unwrap()
}

fn source() -> IdentityDoc {
    let mut body = IdentityBody::first(
        signer().public(),
        [5; 16],
        Inbox::new("https://switch.example", [6; 32]),
        IdentityPolicy::default(),
    );
    body.version = 4;
    body.generation = 3;
    body.recovery_from = Some(2);
    body.apps = vec![
        ListedApp {
            app_id: B,
            cert: [2; 32],
        },
        ListedApp {
            app_id: A,
            cert: [1; 32],
        },
    ];
    body.renewed.push(RenewedCert {
        app_id: A,
        cert: [3; 32],
        until: None,
    });
    signed(body)
}

fn position(generation: u64, seq: u64) -> Position {
    Position { generation, seq }
}

fn model() -> RecordRecovery {
    RecordRecovery::start(&signer().public(), source(), position(3, 1), 2).unwrap()
}

fn current() -> IdentityDoc {
    let mut body = source().body().clone();
    body.version = 7;
    body.generation = 5;
    signed(body)
}

fn request() -> RecoveryCursor {
    RecoveryCursor {
        position: position(5, 10),
        records_complete: Some(position(3, 1)),
        held: Some(position(3, 0)),
        newest: 12,
        continued_from: Some(4),
    }
}

fn no_exclusions() -> WitnessExclusions<'static> {
    WitnessExclusions {
        revoked: &[],
        departed: &[],
    }
}

fn completed() -> RecordRecovery {
    model()
        .propose_cursor(&current(), &A, request())
        .unwrap()
        .into_parts()
        .0
}

fn assert_bad(error: Refusal) {
    assert_eq!(error.code, ErrorCode::BadRequest);
    assert_eq!(error.current, None);
}

fn assert_conflict(error: Refusal, complete: &[[u8; 16]]) {
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(
        error.current,
        Some(json!({ "record_recovery": {
            "position": "3:1", "witnesses": [b64(&A), b64(&B)],
            "complete": complete.iter().map(|app| b64(app)).collect::<Vec<_>>()
        }}))
    );
}

#[test]
fn test_record_recovery_captures_signed_fixed_witnesses() {
    let held = model();
    assert_eq!(held.source(), &source());
    assert_eq!(held.source().signed(), source().signed());
    assert_eq!(held.barrier().position, position(3, 1));
    assert_eq!(held.barrier().witnesses, vec![A, B]);
    assert!(held.barrier().complete.is_empty());
    // Registration, scopes and online state cannot remove a signed witness.
    assert_eq!(
        held.incomplete(&source(), no_exclusions()).unwrap(),
        vec![A, B]
    );
}

#[test]
fn test_record_recovery_source_identity_is_required() {
    assert!(
        RecordRecovery::start(
            &IdentityKey::from_secret([8; 32]).public(),
            source(),
            position(3, 1),
            2
        )
        .is_err()
    );
    assert!(RecordRecovery::start(&signer().public(), source(), position(3, 1), 2).is_ok());
}

#[test]
fn test_record_recovery_source_is_an_immediate_loss() {
    for lost in [None, Some(1), Some(3)] {
        let mut body = source().body().clone();
        body.recovery_from = lost;
        assert!(
            RecordRecovery::start(&signer().public(), signed(body), position(3, 1), 2).is_err(),
            "lost {lost:?}"
        );
    }
    assert!(RecordRecovery::start(&signer().public(), source(), position(3, 1), 2).is_ok());
}

#[test]
fn test_record_recovery_source_position_is_the_loss_transition() {
    for at in [
        position(2, 1),
        position(4, 1),
        position(3, 0),
        position(3, 2),
    ] {
        assert!(
            RecordRecovery::start(&signer().public(), source(), at, 2).is_err(),
            "position {at}"
        );
    }
    let mut first = source().body().clone();
    first.generation = 1;
    first.recovery_from = Some(0);
    assert!(RecordRecovery::start(&signer().public(), signed(first), position(1, 1), 2).is_err());
    assert!(RecordRecovery::start(&signer().public(), source(), position(3, 1), 2).is_ok());
}

#[test]
fn test_record_recovery_witness_limit_counts_app_ids() {
    assert!(RecordRecovery::start(&signer().public(), source(), position(3, 1), 1).is_err());
    assert_eq!(
        RecordRecovery::start(&signer().public(), source(), position(3, 1), 2)
            .unwrap()
            .barrier()
            .witnesses
            .len(),
        2
    );
}

#[test]
fn test_record_recovery_empty_signed_witness_set_retains_provenance() {
    let mut body = source().body().clone();
    body.apps.clear();
    body.renewed.clear();
    let doc = signed(body);
    let held = RecordRecovery::start(&signer().public(), doc.clone(), position(3, 1), 0).unwrap();
    assert!(held.barrier().witnesses.is_empty());
    assert_eq!(held.source(), &doc);
    assert_eq!(held.barrier().position, position(3, 1));
}

#[test]
fn test_record_recovery_restore_requires_exact_witnesses() {
    let held = model();
    for witnesses in [vec![A], vec![B, A], vec![A, A, B], vec![A, C]] {
        let mut barrier = held.barrier().clone();
        barrier.witnesses = witnesses;
        assert!(RecordRecovery::restore(&signer().public(), source(), barrier, 2).is_err());
    }
    assert_eq!(
        RecordRecovery::restore(&signer().public(), source(), held.barrier().clone(), 2).unwrap(),
        held
    );
}

#[test]
fn test_record_recovery_restore_rejects_foreign_completion() {
    let mut barrier = model().barrier().clone();
    barrier.complete = vec![C];
    assert!(RecordRecovery::restore(&signer().public(), source(), barrier.clone(), 2).is_err());
    barrier.complete = vec![A];
    assert_eq!(
        RecordRecovery::restore(&signer().public(), source(), barrier, 2).unwrap(),
        completed()
    );
}

#[test]
fn test_record_recovery_restore_rejects_duplicate_or_unordered_completion() {
    for complete in [vec![A, A], vec![B, A]] {
        let mut barrier = model().barrier().clone();
        barrier.complete = complete;
        assert!(RecordRecovery::restore(&signer().public(), source(), barrier, 2).is_err());
    }
    let mut barrier = model().barrier().clone();
    barrier.complete = vec![A, B];
    assert!(RecordRecovery::restore(&signer().public(), source(), barrier, 2).is_ok());
}

#[test]
fn test_record_recovery_restore_preserves_completed_source() {
    let held = completed();
    let restored = RecordRecovery::restore(
        &signer().public(),
        held.source().clone(),
        held.barrier().clone(),
        2,
    )
    .unwrap();
    assert_eq!(restored, held);
    assert_eq!(
        restored.incomplete(&current(), no_exclusions()).unwrap(),
        vec![B]
    );
    let mut changed = source().body().clone();
    changed.apps[0].app_id = C;
    assert!(
        RecordRecovery::restore(
            &signer().public(),
            signed(changed),
            held.barrier().clone(),
            2
        )
        .is_err()
    );
}

#[test]
fn test_record_recovery_current_identity_must_match() {
    let other = IdentityKey::from_secret([8; 32]);
    let mut body = current().body().clone();
    body.identity = other.public();
    let doc = IdentityDoc::sign(&other, body).unwrap();
    assert!(model().incomplete(&doc, no_exclusions()).is_err());
    assert_bad(model().propose_cursor(&doc, &A, request()).unwrap_err());
}

#[test]
fn test_record_recovery_current_document_cannot_go_back_or_fork() {
    let mut older = source().body().clone();
    older.version -= 1;
    let mut fork = source().body().clone();
    fork.apps.remove(0);
    for body in [older, fork] {
        assert!(model().incomplete(&signed(body), no_exclusions()).is_err());
    }
    assert!(model().incomplete(&current(), no_exclusions()).is_ok());
}

#[test]
fn test_record_recovery_later_generation_keeps_original_loss_boundary() {
    assert_eq!(
        model().incomplete(&current(), no_exclusions()).unwrap(),
        vec![A, B]
    );
    assert_eq!(model().source().body().recovery_from, Some(2));
    for boundary in [None, Some(1), Some(4)] {
        let mut body = current().body().clone();
        body.recovery_from = boundary;
        assert!(model().incomplete(&signed(body), no_exclusions()).is_err());
    }
}

#[test]
fn test_record_recovery_removed_incomplete_witness_counts_on_return() {
    let held = model();
    let mut body = current().body().clone();
    body.apps.retain(|a| a.app_id != A);
    body.removed.push(RemovedApp {
        app_id: A,
        distrust_from: 1,
    });
    let removed = signed(body.clone());
    assert_eq!(held.incomplete(&removed, no_exclusions()).unwrap(), vec![B]);
    body.version += 1;
    body.removed.clear();
    body.apps.push(ListedApp {
        app_id: A,
        cert: [9; 32],
    });
    assert_eq!(
        held.incomplete(&signed(body), no_exclusions()).unwrap(),
        vec![A, B]
    );
    assert!(held.barrier().complete.is_empty());
}

#[test]
fn test_record_recovery_departure_and_revocation_preserve_bits() {
    let held = model();
    assert_eq!(
        held.incomplete(
            &current(),
            WitnessExclusions {
                revoked: &[A],
                departed: &[B]
            }
        )
        .unwrap(),
        Vec::<[u8; 16]>::new()
    );
    assert_eq!(
        held.incomplete(
            &current(),
            WitnessExclusions {
                revoked: &[],
                departed: &[B]
            }
        )
        .unwrap(),
        vec![A]
    );
    assert_eq!(
        held.incomplete(&current(), no_exclusions()).unwrap(),
        vec![A, B]
    );
    assert!(held.barrier().complete.is_empty());
}

#[test]
fn test_record_recovery_new_app_never_joins_fixed_membership() {
    let held = model();
    let mut body = current().body().clone();
    body.apps.push(ListedApp {
        app_id: C,
        cert: [9; 32],
    });
    let doc = signed(body);
    assert_eq!(held.incomplete(&doc, no_exclusions()).unwrap(), vec![A, B]);
    assert_bad(held.propose_cursor(&doc, &C, request()).unwrap_err());
    let mut ordinary = request();
    ordinary.records_complete = None;
    assert_eq!(
        held.propose_cursor(&doc, &C, ordinary).unwrap().cursor(),
        ordinary.position
    );
}

#[test]
fn test_record_recovery_completion_survives_exclusion_and_key_change() {
    let held = completed();
    let mut body = current().body().clone();
    body.apps
        .iter_mut()
        .find(|app| app.app_id == A)
        .unwrap()
        .cert = [9; 32];
    let doc = signed(body);
    assert_eq!(
        held.incomplete(
            &doc,
            WitnessExclusions {
                revoked: &[A],
                departed: &[]
            }
        )
        .unwrap(),
        vec![B]
    );
    assert_eq!(held.incomplete(&doc, no_exclusions()).unwrap(), vec![B]);
    assert_eq!(held.barrier().complete, vec![A]);
}

#[test]
fn test_record_recovery_next_loss_starts_with_no_completed_witness() {
    let old = completed();
    let mut body = current().body().clone();
    body.generation = 6;
    body.version += 1;
    body.recovery_from = Some(5);
    let doc = signed(body);
    let new = RecordRecovery::start(&signer().public(), doc.clone(), position(6, 1), 2).unwrap();
    assert_eq!(new.incomplete(&doc, no_exclusions()).unwrap(), vec![A, B]);
    assert!(new.barrier().complete.is_empty());
    assert_eq!(old.barrier().complete, vec![A]);
    let next = RecoveryCursor {
        position: position(6, 1),
        held: None,
        continued_from: None,
        records_complete: Some(position(3, 1)),
        newest: 1,
    };
    assert_eq!(
        new.propose_cursor(&doc, &A, next).unwrap_err().code,
        ErrorCode::Conflict
    );
}

#[test]
fn test_record_recovery_proposal_keeps_held_state_until_committed() {
    let held = model();
    let before = held.clone();
    let proposal = held.propose_cursor(&current(), &A, request()).unwrap();
    assert_eq!(held, before);
    assert_eq!(proposal.cursor(), position(5, 10));
    assert_eq!(proposal.recovery().barrier().complete, vec![A]);
    drop(proposal);
    assert_eq!(held, before);
    let (next, cursor) = held
        .propose_cursor(&current(), &B, request())
        .unwrap()
        .into_parts();
    assert_eq!(next.barrier().complete, vec![B]);
    assert_eq!(cursor, position(5, 10));
    assert_eq!(held, before);
}

#[test]
fn test_record_recovery_completion_at_exact_barrier() {
    let input = RecoveryCursor {
        position: position(3, 1),
        records_complete: Some(position(3, 1)),
        held: None,
        newest: 1,
        continued_from: None,
    };
    let proposal = model().propose_cursor(&source(), &A, input).unwrap();
    assert_eq!(proposal.cursor(), position(3, 1));
    assert_eq!(proposal.recovery().barrier().complete, vec![A]);
}

#[test]
fn test_record_recovery_wrong_barrier_returns_exact_current() {
    let mut input = request();
    input.records_complete = Some(position(5, 1));
    let held = model();
    assert_conflict(held.propose_cursor(&current(), &A, input).unwrap_err(), &[]);
    assert!(held.barrier().complete.is_empty());
}

#[test]
fn test_record_recovery_outsider_cannot_complete() {
    assert_bad(
        model()
            .propose_cursor(&current(), &C, request())
            .unwrap_err(),
    );
    assert!(model().propose_cursor(&current(), &A, request()).is_ok());
}

#[test]
fn test_record_recovery_cursor_must_reach_barrier() {
    let mut input = request();
    input.position.seq = 0;
    assert_bad(model().propose_cursor(&current(), &A, input).unwrap_err());
    input.records_complete = None;
    assert_eq!(
        model()
            .propose_cursor(&current(), &A, input)
            .unwrap()
            .cursor(),
        position(3, 0)
    );
}

#[test]
fn test_record_recovery_crossing_needs_completion() {
    let mut input = request();
    input.records_complete = None;
    let held = model();
    assert_conflict(held.propose_cursor(&current(), &A, input).unwrap_err(), &[]);
    assert!(held.barrier().complete.is_empty());
    input.position.seq = 0;
    assert!(held.propose_cursor(&current(), &A, input).is_ok());
}

#[test]
fn test_record_recovery_current_or_continued_cursor_only() {
    let held = model();
    let mut input = request();
    input.position = position(4, 10);
    assert!(held.propose_cursor(&current(), &A, input).is_ok());
    for generation in [2, 3, 6] {
        input.position.generation = generation;
        assert_bad(held.propose_cursor(&current(), &A, input).unwrap_err());
    }
    input.position.generation = 4;
    input.continued_from = None;
    assert_bad(held.propose_cursor(&current(), &A, input).unwrap_err());
}

#[test]
fn test_record_recovery_continuation_cannot_cross_a_loss() {
    for generation in [0, 2, 5, 6] {
        let mut input = request();
        input.continued_from = Some(generation);
        assert_bad(model().propose_cursor(&current(), &A, input).unwrap_err());
    }
    assert!(model().propose_cursor(&current(), &A, request()).is_ok());
}

#[test]
fn test_record_recovery_newest_position_bounds_request() {
    let mut input = request();
    input.position.seq = 13;
    assert_bad(model().propose_cursor(&current(), &A, input).unwrap_err());
    input.position.seq = 12;
    assert!(model().propose_cursor(&current(), &A, input).is_ok());
    for newest in [0, MAX_INT + 1] {
        input.newest = newest;
        assert_bad(model().propose_cursor(&current(), &A, input).unwrap_err());
    }
}

#[test]
fn test_record_recovery_held_cursor_cannot_come_from_another_sequence() {
    for at in [position(2, 0), position(6, 0), position(5, 13)] {
        let mut input = request();
        input.held = Some(at);
        assert_bad(model().propose_cursor(&current(), &A, input).unwrap_err());
    }
    assert!(model().propose_cursor(&current(), &A, request()).is_ok());
}

#[test]
fn test_record_recovery_incomplete_held_cursor_cannot_have_crossed() {
    let mut input = request();
    input.held = Some(position(5, 1));
    assert_bad(model().propose_cursor(&current(), &A, input).unwrap_err());
    assert!(completed().propose_cursor(&current(), &A, input).is_ok());
}

#[test]
fn test_record_recovery_repeat_retains_later_cursor() {
    let held = completed();
    let mut input = request();
    input.held = Some(position(4, 11));
    let proposal = held.propose_cursor(&current(), &A, input).unwrap();
    assert_eq!(proposal.cursor(), position(4, 11));
    assert_eq!(proposal.recovery(), &held);
    input.position.seq = 11;
    assert_eq!(
        held.propose_cursor(&current(), &A, input).unwrap().cursor(),
        position(4, 11)
    );
    input.records_complete = None;
    input.position.seq = 12;
    assert_eq!(
        held.propose_cursor(&current(), &A, input).unwrap().cursor(),
        position(5, 12)
    );
}

#[test]
fn test_record_recovery_second_completion_is_sorted_and_independent() {
    let held = model()
        .propose_cursor(&current(), &B, request())
        .unwrap()
        .into_parts()
        .0;
    let next = held
        .propose_cursor(&current(), &A, request())
        .unwrap()
        .into_parts()
        .0;
    assert_eq!(next.barrier().complete, vec![A, B]);
    assert!(
        next.incomplete(&current(), no_exclusions())
            .unwrap()
            .is_empty()
    );
    assert_eq!(held.barrier().complete, vec![B]);
}
