use super::*;

/// The state of every row with one: generation 2, `seq` 10.
const STATE: ChainTip = tip(2, 10, 1);
/// The count of every row's account (Switch wire 7.3, "The state").
const COUNT: u64 = 10;
/// The time of the erasure's record of the erased rows; their marks were made before.
const ERASED_AT: u64 = 200;

const fn tip(generation: u64, seq: u64, hash: u8) -> ChainTip {
    ChainTip {
        generation,
        seq,
        chain_hash: [hash; 32],
    }
}

fn mark(generation: u64, seq: u64, hash: u8) -> MarkInput {
    MarkInput::Mark(mark_created(generation, seq, hash, 100))
}

/// A mark at (`generation`, `seq`) that covers the count `state_version`.
fn counting(generation: u64, seq: u64, hash: u8, state_version: u64) -> MarkInput {
    MarkInput::Mark(Mark {
        state_version,
        ..mark_created(generation, seq, hash, 100)
    })
}

fn mark_created(generation: u64, seq: u64, hash: u8, created_at_ms: u64) -> Mark {
    Mark {
        generation,
        seq,
        chain_hash: if generation == 0 { [0; 32] } else { [hash; 32] },
        state_version: 0,
        created_at_ms,
    }
}

#[derive(Clone, Copy)]
enum Row {
    ErasedAgain,
    None,
    NoneErased,
    StagedNoChain,
    StagedImport,
    Serving,
    Frozen,
}

fn account(row: Row) -> Option<Account> {
    let staged = |state| Account {
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        state,
        state_version: COUNT,
        created_at_ms: 100,
        document_generation: None,
        enrolled_generation: 2,
    };
    let serving = |state| Account {
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        state,
        state_version: COUNT,
        created_at_ms: 100,
        document_generation: Some(2),
        enrolled_generation: 2,
    };
    match row {
        Row::None | Row::NoneErased => None,
        Row::ErasedAgain | Row::Serving => Some(serving(AccountState::Serving(STATE))),
        Row::Frozen => Some(serving(AccountState::Frozen(STATE))),
        Row::StagedNoChain => Some(staged(AccountState::StagedNoChain)),
        Row::StagedImport => Some(staged(AccountState::StagedImport(STATE))),
    }
}

fn judged(row: Row, mark: MarkInput, retired: &[u64]) -> Judgement {
    judged_with(row, mark, None, retired)
}

fn judged_with(row: Row, mark: MarkInput, stub: Option<[u8; 32]>, retired: &[u64]) -> Judgement {
    let account = account(row);
    let erasure_at_ms = match row {
        Row::ErasedAgain | Row::NoneErased => Some(ERASED_AT),
        _ => None,
    };
    judge(&Inputs {
        account: account.as_ref(),
        mark: &mark,
        stub_at_mark: stub,
        erasure_at_ms,
        retired,
    })
}

fn verdict(row: Row, mark: MarkInput, retired: &[u64]) -> Verdict {
    judged(row, mark, retired).verdict
}

fn notice(generation: u64, reason: NoticeReason, permanent: bool) -> RecoveryNotice {
    RecoveryNotice {
        generation,
        reason,
        permanent,
    }
}

fn failing(generation: u64, reason: NoticeReason, permanent: bool, abort_allowed: bool) -> Verdict {
    Verdict::Failing {
        notice: notice(generation, reason, permanent),
        abort_allowed,
    }
}

fn bounded(generation: u64, permanent: bool) -> Verdict {
    Verdict::Bounded {
        notice: notice(generation, NoticeReason::Behind, permanent),
        abort_allowed: true,
    }
}

fn lost(generation: u64, permanent: bool) -> Verdict {
    Verdict::Lost {
        notice: notice(generation, NoticeReason::Behind, permanent),
    }
}

const NOT_HOSTED: Verdict = Verdict::NotHosted { delete_mark: false };
const LEFTOVER: Verdict = Verdict::NotHosted { delete_mark: true };

/// The marks of the column "Mark records a head; state at or past it": at the state,
/// and behind it.
fn at_or_past_marks() -> [MarkInput; 2] {
    [mark(2, 10, 1), mark(2, 5, 7)]
}

/// The marks of the column "state behind it": a higher `seq`, a later generation.
fn behind_marks() -> [MarkInput; 2] {
    [mark(2, 12, 7), mark(3, 1, 7)]
}

/// The mark of the column "Mark at the state's pair, another chain hash".
fn fork_mark() -> MarkInput {
    mark(2, 10, 9)
}

fn assert_erased_again(mark: MarkInput, retired: &[u64], then: Verdict) {
    let judgement = judged(Row::ErasedAgain, mark, retired);
    assert!(judgement.erase_account_again);
    assert_eq!(judgement.verdict, then);
}

// Table 1, row "Any, created at or before the time of an erasure's record".

#[test]
fn test_verdict_rule_fork_stub_of_the_marks_generation_whatever_the_states() {
    let marked = Mark {
        generation: 1,
        seq: 5,
        chain_hash: [1; 32],

        state_version: 0,
        created_at_ms: 0,
    };
    // Past the mark in its generation, and at a later generation: the stub at the
    // mark's generation and `seq` counts either way (Switch wire 7.3 under Table 1).
    assert_eq!(stub_for_fork_rule(Some((1, 6)), &marked), Some((1, 5)));
    assert_eq!(stub_for_fork_rule(Some((2, 3)), &marked), Some((1, 5)));
    // At or behind the mark, without a state, or at a mark that records no head: none.
    assert_eq!(stub_for_fork_rule(Some((1, 5)), &marked), None);
    assert_eq!(stub_for_fork_rule(Some((1, 4)), &marked), None);
    assert_eq!(stub_for_fork_rule(None, &marked), None);
    assert_eq!(stub_for_fork_rule(Some((2, 3)), &Mark::zero(0)), None);
    // A later generation's state over another hash there is a fork.
    let serving = Account {
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        state: AccountState::Serving(ChainTip {
            generation: 2,
            seq: 3,
            chain_hash: [2; 32],
        }),
        state_version: 0,
        created_at_ms: 0,
        document_generation: Some(2),
        enrolled_generation: 2,
    };
    let judged = judge(&Inputs {
        account: Some(&serving),
        mark: &MarkInput::Mark(marked),
        stub_at_mark: Some([9; 32]),
        erasure_at_ms: None,
        retired: &[],
    });
    assert!(
        matches!(
            judged.verdict,
            Verdict::Failing {
                notice: RecoveryNotice {
                    reason: NoticeReason::Fork,
                    ..
                },
                ..
            }
        ),
        "{:?}",
        judged.verdict
    );
}

#[test]
fn test_verdict_erased_again_no_mark() {
    for mark in [MarkInput::Missing, MarkInput::NotAMark] {
        assert_erased_again(
            mark,
            &[],
            if matches!(mark, MarkInput::NotAMark) {
                Verdict::Unknown
            } else {
                NOT_HOSTED
            },
        );
    }
}

#[test]
fn test_verdict_erased_again_zero_mark() {
    assert_erased_again(mark(0, 0, 0), &[], LEFTOVER);
}

#[test]
fn test_verdict_erased_again_at_or_past() {
    for mark in at_or_past_marks() {
        assert_erased_again(mark, &[], LEFTOVER);
    }
}

#[test]
fn test_verdict_erased_again_behind() {
    for mark in behind_marks() {
        assert_erased_again(mark, &[], LEFTOVER);
    }
}

#[test]
fn test_verdict_erased_again_fork() {
    assert_erased_again(fork_mark(), &[], LEFTOVER);
}

#[test]
fn test_verdict_erased_again_store_unreadable() {
    let judgement = judged(Row::ErasedAgain, MarkInput::StoreUnreadable, &[]);
    assert!(!judgement.erase_account_again);
    assert_eq!(judgement.verdict, Verdict::Unknown);
}

#[test]
fn test_verdict_erased_again_retired() {
    assert_erased_again(mark(2, 12, 7), &[2], LEFTOVER);
}

// Table 1, row "None".

#[test]
fn test_verdict_none_no_mark() {
    for mark in [MarkInput::Missing, MarkInput::NotAMark] {
        assert_eq!(
            verdict(Row::None, mark, &[]),
            if matches!(mark, MarkInput::NotAMark) {
                Verdict::Unknown
            } else {
                NOT_HOSTED
            }
        );
    }
}

#[test]
fn test_verdict_none_zero_mark() {
    assert_eq!(verdict(Row::None, mark(0, 0, 0), &[]), NOT_HOSTED);
}

#[test]
fn test_verdict_none_at_or_past() {
    // With no account there is no state: a mark that records a head is a lost
    // account's, whatever it records.
    assert_eq!(verdict(Row::None, mark(2, 10, 1), &[]), lost(2, false));
}

#[test]
fn test_verdict_none_behind() {
    assert_eq!(verdict(Row::None, mark(3, 1, 7), &[]), lost(3, false));
}

#[test]
fn test_verdict_none_fork() {
    assert_eq!(verdict(Row::None, fork_mark(), &[]), lost(2, false));
}

#[test]
fn test_verdict_none_store_unreadable() {
    let judgement = judged(Row::None, MarkInput::StoreUnreadable, &[]);
    assert_eq!(judgement.verdict, Verdict::Unknown);
    assert!(!judgement.erase_account_again);
}

#[test]
fn test_verdict_none_retired() {
    assert_eq!(verdict(Row::None, mark(2, 12, 7), &[2]), lost(2, true));
    // A retirement of another generation doesn't count.
    assert_eq!(verdict(Row::None, mark(2, 12, 7), &[1, 3]), lost(2, false));
}

// Table 1, row "None, erased".

#[test]
fn test_verdict_none_erased_no_mark() {
    for mark in [MarkInput::Missing, MarkInput::NotAMark] {
        assert_eq!(
            verdict(Row::NoneErased, mark, &[]),
            if matches!(mark, MarkInput::NotAMark) {
                Verdict::Unknown
            } else {
                NOT_HOSTED
            }
        );
    }
}

#[test]
fn test_verdict_none_erased_zero_mark() {
    assert_eq!(verdict(Row::NoneErased, mark(0, 0, 0), &[]), LEFTOVER);
}

#[test]
fn test_verdict_none_erased_at_or_past() {
    assert_eq!(verdict(Row::NoneErased, mark(2, 10, 1), &[]), LEFTOVER);
}

#[test]
fn test_verdict_none_erased_behind() {
    assert_eq!(verdict(Row::NoneErased, mark(3, 1, 7), &[]), LEFTOVER);
}

#[test]
fn test_verdict_none_erased_fork() {
    assert_eq!(verdict(Row::NoneErased, fork_mark(), &[]), LEFTOVER);
}

#[test]
fn test_verdict_none_erased_store_unreadable() {
    assert_eq!(
        verdict(Row::NoneErased, MarkInput::StoreUnreadable, &[]),
        Verdict::Unknown
    );
}

#[test]
fn test_verdict_none_erased_retired() {
    assert_eq!(verdict(Row::NoneErased, mark(2, 12, 7), &[2]), LEFTOVER);
}

// Table 1, row "Staged, holding no chain".

#[test]
fn test_verdict_staged_no_chain_no_mark() {
    for mark in [MarkInput::Missing, MarkInput::NotAMark] {
        assert_eq!(
            verdict(Row::StagedNoChain, mark, &[]),
            failing(0, NoticeReason::MarkLost, false, true)
        );
    }
}

#[test]
fn test_verdict_staged_no_chain_zero_mark() {
    assert_eq!(
        verdict(Row::StagedNoChain, mark(0, 0, 0), &[]),
        Verdict::Staged
    );
}

#[test]
fn test_verdict_staged_no_chain_at_or_past() {
    assert_eq!(
        verdict(Row::StagedNoChain, mark(2, 10, 1), &[]),
        bounded(2, false)
    );
}

#[test]
fn test_verdict_staged_no_chain_behind() {
    assert_eq!(
        verdict(Row::StagedNoChain, mark(2, 12, 7), &[]),
        bounded(2, false)
    );
}

#[test]
fn test_verdict_staged_no_chain_fork() {
    assert_eq!(
        verdict(Row::StagedNoChain, fork_mark(), &[]),
        bounded(2, false)
    );
}

#[test]
fn test_verdict_staged_no_chain_store_unreadable() {
    assert_eq!(
        verdict(Row::StagedNoChain, MarkInput::StoreUnreadable, &[]),
        Verdict::Unknown
    );
}

#[test]
fn test_verdict_staged_no_chain_retired() {
    assert_eq!(
        verdict(Row::StagedNoChain, mark(2, 12, 7), &[2]),
        bounded(2, true)
    );
}

// Table 1, rows "Staged, holding an activated import", "Serving" and "Frozen".

const STATE_ROWS: [Row; 3] = [Row::StagedImport, Row::Serving, Row::Frozen];

/// Whether the abort goes through at `row` with a mark of generation 2 or none: only at
/// a staged account.
fn abort_at(row: Row) -> bool {
    matches!(row, Row::StagedImport)
}

fn assert_no_mark(row: Row) {
    for mark in [MarkInput::Missing, MarkInput::NotAMark] {
        assert_eq!(
            verdict(row, mark, &[]),
            failing(
                STATE.generation,
                NoticeReason::MarkLost,
                false,
                abort_at(row)
            )
        );
    }
}

fn assert_zero_mark(row: Row) {
    assert_eq!(verdict(row, mark(0, 0, 0), &[]), Verdict::Healthy);
}

fn assert_at_or_past(row: Row) {
    for mark in at_or_past_marks() {
        assert_eq!(verdict(row, mark, &[]), Verdict::Healthy);
    }
    // Past the mark in a later generation, whatever count the mark's covers.
    assert_eq!(verdict(row, mark(1, 30, 7), &[]), Verdict::Healthy);
    assert_eq!(verdict(row, counting(1, 30, 7, 90), &[]), Verdict::Healthy);
    // In the mark's generation, at or past the count it covers.
    for at_count in [counting(2, 10, 1, COUNT), counting(2, 5, 7, COUNT - 1)] {
        assert_eq!(verdict(row, at_count, &[]), Verdict::Healthy);
    }
}

fn assert_behind(row: Row) {
    assert_eq!(
        verdict(row, mark(2, 12, 7), &[]),
        failing(2, NoticeReason::Behind, false, abort_at(row))
    );
    // Of an earlier generation than the mark: the abort only while the mark's
    // generation isn't above the enrolled one's.
    assert_eq!(
        verdict(row, mark(3, 1, 7), &[]),
        failing(3, NoticeReason::Behind, false, false)
    );
    // At the mark's head or past it, in its generation, with a lower count than the mark
    // covers: an acknowledged write was lost (Switch wire 7.3, Table 1).
    for lost_write in [counting(2, 10, 1, COUNT + 1), counting(2, 8, 7, COUNT + 2)] {
        assert_eq!(
            verdict(row, lost_write, &[]),
            failing(2, NoticeReason::Behind, false, abort_at(row))
        );
    }
}

fn assert_fork(row: Row) {
    assert_eq!(
        verdict(row, fork_mark(), &[]),
        failing(2, NoticeReason::Fork, false, abort_at(row))
    );
    // A fork stays a fork whatever the count: at the state's pair with another chain hash,
    // and past the mark with another chain hash at its stub.
    assert_eq!(
        verdict(row, counting(2, 10, 9, COUNT + 4), &[]),
        failing(2, NoticeReason::Fork, false, abort_at(row))
    );
    assert_eq!(
        judged_with(row, counting(2, 8, 7, COUNT + 4), Some([9; 32]), &[]).verdict,
        failing(2, NoticeReason::Fork, false, abort_at(row))
    );
}

fn assert_store_unreadable(row: Row) {
    assert_eq!(
        verdict(row, MarkInput::StoreUnreadable, &[]),
        Verdict::Unknown
    );
}

fn assert_retired(row: Row) {
    // "Permanent" keeps the reason the account had before it was retired.
    assert_eq!(
        verdict(row, mark(2, 12, 7), &[2]),
        failing(2, NoticeReason::Behind, true, abort_at(row))
    );
    assert_eq!(
        verdict(row, fork_mark(), &[2]),
        failing(2, NoticeReason::Fork, true, abort_at(row))
    );
    // Where the mark is lost, the retirement is of the account's generation, which
    // counts while the state isn't of a later one.
    let lost_mark = verdict(row, MarkInput::Missing, &[STATE.generation]);
    assert_eq!(
        lost_mark,
        failing(
            STATE.generation,
            NoticeReason::MarkLost,
            true,
            abort_at(row)
        )
    );
}

#[test]
fn test_verdict_staged_import_no_mark() {
    assert_no_mark(Row::StagedImport);
}

#[test]
fn test_verdict_staged_import_zero_mark() {
    assert_zero_mark(Row::StagedImport);
}

#[test]
fn test_verdict_staged_import_at_or_past() {
    assert_at_or_past(Row::StagedImport);
}

#[test]
fn test_verdict_staged_import_behind() {
    assert_behind(Row::StagedImport);
}

#[test]
fn test_verdict_staged_import_fork() {
    assert_fork(Row::StagedImport);
}

#[test]
fn test_verdict_staged_import_store_unreadable() {
    assert_store_unreadable(Row::StagedImport);
}

#[test]
fn test_verdict_staged_import_retired() {
    assert_retired(Row::StagedImport);
}

#[test]
fn test_verdict_serving_no_mark() {
    assert_no_mark(Row::Serving);
}

#[test]
fn test_verdict_serving_zero_mark() {
    assert_zero_mark(Row::Serving);
}

#[test]
fn test_verdict_serving_at_or_past() {
    assert_at_or_past(Row::Serving);
}

#[test]
fn test_verdict_serving_behind() {
    assert_behind(Row::Serving);
}

#[test]
fn test_verdict_serving_fork() {
    assert_fork(Row::Serving);
}

#[test]
fn test_verdict_serving_store_unreadable() {
    assert_store_unreadable(Row::Serving);
}

#[test]
fn test_verdict_serving_retired() {
    assert_retired(Row::Serving);
}

#[test]
fn test_verdict_frozen_no_mark() {
    assert_no_mark(Row::Frozen);
}

#[test]
fn test_verdict_frozen_zero_mark() {
    assert_zero_mark(Row::Frozen);
}

#[test]
fn test_verdict_frozen_at_or_past() {
    assert_at_or_past(Row::Frozen);
}

#[test]
fn test_verdict_frozen_behind() {
    assert_behind(Row::Frozen);
}

#[test]
fn test_verdict_frozen_fork() {
    assert_fork(Row::Frozen);
}

#[test]
fn test_verdict_frozen_store_unreadable() {
    assert_store_unreadable(Row::Frozen);
}

#[test]
fn test_verdict_frozen_retired() {
    assert_retired(Row::Frozen);
}

// The rule sentences under Table 1.

#[test]
fn test_verdict_rule_store_unreadable_before_retired_and_first_row() {
    for row in [
        Row::ErasedAgain,
        Row::None,
        Row::StagedNoChain,
        Row::Serving,
    ] {
        let judgement = judged(row, MarkInput::StoreUnreadable, &[0, 1, 2, 3]);
        assert_eq!(judgement.verdict, Verdict::Unknown);
        assert!(!judgement.erase_account_again);
    }
}

#[test]
fn test_verdict_rule_first_row_by_creation_time() {
    let serving = account(Row::Serving).expect("account");
    let mark = mark(2, 10, 1);
    let at = |erasure_at_ms| {
        judge(&Inputs {
            account: Some(&serving),
            mark: &mark,
            stub_at_mark: None,
            erasure_at_ms: Some(erasure_at_ms),
            retired: &[],
        })
    };
    // Created at 100: a record at 100 erases it again, one at 99 doesn't.
    assert!(at(100).erase_account_again);
    let later = at(99);
    assert!(!later.erase_account_again);
    assert_eq!(later.verdict, Verdict::Healthy);
}

#[test]
fn test_verdict_rule_mark_created_after_the_erasure_is_a_later_account() {
    let later = MarkInput::Mark(mark_created(2, 12, 7, ERASED_AT + 1));
    assert_eq!(verdict(Row::NoneErased, later, &[]), lost(2, false));
    // Also after the first row erased an earlier account again.
    let judgement = judged(Row::ErasedAgain, later, &[]);
    assert!(judgement.erase_account_again);
    assert_eq!(judgement.verdict, lost(2, false));
    let zero = MarkInput::Mark(mark_created(0, 0, 0, ERASED_AT + 1));
    assert_eq!(verdict(Row::NoneErased, zero, &[]), NOT_HOSTED);
    // A record at the mark's creation covers it.
    let covered = MarkInput::Mark(mark_created(2, 12, 7, ERASED_AT));
    assert_eq!(verdict(Row::NoneErased, covered, &[]), LEFTOVER);
}

#[test]
fn test_verdict_rule_fork_past_the_mark_by_the_stub() {
    let past = mark(2, 5, 7);
    for row in STATE_ROWS {
        let fork = judged_with(row, past, Some([8; 32]), &[]).verdict;
        assert_eq!(fork, failing(2, NoticeReason::Fork, false, abort_at(row)));
        let same = judged_with(row, past, Some([7; 32]), &[]).verdict;
        assert_eq!(same, Verdict::Healthy);
        assert_eq!(judged_with(row, past, None, &[]).verdict, Verdict::Healthy);
    }
}

#[test]
fn test_verdict_rule_retirement_counts_only_up_to_the_mark_generation() {
    // The state at generation 2 is of a later generation than the mark's 1: the
    // retirement of 1 doesn't count.
    for row in STATE_ROWS {
        assert_eq!(verdict(row, mark(1, 30, 7), &[1]), Verdict::Healthy);
        assert_eq!(
            verdict(row, mark(1, 30, 7), &[2]),
            Verdict::Healthy,
            "a retirement of another generation"
        );
    }
    // A retirement of the mark's generation counts with the state behind it in an
    // earlier one.
    assert_eq!(
        verdict(Row::Serving, mark(3, 1, 7), &[3]),
        failing(3, NoticeReason::Behind, true, false)
    );
    // Where the mark is lost, the retirement is of the account's generation, its
    // state's: it counts; one of another generation doesn't.
    for row in STATE_ROWS {
        assert_eq!(
            verdict(row, MarkInput::Missing, &[2]),
            failing(2, NoticeReason::MarkLost, true, abort_at(row))
        );
        assert_eq!(
            verdict(row, MarkInput::Missing, &[0, 1]),
            failing(2, NoticeReason::MarkLost, false, abort_at(row))
        );
    }
}

#[test]
fn test_verdict_rule_activated_import_without_a_document_has_its_chain_generation() {
    let import = Account {
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        state: AccountState::StagedImport(tip(3, 7, 1)),
        state_version: 0,
        created_at_ms: 100,
        document_generation: None,
        enrolled_generation: 3,
    };
    assert_eq!(import.generation(), 3);
    let at = |account: &Account, mark: MarkInput, retired: &[u64]| {
        judge(&Inputs {
            account: Some(account),
            mark: &mark,
            stub_at_mark: None,
            erasure_at_ms: None,
            retired,
        })
    };
    let judgement = at(&import, MarkInput::Missing, &[]);
    assert_eq!(
        judgement.verdict,
        failing(3, NoticeReason::MarkLost, false, true)
    );

    assert_eq!(
        at(&import, MarkInput::NotAMark, &[3]).verdict,
        failing(3, NoticeReason::MarkLost, true, true)
    );
    assert_eq!(
        at(&import, mark(3, 9, 7), &[]).verdict,
        failing(3, NoticeReason::Behind, false, true)
    );
    // Its chain's generation, also above the document it holds.
    let with_document = Account {
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        document_generation: Some(2),
        ..import
    };
    assert_eq!(with_document.generation(), 3);
    assert_eq!(
        at(&with_document, MarkInput::Missing, &[2]).verdict,
        failing(3, NoticeReason::MarkLost, false, true)
    );
    // Holding no chain, its document's; 0 while it holds neither.
    let staged = Account {
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        state: AccountState::StagedNoChain,
        ..with_document
    };
    assert_eq!(staged.generation(), 2);
    let empty = Account {
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        document_generation: None,
        ..staged
    };
    assert_eq!(empty.generation(), 0);
}

#[test]
fn test_verdict_rule_retired_reason_per_column() {
    // Under a retired generation the reason is the one the columns to its left give the
    // account as it now is, with `permanent` true.
    for row in STATE_ROWS {
        let abort = abort_at(row);
        for lost_mark in [MarkInput::Missing, MarkInput::NotAMark] {
            assert_eq!(
                verdict(row, lost_mark, &[2]),
                failing(2, NoticeReason::MarkLost, true, abort)
            );
        }
        assert_eq!(
            verdict(row, mark(2, 12, 7), &[2]),
            failing(2, NoticeReason::Behind, true, abort)
        );
        assert_eq!(
            verdict(row, fork_mark(), &[2]),
            failing(2, NoticeReason::Fork, true, abort)
        );
        // A fork past the mark by the stub at its `seq`.
        assert_eq!(
            judged_with(row, mark(2, 5, 7), Some([8; 32]), &[2]).verdict,
            failing(2, NoticeReason::Fork, true, abort)
        );
        // No notice to its left: `behind`.
        assert_eq!(
            verdict(row, mark(2, 5, 7), &[2]),
            failing(2, NoticeReason::Behind, true, abort)
        );
        // A (0, 0) mark's generation 0 is below every state's: its retirement doesn't
        // count.
        assert_eq!(verdict(row, mark(0, 0, 0), &[0]), Verdict::Healthy);
    }
    // A lost account: `behind`.
    assert_eq!(verdict(Row::None, mark(2, 12, 7), &[2]), lost(2, true));
    assert_eq!(verdict(Row::None, fork_mark(), &[2]), lost(2, true));
}

#[test]
fn test_verdict_rule_retired_at_the_mark_keeps_behind() {
    // The state at the mark of a retired generation: no reason before the retirement,
    // and `behind` is kept as for a lost account.
    for row in STATE_ROWS {
        assert_eq!(
            verdict(row, mark(2, 10, 1), &[2]),
            failing(2, NoticeReason::Behind, true, abort_at(row))
        );
    }
}

#[test]
fn test_verdict_rule_bounded_retired_is_permanent() {
    assert_eq!(
        verdict(Row::StagedNoChain, mark(0, 0, 0), &[0]),
        bounded(0, true)
    );
    assert_eq!(
        verdict(Row::StagedNoChain, mark(2, 12, 7), &[1]),
        bounded(2, false)
    );
}

#[test]
fn test_verdict_rule_staged_no_chain_retired_with_the_mark_lost_fails() {
    // The retirement is of the account's generation, 0 while it holds neither chain nor
    // document: it fails stop as one that lost its mark.
    for mark in [MarkInput::Missing, MarkInput::NotAMark] {
        let judgement = judged(Row::StagedNoChain, mark, &[0]);
        assert_eq!(
            judgement.verdict,
            failing(0, NoticeReason::MarkLost, true, true)
        );

        assert_eq!(
            verdict(Row::StagedNoChain, mark, &[1]),
            failing(0, NoticeReason::MarkLost, false, true)
        );
    }
}

#[test]
fn test_verdict_rule_none_retired_without_a_mark_is_not_hosted() {
    for mark in [MarkInput::Missing, MarkInput::NotAMark] {
        assert_eq!(
            verdict(Row::None, mark, &[0, 1, 2]),
            if matches!(mark, MarkInput::NotAMark) {
                Verdict::Unknown
            } else {
                NOT_HOSTED
            }
        );
    }
    assert_eq!(verdict(Row::None, mark(0, 0, 0), &[0]), lost(0, true));
}

#[test]
fn test_verdict_rule_notice_generation_is_the_higher() {
    // The account's generation above the mark's: the notice names the account's.
    let mut serving = account(Row::Serving).expect("account");
    serving.state = AccountState::Serving(tip(5, 1, 1));
    serving.document_generation = Some(5);
    let judgement = judge(&Inputs {
        account: Some(&serving),
        mark: &MarkInput::Missing,
        stub_at_mark: None,
        erasure_at_ms: None,
        retired: &[],
    });
    assert_eq!(
        judgement.verdict,
        failing(5, NoticeReason::MarkLost, false, false)
    );
    // The mark's above the account's.
    assert_eq!(
        verdict(Row::Serving, mark(4, 1, 7), &[]),
        failing(4, NoticeReason::Behind, false, false)
    );
}

#[test]
fn test_verdict_rule_abort_while_the_mark_is_not_above_the_enrolled_generation() {
    let mut staged = account(Row::StagedNoChain).expect("account");
    let at = |staged: &Account, mark: MarkInput| {
        judge(&Inputs {
            account: Some(staged),
            mark: &mark,
            stub_at_mark: None,
            erasure_at_ms: None,
            retired: &[],
        })
        .verdict
    };
    staged.enrolled_generation = 2;
    assert_eq!(at(&staged, mark(2, 12, 7)), bounded(2, false));
    staged.enrolled_generation = 1;
    assert_eq!(
        at(&staged, mark(2, 12, 7)),
        Verdict::Bounded {
            notice: notice(2, NoticeReason::Behind, false),
            abort_allowed: false,
        }
    );
    // Always where the mark is lost.
    assert_eq!(
        at(&staged, MarkInput::Missing),
        failing(0, NoticeReason::MarkLost, false, true)
    );
}

// Table 2: the route of each verdict per request class.

const BEHIND: RecoveryNotice = RecoveryNotice {
    generation: 4,
    reason: NoticeReason::Behind,
    permanent: false,
};

fn route_of(verdict: Verdict, class: RequestClass) -> Route {
    let judgement = Judgement {
        recovery_required: false,
        erase_account_again: false,
        verdict,
        recovery_floor: BEHIND.generation,
        retirement_generation: None,
    };
    request_route(&judgement, &class)
}

const ERASE: RequestClass = RequestClass::Erase;
const STEPS: [MoveStep; 6] = [
    MoveStep::ImportOrUpload,
    MoveStep::Activate { clears_mark: true },
    MoveStep::Activate { clears_mark: false },
    MoveStep::ActivateUnjudged,
    MoveStep::Abort,
    MoveStep::Export,
];

fn put(generation: u64, recovery_from: Option<u64>) -> RequestClass {
    RequestClass::PutIdentity {
        generation,
        recovery_from,
    }
}

/// Deliveries other than the one start: not above the notice's generation, without
/// `recovery_from`, or with another one.
fn other_deliveries() -> [RequestClass; 4] {
    [
        put(4, Some(3)),
        put(5, None),
        put(5, Some(3)),
        put(6, Some(4)),
    ]
}

fn bounded_verdict(abort_allowed: bool) -> Verdict {
    Verdict::Bounded {
        notice: BEHIND,
        abort_allowed,
    }
}

fn failing_verdict(abort_allowed: bool) -> Verdict {
    Verdict::Failing {
        notice: BEHIND,
        abort_allowed,
    }
}

const LOST: Verdict = Verdict::Lost { notice: BEHIND };

#[test]
fn test_answer_not_hosted_ordinary() {
    for delete_mark in [false, true] {
        let verdict = Verdict::NotHosted { delete_mark };
        assert_eq!(route_of(verdict, RequestClass::Ordinary), Route::NotHosted);
    }
}

#[test]
fn test_answer_not_hosted_enroll() {
    for delete_mark in [false, true] {
        let verdict = Verdict::NotHosted { delete_mark };
        assert_eq!(
            route_of(verdict, RequestClass::Enroll),
            Route::CreateAccount
        );
    }
}

#[test]
fn test_answer_not_hosted_put_identity() {
    assert_eq!(route_of(NOT_HOSTED, put(1, None)), Route::NotHosted);
    assert_eq!(route_of(NOT_HOSTED, put(5, Some(4))), Route::NotHosted);
}

#[test]
fn test_answer_not_hosted_move() {
    for step in STEPS {
        assert_eq!(
            route_of(NOT_HOSTED, RequestClass::Move(step)),
            Route::NotHosted
        );
    }
}

#[test]
fn test_answer_not_hosted_erase() {
    assert_eq!(route_of(NOT_HOSTED, ERASE), Route::NotHosted);
}

fn assert_goes_on(verdict: Verdict) {
    let on = Route::Proceed { head: true };
    assert_eq!(route_of(verdict, RequestClass::Ordinary), on);
    assert_eq!(route_of(verdict, put(5, Some(4))), on);
    for step in STEPS {
        let expected = match step {
            MoveStep::Activate { clears_mark: false } => Route::Conflict,
            MoveStep::ActivateUnjudged => Route::JudgeActivation,
            _ => on,
        };
        assert_eq!(route_of(verdict, RequestClass::Move(step)), expected);
    }
}

#[test]
fn test_answer_unjudged_activation_never_clears_a_mark() {
    // An activation whose import isn't judged is never routed as one that activates or
    // signs a head: where the import could clear the mark, it goes to be judged; at an
    // account that fails stop or a lost identity it gets the notice, as every move step
    // that isn't an abort (Switch wire 7.3, Table 2).
    let unjudged = RequestClass::Move(MoveStep::ActivateUnjudged);
    for verdict in [
        Verdict::Staged,
        Verdict::Healthy,
        Verdict::Bounded {
            notice: BEHIND,
            abort_allowed: true,
        },
        Verdict::Bounded {
            notice: BEHIND,
            abort_allowed: false,
        },
    ] {
        assert_eq!(route_of(verdict, unjudged), Route::JudgeActivation);
    }
    for verdict in [
        Verdict::Failing {
            notice: BEHIND,
            abort_allowed: true,
        },
        Verdict::Lost { notice: BEHIND },
    ] {
        assert_eq!(route_of(verdict, unjudged), Route::Notice(BEHIND));
    }
    assert_eq!(route_of(NOT_HOSTED, unjudged), Route::NotHosted);
    assert_eq!(route_of(Verdict::Unknown, unjudged), Route::Unavailable);
}

#[test]
fn test_answer_staged_activation_of_a_retired_generation_is_refused() {
    // At a staged account at its (0, 0) mark, an import of a generation the operator
    // retired for the identity doesn't clear the mark, and its activation is refused.
    let zero = Mark::zero(1);
    let head = ChainTip {
        generation: 3,
        seq: 9,
        chain_hash: [1; 32],
    };
    assert!(!activation_clears_mark(head, None, Some(&zero), &[3]));
    assert!(activation_clears_mark(head, None, Some(&zero), &[2]));
    let clears = activation_clears_mark(head, None, Some(&zero), &[3]);
    assert_eq!(
        route_of(
            Verdict::Staged,
            RequestClass::Move(MoveStep::Activate {
                clears_mark: clears
            })
        ),
        Route::Conflict
    );
}

#[test]
fn test_answer_staged_ordinary() {
    assert_eq!(
        route_of(Verdict::Staged, RequestClass::Ordinary),
        Route::Proceed { head: true }
    );
}

#[test]
fn test_answer_staged_enroll() {
    assert_eq!(
        route_of(Verdict::Staged, RequestClass::Enroll),
        Route::Proceed { head: false }
    );
}

#[test]
fn test_answer_staged_put_identity() {
    for class in [put(1, None), put(5, Some(4))] {
        assert_eq!(
            route_of(Verdict::Staged, class),
            Route::Proceed { head: true }
        );
    }
}

#[test]
fn test_answer_staged_move() {
    assert_goes_on(Verdict::Staged);
}

#[test]
fn test_answer_staged_erase() {
    assert_eq!(
        route_of(Verdict::Staged, ERASE),
        Route::Erase {
            fails_stop: false,
            import_bars: true
        }
    );
}

#[test]
fn test_answer_healthy_ordinary() {
    assert_eq!(
        route_of(Verdict::Healthy, RequestClass::Ordinary),
        Route::Proceed { head: true }
    );
}

#[test]
fn test_answer_healthy_enroll() {
    assert_eq!(
        route_of(Verdict::Healthy, RequestClass::Enroll),
        Route::Proceed { head: false }
    );
}

#[test]
fn test_answer_healthy_put_identity() {
    for class in [put(1, None), put(5, Some(4))] {
        assert_eq!(
            route_of(Verdict::Healthy, class),
            Route::Proceed { head: true }
        );
    }
}

#[test]
fn test_answer_healthy_move() {
    assert_goes_on(Verdict::Healthy);
}

#[test]
fn test_answer_healthy_erase() {
    assert_eq!(
        route_of(Verdict::Healthy, ERASE),
        Route::Erase {
            fails_stop: false,
            import_bars: true
        }
    );
}

#[test]
fn test_answer_bounded_ordinary() {
    assert_eq!(
        route_of(bounded_verdict(true), RequestClass::Ordinary),
        Route::Notice(BEHIND)
    );
}

#[test]
fn test_answer_bounded_enroll() {
    assert_eq!(
        route_of(bounded_verdict(true), RequestClass::Enroll),
        Route::Proceed { head: false }
    );
}

#[test]
fn test_answer_bounded_put_identity() {
    assert_eq!(
        route_of(bounded_verdict(true), put(5, Some(4))),
        Route::StartAfresh
    );
    for class in other_deliveries() {
        assert_eq!(
            route_of(bounded_verdict(true), class),
            Route::Notice(BEHIND)
        );
    }
}

#[test]
fn test_answer_bounded_move() {
    let at =
        |abort_allowed, step| route_of(bounded_verdict(abort_allowed), RequestClass::Move(step));
    assert_eq!(
        at(true, MoveStep::ImportOrUpload),
        Route::Proceed { head: false }
    );
    assert_eq!(
        at(true, MoveStep::Activate { clears_mark: true }),
        Route::Proceed { head: true }
    );
    assert_eq!(
        at(true, MoveStep::Activate { clears_mark: false }),
        Route::Conflict
    );
    assert_eq!(at(true, MoveStep::Abort), Route::Proceed { head: false });
    assert_eq!(at(false, MoveStep::Abort), Route::Notice(BEHIND));
    // The column names no export for a bounded account: it gets the notice.
    assert_eq!(at(true, MoveStep::Export), Route::Notice(BEHIND));
}

#[test]
fn test_answer_bounded_erase() {
    for abort_allowed in [true, false] {
        assert_eq!(
            route_of(bounded_verdict(abort_allowed), ERASE),
            Route::Erase {
                fails_stop: false,
                import_bars: abort_allowed
            }
        );
    }
}

#[test]
fn test_answer_failing_ordinary() {
    assert_eq!(
        route_of(failing_verdict(true), RequestClass::Ordinary),
        Route::Notice(BEHIND)
    );
}

#[test]
fn test_answer_failing_enroll() {
    assert_eq!(
        route_of(failing_verdict(false), RequestClass::Enroll),
        Route::Proceed { head: false }
    );
}

#[test]
fn test_answer_failing_put_identity() {
    assert_eq!(
        route_of(failing_verdict(false), put(5, Some(4))),
        Route::StartAfresh
    );
    for class in other_deliveries() {
        assert_eq!(
            route_of(failing_verdict(false), class),
            Route::Notice(BEHIND)
        );
    }
}

#[test]
fn test_answer_failing_move() {
    let at =
        |abort_allowed, step| route_of(failing_verdict(abort_allowed), RequestClass::Move(step));
    assert_eq!(at(true, MoveStep::Abort), Route::Proceed { head: false });
    assert_eq!(at(false, MoveStep::Abort), Route::Notice(BEHIND));
    for step in [
        MoveStep::ImportOrUpload,
        MoveStep::Activate { clears_mark: true },
        MoveStep::Activate { clears_mark: false },
        MoveStep::Export,
    ] {
        for abort_allowed in [true, false] {
            assert_eq!(at(abort_allowed, step), Route::Notice(BEHIND));
        }
    }
}

#[test]
fn test_answer_failing_erase() {
    for abort_allowed in [true, false] {
        assert_eq!(
            route_of(failing_verdict(abort_allowed), ERASE),
            Route::Erase {
                fails_stop: true,
                import_bars: abort_allowed
            }
        );
    }
}

#[test]
fn test_answer_lost_ordinary() {
    assert_eq!(
        route_of(LOST, RequestClass::Ordinary),
        Route::Notice(BEHIND)
    );
}

#[test]
fn test_answer_lost_enroll() {
    assert_eq!(route_of(LOST, RequestClass::Enroll), Route::TakeOverMark);
}

#[test]
fn test_answer_lost_put_identity() {
    assert_eq!(route_of(LOST, put(5, Some(4))), Route::Notice(BEHIND));
    assert_eq!(route_of(LOST, put(1, None)), Route::Notice(BEHIND));
}

#[test]
fn test_answer_lost_move() {
    for step in STEPS {
        assert_eq!(
            route_of(LOST, RequestClass::Move(step)),
            Route::Notice(BEHIND)
        );
    }
}

#[test]
fn test_answer_lost_erase() {
    assert_eq!(route_of(LOST, ERASE), Route::EraseLost);
}

#[test]
fn test_answer_unknown_ordinary() {
    assert_eq!(
        route_of(Verdict::Unknown, RequestClass::Ordinary),
        Route::Unavailable
    );
}

#[test]
fn test_answer_unknown_enroll() {
    assert_eq!(
        route_of(Verdict::Unknown, RequestClass::Enroll),
        Route::Unavailable
    );
}

#[test]
fn test_answer_unknown_put_identity() {
    assert_eq!(
        route_of(Verdict::Unknown, put(5, Some(4))),
        Route::Unavailable
    );
}

#[test]
fn test_answer_unknown_move() {
    for step in STEPS {
        assert_eq!(
            route_of(Verdict::Unknown, RequestClass::Move(step)),
            Route::Unavailable
        );
    }
}

#[test]
fn test_answer_unknown_erase() {
    assert_eq!(route_of(Verdict::Unknown, ERASE), Route::Unavailable);
}

// The bounded activation's condition.

#[test]
fn test_answer_bounded_activation_clears_the_mark() {
    let marked = mark_created(2, 10, 1, 50);
    let clears = |head, at_mark, retired: &[u64]| {
        activation_clears_mark(head, at_mark, Some(&marked), retired)
    };
    assert!(clears(tip(2, 10, 1), Some([1; 32]), &[]));
    assert!(clears(tip(2, 15, 4), Some([1; 32]), &[]));
    assert!(
        clears(tip(3, 2, 4), None, &[]),
        "reaches no stub at the mark's seq"
    );
    assert!(!clears(tip(2, 9, 1), None, &[]), "behind the mark");
    assert!(
        !clears(tip(2, 10, 6), None, &[]),
        "at the mark with another hash"
    );
    assert!(
        !clears(tip(2, 15, 4), Some([6; 32]), &[]),
        "another hash at the mark's seq"
    );
    assert!(!clears(tip(3, 2, 4), None, &[3]), "of a retired generation");
    assert!(clears(tip(3, 2, 4), None, &[2]));
    // With the mark lost, only the retirement bounds it.
    assert!(activation_clears_mark(tip(1, 1, 1), None, None, &[]));
    assert!(!activation_clears_mark(tip(1, 1, 1), None, None, &[1]));
}

#[test]
fn test_answer_recovery_held_document_bounds_start() {
    for row in [
        Row::Serving,
        Row::Frozen,
        Row::StagedImport,
        Row::StagedNoChain,
    ] {
        let mut account = account(row).expect("account");
        account.document_generation = Some(3);
        let judgement = judge(&Inputs {
            account: Some(&account),
            mark: &MarkInput::Missing,
            stub_at_mark: None,
            erasure_at_ms: None,
            retired: &[],
        });
        let notice = notice(account.generation(), NoticeReason::MarkLost, false);
        assert_eq!(
            request_route(&judgement, &RequestClass::Ordinary),
            Route::Notice(notice)
        );
        for generation in [2, 3] {
            assert_eq!(
                request_route(&judgement, &put(generation, Some(generation - 1))),
                Route::Notice(notice)
            );
        }
        assert_eq!(
            request_route(&judgement, &put(4, Some(3))),
            Route::StartAfresh
        );
    }
}

#[test]
fn test_answer_recovery_lost_mark_uses_document_floor() {
    let mut account = account(Row::Serving).expect("account");
    account.document_generation = Some(1);
    let judgement = judge(&Inputs {
        account: Some(&account),
        mark: &MarkInput::Missing,
        stub_at_mark: None,
        erasure_at_ms: None,
        retired: &[],
    });
    assert_eq!(
        request_route(&judgement, &RequestClass::Ordinary),
        Route::Notice(notice(2, NoticeReason::MarkLost, false))
    );
    assert_eq!(
        request_route(&judgement, &put(2, Some(1))),
        Route::StartAfresh
    );
}

#[test]
fn test_account_association_retains_physical_sql_floor() {
    let mut held = account(Row::Serving).expect("account");
    held.document_generation = Some(1);
    let floors = [50, 200].map(|created| {
        judge(&Inputs {
            account: Some(&held),
            mark: &MarkInput::Mark(mark_created(0, 0, 0, created)),
            stub_at_mark: None,
            erasure_at_ms: None,
            retired: &[],
        })
        .recovery_floor
    });
    assert_eq!(floors, [2, 2]);
}

/// Whether the verdict's notice says the loss is permanent; `None` where it gives none.
fn permanent_of(verdict: Verdict) -> Option<bool> {
    match verdict {
        Verdict::Failing { notice, .. }
        | Verdict::Bounded { notice, .. }
        | Verdict::Lost { notice } => Some(notice.permanent),
        Verdict::NotHosted { .. } | Verdict::Staged | Verdict::Healthy | Verdict::Unknown => None,
    }
}

/// For every association of account and mark (Switch account binding 1.1), the generation
/// [`retirement_generation`] selects is the one whose retirement makes the notice permanent,
/// and retiring any other leaves it as it was (Switch wire 7.3 under Table 1).
#[test]
fn test_retirement_generation_is_the_one_the_verdict_reads() {
    let serving_at = |state: ChainTip, created_at_ms| Account {
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        state: AccountState::Serving(state),
        state_version: COUNT,
        created_at_ms,
        document_generation: Some(state.generation),
        enrolled_generation: state.generation,
    };
    let staged = Account {
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        state: AccountState::StagedNoChain,
        state_version: COUNT,
        created_at_ms: 100,
        document_generation: None,
        enrolled_generation: 2,
    };
    let at = |generation, seq, created_at_ms| {
        MarkInput::Mark(mark_created(generation, seq, 1, created_at_ms))
    };
    // (case, account, mark, erasure, the generation the verdict reads)
    let cases = [
        (
            "equal creations, behind",
            Some(serving_at(STATE, 100)),
            at(2, 12, 100),
            None,
            2,
        ),
        (
            "equal creations, mark lost",
            Some(serving_at(STATE, 100)),
            MarkInput::Missing,
            None,
            2,
        ),
        // SQL newer than a readable mark: the lost-mark column, at the account's generation.
        (
            "account above an older mark",
            Some(serving_at(STATE, 150)),
            at(1, 5, 100),
            None,
            2,
        ),
        // SQL older than the mark: the rows without an account, at the mark's generation.
        (
            "account below a newer mark",
            Some(serving_at(tip(1, 3, 1), 50)),
            at(3, 4, 100),
            None,
            3,
        ),
        ("no account", None, at(2, 5, 100), None, 2),
        (
            "staged, mark records a head",
            Some(staged),
            at(3, 1, 100),
            None,
            3,
        ),
        (
            "erased again, a later mark",
            Some(serving_at(STATE, 100)),
            at(2, 5, 300),
            Some(ERASED_AT),
            2,
        ),
    ];
    for (case, account, mark, erasure_at_ms, expected) in cases {
        let judge_retired = |retired: &[u64]| {
            judge(&Inputs {
                account: account.as_ref(),
                mark: &mark,
                stub_at_mark: None,
                erasure_at_ms,
                retired,
            })
        };
        let judgement = judge_retired(&[]);
        assert_eq!(judgement.retirement_generation, Some(expected), "{case}");
        assert_eq!(
            retirement_generation(account.as_ref(), &mark, erasure_at_ms),
            Some(expected),
            "{case}"
        );
        assert_eq!(permanent_of(judgement.verdict), Some(false), "{case}");
        assert_eq!(
            permanent_of(judge_retired(&[expected]).verdict),
            Some(true),
            "{case}"
        );
        for other in (1..=4).filter(|other| *other != expected) {
            assert_eq!(
                permanent_of(judge_retired(&[other]).verdict),
                Some(false),
                "{case}: retired {other}"
            );
        }
    }
}

/// No retirement counts while the mark store can't be read.
#[test]
fn test_retirement_generation_unreadable_store_has_none() {
    let account = account(Row::Serving);
    assert_eq!(
        retirement_generation(account.as_ref(), &MarkInput::StoreUnreadable, None),
        None
    );
    assert_eq!(
        judged(Row::Serving, MarkInput::StoreUnreadable, &[2]).retirement_generation,
        None
    );
}
