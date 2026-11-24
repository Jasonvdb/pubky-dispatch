//! The account model's stored inputs and response signing keys (Dispatch wire 7.3,
//! Tables 1 and 2; Dispatch spec 6.5).
//!
//! The shared [`crate::account`] model decides the verdict and route. These adapters read
//! the held document and persisted mark, and select the key of Table 2's "Signed with"
//! column without changing that decision.

use pubky_dispatch_core::{
    chain::{ChainTip, ZERO_HASH},
    records::{AccountActivation, AccountAssociation, AccountBinding, IdentityBody},
};

pub(super) use crate::account::recovery_starts_above;
pub use crate::account::{AccountState, MoveStep, RequestClass, Route, Verdict};
use crate::{
    account,
    marks::{AccountMark, MarkRead, MarkStoreError},
};

/// The held account and the service key its newest document names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    /// The account state the shared model judges.
    pub model: account::Account,
    /// The key named at this origin, where the service holds it.
    pub named_key: Option<[u8; 32]>,
}

impl Account {
    /// The account as the verdict judges it (Dispatch wire 7.3, "The state"), in one place
    /// for the service and its offline check: serving at its chain head once its newest
    /// `identity.json`, `doc`, names `origin` and a key the service's key store holds, as
    /// `holds` says; else staged, judged by its chain where it holds one (an activated
    /// import), else holding none. `generation` is its row's: that of the `identity.json` it
    /// was enrolled with, or 1 for one enrolled without a document, until a generation
    /// starts there, which makes it serve. `count` is its row's count of changed
    /// commits with its tag, which its state compares with the mark's (Dispatch wire 7.3, "The
    /// state").
    #[allow(clippy::too_many_arguments)]
    pub fn judged(
        origin: &str,
        holds: impl Fn(&[u8; 32]) -> bool,
        generation: u64,
        chain: Option<(u64, [u8; 32])>,
        count: account::Count,
        created_at_ms: u64,
        doc: Option<&IdentityBody>,
        activation: AccountActivation,
    ) -> Self {
        let named_key = doc
            .filter(|body| body.inbox.url == origin && holds(&body.inbox.service_key))
            .map(|body| body.inbox.service_key);
        let (seq, chain_hash) = chain.unwrap_or((0, ZERO_HASH));
        let tip = ChainTip {
            generation,
            seq,
            chain_hash,
        };
        let state = if activation == AccountActivation::Recovery {
            AccountState::StagedNoChain
        } else if named_key.is_some() {
            AccountState::Serving(tip)
        } else if chain.is_some() {
            AccountState::StagedImport(tip)
        } else {
            AccountState::StagedNoChain
        };
        Self {
            model: account::Account {
                activation,
                state,
                count,
                created_at_ms,
                document_generation: doc.map(|body| body.generation),
                enrolled_generation: generation,
            },
            named_key,
        }
    }
}

/// The identity's mark, as the request finds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkInput {
    /// The mark store can't be read.
    StoreUnreadable,
    /// No mark.
    Missing,
    /// A file that doesn't read as a mark.
    NotAMark,
    /// The mark.
    Mark(AccountMark),
}

impl From<&Result<MarkRead, MarkStoreError>> for MarkInput {
    /// A read of the mark store: any failure is a store that can't be read.
    fn from(read: &Result<MarkRead, MarkStoreError>) -> Self {
        match read {
            Ok(MarkRead::Missing) => Self::Missing,
            Ok(MarkRead::NotAMark) => Self::NotAMark,
            Ok(MarkRead::Mark(mark)) => Self::Mark(*mark),
            Err(_) => Self::StoreUnreadable,
        }
    }
}

impl MarkInput {
    fn model(&self) -> account::MarkInput {
        match self {
            Self::StoreUnreadable => account::MarkInput::StoreUnreadable,
            Self::Missing => account::MarkInput::Missing,
            Self::NotAMark => account::MarkInput::NotAMark,
            Self::Mark(mark) => account::MarkInput::Mark(mark.into()),
        }
    }

    fn mark(&self) -> Option<&AccountMark> {
        match self {
            Self::Mark(mark) => Some(mark),
            Self::StoreUnreadable | Self::Missing | Self::NotAMark => None,
        }
    }
}

/// The checked current lifetime, without removing either physical input (Dispatch account
/// binding 1.1).
pub(super) fn account_binding(
    account: Option<&Account>,
    mark: &MarkInput,
) -> pubky_dispatch_core::Result<AccountBinding> {
    account::account_binding(account.map(|account| &account.model), &mark.model())
}

/// The generation whose retirement the verdict reads for these persisted inputs: the
/// shared model's one rule ([`account::retirement_generation`]).
pub fn retirement_generation(
    account: Option<&Account>,
    mark: &MarkInput,
    erasure_at_ms: Option<u64>,
) -> Option<u64> {
    account::retirement_generation(
        account.map(|account| &account.model),
        &mark.model(),
        erasure_at_ms,
    )
}

/// Everything [`judge`] reads.
#[derive(Clone, Copy, Debug)]
pub struct Inputs<'a> {
    /// The identity's account, if the service holds one.
    pub account: Option<&'a Account>,
    /// The identity's mark.
    pub mark: &'a MarkInput,
    /// The chain hash of the stub the service still holds at the mark's generation and
    /// `seq`, if it holds one.
    pub stub_at_mark: Option<[u8; 32]>,
    /// The tag retained at the mark's positive count (Dispatch wire 7.3).
    pub tag_at_mark: Option<[u8; 16]>,
    /// The time of the erasure's record for the identity, in Unix milliseconds, if there is
    /// one (Dispatch wire 7.4.16).
    pub erasure_at_ms: Option<u64>,
    /// The identity's retired generations (Dispatch spec 6.5).
    pub retired: &'a [u64],
    /// The service's current key.
    pub current_key: [u8; 32],
}

/// The shared model's decision and its response signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Judgement {
    /// The account model's verdict, erasure duty and recovery floor.
    pub decision: account::Judgement,
    /// The key for responses other than enrollment (Dispatch wire 7.3, Table 2).
    pub key: [u8; 32],
}

/// Judge the persisted inputs with the shared model and select the response key.
pub fn judge(inputs: &Inputs<'_>) -> Judgement {
    let decision = account::judge(&account::Inputs {
        account: inputs.account.map(|account| &account.model),
        mark: &inputs.mark.model(),
        stub_at_mark: inputs.stub_at_mark,
        tag_at_mark: inputs.tag_at_mark,
        erasure_at_ms: inputs.erasure_at_ms,
        retired: inputs.retired,
    });
    let binding = account_binding(inputs.account, inputs.mark);
    let named_key = inputs
        .account
        .filter(|_| !decision.erase_account_again)
        .filter(|_| {
            !binding
                .as_ref()
                .is_ok_and(|binding| binding.association() != AccountAssociation::Account)
        })
        .and_then(|account| account.named_key);
    let mark_key = inputs
        .mark
        .mark()
        .filter(|mark| {
            binding
                .as_ref()
                .is_ok_and(|binding| binding.created() == Some(mark.created_at_ms))
        })
        .map(|mark| mark.key);
    let key = match decision.verdict {
        Verdict::NotHosted { .. } => inputs.current_key,
        Verdict::Unknown => named_key.unwrap_or(inputs.current_key),
        Verdict::Staged | Verdict::Healthy => named_key.or(mark_key).unwrap_or(inputs.current_key),
        Verdict::Bounded { .. } | Verdict::Failing { .. } | Verdict::Lost { .. } => {
            mark_key.or(named_key).unwrap_or(inputs.current_key)
        }
    };
    Judgement { decision, key }
}

/// The historical stub the model needs to compare a persisted mark (Dispatch wire 7.3).
pub fn stub_for_fork_rule(state: Option<(u64, u64)>, mark: &AccountMark) -> Option<(u64, u64)> {
    account::stub_for_fork_rule(state, &mark.into())
}

/// A request's route and the key its response uses (Dispatch wire 7.3, Table 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The route.
    pub route: Route,
    /// The key.
    pub key: [u8; 32],
}

/// What a request of `class` gets under `judgement` (Dispatch wire 7.3, Table 2). An
/// enrollment's answer is always signed with `current_key`, the key it names (Dispatch wire
/// 7.4.1); any other with the judgement's key. A delivery's own answer is signed as the
/// account stands once the delivery is committed, which the caller judges again.
pub fn answer(judgement: &Judgement, class: &RequestClass, current_key: [u8; 32]) -> Answer {
    let key = match class {
        RequestClass::Enroll => current_key,
        RequestClass::Ordinary
        | RequestClass::PutIdentity { .. }
        | RequestClass::Move(_)
        | RequestClass::Erase => judgement.key,
    };
    Answer {
        route: account::request_route(&judgement.decision, class),
        key,
    }
}

#[cfg(test)]
fn activation_clears_mark(
    import_head: ChainTip,
    hash_at_mark: Option<[u8; 32]>,
    mark: Option<&AccountMark>,
    retired: &[u64],
) -> bool {
    account::activation_clears_mark(
        import_head,
        hash_at_mark,
        mark.map(Into::into).as_ref(),
        retired,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_dispatch_core::http::{NoticeReason, RecoveryNotice};

    const MARK_KEY: [u8; 32] = [1; 32];
    const DOC_KEY: [u8; 32] = [2; 32];
    const CURRENT: [u8; 32] = [3; 32];
    /// The state of every row with one: generation 2, `seq` 10.
    const STATE: ChainTip = tip(2, 10, 1);
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

    fn mark_created(generation: u64, seq: u64, hash: u8, created_at_ms: u64) -> AccountMark {
        AccountMark {
            state_tag: [0; 16],
            generation,
            seq,
            chain_hash: if generation == 0 { [0; 32] } else { [hash; 32] },
            key: MARK_KEY,
            creation_anchor: Default::default(),
            state_version: 0,
            time_floor_ms: 0,
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
            model: account::Account {
                activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
                state,
                count: crate::account::Count {
                    version: 0,
                    tag: [0; 16],
                },
                created_at_ms: 100,
                document_generation: None,
                enrolled_generation: 2,
            },
            named_key: None,
        };
        let serving = |state| Account {
            model: account::Account {
                activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
                state,
                count: crate::account::Count {
                    version: 0,
                    tag: [0; 16],
                },
                created_at_ms: 100,
                document_generation: Some(2),
                enrolled_generation: 2,
            },
            named_key: Some(DOC_KEY),
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

    fn judged_with(
        row: Row,
        mark: MarkInput,
        stub: Option<[u8; 32]>,
        retired: &[u64],
    ) -> Judgement {
        let account = account(row);
        let erasure_at_ms = match row {
            Row::ErasedAgain | Row::NoneErased => Some(ERASED_AT),
            _ => None,
        };
        judge(&Inputs {
            account: account.as_ref(),
            mark: &mark,
            stub_at_mark: stub,
            tag_at_mark: None,
            erasure_at_ms,
            retired,
            current_key: CURRENT,
        })
    }

    fn verdict(row: Row, mark: MarkInput, retired: &[u64]) -> Verdict {
        judged(row, mark, retired).decision.verdict
    }

    fn notice(generation: u64, reason: NoticeReason, permanent: bool) -> RecoveryNotice {
        RecoveryNotice {
            generation,
            reason,
            permanent,
        }
    }

    fn failing(
        generation: u64,
        reason: NoticeReason,
        permanent: bool,
        abort_allowed: bool,
    ) -> Verdict {
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
        assert!(judgement.decision.erase_account_again);
        assert_eq!(judgement.decision.verdict, then);
    }

    // Table 1, row "Any, created at or before the time of an erasure's record".

    #[test]
    fn test_verdict_rule_fork_stub_of_the_marks_generation_whatever_the_states() {
        let marked = AccountMark {
            state_tag: [0; 16],
            generation: 1,
            seq: 5,
            chain_hash: [1; 32],
            key: CURRENT,
            creation_anchor: Default::default(),
            state_version: 0,
            time_floor_ms: 0,
            created_at_ms: 0,
        };
        // Past the mark in its generation, and at a later generation: the stub at the
        // mark's generation and `seq` counts either way (Dispatch wire 7.3 under Table 1).
        assert_eq!(stub_for_fork_rule(Some((1, 6)), &marked), Some((1, 5)));
        assert_eq!(stub_for_fork_rule(Some((2, 3)), &marked), Some((1, 5)));
        // At or behind the mark, without a state, or at a mark that records no head: none.
        assert_eq!(stub_for_fork_rule(Some((1, 5)), &marked), None);
        assert_eq!(stub_for_fork_rule(Some((1, 4)), &marked), None);
        assert_eq!(stub_for_fork_rule(None, &marked), None);
        assert_eq!(
            stub_for_fork_rule(Some((2, 3)), &AccountMark::zero(CURRENT, 0)),
            None
        );
        // A later generation's state over another hash there is a fork.
        let serving = Account {
            model: account::Account {
                activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
                state: AccountState::Serving(ChainTip {
                    generation: 2,
                    seq: 3,
                    chain_hash: [2; 32],
                }),
                count: crate::account::Count {
                    version: 0,
                    tag: [0; 16],
                },
                created_at_ms: 0,
                document_generation: Some(2),
                enrolled_generation: 2,
            },
            named_key: Some(CURRENT),
        };
        let judged = judge(&Inputs {
            account: Some(&serving),
            mark: &MarkInput::Mark(marked),
            stub_at_mark: Some([9; 32]),
            tag_at_mark: None,
            erasure_at_ms: None,
            retired: &[],
            current_key: CURRENT,
        });
        assert!(
            matches!(
                judged.decision.verdict,
                Verdict::Failing {
                    notice: RecoveryNotice {
                        reason: NoticeReason::Fork,
                        ..
                    },
                    ..
                }
            ),
            "{:?}",
            judged.decision.verdict
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
        assert!(!judgement.decision.erase_account_again);
        assert_eq!(judgement.decision.verdict, Verdict::Unknown);
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
        assert_eq!(judgement.decision.verdict, Verdict::Unknown);
        assert!(!judgement.decision.erase_account_again);
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
        // Past the mark in a later generation.
        assert_eq!(verdict(row, mark(1, 30, 7), &[]), Verdict::Healthy);
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
    }

    fn assert_fork(row: Row) {
        assert_eq!(
            verdict(row, fork_mark(), &[]),
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
            assert_eq!(judgement.decision.verdict, Verdict::Unknown);
            assert!(!judgement.decision.erase_account_again);
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
                tag_at_mark: None,
                erasure_at_ms: Some(erasure_at_ms),
                retired: &[],
                current_key: CURRENT,
            })
        };
        // Created at 100: a record at 100 erases it again, one at 99 doesn't.
        assert!(at(100).decision.erase_account_again);
        let later = at(99);
        assert!(!later.decision.erase_account_again);
        assert_eq!(later.decision.verdict, Verdict::Healthy);
    }

    #[test]
    fn test_verdict_rule_mark_created_after_the_erasure_is_a_later_account() {
        let later = MarkInput::Mark(mark_created(2, 12, 7, ERASED_AT + 1));
        assert_eq!(verdict(Row::NoneErased, later, &[]), lost(2, false));
        // Also after the first row erased an earlier account again.
        let judgement = judged(Row::ErasedAgain, later, &[]);
        assert!(judgement.decision.erase_account_again);
        assert_eq!(judgement.decision.verdict, lost(2, false));
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
            let fork = judged_with(row, past, Some([8; 32]), &[]).decision.verdict;
            assert_eq!(fork, failing(2, NoticeReason::Fork, false, abort_at(row)));
            let same = judged_with(row, past, Some([7; 32]), &[]).decision.verdict;
            assert_eq!(same, Verdict::Healthy);
            assert_eq!(
                judged_with(row, past, None, &[]).decision.verdict,
                Verdict::Healthy
            );
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
            model: account::Account {
                activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
                state: AccountState::StagedImport(tip(3, 7, 1)),
                count: crate::account::Count {
                    version: 0,
                    tag: [0; 16],
                },
                created_at_ms: 100,
                document_generation: None,
                enrolled_generation: 3,
            },
            named_key: None,
        };
        assert_eq!(import.model.generation(), 3);
        let at = |account: &Account, mark: MarkInput, retired: &[u64]| {
            judge(&Inputs {
                account: Some(account),
                mark: &mark,
                stub_at_mark: None,
                tag_at_mark: None,
                erasure_at_ms: None,
                retired,
                current_key: CURRENT,
            })
        };
        let judgement = at(&import, MarkInput::Missing, &[]);
        assert_eq!(
            judgement.decision.verdict,
            failing(3, NoticeReason::MarkLost, false, true)
        );
        assert_eq!(judgement.key, CURRENT);
        assert_eq!(
            at(&import, MarkInput::NotAMark, &[3]).decision.verdict,
            failing(3, NoticeReason::MarkLost, true, true)
        );
        assert_eq!(
            at(&import, mark(3, 9, 7), &[]).decision.verdict,
            failing(3, NoticeReason::Behind, false, true)
        );
        // Its chain's generation, also above the document it holds.
        let with_document = Account {
            model: account::Account {
                activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
                document_generation: Some(2),
                ..import.model
            },
            ..import
        };
        assert_eq!(with_document.model.generation(), 3);
        assert_eq!(
            at(&with_document, MarkInput::Missing, &[2])
                .decision
                .verdict,
            failing(3, NoticeReason::MarkLost, false, true)
        );
        // Holding no chain, its document's; 0 while it holds neither.
        let staged = Account {
            model: account::Account {
                activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
                state: AccountState::StagedNoChain,
                ..with_document.model
            },
            ..with_document
        };
        assert_eq!(staged.model.generation(), 2);
        let empty = Account {
            model: account::Account {
                activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
                document_generation: None,
                ..staged.model
            },
            ..staged
        };
        assert_eq!(empty.model.generation(), 0);
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
                judged_with(row, mark(2, 5, 7), Some([8; 32]), &[2])
                    .decision
                    .verdict,
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
        // document: it fails stop as one that lost its mark, signed with failing's
        // mark-lost key.
        for mark in [MarkInput::Missing, MarkInput::NotAMark] {
            let judgement = judged(Row::StagedNoChain, mark, &[0]);
            assert_eq!(
                judgement.decision.verdict,
                failing(0, NoticeReason::MarkLost, true, true)
            );
            assert_eq!(judgement.key, CURRENT);
            assert_eq!(
                verdict(Row::StagedNoChain, mark, &[1]),
                failing(0, NoticeReason::MarkLost, false, true)
            );
        }
        let mut named = account(Row::StagedNoChain).expect("account");
        named.named_key = Some(DOC_KEY);
        let judgement = judge(&Inputs {
            account: Some(&named),
            mark: &MarkInput::Missing,
            stub_at_mark: None,
            tag_at_mark: None,
            erasure_at_ms: None,
            retired: &[0],
            current_key: CURRENT,
        });
        assert_eq!(judgement.key, DOC_KEY);
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
        serving.model.state = AccountState::Serving(tip(5, 1, 1));
        serving.model.document_generation = Some(5);
        let judgement = judge(&Inputs {
            account: Some(&serving),
            mark: &MarkInput::Missing,
            stub_at_mark: None,
            tag_at_mark: None,
            erasure_at_ms: None,
            retired: &[],
            current_key: CURRENT,
        });
        assert_eq!(
            judgement.decision.verdict,
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
                tag_at_mark: None,
                erasure_at_ms: None,
                retired: &[],
                current_key: CURRENT,
            })
            .decision
            .verdict
        };
        staged.model.enrolled_generation = 2;
        assert_eq!(at(&staged, mark(2, 12, 7)), bounded(2, false));
        staged.model.enrolled_generation = 1;
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

    #[test]
    fn test_verdict_rule_mark_input_from_a_store_read() {
        let missing: Result<MarkRead, MarkStoreError> = Ok(MarkRead::Missing);
        assert_eq!(MarkInput::from(&missing), MarkInput::Missing);
        let not_a_mark: Result<MarkRead, MarkStoreError> = Ok(MarkRead::NotAMark);
        assert_eq!(MarkInput::from(&not_a_mark), MarkInput::NotAMark);
        let failed: Result<MarkRead, MarkStoreError> = Err(MarkStoreError::Random);
        assert_eq!(MarkInput::from(&failed), MarkInput::StoreUnreadable);
    }

    fn put(generation: u64, recovery_from: Option<u64>) -> RequestClass {
        RequestClass::PutIdentity {
            generation,
            recovery_from,
        }
    }

    #[test]
    fn test_account_judged_serves_on_a_held_key_at_this_origin() {
        // Serving once the newest document names this origin and a key the store holds;
        // another origin, or a key it doesn't hold, leaves it staged, judged by its chain
        // where it holds one (Dispatch wire 7.3, "The state").
        let body = |origin: &str, key: [u8; 32]| IdentityBody {
            generation: 2,
            ..IdentityBody::first(
                [9; 32],
                [4; 16],
                pubky_dispatch_core::records::Inbox::new(origin, key),
                pubky_dispatch_core::records::IdentityPolicy::default(),
            )
        };
        let holds = |key: &[u8; 32]| *key == DOC_KEY || *key == CURRENT;
        let judged = |doc: Option<&IdentityBody>, chain| {
            Account::judged(
                "https://switch.example",
                holds,
                2,
                chain,
                account::Count::default(),
                5,
                doc,
                AccountActivation::Ordinary,
            )
        };
        let here = body("https://switch.example", DOC_KEY);
        let served = judged(Some(&here), Some((10, [1; 32])));
        assert_eq!(served.model.state, AccountState::Serving(tip(2, 10, 1)));
        assert_eq!(served.named_key, Some(DOC_KEY));
        assert_eq!(served.model.document_generation, Some(2));
        let unheld = body("https://switch.example", [7; 32]);
        let elsewhere = body("https://other.example", DOC_KEY);
        for doc in [&unheld, &elsewhere] {
            let staged = judged(Some(doc), Some((10, [1; 32])));
            assert_eq!(
                staged.model.state,
                AccountState::StagedImport(tip(2, 10, 1))
            );
            assert_eq!(staged.named_key, None);
            assert_eq!(
                judged(Some(doc), None).model.state,
                AccountState::StagedNoChain
            );
        }
        assert_eq!(judged(None, None).model.document_generation, None);
    }

    #[test]
    fn test_answer_staged_activation_of_a_retired_generation_is_refused() {
        // At a staged account at its (0, 0) mark, an import of a generation the operator
        // retired for the identity doesn't clear the mark, and its activation is refused.
        let zero = AccountMark::zero(MARK_KEY, 100);
        let head = ChainTip {
            generation: 3,
            seq: 9,
            chain_hash: [1; 32],
        };
        let clears_mark = activation_clears_mark(head, None, Some(&zero), &[3]);
        assert!(!clears_mark);
        assert!(activation_clears_mark(head, None, Some(&zero), &[2]));
        let judgement = judged(Row::StagedNoChain, MarkInput::Mark(zero), &[3]);
        let class = RequestClass::Move(MoveStep::Activate { clears_mark });
        assert_eq!(
            answer(&judgement, &class, CURRENT),
            Answer {
                route: Route::Conflict,
                key: MARK_KEY,
            }
        );
    }

    // Table 2, "Signed with", and the enrollment's answer with the current key.

    /// The key of `judgement` for every class but an enrollment, whose is the current key.
    fn assert_key(judgement: &Judgement, key: [u8; 32]) {
        assert_eq!(judgement.key, key);
        for class in [
            RequestClass::Ordinary,
            put(5, Some(4)),
            RequestClass::Move(MoveStep::Abort),
            RequestClass::Erase,
        ] {
            assert_eq!(answer(judgement, &class, CURRENT).key, key);
        }
        assert_eq!(
            answer(judgement, &RequestClass::Enroll, CURRENT).key,
            CURRENT
        );
    }

    #[test]
    fn test_answer_not_hosted_key() {
        let judgement = judged(Row::None, MarkInput::Missing, &[]);
        assert_eq!(judgement.decision.verdict, NOT_HOSTED);
        assert_key(&judgement, CURRENT);
        // Erased again: the account's document no longer counts.
        let judgement = judged(Row::ErasedAgain, MarkInput::Missing, &[]);
        assert_key(&judgement, CURRENT);
    }

    #[test]
    fn test_answer_staged_key() {
        // No document names this service: the key in its mark.
        let judgement = judged(Row::StagedNoChain, mark(0, 0, 0), &[]);
        assert_eq!(judgement.decision.verdict, Verdict::Staged);
        assert_key(&judgement, MARK_KEY);
        let mut named = account(Row::StagedNoChain).expect("account");
        named.named_key = Some(DOC_KEY);
        let judgement = judge(&Inputs {
            account: Some(&named),
            mark: &mark(0, 0, 0),
            stub_at_mark: None,
            tag_at_mark: None,
            erasure_at_ms: None,
            retired: &[],
            current_key: CURRENT,
        });
        assert_key(&judgement, DOC_KEY);
    }

    #[test]
    fn test_answer_healthy_key() {
        // The key its newest identity.json names; while none names this service, the mark's.
        let judgement = judged(Row::Serving, mark(2, 10, 1), &[]);
        assert_eq!(judgement.decision.verdict, Verdict::Healthy);
        assert_key(&judgement, DOC_KEY);
        let judgement = judged(Row::StagedImport, mark(2, 10, 1), &[]);
        assert_eq!(judgement.decision.verdict, Verdict::Healthy);
        assert_key(&judgement, MARK_KEY);
    }

    #[test]
    fn test_answer_bounded_key() {
        let judgement = judged(Row::StagedNoChain, mark(2, 12, 7), &[]);
        assert!(matches!(
            judgement.decision.verdict,
            Verdict::Bounded { .. }
        ));
        assert_key(&judgement, MARK_KEY);
    }

    #[test]
    fn test_answer_failing_key() {
        // The key in its mark.
        let judgement = judged(Row::Serving, mark(2, 12, 7), &[]);
        assert!(matches!(
            judgement.decision.verdict,
            Verdict::Failing { .. }
        ));
        assert_key(&judgement, MARK_KEY);
        // With the mark lost, the key its newest identity.json names.
        let judgement = judged(Row::Serving, MarkInput::Missing, &[]);
        assert_key(&judgement, DOC_KEY);
        // Or the current key when no document names this service.
        let judgement = judged(Row::StagedImport, MarkInput::NotAMark, &[]);
        assert_key(&judgement, CURRENT);
    }

    #[test]
    fn test_answer_lost_account_routes_enrollment_and_erasure_with_their_keys() {
        let judgement = judged(Row::None, mark(2, 12, 7), &[]);
        assert!(matches!(judgement.decision.verdict, Verdict::Lost { .. }));
        assert_key(&judgement, MARK_KEY);
        assert_eq!(
            answer(&judgement, &RequestClass::Enroll, CURRENT),
            Answer {
                route: Route::TakeOverMark,
                key: CURRENT,
            }
        );
        assert_eq!(
            answer(&judgement, &RequestClass::Erase, CURRENT),
            Answer {
                route: Route::EraseLost,
                key: MARK_KEY,
            }
        );
    }

    #[test]
    fn test_answer_unknown_key() {
        // The key its newest identity.json names where an account holds one naming this
        // service, else the current key.
        let judgement = judged(Row::Serving, MarkInput::StoreUnreadable, &[]);
        assert_eq!(judgement.decision.verdict, Verdict::Unknown);
        assert_key(&judgement, DOC_KEY);
        assert_key(
            &judged(Row::StagedImport, MarkInput::StoreUnreadable, &[]),
            CURRENT,
        );
        assert_key(&judged(Row::None, MarkInput::StoreUnreadable, &[]), CURRENT);
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
            account.model.document_generation = Some(3);
            let judgement = judge(&Inputs {
                account: Some(&account),
                mark: &MarkInput::Missing,
                stub_at_mark: None,
                tag_at_mark: None,
                erasure_at_ms: None,
                retired: &[],
                current_key: CURRENT,
            });
            let notice = notice(account.model.generation(), NoticeReason::MarkLost, false);
            assert_eq!(
                answer(&judgement, &RequestClass::Ordinary, CURRENT).route,
                Route::Notice(notice)
            );
            for generation in [2, 3] {
                assert_eq!(
                    answer(&judgement, &put(generation, Some(generation - 1)), CURRENT).route,
                    Route::Notice(notice)
                );
            }
            assert_eq!(
                answer(&judgement, &put(4, Some(3)), CURRENT).route,
                Route::StartAfresh
            );
        }
    }

    #[test]
    fn test_answer_recovery_lost_mark_uses_document_floor() {
        let mut account = account(Row::Serving).expect("account");
        account.model.document_generation = Some(1);
        let judgement = judge(&Inputs {
            account: Some(&account),
            mark: &MarkInput::Missing,
            stub_at_mark: None,
            tag_at_mark: None,
            erasure_at_ms: None,
            retired: &[],
            current_key: CURRENT,
        });
        assert_eq!(
            answer(&judgement, &RequestClass::Ordinary, CURRENT).route,
            Route::Notice(notice(2, NoticeReason::MarkLost, false))
        );
        assert_eq!(
            answer(&judgement, &put(2, Some(1)), CURRENT).route,
            Route::StartAfresh
        );
    }
    #[test]
    fn test_account_association_older_mark_uses_sql_key() {
        let held = account(Row::Serving).expect("account");
        let judgement = judge(&Inputs {
            account: Some(&held),
            mark: &MarkInput::Mark(mark_created(2, 10, 1, 50)),
            stub_at_mark: None,
            tag_at_mark: None,
            erasure_at_ms: None,
            retired: &[],
            current_key: CURRENT,
        });
        assert_eq!(judgement.key, DOC_KEY);
        assert_eq!(
            judgement.decision.verdict,
            failing(2, NoticeReason::MarkLost, false, false)
        );
    }

    #[test]
    fn test_account_association_older_sql_uses_mark_key() {
        let held = account(Row::Serving).expect("account");
        let judgement = judge(&Inputs {
            account: Some(&held),
            mark: &MarkInput::Mark(mark_created(2, 10, 1, 200)),
            stub_at_mark: None,
            tag_at_mark: None,
            erasure_at_ms: None,
            retired: &[],
            current_key: CURRENT,
        });
        assert_eq!(judgement.key, MARK_KEY);
        assert_eq!(judgement.decision.verdict, lost(2, false));
    }
}
