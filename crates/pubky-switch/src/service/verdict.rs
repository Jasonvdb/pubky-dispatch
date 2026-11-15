//! The verdict for an account and its mark, and what each verdict answers (Switch wire 7.3,
//! "Accounts and marks", Tables 1 and 2; Switch spec 6.5).
//!
//! Pure functions: the request path reads the account, its mark, the erasure's record and
//! the retirements, and [`judge`] gives the verdict of Table 1 and the key of Table 2's
//! "Signed with" column; [`answer`] gives the route of Table 2 for the request's class.

use pubky_switch_core::{
    chain::{ChainTip, ZERO_HASH},
    http::{NoticeReason, RecoveryNotice},
    records::IdentityBody,
};

use crate::marks::{AccountMark, MarkRead, MarkStoreError};

/// What an account holds, as the request finds it (Switch wire 7.3, "The state").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountState {
    /// Staged, holding no chain: it has activated no import, and has no state to compare.
    StagedNoChain,
    /// Staged, holding an activated import (Switch wire 10.5), ending at this head; also a
    /// staged account holding the chain it served, whose newest document names another
    /// service.
    StagedImport(ChainTip),
    /// Serving, at this head.
    Serving(ChainTip),
    /// Frozen, at this head. The freeze isn't served yet, so no request finds one.
    #[cfg_attr(not(test), allow(dead_code))]
    Frozen(ChainTip),
}

impl AccountState {
    /// The head of the chain it holds: its state, if it has one.
    pub fn state(&self) -> Option<ChainTip> {
        match self {
            Self::StagedNoChain => None,
            Self::StagedImport(head) | Self::Serving(head) | Self::Frozen(head) => Some(*head),
        }
    }

    /// Whether the account is staged.
    pub fn is_staged(&self) -> bool {
        matches!(self, Self::StagedNoChain | Self::StagedImport(_))
    }
}

/// An account, as [`judge`] needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    /// What it holds.
    pub state: AccountState,
    /// When it was created, in Unix milliseconds.
    pub created_at_ms: u64,
    /// The generation of the newest `identity.json` it holds, `None` while it holds none.
    pub document_generation: Option<u64>,
    /// The service key its newest `identity.json` names, where that document names this
    /// service.
    pub named_key: Option<[u8; 32]>,
    /// The generation of the `identity.json` it was enrolled with (Switch wire 7.3, Table 2),
    /// for an account enrolled without one 1, the generation its first document starts
    /// (Switch wire 3.3). The account's row holds it while the account is staged, the only
    /// time the abort it bounds counts.
    pub enrolled_generation: u64,
}

impl Account {
    /// The account as the verdict judges it (Switch wire 7.3, "The state"), in one place
    /// for the service and its offline check: serving at its chain head once its newest
    /// `identity.json`, `doc`, names `origin` and a key the service's key store holds, as
    /// `holds` says; else staged, judged by its chain where it holds one (an activated
    /// import), else holding none. `generation` is its row's: that of the `identity.json` it
    /// was enrolled with, or 1 for one enrolled without a document, until a generation
    /// starts there, which makes it serve.
    pub fn judged(
        origin: &str,
        holds: impl Fn(&[u8; 32]) -> bool,
        generation: u64,
        chain: Option<(u64, [u8; 32])>,
        created_at_ms: u64,
        doc: Option<&IdentityBody>,
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
        let state = if named_key.is_some() {
            AccountState::Serving(tip)
        } else if chain.is_some() {
            AccountState::StagedImport(tip)
        } else {
            AccountState::StagedNoChain
        };
        Self {
            state,
            created_at_ms,
            document_generation: doc.map(|body| body.generation),
            named_key,
            enrolled_generation: generation,
        }
    }

    /// Its generation here (Switch wire 7.6): that of the state it holds, its chain's where
    /// it holds one (an activated import included), else its document's, 0 only while it
    /// holds neither.
    pub fn generation(&self) -> u64 {
        match self.state.state() {
            Some(state) => state.generation,
            None => self.document_generation.unwrap_or(0),
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
    fn mark(&self) -> Option<&AccountMark> {
        match self {
            Self::Mark(mark) => Some(mark),
            Self::StoreUnreadable | Self::Missing | Self::NotAMark => None,
        }
    }
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
    /// The time of the erasure's record for the identity, in Unix milliseconds, if there is
    /// one (Switch wire 7.4.16).
    pub erasure_at_ms: Option<u64>,
    /// The identity's retired generations (Switch spec 6.5).
    pub retired: &'a [u64],
    /// The service's current key.
    pub current_key: [u8; 32],
}

/// The verdict of Table 1 (Switch wire 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The service doesn't host the identity. With `delete_mark`, the mark is an erasure's
    /// leftover, deleted.
    NotHosted {
        /// Whether the mark is deleted.
        delete_mark: bool,
    },
    /// A staged account at its (0, 0) mark.
    Staged,
    /// The account's state is at or past its mark.
    Healthy,
    /// A staged account holding no chain, bounded by its mark.
    Bounded {
        /// The notice it answers.
        notice: RecoveryNotice,
        /// Whether the abort of a move goes through (Table 2).
        abort_allowed: bool,
    },
    /// The account fails stop.
    Failing {
        /// The notice it answers.
        notice: RecoveryNotice,
        /// Whether the abort of a move goes through: only at a staged account (Table 2).
        abort_allowed: bool,
    },
    /// No account, with a mark that records a head, or of a retired generation.
    Lost {
        /// The notice it answers.
        notice: RecoveryNotice,
    },
    /// The mark store can't be read.
    Unknown,
}

/// What [`judge`] finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Judgement {
    /// Table 1's first row: the account was created at or before the time of an erasure's
    /// record for the identity, and is erased again before anything is served or signed;
    /// `verdict` is that of the identity without it.
    pub erase_account_again: bool,
    /// The verdict.
    pub verdict: Verdict,
    /// The held document's generation or the mark's, whichever is greater: a recovery
    /// start must exceed it (Switch wire 7.3, Table 2). This is independent of the notice's
    /// chain generation. Unused while the verdict is unknown.
    pub recovery_floor: u64,
    /// The key the verdict's answers are signed with (Table 2, "Signed with"), but an
    /// enrollment's ([`answer`]).
    pub key: [u8; 32],
}

/// The columns of Table 1 other than the retired one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Column {
    /// No mark, or one that doesn't read as a mark.
    NoMark,
    /// Mark (0, 0).
    Zero,
    /// The mark records a head; the account has no state to compare.
    Head,
    /// The mark records a head; the state is at or past it.
    AtOrPast,
    /// The mark records a head; the state is behind it.
    Behind,
    /// The mark is at the state's pair with another chain hash, or the state is past the
    /// mark with another chain hash at the mark's `seq`.
    Fork,
}

/// Judge the account and its mark together (Switch wire 7.3, Table 1).
///
/// The first row comes before every other, and the columns are read from the right: a store
/// that can't be read, then a retired generation, then the rest.
pub fn judge(inputs: &Inputs<'_>) -> Judgement {
    if matches!(inputs.mark, MarkInput::StoreUnreadable) {
        // While the verdict is unknown no mark is created, moved or deleted, nor is an
        // account erased again.
        let key = inputs
            .account
            .and_then(|account| account.named_key)
            .unwrap_or(inputs.current_key);
        return Judgement {
            erase_account_again: false,
            verdict: Verdict::Unknown,
            recovery_floor: 0,
            key,
        };
    }
    let mut account = inputs.account;
    let mut erase_account_again = false;
    if let (Some(held), Some(erased_at)) = (account, inputs.erasure_at_ms)
        && held.created_at_ms <= erased_at
    {
        // A restore brought it back, or its deletion never committed: then a row "None"
        // applies.
        erase_account_again = true;
        account = None;
    }
    let verdict = match account {
        None => judge_without_account(inputs),
        Some(account) => judge_account(account, inputs),
    };
    let mark_key = inputs.mark.mark().map(|mark| mark.key);
    let named_key = account.and_then(|account| account.named_key);
    let key = match verdict {
        Verdict::NotHosted { .. } | Verdict::Unknown => inputs.current_key,
        Verdict::Staged | Verdict::Healthy => named_key.or(mark_key).unwrap_or(inputs.current_key),
        Verdict::Bounded { .. } | Verdict::Failing { .. } | Verdict::Lost { .. } => {
            mark_key.or(named_key).unwrap_or(inputs.current_key)
        }
    };
    Judgement {
        erase_account_again,
        verdict,
        recovery_floor: account
            .and_then(|account| account.document_generation)
            .unwrap_or(0)
            .max(inputs.mark.mark().map_or(0, |mark| mark.generation)),
        key,
    }
}

/// Table 1, rows "None" and "None, erased".
fn judge_without_account(inputs: &Inputs<'_>) -> Verdict {
    let Some(mark) = inputs.mark.mark() else {
        return Verdict::NotHosted { delete_mark: false };
    };
    // An erasure's record names the identity at or after the mark's creation: the mark is
    // an erasure's leftover. A mark created after the record belongs to a later account.
    if inputs
        .erasure_at_ms
        .is_some_and(|erased_at| erased_at >= mark.created_at_ms)
    {
        return Verdict::NotHosted { delete_mark: true };
    }
    // With no account there is no state, so a retirement always counts.
    if inputs.retired.contains(&mark.generation) {
        return lost(mark, true);
    }
    if mark.records_head() {
        lost(mark, false)
    } else {
        Verdict::NotHosted { delete_mark: false }
    }
}

fn lost(mark: &AccountMark, permanent: bool) -> Verdict {
    Verdict::Lost {
        notice: RecoveryNotice {
            generation: mark.generation,
            reason: NoticeReason::Behind,
            permanent,
        },
    }
}

/// Table 1, the rows of an account.
fn judge_account(account: &Account, inputs: &Inputs<'_>) -> Verdict {
    let state = account.state.state();
    let mark = inputs.mark.mark();
    let column = column(state, mark, inputs.stub_at_mark);
    // A retirement is of the mark's generation, or of the account's where the mark is
    // lost, and counts only while the state isn't of a later generation than that.
    let retired_generation = mark.map_or(account.generation(), |mark| mark.generation);
    let retired = inputs.retired.contains(&retired_generation)
        && state.is_none_or(|state| state.generation <= retired_generation);
    let generation = account
        .generation()
        .max(mark.map_or(0, |mark| mark.generation));
    let abort_allowed = account.state.is_staged()
        && mark.is_none_or(|mark| mark.generation <= account.enrolled_generation);
    let notice = |reason, permanent| RecoveryNotice {
        generation,
        reason,
        permanent,
    };
    let failing = |reason, permanent| Verdict::Failing {
        notice: notice(reason, permanent),
        abort_allowed,
    };
    let bounded = |permanent| Verdict::Bounded {
        notice: notice(NoticeReason::Behind, permanent),
        abort_allowed,
    };
    if state.is_none() {
        // Row "Staged, holding no chain".
        if retired {
            // Where the mark is lost the retirement is of the account's generation, and
            // the account fails stop as one that lost its mark.
            return if mark.is_none() {
                failing(NoticeReason::MarkLost, true)
            } else {
                bounded(true)
            };
        }
        return match column {
            Column::NoMark => failing(NoticeReason::MarkLost, false),
            Column::Zero => Verdict::Staged,
            Column::Head | Column::AtOrPast | Column::Behind | Column::Fork => bounded(false),
        };
    }
    // Rows "Staged, holding an activated import", "Serving" and "Frozen". "Permanent" keeps
    // the reason the account had before it was retired.
    let reason = match column {
        Column::NoMark => Some(NoticeReason::MarkLost),
        Column::Behind => Some(NoticeReason::Behind),
        Column::Fork => Some(NoticeReason::Fork),
        Column::Zero | Column::Head | Column::AtOrPast => None,
    };
    match (retired, reason) {
        (true, reason) => failing(reason.unwrap_or(NoticeReason::Behind), true),
        (false, Some(reason)) => failing(reason, false),
        (false, None) => Verdict::Healthy,
    }
}

/// The stub whose chain hash the fork rule under Table 1 compares with the mark's (Switch
/// wire 7.3): "Where the service still holds the chain stub at the mark's `seq`, a state past
/// the mark with another chain hash there is a fork too". The mark's generation and `seq`,
/// where the mark records a head and `state`, the account's (generation, `seq`), is past it,
/// whatever the state's generation; `None` where the rule doesn't look. In one place for the
/// service and its offline check.
pub fn stub_for_fork_rule(state: Option<(u64, u64)>, mark: &AccountMark) -> Option<(u64, u64)> {
    let marked = (mark.generation, mark.seq);
    (mark.records_head() && state.is_some_and(|at| at > marked)).then_some(marked)
}

/// Which of Table 1's columns, other than the two read first, the state and the mark fall
/// in.
fn column(
    state: Option<ChainTip>,
    mark: Option<&AccountMark>,
    stub_at_mark: Option<[u8; 32]>,
) -> Column {
    let Some(mark) = mark else {
        return Column::NoMark;
    };
    if !mark.records_head() {
        return Column::Zero;
    }
    let Some(state) = state else {
        return Column::Head;
    };
    let at = (state.generation, state.seq);
    let marked = (mark.generation, mark.seq);
    if at < marked {
        Column::Behind
    } else if at == marked {
        if state.chain_hash == mark.chain_hash {
            Column::AtOrPast
        } else {
            Column::Fork
        }
    } else if stub_at_mark.is_some_and(|hash| hash != mark.chain_hash) {
        // Where the service still holds the stub at the mark's `seq`, a state past the
        // mark with another chain hash there is a fork too.
        Column::Fork
    } else {
        Column::AtOrPast
    }
}

/// A request, by the columns of Table 2 (Switch wire 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestClass {
    /// An own signed request, another identity's caller, or the public read.
    Ordinary,
    /// `POST /v1/enroll`.
    Enroll,
    /// `PUT /identity`: the delivered document's generation and `recovery_from`.
    PutIdentity {
        /// The document's generation.
        generation: u64,
        /// Its `recovery_from`, if it carries one.
        recovery_from: Option<u64>,
    },
    /// A step of a move.
    Move(MoveStep),
    /// `POST /erase`.
    Erase,
}

/// A step of a move (Switch wire 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveStep {
    /// The import and the uploads: `POST /import`, `PUT /import/chunks/{chunk_id}`,
    /// `POST /recovery/upload`.
    ImportOrUpload,
    /// `POST /import/activate`, once its import is judged.
    // The activation isn't served yet: its endpoint will route it so.
    #[cfg_attr(not(test), allow(dead_code))]
    Activate {
        /// Whether the import clears the mark ([`activation_clears_mark`]).
        clears_mark: bool,
    },
    /// `POST /import/activate` as the request arrives, before its import is judged: no
    /// verdict lets it activate anything, and wherever the import could clear the mark it is
    /// routed to [`Route::JudgeActivation`], so an activation is only ever answered as
    /// [`MoveStep::Activate`] with `clears_mark` computed from its import. This keeps the
    /// refusal of an import of a retired generation, at any staged account, from being
    /// passed over (Switch wire 7.3, Table 2).
    ActivateUnjudged,
    /// The abort, `POST /unfreeze` (Switch wire 10.6).
    Abort,
    /// The export, `GET /export` and `GET /export/chunks/{chunk_id}`.
    Export,
}

/// What a request gets under a verdict (Switch wire 7.3, Table 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// The `404 not_found` of step 2, `current: { "hosted": false }`, without a head.
    NotHosted,
    /// The enrollment creates the account (Table 3).
    CreateAccount,
    /// The enrollment creates a staged account that takes the mark over (Table 3).
    TakeOverMark,
    /// The request goes on as the endpoint gives. With `head` false its answer carries no
    /// head.
    Proceed {
        /// Whether its answer may carry a head.
        head: bool,
    },
    /// The start of a generation above both the held document's and the mark's, which
    /// starts the account afresh (Switch wire 3.3); its `200` carries the head.
    StartAfresh,
    /// `409 conflict`: an activation that doesn't clear the mark.
    Conflict,
    /// An activation whose import isn't judged yet ([`MoveStep::ActivateUnjudged`]): the
    /// endpoint computes [`activation_clears_mark`] from the import and routes it again as
    /// [`MoveStep::Activate`]; nothing is activated and no head is signed on this route.
    JudgeActivation,
    /// The erasure as Switch wire 7.4.16 gives.
    Erase {
        /// The account fails stop: a frozen account's unfinished export doesn't bar it.
        fails_stop: bool,
        /// Whether an import bars it: only while the abort can go through.
        import_bars: bool,
    },
    /// The erasure at a lost identity: the record is written, then the mark deleted.
    EraseLost,
    /// `503 recovery_required` with this notice, without a head.
    Notice(RecoveryNotice),
    /// `503 unavailable`, without a head.
    Unavailable,
}

/// What a request gets, and the key its answer is signed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The route.
    pub route: Route,
    /// The key.
    pub key: [u8; 32],
}

/// What a request of `class` gets under `judgement` (Switch wire 7.3, Table 2). An
/// enrollment's answer is always signed with `current_key`, the key it names (Switch wire
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
        route: route(&judgement.verdict, class, judgement.recovery_floor),
        key,
    }
}

fn route(verdict: &Verdict, class: &RequestClass, recovery_floor: u64) -> Route {
    match *verdict {
        Verdict::NotHosted { .. } => match class {
            RequestClass::Enroll => Route::CreateAccount,
            RequestClass::Ordinary
            | RequestClass::PutIdentity { .. }
            | RequestClass::Move(_)
            | RequestClass::Erase => Route::NotHosted,
        },
        Verdict::Staged | Verdict::Healthy => match class {
            // An enrollment signs no head (Switch wire 7.4.1).
            RequestClass::Enroll => Route::Proceed { head: false },
            // At any staged account, an import of a retired generation isn't activated: the
            // same `409 conflict` as at a bounded one (Switch wire 7.3, Table 2).
            RequestClass::Move(MoveStep::Activate { clears_mark: false }) => Route::Conflict,
            RequestClass::Move(MoveStep::ActivateUnjudged) => Route::JudgeActivation,
            RequestClass::Ordinary | RequestClass::PutIdentity { .. } | RequestClass::Move(_) => {
                Route::Proceed { head: true }
            }
            RequestClass::Erase => Route::Erase {
                fails_stop: false,
                import_bars: true,
            },
        },
        Verdict::Bounded {
            notice,
            abort_allowed,
        } => match *class {
            RequestClass::Ordinary => Route::Notice(notice),
            RequestClass::Enroll => Route::Proceed { head: false },
            RequestClass::PutIdentity {
                generation,
                recovery_from,
            } => start_or_notice(notice, recovery_floor, generation, recovery_from),
            RequestClass::Move(step) => match step {
                MoveStep::ImportOrUpload => Route::Proceed { head: false },
                MoveStep::Activate { clears_mark: true } => Route::Proceed { head: true },
                MoveStep::Activate { clears_mark: false } => Route::Conflict,
                MoveStep::ActivateUnjudged => Route::JudgeActivation,
                MoveStep::Abort if abort_allowed => Route::Proceed { head: false },
                MoveStep::Abort | MoveStep::Export => Route::Notice(notice),
            },
            RequestClass::Erase => Route::Erase {
                fails_stop: false,
                import_bars: abort_allowed,
            },
        },
        Verdict::Failing {
            notice,
            abort_allowed,
        } => match *class {
            RequestClass::Ordinary => Route::Notice(notice),
            RequestClass::Enroll => Route::Proceed { head: false },
            RequestClass::PutIdentity {
                generation,
                recovery_from,
            } => start_or_notice(notice, recovery_floor, generation, recovery_from),
            // The abort discards the import, signs no head and gives the discard answer.
            RequestClass::Move(MoveStep::Abort) if abort_allowed => Route::Proceed { head: false },
            RequestClass::Move(_) => Route::Notice(notice),
            RequestClass::Erase => Route::Erase {
                fails_stop: true,
                import_bars: abort_allowed,
            },
        },
        Verdict::Lost { notice } => match *class {
            RequestClass::Enroll => Route::TakeOverMark,
            RequestClass::Erase => Route::EraseLost,
            RequestClass::Ordinary | RequestClass::PutIdentity { .. } | RequestClass::Move(_) => {
                Route::Notice(notice)
            }
        },
        Verdict::Unknown => Route::Unavailable,
    }
}

/// Only a recovery above the held document and mark starts; any other delivery gets the
/// unchanged notice (Switch wire 7.3, Table 2; 7.6).
fn start_or_notice(
    notice: RecoveryNotice,
    recovery_floor: u64,
    generation: u64,
    recovery_from: Option<u64>,
) -> Route {
    if recovery_starts_above(recovery_floor, generation, recovery_from) {
        Route::StartAfresh
    } else {
        Route::Notice(notice)
    }
}

/// Whether a delivery starts a recovery above the held document and mark (Switch wire
/// 7.3, Table 2), for routing and the final check before replacing account state.
pub(super) fn recovery_starts_above(floor: u64, generation: u64, from: Option<u64>) -> bool {
    generation > floor && from.is_some_and(|from| generation.checked_sub(1) == Some(from))
}

/// Whether an activation at a bounded account clears its mark (Switch wire 7.3, Table 2):
/// the import's head is at or past the mark and not of a retired generation, and its chain,
/// where it reaches the mark's `seq` in the mark's generation, has the mark's chain hash
/// there. `hash_at_mark` is the import's chain hash at the mark's generation and `seq`,
/// `None` where its chain doesn't reach it. With the mark lost only the retirement bounds
/// it.
// The activation isn't served yet: its endpoint will compute `MoveStep::Activate` with it,
// from the request routed to `Route::JudgeActivation`.
#[cfg_attr(not(test), allow(dead_code))]
pub fn activation_clears_mark(
    import_head: ChainTip,
    hash_at_mark: Option<[u8; 32]>,
    mark: Option<&AccountMark>,
    retired: &[u64],
) -> bool {
    if retired.contains(&import_head.generation) {
        return false;
    }
    let Some(mark) = mark else {
        return true;
    };
    let head = (import_head.generation, import_head.seq);
    let marked = (mark.generation, mark.seq);
    if head < marked {
        return false;
    }
    if head == marked && import_head.chain_hash != mark.chain_hash {
        return false;
    }
    hash_at_mark.is_none_or(|hash| hash == mark.chain_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        MarkInput::Mark(mark_created(generation, seq, hash, 50))
    }

    fn mark_created(generation: u64, seq: u64, hash: u8, created_at_ms: u64) -> AccountMark {
        AccountMark {
            generation,
            seq,
            chain_hash: if generation == 0 { [0; 32] } else { [hash; 32] },
            key: MARK_KEY,
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
            state,
            created_at_ms: 100,
            document_generation: None,
            named_key: None,
            enrolled_generation: 2,
        };
        let serving = |state| Account {
            state,
            created_at_ms: 100,
            document_generation: Some(2),
            named_key: Some(DOC_KEY),
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
            erasure_at_ms,
            retired,
            current_key: CURRENT,
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
        assert!(judgement.erase_account_again);
        assert_eq!(judgement.verdict, then);
    }

    // Table 1, row "Any, created at or before the time of an erasure's record".

    #[test]
    fn test_verdict_rule_fork_stub_of_the_marks_generation_whatever_the_states() {
        let marked = AccountMark {
            generation: 1,
            seq: 5,
            chain_hash: [1; 32],
            key: CURRENT,
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
        assert_eq!(
            stub_for_fork_rule(Some((2, 3)), &AccountMark::zero(CURRENT, 0)),
            None
        );
        // A later generation's state over another hash there is a fork.
        let serving = Account {
            state: AccountState::Serving(ChainTip {
                generation: 2,
                seq: 3,
                chain_hash: [2; 32],
            }),
            created_at_ms: 0,
            document_generation: Some(2),
            named_key: Some(CURRENT),
            enrolled_generation: 2,
        };
        let judged = judge(&Inputs {
            account: Some(&serving),
            mark: &MarkInput::Mark(marked),
            stub_at_mark: Some([9; 32]),
            erasure_at_ms: None,
            retired: &[],
            current_key: CURRENT,
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
            assert_erased_again(mark, &[], NOT_HOSTED);
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
            assert_eq!(verdict(Row::None, mark, &[]), NOT_HOSTED);
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
            assert_eq!(verdict(Row::NoneErased, mark, &[]), NOT_HOSTED);
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
                current_key: CURRENT,
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
            state: AccountState::StagedImport(tip(3, 7, 1)),
            created_at_ms: 100,
            document_generation: None,
            named_key: None,
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
                current_key: CURRENT,
            })
        };
        let judgement = at(&import, MarkInput::Missing, &[]);
        assert_eq!(
            judgement.verdict,
            failing(3, NoticeReason::MarkLost, false, true)
        );
        assert_eq!(judgement.key, CURRENT);
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
            state: AccountState::StagedNoChain,
            ..with_document
        };
        assert_eq!(staged.generation(), 2);
        let empty = Account {
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
        // document: it fails stop as one that lost its mark, signed with failing's
        // mark-lost key.
        for mark in [MarkInput::Missing, MarkInput::NotAMark] {
            let judgement = judged(Row::StagedNoChain, mark, &[0]);
            assert_eq!(
                judgement.verdict,
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
            erasure_at_ms: None,
            retired: &[0],
            current_key: CURRENT,
        });
        assert_eq!(judgement.key, DOC_KEY);
    }

    #[test]
    fn test_verdict_rule_none_retired_without_a_mark_is_not_hosted() {
        for mark in [MarkInput::Missing, MarkInput::NotAMark] {
            assert_eq!(verdict(Row::None, mark, &[0, 1, 2]), NOT_HOSTED);
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
            current_key: CURRENT,
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
                current_key: CURRENT,
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

    #[test]
    fn test_verdict_rule_mark_input_from_a_store_read() {
        let missing: Result<MarkRead, MarkStoreError> = Ok(MarkRead::Missing);
        assert_eq!(MarkInput::from(&missing), MarkInput::Missing);
        let not_a_mark: Result<MarkRead, MarkStoreError> = Ok(MarkRead::NotAMark);
        assert_eq!(MarkInput::from(&not_a_mark), MarkInput::NotAMark);
        let failed: Result<MarkRead, MarkStoreError> = Err(MarkStoreError::Random);
        assert_eq!(MarkInput::from(&failed), MarkInput::StoreUnreadable);
    }

    // Table 2: the route of each verdict per request class.

    const BEHIND: RecoveryNotice = RecoveryNotice {
        generation: 4,
        reason: NoticeReason::Behind,
        permanent: false,
    };

    fn route_of(verdict: Verdict, class: RequestClass) -> Route {
        let judgement = Judgement {
            erase_account_again: false,
            verdict,
            recovery_floor: BEHIND.generation,
            key: MARK_KEY,
        };
        answer(&judgement, &class, CURRENT).route
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
    fn test_account_judged_serves_on_a_held_key_at_this_origin() {
        // Serving once the newest document names this origin and a key the store holds;
        // another origin, or a key it doesn't hold, leaves it staged, judged by its chain
        // where it holds one (Switch wire 7.3, "The state").
        let body = |origin: &str, key: [u8; 32]| IdentityBody {
            generation: 2,
            ..IdentityBody::first(
                [9; 32],
                [4; 16],
                pubky_switch_core::records::Inbox::new(origin, key),
                pubky_switch_core::records::IdentityPolicy::default(),
            )
        };
        let holds = |key: &[u8; 32]| *key == DOC_KEY || *key == CURRENT;
        let judged = |doc: Option<&IdentityBody>, chain| {
            Account::judged("https://switch.example", holds, 2, chain, 5, doc)
        };
        let here = body("https://switch.example", DOC_KEY);
        let served = judged(Some(&here), Some((10, [1; 32])));
        assert_eq!(served.state, AccountState::Serving(tip(2, 10, 1)));
        assert_eq!(served.named_key, Some(DOC_KEY));
        assert_eq!(served.document_generation, Some(2));
        let unheld = body("https://switch.example", [7; 32]);
        let elsewhere = body("https://other.example", DOC_KEY);
        for doc in [&unheld, &elsewhere] {
            let staged = judged(Some(doc), Some((10, [1; 32])));
            assert_eq!(staged.state, AccountState::StagedImport(tip(2, 10, 1)));
            assert_eq!(staged.named_key, None);
            assert_eq!(judged(Some(doc), None).state, AccountState::StagedNoChain);
        }
        assert_eq!(judged(None, None).document_generation, None);
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
        let zero = AccountMark::zero(MARK_KEY, 1);
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
        let at = |abort_allowed, step| {
            route_of(bounded_verdict(abort_allowed), RequestClass::Move(step))
        };
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
        let at = |abort_allowed, step| {
            route_of(failing_verdict(abort_allowed), RequestClass::Move(step))
        };
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

    // Table 2, "Signed with", and the enrollment's answer with the current key.

    /// The key of `judgement` for every class but an enrollment, whose is the current key.
    fn assert_key(judgement: &Judgement, key: [u8; 32]) {
        assert_eq!(judgement.key, key);
        for class in [
            RequestClass::Ordinary,
            put(5, Some(4)),
            RequestClass::Move(MoveStep::Abort),
            ERASE,
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
        assert_eq!(judgement.verdict, NOT_HOSTED);
        assert_key(&judgement, CURRENT);
        // Erased again: the account's document no longer counts.
        let judgement = judged(Row::ErasedAgain, MarkInput::Missing, &[]);
        assert_key(&judgement, CURRENT);
    }

    #[test]
    fn test_answer_staged_key() {
        // No document names this service: the key in its mark.
        let judgement = judged(Row::StagedNoChain, mark(0, 0, 0), &[]);
        assert_eq!(judgement.verdict, Verdict::Staged);
        assert_key(&judgement, MARK_KEY);
        let mut named = account(Row::StagedNoChain).expect("account");
        named.named_key = Some(DOC_KEY);
        let judgement = judge(&Inputs {
            account: Some(&named),
            mark: &mark(0, 0, 0),
            stub_at_mark: None,
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
        assert_eq!(judgement.verdict, Verdict::Healthy);
        assert_key(&judgement, DOC_KEY);
        let judgement = judged(Row::StagedImport, mark(2, 10, 1), &[]);
        assert_eq!(judgement.verdict, Verdict::Healthy);
        assert_key(&judgement, MARK_KEY);
    }

    #[test]
    fn test_answer_bounded_key() {
        let judgement = judged(Row::StagedNoChain, mark(2, 12, 7), &[]);
        assert!(matches!(judgement.verdict, Verdict::Bounded { .. }));
        assert_key(&judgement, MARK_KEY);
    }

    #[test]
    fn test_answer_failing_key() {
        // The key in its mark.
        let judgement = judged(Row::Serving, mark(2, 12, 7), &[]);
        assert!(matches!(judgement.verdict, Verdict::Failing { .. }));
        assert_key(&judgement, MARK_KEY);
        // With the mark lost, the key its newest identity.json names.
        let judgement = judged(Row::Serving, MarkInput::Missing, &[]);
        assert_key(&judgement, DOC_KEY);
        // Or the current key when no document names this service.
        let judgement = judged(Row::StagedImport, MarkInput::NotAMark, &[]);
        assert_key(&judgement, CURRENT);
    }

    #[test]
    fn test_answer_lost_key() {
        let judgement = judged(Row::None, mark(2, 12, 7), &[]);
        assert!(matches!(judgement.verdict, Verdict::Lost { .. }));
        assert_key(&judgement, MARK_KEY);
    }

    #[test]
    fn test_answer_unknown_key() {
        // The key its newest identity.json names where an account holds one naming this
        // service, else the current key.
        let judgement = judged(Row::Serving, MarkInput::StoreUnreadable, &[]);
        assert_eq!(judgement.verdict, Verdict::Unknown);
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
            account.document_generation = Some(3);
            let judgement = judge(&Inputs {
                account: Some(&account),
                mark: &MarkInput::Missing,
                stub_at_mark: None,
                erasure_at_ms: None,
                retired: &[],
                current_key: CURRENT,
            });
            let notice = notice(account.generation(), NoticeReason::MarkLost, false);
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
        account.document_generation = Some(1);
        let judgement = judge(&Inputs {
            account: Some(&account),
            mark: &MarkInput::Missing,
            stub_at_mark: None,
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
}
