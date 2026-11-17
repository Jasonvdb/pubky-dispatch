//! Pure account and rollback-mark decisions (Switch wire 7.3, Tables 1 and 2).
//!
//! Callers supply account, mark, erasure and retirement facts. These functions return
//! verdicts and request routes without reading storage, selecting a signing key or changing
//! account state.

use pubky_switch_core::{
    chain::ChainTip,
    http::{NoticeReason, RecoveryNotice},
    records::{AccountActivation, AccountAssociation, AccountBinding, AccountMarkInput},
};

/// The mark facts used by the account verdict (Switch wire 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    /// The generation of the newest signed head, or zero before any head.
    pub generation: u64,
    /// The sequence number of that head, or zero before any head.
    pub seq: u64,
    /// The chain hash of that head, or the zero hash before any head.
    pub chain_hash: [u8; 32],
    /// The account creation time, in Unix milliseconds.
    pub created_at_ms: u64,
}

impl Mark {
    /// A mark created before any head was signed (Switch wire 7.3, Table 3).
    pub fn zero(created_at_ms: u64) -> Self {
        Self {
            generation: 0,
            seq: 0,
            chain_hash: [0; 32],
            created_at_ms,
        }
    }

    fn records_head(&self) -> bool {
        self.generation != 0
    }
}

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
    /// Frozen, at this head.
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
    /// Whether this current account must recover before it can activate.
    pub activation: AccountActivation,
    /// What it holds.
    pub state: AccountState,
    /// When it was created, in Unix milliseconds.
    pub created_at_ms: u64,
    /// The generation of the newest `identity.json` it holds, `None` while it holds none.
    pub document_generation: Option<u64>,
    /// The generation of the `identity.json` it was enrolled with (Switch wire 7.3, Table 2),
    /// for an account enrolled without one 1, the generation its first document starts
    /// (Switch wire 3.3). The account's row holds it while the account is staged, the only
    /// time the abort it bounds counts.
    pub enrolled_generation: u64,
}

impl Account {
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
    Mark(Mark),
}

impl MarkInput {
    fn binding_input(&self) -> AccountMarkInput {
        match self {
            Self::StoreUnreadable => AccountMarkInput::Unreadable,
            Self::Missing => AccountMarkInput::Missing,
            Self::NotAMark => AccountMarkInput::Malformed,
            Self::Mark(mark) => AccountMarkInput::Created(mark.created_at_ms),
        }
    }

    fn mark(&self) -> Option<&Mark> {
        match self {
            Self::Mark(mark) => Some(mark),
            Self::StoreUnreadable | Self::Missing | Self::NotAMark => None,
        }
    }
}

/// Select the current lifetime while retaining the physical inputs for recovery bounds
/// (Switch account binding 1.1).
pub fn account_binding(
    account: Option<&Account>,
    mark: &MarkInput,
) -> pubky_switch_core::Result<AccountBinding> {
    AccountBinding::select(
        account.map(|account| account.created_at_ms),
        mark.binding_input(),
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
    /// The time of the erasure's record for the identity, in Unix milliseconds, if there is
    /// one (Switch wire 7.4.16).
    pub erasure_at_ms: Option<u64>,
    /// The identity's retired generations (Switch spec 6.5).
    pub retired: &'a [u64],
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
    /// The selected current account requires a durable higher recovery before activation.
    pub recovery_required: bool,
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
    /// The generation whose retirement the verdict read ([`retirement_generation`]): the
    /// one an operator retires to make this account's loss permanent. A retirement of it
    /// still counts only where the verdict lets it (an erasure's leftover mark, or a state
    /// of a later generation, takes none); `None` where none can count at all.
    pub retirement_generation: Option<u64>,
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
        return Judgement {
            recovery_required: false,
            erase_account_again: false,
            verdict: Verdict::Unknown,
            recovery_floor: 0,
            retirement_generation: None,
        };
    }
    let selected = select(inputs.account, inputs.mark, inputs.erasure_at_ms);
    let account = selected.account;
    let erase_account_again = selected.erase_account_again;
    let recovery_floor = account
        .map_or(0, |account| {
            let retained_sql = if account.activation == AccountActivation::Recovery
                || inputs
                    .mark
                    .mark()
                    .is_some_and(|mark| mark.created_at_ms != account.created_at_ms)
            {
                account.enrolled_generation
            } else {
                0
            };
            account.document_generation.unwrap_or(0).max(retained_sql)
        })
        .max(inputs.mark.mark().map_or(0, |mark| mark.generation));
    let recovery_required = account
        .is_some_and(|account| account.activation == AccountActivation::Recovery)
        && selected
            .effective
            .is_some_and(|effective| effective.account.is_some());
    let retirement_generation = selected.retirement_generation();
    let verdict = match selected.effective {
        None => Verdict::Unknown,
        Some(effective) => {
            let effective_inputs = Inputs {
                account: effective.account,
                mark: &effective.mark,
                ..*inputs
            };
            // The selected generation, where the operator retired it.
            let retired =
                retirement_generation.filter(|generation| inputs.retired.contains(generation));
            match effective.account {
                None => judge_without_account(&effective_inputs, retired.is_some()),
                Some(account) => judge_account(account, &effective_inputs, retired),
            }
        }
    };
    Judgement {
        recovery_required,
        erase_account_again,
        verdict,
        recovery_floor,
        retirement_generation,
    }
}

/// The generation whose retirement Table 1 reads for an identity (Switch wire 7.3 under
/// Table 1): the selected mark's generation, or the selected account's where no mark is
/// selected, after the first row and the common association (Switch account binding 1.1).
/// `None` where no retirement can count: the mark store can't be read, the association
/// can't be judged, or neither an account nor a mark is selected. The one rule for the
/// verdict, the service's retirement read and the operator's `retire`.
pub fn retirement_generation(
    account: Option<&Account>,
    mark: &MarkInput,
    erasure_at_ms: Option<u64>,
) -> Option<u64> {
    // An unreadable store fails the association, so it selects no generation.
    select(account, mark, erasure_at_ms).retirement_generation()
}

/// The account and mark Table 1 judges, after its first row and the common association.
struct Selected<'a> {
    /// The account, unless the first row erases it again.
    account: Option<&'a Account>,
    /// The first row applies: the account was created at or before the erasure's record.
    erase_account_again: bool,
    /// The selected account and mark; `None` where the association can't be judged.
    effective: Option<Effective<'a>>,
}

/// The selected inputs of [`Selected`].
#[derive(Clone, Copy)]
struct Effective<'a> {
    /// The account associated with the selected lifetime, if any.
    account: Option<&'a Account>,
    /// The selected mark: missing where it is of an older lifetime than the account.
    mark: MarkInput,
}

impl Selected<'_> {
    fn retirement_generation(&self) -> Option<u64> {
        let effective = self.effective?;
        match (effective.account, effective.mark.mark()) {
            (Some(account), mark) => {
                Some(mark.map_or(account.generation(), |mark| mark.generation))
            }
            (None, Some(mark)) => Some(mark.generation),
            (None, None) => None,
        }
    }
}

/// Apply Table 1's first row and the common association (Switch wire 7.3, account binding
/// 1.1) to the identity's account and mark.
fn select<'a>(
    account: Option<&'a Account>,
    mark: &MarkInput,
    erasure_at_ms: Option<u64>,
) -> Selected<'a> {
    let mut account = account;
    let mut erase_account_again = false;
    if let (Some(held), Some(erased_at)) = (account, erasure_at_ms)
        && held.created_at_ms <= erased_at
    {
        // A restore brought it back, or its deletion never committed: then a row "None"
        // applies.
        erase_account_again = true;
        account = None;
    }
    let effective = account_binding(account, mark).ok().map(|binding| {
        let effective_account =
            account.filter(|_| binding.association() == AccountAssociation::Account);
        // A mark of an older lifetime than the selected account is no mark of it.
        let older_mark = effective_account.is_some_and(|account| {
            mark.mark()
                .is_some_and(|mark| mark.created_at_ms < account.created_at_ms)
        });
        Effective {
            account: effective_account,
            mark: if older_mark {
                MarkInput::Missing
            } else {
                *mark
            },
        }
    });
    Selected {
        account,
        erase_account_again,
        effective,
    }
}

/// Table 1, rows "None" and "None, erased".
fn judge_without_account(inputs: &Inputs<'_>, retired: bool) -> Verdict {
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
    if retired {
        return lost(mark, true);
    }
    if mark.records_head() {
        lost(mark, false)
    } else {
        Verdict::NotHosted { delete_mark: false }
    }
}

fn lost(mark: &Mark, permanent: bool) -> Verdict {
    Verdict::Lost {
        notice: RecoveryNotice {
            generation: mark.generation,
            reason: NoticeReason::Behind,
            permanent,
        },
    }
}

/// Table 1, the rows of an account.
fn judge_account(account: &Account, inputs: &Inputs<'_>, retired: Option<u64>) -> Verdict {
    let state = account.state.state();
    let mark = inputs.mark.mark();
    let column = column(state, mark, inputs.stub_at_mark);
    // A retirement is of the generation [`retirement_generation`] selects, and counts
    // only while the state isn't of a later generation than that.
    let retired =
        retired.is_some_and(|retired| state.is_none_or(|state| state.generation <= retired));
    let generation = account
        .generation()
        .max(mark.map_or(0, |mark| mark.generation));
    let abort_allowed = account.activation == AccountActivation::Ordinary
        && account.state.is_staged()
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
    if account.activation == AccountActivation::Recovery {
        return if mark.is_none() {
            failing(NoticeReason::MarkLost, retired)
        } else {
            bounded(retired)
        };
    }
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
pub fn stub_for_fork_rule(state: Option<(u64, u64)>, mark: &Mark) -> Option<(u64, u64)> {
    let marked = (mark.generation, mark.seq);
    (mark.records_head() && state.is_some_and(|at| at > marked)).then_some(marked)
}

/// Which of Table 1's columns, other than the two read first, the state and the mark fall
/// in.
fn column(state: Option<ChainTip>, mark: Option<&Mark>, stub_at_mark: Option<[u8; 32]>) -> Column {
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

/// The route for this request class (Switch wire 7.3, Table 2).
///
/// This computes a decision from supplied facts; it performs no request or state change.
pub fn request_route(judgement: &Judgement, class: &RequestClass) -> Route {
    if judgement.recovery_required && matches!(class, RequestClass::Move(_)) {
        return match judgement.verdict {
            Verdict::Bounded { notice, .. } | Verdict::Failing { notice, .. } => {
                Route::Notice(notice)
            }
            _ => Route::Unavailable,
        };
    }
    route(&judgement.verdict, class, judgement.recovery_floor)
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
pub(crate) fn recovery_starts_above(floor: u64, generation: u64, from: Option<u64>) -> bool {
    generation > floor && from.is_some_and(|from| generation.checked_sub(1) == Some(from))
}

/// Whether an activation at a bounded account clears its mark (Switch wire 7.3, Table 2):
/// the import's head is at or past the mark and not of a retired generation, and its chain,
/// where it reaches the mark's `seq` in the mark's generation, has the mark's chain hash
/// there. `hash_at_mark` is the import's chain hash at the mark's generation and `seq`,
/// `None` where its chain doesn't reach it. With the mark lost only the retirement bounds
/// it.
pub fn activation_clears_mark(
    import_head: ChainTip,
    hash_at_mark: Option<[u8; 32]>,
    mark: Option<&Mark>,
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
mod tests;
