//! The verdict of an account and its mark on the request path (Switch wire 7.3 steps 2 and
//! 10, "Accounts and marks", Tables 1 to 3; Switch spec 6.5).
//!
//! Every request reads the identity's account, its mark, the erasure's record and the
//! selected retirement, and [`verdict::judge`] gives the verdict: at step 2, from the lookup before
//! the account's lock, and again under the lock before the endpoint, since the state may have
//! changed while the request waited. [`verdict::answer`] gives what the request gets and the
//! key it is signed with. The notice, the not-hosted `404` and the `503` of an unknown verdict
//! are answered in place of whatever later steps would answer. Nothing else in the service
//! compares a state with its mark.

use pubky_switch_core::{
    chain::ChainTip,
    http::{IdentityDelivery, NoticeReason, RecoveryNotice, Uncompared, not_hosted_current},
    records::{AccountActivation, AccountBinding, IdentityBody},
    sig::SignedDoc,
};

use super::{
    Service,
    signed::{AnswerTime, Asked},
    verdict::{self, Account, Inputs, Judgement, MarkInput, MoveStep, RequestClass, Route},
};
use crate::{
    http::{
        SwitchRequest, SwitchResponse,
        error::{ApiError, ErrorCode},
        route::Call,
    },
    marks::{AccountMark, Advance, MarkRead, MarkStoreError, MarkWrite},
};

/// How many accounts' notices one process logs, each once.
const MARK_REFUSALS_LOGGED: usize = 1024;

/// What an identity's verdict reads apart from its account (Switch wire 7.3, "The store").
#[derive(Clone, Debug)]
pub(super) struct MarkInputs {
    mark: MarkInput,
    erasure_at_ms: Option<u64>,
    erasure: ErasureCheck,
}

/// A retry carries the exact authenticated attempt whose identity lock it holds.
#[derive(Clone, Debug)]
enum ErasureCheck {
    Clear,
    Pending(crate::marks::ErasureAttempt),
    Retry(crate::marks::ErasureAttempt),
}

impl MarkInputs {
    pub(super) fn has_pending_erasure(&self) -> bool {
        matches!(self.erasure, ErasureCheck::Pending(_))
    }

    pub(super) fn for_erasure(
        mut self,
        attempt: &crate::marks::ErasureAttempt,
    ) -> Result<Self, ApiError> {
        if !matches!(&self.erasure, ErasureCheck::Pending(held) if held == attempt) {
            return Err(ApiError::unavailable("7.6: the erasure attempt changed"));
        }
        self.erasure = ErasureCheck::Retry(attempt.clone());
        Ok(self)
    }
}

/// The verdict of an identity's account and mark, with what it was judged from.
#[derive(Clone, Debug)]
pub(super) struct Judged {
    /// The verdict and its key.
    pub(super) judgement: Judgement,
    /// The identity's mark, as read.
    pub(super) mark: MarkInput,
    /// The time of the erasure's record for the identity, if any.
    pub(super) erasure_at_ms: Option<u64>,
    /// The account, as judged.
    pub(super) account: Option<Account>,
}

impl Judged {
    /// The mark, where it reads as one.
    pub(super) fn mark(&self) -> Option<&AccountMark> {
        match &self.mark {
            MarkInput::Mark(mark) => Some(mark),
            MarkInput::StoreUnreadable | MarkInput::Missing | MarkInput::NotAMark => None,
        }
    }

    /// Select the lifetime without discarding either physical input's bounds
    /// (Switch account binding 1.1).
    pub(super) fn account_binding(&self) -> pubky_switch_core::Result<AccountBinding> {
        verdict::account_binding(self.account.as_ref(), &self.mark)
    }

    /// The selected creation, with unknown inputs kept distinct from absence (Switch
    /// account binding 1.1).
    pub(super) fn created_at_ms(&self) -> Result<Option<u64>, ApiError> {
        self.account_binding()
            .map(AccountBinding::created)
            .map_err(|_| ApiError::unavailable("account binding: creation is unknown"))
    }

    /// Whether the account answers the notice: it fails stop or is bounded (Table 2).
    pub(super) fn answers_notice(&self) -> bool {
        matches!(
            self.judgement.decision.verdict,
            verdict::Verdict::Bounded { .. } | verdict::Verdict::Failing { .. }
        )
    }
}

/// The `404 not_found` of an identity the service doesn't host, `current: { "hosted": false
/// }` (Switch wire 7.3 step 2).
pub(super) fn not_hosted() -> ApiError {
    ApiError::not_found("no such account").with_current(not_hosted_current())
}

/// The class of `request`, by the columns of Table 2, read before anything is verified: a
/// delivery's generation and `recovery_from`. A body that doesn't read as a delivery is
/// judged as one that starts nothing, which the endpoint then refuses.
pub(super) fn class_of(request: &SwitchRequest) -> RequestClass {
    match &request.route.call {
        Call::Enroll => RequestClass::Enroll,
        Call::PutIdentity => {
            let body = IdentityDelivery::parse(&request.body)
                .ok()
                .and_then(|delivery| delivery.identity.peek::<IdentityBody>().ok());
            RequestClass::PutIdentity {
                generation: body.as_ref().map_or(0, |body| body.generation),
                recovery_from: body.and_then(|body| body.recovery_from),
            }
        }
        Call::Erase => RequestClass::Erase,
        Call::RecoveryUpload | Call::Import | Call::ImportChunk(_) => {
            RequestClass::Move(MoveStep::ImportOrUpload)
        }
        // Whether the import clears the mark is the endpoint's to compute from the import,
        // which isn't read here: the activation is classed as unjudged (Table 2).
        Call::ImportActivate => RequestClass::Move(MoveStep::ActivateUnjudged),
        Call::Unfreeze => RequestClass::Move(MoveStep::Abort),
        Call::Export | Call::ExportChunk(_) => RequestClass::Move(MoveStep::Export),
        _ => RequestClass::Ordinary,
    }
}

impl Service {
    /// An account as the verdict judges it ([`Account::judged`]), naming this origin and a
    /// key the key store holds.
    pub(super) fn account_input(
        &self,
        generation: u64,
        chain: Option<(u64, [u8; 32])>,
        created_at_ms: u64,
        doc: Option<&IdentityBody>,
        activation: AccountActivation,
    ) -> Account {
        Account::judged(
            &self.origin,
            |key| self.keys.signer_for(key).is_some(),
            generation,
            chain,
            created_at_ms,
            doc,
            activation,
        )
    }

    /// The account a lookup found, as the verdict judges it. Its document was verified when
    /// the account took it; only what it names is read here.
    pub(super) fn found_input(&self, found: &crate::store::FoundAccount) -> Account {
        let body = found
            .identity_doc
            .as_ref()
            .and_then(|doc: &SignedDoc| doc.peek::<IdentityBody>().ok());
        self.account_input(
            found.generation,
            found.chain,
            found.created_at_ms,
            body.as_ref(),
            found.activation,
        )
    }

    /// Read `identity`'s mark and the erasure's record before the state
    /// they are judged with: a mark moves only after the head it names is committed, so a
    /// state read after its mark is at the mark or past it, unless state was lost (Switch
    /// wire 7.3, "Moving it"). A store that can't be read leaves the verdict unknown.
    pub(super) async fn mark_inputs(&self, identity: &str) -> MarkInputs {
        let mut mark = match self.marks.read(identity).await {
            Ok(read) => MarkInput::from(&Ok::<_, MarkStoreError>(read)),
            // No file can name it: it has no mark.
            Err(MarkStoreError::InvalidIdentity) => MarkInput::Missing,
            Err(failure) => {
                tracing::error!(%failure, "reading a mark");
                MarkInput::StoreUnreadable
            }
        };
        let erasure_at_ms = match self.marks.erasure(identity).await {
            Ok(at) => at,
            Err(failure) => {
                tracing::error!(%failure, "reading the erasures' records");
                mark = MarkInput::StoreUnreadable;
                None
            }
        };
        let attempt = match self.marks.erasure_attempt(identity).await {
            Ok(attempt) => attempt,
            Err(MarkStoreError::InvalidIdentity) => None,
            Err(_) => {
                mark = MarkInput::StoreUnreadable;
                None
            }
        };
        MarkInputs {
            mark,
            erasure_at_ms,
            erasure: attempt.map_or(ErasureCheck::Clear, ErasureCheck::Pending),
        }
    }

    /// Judge `identity`'s `account` with its mark, the erasure's record and the retirements
    /// (Switch wire 7.3, Table 1), read now. Only under the account's lock, where no commit
    /// moves the state meanwhile.
    pub(super) async fn judge(&self, identity: &str, account: Option<Account>) -> Judged {
        let inputs = self.mark_inputs(identity).await;
        self.judge_with(identity, account, inputs).await
    }

    /// Judge `identity`'s `account` with `inputs`, read before the account was (Switch wire
    /// 7.3, Table 1). Read the selected retirement once its generation is known. A stub
    /// or retirement that can't be read is a store that can't be read: the verdict
    /// is unknown.
    pub(super) async fn judge_with(
        &self,
        identity: &str,
        account: Option<Account>,
        inputs: MarkInputs,
    ) -> Judged {
        let MarkInputs {
            mut mark,
            erasure_at_ms,
            erasure,
        } = inputs;
        // The account read may have waited while deletion committed. Recheck the pending
        // boundary afterwards so that an older "clear" observation proves no absence.
        let current_attempt = self.marks.erasure_attempt(identity).await;
        let clear = match (erasure, current_attempt) {
            (ErasureCheck::Retry(expected), Ok(Some(current))) => current == expected,
            (ErasureCheck::Clear, Ok(None) | Err(MarkStoreError::InvalidIdentity)) => true,
            _ => false,
        };
        if !clear {
            mark = MarkInput::StoreUnreadable;
        }
        // Table 1 reads exactly one retirement, the model's selected generation: no
        // unrelated generation affects this verdict.
        let generation = verdict::retirement_generation(account.as_ref(), &mark, erasure_at_ms);
        let mut retired = None;
        if let Some(generation) = generation {
            match self.marks.is_retired(identity, generation).await {
                Ok(true) => retired = Some(generation),
                Ok(false) | Err(MarkStoreError::InvalidIdentity) => {}
                Err(failure) => {
                    tracing::error!(%failure, "reading the retirement");
                    mark = MarkInput::StoreUnreadable;
                }
            }
        }
        // The stub at the mark's generation and `seq`, where the state is past the mark,
        // whatever the state's generation (Switch wire 7.3 under Table 1).
        let mut stub_at_mark = None;
        let state = account
            .and_then(|account| account.model.state.state())
            .map(|state| (state.generation, state.seq));
        if let MarkInput::Mark(held) = &mark
            && account.is_some_and(|account| account.model.created_at_ms == held.created_at_ms)
            && let Some((generation, seq)) = verdict::stub_for_fork_rule(state, held)
        {
            match self.store.stub_hash_at(identity, generation, seq).await {
                Ok(hash) => stub_at_mark = hash,
                Err(failure) => {
                    tracing::error!(%failure, "reading the stub at the mark");
                    mark = MarkInput::StoreUnreadable;
                }
            }
        }
        let judgement = verdict::judge(&Inputs {
            account: account.as_ref(),
            mark: &mark,
            stub_at_mark,
            erasure_at_ms,
            retired: retired.as_slice(),
            current_key: verdict_key(self),
        });
        Judged {
            judgement,
            mark,
            erasure_at_ms,
            account,
        }
    }

    /// Complete the erasure the identity's current record requires, under its lock, then
    /// delete only a mark the record covers (Switch wire 7.3, Tables 1 and 3).
    ///
    /// # Errors
    ///
    /// `503` when the erasure doesn't commit: nothing is served for the account, and the
    /// next request tries again.
    pub(super) async fn erase_again(&self, identity: &str) -> Result<(), ApiError> {
        if !self.erase_restored(identity).await {
            return Err(ApiError::unavailable("7.6: a temporary failure"));
        }
        Ok(())
    }

    /// Delete `identity`'s mark where it is an erasure's leftover: one created at or before
    /// the erasure's record at `erased_at_ms`, with no account (Switch wire 7.3, Table 1),
    /// under the identity's lock, so no enrollment creates the account meanwhile. Whether no
    /// leftover is left: `false` when the lock, the account or the mark store can't be read,
    /// or the deletion failed.
    pub(super) async fn delete_leftover(&self, identity: &str, erased_at_ms: u64) -> bool {
        let mut lock = match self.store.lock_identity(identity).await {
            Ok(lock) => lock,
            Err(failure) => {
                let _ = super::store_error(&failure);
                return false;
            }
        };
        match lock.has_account().await {
            // A later account's: its mark stays.
            Ok(true) => return true,
            Ok(false) => {}
            Err(failure) => {
                let _ = super::store_error(&failure);
                return false;
            }
        }
        match self.marks.delete_created_by(identity, erased_at_ms).await {
            Ok(_) => true,
            Err(failure) => {
                tracing::warn!(%failure, "deleting an erasure's leftover mark");
                false
            }
        }
    }

    /// Judge `identity` at step 2 from its lookup (Switch wire 7.3): an account that the
    /// first row of Table 1 erases again is erased here, and the identity judged without it;
    /// a leftover mark is deleted.
    ///
    /// # Errors
    ///
    /// `503` when the account can't be looked up or erased again.
    pub(super) async fn judge_at_step_two(
        &self,
        identity: &str,
    ) -> Result<(Option<crate::store::FoundAccount>, Judged), ApiError> {
        let reconciled = self.reconcile_erasure(identity).await;
        let mut inputs = self.mark_inputs(identity).await;
        if reconciled.is_err() {
            // Keep the account lookup and its committed time while refusing unresolved
            // authority through the same verdict as every unreadable mark store.
            inputs.mark = MarkInput::StoreUnreadable;
        }
        let found = self
            .store
            .lookup(identity)
            .await
            .map_err(|error| super::store_error(&error))?;
        let account = found.as_ref().map(|found| self.found_input(found));
        let mut judged = self.judge_with(identity, account, inputs).await;
        let mut found = found;
        if judged.judgement.decision.erase_account_again {
            self.erase_again(identity).await?;
            // Gone now, or a later account made meanwhile.
            let inputs = self.mark_inputs(identity).await;
            found = self
                .store
                .lookup(identity)
                .await
                .map_err(|error| super::store_error(&error))?;
            let account = found.as_ref().map(|found| self.found_input(found));
            judged = self.judge_with(identity, account, inputs).await;
        }
        if let (verdict::Verdict::NotHosted { delete_mark: true }, Some(erased_at_ms)) =
            (judged.judgement.decision.verdict, judged.erasure_at_ms)
        {
            let _ = self.delete_leftover(identity, erased_at_ms).await;
        }
        Ok((found, judged))
    }

    /// Judge again after a request loses its account or observes an erasure while waiting.
    /// An erasure's intent alone confirms no absence: finish it first, then judge the
    /// remaining mark. If an account can serve again, a fresh request must repeat its
    /// checks against that account (Switch wire 7.3, Tables 1 and 2).
    pub(super) async fn answer_after_account_change(
        &self,
        identity: &str,
        class: &RequestClass,
        asked: Asked<'_>,
        base_ms: u64,
        committed_ms: Option<u64>,
        bound_signer: Option<&SwitchRequest>,
    ) -> SwitchResponse {
        let failed_at = committed_ms.map_or(
            AnswerTime::TimeBase(base_ms, Uncompared::Unavailable),
            AnswerTime::Account,
        );
        let (found, judged) = match self.judge_at_step_two(identity).await {
            Ok(judged) => judged,
            Err(error) => return self.service_error(asked, failed_at, &error),
        };
        if let Some(request) = bound_signer {
            // Cleanup may leave a different lifetime's mark. The authenticated request
            // still names its original creation (Switch account binding 1).
            return self
                .signer_notice_under_lock(identity, request, class, asked, base_ms)
                .await;
        }
        let routed = verdict::answer(&judged.judgement, class, self.current_key());
        let committed_ms = found.as_ref().map(|found| found.stamped_time_ms);
        self.verdict_answer(identity, &routed, asked, base_ms, committed_ms)
            .unwrap_or_else(|| {
                self.keyed_error(
                    &routed.key,
                    asked,
                    committed_ms.map_or(failed_at, AnswerTime::Account),
                    &ApiError::unavailable("7.6: the account changed; repeat the request"),
                )
            })
    }

    /// The answer of step 2 or of the judgement under the lock that replaces every other:
    /// the not-hosted `404`, the `503` of an unknown verdict, or the notice, each signed with
    /// the verdict's key, without a head (Switch wire 7.1, 7.3); `None` for a request that
    /// goes on. The notice and the `404`, which count in no comparison of service times, are
    /// signed at the time base `base_ms`; the `503`, which commits nothing, at the last time
    /// the service committed for the identity, `committed_ms`, or at the time base for an
    /// identity without an account, since it counts in no comparison either (Switch wire 7.1
    /// Timestamp).
    pub(super) fn verdict_answer(
        &self,
        identity: &str,
        answer: &verdict::Answer,
        asked: Asked<'_>,
        base_ms: u64,
        committed_ms: Option<u64>,
    ) -> Option<SwitchResponse> {
        let (error, at) = match answer.route {
            Route::NotHosted => (
                not_hosted(),
                AnswerTime::TimeBase(base_ms, Uncompared::NotHosted),
            ),
            Route::Unavailable => (
                ApiError::unavailable("7.3: the mark store can't be read"),
                committed_ms.map_or(
                    AnswerTime::TimeBase(base_ms, Uncompared::Unavailable),
                    AnswerTime::Account,
                ),
            ),
            Route::Notice(notice) => (
                self.notice(identity, notice),
                AnswerTime::TimeBase(base_ms, Uncompared::Notice),
            ),
            Route::CreateAccount
            | Route::TakeOverMark
            | Route::Proceed { .. }
            | Route::StartAfresh
            | Route::Conflict
            | Route::JudgeActivation
            | Route::Erase { .. }
            | Route::EraseLost => return None,
        };
        Some(self.keyed_error(&answer.key, asked, at, &error))
    }

    /// The notice `503 recovery_required` (Switch wire 7.6), counted and logged at its one
    /// place: each means that state the service signed for was lost, or the account is
    /// bounded by its mark (Switch spec 6.5).
    pub(super) fn notice(&self, identity: &str, notice: RecoveryNotice) -> ApiError {
        self.note_mark_refusal(identity, notice.reason);
        ApiError::new(
            ErrorCode::RecoveryRequired,
            "7.3: the account awaits the start of a new generation",
        )
        .with_current(notice.to_current())
    }

    /// Note a notice to `account`, by its reason: counted for an alert, and logged with the
    /// account, once for each account while the process runs; `pubky-switch check-marks`
    /// lists them all.
    fn note_mark_refusal(&self, account: &str, reason: NoticeReason) {
        let reason = reason_label(reason);
        metrics::counter!("pubky_switch_mark_refusals_total", "reason" => reason).increment(1);
        self.mark_refusals
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut logged = self.mark_refused_accounts.lock();
        if logged.contains(account) {
            return;
        }
        if logged.len() >= MARK_REFUSALS_LOGGED {
            if !self
                .mark_refusals_overflowed
                .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                tracing::error!(
                    alert = "behind_mark",
                    "more accounts answer the recovery notice than this process logs: \
                     check-marks lists them all"
                );
            }
            return;
        }
        logged.insert(account.to_string());
        tracing::error!(
            alert = "behind_mark",
            account,
            reason,
            "the account answers the recovery notice: state signed for it was lost, or its \
             mark bounds it, until its signer starts a new generation"
        );
    }

    /// Move the mark of `identity`'s account created at `created_at_ms` to `tip`, answered
    /// with `key`, once the commit that holds it is durable (Switch wire 7.3, "Moving it").
    /// A mark a later move overtook stays. Where the mark is lost, a delivery that starts a
    /// generation (`starts_generation`) writes it anew with the account's creation time
    /// (Table 3); any other move finds no mark and fails.
    ///
    /// The move runs after the commit, outside the identity's lock: the account may have
    /// been erased, and another enrolled, meanwhile. A mark of another creation time is the
    /// other account's and stays, and a mark is written anew only under the identity's lock
    /// while the account is still there; either way the move answers
    /// [`MarkMove::AccountGone`], and nothing signed for the commit is released.
    pub(super) async fn move_mark(
        &self,
        identity: &str,
        tip: ChainTip,
        key: [u8; 32],
        created_at_ms: u64,
        starts_generation: bool,
    ) -> MarkMove {
        #[cfg(any(test, feature = "test-util"))]
        self.wait_before_mark_move().await;
        for _ in 0..2 {
            match self.marks.advance(identity, tip, key, created_at_ms).await {
                Ok(Advance::Moved(_) | Advance::Unchanged(_) | Advance::Overtaken(_)) => {
                    return MarkMove::Done;
                }
                Ok(Advance::Fork(_)) => {
                    tracing::error!("a mark at the head's pair with another chain hash");
                    return MarkMove::Failed;
                }
                Ok(Advance::OtherAccount(_)) => return account_gone(),
                Ok(Advance::NoMark(_)) => {
                    if !starts_generation {
                        let same_account = match self.store.lock_identity(identity).await {
                            Ok(mut lock) => lock
                                .account_created_at()
                                .await
                                .map(|created| created == Some(created_at_ms)),
                            Err(error) => Err(error),
                        };
                        return match same_account {
                            Ok(false) => account_gone(),
                            Ok(true) | Err(_) => MarkMove::Failed,
                        };
                    }
                    match self.write_anew(identity, tip, key, created_at_ms).await {
                        Some(MarkWrite::Written(_)) => return MarkMove::Done,
                        // Written meanwhile: moved, or told another account's, by the next
                        // turn.
                        Some(MarkWrite::Unchanged(MarkRead::Mark(_))) => {}
                        Some(MarkWrite::Unchanged(_)) => return account_gone(),
                        None => return MarkMove::Failed,
                    }
                }
                Err(failure) => {
                    tracing::error!(%failure, "moving a mark");
                    return MarkMove::Failed;
                }
            }
        }
        MarkMove::Failed
    }

    /// Bind the committed recovery to the same SQL lifetime, store and exact older mark
    /// read before it committed (Switch account binding 3.2).
    pub(super) async fn recover_older_mark(
        &self,
        identity: &str,
        tip: ChainTip,
        key: [u8; 32],
        created_at_ms: u64,
        old: AccountMark,
        store_id: [u8; 16],
    ) -> MarkMove {
        #[cfg(any(test, feature = "test-util"))]
        self.wait_before_mark_move().await;
        let Ok(mut lock) = self.store.lock_identity(identity).await else {
            return MarkMove::Failed;
        };
        match lock.account_created_at().await {
            Ok(Some(created)) if created == created_at_ms => {}
            Ok(_) => return account_gone(),
            Err(_) => return MarkMove::Failed,
        }
        match self
            .marks
            .recover_older(identity, old, store_id, tip, key, created_at_ms)
            .await
        {
            Ok(MarkWrite::Written(_)) => MarkMove::Done,
            Ok(MarkWrite::Unchanged(_)) | Err(_) => MarkMove::Failed,
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    async fn wait_before_mark_move(&self) {
        let pause = self.mark_move_pause.lock().take();
        if let Some(pause) = pause {
            pause.wait().await;
        }
    }

    /// Write `identity`'s lost mark anew at `tip` under the identity's lock, only while its
    /// account is the one created at `created_at_ms`: an account erased meanwhile gets no
    /// mark, which would be a leftover, nor does a later one get this account's
    /// (Switch wire 7.3, Table 3). `Unchanged(Missing)` for an account gone; `None` when the
    /// lock, the account or the store can't be read, or the write failed.
    async fn write_anew(
        &self,
        identity: &str,
        tip: ChainTip,
        key: [u8; 32],
        created_at_ms: u64,
    ) -> Option<MarkWrite> {
        let mut lock = match self.store.lock_identity(identity).await {
            Ok(lock) => lock,
            Err(failure) => {
                let _ = super::store_error(&failure);
                return None;
            }
        };
        match lock.account_created_at().await {
            Ok(Some(at_ms)) if at_ms == created_at_ms => {}
            Ok(_) => return Some(MarkWrite::Unchanged(MarkRead::Missing)),
            Err(failure) => {
                let _ = super::store_error(&failure);
                return None;
            }
        }
        let written = self
            .marks
            .write_anew(identity, tip, key, created_at_ms)
            .await;
        drop(lock);
        match written {
            Ok(written) => Some(written),
            Err(failure) => {
                tracing::error!(%failure, "writing a mark anew");
                None
            }
        }
    }

    /// Whether the instance lock was confirmed recently enough for a commit that gives out a
    /// `seq`, signs a head or moves a mark: always, where the service holds no lock.
    pub(super) fn lock_is_fresh(&self) -> bool {
        self.lock_freshness
            .as_ref()
            .is_none_or(crate::store::LockFreshness::is_fresh)
    }
}

/// A request pause for tests of a concurrent account transition.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Debug, Default)]
pub struct RequestPause {
    reached: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(any(test, feature = "test-util"))]
impl RequestPause {
    pub(super) async fn wait(&self) {
        self.reached.notify_one();
        self.release.notified().await;
    }

    /// Wait until the request reaches the pause.
    pub async fn reached(&self) {
        self.reached.notified().await;
    }

    /// Let the paused request go on.
    pub fn release(&self) {
        self.release.notify_one();
    }
}

/// The outcome of [`Service::move_mark`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MarkMove {
    /// The mark is at the head, or past it, durably.
    Done,
    /// The mark didn't move: the request answers `503`, and its retry is answered as a
    /// retry.
    Failed,
    /// The account the move is for is gone: erased since its commit, perhaps with another
    /// enrolled, whose mark stays. The request answers `503`, and nothing signed for the
    /// commit is released.
    AccountGone,
}

/// A move for an account erased since its commit, logged.
fn account_gone() -> MarkMove {
    tracing::warn!("an account erased before its mark moved: its answer is withheld");
    MarkMove::AccountGone
}

/// The service's current key, as the verdict takes it.
fn verdict_key(service: &Service) -> [u8; 32] {
    use pubky_switch_core::signing::Signs;
    service.keys.current().public_key()
}

/// The label a notice's reason is counted under.
pub(super) fn reason_label(reason: NoticeReason) -> &'static str {
    match reason {
        NoticeReason::Behind => "behind",
        NoticeReason::Fork => "fork",
        NoticeReason::MarkLost => "mark_lost",
    }
}
