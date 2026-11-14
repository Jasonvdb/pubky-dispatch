//! The verdict of an account and its mark on the request path (Switch wire 7.3 steps 2 and
//! 10, "Accounts and marks", Tables 1 to 3; Switch spec 6.5).
//!
//! Every request reads the identity's account, its mark, the erasure's record and the
//! retirements, and [`verdict::judge`] gives the verdict: at step 2, from the lookup before
//! the account's lock, and again under the lock before the endpoint, since the state may have
//! changed while the request waited. [`verdict::answer`] gives what the request gets and the
//! key it is signed with. The notice, the not-hosted `404` and the `503` of an unknown verdict
//! are answered in place of whatever later steps would answer. Nothing else in the service
//! compares a state with its mark.

use pubky_switch_core::{
    chain::ChainTip,
    http::{IdentityDelivery, NoticeReason, RecoveryNotice, not_hosted_current},
    records::IdentityBody,
    sig::SignedDoc,
};

use super::{
    Service,
    signed::Asked,
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
    retired: Vec<u64>,
    erasure_at_ms: Option<u64>,
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

    /// The account's creation time, which its enrollment answer names and an erasure names
    /// again (Switch wire 3.7, 7.4.16): the mark's, or the account's own where the mark is
    /// lost.
    pub(super) fn created_at_ms(&self) -> Option<u64> {
        self.mark()
            .map(|mark| mark.created_at_ms)
            .or(self.account.map(|account| account.created_at_ms))
    }

    /// Whether the account answers the notice: it fails stop or is bounded (Table 2).
    pub(super) fn answers_notice(&self) -> bool {
        matches!(
            self.judgement.verdict,
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
    ) -> Account {
        Account::judged(
            &self.origin,
            |key| self.keys.signer_for(key).is_some(),
            generation,
            chain,
            created_at_ms,
            doc,
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
        )
    }

    /// Read `identity`'s mark, the erasure's record and the retirements, before the state
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
        let retired = match self.marks.retired(identity).await {
            Ok(retired) => retired,
            Err(MarkStoreError::InvalidIdentity) => Vec::new(),
            Err(failure) => {
                tracing::error!(%failure, "reading the retirements");
                mark = MarkInput::StoreUnreadable;
                Vec::new()
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
        MarkInputs {
            mark,
            retired,
            erasure_at_ms,
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
    /// 7.3, Table 1). A stub that can't be read is a store that can't be read: the verdict
    /// is unknown.
    pub(super) async fn judge_with(
        &self,
        identity: &str,
        account: Option<Account>,
        inputs: MarkInputs,
    ) -> Judged {
        let MarkInputs {
            mut mark,
            retired,
            erasure_at_ms,
        } = inputs;
        // The stub at the mark's generation and `seq`, where the state is past the mark,
        // whatever the state's generation (Switch wire 7.3 under Table 1).
        let mut stub_at_mark = None;
        let state = account
            .and_then(|account| account.state.state())
            .map(|state| (state.generation, state.seq));
        if let MarkInput::Mark(held) = &mark
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
            retired: &retired,
            current_key: verdict_key(self),
        });
        Judged {
            judgement,
            mark,
            erasure_at_ms,
            account,
        }
    }

    /// Erase again `identity`'s account, created at or before the erasure's record at
    /// `erased_at_ms` (Switch wire 7.3, Table 1 first row), under the identity's lock: the
    /// record again, durably, then the account's deletion; then only a mark created at or
    /// before the record goes, and a later account's mark stays (Table 3).
    ///
    /// # Errors
    ///
    /// `503` when the erasure doesn't commit: nothing is served for the account, and the
    /// next request tries again.
    pub(super) async fn erase_again(
        &self,
        identity: &str,
        erased_at_ms: u64,
    ) -> Result<(), ApiError> {
        if !self.erase_restored(identity, erased_at_ms).await {
            return Err(ApiError::unavailable("7.6: a temporary failure"));
        }
        if let Err(failure) = self.marks.delete_created_by(identity, erased_at_ms).await {
            // Left as an erasure's leftover, deleted at a later request or at start.
            tracing::warn!(%failure, "deleting an erased account's mark");
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
        let inputs = self.mark_inputs(identity).await;
        let found = self
            .store
            .lookup(identity)
            .await
            .map_err(|error| super::store_error(&error))?;
        let account = found.as_ref().map(|found| self.found_input(found));
        let mut judged = self.judge_with(identity, account, inputs).await;
        let mut found = found;
        if judged.judgement.erase_account_again
            && let Some(erased_at_ms) = judged.erasure_at_ms
        {
            self.erase_again(identity, erased_at_ms).await?;
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
            (judged.judgement.verdict, judged.erasure_at_ms)
        {
            let _ = self.delete_leftover(identity, erased_at_ms).await;
        }
        Ok((found, judged))
    }

    /// The answer of step 2 or of the judgement under the lock that replaces every other:
    /// the not-hosted `404`, the `503` of an unknown verdict, or the notice, each signed with
    /// the verdict's key, without a head (Switch wire 7.1, 7.3); `None` for a request that
    /// goes on. The notice and the `404`, which count in no comparison of service times, are
    /// signed at the time base `base_ms`; the `503`, which commits nothing, at the last time
    /// the service committed for the identity, `committed_ms` (Switch wire 7.1 Timestamp).
    pub(super) fn verdict_answer(
        &self,
        identity: &str,
        answer: &verdict::Answer,
        asked: Asked<'_>,
        base_ms: u64,
        committed_ms: u64,
    ) -> Option<SwitchResponse> {
        let (error, at_ms) = match answer.route {
            Route::NotHosted => (not_hosted(), base_ms),
            Route::Unavailable => (
                ApiError::unavailable("7.3: the mark store can't be read"),
                committed_ms,
            ),
            Route::Notice(notice) => (self.notice(identity, notice), base_ms),
            Route::CreateAccount
            | Route::TakeOverMark
            | Route::Proceed { .. }
            | Route::StartAfresh
            | Route::Conflict
            | Route::JudgeActivation
            | Route::Erase { .. }
            | Route::EraseLost => return None,
        };
        Some(self.keyed_error(&answer.key, asked, at_ms, &error))
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
        {
            let pause = self.mark_move_pause.lock().take();
            if let Some(pause) = pause {
                pause.reached.notify_one();
                pause.release.notified().await;
            }
        }
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
                        tracing::error!("a mark to move is gone");
                        return MarkMove::Failed;
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

/// A pause before a mark move, made by [`Service::pause_next_mark_move`].
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Debug, Default)]
pub struct MarkMovePause {
    reached: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(any(test, feature = "test-util"))]
impl MarkMovePause {
    /// Wait until a mark move reaches the pause, its commit durable.
    pub async fn reached(&self) {
        self.reached.notified().await;
    }

    /// Let the paused move go on.
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
