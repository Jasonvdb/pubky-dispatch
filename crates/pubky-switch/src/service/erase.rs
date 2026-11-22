//! `POST /v1/{id}/erase` (Switch wire 7.4.16, spec 12.7): the signer erases the identity's
//! account at this service.
//!
//! The request passes the signer's checks like every call. Its body `{ "created",
//! "identity_hash" }` names the account's creation time, the one its enrollment answer named,
//! and the account's newest `identity.json`, left out only where the account holds none
//! (`409 conflict` otherwise, carrying the creation time). Then the order is fixed (Switch
//! wire 7.3, Table 3):
//! 1. the authenticated attempt is written to the mark store, durably, dated no earlier
//!    than the creation it erases; it is not completed-erasure authority;
//! 2. the account's row is deleted, and with it every row of its state, its apps' push keys
//!    owed deleting in the same transaction (`erased_keys`), and committed; where the
//!    deletion doesn't commit, durable rejection evidence permits withdrawal and the
//!    answer is `503`. An unknown outcome retains the attempt for a signer retry;
//! 3. a matching committed receipt publishes the completed erasure outside database
//!    backups; then the account's mark is deleted, and the owed push keys;
//! 4. only then is the answer released, signed with the key the verdict gives, without a
//!    head.
//!
//! Steps 1 and 2 run under the identity's lock (`store`, "One identity at a time"), which an
//! enrollment holds from the mark's write through the account's insert, so no account is
//! created between the record and the deletion, and every later account is created after the
//! record. A mark the deletion of step 3 leaves is an erasure's leftover: the record covers
//! it, and a later request for the identity or the next start deletes it. Afterwards every
//! request for the account finds no account: the not-hosted `404`, signed with the service
//! key.
//!
//! **A restored database** (spec 6.5). The mark store, apart from the database's backups,
//! keeps each erasure's record. A database restored from a backup taken before
//! an erasure brings the account back. Such an account, one created at or before the time
//! the mark store holds for its identity, is erased again before anything is served or signed
//! for it (Switch wire 7.3, Table 1, first row): at start, for every identity a record
//! names, and at every request's judgement of the account. An account created after the
//! erasure, by an enrollment since, is a new account: an enrollment creates it later than the
//! time the store holds. The store keeps an erasure's record until every database backup that
//! could hold its account has aged out (`keys.backup_retention_days`), and drops a record
//! only once the leftover marks it covers are gone.

use std::sync::Arc;

use pubky_switch_core::{
    http::{ERASED_BODY, Uncompared, parse_erase_body},
    records::{AccountAssociation, IdentityDoc},
    time::rfc3339,
};
use serde_json::json;

use super::{
    Answer, PreLock, Service,
    marking::{self, Judged},
    signed::{AnswerTime, Asked, sign_answer},
    store_error,
    verdict::{self, Route},
};
use crate::{
    http::{
        SwitchRequest, SwitchResponse,
        error::{ApiError, ErrorCode},
        route::Call,
    },
    keys::{KeyId, KeyStore, ServiceSigner},
    marks::{ErasureAttempt, MarkRead, MarkStore},
    store::{AccountTxn, Store},
};

/// The least time an erasure's record is kept, whatever the backups: a day (Switch wire 7.3,
/// Table 3).
const RECORD_KEPT_AT_LEAST_MS: u64 = 24 * 60 * 60 * 1000;

/// The account creation and held document verified for this erasure (Switch wire 7.4.16).
pub(super) struct Erasure {
    created: u64,
    identity_hash: Option<[u8; 32]>,
}

impl Service {
    /// Erase the account whose lock `txn` holds and sign the answer with `signer`
    /// once the deletion is durable (Switch wire 7.4.16 Order, 7.3 Table 3). `committed_ms`
    /// is the time the account last committed, for the `503` of an erasure that doesn't
    /// commit.
    pub(super) async fn finish_erasure(
        &self,
        txn: AccountTxn,
        signer: &ServiceSigner,
        asked: Asked<'_>,
        committed_ms: u64,
        time_ms: u64,
        erasure: Erasure,
    ) -> SwitchResponse {
        // Dated no earlier than the creation it erases (Switch wire 7.3, Table 3).
        let Erasure {
            created: created_at_ms,
            identity_hash,
        } = erasure;
        let record_at = time_ms.max(created_at_ms);
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        let account = txn.head().id.clone();
        // The erasure moves a mark: not while another process may hold the database.
        if !self.lock_is_fresh() {
            drop(txn);
            return Self::signed_error(
                signer,
                asked,
                AnswerTime::Account(committed_ms),
                &unavailable(),
            );
        }
        let attempt = match ErasureAttempt::new(created_at_ms, record_at, identity_hash) {
            Ok(attempt) => attempt,
            Err(_) => {
                return Self::signed_error(
                    signer,
                    asked,
                    AnswerTime::Account(committed_ms),
                    &unavailable(),
                );
            }
        };
        #[cfg(any(test, feature = "test-util"))]
        if let Some(outcome) = self.erasure_faults.take() {
            if let Err(failure) = self.marks.begin_erasure(&account, attempt.clone()).await {
                tracing::error!(%failure, "recording an erasure attempt");
                return Self::signed_error(
                    signer,
                    asked,
                    AnswerTime::Account(committed_ms),
                    &unavailable(),
                );
            }
            if let Err(failure) = self.retain_erasure_outcome(txn, attempt, outcome).await {
                tracing::error!(%failure, "retaining an erasure outcome");
            }
            return Self::signed_error(
                signer,
                asked,
                AnswerTime::Account(committed_ms),
                &unavailable(),
            );
        }
        let (store, keys, marks, identity, freshness) = (
            self.store.clone(),
            self.keys.clone(),
            self.marks.clone(),
            account.clone(),
            self.lock_freshness.clone(),
        );
        #[cfg(any(test, feature = "test-util"))]
        let pause = self.erase_failure_pause.lock().take();
        #[cfg(any(test, feature = "test-util"))]
        let recorded_pause = self.erase_attempt_pause.lock().take();
        // The attempt is recorded on the same task as the deletion it announces: a request
        // cut after the record and before the deletion would leave the attempt with no
        // outcome, and the identity answering `503` until its signer erased again.
        let erased = to_the_end(async move {
            if let Err(failure) = marks.begin_erasure(&identity, attempt.clone()).await {
                drop(txn);
                return Err(format!("recording an erasure attempt: {failure}"));
            }
            #[cfg(any(test, feature = "test-util"))]
            if let Some(pause) = recorded_pause {
                pause.wait().await;
            }
            if let Err(failure) = txn.erase_recorded(&attempt, freshness.as_ref()).await {
                let (error, account) = failure.into_parts();
                let fresh = || {
                    freshness
                        .as_ref()
                        .is_none_or(crate::store::LockFreshness::is_fresh)
                };
                // A successful rollback or definitive COMMIT rejection proves non-application.
                // Its receipt must itself commit before cleanup can release the account.
                let rejected = account.is_some() || error.is_refused();
                // Discard the entire failed request, including work before the deletion's
                // savepoint. Only the outcome receipt belongs in the new transaction.
                drop(account);
                let rejected = if rejected && fresh() {
                    match store.lock_identity(&identity).await {
                        Ok(mut lock) if fresh() => {
                            if marks
                                .erasure_attempt(&identity)
                                .await
                                .ok()
                                .flatten()
                                .as_ref()
                                != Some(&attempt)
                            {
                                false
                            } else {
                                match lock.erasure_outcome(&attempt).await {
                                    Ok(Some(true)) => false,
                                    Ok(_) if fresh() => lock
                                        .reject_erasure(&attempt, freshness.as_ref())
                                        .await
                                        .is_ok(),
                                    _ => false,
                                }
                            }
                        }
                        _ => false,
                    }
                } else {
                    false
                };
                let cleanup_lock = if rejected {
                    store.lock_identity(&identity).await.ok()
                } else {
                    None
                };
                #[cfg(any(test, feature = "test-util"))]
                if let Some(pause) = pause {
                    pause.wait().await;
                }
                if let Some(lock) = cleanup_lock {
                    match marks.clear_erasure_attempt(&identity, attempt).await {
                        Ok(()) => forget_outcome(lock, freshness.as_ref()).await,
                        Err(failure) => tracing::error!(%failure, "taking back an erasure attempt"),
                    }
                }
                return Err(error.to_string());
            }
            // Reacquire after COMMIT: a concurrent request may already have completed the
            // same receipt, but no request can turn an unresolved attempt into deletion.
            let mut lock = store
                .lock_identity(&identity)
                .await
                .map_err(|error| error.to_string())?;
            let pending = marks
                .erasure_attempt(&identity)
                .await
                .map_err(|error| error.to_string())?;
            if pending.as_ref() == Some(&attempt) {
                if lock
                    .erasure_outcome(&attempt)
                    .await
                    .map_err(|error| error.to_string())?
                    != Some(true)
                {
                    return Err("the deletion outcome is unresolved".to_string());
                }
                publish_outcome(&marks, &identity, attempt, true).await?;
            } else if marks
                .erasure(&identity)
                .await
                .map_err(|error| error.to_string())?
                .is_none_or(|at| at < record_at)
            {
                return Err("the erasure has no completed record".to_string());
            }
            if marks
                .erasure_attempt(&identity)
                .await
                .map_err(|error| error.to_string())?
                .is_none()
            {
                forget_outcome(lock, freshness.as_ref()).await;
            }
            let _ = sweep_owed(store, keys, marks).await;
            Ok::<_, String>(())
        })
        .await;
        if !matches!(erased, Some(Ok(()))) {
            if let Some(Err(failure)) = &erased {
                tracing::error!(%failure, "an erasure");
            }
            return Self::signed_error(
                signer,
                asked,
                AnswerTime::Account(committed_ms),
                &unavailable(),
            );
        }
        // Then the mark: only one the record covers, never a later account's.
        if let Err(failure) = self.marks.delete_created_by(&account, record_at).await {
            tracing::warn!(%failure, "deleting an erased account's mark");
        }
        self.forget_account(&account);
        self.forget_aged_erasures().await;
        sign_answer(
            signer,
            asked,
            AnswerTime::Account(time_ms),
            Answer::ok(ERASED_BODY.to_vec()),
        )
    }

    /// Publish only an established outcome, under the identity lock. Absence alone says
    /// nothing about a pending attempt after a restore or an unknown COMMIT answer.
    pub(super) async fn reconcile_erasure(&self, identity: &str) -> Result<bool, ApiError> {
        let unavailable = || ApiError::unavailable("7.6: an erasure outcome is unresolved");
        if self
            .marks
            .erasure_attempt(identity)
            .await
            .map_err(|_| unavailable())?
            .is_none()
        {
            return Ok(true);
        }
        let mut lock = self
            .store
            .lock_identity(identity)
            .await
            .map_err(|error| store_error(&error))?;
        let Some(attempt) = self
            .marks
            .erasure_attempt(identity)
            .await
            .map_err(|_| unavailable())?
        else {
            return Ok(true);
        };
        // A completed external record survives losing the database receipt to a restore.
        let completed = self
            .marks
            .erasure(identity)
            .await
            .map_err(|_| unavailable())?
            .is_some_and(|at| at >= attempt.created_at_ms);
        let outcome = if completed {
            Some(true)
        } else {
            lock.erasure_outcome(&attempt)
                .await
                .map_err(|error| store_error(&error))?
        };
        if let Some(committed) = outcome {
            publish_outcome(&self.marks, identity, attempt, committed)
                .await
                .map_err(|_| unavailable())?;
            forget_outcome(lock, self.lock_freshness.as_ref()).await;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// A fresh signer may resolve an unknown attempt by authorizing deletion again.
    /// Its current creation and document binding are checked under the identity lock;
    /// an ordinary read never exercises this authority (wire 7.4.16).
    pub(super) async fn retry_erasure(
        &self,
        identity: &str,
        request: &SwitchRequest,
        base_ms: u64,
        asked: Asked<'_>,
    ) -> SwitchResponse {
        let at = AnswerTime::TimeBase(base_ms, Uncompared::Erasure);
        let unavailable = || ApiError::unavailable("7.6: an erasure outcome is unresolved");
        let refuse = |error: ApiError| self.service_error(asked, at, &error);
        // The mark before the account, as every reader before the lock reads them
        // (`committed_time_ms`).
        let mark_floor_ms = match self.marks.read(identity).await {
            Ok(crate::marks::MarkRead::Mark(mark)) => Some(mark.time_floor_ms),
            _ => None,
        };
        let found = match self.store.lookup(identity).await {
            Ok(found) => found,
            Err(error) => return refuse(store_error(&error)),
        };
        let service_ms = found.as_ref().map_or(base_ms, |found| {
            base_ms.max(found.committed_ms(self.run, mark_floor_ms))
        });
        let pre = match self.pre_lock(identity, request, base_ms, service_ms).await {
            Ok(pre) => pre,
            Err(error) => return refuse(error),
        };
        if !pre
            .caller
            .is_some_and(|caller| caller.caller == super::rules::Caller::Signer)
        {
            return refuse(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.16: only the signer erases",
            ));
        }
        let mut lock = match self.store.lock_identity(identity).await {
            Ok(lock) => lock,
            Err(error) => return refuse(store_error(&error)),
        };
        let attempt = match self.marks.erasure_attempt(identity).await {
            Ok(Some(attempt)) => attempt,
            _ => return refuse(unavailable()),
        };
        let inputs = match self.mark_inputs(identity).await.for_erasure(&attempt) {
            Ok(inputs) => inputs,
            Err(error) => return refuse(error),
        };
        let created = match lock.account_created_at().await {
            Ok(created) => created,
            Err(error) => return refuse(store_error(&error)),
        };
        if created.is_some() {
            let mut txn = match lock.account().await {
                Ok(Some(txn)) => txn,
                Ok(None) => return refuse(unavailable()),
                Err(error) => return refuse(store_error(&error)),
            };
            let held = match txn.held_identity().await {
                Ok(Some(held)) => match IdentityDoc::verify(&held.doc, &txn.head().identity_key) {
                    Ok(doc) => Some(doc),
                    Err(_) => return refuse(unavailable()),
                },
                Ok(None) => None,
                Err(error) => return refuse(store_error(&error)),
            };
            let head = txn.head().clone();
            let account = self.account_input(
                head.generation,
                head.chain,
                head.count(),
                head.created_at_ms,
                held.as_ref().map(IdentityDoc::body),
                head.activation,
            );
            let judged = self
                .judge_with(txn.conn(), identity, Some(account), inputs)
                .await;
            let routed = verdict::answer(
                &judged.judgement,
                &verdict::RequestClass::Erase,
                self.current_key(),
            );
            if !matches!(routed.route, Route::Erase { .. } | Route::EraseLost)
                || judged.judgement.decision.erase_account_again
            {
                return refuse(unavailable());
            }
            let Some(signer) = self.signer_of(&routed.key) else {
                return refuse(unavailable());
            };
            let erasure = match erasure_binding(request, held.as_ref(), &judged) {
                Ok(erasure) => erasure,
                Err(error) => return Self::signed_error(&signer, asked, at, &error),
            };
            // Step 3 as for every request, so the erasure's answer shows no time before one
            // shown for the identity, and the floor rises past it (Switch wire 7.3,
            // "Trusted time").
            let committed_ms = head.committed_ms(self.run, judged.time_floor_ms());
            let time_ms = match self
                .stamp_under_lock(&mut txn, base_ms, judged.mark())
                .await
            {
                Ok(time_ms) => time_ms,
                Err(error) => return Self::signed_error(&signer, asked, at, &error),
            };
            return self
                .finish_erasure(txn, &signer, asked, committed_ms, time_ms, erasure)
                .await;
        }
        // This is new authenticated authorization at an absent account, not an inference
        // about whether the earlier attempt committed. Preserve its exact binding.
        let named = match parse_erase_body(&request.body) {
            Ok(named) => named,
            Err(error) => return refuse(ApiError::bad_request(error.to_string())),
        };
        if named.created != Some(attempt.created_at_ms)
            || named.identity_hash != attempt.identity_hash
        {
            return refuse(
                ApiError::new(
                    ErrorCode::Conflict,
                    "7.4.16: the erasure names another account or document",
                )
                .with_current(
                    json!({ "created": rfc3339(attempt.created_at_ms), "identity": null }),
                ),
            );
        }
        let judged = self.judge_with(lock.conn(), identity, None, inputs).await;
        if matches!(judged.judgement.decision.verdict, verdict::Verdict::Unknown) {
            return refuse(unavailable());
        }
        let current_created = match judged.created_at_ms() {
            Ok(created) => created,
            Err(error) => return refuse(error),
        };
        if current_created.is_some_and(|created| created != attempt.created_at_ms) {
            return refuse(
                ApiError::new(
                    ErrorCode::Conflict,
                    "7.4.16: the account was created at another time",
                )
                .with_current(json!({ "created": current_created.map(rfc3339) })),
            );
        }
        let routed = verdict::answer(
            &judged.judgement,
            &verdict::RequestClass::Erase,
            self.current_key(),
        );
        let Some(signer) = self.signer_of(&routed.key) else {
            return refuse(unavailable());
        };
        let renewed = match ErasureAttempt::new(
            attempt.created_at_ms,
            base_ms.max(attempt.erased_at_ms),
            attempt.identity_hash,
        ) {
            Ok(renewed) => renewed,
            Err(_) => return refuse(unavailable()),
        };
        if self
            .marks
            .begin_erasure(identity, renewed.clone())
            .await
            .is_err()
            || publish_outcome(&self.marks, identity, renewed.clone(), true)
                .await
                .is_err()
        {
            return refuse(unavailable());
        }
        let _ = self
            .marks
            .delete_created_by(identity, renewed.erased_at_ms)
            .await;
        forget_outcome(lock, self.lock_freshness.as_ref()).await;
        self.forget_account(identity);
        sign_answer(&signer, asked, at, Answer::ok(ERASED_BODY.to_vec()))
    }

    /// Complete retained receipts and discard only receipts whose external attempt is
    /// durably gone. A failed cleanup is retried at the next startup (wire 7.3 Table 3).
    pub(super) async fn reconcile_erasure_outcomes(&self) {
        let mut after = String::new();
        loop {
            let identities = match self.store.erasure_outcome_ids(&after).await {
                Ok(ids) => ids,
                Err(error) => {
                    let _ = store_error(&error);
                    return;
                }
            };
            if identities.is_empty() {
                return;
            }
            for identity in identities {
                after.clone_from(&identity);
                if !matches!(self.reconcile_erasure(&identity).await, Ok(true)) {
                    continue;
                }
                let Ok(lock) = self.store.lock_identity(&identity).await else {
                    continue;
                };
                if matches!(self.marks.erasure_attempt(&identity).await, Ok(None)) {
                    forget_outcome(lock, self.lock_freshness.as_ref()).await;
                }
            }
        }
    }

    /// The erasure at an identity without an account that the verdict lets through: a lost
    /// one (Switch wire 7.3 Table 2, 7.4.16). After the signer's checks, under the identity's
    /// lock, the identity is judged again, then the record is written and the mark deleted;
    /// the answer is signed with the key in the mark.
    pub(super) async fn erase_without_account(
        &self,
        account: &str,
        request: &SwitchRequest,
        routed: &verdict::Answer,
        base_ms: u64,
        asked: Asked<'_>,
    ) -> SwitchResponse {
        // No account's state is shown by an answer to an erasure: each counts in no
        // comparison of service times and carries the time base (Switch wire 7.1 Timestamp).
        let at = AnswerTime::TimeBase(base_ms, Uncompared::Erasure);
        let refuse = |error: ApiError| self.keyed_error(&routed.key, asked, at, &error);
        if request.route.call != Call::Erase {
            let at = AnswerTime::TimeBase(base_ms, Uncompared::NotHosted);
            return self.service_error(asked, at, &marking::not_hosted());
        }
        let PreLock { caller, .. } = match self.pre_lock(account, request, base_ms, base_ms).await {
            Ok(pre) => pre,
            Err(error) => return refuse(error),
        };
        if !caller.is_some_and(|claimed| claimed.caller == super::rules::Caller::Signer) {
            return refuse(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.16: only the signer erases",
            ));
        }
        if routed.route != Route::EraseLost {
            return self.service_error(asked, at, &marking::not_hosted());
        }
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        // No enrollment creates or takes over the account while the erasure holds the
        // identity's lock: what it judges is what it erases.
        let mut lock = match self.store.lock_identity(account).await {
            Ok(lock) => lock,
            Err(error) => return refuse(store_error(&error)),
        };
        match lock.has_account().await {
            Ok(false) => {}
            // An account made meanwhile: the retry is judged at it.
            Ok(true) => return refuse(unavailable()),
            Err(error) => return refuse(store_error(&error)),
        }
        let inputs = self.mark_inputs(account).await;
        let judged = self.judge_with(lock.conn(), account, None, inputs).await;
        let routed = verdict::answer(
            &judged.judgement,
            &verdict::RequestClass::Erase,
            self.current_key(),
        );
        match routed.route {
            Route::EraseLost => {}
            Route::NotHosted => return self.service_error(asked, at, &marking::not_hosted()),
            _ => return refuse(unavailable()),
        }
        let created = match erasure_binding(request, None, &judged) {
            Ok(erasure) => erasure.created,
            Err(error) => return refuse(error),
        };
        // Dated no earlier than the creation it erases (Switch wire 7.3, Table 3).
        let at_ms = base_ms.max(created);
        if let Err(failure) = self.marks.record_erasure(account, at_ms).await {
            tracing::error!(%failure, "recording an erasure");
            return refuse(unavailable());
        }
        // A mark left here is a leftover the record covers, deleted later.
        if let Err(failure) = self.marks.delete_created_by(account, at_ms).await {
            tracing::warn!(%failure, "deleting an erased identity's mark");
        }
        drop(lock);
        self.forget_account(account);
        let Some(signer) = self.signer_of(&routed.key) else {
            return self.service_error(asked, at, &unavailable());
        };
        sign_answer(&signer, asked, at, Answer::ok(ERASED_BODY.to_vec()))
    }

    /// Delete every push key still owed deleting, and drop what is done (Switch wire 8.1).
    /// Each row is locked while its key goes, so a start claiming the key it minted waits,
    /// then finds it gone (`store::push`). A failure leaves the key owed for the next sweep:
    /// at the next erasure, and at start. Run at start by the service's binary. The sweep
    /// runs to its end in a task of its own, so a request dropped meanwhile doesn't stop it.
    ///
    /// Returns the accounts whose keys are still owed; `None` when the owed keys can't be
    /// read.
    pub async fn sweep_erased_keys(&self) -> Option<Vec<String>> {
        to_the_end(sweep_owed(
            self.store.clone(),
            self.keys.clone(),
            self.marks.clone(),
        ))
        .await
        .flatten()
    }

    /// Erase again account `account`, which a restored database brought back after its
    /// erasure (Switch wire 7.3, Table 1 first row), under the identity's lock: read the
    /// record again, since a deletion that failed while this request waited can withdraw
    /// it (Table 3); then, as an erasure does, its state deleted and its push keys owed in
    /// one commit, then the owed keys deleted, with
    /// no answer to sign. Whether the identity holds no such account any more: gone, erased
    /// here, or a new account made since; `false` when the record or the erasure didn't
    /// commit.
    pub(super) async fn erase_restored(&self, account: &str) -> bool {
        let (store, keys, marks, id) = (
            self.store.clone(),
            self.keys.clone(),
            self.marks.clone(),
            account.to_string(),
        );
        // Run to the end in a task of its own, as an erasure is: a request dropped meanwhile
        // can't stop it between the commit and the keys' deletion.
        let erased = to_the_end(async move {
            let lock = match store.lock_identity(&id).await {
                Ok(lock) => lock,
                Err(failure) => return Err(failure.to_string()),
            };
            let erased_at_ms = match marks.erasure(&id).await {
                Ok(Some(at)) => at,
                Ok(None) => return Ok(false),
                Err(failure) => return Err(failure.to_string()),
            };
            if let Err(failure) = marks.record_erasure(&id, erased_at_ms).await {
                return Err(failure.to_string());
            }
            let txn = match lock.account().await {
                Ok(Some(txn)) => txn,
                Ok(None) => {
                    if let Err(failure) = marks.delete_created_by(&id, erased_at_ms).await {
                        tracing::warn!(%failure, "deleting an erased account's mark");
                    }
                    return Ok(false);
                }
                Err(failure) => return Err(failure.to_string()),
            };
            if txn.head().created_at_ms > erased_at_ms {
                return Ok(false);
            }
            txn.erase(erased_at_ms)
                .await
                .map_err(|failure| failure.to_string())?;
            if let Err(failure) = marks.delete_created_by(&id, erased_at_ms).await {
                tracing::warn!(%failure, "deleting an erased account's mark");
            }
            let _ = sweep_owed(store, keys, marks).await;
            Ok(true)
        })
        .await;
        match erased {
            Some(Ok(true)) => {
                // No account ID in the log (Switch wire 9.4).
                tracing::warn!(
                    "erased again an account a restored database brought back after its erasure"
                );
                self.forget_account(account);
                true
            }
            Some(Ok(false)) => true,
            Some(Err(failure)) => {
                tracing::error!(%failure, "erasing again a restored account");
                false
            }
            None => false,
        }
    }

    /// Erase again every account a restored database brought back after its erasure, for
    /// every identity an erasure's record names (Switch wire 7.3, Table 1), deleting the
    /// marks the records cover with them. Run at start, before the service takes requests;
    /// the judgement at each request covers what this misses. The number erased, or `None`
    /// when the records or the accounts can't be read.
    pub async fn erase_restored_accounts(&self) -> Option<usize> {
        let ledger = match self.marks.erasures().await {
            Ok(ledger) => ledger,
            Err(failure) => {
                tracing::error!(%failure, "reading the erasures' records");
                return None;
            }
        };
        if ledger.is_empty() {
            return Some(0);
        }
        let restored = match self.store.restored_erased(&ledger).await {
            Ok(restored) => restored,
            Err(failure) => {
                tracing::error!(%failure, "finding accounts restored after their erasure");
                return None;
            }
        };
        let mut erased = 0;
        for (account, _) in &restored {
            if self.erase_again(account).await.is_ok() {
                erased += 1;
            }
        }
        Some(erased)
    }

    /// Delete the erasures' leftover marks: for each identity an erasure's record names without an
    /// account, a mark created at or before its record (Switch wire 7.3, Table 1). Run at
    /// start; a later request for the identity deletes one this misses.
    pub(super) async fn delete_leftover_marks(&self) {
        let Ok(ledger) = self.marks.erasures().await else {
            return;
        };
        for (identity, erased_at_ms) in ledger {
            let _ = self.delete_leftover(&identity, erased_at_ms).await;
        }
    }

    /// Forget the erasures' records older than `keys.backup_retention_days`, and at least a
    /// day old, whose accounts no kept database backup can hold any more (Switch spec 6.5,
    /// wire 7.3 Table 3), by trusted time only: a
    /// clock ahead would forget an erasure too early. The leftover marks a record covers go
    /// first (Switch wire 7.3, Table 3); a record whose leftover can't be told gone keeps
    /// every record for the next pass. Without the setting, every erasure is kept. Run at
    /// start and after each erasure.
    pub(super) async fn forget_aged_erasures(&self) {
        let Some(retention_ms) = self.backup_retention_ms else {
            return;
        };
        let reading = self.time.read();
        if !reading.trusted {
            return;
        }
        // A record younger than a day stays, whatever the backups (Switch wire 7.3, Table 3).
        let before_ms = reading
            .base_ms
            .saturating_sub(retention_ms.max(RECORD_KEPT_AT_LEAST_MS));
        // It deletes marks and records: not while another process may hold the database.
        if !self.lock_is_fresh() {
            return;
        }
        let Ok(ledger) = self.marks.erasures().await else {
            return;
        };
        for (identity, erased_at_ms) in ledger.iter().filter(|(_, at)| *at < before_ms) {
            if !self.delete_leftover(identity, *erased_at_ms).await {
                return;
            }
        }
        if let Err(failure) = self.marks.forget_erasures_before(before_ms).await {
            tracing::error!(%failure, "forgetting aged erasures");
        }
    }

    /// Forget every count the service keeps for `account` (Switch wire 7.4.16, 9.4).
    fn forget_account(&self, account: &str) {
        self.failed_auth.forget_account(account);
        self.reads_per_source.forget(|(at, _)| at == account);
        self.reads_per_account.forget(|at| at == account);
        self.operation_rate.forget(|(at, _)| at == account);
        self.control_rate.forget(|(at, _)| at == account);
        self.invite_rate.forget(|(at, _)| at == account);
        self.stranger_rate.forget(|at| at == account);
        self.connect_rate.forget(|(at, _)| at == account);
        self.sender_rate.forget(|(at, _)| at == account);
        self.sender_app_rate.forget(|(at, _)| at == account);
        self.upload_rate.forget(|(at, _)| at == account);
        self.notify_rate.forget(|(at, _)| at == account);
    }
}

/// What binds an erasure to the account it erases (Switch wire 7.4.16), in one place: its
/// body `{ "created", "identity_hash" }` names the account's creation time, the one its
/// enrollment answer named (the mark's, or the account's own where the mark is lost), so a
/// replay doesn't reach a later account of the identity; then `held`, the account's newest
/// `identity.json`, by its hash, left out only where the account holds none. At an identity
/// whose account is lost no document is held to compare: the mark's creation time binds it.
/// The verified creation time and document hash for the erasure record.
///
/// # Errors
///
/// `400` for a body that isn't `{ "created": time, "identity_hash": b64(32) }`, both
/// optional in shape, with creation required to agree with the signed header. A creation
/// mismatch uses the common conflict (Switch account binding 1). A different hash, a hash
/// where the account holds no `identity.json`, or none where it holds one is `409 conflict`.
/// For a document conflict at an account that answers the notice, the `409` carries the
/// held copy too, and at a lost identity `identity: null`.
pub(super) fn erasure_binding(
    request: &SwitchRequest,
    held: Option<&IdentityDoc>,
    judged: &Judged,
) -> Result<Erasure, ApiError> {
    let named = parse_erase_body(&request.body)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    super::account::check_creation(request, judged)?;
    let created = judged
        .created_at_ms()?
        .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
    let selected_account = judged
        .account_binding()
        .map_err(|_| ApiError::unavailable("account binding: unknown association"))?
        .association()
        == AccountAssociation::Account;
    let conflict = |why: &'static str| {
        let mut current = json!({ "created": rfc3339(created) });
        if !selected_account {
            current["identity"] = serde_json::Value::Null;
        } else if judged.answers_notice() {
            current["identity"] = json!(held.map(IdentityDoc::signed));
        }
        ApiError::new(ErrorCode::Conflict, why).with_current(current)
    };
    if named.created != Some(created) {
        return Err(conflict("7.4.16: the account was created at another time"));
    }
    let identity_hash = held.filter(|_| selected_account).map(IdentityDoc::hash);
    if selected_account && named.identity_hash != identity_hash {
        return Err(conflict("7.4.16: the account holds another identity.json"));
    }
    Ok(Erasure {
        created,
        identity_hash,
    })
}

/// Run `work` to its end in a task of its own: a request dropped meanwhile (a client that
/// hangs up, whose request future goes at its next `.await`) can't stop it half-way. `None`
/// if the task panicked.
pub(super) async fn to_the_end<T: Send + 'static>(
    work: impl Future<Output = T> + Send + 'static,
) -> Option<T> {
    tokio::spawn(work).await.ok()
}

/// [`Service::sweep_erased_keys`]'s work.
pub(super) async fn sweep_owed(
    store: Store,
    keys: Arc<dyn KeyStore>,
    marks: MarkStore,
) -> Option<Vec<String>> {
    let owed = match store.erased_keys().await {
        Ok(owed) => owed,
        Err(failure) => {
            tracing::error!(%failure, "reading the push keys owed deleting");
            return None;
        }
    };
    let mut left = Vec::new();
    for erased in owed {
        let mut row = match store.lock_owed_key(&erased.key).await {
            Ok(Some(row)) => row,
            // Done meanwhile: claimed by a start's commit, or deleted by another sweep.
            Ok(None) => continue,
            Err(failure) => {
                tracing::error!(%failure, "locking an owed key's row");
                left.push(erased.account);
                continue;
            }
        };
        let covered = match (
            marks.erasure_attempt(&erased.account).await,
            marks.read(&erased.account).await,
            marks.erasure(&erased.account).await,
        ) {
            (Ok(None), Ok(read), Ok(at)) => {
                let mark = match &read {
                    MarkRead::Mark(mark) => Some(mark),
                    MarkRead::Missing => None,
                    MarkRead::NotAMark => {
                        left.push(erased.account);
                        continue;
                    }
                };
                let erased_account = at.is_some_and(|at| {
                    at >= erased.erased_at_ms && mark.is_none_or(|m| m.created_at_ms <= at)
                });
                row.covered_by(&erased.account, mark, erased_account)
                    .await
                    .unwrap_or(false)
            }
            _ => false,
        };
        if !covered {
            left.push(erased.account);
            continue;
        }
        if let Err(failure) = keys.delete(&erased.key).await {
            tracing::error!(%failure, "deleting an owed key");
            left.push(erased.account);
            continue;
        }
        // The key is gone: a row left behind is deleted again, which deletes nothing more.
        if let Err(failure) = row.forget().await {
            tracing::error!(%failure, "dropping a deleted key's row");
        }
    }
    Some(left)
}

/// Delete `ids`, push keys one request owed deleting, once it is over (Switch wire 8.1):
/// those still owed go, each under its row's lock; one claimed meanwhile by a committed
/// registration stays. A failure leaves the key owed for the next sweep.
pub(super) async fn delete_owed(store: Store, keys: Arc<dyn KeyStore>, ids: Vec<KeyId>) {
    for key in &ids {
        let row = match store.lock_owed_key(key).await {
            Ok(Some(row)) => row,
            Ok(None) => continue,
            Err(failure) => {
                tracing::error!(%failure, "locking an owed key's row");
                continue;
            }
        };
        if let Err(failure) = keys.delete(key).await {
            tracing::error!(%failure, "deleting an owed push key");
            continue;
        }
        if let Err(failure) = row.forget().await {
            tracing::error!(%failure, "dropping a deleted key's row");
        }
    }
}

/// Push keys a request owes deleting once it is over (Switch wire 8.1): deleted by
/// [`OwedKeys::delete`] at its end or, when the request is dropped before that (a client that
/// hangs up), by a task of their own as this drops. So no `.await` of the request leaves
/// them to a sweep.
pub(super) struct OwedKeys {
    store: Store,
    keys: Arc<dyn KeyStore>,
    ids: Vec<KeyId>,
}

impl OwedKeys {
    /// `ids`, owed in `store`'s ledger, deleted from `keys`.
    pub(super) fn new(store: Store, keys: Arc<dyn KeyStore>, ids: Vec<KeyId>) -> Self {
        Self { store, keys, ids }
    }

    /// Delete the keys still owed, waiting until it is done.
    pub(super) async fn delete(mut self) {
        let ids = std::mem::take(&mut self.ids);
        if !ids.is_empty() {
            to_the_end(delete_owed(self.store.clone(), self.keys.clone(), ids)).await;
        }
    }
}

impl Drop for OwedKeys {
    fn drop(&mut self) {
        let ids = std::mem::take(&mut self.ids);
        if ids.is_empty() {
            return;
        }
        // Without a runtime, which only a shutting-down service lacks, the keys stay owed
        // for the sweep at start.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(delete_owed(self.store.clone(), self.keys.clone(), ids));
        }
    }
}

impl std::fmt::Debug for OwedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwedKeys")
            .field("keys", &self.ids.len())
            .finish_non_exhaustive()
    }
}

/// The identity lock serializes publication with all later erasure attempts (wire 7.3).
async fn publish_outcome(
    marks: &crate::marks::MarkStore,
    identity: &str,
    attempt: ErasureAttempt,
    committed: bool,
) -> Result<(), String> {
    if committed {
        marks
            .record_erasure(identity, attempt.erased_at_ms)
            .await
            .map_err(|error| error.to_string())?;
    }
    marks
        .clear_erasure_attempt(identity, attempt)
        .await
        .map_err(|error| error.to_string())
}

/// Receipts may go only after the external attempt's durable removal. A cleanup failure
/// leaves the receipt available for the next startup, never changes deletion authority.
async fn forget_outcome(
    lock: crate::store::IdentityLock,
    freshness: Option<&crate::store::LockFreshness>,
) {
    if let Err(failure) = lock.forget_erasure_outcome(freshness).await {
        tracing::warn!(%failure, "removing a resolved erasure receipt");
    }
}
