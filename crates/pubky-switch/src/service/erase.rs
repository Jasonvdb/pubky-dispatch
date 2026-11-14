//! `POST /v1/{id}/erase` (Switch wire 7.4.16, spec 12.7): the signer erases the identity's
//! account at this service.
//!
//! The request passes the signer's checks like every call. Its body `{ "created",
//! "identity_hash" }` names the account's creation time, the one its enrollment answer named,
//! and the account's newest `identity.json`, left out only where the account holds none
//! (`409 conflict` otherwise, carrying the creation time). Then the order is fixed (Switch
//! wire 7.3, Table 3):
//! 1. the erasure's record is written to the key store's ledger, durably, dated no earlier
//!    than the creation it erases;
//! 2. the account's row is deleted, and with it every row of its state, its apps' push keys
//!    owed deleting in the same transaction (`erased_keys`), and committed; where the
//!    deletion doesn't commit, the record is taken back and the answer is `503`;
//! 3. the account's mark is deleted, and the owed push keys;
//! 4. only then is the answer released, signed with the key the verdict gives, without a
//!    head.
//!
//! A mark the deletion of step 3 leaves is an erasure's leftover: the record covers it, and a
//! later request for the identity or the next start deletes it. Afterwards every request for
//! the account finds no account: the not-hosted `404`, signed with the service key.
//!
//! **A restored database** (spec 6.5). The key store, apart from the database's backups,
//! keeps each erasure's record in its ledger. A database restored from a backup taken before
//! an erasure brings the account back. Such an account, one created at or before the time
//! the ledger holds for its identity, is erased again before anything is served or signed
//! for it (Switch wire 7.3, Table 1, first row): at start, for every identity the ledger
//! holds, and at every request's judgement of the account. An account created after the
//! erasure, by an enrollment since, is a new account: an enrollment creates it later than the
//! time the ledger holds. The ledger keeps an erasure until every database backup that could
//! hold its account has aged out (`keys.backup_retention_days`), and drops a record only once
//! the leftover marks it covers are gone.

use std::sync::Arc;

use pubky_switch_core::{
    http::{ERASED_BODY, parse_erase_body},
    records::IdentityDoc,
    time::rfc3339,
};
use serde_json::json;

use super::{
    Answer, Deferred, PreLock, Service,
    marking::{self, Judged},
    signed::{Asked, sign_answer},
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
    store::{AccountTxn, Store},
};

/// The least time an erasure's record is kept, whatever the backups: a day (Switch wire 7.3,
/// Table 3).
const RECORD_KEPT_AT_LEAST_MS: u64 = 24 * 60 * 60 * 1000;

impl Service {
    /// The checks of an erasure from the signer, under the account's lock and the verdict
    /// `judged` (Switch wire 7.4.16): its binding to the account ([`erasure_binding`]). The
    /// answer it returns erases nothing yet: [`Service::finish_erasure`] does.
    ///
    /// # Errors
    ///
    /// As [`erasure_binding`].
    pub(super) fn erase_answer(
        &self,
        request: &SwitchRequest,
        held: Option<&IdentityDoc>,
        judged: &Judged,
        _time_ms: u64,
    ) -> Result<Answer, ApiError> {
        let created = erasure_binding(request, held, judged)?;
        let mut answer = Answer::ok(ERASED_BODY.to_vec());
        answer.deferred = Some(Deferred::Erase(created));
        Ok(answer)
    }

    /// Erase the account whose lock `txn` holds and answer `answer`, signed with `signer`
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
        mut answer: Answer,
    ) -> SwitchResponse {
        // Dated no earlier than the creation it erases (Switch wire 7.3, Table 3).
        let record_at = match answer.deferred.take() {
            Some(Deferred::Erase(created)) => time_ms.max(created),
            _ => time_ms,
        };
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        let account = txn.head().id.clone();
        let created_at_ms = txn.head().created_at_ms;
        // The erasure moves a mark: not while another process may hold the database.
        if !self.lock_is_fresh() {
            drop(txn);
            return Self::signed_error(signer, asked, committed_ms, &unavailable());
        }
        // The record first, durably, once the checks have passed (Table 3).
        let previous = match self.keys.record_erasure(&account, record_at).await {
            Ok(previous) => previous,
            Err(failure) => {
                tracing::error!(%failure, "recording an erasure");
                drop(txn);
                return Self::signed_error(signer, asked, committed_ms, &unavailable());
            }
        };
        // The deletion, and the push keys' after it, run to their end in a task of their
        // own: a signer that hangs up between them leaves no key to the next sweep.
        let (store, keys) = (self.store.clone(), self.keys.clone());
        let erased = to_the_end(async move {
            txn.erase(time_ms).await?;
            let _ = sweep_owed(store, keys).await;
            Ok::<_, crate::store::StoreError>(())
        })
        .await;
        if !matches!(erased, Some(Ok(()))) {
            if let Some(Err(failure)) = &erased {
                tracing::error!(%failure, "an erasure");
            }
            // The record goes again where the deletion didn't commit: the account is still
            // there. Where that can't be told, the record stays, and the account, if it is
            // still there, is erased again at its next request.
            if let Ok(Some(found)) = self.store.lookup(&account).await
                && found.created_at_ms == created_at_ms
                && let Err(failure) = self
                    .keys
                    .withdraw_erasure(&account, record_at, previous)
                    .await
            {
                tracing::error!(%failure, "taking back an erasure's record");
            }
            return Self::signed_error(signer, asked, committed_ms, &unavailable());
        }
        // Then the mark: only one the record covers, never a later account's.
        if let Err(failure) = self.marks.delete_created_by(&account, record_at).await {
            tracing::warn!(%failure, "deleting an erased account's mark");
        }
        self.forget_account(&account);
        self.forget_aged_erasures().await;
        sign_answer(signer, asked, time_ms, answer)
    }

    /// The erasure at an identity without an account that the verdict lets through: a lost
    /// one (Switch wire 7.3 Table 2, 7.4.16). After the signer's checks, the record is
    /// written, then the mark deleted; the answer is signed with the key in the mark.
    pub(super) async fn erase_without_account(
        &self,
        account: &str,
        request: &SwitchRequest,
        judged: &Judged,
        routed: &verdict::Answer,
        base_ms: u64,
        asked: Asked<'_>,
    ) -> SwitchResponse {
        let refuse =
            |error: ApiError| self.keyed_error(&routed.key, asked, base_ms, base_ms, &error);
        if request.route.call != Call::Erase {
            return self.service_error(asked, base_ms, &marking::not_hosted());
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
            return self.service_error(asked, base_ms, &marking::not_hosted());
        }
        let created = match erasure_binding(request, None, judged) {
            Ok(created) => created,
            Err(error) => return refuse(error),
        };
        if !self.lock_is_fresh() {
            return refuse(ApiError::unavailable("7.6: a temporary failure"));
        }
        // Dated no earlier than the creation it erases (Switch wire 7.3, Table 3).
        let at_ms = base_ms.max(created);
        if let Err(failure) = self.keys.record_erasure(account, at_ms).await {
            tracing::error!(%failure, "recording an erasure");
            return refuse(ApiError::unavailable("7.6: a temporary failure"));
        }
        // A mark left here is a leftover the record covers, deleted later.
        self.delete_leftover(account, at_ms).await;
        self.forget_account(account);
        let Some(signer) = self.signer_of(&routed.key) else {
            return self.service_error(
                asked,
                base_ms,
                &ApiError::unavailable("7.6: a temporary failure"),
            );
        };
        sign_answer(&signer, asked, base_ms, Answer::ok(ERASED_BODY.to_vec()))
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
        to_the_end(sweep_owed(self.store.clone(), self.keys.clone()))
            .await
            .flatten()
    }

    /// Erase again account `account`, which a restored database brought back after its
    /// erasure at `erased_at_ms` (Switch wire 7.3, Table 1 first row): as an erasure does,
    /// its state deleted and its push keys owed in one commit, then the owed keys deleted,
    /// its ledger entry kept, with no answer to sign. Whether the identity holds no such
    /// account any more: gone, erased here, or a new account made since; `false` when the
    /// erasure didn't commit.
    pub(super) async fn erase_restored(&self, account: &str, erased_at_ms: u64) -> bool {
        let (store, keys, id) = (self.store.clone(), self.keys.clone(), account.to_string());
        // Run to the end in a task of its own, as an erasure is: a request dropped meanwhile
        // can't stop it between the commit and the keys' deletion.
        let erased = to_the_end(async move {
            let Some(txn) = store.begin(&id).await? else {
                return Ok(false);
            };
            if txn.head().created_at_ms > erased_at_ms {
                return Ok(false);
            }
            txn.erase(erased_at_ms).await?;
            let _ = sweep_owed(store, keys).await;
            Ok::<_, crate::store::StoreError>(true)
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
    /// every identity the key store's ledger holds (Switch wire 7.3, Table 1), deleting the
    /// marks the records cover with them. Run at start, before the service takes requests;
    /// the judgement at each request covers what this misses. The number erased, or `None`
    /// when the ledger or the accounts can't be read.
    pub async fn erase_restored_accounts(&self) -> Option<usize> {
        let ledger = match self.keys.erasures().await {
            Ok(ledger) => ledger,
            Err(failure) => {
                tracing::error!(%failure, "reading the erasure ledger");
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
        for (account, erased_at_ms) in &restored {
            if self.erase_again(account, *erased_at_ms).await.is_ok() {
                erased += 1;
            }
        }
        Some(erased)
    }

    /// Delete the erasures' leftover marks: for each identity the ledger holds without an
    /// account, a mark created at or before its record (Switch wire 7.3, Table 1). Run at
    /// start; a later request for the identity deletes one this misses.
    pub(super) async fn delete_leftover_marks(&self) {
        let Ok(ledger) = self.keys.erasures().await else {
            return;
        };
        for (identity, erased_at_ms) in ledger {
            if matches!(self.store.lookup(&identity).await, Ok(None)) {
                self.delete_leftover(&identity, erased_at_ms).await;
            }
        }
    }

    /// Forget the ledger's erasures older than `keys.backup_retention_days`, and at least a
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
        let Ok(ledger) = self.keys.erasures().await else {
            return;
        };
        for (identity, erased_at_ms) in ledger.iter().filter(|(_, at)| *at < before_ms) {
            match self.store.lookup(identity).await {
                Ok(None) => {
                    if let Err(failure) =
                        self.marks.delete_created_by(identity, *erased_at_ms).await
                    {
                        tracing::warn!(%failure, "deleting an erasure's leftover mark");
                        return;
                    }
                }
                Ok(Some(_)) => {}
                Err(failure) => {
                    let _ = store_error(&failure);
                    return;
                }
            }
        }
        if let Err(failure) = self.keys.forget_erasures_before(before_ms).await {
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
/// The creation time it names, which the erasure's record is dated no earlier than.
///
/// # Errors
///
/// `400` for a body that isn't `{ "created": time, "identity_hash": b64(32) }`, both
/// optional in shape; `409 conflict`, carrying `current.created`, for another creation time
/// or none, another hash, a hash where the account holds no `identity.json`, or none where
/// it holds one; at an account that answers the notice the `409` carries the copy it holds
/// too, and at a lost identity `identity: null`.
fn erasure_binding(
    request: &SwitchRequest,
    held: Option<&IdentityDoc>,
    judged: &Judged,
) -> Result<u64, ApiError> {
    let named = parse_erase_body(&request.body)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let created = judged
        .created_at_ms()
        .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
    let conflict = |why: &'static str| {
        let mut current = json!({ "created": rfc3339(created) });
        if judged.account.is_none() {
            current["identity"] = serde_json::Value::Null;
        } else if judged.answers_notice() {
            current["identity"] = json!(held.map(IdentityDoc::signed));
        }
        ApiError::new(ErrorCode::Conflict, why).with_current(current)
    };
    if named.created != Some(created) {
        return Err(conflict("7.4.16: the account was created at another time"));
    }
    if judged.account.is_none() {
        return Ok(created);
    }
    let matches = match (named.identity_hash, held) {
        (Some(hash), Some(held)) => hash == held.hash(),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    };
    if !matches {
        return Err(conflict("7.4.16: the account holds another identity.json"));
    }
    Ok(created)
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
pub(super) async fn sweep_owed(store: Store, keys: Arc<dyn KeyStore>) -> Option<Vec<String>> {
    let owed = match store.erased_keys().await {
        Ok(owed) => owed,
        Err(failure) => {
            tracing::error!(%failure, "reading the push keys owed deleting");
            return None;
        }
    };
    let mut left = Vec::new();
    for erased in owed {
        let row = match store.lock_owed_key(&erased.key).await {
            Ok(Some(row)) => row,
            // Done meanwhile: claimed by a start's commit, or deleted by another sweep.
            Ok(None) => continue,
            Err(failure) => {
                tracing::error!(%failure, "locking an owed key's row");
                left.push(erased.account);
                continue;
            }
        };
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
