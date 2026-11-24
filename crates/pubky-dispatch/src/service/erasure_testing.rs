//! Controlled erasure outcomes at the durable boundaries, for in-process clients.

use super::Service;
use crate::{
    marks::ErasureAttempt,
    store::{AccountTxn, StoreError},
};
use parking_lot::Mutex;
use std::sync::Arc;

/// The outcome retained when an erasure's response is unavailable.
#[derive(Clone, Copy, Debug)]
pub enum ErasureOutcome {
    /// The attempt is durable, but neither deletion nor an outcome receipt committed.
    Unresolved,
    /// Deletion is durable, but its receipt is missing, as after losing database evidence.
    UnresolvedAbsent,
    /// Deletion and its receipt committed; external completion has not yet been published.
    Committed,
    /// Non-application is durable, but the pending attempt has not yet been withdrawn.
    Rejected,
}

/// One erasure outcome to retain after the next authenticated deletion passes its checks.
#[derive(Clone, Debug, Default)]
pub struct ErasureFaults(Arc<Mutex<Option<ErasureOutcome>>>);

impl ErasureFaults {
    /// Make the next authenticated erasure leave this outcome and answer unavailable.
    pub fn next(&self, outcome: ErasureOutcome) {
        *self.0.lock() = Some(outcome);
    }
    pub(super) fn take(&self) -> Option<ErasureOutcome> {
        self.0.lock().take()
    }
}

impl Service {
    /// Control the next erasure's durable boundary for a test, after its normal checks.
    pub fn erasure_faults(&self) -> ErasureFaults {
        self.erasure_faults.clone()
    }

    pub(super) async fn retain_erasure_outcome(
        &self,
        txn: AccountTxn,
        attempt: ErasureAttempt,
        outcome: ErasureOutcome,
    ) -> Result<(), StoreError> {
        let identity = txn.head().id.clone();
        let store = self.store.clone();
        let freshness = self.store.lock_freshness.clone();
        let result = super::erase::to_the_end(&self.store, async move {
            match outcome {
                ErasureOutcome::Unresolved => {
                    drop(txn);
                    Ok(())
                }
                ErasureOutcome::Rejected => {
                    drop(txn);
                    store
                        .lock_identity(&identity)
                        .await?
                        .reject_erasure(&attempt, freshness.as_ref())
                        .await
                }
                ErasureOutcome::Committed => txn
                    .erase_recorded(&attempt, freshness.as_ref())
                    .await
                    .map_err(|error| error.into_parts().0),
                ErasureOutcome::UnresolvedAbsent => txn
                    .erase(attempt.erased_at_ms)
                    .await
                    .map_err(|error| error.into_parts().0),
            }
        })
        .await;
        result.ok_or(StoreError::Raced("the erasure task ended"))?
    }
}
