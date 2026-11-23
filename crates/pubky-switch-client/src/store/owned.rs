//! An owned namespace, including the lifetime of canceled blocking calls.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{
    CommitOutcome, KeyValue, StateStore, StoreError, StoreHandle, StoreLease, StoreOwner,
    WriteBatch, check_owned_batch,
};

/// A keep-alive capability for credentials derived while a namespace is owned.
///
/// It permits no store mutation or explicit release. Its last holder releases the host's
/// lease. It does not attest to protocol standing or to a successful durable commit.
#[derive(Clone)]
pub struct StoreOwnership {
    _lease: Arc<dyn StoreLease>,
    lost: Arc<AtomicBool>,
}

impl std::fmt::Debug for StoreOwnership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreOwnership(..)")
    }
}

impl StoreOwnership {
    /// Refuse a capability whose store has reported that its ownership was lost.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotOwner`]. Live ownership itself is the host lease's guarantee.
    pub fn check(&self) -> Result<(), StoreError> {
        if self.lost.load(Ordering::SeqCst) {
            Err(StoreError::NotOwner)
        } else {
            Ok(())
        }
    }
}

enum Reply {
    Value(Option<Vec<u8>>),
    Entries(Vec<KeyValue>),
    Committed,
}

#[cfg(feature = "tokio")]
type Pending = tokio::task::JoinHandle<Result<Reply, StoreError>>;

/// One exclusively owned namespace. It is not clonable; credentials retain only its lease.
///
/// Blocking calls remain recorded until their actual completion, even when an awaiting
/// future is dropped. A later call drains them before it reads or writes. The host's lease
/// is held by each blocking closure as well, so dropping this handle cannot release a write
/// that is still running.
pub struct OwnedStoreHandle {
    store: Arc<dyn StateStore>,
    namespace: String,
    owner: StoreOwner,
    ownership: StoreOwnership,
    #[cfg(feature = "tokio")]
    blocking: bool,
    #[cfg(feature = "tokio")]
    pending: tokio::sync::Mutex<Option<Pending>>,
}

impl std::fmt::Debug for OwnedStoreHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnedStoreHandle(..)")
    }
}

impl OwnedStoreHandle {
    pub(super) fn new(
        handle: &StoreHandle,
        namespace: String,
        owner: StoreOwner,
        lease: Arc<dyn StoreLease>,
    ) -> Self {
        Self {
            store: Arc::clone(handle.store()),
            namespace,
            owner,
            ownership: StoreOwnership {
                _lease: lease,
                lost: Arc::new(AtomicBool::new(false)),
            },
            #[cfg(feature = "tokio")]
            blocking: handle.runs_blocking(),
            #[cfg(feature = "tokio")]
            pending: tokio::sync::Mutex::new(None),
        }
    }

    /// The namespace covered by every call through this handle.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Keep ownership alive for a derived capability, without exposing a write interface.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotOwner`] after the store reports ownership lost.
    pub fn ownership(&self) -> Result<StoreOwnership, StoreError> {
        self.ownership.check()?;
        Ok(self.ownership.clone())
    }

    /// Wait for a previously canceled blocking call to finish before using cached state. The
    /// call is waited for even when ownership was lost: until it ends, it holds its lease.
    ///
    /// # Errors
    ///
    /// The pending call's error, or [`StoreError::Unknown`] if its task failed; then
    /// [`StoreError::NotOwner`] when ownership was lost.
    pub async fn drain(&self) -> Result<(), StoreError> {
        #[cfg(feature = "tokio")]
        if self.blocking {
            Self::finish(&mut *self.pending.lock().await).await?;
        }
        self.ownership.check()
    }

    #[cfg(feature = "tokio")]
    async fn finish(pending: &mut Option<Pending>) -> Result<Option<Reply>, StoreError> {
        let Some(task) = pending.as_mut() else {
            return Ok(None);
        };
        let result = task.await.unwrap_or(Err(StoreError::Unknown));
        *pending = None;
        result.map(Some)
    }

    async fn run(
        &self,
        call: impl FnOnce(&dyn StateStore) -> Result<Reply, StoreError> + Send + 'static,
    ) -> Result<Reply, StoreError> {
        self.ownership.check()?;
        #[cfg(feature = "tokio")]
        if self.blocking {
            let mut pending = self.pending.lock().await;
            Self::finish(&mut pending).await?;
            self.ownership.check()?;
            let store = Arc::clone(&self.store);
            let ownership = self.ownership.clone();
            *pending = Some(tokio::task::spawn_blocking(move || {
                let _ownership = ownership;
                call(store.as_ref())
            }));
            return Self::finish(&mut pending).await?.ok_or(StoreError::Unknown);
        }
        call(self.store.as_ref())
    }

    /// Read a key in the owned namespace, after any pending write has finished.
    ///
    /// # Errors
    ///
    /// The store's error, including an ambiguous prior call.
    pub async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let (ns, key) = (self.namespace.clone(), key.to_vec());
        match self
            .run(move |store| store.get(&ns, &key).map(Reply::Value))
            .await?
        {
            Reply::Value(value) => Ok(value),
            _ => Err(StoreError::Unknown),
        }
    }

    /// Scan keys in the owned namespace, as [`StateStore::scan`].
    ///
    /// # Errors
    ///
    /// The store's error, including an ambiguous prior call.
    pub async fn scan(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<KeyValue>, StoreError> {
        let (ns, prefix, after) = (
            self.namespace.clone(),
            prefix.to_vec(),
            after.map(<[u8]>::to_vec),
        );
        match self
            .run(move |store| {
                store
                    .scan(&ns, &prefix, after.as_deref(), limit)
                    .map(Reply::Entries)
            })
            .await?
        {
            Reply::Entries(entries) => Ok(entries),
            _ => Err(StoreError::Unknown),
        }
    }

    /// Atomically commit only while this exact owner still holds the namespace.
    ///
    /// # Errors
    ///
    /// Namespace/size refusal, [`StoreError::NotOwner`], or the store's commit error.
    pub async fn commit(&mut self, batch: WriteBatch) -> Result<(), StoreError> {
        check_owned_batch(&self.namespace, &batch)?;
        let (ns, owner, lost) = (
            self.namespace.clone(),
            self.owner,
            Arc::clone(&self.ownership.lost),
        );
        self.run(move |store| match store.commit_if(&ns, owner, batch) {
            Ok(CommitOutcome::Applied) => Ok(Reply::Committed),
            Ok(CommitOutcome::NotOwner) | Err(StoreError::NotOwner) => {
                lost.store(true, Ordering::SeqCst);
                Err(StoreError::NotOwner)
            }
            Err(error) => Err(error),
        })
        .await
        .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{AcquireOutcome, MAX_BATCH_BYTES, MAX_VALUE_BYTES, MemoryStore};

    fn put(ns: &str, value: &[u8]) -> WriteBatch {
        let mut batch = WriteBatch::new();
        batch.put(ns, b"key", value).unwrap();
        batch
    }

    #[tokio::test]
    async fn test_owned_store_wrong_owner_and_reacquisition_cannot_mutate() {
        let store = Arc::new(MemoryStore::new());
        let owner = StoreOwner::new().unwrap();
        let AcquireOutcome::Acquired(lease) = store.acquire("ns", owner).unwrap() else {
            panic!("not acquired");
        };
        let wrong = StoreOwner::new().unwrap();
        assert_eq!(
            store.commit_if("ns", wrong, put("ns", b"bad")).unwrap(),
            CommitOutcome::NotOwner
        );
        assert_eq!(store.get("ns", b"key").unwrap(), None);
        assert!(matches!(
            store.acquire("ns", wrong).unwrap(),
            AcquireOutcome::Busy
        ));
        assert_eq!(store.commit(put("ns", b"bad")), Err(StoreError::InUse));
        assert_eq!(
            store.commit_if("ns", owner, put("ns", b"first")).unwrap(),
            CommitOutcome::Applied
        );
        drop(lease);
        let handle = StoreHandle::inline(store.clone());
        let mut next = handle.acquire("ns").await.unwrap();
        assert_eq!(
            store.commit_if("ns", owner, put("ns", b"stale")).unwrap(),
            CommitOutcome::NotOwner
        );
        next.commit(put("ns", b"next")).await.unwrap();
        assert_eq!(next.get(b"key").await.unwrap(), Some(b"next".to_vec()));
    }

    #[tokio::test]
    async fn test_owned_store_condition_bytes_and_namespace_are_bounded() {
        let store = Arc::new(MemoryStore::new());
        let handle = StoreHandle::inline(store.clone());
        let mut owner = handle.acquire("n").await.unwrap();
        let half = usize::try_from(MAX_VALUE_BYTES).unwrap();
        let mut exact = WriteBatch::new();
        exact.put("n", b"a", vec![0; half]).unwrap();
        exact.put("n", b"b", vec![0; half - 4 - 33]).unwrap();
        assert_eq!(exact.size() + 33, MAX_BATCH_BYTES);
        owner.commit(exact.clone()).await.unwrap();
        // The batch alone still fits; only its condition takes it over the total cap.
        exact.delete("n", b"").unwrap();
        assert_eq!(
            owner.commit(exact).await,
            Err(StoreError::TooLarge {
                size: MAX_BATCH_BYTES + 1,
                cap: MAX_BATCH_BYTES
            })
        );
        assert_eq!(store.get("n", b"a").unwrap().unwrap().len(), half);
        assert!(owner.commit(put("other", b"bad")).await.is_err());
        assert_eq!(store.get("other", b"key").unwrap(), None);
        owner.commit(WriteBatch::new()).await.unwrap();
    }

    #[tokio::test]
    async fn test_owned_store_capability_retains_exclusion_after_handle_drop() {
        let handle = StoreHandle::inline(Arc::new(MemoryStore::new()));
        let owner = handle.acquire("ns").await.unwrap();
        let capability = owner.ownership().unwrap();
        drop(owner);
        assert!(matches!(handle.acquire("ns").await, Err(StoreError::InUse)));
        drop(capability);
        handle.acquire("ns").await.unwrap();
    }

    struct RefusesOwner(MemoryStore);
    impl StateStore for RefusesOwner {
        fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
            self.0.get(ns, key)
        }
        fn scan(
            &self,
            ns: &str,
            prefix: &[u8],
            after: Option<&[u8]>,
            limit: u32,
        ) -> Result<Vec<KeyValue>, StoreError> {
            self.0.scan(ns, prefix, after, limit)
        }
        fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
            self.0.commit(batch)
        }
        fn acquire(&self, ns: &str, owner: StoreOwner) -> Result<AcquireOutcome, StoreError> {
            self.0.acquire(ns, owner)
        }
        fn commit_if(
            &self,
            _: &str,
            _: StoreOwner,
            _: WriteBatch,
        ) -> Result<CommitOutcome, StoreError> {
            Ok(CommitOutcome::NotOwner)
        }
    }

    #[tokio::test]
    async fn test_owned_store_lost_ownership_is_inert() {
        let handle = StoreHandle::inline(Arc::new(RefusesOwner(MemoryStore::new())));
        let mut owner = handle.acquire("ns").await.unwrap();
        let capability = owner.ownership().unwrap();
        assert_eq!(
            owner.commit(WriteBatch::new()).await,
            Err(StoreError::NotOwner)
        );
        assert_eq!(capability.check(), Err(StoreError::NotOwner));
        assert_eq!(owner.get(b"key").await, Err(StoreError::NotOwner));
        assert_eq!(owner.drain().await, Err(StoreError::NotOwner));
        assert!(matches!(owner.ownership(), Err(StoreError::NotOwner)));
    }
}
