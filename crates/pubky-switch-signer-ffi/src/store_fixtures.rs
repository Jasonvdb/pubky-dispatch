//! Host checks of durable records and exclusive ownership (Switch spec 3.1).

use crate::runtime;
use crate::store::{HostStore, StoreEntry, StoreFailure, blocking_store, store_handle};
use pubky_switch_client::store::{OwnedStoreHandle, StoreError, WriteBatch};
use std::{future::Future, sync::Arc};
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard, mpsc};

/// Access to one owned namespace for a host's store checks (Switch spec 3.1).
#[derive(uniffi::Object)]
pub struct StoreProbe {
    live: Mutex<Option<Acquisition>>,
}

struct Acquisition {
    handle: OwnedStoreHandle,
    released: mpsc::UnboundedReceiver<Result<(), StoreFailure>>,
}

impl StoreProbe {
    async fn handle(&self) -> Result<MappedMutexGuard<'_, OwnedStoreHandle>, StoreError> {
        MutexGuard::try_map(self.live.lock().await, |live| {
            live.as_mut().map(|acquisition| &mut acquisition.handle)
        })
        .map_err(|_| StoreError::NotOwner)
    }
}

async fn run_store<T: Send + 'static>(
    work: impl Future<Output = Result<T, StoreError>> + Send + 'static,
) -> Result<T, StoreFailure> {
    runtime::run(async move { Ok(work.await) })
        .await
        .map_err(|_| StoreFailure::Unknown)?
        .map_err(Into::into)
}

/// Acquire the namespace, returning InUse while another owner holds it (Switch spec 3.1).
#[uniffi::export]
pub async fn store_probe(
    store: Arc<dyn HostStore>,
    namespace: String,
) -> Result<Arc<StoreProbe>, StoreFailure> {
    run_store(async move {
        let (notice, released) = mpsc::unbounded_channel();
        let handle = blocking_store(store, Some(notice))
            .acquire(&namespace)
            .await?;
        Ok(Arc::new(StoreProbe {
            live: Mutex::new(Some(Acquisition { handle, released })),
        }))
    })
    .await
}

#[uniffi::export]
impl StoreProbe {
    /// Durably set a record while this probe owns the namespace (Switch spec 3.1).
    pub async fn put(self: Arc<Self>, key: Vec<u8>, value: Vec<u8>) -> Result<(), StoreFailure> {
        run_store(async move {
            let mut handle = self.handle().await?;
            let mut batch = WriteBatch::new();
            batch.put(handle.namespace(), key, value)?;
            handle.commit(batch).await
        })
        .await
    }

    /// Read an exact key, returning no value for an absent record (Switch spec 3.1).
    pub async fn get(self: Arc<Self>, key: Vec<u8>) -> Result<Option<Vec<u8>>, StoreFailure> {
        run_store(async move { self.handle().await?.get(&key).await }).await
    }

    /// Read a page of matching records after the exclusive cursor (Switch spec 3.1).
    pub async fn scan(
        self: Arc<Self>,
        prefix: Vec<u8>,
        after: Option<Vec<u8>>,
        limit: u32,
    ) -> Result<Vec<StoreEntry>, StoreFailure> {
        run_store(async move {
            let rows = self
                .handle()
                .await?
                .scan(&prefix, after.as_deref(), limit)
                .await?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Durably remove every record with this prefix (Switch spec 3.1).
    pub async fn delete_prefix(self: Arc<Self>, prefix: Vec<u8>) -> Result<(), StoreFailure> {
        run_store(async move {
            let mut handle = self.handle().await?;
            let mut batch = WriteBatch::new();
            batch.delete_prefix(handle.namespace(), prefix)?;
            handle.commit(batch).await
        })
        .await
    }

    /// Wait for pending calls and release ownership. Later calls fail with NotOwner
    /// (Switch spec 3.1).
    #[uniffi::method(name = "close_store")]
    pub async fn close(self: Arc<Self>) -> Result<(), StoreFailure> {
        run_store(async move {
            let mut live = self.live.lock().await;
            let Acquisition {
                handle,
                mut released,
            } = live.take().ok_or(StoreError::NotOwner)?;
            let drained = handle.drain().await;
            drop(handle);
            let release = released.recv().await.ok_or(StoreError::Unknown)?;
            drained.and(release.map_err(Into::into))
        })
        .await
    }
}

/// Write through an unowned handle. An owned namespace refuses the write (Switch spec 3.1).
#[uniffi::export]
pub async fn store_unowned_put(
    store: Arc<dyn HostStore>,
    namespace: String,
    key: Vec<u8>,
    value: Vec<u8>,
) -> Result<(), StoreFailure> {
    run_store(async move {
        let mut batch = WriteBatch::new();
        batch.put(&namespace, key, value)?;
        store_handle(store).commit(batch).await
    })
    .await
}
