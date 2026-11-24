//! Host checks of durable records and exclusive ownership (Switch spec 3.1).

use crate::runtime;
use crate::store::{
    HostStore, StoreEntry, StoreFailure, StoreWrite, blocking_store, release_owed_now, store_handle,
};
use pubky_switch_client::store::{OwnedStoreHandle, StoreError, Write, WriteBatch};
use std::{future::Future, sync::Arc};
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard, mpsc};

/// One owned namespace, for a host's checks of its store (Switch spec 3.1).
#[derive(uniffi::Object)]
pub struct StoreSession {
    host: Arc<dyn HostStore>,
    live: Mutex<Option<Acquisition>>,
}

struct Acquisition {
    handle: OwnedStoreHandle,
    released: mpsc::UnboundedReceiver<Result<(), StoreFailure>>,
}

impl StoreSession {
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
pub async fn open_store_session(
    store: Box<dyn HostStore>,
    namespace: String,
) -> Result<Arc<StoreSession>, StoreFailure> {
    run_store(async move {
        let host: Arc<dyn HostStore> = Arc::from(store);
        let (notice, released) = mpsc::unbounded_channel();
        let handle = blocking_store(host.clone(), Some(notice))
            .acquire(&namespace)
            .await?;
        Ok(Arc::new(StoreSession {
            host,
            live: Mutex::new(Some(Acquisition { handle, released })),
        }))
    })
    .await
}

#[uniffi::export]
impl StoreSession {
    /// Durably set a record while this session owns the namespace (Switch spec 3.1).
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

    /// Wait for pending calls and release ownership, returning the release's failure if
    /// the host didn't confirm it: it stays owed, and ending again tries every release owed
    /// to this store once more, as [`crate::release_owed`] does. Other calls after the end
    /// fail with NotOwner (Switch spec 3.1).
    pub async fn end(self: Arc<Self>) -> Result<(), StoreFailure> {
        run_store(async move {
            let mut live = self.live.lock().await;
            let Some(Acquisition {
                handle,
                mut released,
            }) = live.take()
            else {
                let host = self.host.clone();
                return runtime::blocking(move || release_owed_now(host.as_ref()))
                    .await
                    .map_err(|_| StoreError::Unavailable)?
                    .map_err(Into::into);
            };
            let drained = handle.drain().await;
            drop(handle);
            let release = released.recv().await.ok_or(StoreError::Unknown)?;
            drained.and(release.map_err(Into::into))
        })
        .await
    }
}

/// Commit `writes` through an unowned handle: refused whole if one touches an owned
/// namespace (Switch spec 3.1).
#[uniffi::export]
pub async fn store_unowned_commit(
    store: Box<dyn HostStore>,
    writes: Vec<StoreWrite>,
) -> Result<(), StoreFailure> {
    run_store(async move {
        let mut batch = WriteBatch::new();
        for write in writes.into_iter().map(Write::from) {
            match write {
                Write::Put { ns, key, value } => batch.put(&ns, key, value),
                Write::Delete { ns, key } => batch.delete(&ns, key),
                Write::DeletePrefix { ns, prefix } => batch.delete_prefix(&ns, prefix),
            }?;
        }
        store_handle(Arc::from(store)).commit(batch).await
    })
    .await
}
