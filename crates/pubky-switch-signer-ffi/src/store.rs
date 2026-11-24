//! The signer's records in the host's durable, exclusive store (Switch spec 3.1).

use pubky_switch_client::store::{
    AcquireOutcome, CommitOutcome, KeyValue, MAX_BATCH_BYTES, MAX_VALUE_BYTES, StateStore,
    StoreError, StoreHandle, StoreLease, StoreOwner, Write, WriteBatch,
};
use std::{
    fmt,
    sync::{Arc, Mutex},
};
use tokio::{runtime::Handle, sync::mpsc};

/// A record in an ordered scan (Switch spec 3.1).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct StoreEntry {
    /// The record's binary key (Switch spec 3.1).
    pub key: Vec<u8>,
    /// The opaque bytes stored at the key (Switch spec 3.1).
    pub value: Vec<u8>,
}

impl fmt::Debug for StoreEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreEntry(..)")
    }
}

impl From<KeyValue> for StoreEntry {
    fn from((key, value): KeyValue) -> Self {
        Self { key, value }
    }
}

impl From<StoreEntry> for KeyValue {
    fn from(entry: StoreEntry) -> Self {
        (entry.key, entry.value)
    }
}

/// One operation in an ordered, atomic batch (Switch spec 3.1).
#[derive(PartialEq, Eq, uniffi::Enum)]
pub enum StoreWrite {
    /// Insert or replace a record (Switch spec 3.1).
    Put {
        /// The namespace (Switch spec 3.1).
        namespace: String,
        /// The exact key (Switch spec 3.1).
        key: Vec<u8>,
        /// The opaque record bytes (Switch spec 3.1).
        value: Vec<u8>,
    },
    /// Remove a record if present (Switch spec 3.1).
    Delete {
        /// The namespace (Switch spec 3.1).
        namespace: String,
        /// The exact key (Switch spec 3.1).
        key: Vec<u8>,
    },
    /// Remove every matching record (Switch spec 3.1).
    DeletePrefix {
        /// The namespace (Switch spec 3.1).
        namespace: String,
        /// The key prefix, empty for the whole namespace (Switch spec 3.1).
        prefix: Vec<u8>,
    },
}

impl fmt::Debug for StoreWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Put { .. } => "Put(..)",
            Self::Delete { .. } => "Delete(..)",
            Self::DeletePrefix { .. } => "DeletePrefix(..)",
        })
    }
}

impl From<Write> for StoreWrite {
    fn from(write: Write) -> Self {
        match write {
            Write::Put { ns, key, value } => Self::Put {
                namespace: ns,
                key,
                value,
            },
            Write::Delete { ns, key } => Self::Delete { namespace: ns, key },
            Write::DeletePrefix { ns, prefix } => Self::DeletePrefix {
                namespace: ns,
                prefix,
            },
        }
    }
}

impl From<StoreWrite> for Write {
    fn from(write: StoreWrite) -> Self {
        match write {
            StoreWrite::Put {
                namespace,
                key,
                value,
            } => Self::Put {
                ns: namespace,
                key,
                value,
            },
            StoreWrite::Delete { namespace, key } => Self::Delete { ns: namespace, key },
            StoreWrite::DeletePrefix { namespace, prefix } => Self::DeletePrefix {
                ns: namespace,
                prefix,
            },
        }
    }
}

/// The result of acquiring a namespace (Switch spec 3.1).
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StoreAcquire {
    /// The new owner holds exclusive access to write (Switch spec 3.1).
    Acquired,
    /// Another owner holds the namespace (Switch spec 3.1).
    Busy,
}

/// The result of a conditional write (Switch spec 3.1).
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StoreCommit {
    /// All writes are durable (Switch spec 3.1).
    Applied,
    /// The owner did not match and nothing changed (Switch spec 3.1).
    NotOwner,
}

/// A host storage failure. Only Unknown permits an ambiguous change (Switch spec 3.1).
#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum StoreFailure {
    /// A competing owner holds a requested namespace (Switch spec 3.1).
    #[error("a namespace is held by another writer")]
    InUse,
    /// The writer has lost its ownership (Switch spec 3.1).
    #[error("ownership was lost")]
    NotOwner,
    /// Storage was unavailable before any change (Switch spec 3.1).
    #[error("storage is unavailable")]
    Unavailable,
    /// The change may already have taken effect (Switch spec 3.1).
    #[error("the store could not confirm the outcome")]
    Unknown,
    /// There was insufficient space for the change (Switch spec 3.1).
    #[error("insufficient storage space")]
    Full,
    /// The stored data or scan response is invalid (Switch spec 3.1).
    #[error("invalid stored data")]
    Corrupt,
    /// A value or the complete batch exceeded its byte limit (Switch spec 3.1).
    #[error("{size} bytes exceeds the limit of {cap}")]
    TooLarge {
        /// The measured size in bytes (Switch spec 3.1).
        size: u64,
        /// The applicable limit in bytes (Switch spec 3.1).
        cap: u64,
    },
    /// Another storage failure with no change applied (Switch spec 3.1).
    #[error("the store refused the operation")]
    Other,
}

impl From<StoreFailure> for StoreError {
    fn from(error: StoreFailure) -> Self {
        match error {
            StoreFailure::InUse => Self::InUse,
            StoreFailure::NotOwner => Self::NotOwner,
            StoreFailure::Unavailable => Self::Unavailable,
            StoreFailure::Unknown => Self::Unknown,
            StoreFailure::Full => Self::Full,
            StoreFailure::Corrupt => Self::Corrupt,
            StoreFailure::TooLarge { size, cap } => Self::TooLarge { size, cap },
            StoreFailure::Other => Self::Other("the store refused the operation".into()),
        }
    }
}

impl From<StoreError> for StoreFailure {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::InUse => Self::InUse,
            StoreError::NotOwner => Self::NotOwner,
            StoreError::Unavailable => Self::Unavailable,
            StoreError::Unknown => Self::Unknown,
            StoreError::Full => Self::Full,
            StoreError::Corrupt => Self::Corrupt,
            StoreError::TooLarge { size, cap } => Self::TooLarge { size, cap },
            StoreError::Other(_) => Self::Other,
            _ => Self::Unknown,
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for StoreFailure {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unknown
    }
}

/// Device-bound, encrypted storage excluded from backups. Delete records from the
/// files as well as the index. Serialize writers across handles and processes.
/// Readers see every completed commit and never part of a batch. Calls can overlap
/// on blocking threads. Accept values through 16 MiB and batches through 32 MiB,
/// counting each namespace, key or prefix, and value. A conditional batch also counts
/// the namespace and the 32-byte owner once for the condition. A hold on a namespace
/// ends when its process ends: a release the host can't confirm is tried again, but
/// while the store stays unavailable only that end frees the namespace (Switch spec 3.1).
#[uniffi::export(with_foreign)]
pub trait HostStore: Send + Sync {
    /// Read the exact key. Return no value only for an absent key (Switch spec 3.1).
    fn get(&self, namespace: String, key: Vec<u8>) -> Result<Option<Vec<u8>>, StoreFailure>;

    /// Return at most limit matching prefix entries in strictly ascending unsigned byte
    /// order. The optional after key is an exclusive lower bound (Switch spec 3.1).
    fn scan(
        &self,
        namespace: String,
        prefix: Vec<u8>,
        after: Option<Vec<u8>>,
        limit: u32,
    ) -> Result<Vec<StoreEntry>, StoreFailure>;

    /// Apply all writes in order in one crash-atomic transaction, durable before
    /// returning success. Refuse the whole batch with InUse if it touches any owned
    /// namespace. Return Unknown if the outcome is uncertain (Switch spec 3.1).
    fn commit(&self, writes: Vec<StoreWrite>) -> Result<(), StoreFailure>;

    /// Atomically exclude every other handle, thread and process for this 32-byte owner.
    /// Leave records untouched. Keep the lock separate, with no expiry, replacement or
    /// preemption. Return Busy for a live owner and fail if locking is unsupported.
    /// Even an uncertain acquisition must exclude competitors until released or the
    /// owner dies (Switch spec 3.1).
    fn acquire(&self, namespace: String, owner: Vec<u8>) -> Result<StoreAcquire, StoreFailure>;

    /// Release only this exact 32-byte owner; any other owner's hold stays. Called when
    /// the last holder of an acquisition drops, and again, possibly on another handle of
    /// the same store, until one call succeeds (Switch spec 3.1).
    fn release(&self, namespace: String, owner: Vec<u8>) -> Result<(), StoreFailure>;

    /// Check the exact 32-byte owner and apply the ordered writes in one durable
    /// transaction. All writes must belong to the namespace. A mismatch applies nothing
    /// and returns NotOwner. Report an uncertain commit as Unknown (Switch spec 3.1).
    fn commit_if(
        &self,
        namespace: String,
        owner: Vec<u8>,
        writes: Vec<StoreWrite>,
    ) -> Result<StoreCommit, StoreFailure>;
}

type ReleaseNotice = mpsc::UnboundedSender<Result<(), StoreFailure>>;

struct StoreAdapter {
    host: Arc<dyn HostStore>,
    released: Option<ReleaseNotice>,
}

/// An owner's release that the host hasn't confirmed: owed from the moment its lease
/// drops until a release call succeeds. A release names its own owner, so trying it again,
/// on any handle of the store, never ends another owner's hold, and the namespace is
/// never guessed free (Switch spec 3.1).
#[derive(Clone)]
struct Owed {
    host: Arc<dyn HostStore>,
    namespace: String,
    owner: StoreOwner,
}

/// The releases owed, across every handle of the bindings.
static OWED: Mutex<Vec<Owed>> = Mutex::new(Vec::new());

/// The waits between eager tries of an owed release; after the last, it is tried again
/// only before a call that touches its namespace.
const RETRY_DELAYS_MS: [u64; 8] = [100, 200, 400, 800, 1_600, 3_200, 6_400, 12_800];

fn owed() -> std::sync::MutexGuard<'static, Vec<Owed>> {
    OWED.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Owed {
    fn is(&self, other: &Owed) -> bool {
        self.namespace == other.namespace && self.owner == other.owner
    }

    fn owe(&self) {
        owed().push(self.clone());
    }

    /// Whether it is still owed.
    fn pending(&self) -> bool {
        owed().iter().any(|owed| owed.is(self))
    }

    /// Release on its own handle, then on `current`, the handle of the call under way,
    /// if that one fails. Confirmed, it stops being owed before the result is returned.
    fn release(&self, current: Option<&Arc<dyn HostStore>>) -> Result<(), StoreFailure> {
        let call = |host: &Arc<dyn HostStore>| {
            host.release(self.namespace.clone(), self.owner.as_bytes().to_vec())
        };
        let mut result = call(&self.host);
        if let (Err(_), Some(current)) = (&result, current) {
            result = call(current);
        }
        if result.is_ok() {
            owed().retain(|owed| !owed.is(self));
        }
        result
    }

    /// Try it again on `runtime`'s blocking threads, waiting longer each time, until the
    /// host confirms it or the delays run out.
    fn retry_later(self, runtime: &Handle) {
        let blocking = runtime.clone();
        runtime.spawn(async move {
            for delay in RETRY_DELAYS_MS {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                if !self.pending() {
                    return;
                }
                let owed = self.clone();
                let tried = blocking.spawn_blocking(move || owed.release(None)).await;
                if matches!(tried, Ok(Ok(()))) {
                    return;
                }
            }
        });
    }
}

/// Try the releases owed for `namespace` before a call that touches it.
fn retry_owed(namespace: &str, current: &Arc<dyn HostStore>) {
    let due: Vec<Owed> = owed()
        .iter()
        .filter(|owed| owed.namespace == namespace)
        .cloned()
        .collect();
    for owed in due {
        let _ = owed.release(Some(current));
    }
}

struct HostLease {
    runtime: Handle,
    owed: Option<Owed>,
    released: Option<ReleaseNotice>,
}

impl StoreLease for HostLease {}

impl Drop for HostLease {
    fn drop(&mut self) {
        let Some(owed) = self.owed.take() else {
            return;
        };
        // Owed before anything else, so whoever is told finds it. A foreign finalizer or an
        // async worker can drop the last holder: the host's call runs on a blocking thread.
        // A runtime that is stopping drops that call unrun: the release stays owed, and the
        // notice closes.
        owed.owe();
        let released = self.released.take();
        let runtime = self.runtime.clone();
        self.runtime.spawn_blocking(move || {
            let result = owed.release(None);
            if result.is_err() {
                owed.retry_later(&runtime);
            }
            if let Some(notice) = released {
                let _ = notice.send(result);
            }
        });
    }
}

impl StateStore for StoreAdapter {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let value = self.host.get(ns.into(), key.into())?;
        if value.as_ref().is_some_and(|value| !fits(ns, key, value)) {
            return Err(StoreError::Corrupt);
        }
        Ok(value)
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<KeyValue>, StoreError> {
        let entries = self
            .host
            .scan(ns.into(), prefix.into(), after.map(Vec::from), limit)?;
        if !u32::try_from(entries.len()).is_ok_and(|count| count <= limit) {
            return Err(StoreError::Corrupt);
        }
        let mut previous = after;
        for entry in &entries {
            if !entry.key.starts_with(prefix)
                || previous.is_some_and(|key| key >= entry.key.as_slice())
                || !fits(ns, &entry.key, &entry.value)
            {
                return Err(StoreError::Corrupt);
            }
            previous = Some(&entry.key);
        }
        Ok(entries.into_iter().map(Into::into).collect())
    }

    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        let mut touched: Vec<&str> = batch.writes().iter().map(Write::ns).collect();
        touched.sort_unstable();
        touched.dedup();
        for namespace in touched {
            retry_owed(namespace, &self.host);
        }
        self.host.commit(host_writes(batch)).map_err(Into::into)
    }

    fn acquire(&self, ns: &str, owner: StoreOwner) -> Result<AcquireOutcome, StoreError> {
        let runtime = Handle::try_current().map_err(|_| StoreError::Unavailable)?;
        retry_owed(ns, &self.host);
        let owed = Owed {
            host: self.host.clone(),
            namespace: ns.into(),
            owner,
        };
        match self.host.acquire(ns.into(), owner.as_bytes().to_vec()) {
            Ok(StoreAcquire::Busy) => Ok(AcquireOutcome::Busy),
            Ok(StoreAcquire::Acquired) => Ok(AcquireOutcome::Acquired(Arc::new(HostLease {
                runtime,
                owed: Some(owed),
                released: self.released.clone(),
            }))),
            Err(StoreFailure::Unknown) => {
                // Only this token may have acquired the lock, and its release can't end
                // another owner's hold. Owed until the host confirms it.
                owed.owe();
                if owed.release(None).is_err() {
                    owed.retry_later(&runtime);
                }
                Err(StoreError::Unknown)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn commit_if(
        &self,
        ns: &str,
        owner: StoreOwner,
        batch: WriteBatch,
    ) -> Result<CommitOutcome, StoreError> {
        // The client checks the batch's namespace and size, with its condition, before
        // it calls (`OwnedStoreHandle::commit`, `check_owned_batch`).
        retry_owed(ns, &self.host);
        match self
            .host
            .commit_if(ns.into(), owner.as_bytes().to_vec(), host_writes(batch))?
        {
            StoreCommit::Applied => Ok(CommitOutcome::Applied),
            StoreCommit::NotOwner => Ok(CommitOutcome::NotOwner),
        }
    }
}

/// Whether a record could have been written: its value within the value size, and with
/// its namespace and key within one batch.
fn fits(namespace: &str, key: &[u8], value: &[u8]) -> bool {
    let size = |bytes: usize| u64::try_from(bytes).unwrap_or(u64::MAX);
    size(value.len()) <= MAX_VALUE_BYTES
        && size(namespace.len())
            .saturating_add(size(key.len()))
            .saturating_add(size(value.len()))
            <= MAX_BATCH_BYTES
}

// WriteBatch checks both size limits as each write is added.
fn host_writes(batch: WriteBatch) -> Vec<StoreWrite> {
    batch.into_writes().into_iter().map(Into::into).collect()
}

/// The signer's async handle on the host's blocking callbacks (Switch spec 3.1).
#[allow(dead_code)] // The store fixtures use this signer constructor in test builds.
pub(crate) fn store_handle(store: Arc<dyn HostStore>) -> StoreHandle {
    blocking_store(store, None)
}

/// A blocking handle with optional notification of completed releases (Switch spec 3.1).
pub(super) fn blocking_store(
    host: Arc<dyn HostStore>,
    released: Option<ReleaseNotice>,
) -> StoreHandle {
    StoreHandle::blocking(Arc::new(StoreAdapter { host, released }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_switch_client::store::MemoryStore;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, mpsc as sync_channel};
    use std::time::Duration;
    use tokio::sync::Notify;

    const WAIT: Duration = Duration::from_secs(10);

    enum Fault {
        Refuse,
        Stale,
        Unknown,
        Exception,
        Release,
    }

    fn exception() -> StoreFailure {
        uniffi::UnexpectedUniFFICallbackError::new("private callback text").into()
    }

    #[derive(Default)]
    struct State {
        records: MemoryStore,
        owners: BTreeMap<String, [u8; 32]>,
        fault: Option<Fault>,
        scan_reply: Option<Vec<StoreEntry>>,
        get_reply: Option<Vec<u8>>,
        calls: Vec<&'static str>,
        last_batch: Vec<Write>,
    }

    impl State {
        fn apply(&mut self, writes: Vec<StoreWrite>) -> Result<(), StoreFailure> {
            if matches!(self.fault, Some(Fault::Refuse)) {
                self.fault = None;
                return Err(StoreFailure::Unavailable);
            }
            let mut batch = WriteBatch::new();
            for write in writes.into_iter().map(Write::from) {
                match write {
                    Write::Put { ns, key, value } => batch.put(&ns, key, value),
                    Write::Delete { ns, key } => batch.delete(&ns, key),
                    Write::DeletePrefix { ns, prefix } => batch.delete_prefix(&ns, prefix),
                }
                .map_err(StoreError::from)?;
            }
            self.last_batch = batch.writes().to_vec();
            self.records.commit(batch)?;
            self.calls.push("applied");
            match self.fault.take() {
                Some(Fault::Unknown) => Err(StoreFailure::Unknown),
                Some(Fault::Exception) => Err(exception()),
                _ => Ok(()),
            }
        }
    }

    /// A host store in memory. Two of them can share one store, as two handles of a host
    /// do; one that is closed refuses every release.
    #[derive(Default)]
    struct TestHost {
        state: Arc<Mutex<State>>,
        closed: AtomicBool,
        blocked: Mutex<Option<sync_channel::Receiver<()>>>,
        entered: Notify,
    }

    impl TestHost {
        fn sharing(&self) -> Self {
            Self {
                state: self.state.clone(),
                ..Self::default()
            }
        }

        fn call(&self, name: &'static str) -> std::sync::MutexGuard<'_, State> {
            // A runtime's blocking thread may wait on the runtime; an async worker may not.
            let blocking = std::panic::catch_unwind(|| Handle::current().block_on(async {}));
            assert!(blocking.is_ok(), "a host call on an async worker");
            let mut state = self.state.lock().unwrap();
            state.calls.push(name);
            state
        }

        fn holds(&self, namespace: &str) -> bool {
            self.state.lock().unwrap().owners.contains_key(namespace)
        }
    }

    fn token(bytes: Vec<u8>) -> Result<[u8; 32], StoreFailure> {
        bytes.try_into().map_err(|_| StoreFailure::Other)
    }

    impl HostStore for TestHost {
        fn get(&self, ns: String, key: Vec<u8>) -> Result<Option<Vec<u8>>, StoreFailure> {
            let mut state = self.call("get");
            if let Some(value) = state.get_reply.take() {
                return Ok(Some(value));
            }
            Ok(state.records.get(&ns, &key)?)
        }

        fn scan(
            &self,
            ns: String,
            prefix: Vec<u8>,
            after: Option<Vec<u8>>,
            limit: u32,
        ) -> Result<Vec<StoreEntry>, StoreFailure> {
            let mut state = self.call("scan");
            if let Some(rows) = state.scan_reply.take() {
                return Ok(rows);
            }
            Ok(state
                .records
                .scan(&ns, &prefix, after.as_deref(), limit)?
                .into_iter()
                .map(Into::into)
                .collect())
        }

        fn commit(&self, writes: Vec<StoreWrite>) -> Result<(), StoreFailure> {
            let mut state = self.call("commit");
            if writes.iter().any(|write| {
                let namespace = match write {
                    StoreWrite::Put { namespace, .. }
                    | StoreWrite::Delete { namespace, .. }
                    | StoreWrite::DeletePrefix { namespace, .. } => namespace,
                };
                state.owners.contains_key(namespace)
            }) {
                return Err(StoreFailure::InUse);
            }
            state.apply(writes)
        }

        fn acquire(&self, ns: String, owner: Vec<u8>) -> Result<StoreAcquire, StoreFailure> {
            let owner = token(owner)?;
            let mut state = self.call("acquire");
            let outcome = match state.owners.entry(ns) {
                std::collections::btree_map::Entry::Occupied(_) => StoreAcquire::Busy,
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(owner);
                    StoreAcquire::Acquired
                }
            };
            if matches!(state.fault, Some(Fault::Exception)) {
                state.fault = None;
                return Err(exception());
            }
            Ok(outcome)
        }

        fn release(&self, ns: String, owner: Vec<u8>) -> Result<(), StoreFailure> {
            let owner = token(owner)?;
            let mut state = self.call("release");
            if self.closed.load(Ordering::SeqCst) {
                return Err(StoreFailure::Unavailable);
            }
            if matches!(state.fault, Some(Fault::Release)) {
                state.fault = None;
                return Err(StoreFailure::Unknown);
            }
            if state.owners.get(&ns) == Some(&owner) {
                state.owners.remove(&ns);
            }
            Ok(())
        }

        fn commit_if(
            &self,
            ns: String,
            owner: Vec<u8>,
            writes: Vec<StoreWrite>,
        ) -> Result<StoreCommit, StoreFailure> {
            let owner = token(owner)?;
            let blocked = self.blocked.lock().unwrap().take();
            if let Some(blocked) = blocked {
                self.entered.notify_one();
                blocked.recv_timeout(WAIT).unwrap();
            }
            let mut state = self.call("commit_if");
            if matches!(state.fault, Some(Fault::Stale)) {
                state.owners.remove(&ns);
                state.fault = None;
            }
            if state.owners.get(&ns) != Some(&owner) {
                return Ok(StoreCommit::NotOwner);
            }
            state.apply(writes)?;
            Ok(StoreCommit::Applied)
        }
    }

    fn put(ns: &str, value: &[u8]) -> WriteBatch {
        let mut batch = WriteBatch::new();
        batch.put(ns, b"k", value).unwrap();
        batch
    }

    #[tokio::test]
    async fn test_store_writes_round_trip() {
        let host = Arc::new(TestHost::default());
        let handle = store_handle(host.clone());
        let mut batch = put("ns", b"first");
        batch.put("ns", b"key", [0xff]).unwrap();
        batch.put("other", b"key", []).unwrap();
        batch.delete("ns", b"k").unwrap();
        batch.delete_prefix("ns", b"ke").unwrap();
        batch.put("ns", b"k", [0, 255]).unwrap();
        handle.commit(batch.clone()).await.unwrap();
        assert!(host.state.lock().unwrap().last_batch == batch.writes());
        assert!(handle.get("ns", b"k").await.unwrap() == Some(vec![0, 255]));
        assert!(handle.get("ns", b"key").await.unwrap().is_none());
        assert!(handle.get("other", b"key").await.unwrap() == Some(vec![]));
    }

    #[tokio::test]
    async fn test_store_scan_pages() {
        let handle = store_handle(Arc::new(TestHost::default()));
        let mut batch = WriteBatch::new();
        for key in [b"p\xff", b"p\x00", b"q\x00", b"p\x80"] {
            batch.put("ns", key, key).unwrap();
        }
        handle.commit(batch).await.unwrap();
        let page = handle.scan("ns", b"p", None, 2).await.unwrap();
        assert!(
            page == [
                (b"p\x00".to_vec(), b"p\x00".to_vec()),
                (b"p\x80".to_vec(), b"p\x80".to_vec())
            ]
        );
        let tail = handle.scan("ns", b"p", Some(&page[1].0), 2).await.unwrap();
        assert!(tail == [(b"p\xff".to_vec(), b"p\xff".to_vec())]);
        assert!(handle.scan("ns", b"", None, 0).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_store_corrupt_scan() {
        let host = Arc::new(TestHost::default());
        let handle = store_handle(host.clone());
        for keys in [
            &["pB", "pC", "pD"][..],
            &["pC", "pB"],
            &["pB", "pB"],
            &["pA"],
            &["p0"],
            &["q"],
        ] {
            let rows = keys
                .iter()
                .map(|key| StoreEntry {
                    key: key.as_bytes().into(),
                    value: vec![],
                })
                .collect();
            host.state.lock().unwrap().scan_reply = Some(rows);
            assert!(matches!(
                handle.scan("ns", b"p", Some(b"pA"), 2).await,
                Err(StoreError::Corrupt)
            ));
        }
    }

    #[tokio::test]
    async fn test_store_busy_refuses_whole_batch() {
        let host = Arc::new(TestHost::default());
        let first = store_handle(host.clone()).acquire("ns").await.unwrap();
        let other = store_handle(host);
        assert!(matches!(other.acquire("ns").await, Err(StoreError::InUse)));
        let mut batch = put("other", b"first");
        batch.put("ns", b"k", b"last").unwrap();
        assert_eq!(other.commit(batch).await, Err(StoreError::InUse));
        assert!(other.get("other", b"k").await.unwrap().is_none());
        assert!(first.get(b"k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_store_stale_handle_is_inert() {
        let host = Arc::new(TestHost::default());
        let raw = store_handle(host.clone());
        let mut owner = raw.acquire("ns").await.unwrap();
        host.state.lock().unwrap().fault = Some(Fault::Stale);
        assert_eq!(
            owner.commit(put("ns", b"x")).await,
            Err(StoreError::NotOwner)
        );
        let calls = host.state.lock().unwrap().calls.len();
        assert!(matches!(owner.get(b"k").await, Err(StoreError::NotOwner)));
        assert_eq!(
            owner.commit(put("ns", b"y")).await,
            Err(StoreError::NotOwner)
        );
        assert_eq!(calls, host.state.lock().unwrap().calls.len());
        assert!(raw.get("ns", b"k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_store_commit_outcomes() {
        let host = Arc::new(TestHost::default());
        let mut owner = store_handle(host.clone()).acquire("ns").await.unwrap();
        host.state.lock().unwrap().fault = Some(Fault::Refuse);
        assert_eq!(
            owner.commit(put("ns", b"x")).await,
            Err(StoreError::Unavailable)
        );
        assert!(owner.get(b"k").await.unwrap().is_none());
        host.state.lock().unwrap().fault = Some(Fault::Unknown);
        assert_eq!(
            owner.commit(put("ns", b"x")).await,
            Err(StoreError::Unknown)
        );
        assert!(owner.get(b"k").await.unwrap() == Some(b"x".to_vec()));
    }

    #[tokio::test]
    async fn test_store_unexpected_exception() {
        let host = Arc::new(TestHost::default());
        let raw = store_handle(host.clone());
        let arm = || host.state.lock().unwrap().fault = Some(Fault::Exception);
        arm();
        assert!(matches!(raw.acquire("ns").await, Err(StoreError::Unknown)));
        let mut owner = raw.acquire("ns").await.unwrap();
        arm();
        assert!(matches!(raw.acquire("ns").await, Err(StoreError::Unknown)));
        assert!(matches!(raw.acquire("ns").await, Err(StoreError::InUse)));
        arm();
        assert_eq!(
            raw.commit(put("other", b"x")).await,
            Err(StoreError::Unknown)
        );
        arm();
        assert_eq!(
            owner.commit(put("ns", b"x")).await,
            Err(StoreError::Unknown)
        );
        assert!(raw.get("other", b"k").await.unwrap().is_some());
        assert!(owner.get(b"k").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_store_canceled_commit_drains_before_release() {
        // The caller stops waiting and the owner is dropped while the host's commit blocks:
        // only the running call holds the lease, so the namespace stays owned, and
        // `release` comes once, after it.
        let host = Arc::new(TestHost::default());
        let (notice, mut released) = mpsc::unbounded_channel();
        let raw = blocking_store(host.clone(), Some(notice));
        let mut owner = raw.acquire("ns").await.unwrap();
        let (resume, wait) = sync_channel::channel();
        *host.blocked.lock().unwrap() = Some(wait);
        let mut commit = Box::pin(owner.commit(put("ns", b"saved")));
        tokio::select! {
            () = host.entered.notified() => {},
            _ = &mut commit => panic!("commit returned before its host"),
            () = tokio::time::sleep(WAIT) => panic!("commit did not reach its host"),
        }
        drop(commit);
        drop(owner);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(matches!(raw.acquire("ns").await, Err(StoreError::InUse)));
        resume.send(()).unwrap();
        tokio::time::timeout(WAIT, released.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            host.state.lock().unwrap().calls,
            ["acquire", "acquire", "commit_if", "applied", "release"]
        );
        assert!(raw.get("ns", b"k").await.unwrap() == Some(b"saved".to_vec()));
        raw.acquire("ns").await.unwrap();
    }

    #[tokio::test]
    async fn test_store_drain_waits_for_a_canceled_commit() {
        let host = Arc::new(TestHost::default());
        let mut owner = store_handle(host.clone()).acquire("ns").await.unwrap();
        let (resume, wait) = sync_channel::channel();
        *host.blocked.lock().unwrap() = Some(wait);
        let mut commit = Box::pin(owner.commit(put("ns", b"saved")));
        tokio::select! {
            () = host.entered.notified() => {},
            _ = &mut commit => panic!("commit returned before its host"),
        }
        drop(commit);
        let drained = tokio::spawn(async move { owner.drain().await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!drained.is_finished(), "drain returned before the commit");
        resume.send(()).unwrap();
        tokio::time::timeout(WAIT, drained)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        // The owner, dropped once drained, releases after.
        assert_eq!(
            host.state.lock().unwrap().calls[..3],
            ["acquire", "commit_if", "applied"]
        );
    }

    /// Acquire `namespace` on `host` and drop it, the host refusing the release while
    /// `closed`; the notice of that first release.
    async fn owe(host: &Arc<TestHost>, namespace: &str) -> Option<Result<(), StoreFailure>> {
        let (notice, mut released) = mpsc::unbounded_channel();
        let owner = blocking_store(host.clone(), Some(notice))
            .acquire(namespace)
            .await
            .unwrap();
        host.closed.store(true, Ordering::SeqCst);
        drop(owner);
        tokio::time::timeout(WAIT, released.recv()).await.unwrap()
    }

    #[tokio::test]
    async fn test_store_unconfirmed_release_holds_until_the_host_confirms() {
        let host = Arc::new(TestHost::default());
        assert_eq!(
            owe(&host, "held").await,
            Some(Err(StoreFailure::Unavailable))
        );
        // Never guessed free: the host still holds it for the first owner.
        let raw = store_handle(host.clone());
        assert!(matches!(raw.acquire("held").await, Err(StoreError::InUse)));
        assert!(host.holds("held"));
        host.closed.store(false, Ordering::SeqCst);
        raw.acquire("held").await.unwrap();
    }

    #[tokio::test]
    async fn test_store_unconfirmed_release_is_retried_without_a_new_call() {
        // Another process waiting for the namespace is freed once the host recovers, with
        // no call of this process touching it.
        let host = Arc::new(TestHost::default());
        assert!(owe(&host, "eager").await.unwrap().is_err());
        host.closed.store(false, Ordering::SeqCst);
        tokio::time::timeout(WAIT, async {
            while host.holds("eager") {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_store_commit_after_an_unconfirmed_release() {
        let host = Arc::new(TestHost::default());
        assert!(owe(&host, "write").await.unwrap().is_err());
        host.closed.store(false, Ordering::SeqCst);
        store_handle(host.clone())
            .commit(put("write", b"x"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_store_new_handle_frees_an_owner_owed_through_a_closed_one() {
        // The handle the release was owed through stays closed; a new handle of the same
        // store frees that exact owner.
        let first = Arc::new(TestHost::default());
        assert!(owe(&first, "moved").await.unwrap().is_err());
        let second = Arc::new(first.sharing());
        store_handle(second).acquire("moved").await.unwrap();
    }

    #[tokio::test]
    async fn test_store_acquire_right_after_the_notice_finds_the_release_owed() {
        let host = Arc::new(TestHost::default());
        let (notice, mut released) = mpsc::unbounded_channel();
        let owner = blocking_store(host.clone(), Some(notice))
            .acquire("next")
            .await
            .unwrap();
        host.state.lock().unwrap().fault = Some(Fault::Release);
        drop(owner);
        let first = tokio::time::timeout(WAIT, released.recv()).await.unwrap();
        assert_eq!(first, Some(Err(StoreFailure::Unknown)));
        store_handle(host).acquire("next").await.unwrap();
    }

    #[test]
    fn test_store_release_left_by_a_stopped_runtime_is_owed() {
        let host = Arc::new(TestHost::default());
        let stopping = tokio::runtime::Runtime::new().unwrap();
        let (notice, mut released) = mpsc::unbounded_channel();
        let owner = stopping
            .block_on(blocking_store(host.clone(), Some(notice)).acquire("ns"))
            .unwrap();
        stopping.shutdown_timeout(Duration::ZERO);
        drop(owner);
        assert!(host.holds("ns"));
        let next = tokio::runtime::Runtime::new().unwrap();
        // Its waiter gets an answer: the notice closes, never hangs.
        let notice = next.block_on(async { tokio::time::timeout(WAIT, released.recv()).await });
        assert_eq!(notice, Ok(None));
        next.block_on(store_handle(host.clone()).acquire("ns"))
            .unwrap();
    }

    #[tokio::test]
    async fn test_store_refuses_a_record_that_could_not_have_been_written() {
        let host = Arc::new(TestHost::default());
        let raw = store_handle(host.clone());
        let oversized = vec![0; usize::try_from(MAX_VALUE_BYTES).unwrap() + 1];
        host.state.lock().unwrap().get_reply = Some(oversized.clone());
        assert_eq!(raw.get("ns", b"k").await, Err(StoreError::Corrupt));
        for (key, value) in [
            (b"k".to_vec(), oversized),
            (vec![0; 17 << 20], vec![0; 16 << 20]),
        ] {
            host.state.lock().unwrap().scan_reply = Some(vec![StoreEntry { key, value }]);
            assert_eq!(raw.scan("ns", b"", None, 1).await, Err(StoreError::Corrupt));
        }
    }

    #[test]
    fn test_store_redaction() {
        let text = "private callback text";
        let bytes = text.as_bytes().to_vec();
        let entry = StoreEntry {
            key: bytes.clone(),
            value: bytes.clone(),
        };
        let writes = [
            StoreWrite::Put {
                namespace: text.into(),
                key: bytes.clone(),
                value: bytes.clone(),
            },
            StoreWrite::Delete {
                namespace: text.into(),
                key: bytes.clone(),
            },
            StoreWrite::DeletePrefix {
                namespace: text.into(),
                prefix: bytes.clone(),
            },
        ];
        assert_eq!(format!("{entry:?}"), "StoreEntry(..)");
        assert_eq!(
            format!("{writes:?}"),
            "[Put(..), Delete(..), DeletePrefix(..)]"
        );
        let cases = [
            (StoreError::InUse, StoreFailure::InUse),
            (StoreError::NotOwner, StoreFailure::NotOwner),
            (StoreError::Unavailable, StoreFailure::Unavailable),
            (StoreError::Unknown, exception()),
            (StoreError::Full, StoreFailure::Full),
            (StoreError::Corrupt, StoreFailure::Corrupt),
            (
                StoreError::TooLarge { size: 44, cap: 33 },
                StoreFailure::TooLarge { size: 44, cap: 33 },
            ),
            (StoreError::Other(text.into()), StoreFailure::Other),
        ];
        for (original, expected) in cases {
            let failure = StoreFailure::from(original);
            assert_eq!(failure, expected);
            let shown = [failure.to_string(), format!("{failure:?}")];
            let client = StoreError::from(failure);
            for output in shown
                .into_iter()
                .chain([client.to_string(), format!("{client:?}")])
            {
                assert!(!output.contains(text) && !output.contains(&format!("{bytes:?}")));
            }
            assert_eq!(StoreFailure::from(client), expected);
        }
    }
}
