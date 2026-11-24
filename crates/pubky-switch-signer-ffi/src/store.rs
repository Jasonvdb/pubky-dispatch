//! The signer's records in the host's durable, exclusive store (Switch spec 13.2).

use pubky_switch_client::store::{
    AcquireOutcome, CommitOutcome, KeyValue, MAX_VALUE_BYTES, StateStore, StoreError, StoreHandle,
    StoreLease, StoreOwner, Write, WriteBatch, check_owned_batch,
};
use std::{
    fmt,
    sync::{Arc, Mutex},
};
use tokio::{runtime::Handle, sync::mpsc};

/// A record in an ordered scan (Switch spec 13.2).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct StoreEntry {
    /// The record's binary key (Switch spec 13.2).
    pub key: Vec<u8>,
    /// The opaque bytes stored at the key (Switch spec 13.2).
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

/// One operation in an ordered, atomic batch (Switch spec 13.2).
#[derive(PartialEq, Eq, uniffi::Enum)]
pub enum StoreWrite {
    /// Insert or replace a record (Switch spec 13.2).
    Put {
        /// The namespace (Switch spec 13.2).
        ns: String,
        /// The exact key (Switch spec 13.2).
        key: Vec<u8>,
        /// The opaque record bytes (Switch spec 13.2).
        value: Vec<u8>,
    },
    /// Remove a record if present (Switch spec 13.2).
    Delete {
        /// The namespace (Switch spec 13.2).
        ns: String,
        /// The exact key (Switch spec 13.2).
        key: Vec<u8>,
    },
    /// Remove every matching record (Switch spec 13.2).
    DeletePrefix {
        /// The namespace (Switch spec 13.2).
        ns: String,
        /// The key prefix, empty for the whole namespace (Switch spec 13.2).
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
            Write::Put { ns, key, value } => Self::Put { ns, key, value },
            Write::Delete { ns, key } => Self::Delete { ns, key },
            Write::DeletePrefix { ns, prefix } => Self::DeletePrefix { ns, prefix },
        }
    }
}

impl From<StoreWrite> for Write {
    fn from(write: StoreWrite) -> Self {
        match write {
            StoreWrite::Put { ns, key, value } => Self::Put { ns, key, value },
            StoreWrite::Delete { ns, key } => Self::Delete { ns, key },
            StoreWrite::DeletePrefix { ns, prefix } => Self::DeletePrefix { ns, prefix },
        }
    }
}

/// The result of acquiring a namespace (Switch spec 13.2).
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StoreAcquire {
    /// The new owner holds exclusive access to write (Switch spec 13.2).
    Acquired,
    /// Another owner holds the namespace (Switch spec 13.2).
    Busy,
}

/// The result of a conditional write (Switch spec 13.2).
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StoreCommit {
    /// All writes are durable (Switch spec 13.2).
    Applied,
    /// The owner did not match and nothing changed (Switch spec 13.2).
    NotOwner,
}

/// A host storage failure. Only Unknown permits an ambiguous change (Switch spec 13.2).
#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum StoreFailure {
    /// A competing owner holds a requested namespace (Switch spec 13.2).
    #[error("a namespace is held by another writer")]
    InUse,
    /// The writer has lost its ownership (Switch spec 13.2).
    #[error("ownership was lost")]
    NotOwner,
    /// Storage was unavailable before any change (Switch spec 13.2).
    #[error("storage is unavailable")]
    Unavailable,
    /// The change may already have taken effect (Switch spec 13.2).
    #[error("the store could not confirm the outcome")]
    Unknown,
    /// There was insufficient space for the change (Switch spec 13.2).
    #[error("insufficient storage space")]
    Full,
    /// The stored data or scan response is invalid (Switch spec 13.2).
    #[error("invalid stored data")]
    Corrupt,
    /// A value or the complete batch exceeded its byte limit (Switch spec 13.2).
    #[error("{size} bytes exceeds the limit of {cap}")]
    TooLarge {
        /// The measured size in bytes (Switch spec 13.2).
        size: u64,
        /// The applicable limit in bytes (Switch spec 13.2).
        cap: u64,
    },
    /// Another storage failure with no change applied (Switch spec 13.2).
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
/// the namespace and the 32-byte owner once for the condition (Switch spec 13.2).
#[uniffi::export(with_foreign)]
pub trait HostStore: Send + Sync {
    /// Read the exact key. Return no value only for an absent key (Switch spec 13.2).
    fn get(&self, ns: String, key: Vec<u8>) -> Result<Option<Vec<u8>>, StoreFailure>;

    /// Return at most limit matching prefix entries in strictly ascending unsigned byte
    /// order. The optional after key is an exclusive lower bound (Switch spec 13.2).
    fn scan(
        &self,
        ns: String,
        prefix: Vec<u8>,
        after: Option<Vec<u8>>,
        limit: u32,
    ) -> Result<Vec<StoreEntry>, StoreFailure>;

    /// Apply all writes in order in one crash-atomic transaction, durable before
    /// returning success. Refuse the whole batch with InUse if it touches any owned
    /// namespace. Return Unknown if the outcome is uncertain (Switch spec 13.2).
    fn commit(&self, writes: Vec<StoreWrite>) -> Result<(), StoreFailure>;

    /// Atomically exclude every other handle, thread and process for this 32-byte owner.
    /// Leave records untouched. Keep the lock separate, with no expiry, replacement or
    /// preemption. Return Busy for a live owner and fail if locking is unsupported.
    /// Even an uncertain acquisition must exclude competitors until released or the
    /// owner dies (Switch spec 13.2).
    fn acquire(&self, ns: String, owner: Vec<u8>) -> Result<StoreAcquire, StoreFailure>;

    /// Release only this exact 32-byte owner. The last lease holder calls this once.
    /// A release after an uncertain acquisition is harmless for any other owner.
    /// Process death itself releases the lock (Switch spec 13.2).
    fn release(&self, ns: String, owner: Vec<u8>) -> Result<(), StoreFailure>;

    /// Check the exact 32-byte owner and apply the ordered writes in one durable
    /// transaction. All writes must belong to ns. A mismatch applies nothing and
    /// returns NotOwner. Report an uncertain commit as Unknown (Switch spec 13.2).
    fn commit_if(
        &self,
        ns: String,
        owner: Vec<u8>,
        writes: Vec<StoreWrite>,
    ) -> Result<StoreCommit, StoreFailure>;
}

type ReleaseNotice = mpsc::UnboundedSender<Result<(), StoreFailure>>;

struct StoreAdapter {
    host: Arc<dyn HostStore>,
    released: Option<ReleaseNotice>,
}

struct HostLease {
    runtime: Handle,
    release: Option<Release>,
}

impl StoreLease for HostLease {}

impl Drop for HostLease {
    fn drop(&mut self) {
        // A foreign finalizer or an async worker can drop the last holder: the host's call
        // runs on a blocking thread. A runtime that is stopping drops it unrun, and then it
        // is owed (`Release`'s drop).
        if let Some(release) = self.release.take() {
            self.runtime.spawn_blocking(move || release.run());
        }
    }
}

/// One owner's release of its namespace. Until the host confirms it, it is owed: a release
/// that fails, has an unknown outcome or never runs is tried again, on its own host store,
/// before the next acquisition of that namespace. A release names its own owner, so trying
/// it again never ends another owner's hold, and the namespace stays held, never guessed
/// free, until the host confirms (Switch spec 13.2).
struct Release {
    host: Arc<dyn HostStore>,
    ns: String,
    owner: StoreOwner,
    released: Option<ReleaseNotice>,
    done: bool,
}

/// The releases owed, across every handle of the bindings.
static OWED: Mutex<Vec<Release>> = Mutex::new(Vec::new());

fn owed() -> std::sync::MutexGuard<'static, Vec<Release>> {
    OWED.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Release {
    fn run(mut self) {
        let result = self
            .host
            .release(self.ns.clone(), self.owner.as_bytes().to_vec());
        self.done = result.is_ok();
        if let Some(notice) = self.released.take() {
            let _ = notice.send(result);
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        if !self.done {
            owed().push(Release {
                host: self.host.clone(),
                ns: std::mem::take(&mut self.ns),
                owner: self.owner,
                released: self.released.take(),
                done: true,
            });
        }
    }
}

/// Try again the releases owed for `ns`, each on its own host store; one that fails again
/// stays owed. They are matched by namespace alone: the bindings wrap one host store anew
/// at each call, and a release of another owner's token is harmless.
fn retry_owed(ns: &str) {
    let mut retry = Vec::new();
    owed().retain_mut(|release| {
        if release.ns == ns {
            retry.push(Release {
                host: release.host.clone(),
                ns: std::mem::take(&mut release.ns),
                owner: release.owner,
                released: release.released.take(),
                done: false,
            });
            false
        } else {
            true
        }
    });
    retry.into_iter().for_each(Release::run);
}

impl StateStore for StoreAdapter {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let value = self.host.get(ns.into(), key.into())?;
        if value.as_ref().is_some_and(|v| oversized(v)) {
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
                || oversized(&entry.value)
            {
                return Err(StoreError::Corrupt);
            }
            previous = Some(&entry.key);
        }
        Ok(entries.into_iter().map(Into::into).collect())
    }

    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        self.host.commit(host_writes(batch)).map_err(Into::into)
    }

    fn acquire(&self, ns: &str, owner: StoreOwner) -> Result<AcquireOutcome, StoreError> {
        let runtime = Handle::try_current().map_err(|_| StoreError::Unavailable)?;
        retry_owed(ns);
        match self.host.acquire(ns.into(), owner.as_bytes().to_vec()) {
            Ok(StoreAcquire::Busy) => Ok(AcquireOutcome::Busy),
            Ok(StoreAcquire::Acquired) => Ok(AcquireOutcome::Acquired(Arc::new(HostLease {
                runtime,
                release: Some(Release {
                    host: self.host.clone(),
                    ns: ns.into(),
                    owner,
                    released: self.released.clone(),
                    done: false,
                }),
            }))),
            Err(StoreFailure::Unknown) => {
                // Only this token may have acquired the lock, and its release can't end
                // another owner's hold; a release that fails is owed.
                Release {
                    host: self.host.clone(),
                    ns: ns.into(),
                    owner,
                    released: None,
                    done: false,
                }
                .run();
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
        check_owned_batch(ns, &batch)?;
        match self
            .host
            .commit_if(ns.into(), owner.as_bytes().to_vec(), host_writes(batch))?
        {
            StoreCommit::Applied => Ok(CommitOutcome::Applied),
            StoreCommit::NotOwner => Ok(CommitOutcome::NotOwner),
        }
    }
}

fn oversized(value: &[u8]) -> bool {
    !u64::try_from(value.len()).is_ok_and(|size| size <= MAX_VALUE_BYTES)
}

// WriteBatch checks both size limits as each write is added.
fn host_writes(batch: WriteBatch) -> Vec<StoreWrite> {
    batch.into_writes().into_iter().map(Into::into).collect()
}

/// The signer's async handle on the host's blocking callbacks (Switch spec 13.2).
#[allow(dead_code)] // The store fixtures use this signer constructor in test builds.
pub(crate) fn store_handle(store: Arc<dyn HostStore>) -> StoreHandle {
    blocking_store(store, None)
}

/// A blocking handle with optional notification of completed releases (Switch spec 13.2).
pub(super) fn blocking_store(
    host: Arc<dyn HostStore>,
    released: Option<ReleaseNotice>,
) -> StoreHandle {
    StoreHandle::blocking(Arc::new(StoreAdapter { host, released }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_switch_client::store::{MAX_BATCH_BYTES, MemoryStore};
    use std::collections::BTreeMap;
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

    struct TestHost {
        caller: std::thread::ThreadId,
        state: Mutex<State>,
        blocked: Mutex<Option<sync_channel::Receiver<()>>>,
        entered: Notify,
    }

    impl Default for TestHost {
        fn default() -> Self {
            Self {
                caller: std::thread::current().id(),
                state: Mutex::default(),
                blocked: Mutex::default(),
                entered: Notify::new(),
            }
        }
    }

    impl TestHost {
        fn call(&self, name: &'static str) -> std::sync::MutexGuard<'_, State> {
            assert_ne!(std::thread::current().id(), self.caller);
            let mut state = self.state.lock().unwrap();
            state.calls.push(name);
            state
        }
    }

    fn token(bytes: Vec<u8>) -> Result<[u8; 32], StoreFailure> {
        bytes.try_into().map_err(|_| StoreFailure::Other)
    }

    impl HostStore for TestHost {
        fn get(&self, ns: String, key: Vec<u8>) -> Result<Option<Vec<u8>>, StoreFailure> {
            let state = self.call("get");
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
                let ns = match write {
                    StoreWrite::Put { ns, .. }
                    | StoreWrite::Delete { ns, .. }
                    | StoreWrite::DeletePrefix { ns, .. } => ns,
                };
                state.owners.contains_key(ns)
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
        // only the running call holds the lease, so the namespace stays owned, `drain` waits
        // for it, and `release` comes once, after it.
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
        let mut drain = Box::pin(owner.drain());
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(drain.as_mut(), &mut context).is_pending());
        drop(drain);
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
    async fn test_store_failed_release_is_owed_until_the_host_confirms() {
        let host = Arc::new(TestHost::default());
        let (notice, mut released) = mpsc::unbounded_channel();
        let owner = blocking_store(host.clone(), Some(notice))
            .acquire("ns")
            .await
            .unwrap();
        host.state.lock().unwrap().fault = Some(Fault::Release);
        drop(owner);
        let first = tokio::time::timeout(WAIT, released.recv()).await.unwrap();
        assert_eq!(first, Some(Err(StoreFailure::Unknown)));
        // Never guessed free: the host still holds it for the first owner.
        assert!(host.state.lock().unwrap().owners.contains_key("ns"));
        // The next acquisition releases it again first, then takes it.
        let next = store_handle(host.clone()).acquire("ns").await.unwrap();
        drop(next);
    }

    #[test]
    fn test_store_release_left_by_a_stopped_runtime_is_owed() {
        let host = Arc::new(TestHost::default());
        let stopping = tokio::runtime::Runtime::new().unwrap();
        let owner = stopping
            .block_on(store_handle(host.clone()).acquire("ns"))
            .unwrap();
        stopping.shutdown_timeout(Duration::ZERO);
        drop(owner);
        assert!(host.state.lock().unwrap().owners.contains_key("ns"));
        let next = tokio::runtime::Runtime::new().unwrap();
        next.block_on(store_handle(host.clone()).acquire("ns"))
            .unwrap();
    }

    #[tokio::test]
    async fn test_store_size_limits() {
        // A batch at the cap, whose condition (the namespace and the owner) takes it over,
        // is refused before the host sees it. Value and batch caps on the writes themselves
        // are the batch's own (`WriteBatch`).
        let host = Arc::new(TestHost::default());
        let mut owner = store_handle(host.clone()).acquire("n").await.unwrap();
        let size = usize::try_from(MAX_VALUE_BYTES).unwrap();
        let mut batch = WriteBatch::new();
        batch.put("n", [], vec![0; size]).unwrap();
        batch.put("n", [], vec![0; size - 2]).unwrap();
        assert_eq!(batch.size(), MAX_BATCH_BYTES);
        assert_eq!(
            owner.commit(batch).await,
            Err(StoreError::TooLarge {
                size: MAX_BATCH_BYTES + 33,
                cap: MAX_BATCH_BYTES
            })
        );
        assert_eq!(host.state.lock().unwrap().calls, ["acquire"]);
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
                ns: text.into(),
                key: bytes.clone(),
                value: bytes.clone(),
            },
            StoreWrite::Delete {
                ns: text.into(),
                key: bytes.clone(),
            },
            StoreWrite::DeletePrefix {
                ns: text.into(),
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
