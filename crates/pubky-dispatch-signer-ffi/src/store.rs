//! The signer's records in the host's durable, exclusive store (Dispatch spec 3.1).

use crate::{SignerFfiError, runtime};
use pubky_dispatch_client::store::{
    AcquireOutcome, CommitOutcome, KeyValue, MAX_BATCH_BYTES, MAX_VALUE_BYTES, StateStore,
    StoreError, StoreHandle, StoreLease, StoreOwner, Write, WriteBatch, check_owned_batch,
};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};
use tokio::{runtime::Handle, sync::mpsc};

/// A record in an ordered scan (Dispatch spec 3.1).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct StoreEntry {
    /// The record's binary key (Dispatch spec 3.1).
    pub key: Vec<u8>,
    /// The opaque bytes stored at the key (Dispatch spec 3.1).
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

/// One operation in an ordered, atomic batch (Dispatch spec 3.1).
#[derive(PartialEq, Eq, uniffi::Enum)]
pub enum StoreWrite {
    /// Insert or replace a record (Dispatch spec 3.1).
    Put {
        /// The namespace (Dispatch spec 3.1).
        namespace: String,
        /// The exact key (Dispatch spec 3.1).
        key: Vec<u8>,
        /// The opaque record bytes (Dispatch spec 3.1).
        value: Vec<u8>,
    },
    /// Remove a record if present (Dispatch spec 3.1).
    Delete {
        /// The namespace (Dispatch spec 3.1).
        namespace: String,
        /// The exact key (Dispatch spec 3.1).
        key: Vec<u8>,
    },
    /// Remove every matching record (Dispatch spec 3.1).
    DeletePrefix {
        /// The namespace (Dispatch spec 3.1).
        namespace: String,
        /// The key prefix, empty for the whole namespace (Dispatch spec 3.1).
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

/// The result of acquiring a namespace (Dispatch spec 3.1).
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StoreAcquire {
    /// The new owner holds exclusive access to write (Dispatch spec 3.1).
    Acquired,
    /// Another owner holds the namespace (Dispatch spec 3.1).
    Busy,
}

/// The result of a conditional write (Dispatch spec 3.1).
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StoreCommit {
    /// All writes are durable (Dispatch spec 3.1).
    Applied,
    /// The owner did not match and nothing changed (Dispatch spec 3.1).
    NotOwner,
}

/// A host storage failure. Only Unknown permits an ambiguous change (Dispatch spec 3.1).
#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum StoreFailure {
    /// A competing owner holds a requested namespace (Dispatch spec 3.1).
    #[error("a namespace is held by another writer")]
    InUse,
    /// The writer has lost its ownership (Dispatch spec 3.1).
    #[error("ownership was lost")]
    NotOwner,
    /// Storage was unavailable before any change (Dispatch spec 3.1).
    #[error("storage is unavailable")]
    Unavailable,
    /// The change may already have taken effect (Dispatch spec 3.1).
    #[error("the store could not confirm the outcome")]
    Unknown,
    /// There was insufficient space for the change (Dispatch spec 3.1).
    #[error("insufficient storage space")]
    Full,
    /// The stored data or scan response is invalid (Dispatch spec 3.1).
    #[error("invalid stored data")]
    Corrupt,
    /// A value or the complete batch exceeded its byte limit (Dispatch spec 3.1).
    #[error("{size} bytes exceeds the limit of {cap}")]
    TooLarge {
        /// The measured size in bytes (Dispatch spec 3.1).
        size: u64,
        /// The applicable limit in bytes (Dispatch spec 3.1).
        cap: u64,
    },
    /// Another storage failure with no change applied (Dispatch spec 3.1).
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
            // A store failure this build doesn't know: nothing says it applied nothing.
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
/// the namespace and the 32-byte owner once for the condition (Dispatch spec 3.1).
///
/// Releases: a hold on a namespace ends when its process ends. When the last holder of an
/// acquisition goes, as when a host lets a signer's last handle go without ending it, its
/// release is tried once, through the bindings' bounded start; if that fails, or no thread
/// takes it up, the release stays owed to this store. Nothing retries it by itself. The
/// next acquisition of that namespace for the same store in this process settles what is
/// owed for it first and then acquires; [`release_owed_locks`] settles it too. Until then
/// the namespace stays held for that owner, in every process, and the acquisition answers
/// the release's own failure. What a host does: [signer host guide, 2.4 The Homeserver and
/// the store](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store)
/// (Dispatch spec 3.1).
///
/// Threads: the signer's calls through its store handle (`get`, `scan`, `commit`,
/// `acquire`, `commit_if`) run on the runtime's blocking threads through the store client's
/// own pool, and are not given up: a callback that never returns holds its call, and its
/// thread, for good. Once every blocking thread is held this way, the bindings' own bounded
/// work (the releases above, and the vault's calls) fails with `RuntimeUnavailable` after
/// 30 seconds, and other store calls wait. An asynchronous call into the bindings that a
/// callback starts on its own thread is refused, and takes nothing.
// A callback interface: only the host implements it, so the library exports no Rust
// implementation whose calls would return stored values.
#[uniffi::export(callback_interface)]
pub trait HostStore: Send + Sync {
    /// The store's id, chosen by the host, at most 256 bytes: the same for every handle on
    /// the same records and namespace locks, in every process, and different for every
    /// other store. Releases owed are kept by it. Two stores given one id are the host's
    /// error: a release owed to one can be settled by the other's answer, and the first
    /// store's namespace then stays held for that owner until this process ends. An id
    /// that is empty or longer fails the call that needed it as Other, and a failure fails
    /// it too, with nothing else asked of the store (Dispatch spec 3.1).
    fn store_id(&self) -> Result<String, StoreFailure>;

    /// Read the exact key. Return no value only for an absent key (Dispatch spec 3.1).
    fn get(&self, namespace: String, key: Vec<u8>) -> Result<Option<Vec<u8>>, StoreFailure>;

    /// Return at most limit matching prefix entries in strictly ascending unsigned byte
    /// order. The optional after key is an exclusive lower bound (Dispatch spec 3.1).
    fn scan(
        &self,
        namespace: String,
        prefix: Vec<u8>,
        after: Option<Vec<u8>>,
        limit: u32,
    ) -> Result<Vec<StoreEntry>, StoreFailure>;

    /// Apply all writes in order in one crash-atomic transaction, durable before
    /// returning success. Refuse the whole batch with InUse if it touches any owned
    /// namespace. Return Unknown if the outcome is uncertain (Dispatch spec 3.1).
    fn commit(&self, writes: Vec<StoreWrite>) -> Result<(), StoreFailure>;

    /// Atomically exclude every other handle, thread and process for this 32-byte owner.
    /// Leave records untouched. Keep the lock separate, with no expiry, replacement or
    /// preemption. Return Busy for a live owner and fail if locking is unsupported.
    /// Even an uncertain acquisition must exclude competitors until released or the
    /// owner dies (Dispatch spec 3.1).
    fn acquire(&self, namespace: String, owner: Vec<u8>) -> Result<StoreAcquire, StoreFailure>;

    /// Release only this exact 32-byte owner, through any handle of this store; any other
    /// owner's hold stays. An owner that holds nothing is released at once, with success,
    /// which NotOwner reads as too. Called when the last holder of an acquisition drops,
    /// and again while it stays owed (Dispatch spec 3.1).
    fn release(&self, namespace: String, owner: Vec<u8>) -> Result<(), StoreFailure>;

    /// Check the exact 32-byte owner and apply the ordered writes in one durable
    /// transaction. All writes must belong to the namespace. A mismatch applies nothing
    /// and returns NotOwner. Report an uncertain commit as Unknown (Dispatch spec 3.1).
    fn commit_if(
        &self,
        namespace: String,
        owner: Vec<u8>,
        writes: Vec<StoreWrite>,
    ) -> Result<StoreCommit, StoreFailure>;
}

/// The longest store id a host may give, in bytes.
const MAX_STORE_ID_BYTES: usize = 256;

/// Call the host, marking the thread for the call ([`runtime::in_callback`]): a host that
/// calls back into the bindings from inside it is refused, not left waiting.
fn host_call<T>(call: impl FnOnce() -> T) -> T {
    runtime::in_callback(call)
}

type ReleaseNotice = mpsc::UnboundedSender<Result<(), StoreFailure>>;

struct StoreAdapter {
    host: Arc<dyn HostStore>,
    released: Option<ReleaseNotice>,
}

/// Where a release is owed: a store, by its id, and a namespace in it.
type OwedKey = (String, String);

/// The releases owed: for each store and namespace, the owners whose release the host
/// hasn't confirmed. A set, each owner settled only by its own confirmed release, so none
/// is lost to another. It holds at most this process's leases on the key: an owner is
/// owed when its lease goes, or when its acquisition's outcome is unknown, and an
/// acquisition is asked of the host only once nothing is owed for its key. Entries of a
/// store never seen again stay until the process ends, when its locks end too (Dispatch spec
/// 3.1). Nothing retries in the background.
static OWED: Mutex<BTreeMap<OwedKey, Vec<StoreOwner>>> = Mutex::new(BTreeMap::new());

/// One lock per key, held for an acquisition's whole sequence: settle what is owed, ask the
/// host, record what it answered. Two acquisitions of a key never interleave. Its entries,
/// one per store id and namespace seen, stay until the process ends.
static ACQUIRING: Mutex<BTreeMap<OwedKey, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());

fn owed() -> MutexGuard<'static, BTreeMap<OwedKey, Vec<StoreOwner>>> {
    OWED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Owe `owner`'s release under `key`, before the host is asked: a call that never returns,
/// or one that panics, leaves it owed.
fn owe(key: &OwedKey, owner: StoreOwner) {
    let mut owed = owed();
    let owners = owed.entry(key.clone()).or_default();
    if !owners.contains(&owner) {
        owners.push(owner);
    }
}

/// `owner`'s release under `key` is confirmed: it stops being owed.
fn settle(key: &OwedKey, owner: StoreOwner) {
    let mut owed = owed();
    if let Some(owners) = owed.get_mut(key) {
        owners.retain(|owed| *owed != owner);
        if owners.is_empty() {
            owed.remove(key);
        }
    }
}

/// Release `owner` under `key` through `host`: settled only by the host's confirmation for
/// that same owner, or its NotOwner, which says the owner holds nothing. A panicking host
/// is an unconfirmed release.
fn release(host: &dyn HostStore, key: &OwedKey, owner: StoreOwner) -> Result<(), StoreFailure> {
    let answer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        host_call(|| host.release(key.1.clone(), owner.as_bytes().to_vec()))
    }))
    .unwrap_or(Err(StoreFailure::Unknown));
    match answer {
        Ok(()) | Err(StoreFailure::NotOwner) => {
            settle(key, owner);
            Ok(())
        }
        Err(failure) => Err(failure),
    }
}

/// Try every release owed under `key` once, through `host`, a handle of the same store.
/// The first failure, typed as the host gave it.
fn retry(host: &dyn HostStore, key: &OwedKey) -> Result<(), StoreFailure> {
    let pending = owed().get(key).cloned().unwrap_or_default();
    let mut first = Ok(());
    for owner in pending {
        let answer = release(host, key, owner);
        if first.is_ok() {
            first = answer;
        }
    }
    first
}

/// The store's id, as the host gives it, checked.
fn store_id(host: &dyn HostStore) -> Result<String, StoreFailure> {
    let id = host_call(|| host.store_id())?;
    if id.is_empty() || id.len() > MAX_STORE_ID_BYTES {
        return Err(StoreFailure::Other);
    }
    Ok(id)
}

/// The lock that serializes acquisitions of `key`.
fn acquiring(key: &OwedKey) -> Arc<Mutex<()>> {
    ACQUIRING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(key.clone())
        .or_default()
        .clone()
}

struct HostLease {
    host: Arc<dyn HostStore>,
    runtime: Handle,
    /// The store id and namespace, as they were at the acquisition.
    key: OwedKey,
    owner: StoreOwner,
    released: Option<ReleaseNotice>,
}

impl StoreLease for HostLease {}

impl Drop for HostLease {
    fn drop(&mut self) {
        // Owed before anything else, so whoever is told finds it, and a release that never
        // runs stays owed. A foreign finalizer or an async worker can drop the last holder:
        // the host's call runs once, on one of the runtime's blocking threads. A runtime
        // that is stopping drops it unrun, and the notice closes.
        owe(&self.key, self.owner);
        let (host, key, owner) = (self.host.clone(), self.key.clone(), self.owner);
        let released = self.released.take();
        self.runtime.spawn(async move {
            let result = runtime::blocking(move || release(host.as_ref(), &key, owner))
                .await
                .unwrap_or_else(|error| Err(not_run(&error)));
            if let Some(notice) = released {
                let _ = notice.send(result);
            }
        });
    }
}

impl StateStore for StoreAdapter {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let value = host_call(|| self.host.get(ns.into(), key.into()))?;
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
        let entries = host_call(|| {
            self.host
                .scan(ns.into(), prefix.into(), after.map(Vec::from), limit)
        })?;
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
        host_call(|| self.host.commit(host_writes(batch))).map_err(Into::into)
    }

    fn acquire(&self, ns: &str, owner: StoreOwner) -> Result<AcquireOutcome, StoreError> {
        let runtime = Handle::try_current().map_err(|_| StoreError::Unavailable)?;
        let key = (store_id(self.host.as_ref())?, ns.to_owned());
        let serial = acquiring(&key);
        let _serial = serial.lock().unwrap_or_else(PoisonError::into_inner);
        // What is owed for the key is settled first, through this handle of the same store.
        // While a release stays unconfirmed, its owner may still hold the namespace: the
        // acquisition answers that release's own failure, and the host is not asked.
        retry(self.host.as_ref(), &key)?;
        // A host that panics may have acquired, as one answering Unknown may have.
        let acquired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            host_call(|| self.host.acquire(ns.into(), owner.as_bytes().to_vec()))
        }))
        .unwrap_or(Err(StoreFailure::Unknown));
        match acquired {
            Ok(StoreAcquire::Busy) => Ok(AcquireOutcome::Busy),
            Ok(StoreAcquire::Acquired) => Ok(AcquireOutcome::Acquired(Arc::new(HostLease {
                host: self.host.clone(),
                runtime,
                key,
                owner,
                released: self.released.clone(),
            }))),
            Err(StoreFailure::Unknown) => {
                // Only this token may have acquired the lock, and its release can't end
                // another owner's hold. Owed until the host confirms it.
                owe(&key, owner);
                let _ = release(self.host.as_ref(), &key, owner);
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
        // A caller holding the raw store (`StoreHandle::store`) reaches this without the
        // owned handle's own check: nothing outside the namespace, or over the batch's
        // size with its condition, goes to the host.
        check_owned_batch(ns, &batch)?;
        match host_call(|| {
            self.host
                .commit_if(ns.into(), owner.as_bytes().to_vec(), host_writes(batch))
        })? {
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

/// Try every release owed to `store` again, through it, once each. A host calls it at the
/// end of a session on the store, and after any failure that said a release is owed:
/// [signer host guide, 2.4 The Homeserver and the store](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store).
/// Returns the first failure, typed as the host gave it; a release that fails stays owed,
/// and a later call tries it again. With nothing owed it returns at once, without calling
/// the host. Called from inside a store callback on the same thread, it is refused as
/// Unavailable, and takes nothing (Dispatch spec 3.1).
#[uniffi::export]
pub async fn release_owed_locks(store: Box<dyn HostStore>) -> Result<(), StoreFailure> {
    let host: Arc<dyn HostStore> = Arc::from(store);
    runtime::run(async move { runtime::blocking(move || release_owed_now(host.as_ref())).await })
        .await
        .unwrap_or_else(|error| Err(not_run(&error)))
}

/// The store's reading of a call the bindings' runtime didn't carry out: one that never
/// reached the host is unavailable, and one that stopped part way is unknown.
pub(crate) fn not_run(error: &SignerFfiError) -> StoreFailure {
    match error {
        // Refused before it started: a call from inside a host callback, or no runtime or
        // blocking thread to run it.
        SignerFfiError::InvalidInput { .. } | SignerFfiError::RuntimeUnavailable => {
            StoreFailure::Unavailable
        }
        // Stopped part way, or a failure these calls don't give: what it did is unknown.
        _ => StoreFailure::Unknown,
    }
}

/// [`release_owed_locks`] on the calling thread, a blocking one.
pub(crate) fn release_owed_now(host: &dyn HostStore) -> Result<(), StoreFailure> {
    if owed().is_empty() {
        return Ok(());
    }
    let id = store_id(host)?;
    let due: Vec<OwedKey> = owed()
        .keys()
        .filter(|(store, _)| *store == id)
        .cloned()
        .collect();
    let mut first = Ok(());
    for key in due {
        let answer = retry(host, &key);
        if first.is_ok() {
            first = answer;
        }
    }
    first
}

/// The signer's async handle on the host's blocking callbacks (Dispatch spec 3.1).
#[allow(dead_code)] // The store fixtures use this signer constructor in test builds.
pub(crate) fn store_handle(store: Arc<dyn HostStore>) -> StoreHandle {
    blocking_store(store, None)
}

/// A blocking handle with optional notification of completed releases (Dispatch spec 3.1).
pub(super) fn blocking_store(
    host: Arc<dyn HostStore>,
    released: Option<ReleaseNotice>,
) -> StoreHandle {
    StoreHandle::blocking(Arc::new(StoreAdapter { host, released }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_dispatch_client::store::MemoryStore;
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
        PanicRelease,
        ReleaseNotOwner,
        PanicAcquire,
        CallRelease,
    }

    fn exception() -> StoreFailure {
        uniffi::UnexpectedUniFFICallbackError::new("private callback text").into()
    }

    #[derive(Default)]
    struct State {
        /// The store's id, given at its first use: handles sharing this state are one store.
        store_id: Option<String>,
        records: MemoryStore,
        owners: BTreeMap<String, [u8; 32]>,
        fault: Option<Fault>,
        scan_reply: Option<Vec<StoreEntry>>,
        get_reply: Option<Vec<u8>>,
        calls: Vec<&'static str>,
        last_batch: Vec<Write>,
        /// The host call that next calls into the bindings, and for each such call
        /// whether it was refused.
        reenter: Option<&'static str>,
        refused: Vec<(&'static str, bool)>,
        /// What `release_owed_locks` answered when called from inside a callback.
        called_release: Option<Result<(), StoreFailure>>,
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
        /// The store's id, when a test gives one.
        id: Option<String>,
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
            if state.reenter == Some(name) {
                state.reenter = None;
                state
                    .refused
                    .push((name, runtime::refuse_reentry().is_err()));
            }
            state
        }

        fn holds(&self, namespace: &str) -> bool {
            self.state.lock().unwrap().owners.contains_key(namespace)
        }

        fn releases(&self) -> usize {
            let state = self.state.lock().unwrap();
            state
                .calls
                .iter()
                .filter(|call| **call == "release")
                .count()
        }

        /// The owners owed under `namespace` of this store.
        fn owed_all(&self, namespace: &str) -> Vec<StoreOwner> {
            let key = (self.store_id().unwrap(), namespace.to_owned());
            owed().get(&key).cloned().unwrap_or_default()
        }

        /// The first owner owed under `namespace` of this store, if any.
        fn owed(&self, namespace: &str) -> Option<StoreOwner> {
            self.owed_all(namespace).first().copied()
        }
    }

    fn token(bytes: Vec<u8>) -> Result<[u8; 32], StoreFailure> {
        bytes.try_into().map_err(|_| StoreFailure::Other)
    }

    impl HostStore for TestHost {
        // Handles sharing one state are handles of one store. Not recorded: the tests
        // call it themselves.
        fn store_id(&self) -> Result<String, StoreFailure> {
            let mut state = self.state.lock().unwrap();
            if state.reenter == Some("store_id") {
                state.reenter = None;
                state
                    .refused
                    .push(("store_id", runtime::refuse_reentry().is_err()));
            }
            // From a counter never reused in this process: an address can be given again to a
            // later test's store, which would then settle a release this one left owed.
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let id = state
                .store_id
                .get_or_insert_with(|| format!("store-{}", NEXT.fetch_add(1, Ordering::SeqCst)))
                .clone();
            Ok(self.id.clone().unwrap_or(id))
        }

        fn get(&self, ns: String, key: Vec<u8>) -> Result<Option<Vec<u8>>, StoreFailure> {
            let mut state = self.call("get");
            if matches!(state.fault, Some(Fault::CallRelease)) {
                state.fault = None;
                let host = Box::new(self.sharing());
                drop(state);
                let answer = Handle::current().block_on(release_owed_locks(host));
                state = self.state.lock().unwrap();
                state.called_release = Some(answer);
            }
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
            let panics = matches!(state.fault, Some(Fault::PanicAcquire));
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
            if panics {
                state.fault = None;
                drop(state);
                panic!("a host fault");
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
            if matches!(state.fault, Some(Fault::PanicRelease)) {
                state.fault = None;
                drop(state);
                panic!("a host fault");
            }
            // Kept: every later release answers NotOwner too.
            if matches!(state.fault, Some(Fault::ReleaseNotOwner)) {
                return Err(StoreFailure::NotOwner);
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

    /// [`release_owed_locks`] for `host`, on a blocking thread.
    async fn end(host: &Arc<TestHost>) -> Result<(), StoreFailure> {
        let host = host.clone();
        tokio::task::spawn_blocking(move || release_owed_now(host.as_ref()))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_store_dropped_without_an_end_opens_again_at_once() {
        // A host lets the last handle go without ending it and opens again on the same
        // store at once. Whatever the drop's own release does by then, here refused, the
        // acquisition settles what is owed first, then acquires, and reads the same records.
        let host = Arc::new(TestHost::default());
        let mut owner = store_handle(host.clone()).acquire("again").await.unwrap();
        owner.commit(put("again", b"kept")).await.unwrap();
        host.closed.store(true, Ordering::SeqCst);
        drop(owner);
        let reopened = store_handle(Arc::new(host.sharing()))
            .acquire("again")
            .await
            .unwrap();
        assert!(reopened.get(b"k").await.unwrap() == Some(b"kept".to_vec()));
        assert_eq!(host.owed("again"), None);
    }

    #[tokio::test]
    async fn test_store_unconfirmed_release_holds_until_the_host_confirms() {
        let host = Arc::new(TestHost::default());
        assert_eq!(
            owe(&host, "held").await,
            Some(Err(StoreFailure::Unavailable))
        );
        // Never guessed free: the host still holds it for the first owner. The acquisition
        // answers the release's own failure, without asking the host for a second owner.
        let raw = store_handle(host.clone());
        assert!(matches!(
            raw.acquire("held").await,
            Err(StoreError::Unavailable)
        ));
        assert!(host.holds("held"));
        assert!(!host.state.lock().unwrap().calls[1..].contains(&"acquire"));
        host.closed.store(false, Ordering::SeqCst);
        // The one try before the next acquisition confirms it.
        let _held = raw.acquire("held").await.unwrap();
        assert_eq!(host.owed("held"), None);
    }

    #[tokio::test]
    async fn test_store_owed_releases_are_not_lost_to_one_another() {
        // A stale owner, inert once the host forgot it, drops after a newer owner's
        // release failed: both are owed, and the stale one's empty release settles only
        // itself.
        let host = Arc::new(TestHost::default());
        let (stale_notice, mut stale_released) = mpsc::unbounded_channel();
        let stale = blocking_store(host.clone(), Some(stale_notice))
            .acquire("both")
            .await
            .unwrap();
        host.state.lock().unwrap().owners.remove("both");
        let (notice, mut released) = mpsc::unbounded_channel();
        let newer = blocking_store(host.clone(), Some(notice))
            .acquire("both")
            .await
            .unwrap();
        host.closed.store(true, Ordering::SeqCst);
        drop(newer);
        assert!(
            tokio::time::timeout(WAIT, released.recv())
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let owed_newer = host.owed("both").unwrap();
        host.closed.store(false, Ordering::SeqCst);
        drop(stale);
        let stale_release = tokio::time::timeout(WAIT, stale_released.recv()).await;
        assert_eq!(stale_release.unwrap(), Some(Ok(())));
        assert_eq!(host.owed_all("both"), [owed_newer]);
        assert!(host.holds("both"));
        assert_eq!(end(&host).await, Ok(()));
        assert!(host.owed_all("both").is_empty() && !host.holds("both"));
    }

    #[tokio::test]
    async fn test_store_release_answered_not_owner_is_settled() {
        // An owner that holds nothing: NotOwner from the host is read as its release done,
        // never as a lock held for good.
        let host = Arc::new(TestHost::default());
        let owner = store_handle(host.clone()).acquire("gone").await.unwrap();
        host.state.lock().unwrap().owners.remove("gone");
        host.state.lock().unwrap().fault = Some(Fault::ReleaseNotOwner);
        drop(owner);
        let _reopened = store_handle(Arc::new(host.sharing()))
            .acquire("gone")
            .await
            .unwrap();
        assert!(host.owed_all("gone").is_empty());
    }

    #[tokio::test]
    async fn test_store_unknown_acquisition_stays_owed_until_released() {
        // The host acquired, then threw, and its release fails too: the owner is owed, and
        // the next acquisition settles it first.
        let host = Arc::new(TestHost::default());
        host.state.lock().unwrap().fault = Some(Fault::Exception);
        host.closed.store(true, Ordering::SeqCst);
        let raw = store_handle(host.clone());
        assert!(matches!(
            raw.acquire("unsure").await,
            Err(StoreError::Unknown)
        ));
        assert!(host.owed("unsure").is_some() && host.holds("unsure"));
        let _held = store_handle(Arc::new(host.sharing()))
            .acquire("unsure")
            .await
            .unwrap();
        assert!(host.owed_all("unsure").is_empty());
    }

    #[tokio::test]
    async fn test_store_panicking_acquisition_is_unknown_and_released() {
        let host = Arc::new(TestHost::default());
        host.state.lock().unwrap().fault = Some(Fault::PanicAcquire);
        let raw = store_handle(host.clone());
        assert!(matches!(
            raw.acquire("panic-acquire").await,
            Err(StoreError::Unknown)
        ));
        assert!(!host.holds("panic-acquire"));
        let _held = raw.acquire("panic-acquire").await.unwrap();
    }

    #[tokio::test]
    async fn test_store_every_host_call_is_marked_as_a_callback() {
        // Each host call made through the adapter, including the store's id and a lease's
        // release, refuses a call into the bindings from inside it.
        let host = Arc::new(TestHost::default());
        let raw = store_handle(host.clone());
        let reenter_at = |name: &'static str| host.state.lock().unwrap().reenter = Some(name);
        reenter_at("store_id");
        let mut owner = raw.acquire("marked").await.unwrap();
        reenter_at("acquire");
        drop(raw.acquire("other-marked").await.unwrap());
        reenter_at("get");
        owner.get(b"k").await.unwrap();
        reenter_at("scan");
        owner.scan(b"", None, 1).await.unwrap();
        reenter_at("commit_if");
        owner.commit(put("marked", b"x")).await.unwrap();
        reenter_at("commit");
        raw.commit(put("free", b"x")).await.unwrap();
        let (notice, mut released) = mpsc::unbounded_channel();
        let held = blocking_store(host.clone(), Some(notice))
            .acquire("release-marked")
            .await
            .unwrap();
        reenter_at("release");
        drop(held);
        tokio::time::timeout(WAIT, released.recv()).await.unwrap();
        let refused = host.state.lock().unwrap().refused.clone();
        for name in [
            "store_id",
            "acquire",
            "get",
            "scan",
            "commit_if",
            "commit",
            "release",
        ] {
            assert!(
                refused.contains(&(name, true)),
                "{name} wasn't marked: {refused:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_store_release_call_is_typed_and_refused_from_a_callback() {
        // The exported call: its failure typed as the host gave it, then its success; and
        // from inside a store callback, refused as unavailable without calling the host.
        let host = Arc::new(TestHost::default());
        assert!(owe(&host, "exported").await.unwrap().is_err());
        let store = || -> Box<dyn HostStore> { Box::new(host.sharing()) };
        let closed = Box::new(TestHost {
            state: host.state.clone(),
            closed: AtomicBool::new(true),
            ..TestHost::default()
        });
        assert_eq!(
            release_owed_locks(closed).await,
            Err(StoreFailure::Unavailable)
        );
        let releases = host.releases();
        host.state.lock().unwrap().fault = Some(Fault::CallRelease);
        store_handle(host.clone())
            .get("exported", b"k")
            .await
            .unwrap();
        let called = host.state.lock().unwrap().called_release.take();
        assert_eq!(called, Some(Err(StoreFailure::Unavailable)));
        assert_eq!(host.releases(), releases, "the host was called");
        assert_eq!(release_owed_locks(store()).await, Ok(()));
        assert!(!host.holds("exported"));
    }

    #[tokio::test]
    async fn test_store_id_out_of_bounds_fails_the_call() {
        for id in [String::new(), "x".repeat(257)] {
            let host = Arc::new(TestHost {
                id: Some(id),
                ..TestHost::default()
            });
            assert!(matches!(
                store_handle(host.clone()).acquire("ns").await,
                Err(StoreError::Other(_))
            ));
            assert!(!host.state.lock().unwrap().calls.contains(&"acquire"));
        }
    }

    #[tokio::test]
    async fn test_store_unconfirmed_release_waits_for_a_call() {
        // Nothing retries in the background: the release is tried again only at the
        // host's end, which reports each failure and can be called again.
        let host = Arc::new(TestHost::default());
        assert!(owe(&host, "later").await.unwrap().is_err());
        assert_eq!(host.releases(), 1);
        assert_eq!(end(&host).await, Err(StoreFailure::Unavailable));
        assert_eq!(end(&host).await, Err(StoreFailure::Unavailable));
        assert!(host.holds("later") && host.owed("later").is_some());
        host.closed.store(false, Ordering::SeqCst);
        assert_eq!(end(&host).await, Ok(()));
        assert!(!host.holds("later") && host.owed("later").is_none());
        // Nothing owed: no call to the host.
        let releases = host.releases();
        assert_eq!(end(&host).await, Ok(()));
        assert_eq!(host.releases(), releases);
    }

    #[tokio::test]
    async fn test_store_commit_waits_for_the_owed_release() {
        // A commit doesn't try the release: the namespace stays held until it is
        // confirmed, at the end or before an acquisition.
        let host = Arc::new(TestHost::default());
        assert!(owe(&host, "write").await.unwrap().is_err());
        host.closed.store(false, Ordering::SeqCst);
        let raw = store_handle(host.clone());
        assert_eq!(raw.commit(put("write", b"x")).await, Err(StoreError::InUse));
        assert_eq!(end(&host).await, Ok(()));
        raw.commit(put("write", b"x")).await.unwrap();
    }

    #[tokio::test]
    async fn test_store_new_handle_frees_an_owner_owed_through_a_closed_one() {
        // The handle the release was owed through stays closed; a new handle of the same
        // store frees that exact owner.
        let first = Arc::new(TestHost::default());
        assert!(owe(&first, "moved").await.unwrap().is_err());
        let second = Arc::new(first.sharing());
        let _held = store_handle(second.clone()).acquire("moved").await.unwrap();
        assert_eq!(second.owed("moved"), None);
    }

    #[tokio::test]
    async fn test_store_another_store_keeps_its_owed_release() {
        // An acquisition in another store of the same namespace settles nothing owed to
        // this one: once this store recovers, its owner is released and it acquires.
        let first = Arc::new(TestHost::default());
        assert!(owe(&first, "shared").await.unwrap().is_err());
        let owner = first.owed("shared").unwrap();
        let other = Arc::new(TestHost::default());
        let held = store_handle(other.clone()).acquire("shared").await.unwrap();
        assert_eq!(first.owed("shared"), Some(owner));
        assert!(first.holds("shared"));
        first.closed.store(false, Ordering::SeqCst);
        let _first = store_handle(first.clone()).acquire("shared").await.unwrap();
        assert_eq!(first.owed("shared"), None);
        drop(held);
    }

    #[tokio::test]
    async fn test_store_owed_release_is_settled_only_by_its_owner() {
        // A later owner of the key, released, leaves the earlier owner's release owed.
        let host = Arc::new(TestHost::default());
        assert!(owe(&host, "own").await.unwrap().is_err());
        let earlier = host.owed("own").unwrap();
        // Another owner's token, from another namespace's owed release.
        assert!(owe(&host, "elsewhere").await.unwrap().is_err());
        let later = host.owed("elsewhere").unwrap();
        assert_ne!(later, earlier);
        let key = (host.store_id().unwrap(), "own".to_owned());
        host.closed.store(false, Ordering::SeqCst);
        let releasing = host.clone();
        tokio::task::spawn_blocking(move || release(releasing.as_ref(), &key, later))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(host.owed("own"), Some(earlier));
        assert!(host.holds("own"));
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

    #[tokio::test]
    async fn test_store_panicking_release_stays_owed() {
        let host = Arc::new(TestHost::default());
        let (notice, mut released) = mpsc::unbounded_channel();
        let owner = blocking_store(host.clone(), Some(notice))
            .acquire("panic")
            .await
            .unwrap();
        host.state.lock().unwrap().fault = Some(Fault::PanicRelease);
        drop(owner);
        let first = tokio::time::timeout(WAIT, released.recv()).await.unwrap();
        assert_eq!(first, Some(Err(StoreFailure::Unknown)));
        assert!(host.owed("panic").is_some() && host.holds("panic"));
        assert_eq!(end(&host).await, Ok(()));
        assert!(!host.holds("panic"));
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
        assert!(host.holds("ns") && host.owed("ns").is_some());
        let next = tokio::runtime::Runtime::new().unwrap();
        // Its waiter gets an answer: the notice closes, never hangs.
        let notice = next.block_on(async { tokio::time::timeout(WAIT, released.recv()).await });
        assert_eq!(notice, Ok(None));
        next.block_on(store_handle(host.clone()).acquire("ns"))
            .unwrap();
    }

    #[tokio::test]
    async fn test_store_raw_conditional_commit_keeps_to_its_namespace() {
        // A caller holding the raw store skips the owned handle's check; the adapter's
        // own check keeps a foreign write from the host.
        let host = Arc::new(TestHost::default());
        // An owner's token, from an owed release.
        assert!(owe(&host, "ns").await.unwrap().is_err());
        let owner = host.owed("ns").unwrap();
        let handle = store_handle(host.clone());
        let foreign = put("other", b"x");
        let answer = tokio::task::spawn_blocking({
            let store = handle.store().clone();
            move || store.commit_if("ns", owner, foreign)
        })
        .await
        .unwrap();
        assert!(answer.is_err());
        assert!(!host.state.lock().unwrap().calls.contains(&"commit_if"));
    }

    #[tokio::test]
    async fn test_store_refuses_a_record_that_could_not_have_been_written() {
        let host = Arc::new(TestHost::default());
        let raw = store_handle(host.clone());
        let oversized = vec![0; usize::try_from(MAX_VALUE_BYTES).unwrap() + 1];
        host.state.lock().unwrap().get_reply = Some(oversized.clone());
        assert_eq!(raw.get("ns", b"k").await, Err(StoreError::Corrupt));
        // A key and a value that fill a batch, whose namespace takes it over.
        host.state.lock().unwrap().get_reply = Some(vec![0; 16 << 20]);
        assert_eq!(
            raw.get("n", &vec![0; 16 << 20]).await,
            Err(StoreError::Corrupt)
        );
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
