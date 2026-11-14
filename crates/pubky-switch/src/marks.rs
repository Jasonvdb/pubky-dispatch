//! The per-account mark store (Switch spec 6.5, Switch wire 7.3 "Accounts and marks").
//!
//! For each identity it holds an account for, the service keeps one mark, apart from the
//! state a backup restores: the newest head it signed for the identity (generation, `seq`,
//! chain hash), the service key the account is answered with, and the time the account was
//! created. Beside the marks lie the retirements of generations, one-way. The store lies in
//! `accounts/` under the key store's directory, which no backup of the state restores:
//!
//! - `accounts/store-id`: the store's identity, 16 random bytes in hex, written with the
//!   directory. A directory without a readable one is a store that can't be read; a store
//!   rebuilt after its loss has a new one, and every mark in it reads as missing.
//! - `accounts/marks/<identity>`: the identity's mark, in JSON.
//! - `accounts/retired/<identity>.<generation>`: an empty file per retired generation.
//!
//! Every write is a temporary file, synced, renamed into place, then its directory synced,
//! and is durable before its call returns. A write that fails after its rename landed and
//! before its directory sync isn't taken up: the store keeps in memory what it last wrote
//! durably, so a retry writes and syncs again before it reports success, and the store
//! syncs its directories when it opens, before it reads them. Every read-check-write runs
//! under one lock inside a blocking task, which runs to its end even if its caller stops
//! waiting.

use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use parking_lot::Mutex;
use pubky_switch_core::chain::{ChainTip, ZERO_HASH};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::keys::Faults;
use crate::keys::{
    KeyStoreError, create_private_dir, hex_bytes, is_ledger_name, is_temp_file, rename_into_place,
    sync_dir,
};

/// The largest mark file the store reads, in bytes; a larger one doesn't read as a mark.
const MAX_MARK_FILE: u64 = 4096;

/// An identity's mark (Switch wire 7.3, "Accounts and marks").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountMark {
    /// The generation of the newest head signed for the identity, 0 before any.
    pub generation: u64,
    /// That head's `seq`, 0 before any.
    pub seq: u64,
    /// The chain hash at `seq`, zero before any head.
    #[serde(with = "hex_bytes")]
    pub chain_hash: [u8; 32],
    /// The service key the account is answered with.
    #[serde(with = "hex_bytes")]
    pub key: [u8; 32],
    /// When the account was created, in Unix milliseconds.
    pub created_at_ms: u64,
}

impl AccountMark {
    /// A mark that has recorded no head: (0, 0).
    pub fn zero(key: [u8; 32], created_at_ms: u64) -> Self {
        Self {
            generation: 0,
            seq: 0,
            chain_hash: ZERO_HASH,
            key,
            created_at_ms,
        }
    }

    /// The head it records, (0, 0) with the zero hash before any.
    pub fn head(&self) -> ChainTip {
        ChainTip {
            generation: self.generation,
            seq: self.seq,
            chain_hash: self.chain_hash,
        }
    }

    /// Whether it records a head, rather than being (0, 0).
    pub fn records_head(&self) -> bool {
        self.generation != 0
    }

    /// Whether it is a mark some writer stores: (0, 0) with the zero hash, or a head at a
    /// generation and a `seq` of at least 1 each.
    fn is_valid(&self) -> bool {
        if self.generation == 0 {
            self.seq == 0 && self.chain_hash == ZERO_HASH
        } else {
            self.seq != 0
        }
    }
}

/// Whether `head` is one a mark can move to: generation and `seq` at least 1 each.
fn is_head(head: &ChainTip) -> bool {
    head.generation != 0 && head.seq != 0
}

/// What the store holds for an identity, when the store can be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkRead {
    /// No mark.
    Missing,
    /// A file that doesn't read as a mark: corrupt, or of a shape no writer stores.
    NotAMark,
    /// The mark.
    Mark(AccountMark),
}

/// The outcome of a write that applies only to some of what the store holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkWrite {
    /// The store now holds this mark, durably.
    Written(AccountMark),
    /// The write doesn't apply to what the store holds, which it left as it is.
    Unchanged(MarkRead),
}

/// The outcome of [`MarkStore::advance`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Advance {
    /// The mark moved to the head, durably.
    Moved(AccountMark),
    /// The mark is at the head already, with its chain hash.
    Unchanged(AccountMark),
    /// The mark is past the head: a later move overtook it. The mark stays.
    Overtaken(AccountMark),
    /// The mark is at the head's pair with another chain hash: a fork, refused.
    Fork(AccountMark),
    /// The identity has no mark to move ([`MarkStore::write_anew`] writes one).
    NoMark(MarkRead),
}

/// What the mark store can fail at.
#[derive(Debug, thiserror::Error)]
pub enum MarkStoreError {
    /// The store can't be read: its directory or its identity record is missing, can't be
    /// read or changed, or it holds a file no writer makes.
    #[error("the mark store can't be read: {0}")]
    StoreUnreadable(String),
    /// An identity that can't name a file of the store.
    #[error("invalid identity")]
    InvalidIdentity,
    /// A head a mark can't move to: generation or `seq` 0.
    #[error("invalid head for a mark")]
    InvalidHead,
    /// The storage failed.
    #[error("mark store storage: {0}")]
    Io(#[from] std::io::Error),
    /// No randomness for the store's identity or a temporary file's name.
    #[error("no randomness")]
    Random,
}

impl From<KeyStoreError> for MarkStoreError {
    fn from(error: KeyStoreError) -> Self {
        match error {
            KeyStoreError::Io(error) => Self::Io(error),
            KeyStoreError::Random => Self::Random,
            KeyStoreError::InvalidId => Self::InvalidIdentity,
            other => Self::Io(std::io::Error::other(other.to_string())),
        }
    }
}

/// The per-account mark store, in `accounts/` under the key store's directory.
///
/// One process at a time may use the directory: the key store's lock
/// ([`crate::keys::FileKeyStore::lock_dir`]) holds it.
#[derive(Clone)]
pub struct MarkStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for MarkStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarkStore")
            .field("root", &self.inner.root)
            .finish_non_exhaustive()
    }
}

struct Inner {
    /// The key store's directory.
    root: PathBuf,
    /// The store's identity, once read; `None` while the store can't be read. Each call
    /// tries again, so a store that comes back is read again, every cache refilled.
    store_id: Mutex<Option<String>>,
    /// What the store last held durably for each identity read. The lock is held from a
    /// miss through the file read to the insert, and every write fills it before it
    /// writes, so a read never takes up a file whose directory sync failed, nor puts an
    /// older mark over a newer one.
    marks: Mutex<HashMap<String, MarkRead>>,
    /// Every retirement, read whole when the store is read, so a check needs no file read.
    /// It takes a retirement once its file is durable.
    retired: Mutex<HashMap<String, BTreeSet<u64>>>,
    /// Held around every read-check-write, inside the blocking task that does it, and
    /// before `store_id`, `marks` and `retired`. A caller that stops waiting can't release
    /// it early: the task runs to its end, so writes land in the order they were checked.
    writes: Mutex<()>,
    /// Fails directory syncs and tracks what a crash would undo, for tests.
    #[cfg(test)]
    faults: Arc<Mutex<Faults>>,
}

impl MarkStore {
    /// Open the mark store under the key store's directory `root`. Where `accounts/`
    /// doesn't exist, it is made whole with a new identity record, in a temporary directory
    /// renamed into place, so a crash never leaves a directory without one. A store that
    /// exists and can't be read opens all the same: each call answers
    /// [`MarkStoreError::StoreUnreadable`] until it can be read.
    ///
    /// # Errors
    ///
    /// When `root` or a new store can't be made.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, MarkStoreError> {
        Self::start(Inner::new(root.into()))
    }

    #[cfg(test)]
    fn open_with_faults(
        root: impl Into<PathBuf>,
        faults: Arc<Mutex<Faults>>,
    ) -> Result<Self, MarkStoreError> {
        let mut inner = Inner::new(root.into());
        inner.faults = faults;
        Self::start(inner)
    }

    fn start(inner: Inner) -> Result<Self, MarkStoreError> {
        create_private_dir(&inner.root)?;
        inner.remove_leftover_temp_dirs();
        match fs::symlink_metadata(inner.accounts()) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => inner.create_store()?,
            // Read again, and refused, by the first call.
            Err(_) => {}
        }
        {
            let _writes = inner.writes.lock();
            // A store that can't be read yet stays so; each call tries again.
            let _ = inner.readable_locked();
        }
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The identity's mark: [`MarkRead::Missing`], [`MarkRead::NotAMark`] or the mark.
    ///
    /// # Errors
    ///
    /// The store can't be read; [`MarkStoreError::InvalidIdentity`].
    pub async fn read(&self, identity: &str) -> Result<MarkRead, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || inner.read_sync(&identity)).await
    }

    /// Write (0, 0) with `key` and `created_at_ms` where the identity has no mark, or a file
    /// that doesn't read as one (Switch wire 7.3, Table 3: an enrollment that creates an
    /// account at an identity without a mark). A mark it holds stays.
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`].
    pub async fn create_zero(
        &self,
        identity: &str,
        key: [u8; 32],
        created_at_ms: u64,
    ) -> Result<MarkWrite, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.write_sync(&identity, |held| match held {
                MarkRead::Missing | MarkRead::NotAMark => {
                    Some(AccountMark::zero(key, created_at_ms))
                }
                MarkRead::Mark(_) => None,
            })
        })
        .await
    }

    /// A new account takes the identity's mark: its generation, `seq` and chain hash stay,
    /// as do the identity's retirements; its key and creation time become `key` and
    /// `created_at_ms` (Switch wire 7.3, Table 3). Without a mark nothing changes.
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`].
    pub async fn take(
        &self,
        identity: &str,
        key: [u8; 32],
        created_at_ms: u64,
    ) -> Result<MarkWrite, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.write_sync(&identity, |held| match held {
                MarkRead::Mark(mark) => Some(AccountMark {
                    key,
                    created_at_ms,
                    ..mark
                }),
                MarkRead::Missing | MarkRead::NotAMark => None,
            })
        })
        .await
    }

    /// The mark's key becomes `key`, its head and creation time staying (Switch wire 7.3,
    /// Table 3: an enrollment at a staged account that no document names yet, after a
    /// service key change). Without a mark, or with that key already, nothing changes.
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`].
    pub async fn set_key(
        &self,
        identity: &str,
        key: [u8; 32],
    ) -> Result<MarkWrite, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.write_sync(&identity, |held| match held {
                MarkRead::Mark(mark) if mark.key != key => Some(AccountMark { key, ..mark }),
                MarkRead::Mark(_) | MarkRead::Missing | MarkRead::NotAMark => None,
            })
        })
        .await
    }

    /// Move the identity's mark to `head`, answered with `key`, once the commit that holds
    /// the head is durable (Switch wire 7.3, "Moving it"). The mark moves only to a higher
    /// (generation, `seq`), durably before this returns; at the same head it stays, behind
    /// a later one it stays, and at the head's pair with another chain hash it is refused.
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`];
    /// [`MarkStoreError::InvalidHead`] for a head at generation or `seq` 0.
    pub async fn advance(
        &self,
        identity: &str,
        head: ChainTip,
        key: [u8; 32],
    ) -> Result<Advance, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        if !is_head(&head) {
            return Err(MarkStoreError::InvalidHead);
        }
        blocking(move || inner.advance_sync(&identity, head, key)).await
    }

    /// Write the mark anew at `head`, with `key` and `created_at_ms`, where the identity's
    /// mark is lost: missing, or a file that doesn't read as a mark (Switch wire 7.3,
    /// Table 3: a delivery that starts a generation where the mark is lost). A mark it
    /// holds stays: [`MarkStore::advance`] moves it.
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`];
    /// [`MarkStoreError::InvalidHead`] for a head at generation or `seq` 0.
    pub async fn write_anew(
        &self,
        identity: &str,
        head: ChainTip,
        key: [u8; 32],
        created_at_ms: u64,
    ) -> Result<MarkWrite, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        if !is_head(&head) {
            return Err(MarkStoreError::InvalidHead);
        }
        blocking(move || {
            inner.write_sync(&identity, |held| match held {
                MarkRead::Missing | MarkRead::NotAMark => Some(AccountMark {
                    generation: head.generation,
                    seq: head.seq,
                    chain_hash: head.chain_hash,
                    key,
                    created_at_ms,
                }),
                MarkRead::Mark(_) => None,
            })
        })
        .await
    }

    /// Delete the identity's mark, or the file that doesn't read as one, durably. The
    /// identity's retirements stay.
    ///
    /// # Errors
    ///
    /// The store can't be read or the removal failed; [`MarkStoreError::InvalidIdentity`].
    pub async fn delete(&self, identity: &str) -> Result<(), MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || inner.delete_sync(&identity, None).map(|_| ())).await
    }

    /// Delete the identity's mark, durably, only where it was created at or before `at_ms`
    /// (Switch wire 7.3, Table 3: an account erased again deletes only a mark its erasure's
    /// record covers; a later account's mark stays). Answers whether it deleted one; a file
    /// that doesn't read as a mark stays.
    ///
    /// # Errors
    ///
    /// The store can't be read or the removal failed; [`MarkStoreError::InvalidIdentity`].
    pub async fn delete_created_by(
        &self,
        identity: &str,
        at_ms: u64,
    ) -> Result<bool, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || inner.delete_sync(&identity, Some(at_ms))).await
    }

    /// Record the retirement of `generation` for the identity, durably (Switch spec 6.5).
    /// One-way: nothing removes it but a rebuilt store. Also where the identity has no
    /// mark.
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`].
    pub async fn retire(&self, identity: &str, generation: u64) -> Result<(), MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || inner.retire_sync(&identity, generation)).await
    }

    /// The identity's retired generations, ascending.
    ///
    /// # Errors
    ///
    /// The store can't be read; [`MarkStoreError::InvalidIdentity`].
    pub async fn retired(&self, identity: &str) -> Result<Vec<u64>, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.reading(|_| {
                Ok(inner
                    .retired
                    .lock()
                    .get(&identity)
                    .map(|generations| generations.iter().copied().collect())
                    .unwrap_or_default())
            })
        })
        .await
    }

    /// Every identity with a mark file, a file that doesn't read as a mark included,
    /// ascending.
    ///
    /// # Errors
    ///
    /// The store can't be read, or its marks directory holds a file that names no
    /// identity.
    pub async fn list(&self) -> Result<Vec<String>, MarkStoreError> {
        let inner = self.inner.clone();
        blocking(move || inner.reading(|_| list_marks(&inner.marks_dir()))).await
    }
}

impl Inner {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            store_id: Mutex::new(None),
            marks: Mutex::new(HashMap::new()),
            retired: Mutex::new(HashMap::new()),
            writes: Mutex::new(()),
            #[cfg(test)]
            faults: Arc::default(),
        }
    }

    fn accounts(&self) -> PathBuf {
        self.root.join("accounts")
    }

    fn marks_dir(&self) -> PathBuf {
        self.accounts().join("marks")
    }

    fn retired_dir(&self) -> PathBuf {
        self.accounts().join("retired")
    }

    fn mark_path(&self, identity: &str) -> PathBuf {
        self.marks_dir().join(identity)
    }

    fn retired_path(&self, identity: &str, generation: u64) -> PathBuf {
        self.retired_dir().join(format!("{identity}.{generation}"))
    }

    /// Sync `dir`, so a rename or a removal in it is durable.
    fn sync_dir(&self, dir: &Path) -> Result<(), MarkStoreError> {
        #[cfg(test)]
        if self.faults.lock().fails(dir) {
            return Err(std::io::Error::other("injected directory sync failure").into());
        }
        sync_dir(dir)?;
        #[cfg(test)]
        self.faults.lock().synced(dir);
        Ok(())
    }

    /// Write `bytes` to `path` atomically and durably: a temporary file, synced, renamed
    /// into place, then the directory synced.
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), MarkStoreError> {
        let dir = path
            .parent()
            .ok_or_else(|| MarkStoreError::Io(std::io::Error::other("path without a directory")))?;
        #[cfg(test)]
        let before = fs::read(path).ok();
        rename_into_place(dir, path, bytes, false)?;
        #[cfg(test)]
        self.faults.lock().changed(path, before);
        self.sync_dir(dir)
    }

    /// Remove the file at `path` if it is there, then sync its directory, also when it was
    /// already gone: an earlier removal may have landed without its sync.
    fn remove_durably(&self, path: &Path) -> Result<(), MarkStoreError> {
        #[cfg(test)]
        let before = fs::read(path).ok();
        match fs::remove_file(path) {
            Ok(()) => {
                #[cfg(test)]
                self.faults.lock().changed(path, before);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let dir = path
            .parent()
            .ok_or_else(|| MarkStoreError::Io(std::io::Error::other("path without a directory")))?;
        self.sync_dir(dir)
    }

    /// Temporary directories of a store creation a crash cut short.
    fn remove_leftover_temp_dirs(&self) {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with(".accounts.")
                && name.ends_with(".tmp")
                && entry.file_type().is_ok_and(|kind| kind.is_dir())
            {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }

    /// Make `accounts/` with a new identity record and its two directories, whole: built
    /// in a temporary directory, synced, renamed into place and the root synced.
    fn create_store(&self) -> Result<(), MarkStoreError> {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).map_err(|_| MarkStoreError::Random)?;
        let id = hex::encode(raw);
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).map_err(|_| MarkStoreError::Random)?;
        let temp = self
            .root
            .join(format!(".accounts.{}.tmp", hex::encode(suffix)));
        let result: Result<(), MarkStoreError> = (|| {
            create_private_dir(&temp)?;
            for dir in ["marks", "retired"] {
                create_private_dir(&temp.join(dir))?;
                self.sync_dir(&temp.join(dir))?;
            }
            rename_into_place(&temp, &temp.join("store-id"), id.as_bytes(), false)?;
            self.sync_dir(&temp)?;
            fs::rename(&temp, self.accounts())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temp);
        }
        result?;
        self.sync_dir(&self.root)
    }

    /// The store's identity, reading the store first where it couldn't be read. The caller
    /// holds `writes`.
    fn readable_locked(&self) -> Result<String, MarkStoreError> {
        let mut store_id = self.store_id.lock();
        if let Some(id) = store_id.as_ref() {
            return Ok(id.clone());
        }
        // An earlier process, or an earlier call, may have landed a rename or a removal
        // and stopped before its directory sync: sync every directory before reading any.
        let accounts = self.accounts();
        for dir in [self.marks_dir(), self.retired_dir(), accounts.clone()] {
            self.sync_dir(&dir).map_err(|error| {
                MarkStoreError::StoreUnreadable(format!("{}: {error}", dir.display()))
            })?;
        }
        self.sync_dir(&self.root)?;
        let id = read_store_id(&accounts)?;
        let retired = read_retired(&self.retired_dir())?;
        *self.retired.lock() = retired;
        self.marks.lock().clear();
        *store_id = Some(id.clone());
        Ok(id)
    }

    /// Run `read` once the store can be read, without holding `writes` while it can.
    fn reading<T>(
        &self,
        read: impl FnOnce(&str) -> Result<T, MarkStoreError>,
    ) -> Result<T, MarkStoreError> {
        let known = self.store_id.lock().clone();
        let id = match known {
            Some(id) => id,
            None => {
                let _writes = self.writes.lock();
                self.readable_locked()?
            }
        };
        let result = read(&id);
        self.forget_store_on(&result);
        result
    }

    /// Run `write` under `writes`, once the store can be read.
    fn writing<T>(
        &self,
        write: impl FnOnce(&str) -> Result<T, MarkStoreError>,
    ) -> Result<T, MarkStoreError> {
        let _writes = self.writes.lock();
        let id = self.readable_locked()?;
        let result = write(&id);
        self.forget_store_on(&result);
        result
    }

    /// A store found unreadable mid-call is read whole again by the next call.
    fn forget_store_on<T>(&self, result: &Result<T, MarkStoreError>) {
        if matches!(result, Err(MarkStoreError::StoreUnreadable(_))) {
            *self.store_id.lock() = None;
        }
    }

    /// The identity's mark as last held durably: from memory, or from its file once the
    /// store's identity record is confirmed unchanged. The cache's lock is held from the
    /// miss through the read to the insert.
    fn load_mark(&self, identity: &str, store_id: &str) -> Result<MarkRead, MarkStoreError> {
        let mut marks = self.marks.lock();
        if let Some(held) = marks.get(identity) {
            return Ok(*held);
        }
        // A missing mark counts as missing only in the store it was looked for in.
        if read_store_id(&self.accounts())? != store_id {
            return Err(MarkStoreError::StoreUnreadable(
                "the store's identity changed".into(),
            ));
        }
        let held = read_mark_file(&self.mark_path(identity))?;
        marks.insert(identity.to_string(), held);
        Ok(held)
    }

    fn read_sync(&self, identity: &str) -> Result<MarkRead, MarkStoreError> {
        self.reading(|id| self.load_mark(identity, id))
    }

    /// Write what `next` makes of the mark held, if anything, durably, then hold it.
    fn write_sync(
        &self,
        identity: &str,
        next: impl FnOnce(MarkRead) -> Option<AccountMark>,
    ) -> Result<MarkWrite, MarkStoreError> {
        self.writing(|id| {
            let held = self.load_mark(identity, id)?;
            match next(held) {
                Some(mark) => {
                    self.put_mark(identity, mark)?;
                    Ok(MarkWrite::Written(mark))
                }
                None => Ok(MarkWrite::Unchanged(held)),
            }
        })
    }

    /// Write `mark` durably, then hold it in memory. The caller holds `writes` and loaded
    /// the identity's mark first.
    fn put_mark(&self, identity: &str, mark: AccountMark) -> Result<(), MarkStoreError> {
        let bytes = serde_json::to_vec(&mark)
            .map_err(|error| MarkStoreError::Io(std::io::Error::other(error.to_string())))?;
        self.write_atomic(&self.mark_path(identity), &bytes)?;
        self.marks
            .lock()
            .insert(identity.to_string(), MarkRead::Mark(mark));
        Ok(())
    }

    fn advance_sync(
        &self,
        identity: &str,
        head: ChainTip,
        key: [u8; 32],
    ) -> Result<Advance, MarkStoreError> {
        self.writing(|id| {
            let mark = match self.load_mark(identity, id)? {
                MarkRead::Mark(mark) => mark,
                held => return Ok(Advance::NoMark(held)),
            };
            let held = (mark.generation, mark.seq);
            let new = (head.generation, head.seq);
            if new < held {
                return Ok(Advance::Overtaken(mark));
            }
            if new == held {
                return Ok(if head.chain_hash == mark.chain_hash {
                    Advance::Unchanged(mark)
                } else {
                    Advance::Fork(mark)
                });
            }
            let moved = AccountMark {
                generation: head.generation,
                seq: head.seq,
                chain_hash: head.chain_hash,
                key,
                created_at_ms: mark.created_at_ms,
            };
            self.put_mark(identity, moved)?;
            Ok(Advance::Moved(moved))
        })
    }

    fn delete_sync(&self, identity: &str, created_by: Option<u64>) -> Result<bool, MarkStoreError> {
        self.writing(|id| {
            let held = self.load_mark(identity, id)?;
            if let Some(at_ms) = created_by {
                match held {
                    MarkRead::Mark(mark) if mark.created_at_ms <= at_ms => {}
                    MarkRead::Mark(_) | MarkRead::NotAMark | MarkRead::Missing => {
                        return Ok(false);
                    }
                }
            }
            // Removed and synced also when memory holds it missing: the barrier costs a
            // sync, and an earlier removal may have landed without one.
            self.remove_durably(&self.mark_path(identity))?;
            self.marks
                .lock()
                .insert(identity.to_string(), MarkRead::Missing);
            Ok(!matches!(held, MarkRead::Missing))
        })
    }

    fn retire_sync(&self, identity: &str, generation: u64) -> Result<(), MarkStoreError> {
        self.writing(|_| {
            let held = self
                .retired
                .lock()
                .get(identity)
                .is_some_and(|generations| generations.contains(&generation));
            if held {
                // Memory holds only a retirement whose file is durable.
                return Ok(());
            }
            self.write_atomic(&self.retired_path(identity, generation), b"")?;
            self.retired
                .lock()
                .entry(identity.to_string())
                .or_default()
                .insert(generation);
            Ok(())
        })
    }
}

/// A read-only view of the mark store, for an operator's check beside a running service: it
/// creates, writes, syncs and locks nothing, and reads each mark as its file is then. The
/// retirements are read once, when it opens.
#[derive(Debug)]
pub struct MarkView {
    accounts: PathBuf,
    store_id: String,
    retired: HashMap<String, BTreeSet<u64>>,
}

impl MarkView {
    /// Open the view of the mark store under the key store's directory `root`.
    ///
    /// # Errors
    ///
    /// [`MarkStoreError::StoreUnreadable`] when the store isn't there or can't be read.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, MarkStoreError> {
        let accounts = root.as_ref().join("accounts");
        let store_id = read_store_id(&accounts)?;
        let retired = read_retired(&accounts.join("retired"))?;
        Ok(Self {
            accounts,
            store_id,
            retired,
        })
    }

    /// The identity's mark as its file holds it now.
    ///
    /// # Errors
    ///
    /// The store can't be read, or its identity changed since the view opened;
    /// [`MarkStoreError::InvalidIdentity`].
    pub fn read(&self, identity: &str) -> Result<MarkRead, MarkStoreError> {
        let identity = valid_identity(identity)?;
        if read_store_id(&self.accounts)? != self.store_id {
            return Err(MarkStoreError::StoreUnreadable(
                "the store's identity changed".into(),
            ));
        }
        read_mark_file(&self.accounts.join("marks").join(identity))
    }

    /// The identity's retired generations, ascending, as the view read them.
    pub fn retired(&self, identity: &str) -> Vec<u64> {
        self.retired
            .get(identity)
            .map(|generations| generations.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Every identity with a mark file now, ascending.
    ///
    /// # Errors
    ///
    /// The store can't be read.
    pub fn list(&self) -> Result<Vec<String>, MarkStoreError> {
        list_marks(&self.accounts.join("marks"))
    }
}

/// Run blocking file work off the async runtime; it runs to its end even if the caller
/// stops waiting.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, MarkStoreError> + Send + 'static,
) -> Result<T, MarkStoreError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| MarkStoreError::Io(std::io::Error::other(error.to_string())))?
}

fn valid_identity(identity: &str) -> Result<String, MarkStoreError> {
    if is_ledger_name(identity) {
        Ok(identity.to_string())
    } else {
        Err(MarkStoreError::InvalidIdentity)
    }
}

/// The store's identity record in `accounts`: 32 lowercase hex characters.
fn read_store_id(accounts: &Path) -> Result<String, MarkStoreError> {
    let bytes = fs::read(accounts.join("store-id"))
        .map_err(|error| MarkStoreError::StoreUnreadable(format!("store-id: {error}")))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| MarkStoreError::StoreUnreadable("store-id isn't UTF-8".into()))?;
    if text.len() == 32
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(text)
    } else {
        Err(MarkStoreError::StoreUnreadable(
            "store-id isn't 16 bytes in hex".into(),
        ))
    }
}

/// Every retirement in `dir`. A write's temporary file isn't one; any other file that
/// doesn't name an identity and a generation makes the store unreadable.
fn read_retired(dir: &Path) -> Result<HashMap<String, BTreeSet<u64>>, MarkStoreError> {
    let mut retired: HashMap<String, BTreeSet<u64>> = HashMap::new();
    let entries = fs::read_dir(dir)
        .map_err(|error| MarkStoreError::StoreUnreadable(format!("retired: {error}")))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| MarkStoreError::StoreUnreadable(format!("retired: {error}")))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(MarkStoreError::StoreUnreadable(
                "retired: a file name isn't UTF-8".into(),
            ));
        };
        if is_temp_file(name) {
            continue;
        }
        let parsed = name.split_once('.').and_then(|(identity, generation)| {
            let value = generation.parse::<u64>().ok()?;
            (is_ledger_name(identity) && value.to_string() == generation)
                .then(|| (identity.to_string(), value))
        });
        let Some((identity, generation)) = parsed else {
            return Err(MarkStoreError::StoreUnreadable(format!(
                "retired: {name} names no retirement"
            )));
        };
        retired.entry(identity).or_default().insert(generation);
    }
    Ok(retired)
}

/// Every identity with a file in `dir`, ascending.
fn list_marks(dir: &Path) -> Result<Vec<String>, MarkStoreError> {
    let entries = fs::read_dir(dir)
        .map_err(|error| MarkStoreError::StoreUnreadable(format!("marks: {error}")))?;
    let mut identities = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| MarkStoreError::StoreUnreadable(format!("marks: {error}")))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(MarkStoreError::StoreUnreadable(
                "marks: a file name isn't UTF-8".into(),
            ));
        };
        if is_temp_file(name) {
            continue;
        }
        if !is_ledger_name(name) {
            return Err(MarkStoreError::StoreUnreadable(format!(
                "marks: {name} names no identity"
            )));
        }
        identities.push(name.to_string());
    }
    identities.sort();
    Ok(identities)
}

/// Read the mark file at `path`.
fn read_mark_file(path: &Path) -> Result<MarkRead, MarkStoreError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MarkRead::Missing);
        }
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_MARK_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MARK_FILE {
        return Ok(MarkRead::NotAMark);
    }
    Ok(match serde_json::from_slice::<AccountMark>(&bytes) {
        Ok(mark) if mark.is_valid() => MarkRead::Mark(mark),
        Ok(_) | Err(_) => MarkRead::NotAMark,
    })
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use super::*;

    const ALICE: &str = "alice";
    const BOB: &str = "bob";
    const KEY: [u8; 32] = [7; 32];
    const OTHER_KEY: [u8; 32] = [8; 32];

    fn head(generation: u64, seq: u64, hash: u8) -> ChainTip {
        ChainTip {
            generation,
            seq,
            chain_hash: [hash; 32],
        }
    }

    fn mark_at(generation: u64, seq: u64, hash: u8, created_at_ms: u64) -> AccountMark {
        AccountMark {
            generation,
            seq,
            chain_hash: [hash; 32],
            key: KEY,
            created_at_ms,
        }
    }

    fn open() -> (tempfile::TempDir, MarkStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = MarkStore::open(dir.path()).expect("open");
        (dir, store)
    }

    fn open_faulty() -> (tempfile::TempDir, MarkStore, Arc<Mutex<Faults>>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let faults = Arc::new(Mutex::new(Faults::default()));
        let store = MarkStore::open_with_faults(dir.path(), faults.clone()).expect("open");
        (dir, store, faults)
    }

    fn crash_and_reopen(dir: &tempfile::TempDir, faults: &Arc<Mutex<Faults>>) -> MarkStore {
        faults.lock().crash();
        MarkStore::open_with_faults(dir.path(), faults.clone()).expect("reopen")
    }

    fn marks_dir(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("accounts").join("marks")
    }

    async fn with_mark(store: &MarkStore, identity: &str, at: ChainTip) -> AccountMark {
        store.create_zero(identity, KEY, 100).await.expect("zero");
        match store.advance(identity, at, KEY).await.expect("advance") {
            Advance::Moved(mark) => mark,
            other => panic!("not moved: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_marks_new_store_reads_missing() {
        let (dir, store) = open();
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
        let id = fs::read_to_string(dir.path().join("accounts").join("store-id")).expect("id");
        assert_eq!(id.len(), 32);
        assert!(store.list().await.expect("list").is_empty());
        assert!(store.retired(ALICE).await.expect("retired").is_empty());
    }

    #[tokio::test]
    async fn test_marks_create_zero_writes_zero_and_keeps_a_mark() {
        let (dir, store) = open();
        let zero = AccountMark::zero(KEY, 100);
        assert_eq!(
            store.create_zero(ALICE, KEY, 100).await.expect("create"),
            MarkWrite::Written(zero)
        );
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(zero));
        assert_eq!(
            store
                .create_zero(ALICE, OTHER_KEY, 200)
                .await
                .expect("again"),
            MarkWrite::Unchanged(MarkRead::Mark(zero))
        );
        drop(store);
        let store = MarkStore::open(dir.path()).expect("reopen");
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(zero));
    }

    #[tokio::test]
    async fn test_marks_create_zero_replaces_a_file_that_is_not_a_mark() {
        let (dir, store) = open();
        fs::write(marks_dir(&dir).join(ALICE), b"not json").expect("write");
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::NotAMark);
        assert_eq!(
            store.create_zero(ALICE, KEY, 100).await.expect("create"),
            MarkWrite::Written(AccountMark::zero(KEY, 100))
        );
    }

    #[tokio::test]
    async fn test_marks_take_keeps_head_and_retirements() {
        let (_dir, store) = open();
        let mark = with_mark(&store, ALICE, head(2, 9, 1)).await;
        store.retire(ALICE, 2).await.expect("retire");
        let taken = AccountMark {
            key: OTHER_KEY,
            created_at_ms: 500,
            ..mark
        };
        assert_eq!(
            store.take(ALICE, OTHER_KEY, 500).await.expect("take"),
            MarkWrite::Written(taken)
        );
        assert_eq!(
            store.read(ALICE).await.expect("read"),
            MarkRead::Mark(taken)
        );
        assert_eq!(store.retired(ALICE).await.expect("retired"), vec![2]);
    }

    #[tokio::test]
    async fn test_marks_take_without_a_mark_changes_nothing() {
        let (dir, store) = open();
        assert_eq!(
            store.take(ALICE, KEY, 500).await.expect("take"),
            MarkWrite::Unchanged(MarkRead::Missing)
        );
        fs::write(marks_dir(&dir).join(BOB), b"{}").expect("write");
        assert_eq!(
            store.take(BOB, KEY, 500).await.expect("take"),
            MarkWrite::Unchanged(MarkRead::NotAMark)
        );
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
    }

    #[tokio::test]
    async fn test_marks_set_key_changes_only_the_key() {
        let (_dir, store) = open();
        let mark = with_mark(&store, ALICE, head(1, 3, 1)).await;
        let changed = AccountMark {
            key: OTHER_KEY,
            ..mark
        };
        assert_eq!(
            store.set_key(ALICE, OTHER_KEY).await.expect("set"),
            MarkWrite::Written(changed)
        );
        assert_eq!(
            store.set_key(ALICE, OTHER_KEY).await.expect("again"),
            MarkWrite::Unchanged(MarkRead::Mark(changed))
        );
        assert_eq!(
            store.set_key(BOB, OTHER_KEY).await.expect("none"),
            MarkWrite::Unchanged(MarkRead::Missing)
        );
    }

    #[tokio::test]
    async fn test_marks_advance_moves_to_a_higher_pair() {
        let (dir, store) = open();
        store.create_zero(ALICE, KEY, 100).await.expect("zero");
        assert_eq!(
            store
                .advance(ALICE, head(1, 5, 1), KEY)
                .await
                .expect("first"),
            Advance::Moved(mark_at(1, 5, 1, 100))
        );
        assert_eq!(
            store.advance(ALICE, head(1, 6, 2), KEY).await.expect("seq"),
            Advance::Moved(mark_at(1, 6, 2, 100))
        );
        // A later generation is higher whatever its `seq`, and takes the key it names.
        let moved = AccountMark {
            key: OTHER_KEY,
            ..mark_at(2, 1, 3, 100)
        };
        assert_eq!(
            store
                .advance(ALICE, head(2, 1, 3), OTHER_KEY)
                .await
                .expect("generation"),
            Advance::Moved(moved)
        );
        drop(store);
        let store = MarkStore::open(dir.path()).expect("reopen");
        assert_eq!(
            store.read(ALICE).await.expect("read"),
            MarkRead::Mark(moved)
        );
    }

    #[tokio::test]
    async fn test_marks_advance_lower_or_equal_changes_nothing() {
        let (_dir, store) = open();
        let mark = with_mark(&store, ALICE, head(2, 5, 1)).await;
        assert_eq!(
            store
                .advance(ALICE, head(2, 5, 1), OTHER_KEY)
                .await
                .expect("equal"),
            Advance::Unchanged(mark)
        );
        assert_eq!(
            store
                .advance(ALICE, head(2, 4, 9), KEY)
                .await
                .expect("lower seq"),
            Advance::Overtaken(mark)
        );
        assert_eq!(
            store
                .advance(ALICE, head(1, 50, 9), KEY)
                .await
                .expect("lower generation"),
            Advance::Overtaken(mark)
        );
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(mark));
    }

    #[tokio::test]
    async fn test_marks_advance_fork_refused() {
        let (_dir, store) = open();
        let mark = with_mark(&store, ALICE, head(1, 5, 1)).await;
        assert_eq!(
            store
                .advance(ALICE, head(1, 5, 2), KEY)
                .await
                .expect("fork"),
            Advance::Fork(mark)
        );
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(mark));
    }

    #[tokio::test]
    async fn test_marks_advance_without_a_mark_changes_nothing() {
        let (dir, store) = open();
        assert_eq!(
            store
                .advance(ALICE, head(1, 1, 1), KEY)
                .await
                .expect("missing"),
            Advance::NoMark(MarkRead::Missing)
        );
        fs::write(marks_dir(&dir).join(BOB), b"[]").expect("write");
        assert_eq!(
            store
                .advance(BOB, head(1, 1, 1), KEY)
                .await
                .expect("not a mark"),
            Advance::NoMark(MarkRead::NotAMark)
        );
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
    }

    #[tokio::test]
    async fn test_marks_advance_and_write_anew_refuse_a_zero_head() {
        let (_dir, store) = open();
        store.create_zero(ALICE, KEY, 100).await.expect("zero");
        for bad in [head(0, 0, 0), head(1, 0, 1), head(0, 3, 1)] {
            assert!(matches!(
                store.advance(ALICE, bad, KEY).await,
                Err(MarkStoreError::InvalidHead)
            ));
            assert!(matches!(
                store.write_anew(BOB, bad, KEY, 100).await,
                Err(MarkStoreError::InvalidHead)
            ));
        }
    }

    #[tokio::test]
    async fn test_marks_write_anew_only_where_the_mark_is_lost() {
        let (dir, store) = open();
        let anew = mark_at(3, 1, 4, 700);
        assert_eq!(
            store
                .write_anew(ALICE, head(3, 1, 4), KEY, 700)
                .await
                .expect("missing"),
            MarkWrite::Written(anew)
        );
        fs::write(marks_dir(&dir).join(BOB), b"garbage").expect("write");
        assert_eq!(
            store
                .write_anew(BOB, head(3, 1, 4), KEY, 700)
                .await
                .expect("not a mark"),
            MarkWrite::Written(anew)
        );
        assert_eq!(
            store
                .write_anew(ALICE, head(4, 1, 5), KEY, 800)
                .await
                .expect("held"),
            MarkWrite::Unchanged(MarkRead::Mark(anew))
        );
    }

    #[tokio::test]
    async fn test_marks_delete_and_delete_created_by() {
        let (dir, store) = open();
        with_mark(&store, ALICE, head(1, 2, 1)).await;
        store.delete(ALICE).await.expect("delete");
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
        assert!(!marks_dir(&dir).join(ALICE).exists());
        store.delete(ALICE).await.expect("again");

        // Created at 100: a record at 99 doesn't cover it, one at 100 does.
        store.create_zero(BOB, KEY, 100).await.expect("zero");
        assert!(!store.delete_created_by(BOB, 99).await.expect("later mark"));
        assert!(matches!(
            store.read(BOB).await.expect("read"),
            MarkRead::Mark(_)
        ));
        assert!(store.delete_created_by(BOB, 100).await.expect("covered"));
        assert_eq!(store.read(BOB).await.expect("read"), MarkRead::Missing);
        assert!(!store.delete_created_by(BOB, 100).await.expect("gone"));

        fs::write(marks_dir(&dir).join("carol"), b"x").expect("write");
        assert!(
            !store
                .delete_created_by("carol", u64::MAX)
                .await
                .expect("kept")
        );
        assert_eq!(store.read("carol").await.expect("read"), MarkRead::NotAMark);
        store.delete("carol").await.expect("delete");
        assert_eq!(store.read("carol").await.expect("read"), MarkRead::Missing);
    }

    #[tokio::test]
    async fn test_marks_retire_is_one_way_and_outlives_the_mark() {
        let (dir, store) = open();
        with_mark(&store, ALICE, head(2, 2, 1)).await;
        store.retire(ALICE, 2).await.expect("retire");
        store.retire(ALICE, 2).await.expect("again");
        store.retire(ALICE, 0).await.expect("zero");
        store.retire(BOB, 5).await.expect("without a mark");
        store.delete(ALICE).await.expect("delete");
        drop(store);
        let store = MarkStore::open(dir.path()).expect("reopen");
        assert_eq!(store.retired(ALICE).await.expect("retired"), vec![0, 2]);
        assert_eq!(store.retired(BOB).await.expect("retired"), vec![5]);
        assert!(store.retired("carol").await.expect("none").is_empty());
    }

    #[tokio::test]
    async fn test_marks_list_names_every_mark_file() {
        let (dir, store) = open();
        store.create_zero(BOB, KEY, 1).await.expect("bob");
        store.create_zero(ALICE, KEY, 1).await.expect("alice");
        fs::write(marks_dir(&dir).join("carol"), b"x").expect("write");
        fs::write(marks_dir(&dir).join(".dave.00.tmp"), b"x").expect("temp");
        assert_eq!(
            store.list().await.expect("list"),
            vec!["alice".to_string(), "bob".into(), "carol".into()]
        );
        fs::write(marks_dir(&dir).join("Eve"), b"x").expect("write");
        assert!(matches!(
            store.list().await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
    }

    #[tokio::test]
    async fn test_marks_corrupt_file_reads_not_a_mark() {
        let (dir, store) = open();
        let good = serde_json::to_value(mark_at(1, 1, 1, 1)).expect("json");
        let zero_hash = hex::encode([0u8; 32]);
        let mut cases: Vec<Vec<u8>> = vec![b"not json".to_vec(), b"{}".to_vec()];
        let mut extra = good.clone();
        extra["more"] = 1.into();
        let mut zero_seq = good.clone();
        zero_seq["seq"] = 0.into();
        let mut zero_generation = good.clone();
        zero_generation["generation"] = 0.into();
        let mut zero_with_hash = good.clone();
        zero_with_hash["generation"] = 0.into();
        zero_with_hash["seq"] = 0.into();
        let mut upper = good.clone();
        upper["key"] = hex::encode_upper([0xab_u8; 32]).into();
        let mut short = good.clone();
        short["chain_hash"] = "0101".into();
        for value in [
            extra,
            zero_seq,
            zero_generation,
            zero_with_hash,
            upper,
            short,
        ] {
            cases.push(serde_json::to_vec(&value).expect("bytes"));
        }
        cases.push(vec![b' '; (MAX_MARK_FILE + 1) as usize]);
        for (n, bytes) in cases.iter().enumerate() {
            let identity = format!("id{n}");
            fs::write(marks_dir(&dir).join(&identity), bytes).expect("write");
            assert_eq!(
                store.read(&identity).await.expect("read"),
                MarkRead::NotAMark,
                "case {n}"
            );
        }
        // The same shape, valid, reads as a mark.
        let mut zero = good;
        zero["generation"] = 0.into();
        zero["seq"] = 0.into();
        zero["chain_hash"] = zero_hash.into();
        fs::write(
            marks_dir(&dir).join("zero"),
            serde_json::to_vec(&zero).expect("bytes"),
        )
        .expect("write");
        assert!(matches!(
            store.read("zero").await.expect("read"),
            MarkRead::Mark(mark) if !mark.records_head()
        ));
    }

    #[tokio::test]
    async fn test_marks_missing_store_id_is_unreadable() {
        let (dir, store) = open();
        store.create_zero(ALICE, KEY, 1).await.expect("alice");
        drop(store);
        let id_path = dir.path().join("accounts").join("store-id");
        let id = fs::read(&id_path).expect("id");
        fs::remove_file(&id_path).expect("remove");
        let store = MarkStore::open(dir.path()).expect("opens all the same");
        assert!(
            !id_path.exists(),
            "no identity is made for an existing store"
        );
        for identity in [ALICE, BOB] {
            assert!(matches!(
                store.read(identity).await,
                Err(MarkStoreError::StoreUnreadable(_))
            ));
        }
        assert!(matches!(
            store.create_zero(BOB, KEY, 1).await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
        assert!(matches!(
            store.retire(BOB, 1).await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
        assert!(matches!(
            store.list().await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
        // A wrong record is no record.
        fs::write(&id_path, b"short").expect("write");
        assert!(matches!(
            store.read(ALICE).await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
        // The record back, the store reads again.
        fs::write(&id_path, id).expect("restore");
        assert!(matches!(
            store.read(ALICE).await.expect("read"),
            MarkRead::Mark(_)
        ));
        assert_eq!(store.read(BOB).await.expect("read"), MarkRead::Missing);
    }

    #[tokio::test]
    async fn test_marks_rebuilt_store_reads_every_mark_missing() {
        let (dir, store) = open();
        with_mark(&store, ALICE, head(1, 4, 1)).await;
        store.retire(ALICE, 1).await.expect("retire");
        let accounts = dir.path().join("accounts");
        let old_id = fs::read(accounts.join("store-id")).expect("id");
        drop(store);
        fs::remove_dir_all(&accounts).expect("lose the store");
        let store = MarkStore::open(dir.path()).expect("rebuild");
        assert_ne!(fs::read(accounts.join("store-id")).expect("id"), old_id);
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
        assert!(store.retired(ALICE).await.expect("retired").is_empty());
        assert!(store.list().await.expect("list").is_empty());
    }

    #[tokio::test]
    async fn test_marks_store_id_changed_while_open_is_unreadable() {
        let (dir, store) = open();
        let id_path = dir.path().join("accounts").join("store-id");
        fs::write(&id_path, hex::encode([9u8; 16])).expect("replace");
        // The first look for a mark in the store finds another store.
        assert!(matches!(
            store.read(ALICE).await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
        // The next call reads the store whole again, as the one now there.
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
    }

    #[tokio::test]
    async fn test_marks_bad_retirement_file_is_unreadable() {
        let (dir, store) = open();
        drop(store);
        let retired = dir.path().join("accounts").join("retired");
        fs::write(retired.join(".alice.1.00.tmp"), b"").expect("temp");
        let store = MarkStore::open(dir.path()).expect("open");
        assert!(store.retired(ALICE).await.expect("temp skipped").is_empty());
        drop(store);
        for name in ["alice", "alice.01", "alice.x", "Alice.1"] {
            fs::write(retired.join(name), b"").expect("write");
            let store = MarkStore::open(dir.path()).expect("open");
            assert!(
                matches!(
                    store.read(ALICE).await,
                    Err(MarkStoreError::StoreUnreadable(_))
                ),
                "{name}"
            );
            fs::remove_file(retired.join(name)).expect("remove");
        }
    }

    #[tokio::test]
    async fn test_marks_invalid_identity_refused() {
        let (_dir, store) = open();
        for identity in ["", "Alice", "a/b", "..", "a.b", &"a".repeat(65)] {
            assert!(matches!(
                store.read(identity).await,
                Err(MarkStoreError::InvalidIdentity)
            ));
            assert!(matches!(
                store.retire(identity, 1).await,
                Err(MarkStoreError::InvalidIdentity)
            ));
        }
    }

    #[tokio::test]
    async fn test_marks_crash_undoes_an_advance_whose_sync_failed() {
        let (dir, store, faults) = open_faulty();
        let mark = with_mark(&store, ALICE, head(1, 1, 1)).await;
        faults.lock().fail_sync(&marks_dir(&dir), 1);
        assert!(matches!(
            store.advance(ALICE, head(1, 2, 2), KEY).await,
            Err(MarkStoreError::Io(_))
        ));
        // The process still holds the mark it last wrote durably.
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(mark));
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(mark));
    }

    #[tokio::test]
    async fn test_marks_sync_failure_then_retry_is_durable() {
        let (dir, store, faults) = open_faulty();
        with_mark(&store, ALICE, head(1, 1, 1)).await;
        faults.lock().fail_sync(&marks_dir(&dir), 1);
        assert!(store.advance(ALICE, head(1, 2, 2), KEY).await.is_err());
        assert!(
            marks_dir(&dir).join(ALICE).exists(),
            "the rename landed without its sync"
        );
        // The retry writes and syncs again before it reports the move.
        assert_eq!(
            store
                .advance(ALICE, head(1, 2, 2), KEY)
                .await
                .expect("retry"),
            Advance::Moved(mark_at(1, 2, 2, 100))
        );
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(
            store.read(ALICE).await.expect("read"),
            MarkRead::Mark(mark_at(1, 2, 2, 100))
        );
    }

    #[tokio::test]
    async fn test_marks_retry_refused_while_the_sync_fails() {
        let (dir, store, faults) = open_faulty();
        faults.lock().fail_sync(&marks_dir(&dir), 2);
        for _ in 0..2 {
            assert!(store.create_zero(ALICE, KEY, 1).await.is_err());
            assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
        }
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
    }

    #[tokio::test]
    async fn test_marks_restart_after_a_failed_sync_makes_the_landed_write_durable() {
        let (dir, store, faults) = open_faulty();
        with_mark(&store, ALICE, head(1, 1, 1)).await;
        faults.lock().fail_sync(&marks_dir(&dir), 1);
        assert!(store.advance(ALICE, head(1, 2, 2), KEY).await.is_err());
        drop(store);
        // The next process syncs before it reads: it reads the landed mark, and a crash
        // after can't take it back.
        let store = MarkStore::open_with_faults(dir.path(), faults.clone()).expect("restart");
        let moved = MarkRead::Mark(mark_at(1, 2, 2, 100));
        assert_eq!(store.read(ALICE).await.expect("read"), moved);
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.read(ALICE).await.expect("read"), moved);
    }

    #[tokio::test]
    async fn test_marks_delete_sync_failure_then_retry() {
        let (dir, store, faults) = open_faulty();
        let mark = with_mark(&store, ALICE, head(1, 1, 1)).await;
        faults.lock().fail_sync(&marks_dir(&dir), 1);
        assert!(store.delete_created_by(ALICE, 100).await.is_err());
        assert!(!marks_dir(&dir).join(ALICE).exists(), "the removal landed");
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(mark));
        assert!(store.delete_created_by(ALICE, 100).await.expect("retry"));
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
    }

    #[tokio::test]
    async fn test_marks_retire_sync_failure_then_retry() {
        let (dir, store, faults) = open_faulty();
        let retired = dir.path().join("accounts").join("retired");
        faults.lock().fail_sync(&retired, 1);
        assert!(store.retire(ALICE, 3).await.is_err());
        assert!(retired.join("alice.3").exists(), "the rename landed");
        // Not reported until a sync covers it.
        assert!(store.retired(ALICE).await.expect("retired").is_empty());
        store.retire(ALICE, 3).await.expect("retry");
        assert_eq!(store.retired(ALICE).await.expect("retired"), vec![3]);
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.retired(ALICE).await.expect("retired"), vec![3]);
    }

    #[tokio::test]
    async fn test_marks_write_runs_to_its_end_when_the_caller_stops_waiting() {
        let (dir, store) = open();
        let mut write = Box::pin(store.create_zero(ALICE, KEY, 1));
        // Polled once, so its blocking task starts, then dropped.
        std::future::poll_fn(|cx| {
            let _ = write.as_mut().poll(cx);
            std::task::Poll::Ready(())
        })
        .await;
        drop(write);
        let mut held = MarkRead::Missing;
        for _ in 0..500 {
            held = store.read(ALICE).await.expect("read");
            if held != MarkRead::Missing {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(held, MarkRead::Mark(AccountMark::zero(KEY, 1)));
        assert!(marks_dir(&dir).join(ALICE).exists());
    }
}
