//! The per-account mark store (Switch spec 6.5, Switch wire 7.3 "Accounts and marks", "The
//! store").
//!
//! For each identity it holds an account for, the service keeps one mark, apart from the
//! state a backup restores: the newest head it signed for the identity (generation, `seq`,
//! chain hash), the service key the account is answered with, and the time the account was
//! created. Beside the marks lie the retirements of generations, one-way, and the records of
//! erasures (Switch wire 7.4.16). The three lie in one store, under one identity record, in
//! `accounts/` under the key store's directory, which no backup of the state restores:
//!
//! - `accounts/store-id`: the store's identity, 16 random bytes in hex, written with the
//!   directory. A directory without a readable one is a store that can't be read; a store
//!   rebuilt after its loss has a new one, and every mark, retirement and erasure's record in
//!   it is gone together (Switch wire 7.3, Table 3).
//! - `accounts/marks/<identity>`: the identity's mark, in JSON.
//! - `accounts/retired/<identity>.<generation>`: an empty file per retired generation.
//! - `accounts/erasures/<identity>`: the time of the identity's latest erasure's record, in
//!   Unix milliseconds, as decimal text.
//!
//! Every write is a temporary file, synced, renamed into place, then its directory synced,
//! and is durable before its call returns. A write that fails after its rename landed and
//! before its directory sync isn't taken up: the store keeps in memory what it last wrote
//! durably, so a retry writes and syncs again before it reports success, and the store
//! syncs its directories when it opens, before it reads them. Every read-check-write runs
//! under one lock inside a blocking task, which runs to its end even if its caller stops
//! waiting. A file no writer makes, in name or content, makes the store unreadable, apart
//! from a mark file that doesn't read as a mark, which Table 1 judges (Switch wire 7.3).
//!
//! A store that serves under an instance lock refuses every write once the lock's last
//! confirmed check is stale ([`MarkStore::gated`]): no mark is created, moved, taken, re-keyed
//! or deleted, and no erasure's record written, while another process may hold the database
//! (Switch spec 6.5).

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
use crate::store::LockFreshness;

/// The largest mark file the store reads, in bytes; a larger one doesn't read as a mark.
const MAX_MARK_FILE: u64 = 4096;

/// The largest erasure's record the store reads, in bytes: a `u64` in decimal.
const MAX_ERASURE_FILE: u64 = 20;

/// The store's directories under `accounts/`.
const STORE_DIRS: [&str; 3] = ["marks", "retired", "erasures"];

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
    /// The mark is another account's: created at another time than the account the move
    /// is for, which was erased, and another enrolled, since its commit. The mark stays.
    OtherAccount(AccountMark),
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
    /// A retirement of generation 0, which no account serves (Switch wire 7.3, Table 3).
    #[error("a retirement of generation 0")]
    InvalidGeneration,
    /// The storage failed.
    #[error("mark store storage: {0}")]
    Io(#[from] std::io::Error),
    /// No randomness for the store's identity or a temporary file's name.
    #[error("no randomness")]
    Random,
    /// A write refused: the instance lock's last confirmed check is stale, and another
    /// process may hold the database (Switch spec 6.5).
    #[error("the instance lock isn't confirmed")]
    LockStale,
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
    /// The instance lock every write waits for no stale check of, if the store serves under
    /// one ([`MarkStore::gated`]).
    gate: Option<LockFreshness>,
}

impl std::fmt::Debug for MarkStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarkStore")
            .field("root", &self.inner.root)
            .finish_non_exhaustive()
    }
}

/// Routine calls read only the identity's records. Enumeration and maintenance validate
/// the complete store (Switch wire 7.3, Table 1).
#[derive(Clone, Copy)]
enum RecordScope<'a> {
    Identity(&'a str),
    All,
}

struct Inner {
    /// The key store's directory.
    root: PathBuf,
    /// The last readable store identity. Loss within that store preserves observations;
    /// a rebuilt store invalidates them together before any record is used.
    store_id: Mutex<Option<String>>,
    /// What the store last held durably for each identity read. Reads compare the live
    /// file, and only a successful directory sync publishes a changed mark.
    marks: Mutex<HashMap<String, MarkRead>>,
    /// Retirements last read or written durably, checked against their live files.
    retired: Mutex<HashMap<String, BTreeSet<u64>>>,
    /// Erasure records last read or written durably, checked against their live files.
    erasures: Mutex<HashMap<String, u64>>,
    /// Renames and removals that landed but whose directory sync has not succeeded. Only
    /// these exact bytes may differ from the last durable value without being a lost or
    /// changed record. A successful sync publishes all changes it covers.
    pending: Mutex<HashMap<PathBuf, Option<Vec<u8>>>>,
    /// Held around every read-check-write, inside the blocking task that does it, and
    /// before `store_id`, `marks`, `retired` and `erasures`. A caller that stops waiting can't release
    /// it early: the task runs to its end, so writes land in the order they were checked.
    writes: Mutex<()>,
    /// A test waiting until a write reaches the serialized boundary.
    #[cfg(test)]
    write_waiting: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
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
            gate: None,
        })
    }

    /// The same store, its every write refused with [`MarkStoreError::LockStale`] once
    /// `freshness`'s last confirmed check is stale: what a service serving under the instance
    /// lock writes through, so no path that creates, moves, takes, re-keys or deletes a mark,
    /// or writes an erasure's record, can skip the check (Switch spec 6.5).
    #[must_use]
    pub fn gated(&self, freshness: LockFreshness) -> Self {
        Self {
            inner: self.inner.clone(),
            gate: Some(freshness),
        }
    }

    /// Refuse a write while the instance lock isn't confirmed.
    fn check_gate(&self) -> Result<(), MarkStoreError> {
        match &self.gate {
            Some(freshness) if !freshness.is_fresh() => Err(MarkStoreError::LockStale),
            _ => Ok(()),
        }
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
        self.check_gate()?;
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.write_sync(gate.as_ref(), &identity, |held| match held {
                MarkRead::Missing | MarkRead::NotAMark => {
                    Some(AccountMark::zero(key, created_at_ms))
                }
                MarkRead::Mark(_) => None,
            })
        })
        .await
    }

    /// A new account takes the identity's mark `read`, the one it was judged with: its
    /// generation, `seq` and chain hash stay, as do the identity's retirements; its key and
    /// creation time become `key` and `created_at_ms` (Switch wire 7.3, Table 3). Where the
    /// store holds another mark than `read`, or none, nothing changes.
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`].
    pub async fn take(
        &self,
        identity: &str,
        read: AccountMark,
        key: [u8; 32],
        created_at_ms: u64,
    ) -> Result<MarkWrite, MarkStoreError> {
        self.check_gate()?;
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.write_sync(gate.as_ref(), &identity, |held| match held {
                MarkRead::Mark(mark) if mark == read => Some(AccountMark {
                    key,
                    created_at_ms,
                    ..mark
                }),
                MarkRead::Mark(_) | MarkRead::Missing | MarkRead::NotAMark => None,
            })
        })
        .await
    }

    /// The mark's key becomes `key`, its head and creation time staying (Switch wire 7.3,
    /// Table 3: an enrollment at a staged account that no document names yet, after a
    /// service key change). Only the mark of the account created at `created_at_ms`
    /// changes: without a mark, with another account's, or with that key already, nothing
    /// changes.
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`].
    pub async fn set_key(
        &self,
        identity: &str,
        key: [u8; 32],
        created_at_ms: u64,
    ) -> Result<MarkWrite, MarkStoreError> {
        self.check_gate()?;
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.write_sync(gate.as_ref(), &identity, |held| match held {
                MarkRead::Mark(mark) if mark.key != key && mark.created_at_ms == created_at_ms => {
                    Some(AccountMark { key, ..mark })
                }
                MarkRead::Mark(_) | MarkRead::Missing | MarkRead::NotAMark => None,
            })
        })
        .await
    }

    /// Move the mark of the identity's account created at `created_at_ms` to `head`,
    /// answered with `key`, once the commit that holds the head is durable (Switch wire 7.3,
    /// "Moving it"). The mark moves only to a higher (generation, `seq`), durably before
    /// this returns; at the same head it stays, behind a later one it stays, and at the
    /// head's pair with another chain hash it is refused.
    ///
    /// A move runs after its commit, outside the identity's lock: the account may have been
    /// erased, and another enrolled, meanwhile. Every writer keeps a mark's creation time
    /// equal to its account's, so a mark of another creation time is another account's: it
    /// stays, and the move answers [`Advance::OtherAccount`].
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
        created_at_ms: u64,
    ) -> Result<Advance, MarkStoreError> {
        self.check_gate()?;
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        if !is_head(&head) {
            return Err(MarkStoreError::InvalidHead);
        }
        blocking(move || inner.advance_sync(gate.as_ref(), &identity, head, key, created_at_ms))
            .await
    }

    /// Write the mark anew at `head`, with `key` and `created_at_ms`, where the identity's
    /// mark is lost: missing, or a file that doesn't read as a mark (Switch wire 7.3,
    /// Table 3: a delivery that starts a generation where the mark is lost). A mark it
    /// holds stays: [`MarkStore::advance`] moves it. Nothing is written for an account an
    /// erasure's record covers, one created at or before the record: it was erased since
    /// the commit that holds the head, and a mark written for it would be a leftover.
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
        self.check_gate()?;
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        if !is_head(&head) {
            return Err(MarkStoreError::InvalidHead);
        }
        blocking(move || {
            inner.write_sync(gate.as_ref(), &identity, |held| match held {
                // Read under the writes' lock, as the record is written.
                MarkRead::Missing | MarkRead::NotAMark
                    if inner.erased_after(&identity, created_at_ms) =>
                {
                    None
                }
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
        self.check_gate()?;
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner
                .delete_sync(gate.as_ref(), &identity, None)
                .map(|_| ())
        })
        .await
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
        self.check_gate()?;
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || inner.delete_sync(gate.as_ref(), &identity, Some(at_ms))).await
    }

    /// Record the retirement of `generation` for the identity, durably (Switch spec 6.5).
    /// One-way: nothing removes it but a rebuilt store. Also where the identity has no
    /// mark.
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`];
    /// [`MarkStoreError::InvalidGeneration`] for generation 0 (Switch wire 7.3, Table 3).
    pub async fn retire(&self, identity: &str, generation: u64) -> Result<(), MarkStoreError> {
        self.check_gate()?;
        let gate = self.gate.clone();
        if generation == 0 {
            return Err(MarkStoreError::InvalidGeneration);
        }
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || inner.retire_sync(gate.as_ref(), &identity, generation)).await
    }

    /// Whether `generation` is retired for `identity`, reading that record now. A pending
    /// retirement whose directory sync failed does not count until a sync succeeds.
    ///
    /// # Errors
    ///
    /// The store or this identity's record cannot be read; [`MarkStoreError::InvalidIdentity`].
    pub async fn is_retired(
        &self,
        identity: &str,
        generation: u64,
    ) -> Result<bool, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.reading(RecordScope::Identity(&identity), |_| {
                inner.retirement(&identity, generation)
            })
        })
        .await
    }

    /// The identity's retired generations, ascending, after validating the complete
    /// ledgers. A verdict uses [`MarkStore::is_retired`] for its selected generation.
    ///
    /// # Errors
    ///
    /// The store can't be read; [`MarkStoreError::InvalidIdentity`].
    pub async fn retired(&self, identity: &str) -> Result<Vec<u64>, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.reading(RecordScope::All, |_| {
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
        blocking(move || inner.reading(RecordScope::All, |_| list_marks(&inner.marks_dir()))).await
    }

    /// Record, durably, that `identity`'s account is erased at `erased_at_ms` (Switch wire
    /// 7.4.16, 7.3 Table 3): the store keeps the latest time, so an older one never replaces
    /// a newer one. Answers the time it held before, for [`MarkStore::withdraw_erasure`].
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`].
    pub async fn record_erasure(
        &self,
        identity: &str,
        erased_at_ms: u64,
    ) -> Result<Option<u64>, MarkStoreError> {
        self.check_gate()?;
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || inner.record_erasure_sync(gate.as_ref(), &identity, erased_at_ms)).await
    }

    /// Take back the record of an erasure at `erased_at_ms` whose deletion didn't commit
    /// (Switch wire 7.3, Table 3): the store holds `previous` for `identity` again, durably.
    /// A later record left in its place meanwhile stays.
    ///
    /// # Errors
    ///
    /// The store can't be read or the write failed; [`MarkStoreError::InvalidIdentity`].
    pub async fn withdraw_erasure(
        &self,
        identity: &str,
        erased_at_ms: u64,
        previous: Option<u64>,
    ) -> Result<(), MarkStoreError> {
        self.check_gate()?;
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.withdraw_erasure_sync(gate.as_ref(), &identity, erased_at_ms, previous)
        })
        .await
    }

    /// The time of the erasure's record for `identity`, if any; none for an identity no file
    /// can name, which [`MarkStore::record_erasure`] refuses.
    ///
    /// # Errors
    ///
    /// The store can't be read.
    pub async fn erasure(&self, identity: &str) -> Result<Option<u64>, MarkStoreError> {
        let Ok(identity) = valid_identity(identity) else {
            return Ok(None);
        };
        let inner = self.inner.clone();
        blocking(move || {
            inner.reading(RecordScope::Identity(&identity), |_| {
                Ok(inner.erasures.lock().get(&identity).copied())
            })
        })
        .await
    }

    /// Every erasure's record the store holds: each identity, with the time of its latest
    /// record, ascending.
    ///
    /// # Errors
    ///
    /// The store can't be read.
    pub async fn erasures(&self) -> Result<Vec<(String, u64)>, MarkStoreError> {
        let inner = self.inner.clone();
        blocking(move || {
            inner.reading(RecordScope::All, |_| {
                let mut all: Vec<(String, u64)> = inner
                    .erasures
                    .lock()
                    .iter()
                    .map(|(identity, at)| (identity.clone(), *at))
                    .collect();
                all.sort_unstable();
                Ok(all)
            })
        })
        .await
    }

    /// Forget the erasures recorded before `before_ms`, whose accounts no database backup
    /// the operator keeps can hold any more (Switch spec 6.5); the number forgotten. The
    /// caller deletes the leftover marks a record covers first (Switch wire 7.3, Table 3);
    /// a record that still covers a mark, one created at or before it, stays for the next
    /// pass, also when the mark was written after the caller's deletion: without its record
    /// the leftover would read as a lost account's mark.
    ///
    /// # Errors
    ///
    /// The store can't be read or a removal failed.
    pub async fn forget_erasures_before(&self, before_ms: u64) -> Result<usize, MarkStoreError> {
        self.check_gate()?;
        let gate = self.gate.clone();
        let inner = self.inner.clone();
        blocking(move || inner.forget_erasures_sync(gate.as_ref(), before_ms)).await
    }
}

impl Inner {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            store_id: Mutex::new(None),
            marks: Mutex::new(HashMap::new()),
            retired: Mutex::new(HashMap::new()),
            erasures: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            writes: Mutex::new(()),
            #[cfg(test)]
            write_waiting: Mutex::default(),
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

    fn erasures_dir(&self) -> PathBuf {
        self.accounts().join("erasures")
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
        let mut pending = self.pending.lock();
        let covered: Vec<_> = pending
            .iter()
            .filter(|(path, _)| path.parent() == Some(dir))
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect();
        for (path, bytes) in &covered {
            if read_record_file(path, MAX_MARK_FILE)? != *bytes {
                return Err(MarkStoreError::StoreUnreadable(
                    "a pending record changed".into(),
                ));
            }
        }
        for (path, bytes) in covered {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(MarkStoreError::InvalidIdentity)?;
            if dir == self.marks_dir() {
                self.marks
                    .lock()
                    .insert(name.to_string(), mark_from_bytes(bytes.as_deref()));
            } else if dir == self.retired_dir() {
                let (identity, generation) = retirement_name(name)?;
                self.retired
                    .lock()
                    .entry(identity)
                    .or_default()
                    .insert(generation);
            } else if dir == self.erasures_dir() {
                let mut erasures = self.erasures.lock();
                match erasure_from_bytes(bytes.as_deref())? {
                    Some(at) => {
                        erasures.insert(name.to_string(), at);
                    }
                    None => {
                        erasures.remove(name);
                    }
                }
            }
            pending.remove(&path);
        }
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
        self.pending
            .lock()
            .insert(path.to_path_buf(), Some(bytes.to_vec()));
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
        self.pending.lock().insert(path.to_path_buf(), None);
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
            for dir in STORE_DIRS {
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

    /// Cached records belong only to this readable store. Loss of its identity or any
    /// directory is unknown, even where the requested mark is already in memory.
    fn confirm_store(&self, expected: &str) -> Result<(), MarkStoreError> {
        if read_store_id(&self.accounts())? != expected {
            // A different identity names a rebuilt store. Loss within the same store
            // keeps the old observations, so a retry cannot adopt a rollback.
            *self.store_id.lock() = None;
            self.pending.lock().clear();
            return Err(MarkStoreError::StoreUnreadable(
                "the store's identity changed".into(),
            ));
        }
        for name in STORE_DIRS {
            let path = self.accounts().join(name);
            if fs::read_dir(&path).is_err() {
                return Err(MarkStoreError::StoreUnreadable(format!(
                    "{} isn't a readable directory",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// The store's identity, reading the store first where it couldn't be read. The caller
    /// holds `writes`.
    fn readable_locked(&self) -> Result<String, MarkStoreError> {
        let known = self.store_id.lock().clone();
        if let Some(id) = known {
            self.confirm_store(&id)?;
            return Ok(id);
        }
        // An earlier process, or an earlier call, may have landed a rename or a removal
        // and stopped before its directory sync: sync every directory before reading any.
        let accounts = self.accounts();
        for dir in [
            self.marks_dir(),
            self.retired_dir(),
            self.erasures_dir(),
            accounts.clone(),
        ] {
            self.sync_dir(&dir).map_err(|error| {
                MarkStoreError::StoreUnreadable(format!("{}: {error}", dir.display()))
            })?;
        }
        self.sync_dir(&self.root)?;
        let id = read_store_id(&accounts)?;
        let retired = read_retired(&self.retired_dir())?;
        let erasures = read_erasures(&self.erasures_dir())?;
        *self.retired.lock() = retired;
        *self.erasures.lock() = erasures;
        self.marks.lock().clear();
        *self.store_id.lock() = Some(id.clone());
        Ok(id)
    }

    /// Compare live ledgers with the durable values and exact writes still awaiting a
    /// sync. Missing, malformed or replaced records make this store unknown (wire 7.3).
    fn confirm_all_records(&self) -> Result<(), MarkStoreError> {
        let mut expected_retired = self.retired.lock().clone();
        let mut expected_erasures = self.erasures.lock().clone();
        let pending = self.pending.lock();
        let mut pending_erasure = false;
        for (path, bytes) in pending.iter() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(MarkStoreError::InvalidIdentity)?;
            if path.parent() == Some(self.retired_dir().as_path()) {
                let (identity, generation) = retirement_name(name)?;
                expected_retired
                    .entry(identity)
                    .or_default()
                    .insert(generation);
            } else if path.parent() == Some(self.erasures_dir().as_path()) {
                pending_erasure = true;
                match erasure_from_bytes(bytes.as_deref())? {
                    Some(at) => {
                        expected_erasures.insert(name.to_string(), at);
                    }
                    None => {
                        expected_erasures.remove(name);
                    }
                }
            }
        }
        drop(pending);
        if read_retired(&self.retired_dir())? != expected_retired
            || read_erasures(&self.erasures_dir())? != expected_erasures
        {
            return Err(MarkStoreError::StoreUnreadable(
                "a durable record changed".into(),
            ));
        }
        if pending_erasure {
            // An uncertain erasure intent is taken up only once this barrier succeeds.
            self.sync_dir(&self.erasures_dir())?;
        }
        Ok(())
    }

    /// Check the record this identity's verdict uses, without walking other identities.
    /// A directory sync still covers all known pending changes in that directory.
    fn confirm_records(&self, scope: RecordScope<'_>) -> Result<(), MarkStoreError> {
        let RecordScope::Identity(identity) = scope else {
            return self.confirm_all_records();
        };
        let path = self.erasures_dir().join(identity);
        let bytes = read_record_file(&path, MAX_ERASURE_FILE)?;
        let pending = self.pending.lock().get(&path).cloned();
        let expected = match &pending {
            Some(bytes) => bytes.clone(),
            None => self
                .erasures
                .lock()
                .get(identity)
                .map(|at| at.to_string().into_bytes()),
        };
        if bytes != expected {
            return Err(MarkStoreError::StoreUnreadable(
                "an erasure record changed".into(),
            ));
        }
        if pending.is_some() {
            // An uncertain erasure intent counts only after its durability barrier.
            self.sync_dir(&self.erasures_dir())?;
        }
        Ok(())
    }

    /// Table 1 consults the mark's generation, or the account's when its mark is lost.
    /// Never replace an observed one-way retirement with absence or an unexpected file.
    fn retirement(&self, identity: &str, generation: u64) -> Result<bool, MarkStoreError> {
        let path = self.retired_path(identity, generation);
        let bytes = read_record_file(&path, 0)?;
        let retired = self
            .retired
            .lock()
            .get(identity)
            .is_some_and(|held| held.contains(&generation));
        let expected = self
            .pending
            .lock()
            .get(&path)
            .cloned()
            .unwrap_or_else(|| retired.then(Vec::new));
        if bytes != expected {
            return Err(MarkStoreError::StoreUnreadable(
                "a retirement record changed".into(),
            ));
        }
        Ok(retired)
    }

    /// Serialize live reads with file changes and publication of their durability.
    fn reading<T>(
        &self,
        scope: RecordScope<'_>,
        read: impl FnOnce(&str) -> Result<T, MarkStoreError>,
    ) -> Result<T, MarkStoreError> {
        let _writes = self.writes.lock();
        let id = self.readable_locked()?;
        self.confirm_records(scope)?;
        read(&id)
    }

    /// Run `write` under `writes`, once the store can be read and the instance lock is
    /// still fresh after any wait for the blocking pool or this lock (Switch spec 6.5).
    fn writing<T>(
        &self,
        gate: Option<&LockFreshness>,
        scope: RecordScope<'_>,
        write: impl FnOnce(&str) -> Result<T, MarkStoreError>,
    ) -> Result<T, MarkStoreError> {
        #[cfg(test)]
        if let Some(waiting) = self.write_waiting.lock().take() {
            let _ = waiting.send(());
        }
        let _writes = self.writes.lock();
        let id = self.readable_locked()?;
        self.confirm_records(scope)?;
        if gate.is_some_and(|freshness| !freshness.is_fresh()) {
            return Err(MarkStoreError::LockStale);
        }
        write(&id)
    }

    /// Validate the live mark before using cached authority. A known unsuccessful sync
    /// may leave exactly its pending bytes; any other changed valid mark has lost the
    /// authority of the one held, just as a malformed mark has (wire 7.3, Table 1).
    fn load_mark(&self, identity: &str, store_id: &str) -> Result<MarkRead, MarkStoreError> {
        if read_store_id(&self.accounts())? != store_id {
            return Err(MarkStoreError::StoreUnreadable(
                "the store's identity changed".into(),
            ));
        }
        let path = self.mark_path(identity);
        let bytes = read_record_file(&path, MAX_MARK_FILE)?;
        let observed = mark_from_bytes(bytes.as_deref());
        let mut marks = self.marks.lock();
        let read = if let Some(held) = marks.get(identity) {
            if self
                .pending
                .lock()
                .get(&path)
                .is_some_and(|pending| *pending == bytes)
            {
                *held
            } else {
                match observed {
                    MarkRead::Mark(_) if observed != *held => MarkRead::NotAMark,
                    other => other,
                }
            }
        } else {
            marks.insert(identity.to_string(), observed);
            observed
        };
        if let MarkRead::Mark(mark) = read {
            self.retirement(identity, mark.generation)?;
        }
        Ok(read)
    }

    /// Whether an erasure's record covers an account of `identity` created at
    /// `created_at_ms`: one dated at or after it, every record being dated no earlier than
    /// the creation it erases (Switch wire 7.3, Table 3).
    fn erased_after(&self, identity: &str, created_at_ms: u64) -> bool {
        self.erasures
            .lock()
            .get(identity)
            .is_some_and(|at_ms| created_at_ms <= *at_ms)
    }

    fn read_sync(&self, identity: &str) -> Result<MarkRead, MarkStoreError> {
        self.reading(RecordScope::Identity(identity), |id| {
            self.load_mark(identity, id)
        })
    }

    /// Write what `next` makes of the mark held, if anything, durably, then hold it.
    fn write_sync(
        &self,
        gate: Option<&LockFreshness>,
        identity: &str,
        next: impl FnOnce(MarkRead) -> Option<AccountMark>,
    ) -> Result<MarkWrite, MarkStoreError> {
        self.writing(gate, RecordScope::Identity(identity), |id| {
            let held = self.load_mark(identity, id)?;
            match next(held) {
                Some(mark) => {
                    self.retirement(identity, mark.generation)?;
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
        self.write_atomic(&self.mark_path(identity), &bytes)
    }

    fn advance_sync(
        &self,
        gate: Option<&LockFreshness>,
        identity: &str,
        head: ChainTip,
        key: [u8; 32],
        created_at_ms: u64,
    ) -> Result<Advance, MarkStoreError> {
        self.writing(gate, RecordScope::Identity(identity), |id| {
            let mark = match self.load_mark(identity, id)? {
                MarkRead::Mark(mark) => mark,
                held => return Ok(Advance::NoMark(held)),
            };
            if mark.created_at_ms != created_at_ms {
                return Ok(Advance::OtherAccount(mark));
            }
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
            self.retirement(identity, moved.generation)?;
            self.put_mark(identity, moved)?;
            Ok(Advance::Moved(moved))
        })
    }

    fn delete_sync(
        &self,
        gate: Option<&LockFreshness>,
        identity: &str,
        created_by: Option<u64>,
    ) -> Result<bool, MarkStoreError> {
        self.writing(gate, RecordScope::Identity(identity), |id| {
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
            Ok(!matches!(held, MarkRead::Missing))
        })
    }

    fn retire_sync(
        &self,
        gate: Option<&LockFreshness>,
        identity: &str,
        generation: u64,
    ) -> Result<(), MarkStoreError> {
        self.writing(gate, RecordScope::Identity(identity), |_| {
            let held = self.retirement(identity, generation)?;
            if held {
                // Memory holds only a retirement whose file is durable.
                return Ok(());
            }
            self.write_atomic(&self.retired_path(identity, generation), b"")
        })
    }

    /// Keep the latest erasure time: an account created before it is erased again after a
    /// restore (Switch spec 6.5). Answers the time the store held before.
    fn record_erasure_sync(
        &self,
        gate: Option<&LockFreshness>,
        identity: &str,
        erased_at_ms: u64,
    ) -> Result<Option<u64>, MarkStoreError> {
        self.writing(gate, RecordScope::Identity(identity), |_| {
            let path = self.erasures_dir().join(identity);
            let recorded = read_erasure_file(&path)?;
            let written = if recorded.is_some_and(|recorded| recorded >= erased_at_ms) {
                // A prior rename may have landed without its directory sync.
                self.sync_dir(&self.erasures_dir())
            } else {
                self.write_atomic(&path, erased_at_ms.to_string().as_bytes())
            };
            // Only a landed change is pending. The next read checks its exact bytes
            // and syncs it; a failed rename authorizes no deletion.
            written?;
            Ok(recorded)
        })
    }

    /// Put `previous` back as `identity`'s record where the store holds `erased_at_ms`,
    /// durably, then in memory.
    fn withdraw_erasure_sync(
        &self,
        gate: Option<&LockFreshness>,
        identity: &str,
        erased_at_ms: u64,
        previous: Option<u64>,
    ) -> Result<(), MarkStoreError> {
        self.writing(gate, RecordScope::Identity(identity), |_| {
            let path = self.erasures_dir().join(identity);
            // Memory holds what the files hold, and a record whose file's removal landed
            // without its directory sync: the retry syncs it.
            let held = self.erasures.lock().get(identity).copied();
            if held != Some(erased_at_ms) || previous == Some(erased_at_ms) {
                // A later record took its place, or the record was there before: it stays.
                return Ok(());
            }
            match previous {
                Some(at) => self.write_atomic(&path, at.to_string().as_bytes())?,
                None => self.remove_durably(&path)?,
            }
            Ok(())
        })
    }

    /// Remove the records of erasures before `before_ms`, each removal durable before its
    /// entry leaves memory.
    fn forget_erasures_sync(
        &self,
        gate: Option<&LockFreshness>,
        before_ms: u64,
    ) -> Result<usize, MarkStoreError> {
        self.writing(gate, RecordScope::All, |id| {
            let aged: Vec<(String, u64)> = self
                .erasures
                .lock()
                .iter()
                .filter(|(_, at)| **at < before_ms)
                .map(|(identity, at)| (identity.clone(), *at))
                .collect();
            let mut old = Vec::with_capacity(aged.len());
            for (identity, at_ms) in aged {
                let covers_a_mark = matches!(
                    self.load_mark(&identity, id)?,
                    MarkRead::Mark(mark) if mark.created_at_ms <= at_ms
                );
                if !covers_a_mark {
                    old.push(identity);
                }
            }
            let dir = self.erasures_dir();
            for identity in &old {
                #[cfg(test)]
                let before = fs::read(dir.join(identity)).ok();
                match fs::remove_file(dir.join(identity)) {
                    Ok(()) => {
                        #[cfg(test)]
                        self.faults.lock().changed(&dir.join(identity), before);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                self.pending.lock().insert(dir.join(identity), None);
            }
            if !old.is_empty() {
                self.sync_dir(&dir)?;
            }
            Ok(old.len())
        })
    }
}

/// A read-only view of the mark store, for an operator's check beside a running service: it
/// creates, writes, syncs and locks nothing, and reads each mark as its file is then. The
/// retirements and erasure records are read again when asked for.
#[derive(Debug)]
pub struct MarkView {
    accounts: PathBuf,
    store_id: String,
    /// Retirement is one-way within this store, including records observed after open.
    retired: Mutex<HashMap<String, BTreeSet<u64>>>,
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
        read_erasures(&accounts.join("erasures"))?;
        Ok(Self {
            accounts,
            store_id,
            retired: Mutex::new(retired),
        })
    }

    /// The current erasure record for `identity`.
    ///
    /// # Errors
    ///
    /// The store or record can't be read, or the store identity changed.
    pub fn erasure(&self, identity: &str) -> Result<Option<u64>, MarkStoreError> {
        let identity = valid_identity(identity)?;
        self.confirm_store()?;
        Ok(read_erasures(&self.accounts.join("erasures"))?
            .get(&identity)
            .copied())
    }

    fn confirm_store(&self) -> Result<(), MarkStoreError> {
        if read_store_id(&self.accounts)? != self.store_id {
            return Err(MarkStoreError::StoreUnreadable(
                "the store's identity changed".into(),
            ));
        }
        for name in STORE_DIRS {
            fs::read_dir(self.accounts.join(name))
                .map_err(|error| MarkStoreError::StoreUnreadable(error.to_string()))?;
        }
        Ok(())
    }

    /// The identity's mark as its file holds it now.
    ///
    /// # Errors
    ///
    /// The store can't be read, or its identity changed since the view opened;
    /// [`MarkStoreError::InvalidIdentity`].
    pub fn read(&self, identity: &str) -> Result<MarkRead, MarkStoreError> {
        let identity = valid_identity(identity)?;
        self.confirm_store()?;
        read_mark_file(&self.accounts.join("marks").join(identity))
    }

    /// The identity's current retired generations, ascending.
    ///
    /// # Errors
    ///
    /// The store or a retirement can't be read, or the store identity changed.
    pub fn retired(&self, identity: &str) -> Result<Vec<u64>, MarkStoreError> {
        let identity = valid_identity(identity)?;
        self.confirm_store()?;
        let mut observed = self.retired.lock();
        let current = read_retired(&self.accounts.join("retired"))?;
        if observed.iter().any(|(id, generations)| {
            current
                .get(id)
                .is_none_or(|held| !generations.is_subset(held))
        }) {
            return Err(MarkStoreError::StoreUnreadable(
                "an observed retirement disappeared".into(),
            ));
        }
        let generations = current
            .get(&identity)
            .map(|generations| generations.iter().copied().collect())
            .unwrap_or_default();
        *observed = current;
        Ok(generations)
    }

    /// Every identity with a mark file now, ascending.
    ///
    /// # Errors
    ///
    /// The store can't be read.
    pub fn list(&self) -> Result<Vec<String>, MarkStoreError> {
        self.confirm_store()?;
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

/// The name of each entry in the store's directory `dir`, `what` naming it, but a write's
/// temporary file: each a regular file whose name is UTF-8. Anything else, which no writer
/// makes, makes the store unreadable.
fn store_files(dir: &Path, what: &str) -> Result<Vec<(String, PathBuf)>, MarkStoreError> {
    let unreadable = |why: String| MarkStoreError::StoreUnreadable(format!("{what}: {why}"));
    let entries = fs::read_dir(dir).map_err(|error| unreadable(error.to_string()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| unreadable(error.to_string()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(unreadable("a file name isn't UTF-8".into()));
        };
        if is_temp_file(name) {
            continue;
        }
        let kind = entry
            .file_type()
            .map_err(|error| unreadable(error.to_string()))?;
        if !kind.is_file() {
            return Err(unreadable(format!("{name} isn't a file")));
        }
        files.push((name.to_string(), entry.path()));
    }
    Ok(files)
}

fn retirement_name(name: &str) -> Result<(String, u64), MarkStoreError> {
    name.split_once('.')
        .and_then(|(identity, generation)| {
            let value = generation.parse::<u64>().ok()?;
            (is_ledger_name(identity) && value != 0 && value.to_string() == generation)
                .then(|| (identity.to_string(), value))
        })
        .ok_or_else(|| {
            MarkStoreError::StoreUnreadable(format!("retired: {name} names no retirement"))
        })
}

/// Every retirement in `dir`. A write's temporary file isn't one; any other entry that isn't
/// an empty file naming an identity and a generation above 0, as [`MarkStore::retire`]
/// writes it, makes the store unreadable: a generation-0 retirement, which no writer makes,
/// counts for nothing (Switch wire 7.3, Table 3).
fn read_retired(dir: &Path) -> Result<HashMap<String, BTreeSet<u64>>, MarkStoreError> {
    let mut retired: HashMap<String, BTreeSet<u64>> = HashMap::new();
    for (name, path) in store_files(dir, "retired")? {
        let (identity, generation) = retirement_name(&name)?;
        let len = fs::metadata(&path)
            .map_err(|error| MarkStoreError::StoreUnreadable(format!("retired: {error}")))?
            .len();
        if len != 0 {
            return Err(MarkStoreError::StoreUnreadable(format!(
                "retired: {name} isn't empty"
            )));
        }
        retired.entry(identity).or_default().insert(generation);
    }
    Ok(retired)
}

/// Every erasure's record in `dir`. A write's temporary file isn't one; any other entry that
/// isn't a file naming an identity and holding a time as [`MarkStore::record_erasure`]
/// writes it makes the store unreadable.
fn read_erasures(dir: &Path) -> Result<HashMap<String, u64>, MarkStoreError> {
    let mut erasures = HashMap::new();
    for (name, path) in store_files(dir, "erasures")? {
        if !is_ledger_name(&name) {
            return Err(MarkStoreError::StoreUnreadable(format!(
                "erasures: {name} names no identity"
            )));
        }
        if let Some(at) = read_erasure_file(&path)? {
            erasures.insert(name, at);
        }
    }
    Ok(erasures)
}

/// The erasure's record at `path`: `None` where there is none. A record that isn't a time in
/// decimal, without sign, leading zero or space, as the store writes it, makes the store
/// unreadable.
fn read_erasure_file(path: &Path) -> Result<Option<u64>, MarkStoreError> {
    erasure_from_bytes(read_record_file(path, MAX_ERASURE_FILE)?.as_deref())
}

fn erasure_from_bytes(bytes: Option<&[u8]>) -> Result<Option<u64>, MarkStoreError> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let at = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse::<u64>().ok().filter(|at| at.to_string() == text));
    at.map(Some)
        .ok_or_else(|| MarkStoreError::StoreUnreadable("erasures: a record isn't a time".into()))
}

/// Every identity with a file in `dir`, ascending.
fn list_marks(dir: &Path) -> Result<Vec<String>, MarkStoreError> {
    let mut identities = Vec::new();
    for (name, _) in store_files(dir, "marks")? {
        if !is_ledger_name(&name) {
            return Err(MarkStoreError::StoreUnreadable(format!(
                "marks: {name} names no identity"
            )));
        }
        identities.push(name);
    }
    identities.sort();
    Ok(identities)
}

/// Read the mark file at `path`.
fn read_mark_file(path: &Path) -> Result<MarkRead, MarkStoreError> {
    Ok(mark_from_bytes(
        read_record_file(path, MAX_MARK_FILE)?.as_deref(),
    ))
}

fn mark_from_bytes(bytes: Option<&[u8]>) -> MarkRead {
    let Some(bytes) = bytes else {
        return MarkRead::Missing;
    };
    if bytes.len() as u64 > MAX_MARK_FILE {
        return MarkRead::NotAMark;
    }
    match serde_json::from_slice::<AccountMark>(bytes) {
        Ok(mark) if mark.is_valid() => MarkRead::Mark(mark),
        Ok(_) | Err(_) => MarkRead::NotAMark,
    }
}

fn read_record_file(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, MarkStoreError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MarkStoreError::StoreUnreadable(error.to_string())),
    };
    if !file.metadata()?.is_file() {
        return Err(MarkStoreError::StoreUnreadable(
            "a record isn't a file".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    Ok(Some(bytes))
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
        match store
            .advance(identity, at, KEY, 100)
            .await
            .expect("advance")
        {
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
        // Another mark than the one judged isn't taken.
        let other = AccountMark { seq: 8, ..mark };
        assert_eq!(
            store
                .take(ALICE, other, OTHER_KEY, 500)
                .await
                .expect("take"),
            MarkWrite::Unchanged(MarkRead::Mark(mark))
        );
        assert_eq!(
            store.take(ALICE, mark, OTHER_KEY, 500).await.expect("take"),
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
            store
                .take(ALICE, AccountMark::zero(KEY, 1), KEY, 500)
                .await
                .expect("take"),
            MarkWrite::Unchanged(MarkRead::Missing)
        );
        fs::write(marks_dir(&dir).join(BOB), b"{}").expect("write");
        assert_eq!(
            store
                .take(BOB, AccountMark::zero(KEY, 1), KEY, 500)
                .await
                .expect("take"),
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
            store.set_key(ALICE, OTHER_KEY, 100).await.expect("set"),
            MarkWrite::Written(changed)
        );
        assert_eq!(
            store.set_key(ALICE, OTHER_KEY, 100).await.expect("again"),
            MarkWrite::Unchanged(MarkRead::Mark(changed))
        );
        assert_eq!(
            store.set_key(BOB, OTHER_KEY, 100).await.expect("none"),
            MarkWrite::Unchanged(MarkRead::Missing)
        );
    }

    #[tokio::test]
    async fn test_marks_advance_moves_to_a_higher_pair() {
        let (dir, store) = open();
        store.create_zero(ALICE, KEY, 100).await.expect("zero");
        assert_eq!(
            store
                .advance(ALICE, head(1, 5, 1), KEY, 100)
                .await
                .expect("first"),
            Advance::Moved(mark_at(1, 5, 1, 100))
        );
        assert_eq!(
            store
                .advance(ALICE, head(1, 6, 2), KEY, 100)
                .await
                .expect("seq"),
            Advance::Moved(mark_at(1, 6, 2, 100))
        );
        // A later generation is higher whatever its `seq`, and takes the key it names.
        let moved = AccountMark {
            key: OTHER_KEY,
            ..mark_at(2, 1, 3, 100)
        };
        assert_eq!(
            store
                .advance(ALICE, head(2, 1, 3), OTHER_KEY, 100)
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
                .advance(ALICE, head(2, 5, 1), OTHER_KEY, 100)
                .await
                .expect("equal"),
            Advance::Unchanged(mark)
        );
        assert_eq!(
            store
                .advance(ALICE, head(2, 4, 9), KEY, 100)
                .await
                .expect("lower seq"),
            Advance::Overtaken(mark)
        );
        assert_eq!(
            store
                .advance(ALICE, head(1, 50, 9), KEY, 100)
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
                .advance(ALICE, head(1, 5, 2), KEY, 100)
                .await
                .expect("fork"),
            Advance::Fork(mark)
        );
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(mark));
    }

    #[tokio::test]
    async fn test_marks_advance_refuses_another_creation_time() {
        let (_dir, store) = open();
        // Another account's (0, 0) mark, made after the account the move is for was erased.
        store.create_zero(ALICE, KEY, 200).await.expect("zero");
        let held = AccountMark::zero(KEY, 200);
        for created_at_ms in [100, 300] {
            assert_eq!(
                store
                    .advance(ALICE, head(1, 5, 1), KEY, created_at_ms)
                    .await
                    .expect("other account"),
                Advance::OtherAccount(held)
            );
        }
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(held));
        assert_eq!(
            store
                .advance(ALICE, head(1, 5, 1), KEY, 200)
                .await
                .expect("its own"),
            Advance::Moved(mark_at(1, 5, 1, 200))
        );
    }

    #[tokio::test]
    async fn test_marks_set_key_refuses_another_creation_time() {
        let (_dir, store) = open();
        let mark = with_mark(&store, ALICE, head(1, 3, 1)).await;
        assert_eq!(
            store.set_key(ALICE, OTHER_KEY, 99).await.expect("other"),
            MarkWrite::Unchanged(MarkRead::Mark(mark))
        );
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(mark));
    }

    #[tokio::test]
    async fn test_marks_write_anew_refused_for_an_erased_account() {
        let (_dir, store) = open();
        store.record_erasure(ALICE, 700).await.expect("record");
        for created_at_ms in [600, 700] {
            assert_eq!(
                store
                    .write_anew(ALICE, head(3, 1, 4), KEY, created_at_ms)
                    .await
                    .expect("erased"),
                MarkWrite::Unchanged(MarkRead::Missing)
            );
        }
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
        // An account created after the record is a later one: its mark is written.
        assert_eq!(
            store
                .write_anew(ALICE, head(3, 1, 4), KEY, 701)
                .await
                .expect("later account"),
            MarkWrite::Written(mark_at(3, 1, 4, 701))
        );
    }

    #[tokio::test]
    async fn test_marks_forget_keeps_a_record_that_covers_a_mark() {
        let (_dir, store) = open();
        store.create_zero(ALICE, KEY, 1_000).await.expect("zero");
        store.record_erasure(ALICE, 2_000).await.expect("record");
        store.create_zero(BOB, KEY, 3_000).await.expect("zero");
        store.record_erasure(BOB, 2_500).await.expect("record");
        // Alice's mark is a leftover her record covers; Bob's is a later account's.
        assert_eq!(
            store.forget_erasures_before(5_000).await.expect("forget"),
            1
        );
        assert_eq!(
            store.erasures().await.expect("list"),
            vec![(ALICE.to_string(), 2_000)]
        );
        store.delete_created_by(ALICE, 2_000).await.expect("delete");
        assert_eq!(
            store.forget_erasures_before(5_000).await.expect("forget"),
            1
        );
        assert_eq!(store.erasures().await.expect("list"), vec![]);
    }

    #[tokio::test]
    async fn test_marks_advance_without_a_mark_changes_nothing() {
        let (dir, store) = open();
        assert_eq!(
            store
                .advance(ALICE, head(1, 1, 1), KEY, 100)
                .await
                .expect("missing"),
            Advance::NoMark(MarkRead::Missing)
        );
        fs::write(marks_dir(&dir).join(BOB), b"[]").expect("write");
        assert_eq!(
            store
                .advance(BOB, head(1, 1, 1), KEY, 100)
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
                store.advance(ALICE, bad, KEY, 100).await,
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
        assert!(matches!(
            store.retire(ALICE, 0).await,
            Err(MarkStoreError::InvalidGeneration)
        ));
        store.retire(BOB, 5).await.expect("without a mark");
        store.delete(ALICE).await.expect("delete");
        drop(store);
        let store = MarkStore::open(dir.path()).expect("reopen");
        assert_eq!(store.retired(ALICE).await.expect("retired"), vec![2]);
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
            store.advance(ALICE, head(1, 2, 2), KEY, 100).await,
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
        assert!(store.advance(ALICE, head(1, 2, 2), KEY, 100).await.is_err());
        assert!(
            marks_dir(&dir).join(ALICE).exists(),
            "the rename landed without its sync"
        );
        // The retry writes and syncs again before it reports the move.
        assert_eq!(
            store
                .advance(ALICE, head(1, 2, 2), KEY, 100)
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
        assert!(store.advance(ALICE, head(1, 2, 2), KEY, 100).await.is_err());
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

    #[tokio::test]
    async fn test_marks_erasure_keeps_the_latest_time() {
        let (dir, store) = open();
        assert_eq!(store.erasure(ALICE).await.expect("read"), None);
        assert_eq!(
            store.record_erasure(ALICE, 2_000).await.expect("record"),
            None
        );
        // An older time never replaces a newer one.
        assert_eq!(
            store.record_erasure(ALICE, 1_000).await.expect("record"),
            Some(2_000)
        );
        assert_eq!(store.erasure(ALICE).await.expect("read"), Some(2_000));
        assert_eq!(
            store.record_erasure(ALICE, 3_000).await.expect("record"),
            Some(2_000)
        );
        drop(store);
        let store = MarkStore::open(dir.path()).expect("reopen");
        assert_eq!(store.erasure(ALICE).await.expect("read"), Some(3_000));
        assert_eq!(
            fs::read(dir.path().join("accounts/erasures").join(ALICE)).expect("file"),
            b"3000"
        );
        // A name no file can name was never recorded.
        assert_eq!(store.erasure("../x").await.expect("read"), None);
        assert!(matches!(
            store.record_erasure("../x", 1).await,
            Err(MarkStoreError::InvalidIdentity)
        ));
    }

    #[tokio::test]
    async fn test_marks_withdrawn_erasure_puts_the_earlier_record_back() {
        let (dir, store) = open();
        let previous = store.record_erasure(ALICE, 1_000).await.expect("record");
        assert_eq!(previous, None);
        store
            .withdraw_erasure(ALICE, 1_000, previous)
            .await
            .expect("withdraw");
        assert_eq!(store.erasure(ALICE).await.expect("read"), None);
        assert!(!dir.path().join("accounts/erasures").join(ALICE).exists());
        store.record_erasure(ALICE, 1_000).await.expect("record");
        let previous = store.record_erasure(ALICE, 2_000).await.expect("record");
        store
            .withdraw_erasure(ALICE, 2_000, previous)
            .await
            .expect("withdraw");
        assert_eq!(store.erasure(ALICE).await.expect("read"), Some(1_000));
        // A later record in its place stays.
        store.record_erasure(ALICE, 3_000).await.expect("record");
        store
            .withdraw_erasure(ALICE, 2_000, Some(1_000))
            .await
            .expect("withdraw");
        assert_eq!(store.erasure(ALICE).await.expect("read"), Some(3_000));
    }

    #[tokio::test]
    async fn test_marks_erasures_list_and_forget_before_a_time() {
        let (dir, store) = open();
        store.record_erasure(BOB, 1_000).await.expect("record");
        store.record_erasure(ALICE, 5_000).await.expect("record");
        assert_eq!(
            store.erasures().await.expect("list"),
            vec![(ALICE.to_string(), 5_000), (BOB.to_string(), 1_000)]
        );
        assert_eq!(
            store.forget_erasures_before(5_000).await.expect("forget"),
            1
        );
        assert_eq!(
            store.erasures().await.expect("list"),
            vec![(ALICE.to_string(), 5_000)]
        );
        drop(store);
        let store = MarkStore::open(dir.path()).expect("reopen");
        assert_eq!(store.erasure(BOB).await.expect("read"), None);
        assert_eq!(store.erasure(ALICE).await.expect("read"), Some(5_000));
    }

    #[tokio::test]
    async fn test_marks_erasure_retry_syncs_the_directory_before_it_is_recorded() {
        let (dir, store, faults) = open_faulty();
        let erasures = dir.path().join("accounts").join("erasures");
        faults.lock().fail_sync(&erasures, 1);
        assert!(store.record_erasure(ALICE, 1_000).await.is_err());
        assert!(erasures.join(ALICE).exists(), "the rename landed");
        // A read reconciles the uncertain write from disk, syncing before taking it up.
        assert_eq!(store.erasure(ALICE).await.expect("read"), Some(1_000));
        // The retry finds the file and syncs before it reports the record.
        store.record_erasure(ALICE, 1_000).await.expect("retry");
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.erasure(ALICE).await.expect("read"), Some(1_000));
    }

    #[tokio::test]
    async fn test_marks_erasure_sync_failure_then_crash_loses_only_the_unanswered_record() {
        let (dir, store, faults) = open_faulty();
        let erasures = dir.path().join("accounts").join("erasures");
        faults.lock().fail_sync(&erasures, 1);
        assert!(store.record_erasure(ALICE, 1_000).await.is_err());
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.erasure(ALICE).await.expect("read"), None);
    }

    #[tokio::test]
    async fn test_marks_bad_erasure_file_is_unreadable() {
        let (dir, store) = open();
        drop(store);
        let erasures = dir.path().join("accounts").join("erasures");
        fs::write(erasures.join(".alice.00.tmp"), b"x").expect("temp");
        let store = MarkStore::open(dir.path()).expect("open");
        assert_eq!(store.erasure(ALICE).await.expect("temp skipped"), None);
        drop(store);
        for (name, content) in [
            ("alice", &b"01000"[..]),
            ("alice", b" 1000"),
            ("alice", b"1000\n"),
            ("alice", b"+1000"),
            ("alice", b""),
            ("alice", b"99999999999999999999999"),
            ("Alice", b"1000"),
            ("alice.1", b"1000"),
        ] {
            fs::write(erasures.join(name), content).expect("write");
            let store = MarkStore::open(dir.path()).expect("open");
            assert!(
                matches!(
                    store.erasure(BOB).await,
                    Err(MarkStoreError::StoreUnreadable(_))
                ),
                "{name} {content:?}"
            );
            assert!(MarkView::open(dir.path()).is_err(), "{name}");
            fs::remove_file(erasures.join(name)).expect("remove");
        }
        fs::create_dir(erasures.join(ALICE)).expect("dir");
        let store = MarkStore::open(dir.path()).expect("open");
        assert!(matches!(
            store.erasure(BOB).await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
    }

    #[tokio::test]
    async fn test_marks_generation_zero_or_nonempty_retirement_is_unreadable() {
        let (dir, store) = open();
        store.retire(ALICE, 1).await.expect("retire");
        drop(store);
        let retired = dir.path().join("accounts").join("retired");
        // Only a corrupt or hostile file makes a generation-0 retirement: it fails the
        // store closed, as does a retirement with content, or one that isn't a file.
        for (name, content, dir_entry) in [
            ("alice.0", &b""[..], false),
            ("alice.2", b"x", false),
            ("alice.3", b"", true),
        ] {
            if dir_entry {
                fs::create_dir(retired.join(name)).expect("dir");
            } else {
                fs::write(retired.join(name), content).expect("write");
            }
            let store = MarkStore::open(dir.path()).expect("open");
            assert!(
                matches!(
                    store.retired(ALICE).await,
                    Err(MarkStoreError::StoreUnreadable(_))
                ),
                "{name}"
            );
            assert!(MarkView::open(dir.path()).is_err(), "{name}");
            if dir_entry {
                fs::remove_dir(retired.join(name)).expect("remove");
            } else {
                fs::remove_file(retired.join(name)).expect("remove");
            }
        }
        let store = MarkStore::open(dir.path()).expect("open");
        assert_eq!(store.retired(ALICE).await.expect("retired"), vec![1]);
    }

    #[tokio::test]
    async fn test_marks_entry_that_is_not_a_file_is_unreadable() {
        let (dir, store) = open();
        drop(store);
        fs::create_dir(marks_dir(&dir).join(ALICE)).expect("dir");
        let store = MarkStore::open(dir.path()).expect("open");
        assert!(matches!(
            store.read(ALICE).await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
        assert!(matches!(
            store.list().await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
    }

    #[tokio::test]
    async fn test_marks_rebuilt_store_drops_marks_retirements_and_erasures_together() {
        let (dir, store) = open();
        with_mark(&store, ALICE, head(1, 4, 1)).await;
        store.retire(ALICE, 1).await.expect("retire");
        store.record_erasure(BOB, 1_000).await.expect("record");
        drop(store);
        fs::remove_dir_all(dir.path().join("accounts")).expect("lose the store");
        let store = MarkStore::open(dir.path()).expect("rebuild");
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Missing);
        assert!(store.retired(ALICE).await.expect("retired").is_empty());
        assert_eq!(store.erasure(BOB).await.expect("erasure"), None);
        assert!(store.erasures().await.expect("erasures").is_empty());
    }

    #[tokio::test]
    async fn test_marks_view_reads_the_erasures() {
        let (dir, store) = open();
        store.record_erasure(ALICE, 1_000).await.expect("record");
        let view = MarkView::open(dir.path()).expect("view");
        assert_eq!(view.erasure(ALICE).expect("erasure"), Some(1_000));
        assert_eq!(view.erasure(BOB).expect("erasure"), None);
    }

    #[tokio::test]
    async fn test_marks_cached_authority_requires_the_live_store() {
        let mut failures = Vec::new();
        for fault in [
            "missing_id",
            "corrupt_id",
            "unmounted",
            "missing_marks",
            "missing_retired",
            "bad_erasures",
        ] {
            for action in [
                "read",
                "retired",
                "erasure",
                "erasures",
                "list",
                "create",
                "take",
                "set_key",
                "advance",
                "write_anew",
                "delete",
                "delete_created_by",
                "retire",
                "record_erasure",
                "withdraw_erasure",
                "forget_erasures",
            ] {
                let (dir, store) = open();
                let mark = with_mark(&store, ALICE, head(1, 4, 1)).await;
                store.retire(ALICE, 1).await.expect("retire");
                store.record_erasure(BOB, 1_000).await.expect("record");
                let accounts = dir.path().join("accounts");
                match fault {
                    "missing_id" => fs::remove_file(accounts.join("store-id")).expect("remove"),
                    "corrupt_id" => {
                        fs::write(accounts.join("store-id"), b"invalid").expect("corrupt")
                    }
                    "unmounted" => {
                        fs::rename(&accounts, dir.path().join("detached")).expect("detach")
                    }
                    "missing_marks" => fs::remove_dir_all(accounts.join("marks")).expect("remove"),
                    "missing_retired" => {
                        fs::remove_dir_all(accounts.join("retired")).expect("remove")
                    }
                    "bad_erasures" => {
                        fs::remove_dir_all(accounts.join("erasures")).expect("remove");
                        fs::write(accounts.join("erasures"), b"not a directory").expect("replace");
                    }
                    _ => unreachable!(),
                }
                let result = match action {
                    "read" => store.read(ALICE).await.map(|_| ()),
                    "retired" => store.retired(ALICE).await.map(|_| ()),
                    "erasure" => store.erasure(BOB).await.map(|_| ()),
                    "erasures" => store.erasures().await.map(|_| ()),
                    "list" => store.list().await.map(|_| ()),
                    "create" => store.create_zero("carol", KEY, 1).await.map(|_| ()),
                    "take" => store.take(ALICE, mark, KEY, 200).await.map(|_| ()),
                    "set_key" => store.set_key(ALICE, [8; 32], 100).await.map(|_| ()),
                    "advance" => store
                        .advance(ALICE, mark.head(), KEY, 100)
                        .await
                        .map(|_| ()),
                    "write_anew" => store
                        .write_anew(ALICE, head(2, 1, 9), KEY, 100)
                        .await
                        .map(|_| ()),
                    "delete" => store.delete(ALICE).await,
                    "delete_created_by" => store.delete_created_by(ALICE, 100).await.map(|_| ()),
                    "retire" => store.retire(ALICE, 2).await,
                    "record_erasure" => store.record_erasure(ALICE, 1_000).await.map(|_| ()),
                    "withdraw_erasure" => store.withdraw_erasure(BOB, 1_000, None).await,
                    "forget_erasures" => store.forget_erasures_before(2_000).await.map(|_| ()),
                    _ => unreachable!(),
                };
                if !matches!(result, Err(MarkStoreError::StoreUnreadable(_))) {
                    failures.push(format!("{fault}/{action}: {result:?}"));
                }
            }
        }
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[tokio::test]
    async fn test_marks_live_store_replacement_discards_every_cached_authority() {
        let (dir, store) = open();
        with_mark(&store, ALICE, head(1, 4, 1)).await;
        store.retire(ALICE, 1).await.expect("retire");
        store.record_erasure(BOB, 1_000).await.expect("record");
        let (replacement, _) = open();
        fs::rename(dir.path().join("accounts"), dir.path().join("detached")).expect("detach");
        fs::rename(
            replacement.path().join("accounts"),
            dir.path().join("accounts"),
        )
        .expect("replace");
        assert!(matches!(
            store.read(ALICE).await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
        assert_eq!(
            store.read(ALICE).await.expect("new store"),
            MarkRead::Missing
        );
        assert!(store.retired(ALICE).await.expect("retired").is_empty());
        assert!(store.erasure(BOB).await.expect("erasure").is_none());
        store
            .create_zero(ALICE, KEY, 200)
            .await
            .expect("new account");
    }

    #[tokio::test]
    async fn test_marks_live_store_return_preserves_durable_records() {
        let (dir, store) = open();
        let mark = with_mark(&store, ALICE, head(1, 4, 1)).await;
        store.retire(ALICE, 1).await.expect("retire");
        store.record_erasure(BOB, 1_000).await.expect("record");
        let accounts = dir.path().join("accounts");
        let detached = dir.path().join("detached");
        fs::rename(&accounts, &detached).expect("detach");
        assert!(matches!(
            store.read(ALICE).await,
            Err(MarkStoreError::StoreUnreadable(_))
        ));
        fs::rename(&detached, &accounts).expect("restore");
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(mark));
        assert_eq!(store.retired(ALICE).await.expect("retired"), vec![1]);
        assert_eq!(store.erasure(BOB).await.expect("erasure"), Some(1_000));
        store
            .advance(ALICE, head(1, 5, 2), KEY, 100)
            .await
            .expect("advance");
    }

    async fn queued_writes(wait_on_mutex: bool) {
        use crate::store::LockTiming;
        use std::future::Future as _;
        use std::task::Poll;

        let mut failures = Vec::new();
        for action in [
            "create",
            "take",
            "set_key",
            "advance",
            "write_anew",
            "delete",
            "delete_created_by",
            "retire",
            "record_erasure",
            "withdraw_erasure",
            "forget_erasures",
        ] {
            let (_dir, open_store) = open();
            let mark = with_mark(&open_store, ALICE, head(1, 4, 1)).await;
            open_store.record_erasure(BOB, 1_000).await.expect("record");
            let (started, reached) = tokio::sync::oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel();
            let inner = open_store.inner.clone();
            let occupied = tokio::task::spawn_blocking(move || {
                let _guard = wait_on_mutex.then(|| inner.writes.lock());
                let _ = started.send(());
                let _ = wait.recv();
            });
            reached.await.expect("write blocked");
            let freshness = LockFreshness::confirmed_ago(
                std::time::Duration::ZERO,
                LockTiming::checking_every(std::time::Duration::from_millis(250)),
            );
            let store = open_store.gated(freshness.clone());
            let (waiting, at_mutex) = tokio::sync::oneshot::channel();
            if wait_on_mutex {
                *store.inner.write_waiting.lock() = Some(waiting);
            }
            let write = async {
                match action {
                    "create" => store.create_zero(BOB, KEY, 2_000).await.map(|_| ()),
                    "take" => store.take(ALICE, mark, OTHER_KEY, 2_000).await.map(|_| ()),
                    "set_key" => store.set_key(ALICE, OTHER_KEY, 100).await.map(|_| ()),
                    "advance" => store
                        .advance(ALICE, head(1, 5, 2), KEY, 100)
                        .await
                        .map(|_| ()),
                    "write_anew" => store
                        .write_anew(BOB, head(1, 5, 2), KEY, 2_000)
                        .await
                        .map(|_| ()),
                    "delete" => store.delete(ALICE).await,
                    "delete_created_by" => {
                        store.delete_created_by(ALICE, u64::MAX).await.map(|_| ())
                    }
                    "retire" => store.retire(ALICE, 1).await,
                    "record_erasure" => store.record_erasure(ALICE, 2_000).await.map(|_| ()),
                    "withdraw_erasure" => store.withdraw_erasure(BOB, 1_000, None).await,
                    "forget_erasures" => store.forget_erasures_before(u64::MAX).await.map(|_| ()),
                    _ => unreachable!(),
                }
            };
            tokio::pin!(write);
            assert!(freshness.is_fresh());
            std::future::poll_fn(|cx| {
                assert!(write.as_mut().poll(cx).is_pending(), "write queued");
                Poll::Ready(())
            })
            .await;
            if wait_on_mutex {
                at_mutex.await.expect("write reached the held mutex");
            }
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while freshness.is_fresh() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("freshness expired");
            release.send(()).expect("release write");
            occupied.await.expect("blocking task");
            let result = write.await;
            if !matches!(result, Err(MarkStoreError::LockStale)) {
                failures.push(format!("{action}: {result:?}"));
                continue;
            }
            assert_eq!(
                open_store.read(ALICE).await.expect("mark"),
                MarkRead::Mark(mark)
            );
            assert_eq!(open_store.read(BOB).await.expect("mark"), MarkRead::Missing);
            assert!(
                open_store
                    .retired(ALICE)
                    .await
                    .expect("retirements")
                    .is_empty()
            );
            assert_eq!(open_store.erasure(ALICE).await.expect("erasure"), None);
            assert_eq!(open_store.erasure(BOB).await.expect("erasure"), Some(1_000));
        }
        assert!(
            failures.is_empty(),
            "writes after freshness expired: {failures:?}"
        );
    }

    #[test]
    fn test_marks_queued_pool_writes_refuse_an_expired_instance_lock() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .expect("runtime")
            .block_on(queued_writes(false));
    }

    #[test]
    fn test_marks_queued_mutex_writes_refuse_an_expired_instance_lock() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .expect("runtime")
            .block_on(queued_writes(true));
    }

    #[tokio::test]
    async fn test_marks_stale_gate_refuses_every_write() {
        use crate::store::LockTiming;
        let (dir, open_store) = open();
        let mark = with_mark(&open_store, ALICE, head(1, 4, 1)).await;
        open_store.record_erasure(BOB, 1_000).await.expect("record");
        let timing = LockTiming::checking_every(std::time::Duration::from_secs(5));
        let store = open_store.gated(LockFreshness::confirmed_ago(
            std::time::Duration::from_secs(15),
            timing,
        ));
        let stale = |result: Result<(), MarkStoreError>| {
            assert!(
                matches!(result, Err(MarkStoreError::LockStale)),
                "{result:?}"
            );
        };
        stale(store.create_zero(BOB, KEY, 1).await.map(|_| ()));
        stale(store.take(ALICE, mark, OTHER_KEY, 9).await.map(|_| ()));
        stale(store.set_key(ALICE, OTHER_KEY, 100).await.map(|_| ()));
        stale(
            store
                .advance(ALICE, head(1, 5, 2), KEY, 100)
                .await
                .map(|_| ()),
        );
        stale(
            store
                .write_anew(BOB, head(1, 5, 2), KEY, 9)
                .await
                .map(|_| ()),
        );
        stale(store.delete(ALICE).await);
        stale(store.delete_created_by(ALICE, u64::MAX).await.map(|_| ()));
        stale(store.retire(ALICE, 1).await);
        stale(store.record_erasure(ALICE, 2_000).await.map(|_| ()));
        stale(store.withdraw_erasure(BOB, 1_000, None).await);
        stale(store.forget_erasures_before(u64::MAX).await.map(|_| ()));
        // Reads go on, and nothing changed.
        assert_eq!(store.read(ALICE).await.expect("read"), MarkRead::Mark(mark));
        assert_eq!(store.read(BOB).await.expect("read"), MarkRead::Missing);
        assert!(store.retired(ALICE).await.expect("retired").is_empty());
        assert_eq!(store.erasure(BOB).await.expect("erasure"), Some(1_000));
        assert_eq!(store.erasure(ALICE).await.expect("erasure"), None);
        drop((store, open_store));
        let reopened = MarkStore::open(dir.path()).expect("reopen");
        assert_eq!(
            reopened.read(ALICE).await.expect("read"),
            MarkRead::Mark(mark)
        );
        // Confirmed just now: the writes go through.
        let fresh = reopened.gated(LockFreshness::confirmed_ago(
            std::time::Duration::ZERO,
            timing,
        ));
        fresh.retire(ALICE, 1).await.expect("retire");
    }
    #[tokio::test]
    async fn test_marks_live_record_loss_cannot_be_read_taken_or_advanced() {
        for fault in ["missing", "corrupt", "rollback", "fork", "key", "creation"] {
            let (dir, store) = open();
            let mark = with_mark(&store, ALICE, head(1, 4, 4)).await;
            assert_eq!(
                store
                    .advance(ALICE, mark.head(), KEY, 100)
                    .await
                    .expect("same head"),
                Advance::Unchanged(mark)
            );
            let path = marks_dir(&dir).join(ALICE);
            let lost = match fault {
                "missing" => {
                    fs::remove_file(&path).expect("remove");
                    MarkRead::Missing
                }
                "corrupt" => {
                    fs::write(&path, b"invalid").expect("corrupt");
                    MarkRead::NotAMark
                }
                _ => {
                    let mut changed = mark;
                    match fault {
                        "rollback" => {
                            changed.seq = 3;
                            changed.chain_hash = [3; 32];
                        }
                        "fork" => changed.chain_hash = [9; 32],
                        "key" => changed.key = OTHER_KEY,
                        "creation" => changed.created_at_ms += 1,
                        _ => unreachable!(),
                    }
                    fs::write(&path, serde_json::to_vec(&changed).expect("encode"))
                        .expect("replace");
                    MarkRead::NotAMark
                }
            };
            for _ in 0..2 {
                assert_eq!(store.read(ALICE).await.expect("read"), lost, "{fault}");
                for tip in [mark.head(), head(1, 5, 5)] {
                    assert_eq!(
                        store.advance(ALICE, tip, KEY, 100).await.expect("advance"),
                        Advance::NoMark(lost),
                        "{fault}"
                    );
                }
                assert_eq!(
                    store.take(ALICE, mark, OTHER_KEY, 200).await.expect("take"),
                    MarkWrite::Unchanged(lost),
                    "{fault}"
                );
                assert_eq!(
                    store.set_key(ALICE, OTHER_KEY, 100).await.expect("set key"),
                    MarkWrite::Unchanged(lost),
                    "{fault}"
                );
            }
            let recovered = mark_at(2, 1, 8, 100);
            assert_eq!(
                store
                    .write_anew(ALICE, recovered.head(), KEY, 100)
                    .await
                    .expect("generation start"),
                MarkWrite::Written(recovered)
            );
            assert_eq!(
                store.read(ALICE).await.expect("read recovered"),
                MarkRead::Mark(recovered)
            );
        }
    }

    #[tokio::test]
    async fn test_marks_selected_retirement_checks_live_authority() {
        for fault in ["missing", "corrupt", "unexpected", "unexpected_zero"] {
            let (dir, store) = open();
            let generation = if fault == "unexpected_zero" { 0 } else { 1 };
            let path = dir
                .path()
                .join("accounts/retired")
                .join(format!("alice.{generation}"));
            if matches!(fault, "missing" | "corrupt") {
                store.retire(ALICE, generation).await.expect("record");
                assert!(store.is_retired(ALICE, generation).await.expect("durable"));
                if fault == "missing" {
                    fs::remove_file(&path).expect("remove");
                } else {
                    fs::write(&path, b"invalid").expect("corrupt");
                }
            } else {
                assert!(!store.is_retired(ALICE, generation).await.expect("absent"));
                fs::write(&path, b"").expect("unexpected record");
            }
            for _ in 0..2 {
                assert!(
                    store.is_retired(ALICE, generation).await.is_err(),
                    "{fault}"
                );
                if generation != 0 {
                    assert!(store.retire(ALICE, generation).await.is_err(), "{fault}");
                }
            }
            assert!(
                !store
                    .is_retired(BOB, generation)
                    .await
                    .expect("other identity")
            );
            assert!(!store.is_retired(ALICE, 2).await.expect("other generation"));
        }
    }

    #[tokio::test]
    async fn test_marks_selected_erasure_refuses_unexpected_record() {
        let (dir, store) = open();
        assert_eq!(store.erasure(ALICE).await.expect("none"), None);
        fs::write(dir.path().join("accounts/erasures/alice"), b"100").expect("unexpected record");
        for _ in 0..2 {
            assert!(store.erasure(ALICE).await.is_err());
            assert!(store.record_erasure(ALICE, 200).await.is_err());
            assert!(store.withdraw_erasure(ALICE, 100, None).await.is_err());
        }
        assert_eq!(store.erasure(BOB).await.expect("other identity"), None);
        assert!(store.erasures().await.is_err());
    }

    #[tokio::test]
    async fn test_marks_selected_retirement_waits_for_sync() {
        let (dir, store, faults) = open_faulty();
        let directory = dir.path().join("accounts/retired");
        faults.lock().fail_sync(&directory, 1);
        assert!(store.retire(ALICE, 1).await.is_err());
        assert!(!store.is_retired(ALICE, 1).await.expect("not durable"));
        store.retire(BOB, 1).await.expect("same directory sync");
        assert!(store.is_retired(ALICE, 1).await.expect("covered"));
        let store = crash_and_reopen(&dir, &faults);
        assert!(
            store
                .is_retired(ALICE, 1)
                .await
                .expect("durable after crash")
        );
    }

    #[tokio::test]
    async fn test_marks_unrelated_ledger_loss_does_not_stop_an_account() {
        for ledger in ["retired", "erasures"] {
            for corrupt in [false, true] {
                let (dir, store) = open();
                let mark = with_mark(&store, ALICE, head(1, 4, 4)).await;
                store.retire(BOB, 1).await.expect("retire other account");
                store
                    .record_erasure(BOB, 1_000)
                    .await
                    .expect("record other account");
                let name = if ledger == "retired" { "bob.1" } else { BOB };
                let path = dir.path().join("accounts").join(ledger).join(name);
                if corrupt {
                    fs::write(path, b"invalid").expect("corrupt other record");
                } else {
                    fs::remove_file(path).expect("remove other record");
                }
                assert_eq!(
                    store.read(ALICE).await.expect("unaffected mark"),
                    MarkRead::Mark(mark)
                );
                assert_eq!(
                    store.erasure(ALICE).await.expect("unaffected erasure"),
                    None
                );
                assert_eq!(
                    store.read("carol").await.expect("missing mark"),
                    MarkRead::Missing
                );
                assert_eq!(store.erasure("carol").await.expect("missing erasure"), None);
                assert!(matches!(
                    store
                        .advance(ALICE, head(1, 5, 5), KEY, 100)
                        .await
                        .expect("unaffected write"),
                    Advance::Moved(_)
                ));
                assert!(
                    store.list().await.is_err(),
                    "aggregate validates all records"
                );
                assert!(
                    store.erasures().await.is_err(),
                    "aggregate validates all records"
                );
                assert!(
                    store.retired(BOB).await.is_err(),
                    "retirement listing validates all records"
                );
                assert!(store.forget_erasures_before(2_000).await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn test_marks_unselected_retirement_does_not_stop_an_account() {
        let (dir, store) = open();
        let mark = with_mark(&store, ALICE, head(1, 4, 4)).await;
        store.retire(ALICE, 2).await.expect("other generation");
        fs::write(dir.path().join("accounts/retired/alice.2"), b"invalid")
            .expect("corrupt other generation");
        assert_eq!(
            store.read(ALICE).await.expect("mark generation"),
            MarkRead::Mark(mark)
        );
        assert_eq!(store.erasure(ALICE).await.expect("erasure"), None);
        assert!(
            store.retired(ALICE).await.is_err(),
            "complete retirement listing"
        );
    }

    #[tokio::test]
    async fn test_marks_live_ledger_changes_refuse_reads_and_writes() {
        for ledger in ["retired", "erasures"] {
            for fault in ["missing", "corrupt", "replacement"] {
                let (dir, store) = open();
                let mark = with_mark(&store, ALICE, head(1, 4, 4)).await;
                store.retire(ALICE, 1).await.expect("retire");
                store.record_erasure(ALICE, 1_000).await.expect("record");
                let name = if ledger == "retired" {
                    "alice.1"
                } else {
                    ALICE
                };
                let path = dir.path().join("accounts").join(ledger).join(name);
                let original = fs::read(&path).expect("original");
                let replacement = path.with_file_name("alice.2");
                match fault {
                    "missing" => fs::remove_file(&path).expect("remove"),
                    "corrupt" => fs::write(&path, b"invalid").expect("corrupt"),
                    "replacement" if ledger == "retired" => {
                        fs::rename(&path, &replacement).expect("replace")
                    }
                    "replacement" => fs::write(&path, b"999").expect("rollback"),
                    _ => unreachable!(),
                }
                for _ in 0..2 {
                    let mut outcomes = vec![
                        store.read(ALICE).await.map(|_| ()),
                        store.retired(ALICE).await.map(|_| ()),
                        store.erasures().await.map(|_| ()),
                        store.list().await.map(|_| ()),
                        store.create_zero(ALICE, KEY, 100).await.map(|_| ()),
                        store.take(ALICE, mark, KEY, 200).await.map(|_| ()),
                        store.set_key(ALICE, OTHER_KEY, 100).await.map(|_| ()),
                        store
                            .advance(ALICE, head(1, 5, 5), KEY, 100)
                            .await
                            .map(|_| ()),
                        store
                            .write_anew(ALICE, head(2, 1, 8), KEY, 100)
                            .await
                            .map(|_| ()),
                        store.delete(ALICE).await,
                        store.delete_created_by(ALICE, 100).await.map(|_| ()),
                        store.retire(ALICE, 1).await,
                        store.forget_erasures_before(2_000).await.map(|_| ()),
                    ];
                    if ledger == "erasures" {
                        outcomes.extend([
                            store.erasure(ALICE).await.map(|_| ()),
                            store.record_erasure(ALICE, 2_000).await.map(|_| ()),
                            store.withdraw_erasure(ALICE, 1_000, None).await,
                        ]);
                    }
                    outcomes.push(store.is_retired(ALICE, 1).await.map(|_| ()));
                    assert!(
                        outcomes.iter().all(|outcome| matches!(
                            outcome,
                            Err(MarkStoreError::StoreUnreadable(_))
                        )),
                        "{ledger}/{fault}: {outcomes:?}"
                    );
                }
                if ledger == "retired" && fault == "replacement" {
                    fs::remove_file(replacement).expect("remove replacement");
                }
                fs::write(path, original).expect("restore");
                assert_eq!(store.read(ALICE).await.expect("mark"), MarkRead::Mark(mark));
                assert_eq!(store.retired(ALICE).await.expect("retired"), vec![1]);
                assert_eq!(store.erasure(ALICE).await.expect("erasure"), Some(1_000));
            }
        }
    }

    #[tokio::test]
    async fn test_marks_unsynced_record_does_not_hide_subsequent_corruption() {
        let (dir, store, faults) = open_faulty();
        let mark = with_mark(&store, ALICE, head(1, 1, 1)).await;
        faults.lock().fail_sync(&marks_dir(&dir), 1);
        assert!(store.advance(ALICE, head(1, 2, 2), KEY, 100).await.is_err());
        assert_eq!(
            store.read(ALICE).await.expect("pending"),
            MarkRead::Mark(mark)
        );
        fs::write(marks_dir(&dir).join(ALICE), b"invalid").expect("corrupt pending file");
        assert_eq!(store.read(ALICE).await.expect("lost"), MarkRead::NotAMark);
        assert_eq!(
            store
                .advance(ALICE, head(1, 3, 3), KEY, 100)
                .await
                .expect("refused"),
            Advance::NoMark(MarkRead::NotAMark)
        );
    }

    #[tokio::test]
    async fn test_marks_directory_sync_covers_other_pending_records() {
        let (dir, store, faults) = open_faulty();
        let mark = with_mark(&store, ALICE, head(1, 1, 1)).await;
        faults.lock().fail_sync(&marks_dir(&dir), 1);
        assert!(store.advance(ALICE, head(1, 2, 2), KEY, 100).await.is_err());
        assert_eq!(
            store.read(ALICE).await.expect("pending"),
            MarkRead::Mark(mark)
        );
        store
            .create_zero(BOB, KEY, 100)
            .await
            .expect("same directory sync");
        assert_eq!(
            store.read(ALICE).await.expect("covered"),
            MarkRead::Mark(mark_at(1, 2, 2, 100))
        );
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(
            store.read(ALICE).await.expect("after crash"),
            MarkRead::Mark(mark_at(1, 2, 2, 100))
        );
    }

    #[tokio::test]
    async fn test_marks_view_reads_current_ledgers() {
        let (dir, store) = open();
        let view = MarkView::open(dir.path()).expect("view");
        assert_eq!(view.erasure(ALICE).expect("none"), None);
        assert!(view.retired(ALICE).expect("none").is_empty());
        store.record_erasure(ALICE, 100).await.expect("record");
        store.retire(ALICE, 1).await.expect("retire");
        assert_eq!(view.erasure(ALICE).expect("current"), Some(100));
        assert_eq!(view.retired(ALICE).expect("current"), vec![1]);
    }

    #[tokio::test]
    async fn test_marks_view_refuses_live_record_corruption() {
        let (dir, store) = open();
        store.record_erasure(ALICE, 100).await.expect("record");
        store.retire(ALICE, 1).await.expect("retire");
        let view = MarkView::open(dir.path()).expect("view");
        fs::write(dir.path().join("accounts/erasures/alice"), b"invalid").expect("corrupt");
        fs::write(dir.path().join("accounts/retired/alice.1"), b"invalid").expect("corrupt");
        assert!(view.erasure(ALICE).is_err());
        assert!(
            view.erasure(BOB).is_err(),
            "an unreadable ledger is not an absent record"
        );
        assert!(view.retired(ALICE).is_err());
    }
    #[tokio::test]
    async fn test_marks_unsynced_ledger_changes_require_the_written_bytes() {
        for ledger in ["retired", "erasures"] {
            let (dir, store, faults) = open_faulty();
            let directory = dir.path().join("accounts").join(ledger);
            let name = if ledger == "retired" {
                "alice.1"
            } else {
                ALICE
            };
            let path = directory.join(name);
            faults.lock().fail_sync(&directory, 1);
            if ledger == "retired" {
                assert!(store.retire(ALICE, 1).await.is_err());
            } else {
                assert!(store.record_erasure(ALICE, 100).await.is_err());
            }
            let pending = fs::read(&path).expect("landed bytes");
            fs::write(&path, b"101").expect("changed bytes");
            for _ in 0..2 {
                assert!(matches!(
                    store.retired(ALICE).await,
                    Err(MarkStoreError::StoreUnreadable(_))
                ));
                assert!(matches!(
                    store.is_retired(ALICE, 1).await,
                    Err(MarkStoreError::StoreUnreadable(_))
                ));
            }
            fs::write(&path, pending).expect("restore pending bytes");
            if ledger == "retired" {
                assert!(
                    store
                        .retired(ALICE)
                        .await
                        .expect("not yet durable")
                        .is_empty()
                );
                store.retire(ALICE, 1).await.expect("retry");
                assert_eq!(store.retired(ALICE).await.expect("durable"), vec![1]);
            } else {
                assert_eq!(
                    store.erasure(ALICE).await.expect("synced before read"),
                    Some(100)
                );
            }
        }
    }
    async fn view_loses_retirement(recorded_before_open: bool) {
        let (dir, store) = open();
        if recorded_before_open {
            store.retire(ALICE, 1).await.expect("retire");
        }
        let view = MarkView::open(dir.path()).expect("view");
        if !recorded_before_open {
            store.retire(ALICE, 1).await.expect("retire");
        }
        assert_eq!(view.retired(ALICE).expect("observed"), vec![1]);
        fs::remove_file(dir.path().join("accounts/retired/alice.1")).expect("lost retirement");
        assert!(
            view.retired(ALICE).is_err(),
            "an observed retirement cannot disappear within this store"
        );
    }

    #[tokio::test]
    async fn test_marks_view_remembers_initial_retirements() {
        view_loses_retirement(true).await;
    }

    #[tokio::test]
    async fn test_marks_view_remembers_newly_read_retirements() {
        view_loses_retirement(false).await;
    }
}
