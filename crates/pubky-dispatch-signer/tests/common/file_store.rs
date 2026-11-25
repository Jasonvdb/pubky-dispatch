//! A test store with real process locks and a replaceable atomic snapshot.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, Weak};

use pubky_dispatch_client::store::{
    AcquireOutcome, CommitOutcome, KeyValue, StateStore, StoreError, StoreLease, StoreOwner, Write,
    WriteBatch, check_owned_batch,
};

const SNAPSHOT_CAP: u64 = 64 << 20;
type Entries = BTreeMap<String, Vec<KeyValue>>;

struct Lease(File);
impl StoreLease for Lease {}

pub struct FileStore {
    directory: PathBuf,
    owners: Mutex<BTreeMap<String, (StoreOwner, Weak<Lease>)>>,
    // 1: before replacing the snapshot; 2: after replacing it, with an unknown answer.
    pub fault: AtomicU8,
}

impl FileStore {
    pub fn new(directory: &Path) -> Self {
        std::fs::create_dir_all(directory).unwrap();
        Self {
            directory: directory.to_owned(),
            owners: Mutex::default(),
            fault: AtomicU8::new(0),
        }
    }

    fn lock_file(&self, name: &str) -> Result<File, StoreError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.directory.join(name))
            .map_err(|_| StoreError::Unavailable)
    }

    fn transaction(&self) -> Result<File, StoreError> {
        let file = self.lock_file("transaction.lock")?;
        file.lock().map_err(|_| StoreError::Unavailable)?;
        Ok(file)
    }

    fn namespace_lock(&self, ns: &str) -> Result<Option<File>, StoreError> {
        // These files are never unlinked or replaced; the snapshot has a different inode.
        let file = self.lock_file(&format!("{}.lock", hex::encode(ns.as_bytes())))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(_)) => Err(StoreError::Unavailable),
        }
    }

    fn read(&self) -> Result<Entries, StoreError> {
        let file = match File::open(self.directory.join("snapshot")) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Entries::new()),
            Err(_) => return Err(StoreError::Unavailable),
        };
        let mut bytes = Vec::new();
        file.take(SNAPSHOT_CAP + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| StoreError::Unavailable)?;
        if bytes.len() as u64 > SNAPSHOT_CAP {
            return Err(StoreError::Corrupt);
        }
        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)
    }

    fn apply(&self, batch: WriteBatch) -> Result<(), StoreError> {
        let mut entries = self.read()?;
        for write in batch.into_writes() {
            match write {
                Write::Put { ns, key, value } => {
                    let keys = entries.entry(ns).or_default();
                    keys.retain(|(held, _)| held != &key);
                    keys.push((key, value));
                    keys.sort_by(|a, b| a.0.cmp(&b.0));
                }
                Write::Delete { ns, key } => {
                    if let Some(keys) = entries.get_mut(&ns) {
                        keys.retain(|(held, _)| held != &key);
                    }
                }
                Write::DeletePrefix { ns, prefix } => {
                    if let Some(keys) = entries.get_mut(&ns) {
                        keys.retain(|(held, _)| !held.starts_with(&prefix));
                    }
                }
            }
        }
        entries.retain(|_, values| !values.is_empty());
        let bytes = serde_json::to_vec(&entries).map_err(|_| StoreError::Corrupt)?;
        if bytes.len() as u64 > SNAPSHOT_CAP {
            return Err(StoreError::TooLarge {
                size: bytes.len() as u64,
                cap: SNAPSHOT_CAP,
            });
        }
        let mut temp = tempfile::NamedTempFile::new_in(&self.directory)
            .map_err(|_| StoreError::Unavailable)?;
        temp.write_all(&bytes)
            .map_err(|_| StoreError::Unavailable)?;
        temp.as_file()
            .sync_all()
            .map_err(|_| StoreError::Unavailable)?;
        let fault = self.fault.swap(0, Ordering::SeqCst);
        if fault == 1 {
            return Err(StoreError::Unavailable);
        }
        // A failure from the replacing rename is conservatively ambiguous.
        temp.persist(self.directory.join("snapshot"))
            .map_err(|_| StoreError::Unknown)?;
        File::open(&self.directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| StoreError::Unknown)?;
        if fault == 2 {
            return Err(StoreError::Unknown);
        }
        Ok(())
    }
}

impl StateStore for FileStore {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let _transaction = self.transaction()?;
        Ok(self
            .read()?
            .get(ns)
            .and_then(|entries| entries.iter().find(|(held, _)| held == key))
            .map(|(_, value)| value.clone()))
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<KeyValue>, StoreError> {
        let _transaction = self.transaction()?;
        Ok(self
            .read()?
            .remove(ns)
            .unwrap_or_default()
            .into_iter()
            .filter(|(key, _)| {
                key.starts_with(prefix) && after.is_none_or(|after| key.as_slice() > after)
            })
            .take(limit as usize)
            .collect())
    }

    fn acquire(&self, ns: &str, owner: StoreOwner) -> Result<AcquireOutcome, StoreError> {
        let _transaction = self.transaction()?;
        let Some(file) = self.namespace_lock(ns)? else {
            return Ok(AcquireOutcome::Busy);
        };
        let lease = Arc::new(Lease(file));
        self.owners
            .lock()
            .unwrap()
            .insert(ns.to_owned(), (owner, Arc::downgrade(&lease)));
        Ok(AcquireOutcome::Acquired(lease))
    }

    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        let _transaction = self.transaction()?;
        let namespaces: std::collections::BTreeSet<_> =
            batch.writes().iter().map(Write::ns).collect();
        let mut guards = Vec::new();
        for ns in namespaces {
            guards.push(self.namespace_lock(ns)?.ok_or(StoreError::InUse)?);
        }
        self.apply(batch)
    }

    fn commit_if(
        &self,
        ns: &str,
        owner: StoreOwner,
        batch: WriteBatch,
    ) -> Result<CommitOutcome, StoreError> {
        check_owned_batch(ns, &batch)?;
        let _transaction = self.transaction()?;
        let held = self
            .owners
            .lock()
            .unwrap()
            .get(ns)
            .filter(|(active, _)| active == &owner)
            .and_then(|(_, weak)| weak.upgrade());
        let Some(lease) = held else {
            return Ok(CommitOutcome::NotOwner);
        };
        // Keep the actual descriptor alive through snapshot replacement and synchronization.
        let _file = &lease.0;
        self.apply(batch)?;
        Ok(CommitOutcome::Applied)
    }
}
