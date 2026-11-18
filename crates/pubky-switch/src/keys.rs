//! The service key and the push keys (Switch spec 6.5, Switch wire 7.1, 8.1).
//!
//! The service signs with one key, the service key, for every account it hosts and for every
//! answer it can't tie to an account (Switch wire 7.1). The key store holds it and the push
//! keys that sign webhooks (Switch wire 8.1). The mark store lies beside it, in the same
//! directory: the per-account marks, the retirements and the erasures' records
//! ([`crate::marks`]).
//!
//! [`KeyStore`] is the interface, ready for an HSM or a KMS. [`FileKeyStore`] keeps the keys
//! in files on a disk of their own, written and synced before an answer goes out. Secret keys
//! never leave the key store: callers get public keys and signatures.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{Read, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use ed25519_dalek::SigningKey;
use parking_lot::Mutex;
use pubky_switch_core::{
    chain::{ChainTip, SignedHead},
    signing::Signs,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The longest identity a file of the mark store names, in characters.
const MAX_IDENTITY_LEN: usize = 64;

/// The service key's file under the store's directory: its 32-byte secret seed.
const SERVICE_KEY_FILE: &str = "service-key";

/// The key store settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeysConfig {
    /// The directory of the file key store. Required to run the service. Put it on a disk
    /// that database backups don't cover, and back up the service key on its own.
    pub path: Option<PathBuf>,
    /// How many days the operator keeps database backups: the mark store keeps each
    /// erasure's record that long, so a database restored from any kept backup erases the account
    /// again (Switch spec 6.5). Unset, the store keeps every erasure's record for good.
    pub backup_retention_days: Option<u64>,
}

/// The readiness check of the file key store: its directories are there and readable.
#[derive(Clone, Debug)]
pub struct KeyStoreReadiness(pub FileKeyStore);

impl crate::admin::ReadinessCheck for KeyStoreReadiness {
    fn name(&self) -> &str {
        "keys"
    }

    fn check(&self) -> crate::admin::CheckFuture<'_> {
        let root = self.0.root().to_path_buf();
        Box::pin(async move {
            for dir in DIRS {
                fs::read_dir(root.join(dir))
                    .map_err(|_| format!("the key store's {dir} directory isn't readable"))?;
            }
            Ok(())
        })
    }
}

/// The ID of one push key: 32 lowercase hex digits, chosen at random.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyId(String);

impl KeyId {
    /// Parse a key ID.
    pub fn parse(text: &str) -> Result<Self, KeyStoreError> {
        if text.len() == 32
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(text.to_string()))
        } else {
            Err(KeyStoreError::InvalidId)
        }
    }

    /// The ID as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A new random ID, for a key whose deletion is owed before it exists
    /// ([`KeyStore::generate_as`]).
    pub fn random() -> Result<Self, KeyStoreError> {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).map_err(|_| KeyStoreError::Random)?;
        Ok(Self(hex::encode(raw)))
    }
}

impl TryFrom<String> for KeyId {
    type Error = KeyStoreError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<KeyId> for String {
    fn from(id: KeyId) -> Self {
        id.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A newly generated push key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceKey {
    /// Its ID in the key store.
    pub id: KeyId,
    /// Its Ed25519 public key.
    pub public: [u8; 32],
}

/// What a key store can fail at.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// No key with this ID.
    #[error("no such key")]
    NotFound,
    /// Another process holds the key store's directory ([`FileKeyStore::lock_dir`]).
    #[error("the key store at {0} is in use by another process")]
    InUse(String),
    /// A key ID or identity that isn't well formed.
    #[error("invalid key ID or identity")]
    InvalidId,
    /// Stored key material that doesn't decode.
    #[error("corrupt key store entry: {0}")]
    Corrupt(String),
    /// The storage failed.
    #[error("key store storage: {0}")]
    Io(#[from] std::io::Error),
    /// No randomness for a new key.
    #[error("no randomness for a new key")]
    Random,
}

/// A future returned by a [`KeyStore`] method.
pub type KeyFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, KeyStoreError>> + Send + 'a>>;

/// Holds the service key and the push keys.
///
/// Every write is durable when its future resolves. A write runs to its end, in order with
/// the store's other writes, even if its caller stops waiting.
pub trait KeyStore: Send + Sync {
    /// The service key's signer: the one key the service signs with, for every account and
    /// every answer it can't tie to one (Switch wire 7.1).
    fn current(&self) -> ServiceSigner;

    /// The signer of the service key whose public key is `public`, if the store holds it:
    /// the key an account is answered with (Switch wire 7.3, Table 2).
    fn signer_for(&self, public: &[u8; 32]) -> Option<ServiceSigner>;

    /// Generate a new push key under `id`, an ID the caller chose ([`KeyId::random`]), so the
    /// caller can owe its deletion durably before it exists (Switch wire 8.1). An `id`
    /// already in use is refused.
    fn generate_as<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceKey>;

    /// The public key of push key `id`.
    fn public_key<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, [u8; 32]>;

    /// A signer for push key `id`, which signs webhooks (Switch wire 8.2).
    fn signer<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceSigner>;

    /// Delete push key `id`, for good.
    fn delete<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ()>;
}

/// A key's signer: it signs `lp(label, fields...)` under a Switch label, for the core's
/// signing functions (Switch wire 2.1). The secret key stays inside it.
#[derive(Clone)]
pub struct ServiceSigner(Arc<dyn Signs + Send + Sync>);

impl ServiceSigner {
    /// A signer over `key`, for a key store that holds keys in memory or behind its own
    /// signing interface, such as an HSM's.
    pub fn new(key: Arc<dyn Signs + Send + Sync>) -> Self {
        Self(key)
    }
}

impl std::fmt::Debug for ServiceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSigner")
            .field("public", &hex::encode(self.0.public_key()))
            .finish_non_exhaustive()
    }
}

impl Signs for ServiceSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key()
    }

    fn sign_fields(&self, label: &str, fields: &[&[u8]]) -> [u8; 64] {
        self.0.sign_fields(label, fields)
    }
}

/// Sign the head at `tip` for `identity` (Switch wire 6.7). The caller signs only under the
/// account's lock, with the key and under the verdict the request judged there (Switch wire
/// 7.3 step 10, Table 2); the mark moves once the head's state is durable
/// ([`crate::marks::MarkStore::advance`]).
pub fn sign_head(signer: &ServiceSigner, identity: &[u8; 32], tip: &ChainTip) -> SignedHead {
    SignedHead::sign(signer, identity, tip)
}

/// Sign a checkpoint at `at`, a chain item at or before `head` in its generation, for
/// `identity` (Switch spec 6.5, 8.3; wire 7.4.4): a head at an earlier `seq` of the chain the
/// account holds, not a state behind its mark. The caller signs one only while the verdict
/// finds the account's state at or past its mark (Switch wire 7.3 step 10). `None` for an
/// `at` outside `head`'s chain.
pub fn sign_checkpoint(
    signer: &ServiceSigner,
    identity: &[u8; 32],
    head: &ChainTip,
    at: &ChainTip,
) -> Option<SignedHead> {
    if at.generation != head.generation || at.seq > head.seq {
        return None;
    }
    Some(SignedHead::sign(signer, identity, at))
}

/// A key store in files under one directory:
///
/// - `service-key`: the service key's 32-byte secret seed, made when the store is first
///   opened;
/// - `keys/<id>`: a push key's 32-byte secret seed;
/// - `accounts/`: the mark store: the marks, the retirements, the erasures' records and the
///   store's identity ([`crate::marks`]).
///
/// Every file is readable by the owner only, and written to a temporary file, synced,
/// renamed into place and its directory synced, so a crash leaves the old content or the new,
/// never a mix. A write that fails may have landed its rename without the directory sync, so
/// nothing the store reads from a file counts as written before a directory sync covers it:
/// a retry that finds its file in place repeats the sync before it reports success, writes
/// the file again or is refused, and the store syncs its directories when it opens, before it
/// reads them. Put the directory on a disk that database backups don't cover, and back up
/// the service key on its own: losing it loses the key every client pinned.
///
/// One process at a time may use a directory.
#[derive(Clone)]
pub struct FileKeyStore {
    inner: Arc<Inner>,
}

/// The store's directory, and how its files are written and synced.
struct Disk {
    root: PathBuf,
    /// Fails directory syncs and tracks what a crash would undo, for tests.
    #[cfg(test)]
    faults: Arc<Mutex<Faults>>,
}

struct Inner {
    disk: Disk,
    /// The service key, read or made at open.
    service: Arc<SigningKey>,
    keys: Mutex<HashMap<KeyId, Arc<SigningKey>>>,
    /// Held around every deletion, inside the blocking task
    /// that does it. A caller that stops waiting can't release it early: the task runs to its
    /// end, so writes land in the order they were checked.
    writes: Mutex<()>,
}

/// The directories under the store's root.
const DIRS: [&str; 1] = ["keys"];

/// Directory syncs that fail on request, and a model of a crash: every rename and removal
/// no directory sync covers yet, which a crash may undo.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Faults {
    /// How many of a directory's next syncs fail.
    failing: HashMap<PathBuf, usize>,
    /// Each rename or removal not yet covered by a sync of its directory, with the content
    /// the file had before it, if it existed.
    unsynced: Vec<(PathBuf, Option<Vec<u8>>)>,
}

#[cfg(test)]
impl Faults {
    /// Fail the next `times` syncs of `dir`.
    pub(crate) fn fail_sync(&mut self, dir: &Path, times: usize) {
        self.failing.insert(dir.to_path_buf(), times);
    }

    /// Whether this sync of `dir` fails.
    pub(crate) fn fails(&mut self, dir: &Path) -> bool {
        match self.failing.get_mut(dir) {
            Some(left) if *left > 0 => {
                *left -= 1;
                true
            }
            _ => false,
        }
    }

    /// A rename onto `path` or its removal landed: `before` is what the file held.
    pub(crate) fn changed(&mut self, path: &Path, before: Option<Vec<u8>>) {
        self.unsynced.push((path.to_path_buf(), before));
    }

    /// A sync of `dir` succeeded: a crash no longer undoes the changes in it.
    pub(crate) fn synced(&mut self, dir: &Path) {
        self.unsynced.retain(|(path, _)| path.parent() != Some(dir));
    }

    /// Crash: undo every change no directory sync covers, newest first.
    pub(crate) fn crash(&mut self) {
        while let Some((path, before)) = self.unsynced.pop() {
            match before {
                Some(bytes) => fs::write(&path, bytes).expect("restore"),
                None => fs::remove_file(&path).expect("remove"),
            }
        }
    }
}

impl std::fmt::Debug for FileKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKeyStore")
            .field("root", &self.inner.disk.root)
            .finish_non_exhaustive()
    }
}

impl FileKeyStore {
    /// Open the key store at `root`, creating its directories, and the service key, if they
    /// don't exist.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, KeyStoreError> {
        Self::start(Disk::new(root.into()), None)
    }

    /// Open the key store at `root` with the service key `seed` where it holds none yet, for
    /// tests that replay the vectors' fixed key.
    #[cfg(any(test, feature = "test-util"))]
    pub fn open_with_service_seed(
        root: impl Into<PathBuf>,
        seed: [u8; 32],
    ) -> Result<Self, KeyStoreError> {
        Self::start(Disk::new(root.into()), Some(seed))
    }

    /// Open the key store at `root` with `faults`, which outlive it: a test's next store on
    /// the same directory takes them over, as the next process takes over the disk.
    #[cfg(test)]
    fn open_with_faults(
        root: impl Into<PathBuf>,
        faults: Arc<Mutex<Faults>>,
    ) -> Result<Self, KeyStoreError> {
        let mut disk = Disk::new(root.into());
        disk.faults = faults;
        Self::start(disk, None)
    }

    fn start(disk: Disk, seed: Option<[u8; 32]>) -> Result<Self, KeyStoreError> {
        for dir in DIRS {
            create_private_dir(&disk.root.join(dir))?;
        }
        // An earlier process may have landed a rename or a removal and stopped before its
        // directory sync, or failed it: the file is there to read, and a crash could still
        // undo it. Sync every directory before reading any, so the service key is durable
        // before it is used.
        for dir in DIRS {
            disk.sync_dir(&disk.root.join(dir))?;
        }
        disk.sync_dir(&disk.root)?;
        let path = disk.root.join(SERVICE_KEY_FILE);
        let service = match read_seed_file(&path) {
            Ok(key) => key,
            Err(KeyStoreError::NotFound) => {
                let mut fresh = Zeroizing::new([0u8; 32]);
                match seed {
                    Some(seed) => *fresh = seed,
                    None => getrandom::fill(fresh.as_mut()).map_err(|_| KeyStoreError::Random)?,
                }
                disk.write_atomic(&path, fresh.as_ref(), true)?;
                SigningKey::from_bytes(&fresh)
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                disk,
                service: Arc::new(service),
                keys: Mutex::new(HashMap::new()),
                writes: Mutex::new(()),
            }),
        })
    }

    /// The directory.
    pub fn root(&self) -> &Path {
        &self.inner.disk.root
    }

    /// Hold the directory `root` for this process alone, as long as the lock lives: an
    /// exclusive lock on its `lock` file, which the operating system releases when the
    /// process ends. The directory is created if it doesn't exist. The service's binary takes
    /// the lock at start, before it opens the store, so a second process on the same
    /// directory refuses to start having read and written nothing in it
    /// (docs/configuration.md, "Topology").
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::InUse`] while another process holds it; [`KeyStoreError::Io`] when
    /// the directory or the file can't be opened.
    pub fn lock_dir(root: impl AsRef<Path>) -> Result<KeyDirLock, KeyStoreError> {
        let root = root.as_ref();
        create_private_dir(root)?;
        let path = root.join("lock");
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(KeyDirLock { _file: file }),
            Err(fs::TryLockError::WouldBlock) => {
                Err(KeyStoreError::InUse(root.display().to_string()))
            }
            Err(fs::TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

/// A key store directory held by this process alone ([`FileKeyStore::lock_dir`]); dropped,
/// the directory is free again.
#[derive(Debug)]
pub struct KeyDirLock {
    _file: File,
}

impl Disk {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            #[cfg(test)]
            faults: Arc::default(),
        }
    }

    /// Sync `dir`, so a rename or a removal in it is durable.
    fn sync_dir(&self, dir: &Path) -> Result<(), KeyStoreError> {
        #[cfg(test)]
        if self.faults.lock().fails(dir) {
            return Err(std::io::Error::other("injected directory sync failure").into());
        }
        sync_dir(dir)?;
        #[cfg(test)]
        self.faults.lock().synced(dir);
        Ok(())
    }

    /// Write `bytes` to `path` atomically and durably: a temporary file in the same
    /// directory, synced, renamed into place, then the directory synced. `exclusive` refuses
    /// to replace an existing file. On a failure the rename may have landed without the
    /// directory sync: whoever then finds the file in place syncs the directory before
    /// counting it as written.
    fn write_atomic(
        &self,
        path: &Path,
        bytes: &[u8],
        exclusive: bool,
    ) -> Result<(), KeyStoreError> {
        let dir = path
            .parent()
            .ok_or_else(|| KeyStoreError::Io(std::io::Error::other("path without a directory")))?;
        #[cfg(test)]
        let before = fs::read(path).ok();
        rename_into_place(dir, path, bytes, exclusive)?;
        #[cfg(test)]
        self.faults.lock().changed(path, before);
        self.sync_dir(dir)
    }

    /// Remove the file at `path`, if it is there. The removal is durable once its directory
    /// is synced, which the caller does also when the file was already gone: an earlier
    /// removal may have landed without its sync.
    fn remove_file(&self, path: &Path) -> Result<(), KeyStoreError> {
        #[cfg(test)]
        let before = fs::read(path).ok();
        match fs::remove_file(path) {
            Ok(()) => {
                #[cfg(test)]
                self.faults.lock().changed(path, before);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

impl Inner {
    fn key_path(&self, id: &KeyId) -> PathBuf {
        self.disk.root.join("keys").join(id.as_str())
    }

    /// The push key `id`, from memory or from its file. The cache's lock is held from the
    /// miss through the read to the insert, so a deletion that lands meanwhile can't be undone
    /// in memory by a read of the file from before it.
    fn load_key(&self, id: &KeyId) -> Result<Arc<SigningKey>, KeyStoreError> {
        let mut keys = self.keys.lock();
        if let Some(key) = keys.get(id) {
            return Ok(key.clone());
        }
        let key = Arc::new(read_seed_file(&self.key_path(id))?);
        keys.insert(id.clone(), key.clone());
        Ok(key)
    }

    fn generate_as_sync(&self, id: KeyId) -> Result<ServiceKey, KeyStoreError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| KeyStoreError::Random)?;
        self.disk
            .write_atomic(&self.key_path(&id), seed.as_ref(), true)?;
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        self.keys.lock().insert(id.clone(), Arc::new(key));
        Ok(ServiceKey { id, public })
    }

    fn delete_sync(&self, id: &KeyId) -> Result<(), KeyStoreError> {
        let _writes = self.writes.lock();
        self.disk.remove_file(&self.key_path(id))?;
        self.disk.sync_dir(&self.disk.root.join("keys"))?;
        self.keys.lock().remove(id);
        Ok(())
    }
}

/// Run blocking file work off the async runtime.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, KeyStoreError> + Send + 'static,
) -> Result<T, KeyStoreError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| KeyStoreError::Io(std::io::Error::other(error.to_string())))?
}

impl KeyStore for FileKeyStore {
    fn current(&self) -> ServiceSigner {
        ServiceSigner(self.inner.service.clone() as Arc<dyn Signs + Send + Sync>)
    }

    fn signer_for(&self, public: &[u8; 32]) -> Option<ServiceSigner> {
        let current = self.current();
        (current.public_key() == *public).then_some(current)
    }

    fn generate_as<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceKey> {
        let store = self.inner.clone();
        let id = id.clone();
        Box::pin(blocking(move || store.generate_as_sync(id)))
    }

    fn public_key<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, [u8; 32]> {
        let store = self.inner.clone();
        let id = id.clone();
        Box::pin(blocking(move || {
            Ok(store.load_key(&id)?.verifying_key().to_bytes())
        }))
    }

    fn signer<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceSigner> {
        let store = self.inner.clone();
        let id = id.clone();
        Box::pin(async move {
            let key = blocking(move || store.load_key(&id)).await?;
            Ok(ServiceSigner(key as Arc<dyn Signs + Send + Sync>))
        })
    }

    fn delete<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ()> {
        let store = self.inner.clone();
        let id = id.clone();
        Box::pin(blocking(move || store.delete_sync(&id)))
    }
}

/// Whether `name` may name an identity in the mark store: a Pubky
/// ID's characters, at most [`MAX_IDENTITY_LEN`]. A write's temporary file, which starts
/// with a dot, never does.
pub(crate) fn is_ledger_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_IDENTITY_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Whether `name` is a write's temporary file, as a crash before its rename leaves it.
pub(crate) fn is_temp_file(name: &str) -> bool {
    name.starts_with('.') && name.ends_with(".tmp")
}

/// Create `dir` and its parents, readable by the owner only.
pub(crate) fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `bytes` to a temporary file in `dir`, sync it and rename it to `path`, a file in
/// `dir`, readable by the owner only. `exclusive` refuses to replace an existing file. The
/// rename isn't durable until `dir` is synced.
pub(crate) fn rename_into_place(
    dir: &Path,
    path: &Path,
    bytes: &[u8],
    exclusive: bool,
) -> Result<(), KeyStoreError> {
    if exclusive && path.exists() {
        return Err(KeyStoreError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "key file exists",
        )));
    }
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| KeyStoreError::Random)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(KeyStoreError::InvalidId)?;
    let temp = dir.join(format!(".{name}.{}.tmp", hex::encode(suffix)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Sync a directory, so a rename or removal in it is durable.
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Lowercase hex for 32-byte values in JSON.
pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    /// Write `bytes` as lowercase hex.
    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Read `N` bytes of lowercase hex.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(D::Error::custom("uppercase hex"));
        }
        let mut bytes = [0u8; N];
        hex::decode_to_slice(text, &mut bytes).map_err(D::Error::custom)?;
        Ok(bytes)
    }
}

/// Read a key file at `path`: its 32-byte secret seed. [`KeyStoreError::NotFound`] when
/// there is no such file.
fn read_seed_file(path: &Path) -> Result<SigningKey, KeyStoreError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(KeyStoreError::NotFound);
        }
        Err(error) => return Err(error.into()),
    };
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut rest = [0u8; 1];
    file.read_exact(seed.as_mut())
        .map_err(|_| KeyStoreError::Corrupt(format!("key {name}: too short")))?;
    if file.read(&mut rest)? != 0 {
        return Err(KeyStoreError::Corrupt(format!("key {name}: too long")));
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// A read-only view of a [`FileKeyStore`]'s directory, for an operator's check beside a
/// running service: it creates, writes, locks and caches nothing. It hands out the service
/// key's public key only: the seed is read to derive it and dropped.
#[derive(Debug)]
pub struct KeyStoreView {
    root: PathBuf,
}

impl KeyStoreView {
    /// Open the view of the key store at `root`.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::Io`] when its `keys` directory isn't there or doesn't read.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, KeyStoreError> {
        let root = root.into();
        fs::read_dir(root.join("keys")).map_err(|error| {
            KeyStoreError::Io(std::io::Error::new(
                error.kind(),
                format!("the key store's keys directory: {error}"),
            ))
        })?;
        Ok(Self { root })
    }

    /// The directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The service key's public key; `None` when there is no service key file.
    pub fn service_key(&self) -> Result<Option<[u8; 32]>, KeyStoreError> {
        match read_seed_file(&self.root.join(SERVICE_KEY_FILE)) {
            Ok(key) => Ok(Some(key.verifying_key().to_bytes())),
            Err(KeyStoreError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_switch_core::{labels, sig};

    fn open() -> (tempfile::TempDir, FileKeyStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileKeyStore::open(dir.path()).expect("open");
        (dir, store)
    }

    fn open_faulty() -> (tempfile::TempDir, FileKeyStore, Arc<Mutex<Faults>>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let faults = Arc::new(Mutex::new(Faults::default()));
        let store = FileKeyStore::open_with_faults(dir.path(), faults.clone()).expect("open");
        (dir, store, faults)
    }

    /// The machine crashes, losing what no directory sync covers, and a new process opens
    /// the store.
    fn crash_and_reopen(dir: &tempfile::TempDir, faults: &Arc<Mutex<Faults>>) -> FileKeyStore {
        faults.lock().crash();
        FileKeyStore::open_with_faults(dir.path(), faults.clone()).expect("reopen")
    }

    #[tokio::test]
    async fn test_key_store_service_key_signs_and_is_kept() {
        let (dir, store) = open();
        let signer = store.current();
        let public = signer.public_key();
        let fields: [&[u8]; 2] = [b"status", b"body"];
        let signature = signer.sign_fields(labels::sig::HTTP_RESPONSE, &fields);
        sig::verify(&public, labels::sig::HTTP_RESPONSE, &fields, &signature)
            .expect("verifies under its label");
        assert!(sig::verify(&public, labels::sig::HEAD, &fields, &signature).is_err());
        assert_eq!(
            store.signer_for(&public).map(|s| s.public_key()),
            Some(public)
        );
        assert!(store.signer_for(&[7; 32]).is_none());
        let store = FileKeyStore::open(dir.path()).expect("reopen");
        assert_eq!(store.current().public_key(), public);
    }

    #[tokio::test]
    async fn test_key_store_service_seed_is_taken_only_where_none_is_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileKeyStore::open_with_service_seed(dir.path(), [3; 32]).expect("open");
        let fixed = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        assert_eq!(store.current().public_key(), fixed);
        let store = FileKeyStore::open_with_service_seed(dir.path(), [4; 32]).expect("reopen");
        assert_eq!(store.current().public_key(), fixed);
    }

    #[tokio::test]
    async fn test_key_store_service_key_that_doesnt_read_refuses_to_open() {
        let (dir, store) = open();
        drop(store);
        fs::write(dir.path().join(SERVICE_KEY_FILE), [1u8; 31]).expect("corrupt");
        assert!(matches!(
            FileKeyStore::open(dir.path()),
            Err(KeyStoreError::Corrupt(_))
        ));
    }

    #[test]
    fn test_key_store_directory_is_held_by_one_lock_at_a_time() {
        // A second lock on a held directory is refused, as a second process's is; once the
        // first is dropped the directory is free again.
        let dir = tempfile::tempdir().expect("tempdir");
        let held = FileKeyStore::lock_dir(dir.path()).expect("lock");
        assert!(matches!(
            FileKeyStore::lock_dir(dir.path()),
            Err(KeyStoreError::InUse(_))
        ));
        drop(held);
        let _again = FileKeyStore::lock_dir(dir.path()).expect("free again");
        // A directory that isn't there yet is created and held.
        let new = dir.path().join("new");
        let _held = FileKeyStore::lock_dir(&new).expect("lock");
        assert!(new.join("lock").exists());
    }

    #[tokio::test]
    async fn test_key_store_generate_as_takes_the_id_once() {
        // A push key generated under an ID the caller chose, owed before it exists: signs,
        // and a second key under the same ID is refused.
        let (_dir, store) = open();
        let id = KeyId::random().expect("id");
        let key = store.generate_as(&id).await.expect("generate");
        assert_eq!(key.id, id);
        assert_eq!(store.public_key(&id).await.expect("public"), key.public);
        assert_eq!(
            store.signer(&id).await.expect("signer").public_key(),
            key.public
        );
        assert!(store.generate_as(&id).await.is_err());
        assert_eq!(store.public_key(&id).await.expect("public"), key.public);
        store.delete(&id).await.expect("delete");
        assert!(matches!(
            store.public_key(&id).await,
            Err(KeyStoreError::NotFound)
        ));
        // Deleting again is fine.
        store.delete(&id).await.expect("delete again");
    }

    #[tokio::test]
    async fn test_key_store_unknown_key_is_not_found() {
        let (_dir, store) = open();
        let id = KeyId::parse("00112233445566778899aabbccddeeff").expect("id");
        assert!(matches!(
            store.public_key(&id).await,
            Err(KeyStoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_key_store_detects_corrupt_key() {
        let (dir, store) = open();
        let id = KeyId::parse("00112233445566778899aabbccddeeff").expect("id");
        fs::write(dir.path().join("keys").join(id.as_str()), [1u8; 31]).expect("write");
        assert!(matches!(
            store.public_key(&id).await,
            Err(KeyStoreError::Corrupt(_))
        ));
    }

    #[tokio::test]
    async fn test_key_store_service_key_whose_root_sync_failed_is_synced_before_it_signs() {
        // An earlier open's rename of the service key landed and its root sync failed. The
        // next open finds the file and syncs the root before it uses the key, so a crash
        // can't drop the file and have another key take its place.
        let dir = tempfile::tempdir().expect("tempdir");
        let faults = Arc::new(Mutex::new(Faults::default()));
        let path = dir.path().join(SERVICE_KEY_FILE);
        fs::write(&path, [5u8; 32]).expect("landed");
        faults.lock().changed(&path, None);
        let store = FileKeyStore::open_with_faults(dir.path(), faults.clone()).expect("open");
        let first = store.current().public_key();
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.current().public_key(), first);
        // While the root's sync fails the key isn't used at all.
        faults.lock().fail_sync(dir.path(), 1);
        assert!(FileKeyStore::open_with_faults(dir.path(), faults.clone()).is_err());
    }

    #[tokio::test]
    async fn test_key_store_generate_as_refuses_the_id_of_an_unsynced_key() {
        // A key whose rename landed without the directory sync is never handed out: the
        // write is refused, and so is a retry under the same ID.
        let (dir, store, faults) = open_faulty();
        let id = KeyId::random().expect("id");
        faults.lock().fail_sync(&dir.path().join("keys"), 1);
        assert!(store.generate_as(&id).await.is_err());
        assert!(store.generate_as(&id).await.is_err());
    }

    #[tokio::test]
    async fn test_key_store_delete_retry_syncs_the_directory() {
        let (dir, store, faults) = open_faulty();
        let id = KeyId::random().expect("id");
        store.generate_as(&id).await.expect("generate");
        faults.lock().fail_sync(&dir.path().join("keys"), 1);
        assert!(store.delete(&id).await.is_err());
        store.delete(&id).await.expect("retry");
        let store = crash_and_reopen(&dir, &faults);
        assert!(matches!(
            store.public_key(&id).await,
            Err(KeyStoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_key_store_open_fails_when_a_directory_sync_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        for failing in [dir.path().to_path_buf(), dir.path().join("keys")] {
            let faults = Arc::new(Mutex::new(Faults::default()));
            faults.lock().fail_sync(&failing, 1);
            assert!(matches!(
                FileKeyStore::open_with_faults(dir.path(), faults),
                Err(KeyStoreError::Io(_))
            ));
        }
        FileKeyStore::open(dir.path()).expect("open");
    }

    #[tokio::test]
    async fn test_key_store_view_reads_what_the_store_wrote() {
        let (dir, store) = open();
        let view = KeyStoreView::open(dir.path()).expect("view");
        assert_eq!(
            view.service_key().expect("public"),
            Some(store.current().public_key())
        );
        fs::write(dir.path().join(SERVICE_KEY_FILE), [1u8; 31]).expect("write");
        assert!(matches!(view.service_key(), Err(KeyStoreError::Corrupt(_))));
    }

    #[test]
    fn test_key_store_view_open_refuses_a_missing_directory_and_creates_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("absent");
        assert!(matches!(
            KeyStoreView::open(&root),
            Err(KeyStoreError::Io(_))
        ));
        assert!(!root.exists());
        fs::create_dir_all(root.join("keys")).expect("keys");
        let view = KeyStoreView::open(&root).expect("view");
        assert_eq!(view.root(), root.as_path());
        assert_eq!(view.service_key().expect("read"), None);
        let listing: Vec<_> = fs::read_dir(&root)
            .expect("list")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(listing.len(), 1, "{listing:?}");
    }

    #[test]
    fn test_key_id_parsing() {
        assert!(KeyId::parse("00112233445566778899aabbccddeeff").is_ok());
        for bad in [
            "",
            "00112233445566778899AABBCCDDEEFF",
            "00112233445566778899aabbccddeef",
            "../112233445566778899aabbccddeeff",
        ] {
            assert!(KeyId::parse(bad).is_err(), "{bad}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_key_store_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, store) = open();
        let id = KeyId::random().expect("id");
        store.generate_as(&id).await.expect("generate");
        for file in [
            dir.path().join("keys").join(id.as_str()),
            dir.path().join(SERVICE_KEY_FILE),
        ] {
            let mode = fs::metadata(file).expect("metadata").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let mode = fs::metadata(dir.path().join("keys"))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
