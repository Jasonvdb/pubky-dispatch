//! The identity keyring over the host's secure vault (Switch spec 13.3).

use crate::{SignerFfiError, runtime};
use pubky_switch_signer::{
    AddOutcome, IdentityKeyring, IdentitySecret, KeyError, SecretVault, VaultError,
};
use std::{fmt, sync::Arc};
use zeroize::Zeroize;

/// Secure storage shared by every handle, thread and process using the identity
/// (Switch spec 13.3).
///
/// Only a host implements it: the bindings call its methods and export none of them, so
/// nothing returns the seed to a caller. A method returns or takes exactly the seed's 32
/// bytes and puts no secret byte in what it throws.
///
/// A method never waits for a call into the bindings. One it starts on its own thread,
/// before it returns, is refused with [`SignerFfiError::InvalidInput`] and changes nothing.
/// One it waits for from another thread isn't seen: it holds one of the bindings' few
/// threads for host callbacks, and once all are held this way, a call that needs one fails
/// with [`SignerFfiError::RuntimeUnavailable`] after a wait.
#[uniffi::export(callback_interface)]
pub trait HostVault: Send + Sync {
    /// Return the held 32-byte seed, or none if empty. Report a read failure separately
    /// (Switch spec 13.3).
    fn load(&self) -> Result<Option<Vec<u8>>, VaultFailure>;

    /// Atomically store the seed only if empty, across all callers (Switch spec 13.3).
    /// Stored means the seed survives power loss. An occupied vault keeps its seed,
    /// even if the supplied bytes match. A failed write leaves the vault as it was.
    fn add(&self, secret: Vec<u8>) -> Result<VaultAdd, VaultFailure>;

    /// Atomically compare and delete every held copy of the expected seed (Switch spec 13.3).
    /// An empty vault or a different seed is a successful no-op. Report any failure to
    /// check or delete.
    fn delete(&self, expected: Vec<u8>) -> Result<(), VaultFailure>;
}

/// The outcome of adding an identity seed to the vault (Switch spec 13.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum VaultAdd {
    /// The empty vault now holds the supplied seed (Switch spec 13.3).
    Stored,
    /// The vault kept the seed it already held (Switch spec 13.3).
    Occupied,
}

/// A vault failure identified only by its class (Switch spec 13.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum VaultFailure {
    /// The vault is locked (Switch spec 13.3).
    #[error("the vault is locked")]
    Locked,
    /// The vault is unavailable (Switch spec 13.3).
    #[error("the vault is unavailable")]
    Unavailable,
    /// The vault reported another failure (Switch spec 13.3).
    #[error("other vault failure")]
    Other,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for VaultFailure {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Other
    }
}

impl From<VaultFailure> for VaultError {
    fn from(failure: VaultFailure) -> Self {
        let class = match failure {
            VaultFailure::Locked => "locked",
            VaultFailure::Unavailable => "unavailable",
            VaultFailure::Other => "other vault failure",
        };
        Self(class.into())
    }
}

struct VaultAdapter(Box<dyn HostVault>);

impl fmt::Debug for VaultAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultAdapter(..)")
    }
}

impl SecretVault for VaultAdapter {
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
        runtime::in_callback(|| self.0.load())?
            .map(|mut loaded| take_seed(&mut loaded))
            .transpose()
    }

    fn add(&self, secret: &IdentitySecret) -> Result<AddOutcome, VaultError> {
        // The host takes the bytes by value: this copy, and the buffer the bindings fill
        // from it, are transfer copies the bindings free without a wipe (the crate docs).
        let bytes = secret.as_bytes().to_vec();
        Ok(match runtime::in_callback(|| self.0.add(bytes))? {
            VaultAdd::Stored => AddOutcome::Stored,
            VaultAdd::Occupied => AddOutcome::Occupied,
        })
    }

    fn delete(&self, expected: &IdentitySecret) -> Result<(), VaultError> {
        let bytes = expected.as_bytes().to_vec();
        runtime::in_callback(|| self.0.delete(bytes))?;
        Ok(())
    }
}

/// The seed in what the vault loaded, which is wiped in place whatever its length.
fn take_seed(loaded: &mut [u8]) -> Result<IdentitySecret, VaultError> {
    let seed = IdentitySecret::from_slice(loaded)
        .map_err(|_| VaultError("the vault seed must be 32 bytes".into()));
    loaded.zeroize();
    seed
}

/// Generate an identity, store it in an empty vault and verify it by reading it back
/// (Switch spec 13.3).
#[uniffi::export]
pub async fn create_keyring(vault: Box<dyn HostVault>) -> Result<Arc<Keyring>, SignerFfiError> {
    bind_keyring(vault, IdentityKeyring::create).await
}

/// Open the identity already held by the vault (Switch spec 13.3).
#[uniffi::export]
pub async fn open_keyring(vault: Box<dyn HostVault>) -> Result<Arc<Keyring>, SignerFfiError> {
    bind_keyring(vault, IdentityKeyring::open).await
}

async fn bind_keyring(
    host: Box<dyn HostVault>,
    bind: fn(Arc<dyn SecretVault>) -> Result<IdentityKeyring, KeyError>,
) -> Result<Arc<Keyring>, SignerFfiError> {
    run_vault_call(move || {
        let identity = Arc::new(bind(Arc::new(VaultAdapter(host)))?);
        Ok(Arc::new(Keyring { identity }))
    })
    .await
}

async fn run_vault_call<T: Send + 'static>(
    call: impl FnOnce() -> Result<T, KeyError> + Send + 'static,
) -> Result<T, SignerFfiError> {
    runtime::run(async move { Ok(runtime::blocking(call).await??) }).await
}

/// An identity's public key and access to its host vault (Switch spec 13.3).
#[derive(uniffi::Object)]
pub struct Keyring {
    identity: Arc<IdentityKeyring>,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keyring(..)")
    }
}

#[uniffi::export]
impl Keyring {
    /// The identity's cached 32-byte Ed25519 public key (Switch spec 13.3).
    pub fn public_key(&self) -> Vec<u8> {
        self.identity.public_key().to_vec()
    }

    /// The Pubky ID of the cached public key (Switch spec 13.3).
    pub fn pubky_id(&self) -> String {
        self.identity.pubky_id()
    }

    /// Reload the identity and derive the public half of its backup key (Switch wire 3.13).
    pub async fn backup_public_key(&self) -> Result<BackupPublicKey, SignerFfiError> {
        let identity = self.identity.clone();
        run_vault_call(move || {
            let (public_key, key_id) = identity.backup_public()?;
            Ok(BackupPublicKey {
                public_key: public_key.to_vec(),
                key_id: key_id.to_vec(),
            })
        })
        .await
    }
}

/// Delete `expected` from `vault` through the bindings, as the signer does when it removes
/// an identity. For the host programs only: no production build exports it.
///
/// # Errors
///
/// [`SignerFfiError::Key`]: malformed for an `expected` that isn't 32 bytes, or the
/// vault's failure.
#[cfg(feature = "test-fixtures")]
#[uniffi::export]
pub async fn fixture_vault_delete(
    vault: Box<dyn HostVault>,
    mut expected: Vec<u8>,
) -> Result<(), SignerFfiError> {
    let secret = IdentitySecret::from_slice(&expected);
    expected.zeroize();
    let secret = secret?;
    run_vault_call(move || Ok(VaultAdapter(vault).delete(&secret)?)).await
}

/// The public recipient of a signer backup (Switch wire 3.13).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct BackupPublicKey {
    /// The 32-byte backup public key (Switch wire 3.13).
    pub public_key: Vec<u8>,
    /// The 8-byte identifier of the backup key, its `kid` (Switch wire 3.13).
    pub key_id: Vec<u8>,
}

impl fmt::Debug for BackupPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BackupPublicKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyFailure;
    use pubky_switch_core::enc::{b64, pubky_key};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    /// A vault in memory. As the vector seeds the tests read, what it holds and is handed
    /// are test seeds in ordinary, unwiped memory.
    #[derive(Default)]
    struct MemoryVault {
        held: Mutex<Option<Vec<u8>>>,
        load_failure: Option<VaultFailure>,
        short_load: bool,
        long_load: bool,
        concurrent_adds: Option<(Mutex<usize>, Condvar)>,
        reentered: Option<Mutex<Option<SignerFfiError>>>,
        loads: AtomicUsize,
    }

    impl fmt::Debug for MemoryVault {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("MemoryVault(..)")
        }
    }

    impl HostVault for MemoryVault {
        fn load(&self) -> Result<Option<Vec<u8>>, VaultFailure> {
            self.loads.fetch_add(1, Ordering::Relaxed);
            if let Some(failure) = self.load_failure {
                return Err(failure);
            }
            if let Some(reentered) = &self.reentered {
                // The host calls the bindings from inside its callback and waits.
                let inner = tokio::runtime::Handle::current()
                    .block_on(open_keyring(Box::new(MemoryVault::default())));
                *reentered.lock().unwrap() = inner.err();
            }
            let mut secret = self.held.lock().unwrap().clone();
            if self.short_load
                && let Some(bytes) = &mut secret
            {
                bytes.pop();
            }
            if self.long_load
                && let Some(bytes) = &mut secret
            {
                bytes.push(7);
            }
            Ok(secret)
        }

        fn add(&self, secret: Vec<u8>) -> Result<VaultAdd, VaultFailure> {
            if let Some((count, ready)) = &self.concurrent_adds {
                let mut arrived = count.lock().unwrap();
                *arrived += 1;
                ready.notify_all();
                let (arrived, _) = ready
                    .wait_timeout_while(arrived, Duration::from_secs(5), |n| *n < 2)
                    .unwrap();
                if *arrived < 2 {
                    return Err(VaultFailure::Unavailable);
                }
            }
            let mut held = self.held.lock().unwrap();
            if held.is_some() {
                return Ok(VaultAdd::Occupied);
            }
            *held = Some(secret);
            Ok(VaultAdd::Stored)
        }

        fn delete(&self, expected: Vec<u8>) -> Result<(), VaultFailure> {
            let mut held = self.held.lock().unwrap();
            if held.as_ref() == Some(&expected) {
                *held = None;
            }
            Ok(())
        }
    }

    /// The tests keep the vault they hand over, to look into it.
    impl HostVault for Arc<MemoryVault> {
        fn load(&self) -> Result<Option<Vec<u8>>, VaultFailure> {
            (**self).load()
        }

        fn add(&self, secret: Vec<u8>) -> Result<VaultAdd, VaultFailure> {
            (**self).add(secret)
        }

        fn delete(&self, expected: Vec<u8>) -> Result<(), VaultFailure> {
            (**self).delete(expected)
        }
    }

    fn host(vault: &Arc<MemoryVault>) -> Box<dyn HostVault> {
        Box::new(vault.clone())
    }

    fn vector_identity() -> serde_json::Value {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/keys.json"
        )))
        .unwrap();
        vectors["identities"][0].clone()
    }

    fn vector_seed() -> Vec<u8> {
        let vector = vector_identity();
        let hex = vector["secret_hex"].as_str().unwrap();
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect()
    }

    fn assert_key_failure(error: &SignerFfiError, expected: KeyFailure) {
        assert!(matches!(error, SignerFfiError::Key { kind } if *kind == expected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_create_and_open() {
        let vault = Arc::new(MemoryVault::default());
        let created = create_keyring(host(&vault)).await.unwrap();
        assert_eq!(vault.loads.load(Ordering::Relaxed), 1);
        assert_eq!(vault.held.lock().unwrap().as_ref().unwrap().len(), 32);
        assert_eq!(created.public_key().len(), 32);
        assert!(!created.pubky_id().is_empty());
        assert_eq!(vault.loads.load(Ordering::Relaxed), 1);
        let opened = open_keyring(host(&vault)).await.unwrap();
        assert!(created.pubky_id() == opened.pubky_id());
        assert!(created.public_key() == opened.public_key());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_occupied() {
        let vault = Arc::new(MemoryVault::default());
        assert_eq!(vault.add(vector_seed()).unwrap(), VaultAdd::Stored);
        let error = create_keyring(host(&vault)).await.unwrap_err();
        assert_key_failure(&error, KeyFailure::Occupied);
        assert!(vault.load().unwrap() == Some(vector_seed()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_missing() {
        let error = open_keyring(Box::new(MemoryVault::default()))
            .await
            .unwrap_err();
        assert_key_failure(&error, KeyFailure::Missing);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_short_load() {
        let vault = Arc::new(MemoryVault {
            short_load: true,
            ..Default::default()
        });
        vault.add(vector_seed()).unwrap();
        assert_eq!(vault.load().unwrap().unwrap().len(), 31);
        let error = open_keyring(host(&vault)).await.unwrap_err();
        assert_key_failure(&error, KeyFailure::Vault);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_long_load() {
        let vault = Arc::new(MemoryVault {
            long_load: true,
            ..Default::default()
        });
        vault.add(vector_seed()).unwrap();
        assert_eq!(vault.load().unwrap().unwrap().len(), 33);
        let error = open_keyring(host(&vault)).await.unwrap_err();
        assert_key_failure(&error, KeyFailure::Vault);
        let hex = vector_identity()["secret_hex"].as_str().unwrap().to_owned();
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains(&hex[..16]));
        }
    }

    #[test]
    fn test_vault_loaded_bytes_are_wiped() {
        for length in [31, 32, 33] {
            let mut loaded = vec![7; length];
            assert_eq!(take_seed(&mut loaded).is_ok(), length == 32);
            assert_eq!(loaded, vec![0; length]);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_failures() {
        let detail = "private host diagnostic";
        let unexpected = VaultFailure::from(uniffi::UnexpectedUniFFICallbackError::new(detail));
        assert_eq!(unexpected, VaultFailure::Other);
        for (failure, description) in [
            (VaultFailure::Locked, "locked"),
            (VaultFailure::Unavailable, "unavailable"),
            (unexpected, "other vault failure"),
        ] {
            let vault = Arc::new(MemoryVault {
                load_failure: Some(failure),
                ..Default::default()
            });
            vault.add(vector_seed()).unwrap();
            let error = VaultAdapter(host(&vault)).load().unwrap_err();
            assert!(error.0 == description);
            let error = open_keyring(host(&vault)).await.unwrap_err();
            assert_key_failure(&error, KeyFailure::Vault);
            for text in [error.to_string(), format!("{error:?}")] {
                assert!(!text.contains(detail));
                assert!(!text.contains(description));
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_call_from_inside_a_callback_is_refused() {
        let vault = Arc::new(MemoryVault {
            reentered: Some(Mutex::new(None)),
            ..Default::default()
        });
        vault.add(vector_seed()).unwrap();
        // The outer call goes through; the call the host made from inside `load` was refused.
        open_keyring(host(&vault)).await.unwrap();
        let inner = vault.reentered.as_ref().unwrap().lock().unwrap().take();
        assert!(matches!(inner, Some(SignerFfiError::InvalidInput { .. })));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_backup_public() {
        let vault = Arc::new(MemoryVault::default());
        vault.add(vector_seed()).unwrap();
        let keyring = open_keyring(host(&vault)).await.unwrap();
        let vector = vector_identity();
        let expected_id = vector["pubky_id"].as_str().unwrap();
        assert!(keyring.pubky_id() == expected_id);
        assert!(keyring.public_key() == pubky_key(expected_id).unwrap());
        let backup = keyring.backup_public_key().await.unwrap();
        assert_eq!((backup.public_key.len(), backup.key_id.len()), (32, 8));
        assert!(b64(&backup.public_key) == vector["backup_public"].as_str().unwrap());
        assert!(b64(&backup.key_id) == vector["backup_kid"].as_str().unwrap());
        assert_eq!(backup, keyring.backup_public_key().await.unwrap());
        vault.delete(vector_seed()).unwrap();
        let error = keyring.backup_public_key().await.unwrap_err();
        assert_key_failure(&error, KeyFailure::Missing);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_racing_creates() {
        let vault = Arc::new(MemoryVault {
            concurrent_adds: Some(Default::default()),
            ..Default::default()
        });
        let (first, second) =
            tokio::join!(create_keyring(host(&vault)), create_keyring(host(&vault)));
        let (created, refused) = match (first, second) {
            (Ok(created), Err(refused)) | (Err(refused), Ok(created)) => (created, refused),
            _ => panic!("expected exactly one stored identity"),
        };
        assert_key_failure(&refused, KeyFailure::Occupied);
        assert!(open_keyring(host(&vault)).await.unwrap().public_key() == created.public_key());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_compare_delete() {
        let vault = Arc::new(MemoryVault::default());
        create_keyring(host(&vault)).await.unwrap();
        let adapter = VaultAdapter(host(&vault));
        let held = adapter.load().unwrap().unwrap();
        let other = IdentitySecret::from_slice(&vector_seed()).unwrap();
        adapter.delete(&other).unwrap();
        assert!(adapter.load().unwrap().unwrap().as_bytes() == held.as_bytes());
        adapter.delete(&held).unwrap();
        assert!(adapter.load().unwrap().is_none());
        adapter.delete(&held).unwrap();
        assert!(adapter.load().unwrap().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_replaced_identity() {
        let vault = Arc::new(MemoryVault::default());
        vault.add(vector_seed()).unwrap();
        let keyring = open_keyring(host(&vault)).await.unwrap();
        vault.delete(vector_seed()).unwrap();
        create_keyring(host(&vault)).await.unwrap();
        // The handle stays bound to the identity it opened: another seed isn't used for it.
        let error = keyring.backup_public_key().await.unwrap_err();
        assert_key_failure(&error, KeyFailure::Mismatch);
        assert!(keyring.pubky_id() == vector_identity()["pubky_id"].as_str().unwrap());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_vault_debug() {
        let vault = Arc::new(MemoryVault::default());
        vault.add(vector_seed()).unwrap();
        let adapter = VaultAdapter(host(&vault));
        let keyring = open_keyring(host(&vault)).await.unwrap();
        let backup = keyring.backup_public_key().await.unwrap();
        for (value, safe_text) in [
            (&*vault as &dyn fmt::Debug, "MemoryVault(..)"),
            (&adapter, "VaultAdapter(..)"),
            (&*keyring, "Keyring(..)"),
            (&backup, "BackupPublicKey(..)"),
            (&VaultAdd::Stored, "Stored"),
            (&VaultAdd::Occupied, "Occupied"),
            (&VaultFailure::Locked, "Locked"),
            (&VaultFailure::Unavailable, "Unavailable"),
            (&VaultFailure::Other, "Other"),
        ] {
            assert!(format!("{value:?}") == safe_text);
        }
    }
}
