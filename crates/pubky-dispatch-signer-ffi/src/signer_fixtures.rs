//! An in-memory service for the host's enrollment checks (Dispatch wire 7.4.1).

use crate::environment::session;
use crate::signer::bind_signer;
use crate::{HostHomeserver, HostStore, HostVault, Signer, SignerFfiError, protocol};
use pubky_dispatch_client::{
    clock::TestClock,
    store::StoreHandle,
    testing::{Fault, START_MS, ScriptedDispatch},
    transport::{HttpConfig, MockTransport},
};
use pubky_dispatch_core::keys::IdentityKey;
use pubky_dispatch_signer::{Homeserver, IdentitySecret, Protocols, SignerEnv};
use std::{collections::BTreeSet, fmt, sync::Arc};
use zeroize::Zeroize;

const ENROLL: &str = "/v1/enroll";

/// An in-memory service where the identity has no account until it enrolls (Dispatch wire 7.4.1).
#[derive(uniffi::Object)]
pub struct FixtureService {
    service: Arc<ScriptedDispatch>,
    transport: Arc<MockTransport>,
    clock: Arc<TestClock>,
    homeserver: Arc<dyn Homeserver>,
    protocols: Protocols,
}

impl fmt::Debug for FixtureService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixtureService(..)")
    }
}

impl FixtureService {
    /// The signer's environment at the scripted service (Dispatch wire 7.4.1).
    pub(crate) fn signer_env(&self, store: StoreHandle) -> SignerEnv {
        SignerEnv {
            store,
            transport: self.transport.clone(),
            clock: self.clock.clone(),
            homeserver: self.homeserver.clone(),
            protocols: self.protocols.clone(),
        }
    }
}

#[uniffi::export]
impl FixtureService {
    /// An unenrolled service for the identity of the fixed test seed from the key vectors
    /// (Dispatch wire 7.4.1).
    #[uniffi::constructor]
    pub fn new(
        mut seed: Vec<u8>,
        homeserver: Box<dyn HostHomeserver>,
    ) -> Result<Arc<Self>, SignerFfiError> {
        let secret = IdentitySecret::from_slice(&seed);
        seed.zeroize();
        let identity = IdentityKey::from_secret(*secret?.as_bytes());
        let clock = Arc::new(TestClock::new(START_MS));
        let service = ScriptedDispatch::unenrolled(&identity, [22; 32], clock.clone());
        Ok(Arc::new(Self {
            transport: service.transport(),
            service,
            clock,
            homeserver: session(Arc::from(homeserver), &HttpConfig::default()),
            protocols: protocol::registered()?,
        }))
    }

    /// Commit this install's signer ID and enrollment nonce before discovery (Dispatch spec 4.3).
    pub async fn create_signer(
        &self,
        vault: Box<dyn HostVault>,
        store: Box<dyn HostStore>,
        origin: String,
    ) -> Result<Arc<Signer>, SignerFfiError> {
        bind_signer(|handle| self.signer_env(handle), store, vault, Some(origin)).await
    }

    /// As [`FixtureService::create_signer`], with the signer's handle lost as a cancelled
    /// call can lose it: nothing drops it, and the signer stays open until
    /// [`crate::shutdown_signers`] (Dispatch spec 3.1).
    pub async fn create_signer_losing_handle(
        &self,
        vault: Box<dyn HostVault>,
        store: Box<dyn HostStore>,
        origin: String,
    ) -> Result<(), SignerFfiError> {
        let signer = self.create_signer(vault, store, origin).await?;
        std::mem::forget(signer);
        Ok(())
    }

    /// The signer whose records the store holds for the identity the vault holds the key of
    /// (Dispatch spec 4.3).
    pub async fn open_signer(
        &self,
        vault: Box<dyn HostVault>,
        store: Box<dyn HostStore>,
    ) -> Result<Arc<Signer>, SignerFfiError> {
        bind_signer(|handle| self.signer_env(handle), store, vault, None).await
    }

    /// The service applies the next enrollment and its answer is lost (Dispatch wire 7.4.1).
    pub fn lose_next_enroll_answer(&self) {
        self.service.fail_next(Fault::LoseAnswer {
            path: ENROLL.into(),
        });
    }

    /// The number of distinct enrollment bodies sent to this service (Dispatch wire 7.4.1).
    pub fn enrollments(&self) -> u64 {
        let bodies: BTreeSet<_> = self
            .transport
            .requests()
            .into_iter()
            .filter(|r| r.method == "POST" && r.path_and_query == ENROLL)
            .map(|r| r.body)
            .collect();
        u64::try_from(bodies.len()).unwrap_or(u64::MAX)
    }
}
