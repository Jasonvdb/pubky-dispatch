//! Apps that join with the certificate in their approval (Dispatch spec 12.1 step 2).

use crate::{
    HostHomeserver, HostStore, HostVault, Signer, SignerFfiError,
    environment::session,
    protocol,
    signer::{app_id as app_id_bytes, bind_signer},
};
use pubky_dispatch_client::{
    clock::TestClock,
    store::StoreHandle,
    testing::{START_MS, ScriptError, ScriptedDispatch, Seeds, TestIdentity},
    transport::HttpConfig,
};
use pubky_dispatch_core::{
    keys::{AppKeys, IdentityKey},
    ops::OpKind,
    records::{
        AppCert, AppRecord, AppRecordBody, AppRequest, AppRequestBody, Approval, ApprovalClaim,
        AuthRequest, app_record_path,
    },
};
use pubky_dispatch_signer::{
    Homeserver, IdentitySecret, Protocols, Refusal, Signer as NativeSigner, SignerEnv, SignerError,
};
use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};
use zeroize::Zeroize;

/// An in-memory service whose apps deliver their records with the certificates they take
/// up (Dispatch wire 3.8).
#[derive(Clone, uniffi::Object)]
pub struct FixtureApps {
    service: Arc<ScriptedDispatch>,
    clock: Arc<TestClock>,
    homeserver: Arc<dyn Homeserver>,
    protocols: Protocols,
    joined: Arc<Mutex<Vec<JoinedApp>>>,
}

struct JoinedApp {
    id: [u8; 16],
    keys: AppKeys,
}

impl fmt::Debug for FixtureApps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixtureApps(..)")
    }
}

#[uniffi::export]
impl FixtureApps {
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
        Ok(Arc::new(Self {
            service: ScriptedDispatch::unenrolled(&identity, [22; 32], clock.clone()),
            clock,
            homeserver: session(Arc::from(homeserver), &HttpConfig::default()),
            protocols: protocol::registered()?,
            joined: Arc::default(),
        }))
    }

    /// An enrolled signer whose apps have joined under the certificates their approvals
    /// name (Dispatch spec 12.1 step 2).
    pub async fn signer_with_apps(
        &self,
        vault: Box<dyn HostVault>,
        store: Box<dyn HostStore>,
        origin: String,
        apps: u32,
    ) -> Result<Arc<Signer>, SignerFfiError> {
        let fixture = self.clone();
        let signer = bind_signer(
            move |store| fixture.signer_env(store),
            store,
            vault,
            Some(origin),
        )
        .await?;
        signer.resume().await?;
        self.join_apps(&signer, apps).await?;
        Ok(signer)
    }

    /// The App IDs of the joined apps in approval order (Dispatch spec 12.1).
    pub fn app_ids(&self) -> Vec<Vec<u8>> {
        self.joined().iter().map(|app| app.id.to_vec()).collect()
    }

    /// The app delivers its record carrying the new certificate (Dispatch wire 3.8 step 3).
    pub fn take_up_renewal(&self, app_id: Vec<u8>) -> Result<(), SignerFfiError> {
        let id = app_id_bytes(&app_id)?;
        let keys = self
            .joined()
            .iter()
            .find(|app| app.id == id)
            .map(|app| app.keys.clone())
            .ok_or(Refusal::NotListed)?;
        let held = self.service.app(&id);
        let cert = held.renewed.or(held.cert).ok_or(Refusal::NotJoined)?;
        self.put_record(&keys, &cert)
    }

    /// Move the shared device and service time forward in milliseconds (Dispatch spec 10.1).
    pub fn advance_time_ms(&self, by: u64) {
        self.clock.advance_ms(by);
    }
}

impl FixtureApps {
    fn joined(&self) -> MutexGuard<'_, Vec<JoinedApp>> {
        self.joined
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The signer's environment at the scripted service (Dispatch wire 7.4.1).
    fn signer_env(&self, store: StoreHandle) -> SignerEnv {
        SignerEnv {
            store,
            clock: self.clock.clone(),
            transport: self.service.transport(),
            homeserver: self.homeserver.clone(),
            protocols: self.protocols.clone(),
        }
    }

    /// Approve `apps` apps on the enrolled `signer`, each delivering its record carrying its
    /// certificate (Dispatch spec 12.1 step 2), as one signer call.
    async fn join_apps(&self, signer: &Signer, apps: u32) -> Result<(), SignerFfiError> {
        let fixture = self.clone();
        signer
            .call(move |signer| {
                Box::pin(async move {
                    let identity = TestIdentity::new(&Seeds::default(), "fixture");
                    for index in 0..apps {
                        let label = format!("app-{index}");
                        let keys = identity.app_keys(&label);
                        let auth = AuthRequest {
                            client_id: "app.example".into(),
                            client_key: identity.seed(&format!("{label}/client")),
                            caps: format!("{}:rw", app_record_path(&keys.app_id_bytes())),
                            secret: identity.seed(&format!("{label}/auth")),
                        };
                        let cert = fixture.approve(signer, &keys, &auth).await?;
                        fixture.put_record(&keys, &cert)?;
                        fixture.joined().push(JoinedApp {
                            id: cert.app_id(),
                            keys,
                        });
                    }
                    Ok(())
                })
            })
            .await
    }

    async fn approve(
        &self,
        signer: &mut NativeSigner,
        keys: &AppKeys,
        auth: &AuthRequest,
    ) -> Result<AppCert, SignerError> {
        let scopes = vec!["sample-a".into(), "sample-b".into()];
        let request = AppRequest::sign(keys, AppRequestBody::new(keys, scopes, auth))?;
        let review = signer.review(request.signed(), auth)?;
        let approved = signer.approve(review).await?;
        signer.claim_delivered(&approved.request).await?;
        let identity = signer.identity();
        let claim = ApprovalClaim::from_plaintext(&approved.claim)?;
        let json = claim.verify(&identity, auth)?;
        let read = Approval::read(json, &request, &identity, &keys.bundle_secret(), &|scope| {
            self.protocols.has_keys(scope)
        })?;
        Ok(read.cert)
    }

    fn put_record(&self, keys: &AppKeys, cert: &AppCert) -> Result<(), SignerFfiError> {
        // Each certificate has a later issue time, even with the test clock held still.
        let record = AppRecord::sign(keys, AppRecordBody::new(cert, Vec::new(), cert.issued_at()))
            .map_err(SignerError::from)?;
        self.service
            .app_op(
                keys,
                OpKind::AppPut {
                    record: record.signed().clone(),
                },
            )
            .map_err(|error| match error {
                ScriptError::Core(error) => SignerError::from(error).into(),
                _ => SignerFfiError::Unknown {
                    reason: "fixture app record".into(),
                },
            })?;
        Ok(())
    }
}
