//! The identity's apps and the signer's newest version (Dispatch spec 3.2, 4.3).
//!
//! Each of these is a signer call, as `resume` is: it waits its turn behind the call the
//! signer is running. Unlike `status`, `identity` and `install_id`, which answer at once, none
//! of them may be awaited from inside a host callback of the same signer
//! ([signer host guide, 2.4](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store)).
//!
//! See the [signer host guide](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md),
//! sections 2.14, 3.3 and 3.12.

use crate::{AlertKind, CoreFailure, Signer, SignerFfiError};
use pubky_dispatch_core::{
    json::MAX_INT,
    records::{AppCert, ConnectRequests, IdentityDoc, SuiteKey},
    scopes::permission_names,
};
use pubky_dispatch_signer::{AppStanding, AppSummary, HighWater};
use std::fmt;

/// One app of the identity, for a management screen (Dispatch spec 3.2).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct AppSummaryView {
    /// The App ID (Dispatch wire 3.1).
    pub app_id: Vec<u8>,
    /// Where the app stands in the newest `identity.json`, as this install's records show it
    /// (Dispatch spec 12.2).
    pub standing: AppStandingView,
    /// The document hash of the certificate the newest version lists for the app (Dispatch wire 3.3).
    pub listed_cert: Option<Vec<u8>>,
    /// The listed certificate, if this install holds it: `None` for a removed app, and for a
    /// listed one in a version adopted from another install (Dispatch spec 3.2).
    pub cert: Option<AppCertView>,
    /// Whether a renewal of the app is open: an earlier certificate of it is in `renewed`
    /// with no `until` yet, and still counts. Once `until` is set, the earlier certificate
    /// counts only for messages accepted more than 5 minutes before it (Dispatch wire 3.3,
    /// 3.8).
    pub renewal_open: bool,
    /// The registered protocols that own some of its scopes, in registration order, if the
    /// certificate is known (Dispatch spec 3.2).
    pub protocols: Option<Vec<String>>,
    /// Its scopes that no registered protocol owns, if the certificate is known (Dispatch spec 3.2).
    pub unowned_scopes: Option<Vec<String>>,
    /// From when the app's messages are distrusted, in Unix milliseconds: a removed app's
    /// `distrust_from`, or the earlier time the user picked for a revocation in progress. Its
    /// messages count only if accepted at least 5 minutes before it (Dispatch spec 4.3, 12.2;
    /// Dispatch wire 3.3).
    pub distrust_from: Option<u64>,
    /// How many of its automatic renewals in a row no record took up (Dispatch spec 3.1).
    pub untaken_renewals: u64,
    /// The kinds of the uncleared alerts that name the app, oldest first (Dispatch spec 4.3).
    pub alerts: Vec<AlertKind>,
}

impl From<AppSummary> for AppSummaryView {
    fn from(app: AppSummary) -> Self {
        Self {
            app_id: app.app_id.to_vec(),
            standing: app.standing.into(),
            listed_cert: app.listed_cert.map(Vec::from),
            cert: app.cert.map(Into::into),
            renewal_open: app.renewal_open,
            protocols: app.protocols,
            unowned_scopes: app.unowned_scopes,
            distrust_from: app.distrust_from,
            untaken_renewals: u64::try_from(app.untaken_renewals).unwrap_or(u64::MAX),
            alerts: app.alerts.iter().map(AlertKind::from).collect(),
        }
    }
}

/// Where an app stands in the newest `identity.json`, as this install's records show it
/// (Dispatch spec 12.2).
#[derive(PartialEq, Eq, uniffi::Enum)]
pub enum AppStandingView {
    /// Listed as current. An app that left by itself stays listed until a version removes
    /// it; its alerts tell it apart (Dispatch spec 12.2, 12.3).
    Listed,
    /// The user asked to revoke it, and no delivered version removes it yet (Dispatch spec 12.2).
    Revoking {
        /// Whether the Dispatch answered the revocation, so it serves the app no more. During
        /// a recovery it is the lost service's answer until the recovery's version is
        /// delivered (Dispatch spec 12.2, 12.6).
        at_dispatch: bool,
    },
    /// Named in `removed` as revoked or gone by itself, for good. An app the signer purged
    /// is in no list any more, and its App ID is never approved or listed again (Dispatch
    /// spec 4.3, 12.2).
    Removed,
    /// The app's standing is unknown to these bindings (Dispatch spec 12.2).
    Unknown,
}

impl From<AppStanding> for AppStandingView {
    fn from(standing: AppStanding) -> Self {
        match standing {
            AppStanding::Listed => Self::Listed,
            AppStanding::Revoking { at_dispatch } => Self::Revoking { at_dispatch },
            AppStanding::Removed => Self::Removed,
            _ => Self::Unknown,
        }
    }
}

/// A verified app certificate (Dispatch wire 3.1).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct AppCertView {
    /// The certificate's document hash, as `identity.json` lists it (Dispatch wire 2.2).
    pub hash: Vec<u8>,
    /// The identity that signs the certificate (Dispatch wire 3.1).
    pub identity: Vec<u8>,
    /// The App ID derived from the signing key (Dispatch wire 3.1).
    pub app_id: Vec<u8>,
    /// The app's Ed25519 signing key (Dispatch wire 3.1).
    pub signing_key: Vec<u8>,
    /// The app's X25519 bundle key, which key bundles are sealed to (Dispatch wire 3.1).
    pub bundle_key: Vec<u8>,
    /// The protocol's scopes, opaque strings to the Dispatch (Dispatch wire 3.1).
    pub scopes: Vec<String>,
    /// The Dispatch permissions, by name, in the fixed order (Dispatch wire 3.1).
    pub permissions: Vec<String>,
    /// When the certificate was issued, in Unix milliseconds (Dispatch wire 3.1).
    pub issued_at: u64,
    /// When the certificate expires, in Unix milliseconds: expired at or past it (Dispatch
    /// wire 3.1).
    pub expires_at: u64,
    /// Bundle keys of later suites (Dispatch wire 3.1).
    pub suite_keys: Option<Vec<SuiteKeyView>>,
}

impl From<AppCert> for AppCertView {
    fn from(cert: AppCert) -> Self {
        Self {
            hash: cert.hash().to_vec(),
            identity: cert.identity().to_vec(),
            app_id: cert.app_id().to_vec(),
            signing_key: cert.signing_key().to_vec(),
            bundle_key: cert.bundle_key().to_vec(),
            scopes: cert.scopes().to_vec(),
            permissions: permission_names(cert.permissions()),
            issued_at: cert.issued_at(),
            expires_at: cert.expires_at(),
            suite_keys: cert
                .body()
                .suite_keys
                .as_ref()
                .map(|keys| keys.iter().map(Into::into).collect()),
        }
    }
}

/// A key of a later suite, as a certificate's `suite_keys` carries it (Dispatch wire 3.1).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct SuiteKeyView {
    /// The envelope's suite byte, from 2 to 255 (Dispatch wire 3.1).
    pub suite: u64,
    /// The key, from 1 to 4096 bytes (Dispatch wire 3.1).
    pub key: Vec<u8>,
}

impl From<&SuiteKey> for SuiteKeyView {
    fn from(key: &SuiteKey) -> Self {
        Self {
            suite: key.suite,
            key: key.key.clone(),
        }
    }
}

/// A verified `identity.json` (Dispatch wire 3.3).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct IdentityDocView {
    /// The generation (Dispatch wire 3.3).
    pub generation: u64,
    /// The version (Dispatch wire 3.3).
    pub version: u64,
    /// The document hash, as `prev` names it (Dispatch wire 2.2).
    pub hash: Vec<u8>,
    /// The hash of the body bytes, which equivocation compares (Dispatch wire 3.3).
    pub body_hash: Vec<u8>,
    /// The record age limit in seconds, with `None` standing for 90 days (Dispatch spec 4.3).
    pub record_max_age: Option<u64>,
    /// The connect request settings of the policy (Dispatch wire 3.3).
    pub connect_requests: ConnectRequestsView,
}

impl From<IdentityDoc> for IdentityDocView {
    fn from(doc: IdentityDoc) -> Self {
        Self {
            generation: doc.generation(),
            version: doc.version(),
            hash: doc.hash().to_vec(),
            body_hash: doc.body_hash().to_vec(),
            record_max_age: doc.body().record_max_age,
            connect_requests: doc.body().policy.connect_requests.into(),
        }
    }
}

/// The newest `identity.json` a service accepted from the signer, or that it adopted
/// (Dispatch spec 4.3).
#[derive(PartialEq, Eq, uniffi::Record)]
pub struct HighWaterView {
    /// The generation (Dispatch spec 4.3).
    pub generation: u64,
    /// The version (Dispatch spec 4.3).
    pub version: u64,
    /// The document hash (Dispatch spec 4.3).
    pub doc_hash: Vec<u8>,
    /// The hash of the body bytes, which equivocation compares (Dispatch spec 4.3).
    pub body_hash: Vec<u8>,
}

impl From<HighWater> for HighWaterView {
    fn from(mark: HighWater) -> Self {
        Self {
            generation: mark.generation,
            version: mark.version,
            doc_hash: mark.doc_hash.to_vec(),
            body_hash: mark.body_hash.to_vec(),
        }
    }
}

/// The connect request settings of the policy (Dispatch wire 3.3).
#[derive(Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ConnectRequestsView {
    /// Whether strangers may ask to be invited (Dispatch wire 3.3).
    pub enabled: bool,
    /// The most pending connect requests (Dispatch wire 3.3).
    pub max_pending: u64,
    /// Whether a connect request pushes (Dispatch wire 3.3).
    pub push: bool,
}

impl From<ConnectRequests> for ConnectRequestsView {
    fn from(settings: ConnectRequests) -> Self {
        Self {
            enabled: settings.enabled,
            max_pending: settings.max_pending,
            push: settings.push,
        }
    }
}

impl From<ConnectRequestsView> for ConnectRequests {
    fn from(settings: ConnectRequestsView) -> Self {
        Self {
            enabled: settings.enabled,
            max_pending: settings.max_pending,
            push: settings.push,
        }
    }
}

macro_rules! redacted_debug {
    ($($view:ident),+ $(,)?) => {
        $(
            impl fmt::Debug for $view {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(concat!(stringify!($view), "(..)"))
                }
            }
        )+
    };
}

redacted_debug!(
    AppSummaryView,
    AppStandingView,
    AppCertView,
    SuiteKeyView,
    IdentityDocView,
    HighWaterView,
    ConnectRequestsView,
);

#[uniffi::export]
impl Signer {
    /// The identity's apps in the newest document's order, listed apps first and then
    /// removed apps; an app the signer purged is in neither (Dispatch spec 4.3, 12.2). A
    /// signer call: never awaited from inside a host callback of this signer (module docs).
    pub async fn apps(&self) -> Result<Vec<AppSummaryView>, SignerFfiError> {
        self.call(|signer| {
            Box::pin(async move { Ok(signer.apps()?.into_iter().map(Into::into).collect()) })
        })
        .await
    }

    /// The certificates the signer issued and keeps, verified: those of the newest version's
    /// apps and `renewed` entries, and that of an app it approved whose version isn't
    /// delivered yet (Dispatch spec 3.2). A signer call: never awaited from inside a host
    /// callback of this signer (module docs).
    pub async fn certificates(&self) -> Result<Vec<AppCertView>, SignerFfiError> {
        self.call(|signer| {
            Box::pin(
                async move { Ok(signer.certificates()?.into_iter().map(Into::into).collect()) },
            )
        })
        .await
    }

    /// The newest `identity.json` a service accepted from this signer, or that it adopted
    /// (Dispatch spec 4.3). A signer call: never awaited from inside a host callback of this
    /// signer (module docs).
    pub async fn identity_doc(&self) -> Result<Option<IdentityDocView>, SignerFfiError> {
        self.call(|signer| Box::pin(async move { Ok(signer.identity_doc()?.map(Into::into)) }))
            .await
    }

    /// The high-water mark, absent before the first delivery (Dispatch spec 4.3). A signer
    /// call: never awaited from inside a host callback of this signer (module docs).
    pub async fn high_water(&self) -> Result<Option<HighWaterView>, SignerFfiError> {
        self.call(|signer| Box::pin(async move { Ok(signer.high_water()?.map(Into::into)) }))
            .await
    }

    /// Set the record age limit in seconds, from 1 to 2^53 - 1, or clear it for the 90-day
    /// default, in a new version (Dispatch spec 4.3, Dispatch wire 3.3). A limit out of that
    /// range is refused as [`SignerFfiError::InvalidData`] before anything is signed. While
    /// another step is pending, see
    /// [signer host guide, 2.14](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#214-periodic-work).
    /// A signer call: never awaited from inside a host callback of this signer (module docs).
    pub async fn set_record_max_age(
        &self,
        seconds: Option<u64>,
    ) -> Result<IdentityDocView, SignerFfiError> {
        if seconds.is_some_and(|seconds| !(1..=MAX_INT).contains(&seconds)) {
            return Err(out_of_range());
        }
        self.call(move |signer| {
            Box::pin(async move { Ok(signer.set_record_max_age(seconds).await?.into()) })
        })
        .await
    }

    /// Set the connect request settings of the policy in a new version, `max_pending` from 0
    /// to 2^53 - 1; the service applies its own cap (Dispatch wire 3.3, 9.2). A `max_pending`
    /// out of that range is refused as [`SignerFfiError::InvalidData`] before anything is
    /// signed. While another step is pending, see
    /// [signer host guide, 2.14](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#214-periodic-work).
    /// A signer call: never awaited from inside a host callback of this signer (module docs).
    pub async fn set_connect_requests(
        &self,
        settings: ConnectRequestsView,
    ) -> Result<IdentityDocView, SignerFfiError> {
        if settings.max_pending > MAX_INT {
            return Err(out_of_range());
        }
        self.call(move |signer| {
            Box::pin(async move { Ok(signer.set_connect_requests(settings.into()).await?.into()) })
        })
        .await
    }
}

/// A setting outside the range `identity.json` can carry (Dispatch wire 1.1, 3.3).
fn out_of_range() -> SignerFfiError {
    SignerFfiError::InvalidData {
        kind: CoreFailure::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_dispatch_core::{
        keys::{AppKeys, IdentityKey},
        records::{AppCertBody, IdentityBody, IdentityPolicy, Inbox},
        scopes::Permission,
    };

    const ORIGIN: &str = "https://dispatch.example";

    #[test]
    fn test_status_app_standing() {
        assert_eq!(
            AppStandingView::from(AppStanding::Listed),
            AppStandingView::Listed
        );
        for at_dispatch in [false, true] {
            assert_eq!(
                AppStandingView::from(AppStanding::Revoking { at_dispatch }),
                AppStandingView::Revoking { at_dispatch }
            );
        }
        assert_eq!(
            AppStandingView::from(AppStanding::Removed),
            AppStandingView::Removed
        );
    }

    #[test]
    fn test_status_certificate() {
        let identity = IdentityKey::from_secret([1; 32]);
        let keys = AppKeys::from_secrets([2; 32], [3; 32]);
        let mut body = AppCertBody::new(
            identity.public(),
            keys.signing_public(),
            keys.bundle_public(),
            vec!["sample-a:private-label".into(), "sample-b".into()],
            &Permission::ALL,
            1234,
            5678,
        );
        let cert = AppCert::issue(&identity, body.clone()).unwrap();
        assert!(AppCertView::from(cert).suite_keys.is_none());

        body.suite_keys = Some(vec![
            SuiteKey {
                suite: 2,
                key: vec![73, 91],
            },
            SuiteKey {
                suite: 255,
                key: vec![83],
            },
        ]);
        let cert = AppCert::issue(&identity, body).unwrap();
        let hash = cert.hash();
        let view = AppCertView::from(cert);
        assert_eq!(view.hash, hash);
        assert_eq!(view.identity, identity.public());
        assert_eq!(view.app_id, keys.app_id_bytes());
        assert_eq!(view.signing_key, keys.signing_public());
        assert_eq!(view.bundle_key, keys.bundle_public());
        assert_eq!(view.scopes, ["sample-a:private-label", "sample-b"]);
        assert_eq!(
            view.permissions,
            [
                "claims.read",
                "claims.write",
                "lists.read",
                "lists.manage",
                "reply.add"
            ]
        );
        assert_eq!(view.issued_at, 1234);
        assert_eq!(view.expires_at, 5678);
        let suites = view.suite_keys.as_ref().unwrap();
        assert_eq!(suites.len(), 2);
        assert_eq!(suites[0].suite, 2);
        assert_eq!(suites[0].key, [73, 91]);
        assert_eq!(suites[1].suite, 255);
        assert_eq!(suites[1].key, [83]);
        assert_eq!(format!("{view:?}"), "AppCertView(..)");
        assert_eq!(format!("{:?}", suites[0]), "SuiteKeyView(..)");
    }

    #[test]
    fn test_status_document_and_mark_fields() {
        let identity = IdentityKey::from_secret([1; 32]);
        let settings = ConnectRequests {
            enabled: false,
            max_pending: 9,
            push: true,
        };
        let mut body = IdentityBody::first(
            identity.public(),
            [4; 16],
            Inbox::new(ORIGIN, [5; 32]),
            IdentityPolicy {
                connect_requests: settings,
                ..Default::default()
            },
        );
        body.generation = 3;
        body.version = 8;
        body.record_max_age = Some(123);
        let doc = IdentityDoc::sign(&identity, body).unwrap();
        let hash = doc.hash();
        let body_hash = doc.body_hash();
        let view = IdentityDocView::from(doc);
        assert_eq!(view.generation, 3);
        assert_eq!(view.version, 8);
        assert_eq!(view.hash, hash);
        assert_eq!(view.body_hash, body_hash);
        assert_eq!(view.record_max_age, Some(123));
        assert!(!view.connect_requests.enabled);
        assert_eq!(view.connect_requests.max_pending, 9);
        assert!(view.connect_requests.push);

        let mark = HighWaterView::from(HighWater {
            generation: 3,
            version: 8,
            doc_hash: hash,
            body_hash,
        });
        assert_eq!(mark.generation, 3);
        assert_eq!(mark.version, 8);
        assert_eq!(mark.doc_hash, hash);
        assert_eq!(mark.body_hash, body_hash);
        assert_eq!(format!("{view:?}"), "IdentityDocView(..)");
        assert_eq!(format!("{mark:?}"), "HighWaterView(..)");
    }

    #[test]
    fn test_status_connect_request_fields() {
        for (enabled, max_pending, push) in [(true, 0, false), (false, u64::MAX, true)] {
            let native = ConnectRequests {
                enabled,
                max_pending,
                push,
            };
            let view = ConnectRequestsView::from(native);
            assert_eq!(view.enabled, enabled);
            assert_eq!(view.max_pending, max_pending);
            assert_eq!(view.push, push);
            assert_eq!(ConnectRequests::from(view), native);
            assert_eq!(format!("{view:?}"), "ConnectRequestsView(..)");
        }
    }

    #[cfg(feature = "test-fixtures")]
    mod scripted {
        use super::*;
        use crate::{
            FixtureService, HomeserverFailure, HostHomeserver, HostVault, VaultAddOutcome,
            VaultFailure, protocol, test_host::MemoryHost,
        };
        use pubky_dispatch_signer::Alert;
        use std::{
            collections::BTreeMap,
            sync::{Arc, Mutex},
        };

        // The first identity in the key vectors, also used by the host programs.
        const SEED: [u8; 32] = [
            0xf6, 0x98, 0x6c, 0xa5, 0x7b, 0xe7, 0x38, 0xd6, 0x81, 0x45, 0xe3, 0xc0, 0x6e, 0xf2,
            0xd1, 0xdc, 0x30, 0x25, 0x95, 0x2f, 0xc2, 0xbe, 0x9d, 0x62, 0x46, 0xc6, 0x49, 0x74,
            0x10, 0x51, 0x91, 0x42,
        ];

        struct Vault;

        impl HostVault for Vault {
            fn load(&self) -> Result<Option<Vec<u8>>, VaultFailure> {
                Ok(Some(SEED.to_vec()))
            }
            fn add(&self, _: Vec<u8>) -> Result<VaultAddOutcome, VaultFailure> {
                Err(VaultFailure::Locked)
            }
            fn delete(&self, _: Vec<u8>) -> Result<(), VaultFailure> {
                Err(VaultFailure::Locked)
            }
        }

        #[derive(Default)]
        struct Home(Mutex<BTreeMap<String, Vec<u8>>>);

        #[async_trait::async_trait]
        impl HostHomeserver for Home {
            async fn get(
                &self,
                path: String,
                limit: u64,
            ) -> Result<Option<Vec<u8>>, HomeserverFailure> {
                let files = self.0.lock().unwrap();
                let bytes = files.get(&path);
                if bytes.is_some_and(|bytes| bytes.len() as u64 > limit) {
                    return Err(HomeserverFailure::TooLarge { limit });
                }
                Ok(bytes.cloned())
            }
            async fn put(&self, path: String, bytes: Vec<u8>) -> Result<(), HomeserverFailure> {
                self.0.lock().unwrap().insert(path, bytes);
                Ok(())
            }
            async fn delete(&self, path: String) -> Result<(), HomeserverFailure> {
                self.0.lock().unwrap().remove(&path);
                Ok(())
            }
        }

        async fn create() -> Arc<Signer> {
            protocol::sample().unwrap();
            let service = FixtureService::new(SEED.to_vec(), Box::<Home>::default()).unwrap();
            service
                .create_signer(
                    Box::new(Vault),
                    MemoryHost::default().boxed(),
                    ORIGIN.into(),
                )
                .await
                .unwrap()
        }

        async fn enrolled() -> Arc<Signer> {
            let signer = create().await;
            signer.resume().await.unwrap();
            signer
        }

        /// The longest a scripted test may take: each runs against in-memory hosts and a
        /// scripted service, so one that takes longer is stuck.
        const TEST_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

        async fn bounded(test: impl std::future::Future<Output = ()>) {
            tokio::time::timeout(TEST_BOUND, test)
                .await
                .expect("the test ended within its bound");
        }

        #[tokio::test]
        async fn test_status_enrollment() {
            bounded(async {
                let signer = create().await;
                assert!(signer.identity_doc().await.unwrap().is_none());
                assert!(signer.high_water().await.unwrap().is_none());
                assert!(signer.apps().await.unwrap().is_empty());
                signer.resume().await.unwrap();
                let doc = signer.identity_doc().await.unwrap().unwrap();
                let mark = signer.high_water().await.unwrap().unwrap();
                assert_eq!((doc.generation, doc.version), (1, 1));
                assert_eq!((mark.generation, mark.version), (1, 1));
                assert_eq!(mark.doc_hash, doc.hash);
                assert_eq!(mark.body_hash, doc.body_hash);
                assert!(doc.record_max_age.is_none());
                assert_eq!(doc.connect_requests, ConnectRequests::default().into());
                assert!(signer.apps().await.unwrap().is_empty());
                assert!(signer.certificates().await.unwrap().is_empty());
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        #[tokio::test]
        async fn test_status_record_max_age() {
            bounded(async {
                let signer = enrolled().await;
                let limited = signer.set_record_max_age(Some(86_400)).await.unwrap();
                assert_eq!(limited.version, 2);
                assert_eq!(limited.record_max_age, Some(86_400));
                assert_eq!(
                    signer.identity_doc().await.unwrap().as_ref(),
                    Some(&limited)
                );

                // Out of range, nothing is signed: the version and the high-water mark stay.
                let mark = signer.high_water().await.unwrap();
                for refused in [0, MAX_INT + 1, u64::MAX] {
                    assert!(matches!(
                        signer.set_record_max_age(Some(refused)).await,
                        Err(SignerFfiError::InvalidData {
                            kind: CoreFailure::Invalid
                        })
                    ));
                    assert_eq!(
                        signer.identity_doc().await.unwrap().as_ref(),
                        Some(&limited)
                    );
                    assert_eq!(signer.high_water().await.unwrap(), mark);
                }

                // Both ends of the range are taken.
                for (version, seconds) in [(3, 1), (4, MAX_INT)] {
                    let set = signer.set_record_max_age(Some(seconds)).await.unwrap();
                    assert_eq!((set.version, set.record_max_age), (version, Some(seconds)));
                }

                let cleared = signer.set_record_max_age(None).await.unwrap();
                assert_eq!(cleared.version, 5);
                assert_eq!(cleared.record_max_age, None);
                assert_eq!(signer.identity_doc().await.unwrap(), Some(cleared));
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        #[tokio::test]
        async fn test_status_connect_requests() {
            bounded(async {
                let signer = enrolled().await;
                for (version, enabled, max_pending, push) in
                    [(2, true, 19, false), (3, false, 7, true)]
                {
                    let settings = ConnectRequestsView {
                        enabled,
                        max_pending,
                        push,
                    };
                    let changed = signer.set_connect_requests(settings).await.unwrap();
                    assert_eq!(changed.version, version);
                    assert_eq!(changed.connect_requests, settings);
                    assert_eq!(signer.identity_doc().await.unwrap(), Some(changed));
                }

                // Out of range, nothing is signed: the version and the high-water mark stay.
                let doc = signer.identity_doc().await.unwrap();
                let mark = signer.high_water().await.unwrap();
                for max_pending in [MAX_INT + 1, u64::MAX] {
                    let settings = ConnectRequestsView {
                        enabled: true,
                        max_pending,
                        push: false,
                    };
                    assert!(matches!(
                        signer.set_connect_requests(settings).await,
                        Err(SignerFfiError::InvalidData {
                            kind: CoreFailure::Invalid
                        })
                    ));
                    assert_eq!(signer.identity_doc().await.unwrap(), doc);
                    assert_eq!(signer.high_water().await.unwrap(), mark);
                }

                // Both ends of the range are taken.
                for (version, max_pending) in [(4, 0), (5, MAX_INT)] {
                    let settings = ConnectRequestsView {
                        enabled: true,
                        max_pending,
                        push: false,
                    };
                    let changed = signer.set_connect_requests(settings).await.unwrap();
                    assert_eq!(changed.version, version);
                    assert_eq!(changed.connect_requests.max_pending, max_pending);
                }
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        fn assert_closed<T>(result: Result<T, SignerFfiError>) {
            assert!(
                matches!(result, Err(SignerFfiError::InvalidInput { reason }) if reason == "the signer is closed")
            );
        }

        #[tokio::test]
        async fn test_status_closed() {
            bounded(async {
                let signer = create().await;
                signer.shutdown().await.unwrap();
                assert_closed(signer.apps().await);
                assert_closed(signer.certificates().await);
                assert_closed(signer.identity_doc().await);
                assert_closed(signer.high_water().await);
                assert_closed(signer.set_record_max_age(Some(60)).await);
                assert_closed(
                    signer
                        .set_connect_requests(ConnectRequests::default().into())
                        .await,
                );
            })
            .await;
        }

        // AppSummary is non-exhaustive. Start with an app the native signer lists.
        async fn listed_app(handle: Arc<Signer>) -> AppSummary {
            handle.fixture_approve_sample_app().await.unwrap();
            handle
                .call(|signer| Box::pin(async move { Ok(signer.apps()?.pop()) }))
                .await
                .unwrap()
                .expect("the approved app is listed")
        }

        #[tokio::test]
        async fn test_status_app_summary() {
            bounded(async {
                let signer = enrolled().await;
                let mut app = listed_app(signer.clone()).await;
                let app_id = app.app_id;
                let cert = app.cert.clone().unwrap();
                let hash = cert.hash().to_vec();
                assert_eq!(
                    signer.certificates().await.unwrap(),
                    [AppCertView::from(cert.clone())]
                );
                assert_eq!(
                    signer.apps().await.unwrap(),
                    [AppSummaryView::from(app.clone())]
                );

                app.standing = AppStanding::Revoking { at_dispatch: true };
                app.renewal_open = true;
                app.distrust_from = Some(91);
                app.untaken_renewals = 2;
                app.alerts = vec![
                    Alert::RevocationUnconfirmed { app_id },
                    Alert::GrantRevocationOwed { app_id },
                ];
                let view = AppSummaryView::from(app.clone());
                assert_eq!(view.app_id, app_id);
                assert_eq!(
                    view.standing,
                    AppStandingView::Revoking { at_dispatch: true }
                );
                assert_eq!(view.listed_cert.as_ref(), Some(&hash));
                assert_eq!(view.cert, Some(AppCertView::from(cert)));
                assert!(view.renewal_open);
                assert_eq!(view.protocols, Some(vec!["sample".into()]));
                assert_eq!(view.unowned_scopes, Some(vec![]));
                assert_eq!(view.distrust_from, Some(91));
                assert_eq!(view.untaken_renewals, 2);
                assert_eq!(
                    view.alerts,
                    [
                        AlertKind::RevocationUnconfirmed,
                        AlertKind::GrantRevocationOwed
                    ]
                );
                assert_eq!(format!("{view:?}"), "AppSummaryView(..)");
                assert_eq!(format!("{:?}", view.standing), "AppStandingView(..)");

                app.protocols = Some(vec![]);
                app.unowned_scopes = Some(vec!["sample-a:private-label".into()]);
                let unowned = AppSummaryView::from(app.clone());
                assert_eq!(unowned.protocols, Some(vec![]));
                assert_eq!(
                    unowned.unowned_scopes,
                    Some(vec!["sample-a:private-label".into()])
                );

                app.standing = AppStanding::Listed;
                app.cert = None;
                app.protocols = None;
                app.unowned_scopes = None;
                let missing = AppSummaryView::from(app.clone());
                assert_eq!(missing.standing, AppStandingView::Listed);
                assert_eq!(missing.listed_cert, Some(hash));
                assert!(missing.cert.is_none());
                assert!(missing.protocols.is_none());
                assert!(missing.unowned_scopes.is_none());

                app.standing = AppStanding::Removed;
                app.listed_cert = None;
                let removed = AppSummaryView::from(app);
                assert_eq!(removed.standing, AppStandingView::Removed);
                assert!(removed.listed_cert.is_none());
                signer.shutdown().await.unwrap();
            })
            .await;
        }
    }
}
