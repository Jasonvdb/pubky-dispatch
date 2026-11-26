//! Renewing an app's certificate (Dispatch spec 3.2, Dispatch wire 3.8).
//!
//! See the [signer host guide](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md),
//! sections 2.6 and 3.4.

use crate::{IdentityDocView, Signer, SignerFfiError, signer::app_id as app_id_bytes};
use pubky_dispatch_signer::CertChange;
use std::fmt;

/// What a renewal changes (Dispatch spec 3.2).
#[derive(Default, uniffi::Record)]
pub struct CertChangeView {
    /// The new scopes, or `None` to keep the certificate's scopes (Dispatch spec 3.2).
    pub scopes: Option<Vec<String>>,
    /// The new expiry in Unix milliseconds, or `None` for the configured certificate
    /// lifetime from the new issue time (Dispatch spec 3.1).
    pub expires_at: Option<u64>,
}

impl fmt::Debug for CertChangeView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CertChangeView(..)")
    }
}

impl From<CertChangeView> for CertChange {
    fn from(change: CertChangeView) -> Self {
        Self {
            scopes: change.scopes,
            expires_at: change.expires_at,
        }
    }
}

#[uniffi::export]
impl Signer {
    /// Renew the certificate of the listed app with the change, then deliver and publish
    /// the renewing version, which is returned (Dispatch spec 3.2, Dispatch wire 3.8). A
    /// renewal that removes a scope is closed at once, by one more version, so the newest
    /// version is then the one after the version returned. An App ID that isn't 16 bytes is
    /// refused as invalid input.
    /// A signer call, which waits its turn behind the call the signer is running: never
    /// awaited from inside a host callback of this signer
    /// ([signer host guide, 2.4](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store)).
    pub async fn renew(
        &self,
        app_id: Vec<u8>,
        change: CertChangeView,
    ) -> Result<IdentityDocView, SignerFfiError> {
        let app_id = app_id_bytes(&app_id)?;
        self.call(move |signer| {
            Box::pin(async move { Ok(signer.renew(app_id, change.into()).await?.into()) })
        })
        .await
    }

    /// Close every open renewal whose app the Dispatch now holds a record of carrying the
    /// new certificate (Dispatch spec 3.2 step 4, Dispatch wire 3.8 step 4). Returns the apps
    /// whose renewal was closed.
    /// A signer call, which waits its turn behind the call the signer is running: never
    /// awaited from inside a host callback of this signer
    /// ([signer host guide, 2.4](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store)).
    pub async fn complete_renewals(&self) -> Result<Vec<Vec<u8>>, SignerFfiError> {
        self.call(|signer| {
            Box::pin(async move {
                let ids = signer.complete_renewals().await?;
                Ok(ids.into_iter().map(Vec::from).collect())
            })
        })
        .await
    }

    /// Renew the certificates of current apps that have less than half their lifetime
    /// left, each with the lifetime its certificate has, from now (Dispatch spec 3.1). At
    /// most four are renewed in one call, the soonest to expire first; an app it leaves
    /// out for another reason is named by an alert. Returns the apps renewed: four of them
    /// means more may be due, which the next call, or the next periodic run, renews
    /// ([signer host guide, 2.14](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#214-periodic-work)).
    /// A signer call, which waits its turn behind the call the signer is running: never
    /// awaited from inside a host callback of this signer
    /// ([signer host guide, 2.4](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store)).
    pub async fn renew_expiring(&self) -> Result<Vec<Vec<u8>>, SignerFfiError> {
        self.call(|signer| {
            Box::pin(async move {
                let ids = signer.renew_expiring().await?;
                Ok(ids.into_iter().map(Vec::from).collect())
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_renewal_change_fields() {
        for scopes in [
            None,
            Some(vec![]),
            Some(vec!["second".into(), "first".into()]),
        ] {
            for expires_at in [None, Some(0), Some(u64::MAX)] {
                let native = CertChange::from(CertChangeView {
                    scopes: scopes.clone(),
                    expires_at,
                });
                assert_eq!(native.scopes, scopes);
                assert_eq!(native.expires_at, expires_at);
            }
        }
    }

    #[test]
    fn test_renewal_debug() {
        let change = CertChangeView {
            scopes: Some(vec!["private:scope-name".into()]),
            expires_at: Some(1234),
        };
        assert_eq!(format!("{change:?}"), "CertChangeView(..)");
    }

    #[cfg(feature = "test-fixtures")]
    mod scripted {
        use super::*;
        use crate::{
            AppSummaryView, HomeserverFailure, HostHomeserver, HostVault, RefusalKind,
            VaultAddOutcome, VaultFailure, app_fixtures::FixtureApps, protocol,
            test_host::MemoryHost,
        };
        use pubky_dispatch_client::testing::{DISPATCH_ORIGIN, START_MS};
        use pubky_dispatch_core::{
            keys::IdentityKey,
            records::{DEFAULT_CERT_LIFETIME_MS, IDENTITY_PATH, IdentityDoc},
        };
        use std::{
            collections::BTreeMap,
            sync::{Arc, Mutex},
        };

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

        #[derive(Clone, Default)]
        struct Home {
            files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        }

        #[async_trait::async_trait]
        impl HostHomeserver for Home {
            async fn get(
                &self,
                path: String,
                limit: u64,
            ) -> Result<Option<Vec<u8>>, HomeserverFailure> {
                let files = self.files.lock().unwrap();
                let bytes = files.get(&path);
                if bytes.is_some_and(|bytes| bytes.len() as u64 > limit) {
                    return Err(HomeserverFailure::TooLarge { limit });
                }
                Ok(bytes.cloned())
            }
            async fn put(&self, path: String, bytes: Vec<u8>) -> Result<(), HomeserverFailure> {
                self.files.lock().unwrap().insert(path, bytes);
                Ok(())
            }
            async fn delete(&self, path: String) -> Result<(), HomeserverFailure> {
                self.files.lock().unwrap().remove(&path);
                Ok(())
            }
        }

        async fn joined(apps: u32) -> (Arc<FixtureApps>, Arc<Signer>, Home) {
            protocol::sample().unwrap();
            let home = Home::default();
            let fixture = FixtureApps::new(SEED.to_vec(), Box::new(home.clone())).unwrap();
            let signer = fixture
                .signer_with_apps(
                    Box::new(Vault),
                    MemoryHost::default().boxed(),
                    DISPATCH_ORIGIN.into(),
                    apps,
                )
                .await
                .unwrap();
            (fixture, signer, home)
        }

        /// The longest a scripted test may take: each runs against in-memory hosts and a
        /// scripted service, so one that takes longer is stuck.
        const TEST_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

        async fn bounded(test: impl std::future::Future<Output = ()>) {
            tokio::time::timeout(TEST_BOUND, test)
                .await
                .expect("the test ended within its bound");
        }

        async fn app(signer: &Signer, id: &[u8]) -> AppSummaryView {
            signer
                .apps()
                .await
                .unwrap()
                .into_iter()
                .find(|a| a.app_id == id)
                .unwrap()
        }

        #[tokio::test]
        async fn test_renewal_unknown_app() {
            bounded(async {
                let (_fixture, signer, _) = joined(1).await;
                assert!(matches!(
                    signer.renew(vec![0; 16], CertChangeView::default()).await,
                    Err(SignerFfiError::Refused {
                        kind: RefusalKind::NotListed,
                        ..
                    })
                ));
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        #[tokio::test]
        async fn test_renewal_invalid_app_id() {
            bounded(async {
                let (_fixture, signer, _) = joined(1).await;
                for len in [15, 17] {
                    assert!(matches!(
                        signer.renew(vec![0; len], CertChangeView::default()).await,
                        Err(SignerFfiError::InvalidInput { .. })
                    ));
                }
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        #[tokio::test]
        async fn test_renewal_expiry_and_take_up() {
            bounded(async {
                let (fixture, signer, home) = joined(1).await;
                assert_eq!(format!("{fixture:?}"), "FixtureApps(..)");
                let [id]: [_; 1] = fixture.app_ids().try_into().unwrap();
                let before = signer.identity_doc().await.unwrap().unwrap();
                let old = app(&signer, &id).await.cert.unwrap();
                let later = old.expires_at + 86_400_000;
                let renewed = signer
                    .renew(
                        id.clone(),
                        CertChangeView {
                            scopes: None,
                            expires_at: Some(later),
                        },
                    )
                    .await
                    .unwrap();

                assert_eq!(renewed.version, before.version + 1);
                assert_eq!(signer.identity_doc().await.unwrap().unwrap(), renewed);
                let bytes = home
                    .get(IDENTITY_PATH.into(), u64::MAX)
                    .await
                    .unwrap()
                    .unwrap();
                let published = IdentityDoc::verify(
                    &serde_json::from_slice(&bytes).unwrap(),
                    &IdentityKey::from_secret(SEED).public(),
                )
                .unwrap();
                assert_eq!(published.hash().as_slice(), renewed.hash);
                let [earlier] = published.body().renewed.as_slice() else {
                    panic!("expected one renewal")
                };
                assert_eq!(earlier.app_id.as_slice(), id);
                assert_eq!(earlier.cert.as_slice(), old.hash);
                assert_eq!(earlier.until, None);

                let open = app(&signer, &id).await;
                assert!(open.renewal_open);
                let new = open.cert.unwrap();
                assert_eq!(open.listed_cert.as_ref(), Some(&new.hash));
                assert_eq!(
                    published.listed_cert(&earlier.app_id).map(Vec::from),
                    open.listed_cert
                );
                assert_ne!(new.hash, old.hash);
                assert_eq!(new.expires_at, later);
                assert_eq!(new.scopes, old.scopes);
                let held = signer.certificates().await.unwrap();
                assert!(held.contains(&old) && held.contains(&new));
                assert!(signer.complete_renewals().await.unwrap().is_empty());
                assert!(app(&signer, &id).await.renewal_open);

                fixture.take_up_renewal(id.clone()).unwrap();
                let closed = signer.complete_renewals().await.unwrap();
                assert_eq!(closed.as_slice(), std::slice::from_ref(&id));
                assert!(!app(&signer, &id).await.renewal_open);
                assert!(signer.complete_renewals().await.unwrap().is_empty());
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        #[tokio::test]
        async fn test_renewal_scope_reduction() {
            bounded(async {
                let (fixture, signer, _) = joined(1).await;
                let [id]: [_; 1] = fixture.app_ids().try_into().unwrap();
                assert_eq!(
                    app(&signer, &id).await.cert.unwrap().scopes,
                    ["sample-a", "sample-b"]
                );
                let before = signer.identity_doc().await.unwrap().unwrap();
                let renewed = signer
                    .renew(
                        id.clone(),
                        CertChangeView {
                            scopes: Some(vec!["sample-a".into()]),
                            expires_at: None,
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(renewed.version, before.version + 1);
                assert_eq!(
                    signer.identity_doc().await.unwrap().unwrap().version,
                    renewed.version + 1
                );
                let reduced = app(&signer, &id).await;
                assert!(!reduced.renewal_open);
                let cert = reduced.cert.unwrap();
                assert_eq!(cert.scopes, ["sample-a"]);
                assert_eq!(cert.expires_at - cert.issued_at, DEFAULT_CERT_LIFETIME_MS);
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        #[tokio::test]
        async fn test_renewal_unowned_scopes() {
            bounded(async {
                let (fixture, signer, _) = joined(1).await;
                let [id]: [_; 1] = fixture.app_ids().try_into().unwrap();
                let before = signer.identity_doc().await.unwrap();
                let scope = "unowned:private-label";
                let error = signer
                    .renew(
                        id,
                        CertChangeView {
                            scopes: Some(vec![scope.into()]),
                            expires_at: None,
                        },
                    )
                    .await
                    .unwrap_err();
                assert!(!format!("{error:?}").contains(scope));
                assert!(matches!(error, SignerFfiError::Refused {
                    kind: RefusalKind::UnknownScopes, scopes: Some(unowned), ..
                } if unowned.names == [scope]));
                assert_eq!(signer.identity_doc().await.unwrap(), before);
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        #[tokio::test]
        async fn test_renewal_past_half_lifetime() {
            bounded(async {
                let (fixture, signer, _) = joined(2).await;
                let mut ids = fixture.app_ids();
                assert_eq!(ids.len(), 2);
                assert_ne!(ids[0], ids[1]);
                fixture.advance_time_ms(DEFAULT_CERT_LIFETIME_MS / 2);
                assert!(signer.renew_expiring().await.unwrap().is_empty());
                fixture.advance_time_ms(1);
                let mut renewed = signer.renew_expiring().await.unwrap();
                renewed.sort();
                ids.sort();
                assert_eq!(renewed, ids);
                for id in ids {
                    let cert = app(&signer, &id).await.cert.unwrap();
                    assert_eq!(cert.issued_at, START_MS + DEFAULT_CERT_LIFETIME_MS / 2 + 1);
                    assert_eq!(cert.expires_at - cert.issued_at, DEFAULT_CERT_LIFETIME_MS);
                }
                assert!(signer.renew_expiring().await.unwrap().is_empty());
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        #[tokio::test]
        async fn test_renewal_expiring_renews_four_a_call() {
            bounded(async {
                // Five due: a call that renews four says so by naming four, and the next call
                // renews the last; only then is nothing due.
                let (fixture, signer, _) = joined(5).await;
                let mut ids = fixture.app_ids();
                fixture.advance_time_ms(DEFAULT_CERT_LIFETIME_MS / 2 + 1);
                let mut renewed = signer.renew_expiring().await.unwrap();
                assert_eq!(renewed.len(), 4);
                let rest = signer.renew_expiring().await.unwrap();
                assert_eq!(rest.len(), 1);
                renewed.extend(rest);
                renewed.sort();
                ids.sort();
                assert_eq!(renewed, ids);
                assert!(signer.renew_expiring().await.unwrap().is_empty());
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        #[tokio::test]
        async fn test_renewal_after_shutdown() {
            bounded(async {
                fn closed<T>(result: Result<T, SignerFfiError>) {
                    assert!(
                        matches!(result, Err(SignerFfiError::InvalidInput { reason }) if reason == "the signer is closed")
                    );
                }
                let (fixture, signer, _) = joined(1).await;
                let [id]: [_; 1] = fixture.app_ids().try_into().unwrap();
                signer.shutdown().await.unwrap();
                closed(signer.renew(id, CertChangeView::default()).await);
                // A malformed App ID is refused for itself, before the signer is reached.
                assert!(matches!(
                    signer.renew(vec![0; 15], CertChangeView::default()).await,
                    Err(SignerFfiError::InvalidInput { reason }) if reason == "an app ID must be 16 bytes"
                ));
                closed(signer.complete_renewals().await);
                closed(signer.renew_expiring().await);
            })
            .await;
        }
    }
}
