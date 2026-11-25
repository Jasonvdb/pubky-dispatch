//! `identity.json` copies (Dispatch spec 4.3; Dispatch wire 3.3): the app's own and its
//! senders'.
//!
//! For every identity the app keeps the newest copy it took, from any source (the
//! approval, its Dispatch's feed and directory, the Homeserver), the version and generation
//! floor, and the hash of every body it saw by version:
//!
//! - a copy below the floor is ignored: readers use the higher version;
//! - another body at a version seen is equivocation. For the own identity it is an alarm
//!   that stops the app; for a sender it is an alert, and the app takes nothing more from
//!   that identity;
//! - an own copy that lists again an App ID an earlier version removed is an alarm too.
//!
//! [`App::refresh_identity`] reads the own copy from the Homeserver and says whether the read
//! confirmed the copy held, which an attempt needs within the last 60 seconds (Dispatch spec
//! 12.6).
//!
//! The Homeserver is read through [`HomeserverReader`], one method, so tests can fake it.
//! The Pubky implementation (a `PublicStorage` read of
//! `/pub/pubky-dispatch/v1/identity.json`) belongs to the host's Pubky integration and isn't
//! part of this crate yet.

use pubky_dispatch_core::records::{IDENTITY_PATH, IdentityDoc, VersionOrder};
use pubky_dispatch_core::sig::SignedDoc;

use super::App;
use super::error::{Alarm, AppError};
use super::state::{CachedDoc, Floor, Reader, SourceReads, Tx, key};
use crate::error::TransportError;
use crate::transport::BoxFuture;

/// How long a sender's `identity.json` copy is used without reading it again: 10 minutes
/// (Dispatch spec 4.3, "Caching for verification and use").
pub const DOC_CACHE_MS: u64 = 10 * 60_000;

/// How recent the last confirmed read of the own `identity.json` must be for an app to make
/// an attempt: 60 seconds (Dispatch spec 12.6 "Residual risk", 4.3).
pub const REVALIDATION_MS: u64 = 60_000;

/// What reading the own `identity.json` from the Homeserver found ([`App::refresh_identity`]).
///
/// Only [`IdentityRefresh::Newer`] and [`IdentityRefresh::Current`] confirm the copy the app
/// holds. Times are the app's clock, in Unix milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityRefresh {
    /// The Homeserver serves a newer version, which the app took: it is confirmed.
    Newer {
        /// The version taken.
        version: u64,
        /// When the request began, on the device clock.
        confirmed_at: u64,
    },
    /// The Homeserver serves the version the app holds: it is confirmed.
    Current {
        /// When the request began, on the device clock.
        confirmed_at: u64,
    },
    /// The exact signed copy was taken, but the device clock moved backwards during
    /// the read. A new read is needed to confirm its time.
    ClockMovedBack {
        /// Whether the app took a newer version.
        newer: bool,
    },
    /// The Homeserver serves a version the app doesn't take, older than the one it took from
    /// its Dispatch: the Homeserver lags, and confirms nothing.
    Older {
        /// The version it serves.
        served: u64,
    },
    /// The Homeserver serves no `identity.json`: nothing is confirmed.
    Missing,
    /// The Homeserver couldn't be read: nothing is confirmed.
    Unavailable,
}

impl IdentityRefresh {
    /// When this read confirmed the copy it found. Before acting, check the current
    /// [`App::identity_confirmation_age_ms`], which also observes later clock changes.
    pub fn confirmed_at(&self) -> Option<u64> {
        match self {
            IdentityRefresh::Newer { confirmed_at, .. }
            | IdentityRefresh::Current { confirmed_at } => Some(*confirmed_at),
            _ => None,
        }
    }
}

/// The last read that confirmed the own copy: the version confirmed, and when.
pub(crate) struct Confirmed {
    pub(crate) version: u64,
    pub(crate) start: crate::clock::ClockSample,
}

impl App {
    /// Read the own `identity.json` from the Homeserver and take it if newer (Dispatch spec
    /// 4.3): the app calls this when the Homeserver's event stream names the document, after
    /// waking, and before an attempt that needs a fresh copy.
    ///
    /// An app makes no attempt without an `identity.json` revalidated in the last
    /// [`REVALIDATION_MS`] (Dispatch spec 12.6 "Residual risk"). Immediately before an attempt,
    /// [`App::identity_confirmation_age_ms`] must give an age below that limit. A backwards
    /// sample during or after the read invalidates it. A missing, older or unavailable
    /// copy and a failed read leave the current version without a new confirmation.
    ///
    /// # Errors
    ///
    /// The alarm a copy raises (equivocation, a removed app listed again); a copy that
    /// doesn't verify; a failed commit.
    pub async fn refresh_identity(&mut self) -> Result<IdentityRefresh, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let identity = self.state.meta.identity;
            let start = self.clock.sample();
            let read = read_homeserver(self.env.homeserver.as_ref(), &identity).await;
            self.now();
            let doc = match read {
                Ok(Some(doc)) => doc,
                Ok(None) => return Ok(IdentityRefresh::Missing),
                Err(AppError::Transport(_)) => return Ok(IdentityRefresh::Unavailable),
                Err(error) => return Err(error),
            };
            // The read's own time: taking the copy may commit and fetch keys first, and the
            // confirmation is only as fresh as the read (Dispatch spec 12.6).
            let served = doc.version();
            let newer = self.take_own_copy(doc).await?;
            let held = self.state.own_doc.version();
            if served != held {
                return Ok(IdentityRefresh::Older { served });
            }
            if self.clock.elapsed(&start).is_none() {
                return Ok(IdentityRefresh::ClockMovedBack { newer });
            }
            let confirmed_at = start.at_ms;
            self.identity_confirmed = Some(Confirmed {
                version: held,
                start,
            });
            Ok(if newer {
                IdentityRefresh::Newer {
                    version: held,
                    confirmed_at,
                }
            } else {
                IdentityRefresh::Current { confirmed_at }
            })
        })
        .await
    }

    /// When a Homeserver read last confirmed the own `identity.json` the app holds now, on
    /// the app's clock, in Unix milliseconds ([`App::refresh_identity`]). `None` when none
    /// has since the app was loaded, or the app took a newer copy from another source since,
    /// or the device clock has moved backwards since the read began.
    pub fn identity_confirmed_at(&self) -> Option<u64> {
        self.confirmed_read().map(|(read, _)| read.start.at_ms)
    }

    /// Age of the last exact own Homeserver observation on the current run of the
    /// device clock. A backwards sample invalidates the observation, even after
    /// the device clock catches up. Compare this age with [`REVALIDATION_MS`].
    pub fn identity_confirmation_age_ms(&self) -> Option<u64> {
        self.confirmed_read().map(|(_, age)| age)
    }

    fn confirmed_read(&self) -> Option<(&Confirmed, u64)> {
        let read = self.identity_confirmed.as_ref()?;
        if read.version != self.state.own_doc.version() {
            return None;
        }
        Some((read, self.clock.elapsed(&read.start)?))
    }
}

/// Reads a public file of an identity's Homeserver.
///
/// Object-safe; the app holds an `Arc<dyn HomeserverReader>`. The host implements it on its
/// Pubky client; tests fake it.
pub trait HomeserverReader: Send + Sync {
    /// The bytes at `path` on `identity`'s Homeserver, `None` when there is no such file.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when the Homeserver can't be read now.
    fn get(
        &self,
        identity: [u8; 32],
        path: String,
    ) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>>;
}

/// What taking a copy did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Taken {
    /// A newer copy, now the one held.
    Newer,
    /// The copy held already, or the same body.
    Same,
    /// Below the floor: ignored.
    Older,
}

/// Another body at a version seen (Dispatch wire 3.3 "Equivocation").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Equivocation {
    pub(crate) version: u64,
}

/// Take a verified copy of `doc`'s identity against what the store holds for it, and add
/// the records it changes to `tx`. `held` is the newest copy held, if any; a newer copy is
/// kept with its source observations, if any.
///
/// # Errors
///
/// [`Equivocation`] for another body at a version seen; nothing is written then but the
/// mark.
pub(crate) async fn take_copy(
    reader: &Reader,
    tx: &mut Tx,
    doc: &IdentityDoc,
    held: Option<&IdentityDoc>,
    reads: SourceReads,
) -> Result<Result<Taken, Equivocation>, AppError> {
    let identity = doc.identity();
    let version = doc.version();
    if let Some(seen) = reader
        .get::<String>(&key::ident_body(&identity, version))
        .await?
        && seen != pubky_dispatch_core::enc::b64(&doc.body_hash())
    {
        tx.put(&key::ident_equivocated(&identity), &version)?;
        return Ok(Err(Equivocation { version }));
    }
    if let Some(held) = held {
        match held.compare(doc) {
            VersionOrder::Equivocation => {
                tx.put(&key::ident_equivocated(&identity), &version)?;
                return Ok(Err(Equivocation { version }));
            }
            VersionOrder::Same | VersionOrder::SameBody => return Ok(Ok(Taken::Same)),
            VersionOrder::Older => return Ok(Ok(Taken::Older)),
            VersionOrder::Newer => {}
        }
    }
    let floor = reader
        .get::<Floor>(&key::ident_floor(&identity))
        .await?
        .unwrap_or_default();
    if version < floor.version || doc.generation() < floor.generation {
        return Ok(Ok(Taken::Older));
    }
    tx.put(
        &key::ident_body(&identity, version),
        &pubky_dispatch_core::enc::b64(&doc.body_hash()),
    )?;
    tx.put(
        &key::ident_floor(&identity),
        &Floor {
            version: version.max(floor.version),
            generation: doc.generation().max(floor.generation),
        },
    )?;
    tx.put(
        &key::ident_doc(&identity),
        &CachedDoc {
            doc: doc.signed().clone(),
            reads,
        },
    )?;
    Ok(Ok(Taken::Newer))
}

/// Keep source times with the version that supplied them (Dispatch spec 4.3). Directory
/// answers carry empty observations. An older version only caps the held times if the
/// device clock moved back.
pub(crate) async fn take_peer_read(
    reader: &Reader,
    tx: &mut Tx,
    doc: IdentityDoc,
    held: Option<(IdentityDoc, SourceReads)>,
    observed: SourceReads,
    now: u64,
) -> Result<Result<(IdentityDoc, SourceReads), Equivocation>, AppError> {
    let held_doc = held.as_ref().map(|(held, _)| held);
    let taken = match take_copy(reader, tx, &doc, held_doc, observed).await? {
        Ok(taken) => taken,
        Err(equivocation) => return Ok(Err(equivocation)),
    };
    let (Some((held, previous)), Taken::Same | Taken::Older) = (held, &taken) else {
        return Ok(Ok((doc, observed)));
    };
    let update = |prior: Option<u64>, read: Option<u64>| {
        let latest = if taken == Taken::Same {
            prior.max(read)
        } else {
            prior
        };
        latest.map(|at| at.min(now))
    };
    let reads = SourceReads {
        homeserver_ms: update(previous.homeserver_ms, observed.homeserver_ms),
        dispatch_ms: update(previous.dispatch_ms, observed.dispatch_ms),
    };
    if previous != reads {
        tx.put(
            &key::ident_doc(&held.identity()),
            &CachedDoc {
                doc: held.signed().clone(),
                reads,
            },
        )?;
    }
    Ok(Ok((held, reads)))
}

/// The newest copy held for `identity`, verified, with when it was read.
pub(crate) async fn held_copy(
    reader: &Reader,
    identity: &[u8; 32],
) -> Result<Option<(IdentityDoc, SourceReads)>, AppError> {
    let Some(cached) = reader.get::<CachedDoc>(&key::ident_doc(identity)).await? else {
        return Ok(None);
    };
    let doc = IdentityDoc::verify(&cached.doc, identity)
        .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
    Ok(Some((doc, cached.reads)))
}

/// Read `identity`'s `identity.json` from its Homeserver: `Ok(None)` when it publishes
/// none, an error when it can't be read or doesn't verify.
pub(crate) async fn read_homeserver(
    homeserver: &dyn HomeserverReader,
    identity: &[u8; 32],
) -> Result<Option<IdentityDoc>, AppError> {
    let Some(bytes) = homeserver.get(*identity, IDENTITY_PATH.to_owned()).await? else {
        return Ok(None);
    };
    let signed: SignedDoc = pubky_dispatch_core::json::parse_json(&bytes)?;
    Ok(Some(IdentityDoc::verify(&signed, identity)?))
}

/// The checks of a newer own copy beyond the floor (Dispatch spec 4.3): it may follow the
/// copy held, and lists no App ID the held copy removed.
pub(crate) fn check_own_successor(held: &IdentityDoc, newer: &IdentityDoc) -> Result<(), Alarm> {
    held.check_successor(newer)
        .map_err(|error| Alarm::IdentityRollback {
            reason: error.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, StoreHandle};
    use pubky_dispatch_core::keys::IdentityKey;
    use pubky_dispatch_core::records::{
        IdentityBody, IdentityPolicy, Inbox, ListedApp, RemovedApp,
    };
    use std::sync::Arc;

    fn doc(version: u64, change: impl Fn(&mut IdentityBody)) -> IdentityDoc {
        let key = IdentityKey::from_secret([1; 32]);
        let mut body = IdentityBody::first(
            key.public(),
            [0; 16],
            Inbox::new("https://dispatch.example", [9; 32]),
            IdentityPolicy::default(),
        );
        body.version = version;
        change(&mut body);
        IdentityDoc::sign(&key, body).unwrap()
    }

    fn reader() -> (Reader, StoreHandle) {
        let store = StoreHandle::inline(Arc::new(MemoryStore::new()));
        (
            Reader {
                ns: "client/a".into(),
                store: store.clone(),
            },
            store,
        )
    }

    async fn take(
        reader: &Reader,
        store: &StoreHandle,
        d: &IdentityDoc,
    ) -> Result<Taken, Equivocation> {
        let held = held_copy(reader, &d.identity())
            .await
            .unwrap()
            .map(|(d, _)| d);
        let mut tx = Tx::new("client/a");
        let taken = take_copy(reader, &mut tx, d, held.as_ref(), SourceReads::default())
            .await
            .unwrap();
        tx.commit(store).await.unwrap();
        taken
    }

    #[tokio::test]
    async fn test_take_copy_keeps_the_newest_and_ignores_older() {
        let (reader, store) = reader();
        let v1 = doc(1, |_| {});
        let v2 = doc(2, |_| {});
        assert!(matches!(take(&reader, &store, &v1).await, Ok(Taken::Newer)));
        assert!(matches!(take(&reader, &store, &v2).await, Ok(Taken::Newer)));
        assert_eq!(take(&reader, &store, &v1).await, Ok(Taken::Older));
        assert_eq!(take(&reader, &store, &v2).await, Ok(Taken::Same));
        let held = held_copy(&reader, &v2.identity()).await.unwrap().unwrap();
        assert_eq!(held.0.version(), 2);
    }

    #[tokio::test]
    async fn test_take_copy_finds_equivocation_even_below_the_newest() {
        let (reader, store) = reader();
        let v1 = doc(1, |_| {});
        let v2 = doc(2, |_| {});
        take(&reader, &store, &v1).await.unwrap();
        take(&reader, &store, &v2).await.unwrap();
        // Another body at version 1, seen after version 2: still equivocation.
        let other = doc(1, |b| {
            b.removed.push(RemovedApp {
                app_id: [3; 16],
                distrust_from: 5,
            })
        });
        assert_eq!(
            take(&reader, &store, &other).await,
            Err(Equivocation { version: 1 })
        );
        assert!(
            reader
                .exists(&key::ident_equivocated(&v1.identity()))
                .await
                .unwrap()
        );
    }

    #[test]
    fn test_own_successor_refuses_a_removed_app_listed_again() {
        let removed = doc(2, |b| {
            b.removed.push(RemovedApp {
                app_id: [3; 16],
                distrust_from: 5,
            })
        });
        let listed_again = doc(3, |b| {
            b.apps.push(ListedApp {
                app_id: [3; 16],
                cert: [4; 32],
            })
        });
        assert!(check_own_successor(&removed, &listed_again).is_err());
        assert!(check_own_successor(&removed, &doc(3, |_| {})).is_ok());
    }
}
