//! The signer's alerts (Dispatch spec 4.3).
//!
//! See the signer host guide's [alarms] and [alerts] sections.
//!
//! [alarms]: https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#215-alarms
//! [alerts]: https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#311-alerts

use crate::signer::SignerRef;
use crate::{Signer, SignerFfiError};
use pubky_dispatch_signer::{Alert, FirstEnrollmentStop, RenewalSkip, Source};
use std::{fmt, sync::Arc};

/// Where the signer saw a copy of `identity.json` (Dispatch spec 4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AlertSource {
    /// The service's copy (Dispatch spec 4.3).
    Service,
    /// The Homeserver's copy (Dispatch spec 4.3).
    Homeserver,
    /// The signer backup on the Homeserver (Dispatch wire 3.13).
    Backup,
}

impl From<Source> for AlertSource {
    fn from(source: Source) -> Self {
        match source {
            Source::Dispatch => Self::Service,
            Source::Homeserver => Self::Homeserver,
            Source::Backup => Self::Backup,
        }
    }
}

/// Why the signer didn't renew a certificate past half its lifetime by itself (Dispatch spec 3.2).
#[derive(PartialEq, Eq, uniffi::Enum)]
pub enum RenewalSkipFacts {
    /// The certificate holds scopes no registered protocol owns, which a renewal can only
    /// remove (Dispatch spec 3.2).
    UnownedScopes {
        /// Those scopes (Dispatch spec 3.2).
        scopes: Vec<String>,
    },
    /// The registered protocols now give the certificate's scopes other Dispatch permissions
    /// than it holds (Dispatch spec 3.2).
    PermissionsChanged {
        /// The permissions the certificate holds (Dispatch spec 3.2).
        held: Vec<String>,
        /// The permissions a renewal would give it now (Dispatch spec 3.2).
        now: Vec<String>,
    },
    /// The certificate's scopes now fail a scope rule (Dispatch spec 3.2).
    ScopesRefused {
        /// The protocol whose rule refused them, or `None` for the Dispatch's own scope rule
        /// (Dispatch spec 3.2).
        protocol: Option<String>,
        /// The rule's own reason, as its code gives it (Dispatch spec 3.2).
        reason: String,
    },
    /// The reason is unknown to these bindings (Dispatch spec 3.2).
    Unknown,
}

impl fmt::Debug for RenewalSkipFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RenewalSkipFacts(..)")
    }
}

impl From<&RenewalSkip> for RenewalSkipFacts {
    fn from(reason: &RenewalSkip) -> Self {
        match reason {
            RenewalSkip::UnownedScopes { scopes } => Self::UnownedScopes {
                scopes: scopes.clone(),
            },
            RenewalSkip::PermissionsChanged { held, now } => Self::PermissionsChanged {
                held: held.clone(),
                now: now.clone(),
            },
            RenewalSkip::ScopesRefused { protocol, reason } => Self::ScopesRefused {
                protocol: protocol.clone(),
                reason: reason.clone(),
            },
            _ => Self::Unknown,
        }
    }
}

/// Why the original first enrollment is waiting for the host (Dispatch account binding 3).
#[derive(PartialEq, Eq, uniffi::Enum)]
pub enum FirstEnrollmentStopFacts {
    /// The original service authenticated the expiry of the signed creation's observation
    /// (Dispatch account binding 3).
    Expired,
    /// The original service authenticated a change to the signed creation's account binding
    /// (Dispatch account binding 3).
    Changed,
    /// The service refused this request with a code requiring action before retry
    /// (Dispatch account binding 3).
    Refused {
        /// The refusal code's wire spelling (Dispatch spec 6.4).
        code: String,
    },
    /// No usable answer establishes what happened to the original setup (Dispatch account binding 3).
    Unconfirmed,
    /// The reason is unknown to these bindings (Dispatch account binding 3).
    Unknown,
}

impl fmt::Debug for FirstEnrollmentStopFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirstEnrollmentStopFacts(..)")
    }
}

impl From<FirstEnrollmentStop> for FirstEnrollmentStopFacts {
    fn from(reason: FirstEnrollmentStop) -> Self {
        match reason {
            FirstEnrollmentStop::Expired => Self::Expired,
            FirstEnrollmentStop::Changed => Self::Changed,
            FirstEnrollmentStop::Refused(code) => Self::Refused {
                code: code.as_str().to_owned(),
            },
            FirstEnrollmentStop::Unconfirmed => Self::Unconfirmed,
            _ => Self::Unknown,
        }
    }
}

/// The facts an alert carries (Dispatch spec 4.3).
#[derive(PartialEq, Eq, uniffi::Enum)]
pub enum AlertFacts {
    /// First setup is paused at its original step (Dispatch account binding 3).
    FirstEnrollmentHeld {
        /// Why the original first enrollment is waiting (Dispatch account binding 3).
        reason: FirstEnrollmentStopFacts,
    },
    /// A copy of `identity.json` is older than the newest one a service accepted from this signer
    /// (Dispatch spec 4.3, Dispatch wire 3.3).
    Rollback {
        /// Where the copy was seen (Dispatch spec 4.3).
        source: AlertSource,
        /// The copy's version, or `None` when the source holds no copy at all (Dispatch spec 4.3).
        version: Option<u64>,
        /// The copy's generation, or `None` when the source holds no copy at all (Dispatch spec 4.3).
        generation: Option<u64>,
        /// The newest version a service accepted from this signer (Dispatch spec 4.3).
        high_water_version: u64,
    },
    /// Another `identity.json` at the version of the newest one a service accepted from this
    /// signer (Dispatch spec 4.3).
    Equivocation {
        /// Where the copy was seen (Dispatch spec 4.3).
        source: AlertSource,
        /// The version (Dispatch spec 4.3).
        version: u64,
    },
    /// Another install is the identity's signer, as the newest `identity.json` or the
    /// signer's backup names it (Dispatch spec 4.3, 12.8).
    ManagedByOtherInstall {
        /// That install's signer ID (Dispatch spec 4.3, 12.8).
        install: Vec<u8>,
    },
    /// The signer's backup on the Homeserver didn't open (Dispatch wire 3.13).
    BackupUnreadable,
    /// The end of the staged admission a recovery started didn't go through at the new service
    /// (Dispatch spec 12.6 step 2).
    AdmissionNotEnded,
    /// Before this install's first version was delivered, the Homeserver held a signer backup it
    /// can't open (Dispatch wire 3.13).
    UnreadableBackupBeforeEnrollment,
    /// The Homeserver held no signer backup, though this signer had written one (Dispatch wire 3.13).
    BackupMissing,
    /// The Dispatch or the Homeserver holds a newer `identity.json` that this install signed itself
    /// (Dispatch wire 3.13).
    RecordsBehind {
        /// Where the newer copy was (Dispatch wire 3.13).
        source: AlertSource,
        /// Its version (Dispatch wire 3.13).
        version: u64,
        /// The newest version this signer's records hold (Dispatch wire 3.13).
        high_water_version: u64,
    },
    /// A reduction still owes its closing delivery (Dispatch wire 3.8).
    ReductionNotClosed {
        /// The apps whose reduction stays open (Dispatch wire 3.8).
        apps: Vec<Vec<u8>>,
    },
    /// A rotation gave this app no keys for its new data epoch (Dispatch wire 3.5).
    RotationSkipped {
        /// The app left without the new epoch's keys (Dispatch wire 3.5).
        app_id: Vec<u8>,
        /// Its scopes that no registered protocol owns (Dispatch wire 3.5).
        scopes: Vec<String>,
    },
    /// No record of this app took up either of its last two automatic renewals, so the signer
    /// stops renewing it by itself (Dispatch spec 3.1).
    RenewalsStopped {
        /// The app (Dispatch spec 3.1).
        app_id: Vec<u8>,
        /// When its certificate expires, in Unix milliseconds (Dispatch spec 3.1).
        expires_at: u64,
    },
    /// This app's renewal didn't happen (Dispatch spec 3.2).
    RenewalRefused {
        /// The app (Dispatch spec 3.2).
        app_id: Vec<u8>,
        /// Whether the renewal refused was a reduction (Dispatch wire 3.8).
        reduction: bool,
        /// Whether the user asked for it, rather than an automatic renewal (Dispatch spec 3.2).
        by_user: bool,
    },
    /// An app whose renewals stopped still owns open or `unknown` attempts (Dispatch spec 10.2).
    LapsingWithOpenAttempts {
        /// The app (Dispatch spec 10.2).
        app_id: Vec<u8>,
        /// When its certificate expires, in Unix milliseconds (Dispatch spec 10.2).
        expires_at: u64,
        /// How many attempts it owns that are open or `unknown` (Dispatch spec 10.2).
        open_attempts: u64,
    },
    /// An app being revoked, or revoked, owns open or `unknown` attempts (Dispatch spec 12.2,
    /// 10.2).
    RevokedWithOpenAttempts {
        /// The app (Dispatch spec 12.2, 10.2).
        app_id: Vec<u8>,
        /// How many attempts it owns that are open or `unknown` (Dispatch spec 12.2, 10.2).
        open_attempts: u64,
    },
    /// This app's certificate is past half its lifetime, and the signer doesn't renew it by
    /// itself, for `reason` (Dispatch spec 3.2).
    RenewalSkipped {
        /// The app whose certificate isn't renewed (Dispatch spec 3.2).
        app_id: Vec<u8>,
        /// Why the certificate isn't renewed (Dispatch spec 3.2).
        reason: RenewalSkipFacts,
    },
    /// The newest `identity.json`, as delivered or as a move's enrollment would carry it,
    /// takes more than three quarters of the most that body may carry (Dispatch wire 3.7, 7.1).
    IdentityNearLimit {
        /// The version's size in that body, in bytes (Dispatch wire 3.7).
        bytes: u64,
        /// That body's cap, in bytes (Dispatch wire 3.7).
        limit: u64,
    },
    /// The device clock and the Dispatch's signed time differ by more than the clock tolerance
    /// (Dispatch spec 10.1).
    ClockOff,
    /// The Dispatch answers `GET /apps` with a `404` its pinned key didn't sign, while no
    /// erasure of this install's is in progress (Dispatch spec 12.5).
    AccountNotHosted,
    /// The Dispatch says, under the key this install pinned, that it holds no account for the
    /// identity (Dispatch wire 7.3).
    ServiceHoldsNoAccount,
    /// A provider loss declaration the user started enrolled at a service whose key this
    /// install had pinned, and the enrollment answer named another key (Dispatch spec 12.5).
    ServiceKeyTaken {
        /// The service's origin (Dispatch spec 12.5).
        origin: String,
        /// The key pinned for it before (Dispatch spec 12.5).
        pinned: Vec<u8>,
        /// The key taken (Dispatch spec 12.5).
        service_key: Vec<u8>,
    },
    /// A recovery with the identity key alone enrolled at the account's service, and the
    /// enrollment answer named another key than the one the service's copy of `identity.json`
    /// names (Dispatch spec 12.5).
    ServiceKeyNotFollowed {
        /// The service's origin (Dispatch spec 12.5).
        origin: String,
        /// The key the copy names, kept (Dispatch spec 12.5).
        kept: Vec<u8>,
        /// The key the enrollment answer named (Dispatch spec 12.5).
        answered: Vec<u8>,
    },
    /// A removed app's grants still let it write its Homeserver paths (Dispatch spec 3.4, 12.2).
    GrantRevocationOwed {
        /// The removed app (Dispatch spec 3.4, 12.2 step 1).
        app_id: Vec<u8>,
    },
    /// The Dispatch took the revocation of this app but gave no time for it, neither in its
    /// answer's proof nor in `GET /apps` (Dispatch wire 7.4.12).
    RevocationUnconfirmed {
        /// The app (Dispatch wire 7.4.12).
        app_id: Vec<u8>,
    },
    /// The Dispatch shows an app revoked or departed that this signer didn't ask for (Dispatch spec
    /// 12.2, 12.3).
    RemovedAtDispatch {
        /// The app (Dispatch spec 12.2, 12.3).
        app_id: Vec<u8>,
        /// Whether the app left on its own, rather than being revoked (Dispatch spec 12.2, 12.3).
        left: bool,
    },
    /// The Dispatch reported a revocation or departure time for this app before it took this
    /// signer's newest version, which lists the app (Dispatch wire 3.3).
    RemovalTimeBounded {
        /// The app (Dispatch wire 3.3).
        app_id: Vec<u8>,
        /// The time the Dispatch reported (Dispatch wire 3.3).
        reported: u64,
        /// The time it was removed from (Dispatch wire 3.3).
        distrust_from: u64,
    },
    /// The Dispatch refused the key bundle answering this app's full-bundle request
    /// (Dispatch wire 3.5).
    FullBundleRefused {
        /// The app (Dispatch wire 3.5).
        app_id: Vec<u8>,
    },
    /// A revocation is asked for and no version removes the app yet (Dispatch spec 12.2).
    RevocationPending {
        /// The app (Dispatch spec 12.2).
        app_id: Vec<u8>,
        /// Whether the Dispatch took the revocation while `identity.json` still lists the app
        /// (Dispatch spec 12.2).
        at_dispatch: bool,
    },
    /// After a restore, the signer backup couldn't be written once its delivery won
    /// (Dispatch wire 3.13).
    BackupNotWritten,
    /// The Dispatch refused to store the hand-over to this app for good (Dispatch wire 7.4.17).
    HandOverRefused {
        /// The new signer's App ID (Dispatch wire 7.4.17).
        to_app: Vec<u8>,
    },
    /// The take-over's delivery won, but the vault didn't take the received secret, or didn't
    /// give it back (Dispatch wire 3.12).
    KeyNotInstalled,
    /// The Dispatch refused the take-over's first delivery for good (Dispatch wire 3.12).
    TakeOverRefused,
    /// This install took the identity back from `from`, which the user confirmed lost
    /// (Dispatch wire 3.12).
    TakenBack {
        /// The signer ID the Dispatch's copy named (Dispatch wire 3.12).
        from: Vec<u8>,
    },
    /// A restore found a claim of keys past the next data epoch and kept the floor at the next
    /// epoch (Dispatch spec 3.2, 3.5).
    EpochFloorBounded {
        /// The highest epoch claimed (Dispatch spec 3.2, 3.5).
        claimed: u64,
        /// The floor kept (Dispatch spec 3.2, 3.5).
        kept: u64,
    },
    /// The alert is unknown to these bindings (Dispatch spec 4.3).
    Unknown,
}

impl fmt::Debug for AlertFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AlertFacts(..)")
    }
}

impl From<&Alert> for AlertFacts {
    fn from(alert: &Alert) -> Self {
        match alert {
            Alert::FirstEnrollmentHeld { reason } => Self::FirstEnrollmentHeld {
                reason: (*reason).into(),
            },
            Alert::Rollback {
                source,
                version,
                generation,
                high_water_version,
            } => Self::Rollback {
                source: (*source).into(),
                version: *version,
                generation: *generation,
                high_water_version: *high_water_version,
            },
            Alert::Equivocation { source, version } => Self::Equivocation {
                source: (*source).into(),
                version: *version,
            },
            Alert::ManagedByOtherInstall { install } => Self::ManagedByOtherInstall {
                install: install.to_vec(),
            },
            Alert::BackupUnreadable => Self::BackupUnreadable,
            Alert::AdmissionNotEnded => Self::AdmissionNotEnded,
            Alert::UnreadableBackupBeforeEnrollment => Self::UnreadableBackupBeforeEnrollment,
            Alert::BackupMissing => Self::BackupMissing,
            Alert::RecordsBehind {
                source,
                version,
                high_water_version,
            } => Self::RecordsBehind {
                source: (*source).into(),
                version: *version,
                high_water_version: *high_water_version,
            },
            Alert::ReductionNotClosed { apps } => Self::ReductionNotClosed {
                apps: apps.iter().map(|id| id.to_vec()).collect(),
            },
            Alert::RotationSkipped { app_id, scopes } => Self::RotationSkipped {
                app_id: app_id.to_vec(),
                scopes: scopes.clone(),
            },
            Alert::RenewalsStopped { app_id, expires_at } => Self::RenewalsStopped {
                app_id: app_id.to_vec(),
                expires_at: *expires_at,
            },
            Alert::RenewalRefused {
                app_id,
                reduction,
                by_user,
            } => Self::RenewalRefused {
                app_id: app_id.to_vec(),
                reduction: *reduction,
                by_user: *by_user,
            },
            Alert::LapsingWithOpenAttempts {
                app_id,
                expires_at,
                open_attempts,
            } => Self::LapsingWithOpenAttempts {
                app_id: app_id.to_vec(),
                expires_at: *expires_at,
                open_attempts: *open_attempts,
            },
            Alert::RevokedWithOpenAttempts {
                app_id,
                open_attempts,
            } => Self::RevokedWithOpenAttempts {
                app_id: app_id.to_vec(),
                open_attempts: *open_attempts,
            },
            Alert::RenewalSkipped { app_id, reason } => Self::RenewalSkipped {
                app_id: app_id.to_vec(),
                reason: reason.into(),
            },
            Alert::IdentityNearLimit { bytes, limit } => Self::IdentityNearLimit {
                bytes: *bytes,
                limit: *limit,
            },
            Alert::ClockOff => Self::ClockOff,
            Alert::AccountNotHosted => Self::AccountNotHosted,
            Alert::ServiceHoldsNoAccount => Self::ServiceHoldsNoAccount,
            Alert::ServiceKeyTaken {
                origin,
                pinned,
                service_key,
            } => Self::ServiceKeyTaken {
                origin: origin.clone(),
                pinned: pinned.to_vec(),
                service_key: service_key.to_vec(),
            },
            Alert::ServiceKeyNotFollowed {
                origin,
                kept,
                answered,
            } => Self::ServiceKeyNotFollowed {
                origin: origin.clone(),
                kept: kept.to_vec(),
                answered: answered.to_vec(),
            },
            Alert::GrantRevocationOwed { app_id } => Self::GrantRevocationOwed {
                app_id: app_id.to_vec(),
            },
            Alert::RevocationUnconfirmed { app_id } => Self::RevocationUnconfirmed {
                app_id: app_id.to_vec(),
            },
            Alert::RemovedAtDispatch { app_id, left } => Self::RemovedAtDispatch {
                app_id: app_id.to_vec(),
                left: *left,
            },
            Alert::RemovalTimeBounded {
                app_id,
                reported,
                distrust_from,
            } => Self::RemovalTimeBounded {
                app_id: app_id.to_vec(),
                reported: *reported,
                distrust_from: *distrust_from,
            },
            Alert::FullBundleRefused { app_id } => Self::FullBundleRefused {
                app_id: app_id.to_vec(),
            },
            Alert::RevocationPending {
                app_id,
                at_dispatch,
            } => Self::RevocationPending {
                app_id: app_id.to_vec(),
                at_dispatch: *at_dispatch,
            },
            Alert::BackupNotWritten => Self::BackupNotWritten,
            Alert::HandOverRefused { to_app } => Self::HandOverRefused {
                to_app: to_app.to_vec(),
            },
            Alert::KeyNotInstalled => Self::KeyNotInstalled,
            Alert::TakeOverRefused => Self::TakeOverRefused,
            Alert::TakenBack { from } => Self::TakenBack {
                from: from.to_vec(),
            },
            Alert::EpochFloorBounded { claimed, kept } => Self::EpochFloorBounded {
                claimed: *claimed,
                kept: *kept,
            },
            _ => Self::Unknown,
        }
    }
}

/// An alert this signer keeps until the user has seen it (Dispatch spec 4.3). It doesn't keep
/// its signer open: once the signer is shut down, or its last handle is gone, the alert's
/// facts stay readable and clearing it is refused as on a closed signer.
#[derive(uniffi::Object)]
pub struct SeenAlert {
    alert: Alert,
    signer: SignerRef,
}

impl fmt::Debug for SeenAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SeenAlert(..)")
    }
}

#[uniffi::export]
impl Signer {
    /// The alerts the user hasn't cleared, oldest first (Dispatch spec 4.3). A signer call,
    /// which waits its turn behind the call the signer is running: never awaited from inside
    /// a host callback of this signer
    /// ([signer host guide, 2.4](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store)).
    pub async fn alerts(&self) -> Result<Vec<Arc<SeenAlert>>, SignerFfiError> {
        let alerts = self
            .call(|signer| Box::pin(async move { Ok(signer.alerts().to_vec()) }))
            .await?;
        Ok(alerts
            .into_iter()
            .map(|alert| {
                Arc::new(SeenAlert {
                    alert,
                    signer: self.weak(),
                })
            })
            .collect())
    }
}

#[uniffi::export]
impl SeenAlert {
    /// The facts this alert carries (Dispatch spec 4.3). Synchronous: read from what this
    /// handle holds, on the caller's thread; it takes no turn and doesn't reach the signer.
    pub fn facts(&self) -> AlertFacts {
        (&self.alert).into()
    }

    /// Whether this alert is about the app `app_id` (Dispatch spec 4.3); an App ID that isn't
    /// 16 bytes is refused as invalid input. Synchronous: read from what this handle holds, on
    /// the caller's thread; it takes no turn and doesn't reach the signer.
    pub fn names_app(&self, app_id: Vec<u8>) -> Result<bool, SignerFfiError> {
        let id = app_id
            .as_slice()
            .try_into()
            .map_err(|_| SignerFfiError::InvalidInput {
                reason: "an app ID must be 16 bytes".into(),
            })?;
        Ok(self.alert.names_app(id))
    }

    /// Clear this alert once the user has seen it (Dispatch spec 4.3). A call of its signer,
    /// which waits its turn behind the call the signer is running: never awaited from inside
    /// a host callback of that signer
    /// ([signer host guide, 2.4](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store)).
    pub async fn clear(&self) -> Result<(), SignerFfiError> {
        let alert = self.alert.clone();
        self.signer
            .call(move |signer| {
                Box::pin(async move {
                    signer.clear_alert(&alert).await?;
                    Ok(())
                })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_dispatch_core::http::ErrorCode;

    #[test]
    fn test_alerts_facts() {
        use Alert as A;
        use AlertFacts as F;
        let app_id = [0x12; 16];
        let other = [0x34; 16];
        let pinned = [0x56; 32];
        let answered = [0x78; 32];
        let origin = "https://service.example";
        for (native, expected) in [
            (
                A::FirstEnrollmentHeld {
                    reason: FirstEnrollmentStop::Changed,
                },
                F::FirstEnrollmentHeld {
                    reason: FirstEnrollmentStopFacts::Changed,
                },
            ),
            (
                A::Rollback {
                    source: Source::Homeserver,
                    version: Some(2),
                    generation: Some(7),
                    high_water_version: 9,
                },
                F::Rollback {
                    source: AlertSource::Homeserver,
                    version: Some(2),
                    generation: Some(7),
                    high_water_version: 9,
                },
            ),
            (
                A::Equivocation {
                    source: Source::Dispatch,
                    version: 3,
                },
                F::Equivocation {
                    source: AlertSource::Service,
                    version: 3,
                },
            ),
            (
                A::ManagedByOtherInstall { install: other },
                F::ManagedByOtherInstall {
                    install: other.to_vec(),
                },
            ),
            (A::BackupUnreadable, F::BackupUnreadable),
            (A::AdmissionNotEnded, F::AdmissionNotEnded),
            (
                A::UnreadableBackupBeforeEnrollment,
                F::UnreadableBackupBeforeEnrollment,
            ),
            (A::BackupMissing, F::BackupMissing),
            (
                A::RecordsBehind {
                    source: Source::Backup,
                    version: 11,
                    high_water_version: 8,
                },
                F::RecordsBehind {
                    source: AlertSource::Backup,
                    version: 11,
                    high_water_version: 8,
                },
            ),
            (
                A::ReductionNotClosed {
                    apps: vec![other, app_id],
                },
                F::ReductionNotClosed {
                    apps: vec![other.to_vec(), app_id.to_vec()],
                },
            ),
            (
                A::RotationSkipped {
                    app_id,
                    scopes: vec!["sample/read".into(), "sample/write".into()],
                },
                F::RotationSkipped {
                    app_id: app_id.to_vec(),
                    scopes: vec!["sample/read".into(), "sample/write".into()],
                },
            ),
            (
                A::RenewalsStopped {
                    app_id,
                    expires_at: 123,
                },
                F::RenewalsStopped {
                    app_id: app_id.to_vec(),
                    expires_at: 123,
                },
            ),
            (
                A::RenewalRefused {
                    app_id,
                    reduction: true,
                    by_user: false,
                },
                F::RenewalRefused {
                    app_id: app_id.to_vec(),
                    reduction: true,
                    by_user: false,
                },
            ),
            (
                A::LapsingWithOpenAttempts {
                    app_id,
                    expires_at: 264,
                    open_attempts: 5,
                },
                F::LapsingWithOpenAttempts {
                    app_id: app_id.to_vec(),
                    expires_at: 264,
                    open_attempts: 5,
                },
            ),
            (
                A::RevokedWithOpenAttempts {
                    app_id,
                    open_attempts: 4,
                },
                F::RevokedWithOpenAttempts {
                    app_id: app_id.to_vec(),
                    open_attempts: 4,
                },
            ),
            (
                A::RenewalSkipped {
                    app_id,
                    reason: RenewalSkip::UnownedScopes {
                        scopes: vec!["sample/read".into()],
                    },
                },
                F::RenewalSkipped {
                    app_id: app_id.to_vec(),
                    reason: RenewalSkipFacts::UnownedScopes {
                        scopes: vec!["sample/read".into()],
                    },
                },
            ),
            (
                A::IdentityNearLimit {
                    bytes: 81,
                    limit: 100,
                },
                F::IdentityNearLimit {
                    bytes: 81,
                    limit: 100,
                },
            ),
            (A::ClockOff, F::ClockOff),
            (A::AccountNotHosted, F::AccountNotHosted),
            (A::ServiceHoldsNoAccount, F::ServiceHoldsNoAccount),
            (
                A::ServiceKeyTaken {
                    origin: origin.into(),
                    pinned,
                    service_key: answered,
                },
                F::ServiceKeyTaken {
                    origin: origin.into(),
                    pinned: pinned.to_vec(),
                    service_key: answered.to_vec(),
                },
            ),
            (
                A::ServiceKeyNotFollowed {
                    origin: origin.into(),
                    kept: pinned,
                    answered,
                },
                F::ServiceKeyNotFollowed {
                    origin: origin.into(),
                    kept: pinned.to_vec(),
                    answered: answered.to_vec(),
                },
            ),
            (
                A::GrantRevocationOwed { app_id },
                F::GrantRevocationOwed {
                    app_id: app_id.to_vec(),
                },
            ),
            (
                A::RevocationUnconfirmed { app_id },
                F::RevocationUnconfirmed {
                    app_id: app_id.to_vec(),
                },
            ),
            (
                A::RemovedAtDispatch { app_id, left: true },
                F::RemovedAtDispatch {
                    app_id: app_id.to_vec(),
                    left: true,
                },
            ),
            (
                A::RemovalTimeBounded {
                    app_id,
                    reported: 2,
                    distrust_from: 51,
                },
                F::RemovalTimeBounded {
                    app_id: app_id.to_vec(),
                    reported: 2,
                    distrust_from: 51,
                },
            ),
            (
                A::FullBundleRefused { app_id },
                F::FullBundleRefused {
                    app_id: app_id.to_vec(),
                },
            ),
            (
                A::RevocationPending {
                    app_id,
                    at_dispatch: true,
                },
                F::RevocationPending {
                    app_id: app_id.to_vec(),
                    at_dispatch: true,
                },
            ),
            (A::BackupNotWritten, F::BackupNotWritten),
            (
                A::HandOverRefused { to_app: app_id },
                F::HandOverRefused {
                    to_app: app_id.to_vec(),
                },
            ),
            (A::KeyNotInstalled, F::KeyNotInstalled),
            (A::TakeOverRefused, F::TakeOverRefused),
            (
                A::TakenBack { from: other },
                F::TakenBack {
                    from: other.to_vec(),
                },
            ),
            (
                A::EpochFloorBounded {
                    claimed: 13,
                    kept: 10,
                },
                F::EpochFloorBounded {
                    claimed: 13,
                    kept: 10,
                },
            ),
        ] {
            assert_eq!(
                AlertFacts::from(&native),
                expected,
                "{:?}",
                crate::AlertKind::from(&native)
            );
        }
    }

    #[test]
    fn test_alerts_sources() {
        for (native, expected) in [
            (Source::Dispatch, AlertSource::Service),
            (Source::Homeserver, AlertSource::Homeserver),
            (Source::Backup, AlertSource::Backup),
        ] {
            assert_eq!(AlertSource::from(native), expected);
        }
    }

    #[test]
    fn test_alerts_renewal_skip() {
        use RenewalSkip as R;
        use RenewalSkipFacts as F;
        for (native, expected) in [
            (
                R::UnownedScopes {
                    scopes: vec!["sample/read".into(), "sample/write".into()],
                },
                F::UnownedScopes {
                    scopes: vec!["sample/read".into(), "sample/write".into()],
                },
            ),
            (
                R::PermissionsChanged {
                    held: vec!["read".into()],
                    now: vec!["write".into()],
                },
                F::PermissionsChanged {
                    held: vec!["read".into()],
                    now: vec!["write".into()],
                },
            ),
            (
                R::ScopesRefused {
                    protocol: Some("sample".into()),
                    reason: "too_many".into(),
                },
                F::ScopesRefused {
                    protocol: Some("sample".into()),
                    reason: "too_many".into(),
                },
            ),
            (
                R::ScopesRefused {
                    protocol: None,
                    reason: "bad_scope".into(),
                },
                F::ScopesRefused {
                    protocol: None,
                    reason: "bad_scope".into(),
                },
            ),
        ] {
            assert_eq!(RenewalSkipFacts::from(&native), expected);
        }
    }

    #[test]
    fn test_alerts_first_enrollment_stop() {
        use FirstEnrollmentStop as R;
        use FirstEnrollmentStopFacts as F;
        for (native, expected) in [
            (R::Expired, F::Expired),
            (R::Changed, F::Changed),
            (
                R::Refused(ErrorCode::PermissionMissing),
                F::Refused {
                    code: "permission_missing".into(),
                },
            ),
            (R::Unconfirmed, F::Unconfirmed),
        ] {
            assert_eq!(FirstEnrollmentStopFacts::from(native), expected);
        }
    }

    #[cfg(feature = "test-fixtures")]
    mod scripted {
        use super::*;
        use crate::{
            AlertKind, FixtureService, HomeserverFailure, HostHomeserver, HostVault, SignerStatus,
            VaultAddOutcome, VaultFailure, protocol, test_host::MemoryHost,
        };
        use pubky_dispatch_core::records::SIGNER_BACKUP_PATH;
        use std::{collections::BTreeMap, sync::Mutex};

        const SEED: [u8; 32] = [
            0xf6, 0x98, 0x6c, 0xa5, 0x7b, 0xe7, 0x38, 0xd6, 0x81, 0x45, 0xe3, 0xc0, 0x6e, 0xf2,
            0xd1, 0xdc, 0x30, 0x25, 0x95, 0x2f, 0xc2, 0xbe, 0x9d, 0x62, 0x46, 0xc6, 0x49, 0x74,
            0x10, 0x51, 0x91, 0x42,
        ];
        const ORIGIN: &str = "https://dispatch.example";

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

        async fn enrolled(home: Home) -> (Arc<FixtureService>, Arc<Signer>) {
            protocol::sample().unwrap();
            let service = FixtureService::new(SEED.to_vec(), Box::new(home)).unwrap();
            let signer = service
                .create_signer(
                    Box::new(Vault),
                    MemoryHost::default().boxed(),
                    ORIGIN.into(),
                )
                .await
                .unwrap();
            signer.resume().await.unwrap();
            assert_eq!(signer.status().unwrap(), SignerStatus::Signing);
            (service, signer)
        }

        async fn lose_copy(service: &FixtureService, signer: &Signer) {
            service.lose_identity();
            if let Err(error) = signer.set_record_max_age(Some(3_600)).await {
                assert!(matches!(
                    error,
                    SignerFfiError::Alarm {
                        alert: AlertKind::Rollback
                    }
                ));
            }
        }

        /// The longest a scripted test may take: each runs against in-memory hosts and a
        /// scripted service, so one that takes longer is stuck.
        const TEST_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

        async fn bounded(test: impl std::future::Future<Output = ()>) {
            tokio::time::timeout(TEST_BOUND, test)
                .await
                .expect("the test ended within its bound");
        }

        fn rollback(high_water_version: u64) -> AlertFacts {
            AlertFacts::Rollback {
                source: AlertSource::Service,
                version: None,
                generation: None,
                high_water_version,
            }
        }

        #[tokio::test]
        async fn test_alerts_rollback() {
            bounded(async {
                let (service, signer) = enrolled(Home::default()).await;
                assert!(signer.alerts().await.unwrap().is_empty());
                lose_copy(&service, &signer).await;
                let [alert]: [_; 1] = signer.alerts().await.unwrap().try_into().unwrap();
                assert_eq!(alert.facts(), rollback(1));
                assert!(matches!(
                    alert.clear().await,
                    Err(SignerFfiError::Alarm {
                        alert: AlertKind::Rollback
                    })
                ));
                let [again]: [_; 1] = signer.alerts().await.unwrap().try_into().unwrap();
                assert_eq!(again.facts(), alert.facts());
                assert_eq!(signer.status().unwrap(), SignerStatus::Alarm);
                signer.shutdown().await.unwrap();
                assert_eq!(alert.facts(), rollback(1));
                assert!(matches!(alert.clear().await,
                    Err(SignerFfiError::InvalidInput { reason }) if reason == "the signer is closed"));
            })
            .await;
        }

        #[tokio::test]
        async fn test_alerts_handle_does_not_keep_its_signer_open() {
            bounded(async {
                protocol::sample().unwrap();
                let service = FixtureService::new(SEED.to_vec(), Box::<Home>::default()).unwrap();
                let host = MemoryHost::default();
                let signer = service
                    .create_signer(Box::new(Vault), host.boxed(), ORIGIN.into())
                    .await
                    .unwrap();
                signer.resume().await.unwrap();
                lose_copy(&service, &signer).await;
                let [alert]: [_; 1] = signer.alerts().await.unwrap().try_into().unwrap();
                // The signer's last handle goes without a shutdown, and the alert is kept.
                drop(signer);
                assert_eq!(alert.facts(), rollback(1));
                assert!(matches!(alert.clear().await,
                    Err(SignerFfiError::InvalidInput { reason }) if reason == "the signer is closed"));
                // The store's records are free: the signer opens again, and holds them.
                let reopened = service
                    .open_signer(Box::new(Vault), host.boxed())
                    .await
                    .unwrap();
                assert!(host.held());
                // The old alert reaches only its own signer, closed, never the one open now.
                assert!(matches!(alert.clear().await,
                    Err(SignerFfiError::InvalidInput { reason }) if reason == "the signer is closed"));
                assert_eq!(reopened.alerts().await.unwrap().len(), 1);
                reopened.shutdown().await.unwrap();
                assert!(!host.held());
                // The alert holds neither signer, nor what either held: the old entry goes once
                // its closer has let it go.
                let until = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
                while !alert.signer.is_gone() && tokio::time::Instant::now() < until {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                assert!(alert.signer.is_gone(), "the alert keeps its signer's entry");
                assert_eq!(alert.facts(), rollback(1));
            })
            .await;
        }

        #[tokio::test]
        async fn test_alerts_clear_stale() {
            bounded(async {
                let home = Home::default();
                let (service, signer) = enrolled(home.clone()).await;
                home.delete(SIGNER_BACKUP_PATH.into()).await.unwrap();
                signer.set_record_max_age(Some(86_400)).await.unwrap();
                let [first]: [_; 1] = signer.alerts().await.unwrap().try_into().unwrap();
                assert_eq!(first.facts(), AlertFacts::BackupMissing);

                lose_copy(&service, &signer).await;
                let [listed, alarm]: [_; 2] = signer.alerts().await.unwrap().try_into().unwrap();
                assert_eq!(listed.facts(), AlertFacts::BackupMissing);
                assert_eq!(alarm.facts(), rollback(2));
                // Cleared through the handle of the second listing: only that alert goes.
                listed.clear().await.unwrap();
                let [remaining]: [_; 1] = signer.alerts().await.unwrap().try_into().unwrap();
                assert_eq!(remaining.facts(), alarm.facts());
                // The first listing's handle to it is stale now: its clear clears nothing more.
                first.clear().await.unwrap();
                let [remaining]: [_; 1] = signer.alerts().await.unwrap().try_into().unwrap();
                assert_eq!(remaining.facts(), alarm.facts());
                // An older alert of the same kind, with other fields, isn't the newer one: its
                // clear leaves the newer rollback in place.
                let older = SeenAlert {
                    alert: Alert::Rollback {
                        source: Source::Dispatch,
                        version: None,
                        generation: None,
                        high_water_version: 1,
                    },
                    signer: signer.weak(),
                };
                older.clear().await.unwrap();
                let [remaining]: [_; 1] = signer.alerts().await.unwrap().try_into().unwrap();
                assert_eq!(remaining.facts(), rollback(2));
                signer.shutdown().await.unwrap();
            })
            .await;
        }

        #[tokio::test]
        async fn test_alerts_names_app() {
            bounded(async {
                let (_service, signer) = enrolled(Home::default()).await;
                let app_id = [1; 16];
                let app = SeenAlert {
                    alert: Alert::GrantRevocationOwed { app_id },
                    signer: signer.weak(),
                };
                let identity = SeenAlert {
                    alert: Alert::ManagedByOtherInstall { install: app_id },
                    signer: signer.weak(),
                };
                signer.shutdown().await.unwrap();
                assert!(app.names_app(app_id.to_vec()).unwrap());
                assert!(!app.names_app(vec![2; 16]).unwrap());
                assert!(!identity.names_app(app_id.to_vec()).unwrap());
                for length in [15, 17] {
                    assert!(matches!(
                        app.names_app(vec![1; length]),
                        Err(SignerFfiError::InvalidInput { .. })
                    ));
                }
            })
            .await;
        }

        #[tokio::test]
        async fn test_alerts_debug() {
            bounded(async {
                let (_service, signer) = enrolled(Home::default()).await;
                let reason = RenewalSkip::UnownedScopes {
                    scopes: vec!["private/scope".into()],
                };
                assert_eq!(
                    format!("{:?}", RenewalSkipFacts::from(&reason)),
                    "RenewalSkipFacts(..)"
                );
                for alert in [
                    Alert::RenewalSkipped {
                        app_id: [7; 16],
                        reason,
                    },
                    Alert::ServiceKeyTaken {
                        origin: ORIGIN.into(),
                        pinned: [55; 32],
                        service_key: [66; 32],
                    },
                ] {
                    let seen = SeenAlert {
                        alert,
                        signer: signer.weak(),
                    };
                    assert_eq!(format!("{seen:?}"), "SeenAlert(..)");
                    assert_eq!(format!("{:?}", seen.facts()), "AlertFacts(..)");
                }
                signer.shutdown().await.unwrap();
            })
            .await;
        }
    }
}
