//! What the signer tells the user: alerts it keeps until the user has seen them.
//!
//! Each alert carries the facts to show; the wording is the host's.

use pubky_dispatch_client::{ClientError, TransportError};
use pubky_dispatch_core::http::{ErrorCode, Retry};
use serde::{Deserialize, Serialize};

/// Where the signer saw a copy of `identity.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    /// The Dispatch's copy.
    Dispatch,
    /// The Homeserver's copy.
    Homeserver,
    /// The signer backup on the Homeserver.
    Backup,
}

/// Why the signer didn't renew a certificate past half its lifetime by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RenewalSkip {
    /// The certificate holds scopes no registered protocol owns, which a renewal can only
    /// remove (design note, decision 2).
    UnownedScopes {
        /// Those scopes.
        scopes: Vec<String>,
    },
    /// The registered protocols now give the certificate's scopes other Dispatch permissions
    /// than it holds. A renewal the user didn't ask for never changes what a certificate
    /// grants: the user renews it, and sees the change.
    PermissionsChanged {
        /// The permissions the certificate holds.
        held: Vec<String>,
        /// The permissions a renewal would give it now.
        now: Vec<String>,
    },
    /// The certificate's scopes now fail a scope rule, the Dispatch's or their protocol's: a
    /// renewal keeping them would be refused.
    ScopesRefused {
        /// The protocol whose rule refused them; `None` for the Dispatch's own scope rule.
        protocol: Option<String>,
        /// The rule's own reason, as its code gives it.
        reason: String,
    },
}

/// Why the original first enrollment is waiting for the host (Dispatch account binding 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FirstEnrollmentStop {
    /// The original service authenticated the expiry of the signed creation's observation.
    Expired,
    /// The original service authenticated a change to the signed creation's account binding.
    Changed,
    /// The service refused this request with a code requiring action before retry.
    Refused(#[serde(with = "refusal_code")] ErrorCode),
    /// No usable answer establishes what happened to the original setup.
    Unconfirmed,
}

impl FirstEnrollmentStop {
    pub(crate) fn from_error(error: &ClientError) -> Option<Self> {
        match error {
            ClientError::Dispatch {
                code: ErrorCode::Conflict,
                current,
                ..
            } if *current == serde_json::json!({ "binding": "expired" }) => Some(Self::Expired),
            ClientError::Dispatch {
                code: ErrorCode::Conflict,
                current,
                ..
            } if *current == serde_json::json!({ "binding": "changed" }) => Some(Self::Changed),
            ClientError::Dispatch { code, .. } if Self::needs_action(*code) => {
                Some(Self::Refused(*code))
            }
            ClientError::BodyUnread {
                code: ErrorCode::RateLimited,
                ..
            } => None,
            ClientError::BadServiceSignature { .. }
            | ClientError::InvalidResponse(_)
            | ClientError::BodyUnread { .. }
            | ClientError::Core(_)
            | ClientError::Chain(_)
            | ClientError::BodyOverCap { .. }
            | ClientError::Unpinned
            | ClientError::Usage(_)
            | ClientError::StaleAnswer { .. }
            | ClientError::Transport(
                TransportError::Refused(_)
                | TransportError::TooLarge(_)
                | TransportError::InvalidRequest(_)
                | TransportError::UnreadableSignedHeader { .. },
            ) => Some(Self::Unconfirmed),
            _ => None,
        }
    }

    fn needs_action(code: ErrorCode) -> bool {
        !matches!(
            code.retry(),
            Retry::WithNewTimestamp | Retry::AfterRetryAfter | Retry::WhenLimitFrees | Retry::Yes
        )
    }
}

/// Keep only a defined refusal code from spec 6.4 in the signer's alert.
mod refusal_code {
    use super::{ErrorCode, FirstEnrollmentStop};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub(super) fn serialize<S: Serializer>(
        code: &ErrorCode,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(code.as_str())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ErrorCode, D::Error> {
        ErrorCode::parse(&String::deserialize(deserializer)?)
            .filter(|code| FirstEnrollmentStop::needs_action(*code))
            .ok_or_else(|| D::Error::custom("invalid first enrollment refusal code"))
    }
}

/// One occurrence of an alert the signer holds, as [`crate::Signer::alert_occurrences`] lists
/// it: what the user is shown, and what [`crate::Signer::clear_alert`] clears. An alert
/// raised again while it is held unchanged is the same occurrence; one raised again after it
/// was cleared, or whose facts changed, is another occurrence, with another number. Numbers
/// are this install's own, kept in its records across a restart and a restore; a new install
/// numbers its alerts afresh. A number means something only within its install: never
/// compare it with another install's, or carry it to one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlertOccurrence {
    /// The occurrence's number in this install's records: no other occurrence had it.
    pub number: u64,
    /// The alert.
    pub alert: Alert,
}

/// Something the user needs to know.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Alert {
    /// First setup is paused at its original step. Clear after the user chooses to retry
    /// that step, or use the applicable confirmed recovery (Dispatch account binding 3).
    FirstEnrollmentHeld {
        /// The result the host should explain.
        reason: FirstEnrollmentStop,
    },
    /// A copy of `identity.json` older than the newest one a service accepted from this signer:
    /// a rollback, which the signer doesn't build on (Dispatch spec 4.3, Dispatch wire 3.3 "Never
    /// back").
    Rollback {
        /// Where the copy was seen.
        source: Source,
        /// The copy's version; `None` when the source holds no copy at all.
        version: Option<u64>,
        /// The copy's generation; `None` when the source holds no copy at all.
        generation: Option<u64>,
        /// The newest version a service accepted from this signer.
        high_water_version: u64,
    },
    /// Another `identity.json` at the version of the newest one a service accepted from this
    /// signer: equivocation (Dispatch spec 4.3).
    Equivocation {
        /// Where the copy was seen.
        source: Source,
        /// The version.
        version: u64,
    },
    /// Another install is the identity's signer, as the newest `identity.json` or the
    /// signer's backup names it. This install signs nothing until the user has it take over
    /// (Dispatch spec 4.3, 12.8).
    ManagedByOtherInstall {
        /// That install's signer ID.
        install: [u8; 16],
    },
    /// The signer's backup on the Homeserver didn't open. The Dispatch still held the newest
    /// version this signer delivered, so no other install had taken over, and the signer
    /// wrote its own backup over it (Dispatch wire 3.13).
    BackupUnreadable,
    /// The end of the staged admission a recovery started didn't go through at the new
    /// service: it stays owed and is sent again at every run, and the alert goes once `GET
    /// /apps` shows the wait ended (Dispatch spec 12.6 step 2).
    AdmissionNotEnded,
    /// Before this install's first version was delivered, the Homeserver held a signer backup
    /// it can't open: another install may sign for the identity, or the file is damaged. The
    /// signer writes nothing and delivers nothing until the user deals with it (Dispatch wire
    /// 3.13): by restoring from it on the install that wrote it, or, sure that no other
    /// install signs, by removing it from the Homeserver, after which `resume` goes on.
    UnreadableBackupBeforeEnrollment,
    /// The Homeserver held no signer backup, though this signer had written one. The Dispatch
    /// still held the newest version this signer delivered, so the signer wrote its backup
    /// again (Dispatch wire 3.13).
    BackupMissing,
    /// The Dispatch or the Homeserver holds a newer `identity.json` that this install signed
    /// itself: its records are behind, as after a restore of an old device backup. Signing
    /// on top of its older records would roll the identity's state back (its data epoch,
    /// apps and renewals), so it signs nothing more. The way forward is a restore from the
    /// signer backup, which is written before every delivery and so holds that newer
    /// version (Dispatch wire 3.13). (A newer one by another install isn't this alert: this
    /// install adopts it and stops.)
    RecordsBehind {
        /// Where the newer copy was.
        source: Source,
        /// Its version.
        version: u64,
        /// The newest version this signer's records hold.
        high_water_version: u64,
    },
    /// A reduction still owes its closing delivery. Earlier certificates remain open
    /// until the service accepts it. Clear any signing alarm and let `resume` or
    /// `run_due` retry. If the renewing delivery's exact retry supplied no proof,
    /// the signer needs a verified read of the same document at that account to
    /// establish the service-time cutoff (Dispatch wire 3.8).
    ReductionNotClosed {
        /// The apps whose reduction stays open.
        apps: Vec<[u8; 16]>,
    },
    /// A rotation gave this app no keys for its new data epoch: its certificate holds scopes
    /// no registered protocol owns, so the signer can't tell which keys it holds (design note,
    /// decision 2). Its next bundle, once a protocol owns them, starts after the epochs it
    /// holds, so it catches up (Dispatch wire 3.5).
    RotationSkipped {
        /// The app left without the new epoch's keys.
        app_id: [u8; 16],
        /// Its scopes that no registered protocol owns.
        scopes: Vec<String>,
    },
    /// No record of this app took up either of its last two automatic renewals, so the signer
    /// stops renewing it by itself (Dispatch spec 3.1). The app lapses at `expires_at`: from
    /// then the Dispatch refuses its every request, its feed read included, and readers check
    /// what it writes or sends against that expiry. The user renews it, which brings it back
    /// with nothing from the app (Dispatch wire 3.8 "An expired certificate"), or removes it.
    /// Cleared once the user renews it, a record of it carries the newest certificate, or the
    /// app is removed.
    RenewalsStopped {
        /// The app.
        app_id: [u8; 16],
        /// When its certificate expires, in Unix milliseconds.
        expires_at: u64,
    },
    /// This app's renewal didn't happen (Dispatch spec 3.2): the Dispatch refused it for good, at
    /// the storage of its certificate and key bundle or at its delivery, or its flow ended
    /// without it, as at an alarm or when the epoch completion it waited for was cut off. The
    /// app keeps the certificate `identity.json` lists, with its scopes, their keys, its
    /// Dispatch permissions and its expiry. For a `reduction` the access was not reduced: the
    /// app still holds the scope, or the permission, or the later expiry, that the user asked
    /// to remove. The user renews or reduces it again, or revokes it.
    ///
    /// Raised whichever call met it, the renewal's own or a later [`crate::Signer::resume`]
    /// or [`crate::Signer::run_due`], for a renewal the user asked for (`by_user`) and for an
    /// automatic one, which the next run tries again. One per app, kept in its place, and the
    /// user's wins: a refused automatic renewal leaves the user's alert as it is, and a second
    /// refused renewal the user asked for adds what it asks to the first's, the user's newest
    /// request counting where two contradict (a scope asked to be removed, then added; an
    /// earlier expiry, then a later one). Not raised for an app being revoked, whose removal
    /// tells of it.
    ///
    /// Whether it holds is judged from the certificate `identity.json` lists for the app,
    /// whoever's renewal listed it, against what the user asked, which the records keep
    /// beside the alert:
    ///
    /// - a reduction the user asked for stays while that certificate still holds a scope the
    ///   user asked to remove, by the scope hierarchy, or a Dispatch permission the reduction
    ///   would have removed, or expires later than they asked;
    /// - another renewal the user asked for stays until a certificate holding what they asked
    ///   is listed, or a later renewal they ask for is delivered for the app;
    /// - an automatic renewal's stays until the app is renewed;
    /// - each goes once a version removing the app is delivered.
    ///
    /// A user who clears it doesn't see it again, and what they asked goes with it. It is this
    /// install's own: a restore, in place or on a new install, doesn't bring it back, nor what
    /// the user asked, which only this install knew; the listed certificate shows what the app
    /// holds.
    RenewalRefused {
        /// The app.
        app_id: [u8; 16],
        /// Whether the renewal refused was a reduction (Dispatch wire 3.8 "Reductions").
        reduction: bool,
        /// Whether the user asked for it, rather than an automatic renewal.
        by_user: bool,
    },
    /// An app whose renewals stopped ([`Alert::RenewalsStopped`]) still owns attempts open
    /// or `unknown`, as `GET /apps` lists them: at `expires_at` it isn't current any more, its
    /// open ones are orphaned, and its `unknown` ones are left, for the identity's other apps
    /// or the user to resolve (Dispatch spec 3.2, 10.2). The user renews it, which keeps them its own, or lets it lapse. Brought up
    /// to date at each run; cleared once it owns none, its renewals start again, or it is
    /// removed.
    LapsingWithOpenAttempts {
        /// The app.
        app_id: [u8; 16],
        /// When its certificate expires, in Unix milliseconds.
        expires_at: u64,
        /// How many attempts it owns that are open or `unknown`.
        open_attempts: u64,
    },
    /// An app being revoked, or revoked, owns attempts open or `unknown`, as `GET /apps`
    /// lists them: they remain, the open ones orphaned, for the identity's other apps or the
    /// user to resolve (Dispatch spec 12.2, 10.2). The revocation goes on all the same; before
    /// it, the host shows the count [`crate::Signer::open_attempts`] gives. Brought up to date
    /// at each read of `GET /apps` the removal makes; cleared once it owns none. It is this
    /// install's own: a new install, restored once the removal is delivered, doesn't find it
    /// again.
    RevokedWithOpenAttempts {
        /// The app.
        app_id: [u8; 16],
        /// How many attempts it owns that are open or `unknown`.
        open_attempts: u64,
    },
    /// This app's certificate is past half its lifetime, and the signer doesn't renew it by
    /// itself, for `reason` (Dispatch spec 3.2). Unless the user renews it, the certificate
    /// expires and the Dispatch stops serving the app.
    RenewalSkipped {
        /// The app whose certificate isn't renewed.
        app_id: [u8; 16],
        /// Why.
        reason: RenewalSkip,
    },
    /// The newest `identity.json`, as delivered or as a move's enrollment would carry it,
    /// takes more than three quarters of the most that body may carry (the body caps of `PUT
    /// /identity` and `POST /enroll`, Dispatch wire 3.7, 7.1), in the body it comes nearest to
    /// filling. Also raised when a removal must drop closed entries of removed apps
    /// to fit, or is still too large once they are gone (Dispatch wire 3.3).
    IdentityNearLimit {
        /// The version's size in that body, in bytes.
        bytes: u64,
        /// That body's cap, in bytes.
        limit: u64,
    },
    /// The device clock and the Dispatch's signed time differ by more than the clock tolerance
    /// (Dispatch spec 10.1): certificates are stamped with the device clock, so the signer
    /// renews none by itself, and refuses to issue or renew one, until they agree again. It
    /// clears itself at the first run that finds them agreeing.
    ClockOff,
    /// The Dispatch answers `GET /apps` with a `404` its pinned key didn't sign, while no
    /// erasure of this install's is in progress: an intermediary's, or the service's own
    /// under a key it changed to (Dispatch spec 12.5). This install can't tell which, so it
    /// deletes and changes nothing, and signs nothing while the Dispatch can't be read (Dispatch
    /// wire 7.3 step 2, 7.4.16). The account may have been erased from another copy of this
    /// install; the way out is the user's, a restore or an enrollment elsewhere. It clears
    /// itself at the next check whose `GET /apps` gets an answer the pinned key signs, an
    /// error included; an unsigned answer or no answer leaves it. Every signing step checks first, so it outlasts the Dispatch's
    /// recovery by one check at most. Never raised once the account is erased.
    AccountNotHosted,
    /// The Dispatch says, under the key this install pinned, that it holds no account for the
    /// identity: `GET /apps` got its signed `404 not_found` with `current: { "hosted": false
    /// }`, which the service gives only for an account it doesn't hold, while no erasure of
    /// this install's is in progress (Dispatch wire 7.3 step 2, 7.4.16 "The signer's `404`").
    /// The service lost the account, or it was erased from another copy of this install.
    /// This install deletes and changes nothing, and signs nothing while the Dispatch answers
    /// so; the way out is the user's: a provider loss declared at this service or another
    /// (Dispatch spec 12.6), or a restore. It clears itself at the next `GET /apps` the pinned
    /// key signs with any other answer, and once a recovery's version is delivered. Never
    /// raised once the account is erased.
    ServiceHoldsNoAccount,
    /// A provider loss declaration the user started enrolled at a service whose key this
    /// install had pinned, and the enrollment answer named another key: the service changed
    /// its key (Dispatch spec 12.5). The signer took the new key, which the recovery's version
    /// names, as it does only within a step the user started, and shows it here: the key an
    /// enrollment answer names is trusted on first use, tied to the origin only by the HTTPS
    /// connection (Dispatch wire 7.4.1 "Which key signs").
    ServiceKeyTaken {
        /// The service's origin.
        origin: String,
        /// The key pinned for it before.
        pinned: [u8; 32],
        /// The key taken.
        service_key: [u8; 32],
    },
    /// A recovery with the identity key alone enrolled at the account's service, and the
    /// enrollment answer named another key than the one the service's copy of `identity.json`
    /// names: the service changed its key (Dispatch spec 12.5). The account is served under the
    /// key its copy names, so the recovery keeps that one and doesn't follow the other; the
    /// user is shown both (Dispatch spec 12.8).
    ServiceKeyNotFollowed {
        /// The service's origin.
        origin: String,
        /// The key the copy names, kept.
        kept: [u8; 32],
        /// The key the enrollment answer named.
        answered: [u8; 32],
    },
    /// A removed app's Pubky grants still let it write its Homeserver paths. Each approved
    /// request made one, and each names the app's record path
    /// `/pub/pubky-dispatch/v1/apps/<app_id>.json`. The signer doesn't revoke grants itself:
    /// the host revokes every grant whose capabilities name that path (the Pubky SDK's grant
    /// manager lists and revokes them with a root-capability session), then clears the alert
    /// (Dispatch spec 3.4, 12.2 step 1; design note, decision 4). Raised once for each removed
    /// app, also while its record's deletion keeps failing.
    GrantRevocationOwed {
        /// The removed app.
        app_id: [u8; 16],
    },
    /// The Dispatch took the revocation of this app but gave no time for it, neither in its
    /// answer's proof nor in `GET /apps` (Dispatch wire 7.4.12). The app is cut off at the Dispatch,
    /// but no version removes it yet; each run tries again. A Dispatch that keeps doing this is
    /// faulty, and the user moves to another provider.
    RevocationUnconfirmed {
        /// The app.
        app_id: [u8; 16],
    },
    /// The Dispatch shows this app revoked or departed, which this signer didn't ask for: it
    /// was removed from that time, and its App ID is kept for good (Dispatch spec 12.2, 12.3).
    /// The user checks that the app was meant to go.
    RemovedAtDispatch {
        /// The app.
        app_id: [u8; 16],
        /// Whether the app left on its own, rather than being revoked.
        left: bool,
    },
    /// The Dispatch reported a revocation or departure time for this app before it took this
    /// signer's newest version, which lists the app: its own answer contradicts it, since it
    /// refuses a version listing a revoked or departed App ID (Dispatch wire 3.3). The app is
    /// distrusted only from that version's time, so its earlier messages stand; the Dispatch
    /// may be faulty.
    RemovalTimeBounded {
        /// The app.
        app_id: [u8; 16],
        /// The time the Dispatch reported.
        reported: u64,
        /// The time it was removed from.
        distrust_from: u64,
    },
    /// The Dispatch refused the key bundle answering this app's full-bundle request. The
    /// request isn't tried again until the app asks anew; the other apps' are answered.
    FullBundleRefused {
        /// The app.
        app_id: [u8; 16],
    },
    /// A revocation is asked for and no version removes the app yet: the Dispatch couldn't be
    /// reached or refused it, or the version waits for an alarm to be cleared, and each run
    /// tries again; or a recovery is in progress, when no run sends it and it waits for the
    /// new service to take the recovery's version (Dispatch spec 12.2, 12.6 step 1). The App ID
    /// is refused for good already, and gets no key.
    RevocationPending {
        /// The app.
        app_id: [u8; 16],
        /// Whether the Dispatch took the revocation, so it serves the app no more, while
        /// `identity.json` still lists it. An alert raised with `false` isn't rewritten when a
        /// later send succeeds.
        at_dispatch: bool,
    },
    /// After a restore, the signer backup couldn't be written once its delivery won (Dispatch
    /// wire 3.13). The backup on the Homeserver is the one restored from; the next version's
    /// backup write replaces it.
    BackupNotWritten,
    /// The Dispatch refused to store the hand-over to this app for good (Dispatch wire 7.4.17),
    /// as when it isn't current there. An earlier send may still be stored, so the hand-over
    /// stays in progress: it takes effect if that app takes over, and the user aborts it
    /// otherwise.
    HandOverRefused {
        /// The new signer's App ID.
        to_app: [u8; 16],
    },
    /// The take-over's delivery won, but the vault didn't take the received secret, or didn't
    /// give it back (Dispatch wire 3.12). The take-over keeps the hand-over as received, and
    /// [`crate::Signer::resume`] puts the secret in the vault again; nothing is signed until
    /// then.
    KeyNotInstalled,
    /// The Dispatch refused the take-over's first delivery for good, as with a `400`, a `403`
    /// or a `409 conflict` (Dispatch wire 3.12). The take-over stays undecided and is sent again;
    /// the old signer's abort is the way out.
    TakeOverRefused,
    /// This install took the identity back from `from`, which the user confirmed lost (Dispatch
    /// wire 3.12). If `from` is still around, it holds the key too, and stops as an install
    /// that isn't named; nothing deletes it there.
    TakenBack {
        /// The signer ID the Dispatch's copy named.
        from: [u8; 16],
    },
    /// A restore found the Dispatch or the backup claiming keys sent past the next data
    /// epoch, which can't be: epochs never skip, and at most one is in progress beyond
    /// `data_epoch` (Dispatch spec 3.2, 3.5). The floor is kept at the next epoch.
    EpochFloorBounded {
        /// The highest epoch claimed.
        claimed: u64,
        /// The floor kept.
        kept: u64,
    },
}

impl Alert {
    pub(crate) fn is_signing_alarm(&self) -> bool {
        matches!(self, Self::Rollback { .. } | Self::Equivocation { .. })
    }

    /// Whether this alert is about the app `app_id`: it names that app, as its subject, among
    /// the apps it lists, or as the app a hand-over goes to.
    pub fn names_app(&self, app_id: &[u8; 16]) -> bool {
        match self {
            Self::RotationSkipped { app_id: named, .. }
            | Self::RenewalsStopped { app_id: named, .. }
            | Self::RenewalRefused { app_id: named, .. }
            | Self::LapsingWithOpenAttempts { app_id: named, .. }
            | Self::RevokedWithOpenAttempts { app_id: named, .. }
            | Self::RenewalSkipped { app_id: named, .. }
            | Self::GrantRevocationOwed { app_id: named }
            | Self::RevocationUnconfirmed { app_id: named }
            | Self::RemovedAtDispatch { app_id: named, .. }
            | Self::RemovalTimeBounded { app_id: named, .. }
            | Self::FullBundleRefused { app_id: named }
            | Self::RevocationPending { app_id: named, .. }
            | Self::HandOverRefused { to_app: named } => named == app_id,
            Self::ReductionNotClosed { apps } => apps.contains(app_id),
            Self::Rollback { .. }
            | Self::Equivocation { .. }
            | Self::ManagedByOtherInstall { .. }
            | Self::FirstEnrollmentHeld { .. }
            | Self::BackupUnreadable
            | Self::AdmissionNotEnded
            | Self::UnreadableBackupBeforeEnrollment
            | Self::BackupMissing
            | Self::RecordsBehind { .. }
            | Self::IdentityNearLimit { .. }
            | Self::ClockOff
            | Self::AccountNotHosted
            | Self::ServiceHoldsNoAccount
            | Self::ServiceKeyTaken { .. }
            | Self::ServiceKeyNotFollowed { .. }
            | Self::BackupNotWritten
            | Self::KeyNotInstalled
            | Self::TakeOverRefused
            | Self::TakenBack { .. }
            | Self::EpochFloorBounded { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The alert's sources and its two members that name the service, stored under the
    /// current format's names.
    #[test]
    fn test_alert_stores_the_current_names() {
        assert_eq!(
            serde_json::to_value(Source::Dispatch).unwrap(),
            serde_json::json!("Dispatch")
        );
        let removed = serde_json::to_value(Alert::RemovedAtDispatch {
            app_id: [1; 16],
            left: true,
        })
        .unwrap();
        assert_eq!(
            removed["RemovedAtDispatch"]["left"],
            serde_json::json!(true)
        );
        let pending = serde_json::to_value(Alert::RevocationPending {
            app_id: [1; 16],
            at_dispatch: true,
        })
        .unwrap();
        assert_eq!(
            pending["RevocationPending"]["at_dispatch"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn test_alert_names_the_apps_it_is_about() {
        let (app, other) = ([1; 16], [2; 16]);
        assert!(Alert::GrantRevocationOwed { app_id: app }.names_app(&app));
        assert!(!Alert::GrantRevocationOwed { app_id: app }.names_app(&other));
        let reduction = Alert::ReductionNotClosed {
            apps: vec![other, app],
        };
        assert!(reduction.names_app(&app) && reduction.names_app(&other));
        assert!(Alert::HandOverRefused { to_app: app }.names_app(&app));
        // An alert about the identity names no app, nor does one that names an install.
        assert!(!Alert::BackupMissing.names_app(&app));
        assert!(!Alert::ManagedByOtherInstall { install: app }.names_app(&app));
    }
}
