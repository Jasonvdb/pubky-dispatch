//! The bindings' typed errors. Each names a failure's class and the rule that failed; none
//! carries a secret, a decrypted value or an inner error's text that could hold either.

use pubky_switch_client::store::BatchError;
use pubky_switch_client::{ClientError, StoreError, TransportError};
use pubky_switch_core::chain::ChainError;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_signer::{
    Alert, KeyError, KeyRecoveryStop, ProtocolError, RecordsFault, Refusal, SignerError, SizedBody,
};

/// Retry conditions from the service's error table (Switch spec 6.4).
pub use pubky_switch_core::http::Retry as RetryKind;
/// The state or flow record read by the signer (Switch wire 2.1).
pub use pubky_switch_signer::SignerRecord as RecordKind;

/// Why a signer call failed (Switch spec 4.3).
#[derive(Clone, thiserror::Error, uniffi::Error)]
pub enum SignerFfiError {
    /// The identity key or the host's vault failed (Switch spec 3.1).
    #[error("identity key: {kind:?}")]
    Key {
        /// Which key failure (Switch spec 3.1).
        kind: KeyFailure,
    },
    /// The host passed something the call can't take, such as a secret already used (Switch spec 3.1).
    #[error("invalid input: {reason}")]
    InvalidInput {
        /// The rule the input broke (Switch spec 4.3).
        reason: String,
    },
    /// The bindings' runtime couldn't start, stopped before the call's answer, or had no
    /// thread free in time for the host callbacks the call needs (Switch spec 4.3).
    #[error("the bindings' runtime is unavailable")]
    RuntimeUnavailable,
    /// A failure these bindings don't name yet. A host treats it as the call's failure (Switch spec 4.3).
    #[error("signer failure: {reason}")]
    Unknown {
        /// Its class, never an inner error's text (Switch spec 4.3).
        reason: String,
    },
    /// A signer rule refused the action (Switch spec 4.3).
    #[error("signer refusal: {kind:?}")]
    Refused {
        /// The rule that stopped the action (Switch spec 4.3).
        kind: RefusalKind,
        /// Device time of the first unsigned absence (Switch spec 4.3).
        since_ms: Option<u64>,
        /// The newer identity version (Switch spec 4.3).
        version: Option<u64>,
        /// The 16-byte target App ID (Switch spec 4.3).
        to_app: Option<Vec<u8>>,
        /// The 16-byte successor signer ID (Switch spec 4.3).
        install: Option<Vec<u8>>,
        /// Why key recovery stopped (Switch spec 4.3).
        stop: Option<KeyRecoveryStopKind>,
        /// The clocks, byte sizes or versions compared by the rule (Switch spec 4.3).
        measurements: Option<RefusalMeasurements>,
        /// For a held claim, the rollback or equivocation alert behind it while signer
        /// status still holds it (Switch spec 4.3).
        alert: Option<AlertKind>,
        /// The scopes no registered protocol owns (Switch wire 3.9 step 1).
        scopes: Option<UnownedScopes>,
    },
    /// The registered protocol definitions cannot be used (Switch spec 3.2).
    #[error("protocols: {kind:?}")]
    Protocols {
        /// The failed protocol rule (Switch wire 3.1).
        kind: ProtocolFailure,
    },
    /// Input or a network document failed verification (Switch wire 2.1).
    #[error("invalid signer data: {kind:?}")]
    InvalidData {
        /// Which check failed (Switch wire 2.1).
        kind: CoreFailure,
    },
    /// A service call failed (Switch wire 7.6).
    #[error("service: {kind:?}")]
    Service {
        /// How the call failed (Switch wire 7.1).
        kind: ServiceFailure,
        /// The HTTP status when available (Switch wire 7.1).
        status: Option<u16>,
        /// True for the answers the client always checks with the pinned service key: a
        /// verified error, one given before the body was read (final for nothing) and a stale
        /// signed time. False says nothing either way (Switch wire 7.1).
        authenticated: bool,
        /// The service error code in wire spelling (Switch wire 7.1).
        code: Option<String>,
        /// The service retry interval in seconds, on `429 rate_limited` only (Switch wire 7.6).
        retry_after_s: Option<u64>,
        /// The retry rule for a fully bound error (Switch wire 7.1).
        retry: Option<RetryKind>,
        /// Whether the service confirms it does not host this identity (Switch wire 7.1).
        not_hosted: bool,
        /// The version in a signed `409 identity_needed` answer, on that code only (Switch
        /// wire 7.1).
        known_version: Option<u64>,
        /// The transport failure class (Switch wire 7.1).
        transport: Option<TransportFailure>,
        /// The refused request or response byte limit (Switch wire 7.1).
        limit: Option<u64>,
        /// The generation in the local recovery notice (Switch wire 7.1).
        generation: Option<u64>,
        /// The time of a stale signed read (Switch wire 7.1).
        server_time_ms: Option<u64>,
        /// The typed facts of the failure, where it has some (Switch wire 7.6).
        detail: Option<ServiceDetail>,
    },
    /// Access to the identity's Homeserver failed (Switch spec 4.1).
    #[error("homeserver: {kind:?}")]
    Homeserver {
        /// The transport failure class (Switch wire 7.1).
        kind: TransportFailure,
        /// The byte bound of an oversized response (Switch wire 7.1).
        size: Option<u64>,
        /// The status accompanying an unreadable signed header (Switch wire 7.1).
        status: Option<u16>,
    },
    /// Durable storage failed (Switch wire 2.1).
    #[error("store: {kind:?}")]
    Store {
        /// The store failure class (Switch wire 2.1).
        kind: StoreErrorKind,
        /// The size of the refused write (Switch wire 2.1).
        size: Option<u64>,
        /// The byte limit of the refused write (Switch wire 2.1).
        cap: Option<u64>,
    },
    /// The signer's local records failed a check (Switch wire 2.1).
    #[error("signer records: {kind:?}")]
    Records {
        /// The record failure class (Switch wire 2.1).
        kind: RecordsFailure,
        /// The record the decoder was reading (Switch wire 2.1).
        record: Option<RecordKind>,
        /// The decoder line (Switch wire 2.1).
        line: Option<u64>,
        /// The decoder column (Switch wire 2.1).
        column: Option<u64>,
        /// The write batch rule that failed (Switch wire 2.1).
        write: Option<WriteFailure>,
        /// The measured write size in bytes (Switch wire 2.1).
        size: Option<u64>,
        /// The write limit in bytes (Switch wire 2.1).
        cap: Option<u64>,
    },
    /// A locally stored signed document failed verification (Switch wire 2.1).
    #[error("invalid stored signer data: {kind:?}")]
    StoredData {
        /// Which check failed (Switch wire 2.1).
        kind: CoreFailure,
    },
    /// Another install is named as signer (Switch spec 4.3).
    #[error("another install is named as signer")]
    NotNamed {
        /// The named install's 16-byte signer ID (Switch spec 4.3).
        install: Vec<u8>,
    },
    /// The signer stopped on an alarm. Its alert's details belong to signer status (Switch
    /// spec 4.3).
    #[error("signer alarm: {alert:?}")]
    Alarm {
        /// The alert that stopped it, such as a rollback or an equivocation (Switch spec 4.3).
        alert: AlertKind,
    },
    /// Hand-over took effect and this install deleted its records and key (Switch wire 3.12).
    #[error("identity handed over")]
    HandedOver {
        /// The successor's 16-byte signer ID (Switch wire 3.12).
        install: Vec<u8>,
    },
}

impl std::fmt::Debug for SignerFfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// The identity key's failures (the signer's `KeyError`, Switch spec 3.1). What to do for
/// each: [signer host guide, 2.2 The key vault](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#22-the-key-vault).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum KeyFailure {
    /// The vault holds no identity secret (Switch spec 3.1).
    Missing,
    /// The vault already holds an identity secret, so a new one isn't stored over it (Switch
    /// spec 3.1).
    Occupied,
    /// The secret isn't the identity's: its public key isn't the one expected (Switch spec
    /// 3.1).
    Mismatch,
    /// A secret that isn't 32 bytes (Switch spec 3.1).
    Malformed,
    /// The secure random generator failed (Switch spec 3.1).
    Crypto,
    /// The host's vault failed (Switch spec 3.1).
    Vault,
    /// A key failure this build does not recognize (Switch spec 3.1).
    Unknown,
}

impl From<KeyError> for SignerFfiError {
    fn from(error: KeyError) -> Self {
        // Only the class crosses: a vault's or a crypto library's text stays in Rust.
        let kind = match error {
            KeyError::Missing => KeyFailure::Missing,
            KeyError::Occupied => KeyFailure::Occupied,
            KeyError::Mismatch => KeyFailure::Mismatch,
            KeyError::Malformed => KeyFailure::Malformed,
            KeyError::Crypto(_) => KeyFailure::Crypto,
            KeyError::Vault(_) => KeyFailure::Vault,
            _ => KeyFailure::Unknown,
        };
        Self::Key { kind }
    }
}

/// The scopes no registered protocol owns, in the order they were asked for. They passed the
/// scope rule first, but another app chose them, sub-scope labels included: a host reads them
/// as data, and the error's message and description leave them out (Switch spec 3.3, Switch
/// wire 3.9 step 1).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnownedScopes {
    /// The scope names (Switch wire 3.1).
    pub names: Vec<String>,
}

/// Quantities compared when a signer rule refused an action (Switch spec 4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RefusalMeasurements {
    /// Device and service times disagree (Switch spec 10.1).
    ClockOff {
        /// The device's Unix time in milliseconds (Switch spec 10.1).
        device_ms: u64,
        /// The signed service time in milliseconds (Switch spec 10.1).
        service_ms: u64,
    },
    /// An identity document exceeds a call's cap (Switch wire 3.7).
    IdentityTooLarge {
        /// Which call must carry the document (Switch wire 3.7).
        body: SizedBodyKind,
        /// The measured byte count (Switch wire 7.1).
        bytes: u64,
        /// The permitted byte count (Switch wire 7.1).
        limit: u64,
    },
    /// Recovery saw a version newer than the service's copy (Switch spec 12.8).
    ServiceBehind {
        /// The version held by the service (Switch spec 12.8).
        service_version: u64,
        /// The newest version observed (Switch spec 12.8).
        seen_version: u64,
    },
}

// Keep each public kind beside the source case it represents. A case named otherwise than
// its source gives the source's name after `=`.
macro_rules! failure_kinds {
    ($(#[$doc:meta])* pub enum $kind:ident for $source:ident {
        $($(#[$item:meta])* $case:ident $(= $from:ident)? $(($arg:pat))? $({ $($field:tt)* })?,)*
    }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
        pub enum $kind {
            $($(#[$item])* $case,)*
            /// A failure this build does not recognize (Switch spec 4.3).
            Unknown,
        }

        impl From<&$source> for $kind {
            fn from(error: &$source) -> Self {
                match error {
                    $(source_case!($source; $case $(= $from)?; $(($arg))? $({ $($field)* })?)
                        => Self::$case,)*
                    _ => Self::Unknown,
                }
            }
        }
    };
}

// The source pattern of one case: its own name, or the one given after `=`.
macro_rules! source_case {
    ($source:ident; $case:ident; $($rest:tt)*) => {
        $source::$case $($rest)*
    };
    ($source:ident; $case:ident = $from:ident; $($rest:tt)*) => {
        $source::$from $($rest)*
    };
}

failure_kinds! {
    /// The signer rule that refused an action. Each case gives what the refusal means and
    /// where the signer host guide says what the host does about it (Switch spec 4.3).
    pub enum RefusalKind for Refusal {
        /// The scopes break the Switch's scope rule (Switch spec 3.3, Switch wire 3.1). What to
        /// do: [signer host guide, 2.5 Adding an app](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#25-adding-an-app-approval).
        Scopes(_),
        /// Scopes whose names no registered protocol owns (Switch wire 3.9 step 1). What to do:
        /// [signer host guide, 2.5 Adding an app](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#25-adding-an-app-approval).
        UnknownScopes { .. },
        /// A protocol's own rule on its scopes, or on its grant paths, refused them (Switch spec
        /// 1, 3.4). What to do: [signer host guide, 2.5 Adding an app](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#25-adding-an-app-approval).
        ProtocolRule { .. },
        /// A decline of a path that isn't one the user may decline (Switch spec 3.4, Switch wire
        /// 3.9). What to do: [signer host guide, 2.5 Adding an app](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#25-adding-an-app-approval).
        NotDeclinable { .. },
        /// The app request fails a check of Switch wire 3.9. What to do: [signer host guide,
        /// 2.5 Adding an app](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#25-adding-an-app-approval).
        AppRequest(_),
        /// The effective authority of a previously confirmed app request has changed (Switch
        /// spec 12.1). What to do: [signer host guide, 2.5 Adding an app](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#25-adding-an-app-approval).
        ApprovalChanged,
        /// The app isn't listed in the newest `identity.json`, so it has no certificate to
        /// renew. What to do: [signer host guide, 2.6 Renewal and reductions](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#26-renewal-and-reductions).
        NotListed,
        /// The approval's version is delivered, but its claim is held: the switch isn't
        /// confirmed to hold the signer's newest version since a rollback or an equivocation
        /// (Switch spec 4.3). What to do: [signer host guide, 2.5 Adding an app](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#25-adding-an-app-approval).
        ClaimHeld { .. },
        /// The app hasn't joined: the switch holds no record of it, so it takes no certificate
        /// or bundle for it yet (Switch wire 6.2, Switch spec 12.1 step 2). What to do:
        /// [signer host guide, 2.6 Renewal and reductions](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#26-renewal-and-reductions).
        NotJoined,
        /// The store already holds this identity's signer records, so it isn't set up again.
        /// What to do: [signer host guide, 2.1 First set-up and enrollment](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#21-first-set-up-and-enrollment).
        AlreadySetUp,
        /// This install's records are behind a newer `identity.json` it signed itself, so it
        /// signs nothing until they are restored (Switch wire 3.13). What to do: [signer host
        /// guide, 2.13 Backup and restore](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#213-backup-and-restore).
        RecordsBehind { .. },
        /// That App ID is revoked, being revoked, or seen departing: it gets no new certificate
        /// or key (Switch spec 12.2). What to do: [signer host guide, 2.6 Renewal and reductions](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#26-renewal-and-reductions).
        CutOff,
        /// This install is handing the identity over to the app `to_app`: it signs nothing but
        /// the abort until the hand-over takes effect or is aborted (Switch wire 3.12). What to
        /// do: [signer host guide, 2.12 Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        HandingOver { .. },
        /// The device clock and the switch's signed time differ by more than the clock
        /// tolerance (Switch spec 10.1). What to do: [signer host guide, 2.5 Adding an app](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#25-adding-an-app-approval).
        ClockOff { .. },
        /// The version would be larger than the delivery or the move's enrollment that must
        /// carry it may be (Switch wire 3.7, 7.1). What to do: [signer host guide, 2.5 Adding
        /// an app](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#25-adding-an-app-approval).
        IdentityTooLarge { .. },
        /// No hand-over is in progress to abort. What to do: [signer host guide, 2.12
        /// Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        NotHandingOver,
        /// The identity's account at its switch is erased: nothing more is signed for it
        /// (Switch spec 12.7). What to do: [signer host guide, 2.11 Erasure](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#211-erasure).
        Erased,
        /// The switch refused the erasure (`409 conflict`) while it still holds this install's
        /// mark, as during a move (Switch wire 7.4.16). What to do: [signer host guide, 2.11
        /// Erasure](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#211-erasure).
        ErasureRefused,
        /// No erasure is in progress to abort. What to do: [signer host guide, 2.11 Erasure](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#211-erasure).
        NotErasing,
        /// An erasure request went unanswered, so it may have erased the account (Switch wire
        /// 7.4.16). What to do: [signer host guide, 2.11 Erasure](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#211-erasure).
        ErasureUnanswered,
        /// The account looks erased: a check met an unsigned `404` at `since_ms`, and no answer
        /// the pinned key signs has come since (Switch wire 7.4.16, Switch spec 12.7 step 5).
        /// What to do: [signer host guide, 2.11 Erasure](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#211-erasure).
        ErasureUnconfirmed { .. },
        /// This install is taking the identity over: it signs nothing but its first delivery
        /// until that has won (Switch wire 3.12). What to do: [signer host guide, 2.12
        /// Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        TakingOver,
        /// The target of a hand-over isn't current at the switch with the certificate the
        /// newest `identity.json` lists for it (Switch wire 3.12, 7.4.17). What to do: [signer
        /// host guide, 2.12 Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        TargetNotCurrent,
        /// A revocation is asked for whose version isn't delivered yet: no hand-over until it
        /// is (Switch spec 12.2, Switch wire 3.12). What to do: [signer host guide, 2.12
        /// Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        RevocationOwed,
        /// A reduction's closing delivery is owed: no hand-over until it is made (Switch wire
        /// 3.12). What to do: [signer host guide, 2.12 Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        ClosingOwed,
        /// The switch's copy of `identity.json` isn't the version handed over, or the
        /// Homeserver's is newer or another at its version (Switch wire 3.12). What to do:
        /// [signer host guide, 2.12 Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        StaleHandOver,
        /// The switch holds a newer version naming `install`, but the proof that it holds the
        /// identity isn't there yet (Switch wire 3.12). What to do: [signer host guide, 2.12
        /// Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        SuccessorUnproven { .. },
        /// Nothing to take back: no other install's version follows the one handed over, that
        /// install's proof is there, or no hand-over is in progress (Switch wire 3.12). What to
        /// do: [signer host guide, 2.12 Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        NothingToTakeBack,
        /// The store holds no take-over in progress for this identity. What to do: [signer
        /// host guide, 2.12 Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        NotTakingOver,
        /// The take-over was cancelled: the switch holds a newer version that isn't this
        /// install's first delivery, as after an abort (Switch wire 3.12). What to do: [signer
        /// host guide, 2.12 Hand-over and take-over](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#212-hand-over-to-another-signer-install-and-take-over).
        TakeOverCancelled,
        /// The Homeserver holds no signer backup to restore from (Switch wire 3.13). What to
        /// do: [signer host guide, 2.13 Backup and restore](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#213-backup-and-restore).
        NoBackup,
        /// The signer backup is stale: the switch holds another version than the backup's or
        /// the one it builds on, or the Homeserver a newer one or another at its version (Switch
        /// wire 3.13). What to do: [signer host guide, 2.13 Backup and restore](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#213-backup-and-restore).
        StaleBackup,
        /// A recovery with the identity key alone doesn't go ahead, for the reason `stop` gives;
        /// nothing was signed (Switch spec 12.8). What to do: [signer host guide, 2.13 Backup
        /// and restore](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#213-backup-and-restore),
        /// or for a provider loss, [signer host guide, Provider loss with the identity key](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#provider-loss-with-the-identity-key).
        KeyRecovery(_),
        /// The newest `identity.json` doesn't list that App ID in `removed`. What to do:
        /// [signer host guide, 2.7 Revocation](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#27-revocation).
        NotRemoved,
        /// An alarm's alert was cleared, and the re-delivery that confirms the switch holds
        /// this signer's newest version hasn't succeeded yet (Switch spec 4.3). What to do:
        /// [signer host guide, 2.15 Alarms](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#215-alarms).
        SwitchUnconfirmed,
        /// There is no ordinary recovery that the holder can stop before its version is signed
        /// (Switch spec 12.8). What to do: [signer host guide, 2.13 Backup and restore](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#213-backup-and-restore).
        NoPendingKeyRecovery,
        /// The original first creation cannot be restarted under the same absent account
        /// binding (Switch account binding 3). What to do: [signer host guide, 2.1 First set-up
        /// and enrollment](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#21-first-set-up-and-enrollment).
        FirstEnrollmentUnavailable,
        /// Setup waits at the saved first step until the user addresses its alert (Switch
        /// account binding 3). What to do: [signer host guide, 2.1 First set-up and enrollment](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#21-first-set-up-and-enrollment).
        FirstEnrollmentHeld,
        /// First discovery found an account or its mark before this install signed a creation
        /// (Switch account binding 3, Switch spec 12.8). What to do: [signer host guide, 2.1
        /// First set-up and enrollment](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#21-first-set-up-and-enrollment).
        FirstAccountPresent,
        /// The store holds no signer records for this identity. What to do: [signer host
        /// guide, 2.1 First set-up and enrollment](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#21-first-set-up-and-enrollment).
        NotSetUp,
        /// The Homeserver holds a signer backup this install can't open (Switch wire 3.13).
        /// What to do: at a restore, [signer host guide, 2.13 Backup and restore](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#213-backup-and-restore);
        /// before the first delivery, [signer host guide, 2.1 First set-up and enrollment](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#21-first-set-up-and-enrollment).
        UnreadableBackup,
        /// A flow is in progress, which resuming finishes first (Switch wire 2.1). What to do:
        /// [signer host guide, 2.9 Provider loss and recovery](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#29-provider-loss-and-recovery).
        FlowInProgress,
        /// A provider loss is declared and the new service hasn't taken its version yet:
        /// nothing else is signed meanwhile (Switch spec 12.6 step 1). What to do: [signer host
        /// guide, 2.9 Provider loss and recovery](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#29-provider-loss-and-recovery).
        Recovering,
        /// The Homeserver holds no `identity.json`, which the records don't explain, so a
        /// provider loss isn't declared on this install's records alone (Switch spec 12.6 step
        /// 1). What to do: [signer host guide, 2.9 Provider loss and recovery](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#29-provider-loss-and-recovery).
        HomeserverCopyMissing,
        /// The Homeserver's `identity.json` doesn't verify, which the signer's own steps never
        /// leave (Switch spec 12.6 step 1). What to do: [signer host guide, 2.9 Provider loss
        /// and recovery](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#29-provider-loss-and-recovery).
        HomeserverCopyUnreadable,
        /// The switch holds a newer `identity.json` that this install didn't sign, which it
        /// adopted; the change asked for wasn't made (Switch spec 4.3). What to do: [signer
        /// host guide, 2.6 Renewal and reductions](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#26-renewal-and-reductions).
        Superseded { .. },
    }
}

failure_kinds! {
    /// Why key-only recovery stopped. What to do for each: [signer host guide, 2.13 Backup and
    /// restore](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#213-backup-and-restore)
    /// (Switch spec 12.8).
    pub enum KeyRecoveryStopKind for KeyRecoveryStop {
        /// No copy of `identity.json` the identity key signed was found, so no service is
        /// known to recover at (Switch spec 12.8).
        NoCopy,
        /// The service the newest copy names, or the one the user gave, doesn't serve the
        /// account (Switch spec 12.8).
        NotServing,
        /// The service's copy is missing, doesn't verify, or names another origin or service
        /// key than the one that answered (Switch spec 12.8).
        SwitchCopy,
        /// A copy newer than the service's was seen, and building on the service's would undo
        /// what came after (Switch spec 12.8).
        ServiceBehind { .. },
        /// What the survey shows changed since the user confirmed it (Switch spec 12.8).
        SurveyChanged,
        /// The service's copy carries members this signer doesn't read (Switch spec 12.8).
        UnknownMembers,
    }
}

failure_kinds! {
    /// Which call must carry the identity document (Switch wire 3.7).
    pub enum SizedBodyKind for SizedBody {
        /// The identity delivery (Switch wire 3.7).
        Delivery,
        /// The move's enrollment (Switch wire 3.7).
        Enrollment,
    }
}

failure_kinds! {
    /// The signer alert behind an alarm or a held claim. Its details are in signer status
    /// (Switch spec 4.3).
    pub enum AlertKind for Alert {
        /// First setup is paused at its original step (Switch account binding 3).
        FirstEnrollmentHeld { .. },
        /// A copy of `identity.json` older than the newest one a service accepted from this
        /// signer: a rollback (Switch spec 4.3, Switch wire 3.3).
        Rollback { .. },
        /// Another `identity.json` at the version of the newest one a service accepted from
        /// this signer: equivocation (Switch spec 4.3).
        Equivocation { .. },
        /// Another install is the identity's signer (Switch spec 4.3, 12.8).
        ManagedByOtherInstall { .. },
        /// The signer's backup on the Homeserver didn't open, and the signer wrote its own
        /// over it (Switch wire 3.13).
        BackupUnreadable,
        /// The end of the staged admission a recovery started didn't go through at the new
        /// service (Switch spec 12.6 step 2).
        AdmissionNotEnded,
        /// Before this install's first version was delivered, the Homeserver held a signer
        /// backup it can't open (Switch wire 3.13).
        UnreadableBackupBeforeEnrollment,
        /// The Homeserver held no signer backup, though this signer had written one (Switch
        /// wire 3.13).
        BackupMissing,
        /// The switch or the Homeserver holds a newer `identity.json` that this install signed
        /// itself (Switch wire 3.13).
        RecordsBehind { .. },
        /// A reduction still owes its closing delivery (Switch wire 3.8).
        ReductionNotClosed { .. },
        /// A rotation gave this app no keys for its new data epoch (Switch wire 3.5).
        RotationSkipped { .. },
        /// The signer stopped renewing this app by itself (Switch spec 3.1).
        RenewalsStopped { .. },
        /// This app's renewal didn't happen (Switch spec 3.2).
        RenewalRefused { .. },
        /// An app whose renewals stopped still owns open or `unknown` attempts (Switch spec
        /// 10.2).
        LapsingWithOpenAttempts { .. },
        /// An app being revoked, or revoked, owns open or `unknown` attempts (Switch spec 12.2,
        /// 10.2).
        RevokedWithOpenAttempts { .. },
        /// The signer doesn't renew this app's certificate by itself (Switch spec 3.2).
        RenewalSkipped { .. },
        /// The newest `identity.json` is near the most its body may carry (Switch wire 3.7).
        IdentityNearLimit { .. },
        /// The device clock and the switch's signed time differ by more than the clock
        /// tolerance (Switch spec 10.1).
        ClockOff,
        /// The switch answered with a `404` its pinned key didn't sign (Switch spec 12.5).
        AccountNotHosted,
        /// The switch says, under the pinned key, that it holds no account for the identity
        /// (Switch wire 7.3).
        ServiceHoldsNoAccount,
        /// A provider loss declaration took a new service key (Switch spec 12.5).
        ServiceKeyTaken { .. },
        /// A recovery with the identity key kept the service key its copy names, not the one
        /// the answer named (Switch spec 12.5).
        ServiceKeyNotFollowed { .. },
        /// A removed app's Homeserver grants are the host's to revoke (Switch spec 12.2).
        GrantRevocationOwed { .. },
        /// The switch took a revocation but gave no time for it (Switch wire 7.4.12).
        RevocationUnconfirmed { .. },
        /// The switch shows an app revoked or departed that this signer didn't ask for
        /// (Switch spec 12.2, 12.3).
        RemovedAtSwitch { .. },
        /// The switch reported a removal time before a version that lists the app (Switch
        /// wire 3.3).
        RemovalTimeBounded { .. },
        /// The switch refused the key bundle answering an app's full-bundle request (Switch
        /// wire 3.5).
        FullBundleRefused { .. },
        /// A revocation is asked for and no version removes the app yet (Switch spec 12.2).
        RevocationPending { .. },
        /// After a restore, the signer backup couldn't be written (Switch wire 3.13).
        BackupNotWritten,
        /// The switch refused to store the hand-over for good (Switch wire 7.4.17).
        HandOverRefused { .. },
        /// The take-over's delivery won, but the vault didn't take the received secret (Switch
        /// wire 3.12).
        KeyNotInstalled,
        /// The switch refused the take-over's first delivery for good (Switch wire 3.12).
        TakeOverRefused,
        /// This install took the identity back from an install the user confirmed lost
        /// (Switch wire 3.12).
        TakenBack { .. },
        /// A restore found a claim of keys past the next data epoch and kept the floor at the
        /// next epoch (Switch spec 3.2, 3.5).
        EpochFloorBounded { .. },
    }
}

failure_kinds! {
    /// Why a set of protocol rules cannot be used (Switch wire 3.1).
    pub enum ProtocolFailure for ProtocolError {
        /// The set is empty (Switch wire 3.1).
        NoProtocols,
        /// A protocol name breaks the naming rule (Switch wire 3.1).
        BadName,
        /// A scope belongs to another root (Switch wire 3.1).
        ForeignRoot { .. },
        /// Two protocols have the same name (Switch wire 3.1).
        DuplicateProtocol { .. },
        /// A protocol owns no scopes (Switch wire 3.1).
        NoScopes { .. },
        /// A declared scope name is invalid (Switch wire 3.1).
        BadScopeName { .. },
        /// A scope is declared twice (Switch wire 3.1).
        ScopeClaimedTwice { .. },
        /// A protocol grant path breaks the grant rule (Switch wire 3.1).
        BadGrantPath { .. },
    }
}

failure_kinds! {
    /// Why the signer could not use its local records (Switch wire 2.1).
    pub enum RecordsFailure for RecordsFault {
        /// The state or flow could not be decoded (Switch wire 2.1).
        Undecodable { .. },
        /// The state header is invalid (Switch wire 2.1).
        InvalidHeader,
        /// The namespace holds another identity's state (Switch wire 2.1).
        OtherIdentity,
        /// The flow has no corresponding state (Switch wire 2.1).
        Incomplete,
        /// The saved state breaks a binding (Switch wire 2.1).
        Damaged(_),
        /// The local write batch refused a write (Switch wire 2.1).
        WriteRefused(_),
        /// The records could not be encoded (Switch wire 2.1).
        Encode,
        /// A local invariant failed (Switch wire 2.1).
        Invariant(_),
    }
}

/// Which atomic signer record could not be read (Switch wire 2.1).
#[uniffi::remote(Enum)]
enum RecordKind {
    /// Signer state (Switch wire 2.1).
    State,
    /// The operation saved for retry (Switch wire 2.1).
    Flow,
}

failure_kinds! {
    /// Why a local record write was refused (Switch wire 2.1).
    pub enum WriteFailure for BatchError {
        /// One value exceeds its cap (Switch wire 2.1).
        ValueTooLarge { .. },
        /// The batch exceeds its cap (Switch wire 2.1).
        BatchTooLarge { .. },
        /// The namespace is outside the batch's authority (Switch wire 2.1).
        Namespace,
    }
}

/// What a failed store call guarantees about the write (Switch wire 2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StoreErrorKind {
    /// Another writer owns the namespace (Switch wire 2.1).
    InUse,
    /// The writer lost ownership (Switch wire 2.1).
    NotOwner,
    /// Nothing was applied and the store can be retried (Switch wire 2.1).
    Unavailable,
    /// The writes may or may not have been applied: read the store again before continuing
    /// (Switch wire 2.1).
    Unknown,
    /// The store ran out of space (Switch wire 2.1).
    Full,
    /// A stored value failed validation (Switch wire 2.1).
    Corrupt,
    /// A value or batch exceeds its cap (Switch wire 2.1).
    TooLarge,
    /// Another store failure applied nothing (Switch wire 2.1).
    Other,
    /// A store failure this build does not recognize. Nothing says whether the writes were
    /// applied: read the store again before continuing (Switch wire 2.1).
    Unrecognized,
}

failure_kinds! {
    /// Why a call could not deliver an answer (Switch wire 7.1).
    pub enum TransportFailure for TransportError {
        /// No timely first handoff was established (Switch wire 7.1).
        FirstSendUnavailable,
        /// The first handoff deadline passed (Switch wire 7.1).
        FirstSendExpired,
        /// The connection or access was refused (Switch wire 7.1).
        Refused(_),
        /// No connection was established (Switch wire 7.1).
        Connect(_),
        /// The call timed out (Switch wire 7.1).
        Timeout,
        /// The answer exceeded the byte limit (Switch wire 7.1).
        TooLarge(_),
        /// The request could not be built (Switch wire 7.1).
        InvalidRequest(_),
        /// A signed header could not be read exactly (Switch wire 7.1).
        UnreadableSignedHeader { .. },
        /// Another transport failure (Switch wire 7.1).
        Other(_),
    }
}

failure_kinds! {
    /// What the client learned from the service call (Switch wire 7.1).
    pub enum ServiceFailure for ClientError {
        /// A recovery notice forbids the write (Switch wire 7.1).
        OwnRecoveryRequired { .. },
        /// The owner is awaiting the original response to a signed display read (Switch wire
        /// 7.1).
        DisplayReadPending,
        /// The service answered with an error that the pinned key verified and that binds the
        /// whole request (Switch wire 7.1, 7.6).
        ErrorAnswer = Switch { .. },
        /// The transport failed (Switch wire 7.1).
        Transport(_),
        /// The response status is unauthenticated (Switch wire 7.1).
        BadServiceSignature { .. },
        /// The signed service time was outside the reader's window (Switch wire 7.1).
        StaleAnswer { .. },
        /// A signed error given before the body was read: final for nothing, the call failed
        /// as when no answer comes (Switch wire 7.1).
        BodyUnread { .. },
        /// The request exceeded its byte cap before sending (Switch wire 7.1).
        BodyOverCap { .. },
        /// The call requires a pinned service key (Switch wire 7.1).
        Unpinned,
        /// The answer breaks a wire rule (Switch wire 7.1).
        InvalidResponse(_),
        /// A head or a transition proof failed verification. The key that checked it may not
        /// be the pinned one (Switch wire 6.5, 6.7).
        Chain(_),
        /// A document failed validation (Switch wire 7.1).
        Core(_),
        /// The credentials or arguments do not permit the call (Switch wire 7.1).
        Usage(_),
    }
}

/// The typed facts a service failure carries, beside its kind (Switch wire 7.6).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ServiceDetail {
    /// The chain rule that a stub, a head or a proof broke (Switch wire 6.5 to 6.7).
    Chain {
        /// Which rule (Switch wire 6.6).
        kind: ChainFailure,
        /// The `seq` of the stub, head or checkpoint, where the rule names one (Switch wire
        /// 6.6).
        seq: Option<u64>,
        /// The 16-byte batch ID of a partial, repeated or unfinished batch (Switch wire 6.4,
        /// 6.6).
        batch_id: Option<Vec<u8>>,
    },
    /// The core check a document failed (Switch wire 2.1).
    Core {
        /// Which check (Switch wire 2.1).
        kind: CoreFailure,
    },
    /// The budget a `429 quota_exceeded` names in `current.limit` (Switch wire 9.3).
    Quota {
        /// Which budget is full (Switch wire 9.3).
        budget: QuotaBudget,
        /// For `deny`, how many entries the upload is over by (Switch wire 9.3).
        over: Option<u64>,
    },
    /// The account binding a `409 conflict` reports in `current.binding` (Switch account
    /// binding 3).
    Binding {
        /// What happened to the binding (Switch account binding 3).
        conflict: BindingConflict,
    },
}

/// The chain rule that failed (Switch wire 6.5 to 6.7). Each is evidence of a rollback or a
/// fork, outside a declared provider loss (Switch spec 10.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChainFailure {
    /// A stub, head or proof that doesn't read (Switch wire 6.6).
    Malformed,
    /// A chain version other than 1 (Switch wire 6.6).
    ChainVersion,
    /// The chain hash doesn't follow from the envelope (Switch wire 6.6).
    ChainHash,
    /// The `seq` isn't above the last one (Switch wire 6.6).
    Seq,
    /// The stub doesn't extend the previous chain hash: a gap or a fork (Switch wire 6.6).
    Link,
    /// The generation went back (Switch wire 6.6).
    Generation,
    /// A stub stamped earlier than the previous one (Switch wire 6.6).
    Stamp,
    /// A batch interrupted before its count (Switch wire 6.4).
    PartialBatch,
    /// A batch whose count is 0 (Switch wire 6.6).
    BatchCount,
    /// A batch ID repeats an earlier batch's within 30 days (Switch wire 6.6).
    RepeatedBatchId,
    /// The feed ends inside a batch (Switch wire 7.4.4).
    FeedEndsInBatch,
    /// A head with another chain hash than the chain at its `seq` (Switch wire 6.7).
    Head,
    /// A read that reached the end of the feed didn't reach a head the app has seen (Switch
    /// wire 6.7).
    HeadBeyondFeed,
    /// A full item that doesn't match its stub's type and hash (Switch wire 6.6).
    Item,
    /// A checkpoint that doesn't match the chain, or lies behind an accepted one (Switch wire
    /// 7.4.4).
    Checkpoint,
    /// A transition proof that doesn't bind what it answers (Switch wire 6.5).
    Proof,
    /// A signature of the service key that doesn't verify (Switch wire 6.7).
    Signature,
}

fn chain_facts(error: &ChainError) -> ServiceDetail {
    use ChainFailure as Kind;
    let (kind, seq, batch_id) = match error {
        ChainError::Malformed(_) => (Kind::Malformed, None, None),
        ChainError::ChainVersion { seq } => (Kind::ChainVersion, Some(*seq), None),
        ChainError::ChainHash { seq } => (Kind::ChainHash, Some(*seq), None),
        ChainError::Seq { seq } => (Kind::Seq, Some(*seq), None),
        ChainError::Link { seq } => (Kind::Link, Some(*seq), None),
        ChainError::Generation { seq } => (Kind::Generation, Some(*seq), None),
        ChainError::Stamp { seq } => (Kind::Stamp, Some(*seq), None),
        ChainError::PartialBatch { seq, batch_id } => {
            (Kind::PartialBatch, Some(*seq), Some(batch_id.to_vec()))
        }
        ChainError::BatchCount { seq } => (Kind::BatchCount, Some(*seq), None),
        ChainError::RepeatedBatchId { seq, batch_id } => {
            (Kind::RepeatedBatchId, Some(*seq), Some(batch_id.to_vec()))
        }
        ChainError::FeedEndsInBatch { batch_id } => {
            (Kind::FeedEndsInBatch, None, Some(batch_id.to_vec()))
        }
        ChainError::Head { seq } => (Kind::Head, Some(*seq), None),
        ChainError::HeadBeyondFeed { seq } => (Kind::HeadBeyondFeed, Some(*seq), None),
        ChainError::Item { seq } => (Kind::Item, Some(*seq), None),
        ChainError::Checkpoint { seq } => (Kind::Checkpoint, Some(*seq), None),
        ChainError::Proof(_) => (Kind::Proof, None, None),
        ChainError::Signature(_) => (Kind::Signature, None, None),
    };
    ServiceDetail::Chain {
        kind,
        seq,
        batch_id,
    }
}

/// The class of a core check that failed (Switch wire 2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CoreFailure {
    /// Malformed input, or a document that breaks a rule of the wire format (Switch wire
    /// 2.1).
    Invalid,
    /// A signature didn't verify (Switch wire 2.1).
    Signature,
    /// A sealing, opening or key failure (Switch wire 2.1).
    Crypto,
}

impl From<&pubky_switch_core::Error> for CoreFailure {
    fn from(error: &pubky_switch_core::Error) -> Self {
        match error {
            pubky_switch_core::Error::Invalid(_) => Self::Invalid,
            pubky_switch_core::Error::Signature(_) => Self::Signature,
            pubky_switch_core::Error::Crypto(_) => Self::Crypto,
        }
    }
}

/// The budget a `429 quota_exceeded` names (Switch wire 9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum QuotaBudget {
    /// The recipient's inbox (Switch wire 9.3).
    Inbox,
    /// One sender's share of the inbox (Switch wire 9.3).
    SenderShare,
    /// Record storage (Switch wire 9.3).
    Storage,
    /// Live record keys (Switch wire 9.3).
    RecordKeys,
    /// Claims (Switch wire 9.3).
    Claims,
    /// The claims one app created (Switch wire 9.3).
    ClaimShare,
    /// Attempts (Switch wire 9.3).
    Attempts,
    /// The open attempts one app owns (Switch wire 9.3).
    OpenAttempts,
    /// Kept peers (Switch wire 9.3).
    KeptPeers,
    /// Reply peers (Switch wire 9.3).
    ReplyPeers,
    /// Deny list entries (Switch wire 9.3).
    Deny,
    /// Invite codes (Switch wire 9.3).
    InviteCodes,
    /// Pending connect requests (Switch wire 9.3).
    ConnectRequests,
    /// A budget this build does not recognize (Switch wire 9.3).
    Unknown,
}

impl QuotaBudget {
    fn from_wire(limit: &str) -> Self {
        match limit {
            "inbox" => Self::Inbox,
            "sender_share" => Self::SenderShare,
            "storage" => Self::Storage,
            "record_keys" => Self::RecordKeys,
            "claims" => Self::Claims,
            "claim_share" => Self::ClaimShare,
            "attempts" => Self::Attempts,
            "open_attempts" => Self::OpenAttempts,
            "kept_peers" => Self::KeptPeers,
            "reply_peers" => Self::ReplyPeers,
            "deny" => Self::Deny,
            "invite_codes" => Self::InviteCodes,
            "connect_requests" => Self::ConnectRequests,
            _ => Self::Unknown,
        }
    }
}

/// What a `409 conflict` says happened to the account binding (Switch account binding 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BindingConflict {
    /// The observation the request carried has expired (Switch account binding 3).
    Expired,
    /// Another binding holds: a different key, store, association or creation (Switch
    /// account binding 3).
    Changed,
    /// A binding answer this build does not recognize (Switch account binding 3).
    Unknown,
}

/// When the service's error permits another attempt (Switch spec 6.4).
#[uniffi::remote(Enum)]
enum RetryKind {
    /// Change the request first (Switch spec 6.4).
    No,
    /// Use a fresh timestamp (Switch spec 6.4).
    WithNewTimestamp,
    /// Read the state and recompute (Switch spec 6.4).
    AfterReread,
    /// Fetch the key bundle (Switch spec 6.4).
    AfterKeyBundle,
    /// Sign for the current generation (Switch spec 6.4).
    AfterResigning,
    /// Seal to the current keys (Switch spec 6.4).
    AfterResealing,
    /// Deliver the identity document (Switch spec 6.4).
    AfterDeliveringIdentity,
    /// Use the next service (Switch spec 6.4).
    AtNextService,
    /// Wait for the retry interval (Switch spec 6.4).
    AfterRetryAfter,
    /// Wait for capacity (Switch spec 6.4).
    WhenLimitFrees,
    /// Send the same request (Switch spec 6.4).
    Yes,
    /// Hold the request for the next generation (Switch spec 6.4).
    HeldForNextGeneration,
}

impl From<SignerError> for SignerFfiError {
    fn from(error: SignerError) -> Self {
        match error {
            SignerError::Key(e) => e.into(),
            SignerError::Refused(e) => e.into(),
            SignerError::Protocol(e) => e.into(),
            SignerError::InvalidData(e) => Self::InvalidData { kind: (&e).into() },
            SignerError::Switch(e) => e.into(),
            SignerError::Homeserver(e) => {
                let (kind, size, status) = transport_facts(e);
                Self::Homeserver { kind, size, status }
            }
            SignerError::Store(e) => e.into(),
            SignerError::Records(e) => e.into(),
            SignerError::StoredData(e) => Self::StoredData { kind: (&e).into() },
            SignerError::NotNamed { install } => Self::NotNamed {
                install: install.to_vec(),
            },
            SignerError::Alarm(alert) => Self::Alarm {
                alert: (&alert).into(),
            },
            SignerError::HandedOver { install } => Self::HandedOver {
                install: install.to_vec(),
            },
            _ => Self::Unknown {
                reason: "signer".into(),
            },
        }
    }
}

impl From<Refusal> for SignerFfiError {
    fn from(refusal: Refusal) -> Self {
        use RefusalMeasurements as Measurements;

        let mut since_ms = None;
        let mut version = None;
        let mut to_app = None;
        let mut install = None;
        let mut stop = None;
        let mut measurements = None;
        let mut alert = None;
        let mut scopes = None;
        let kind = RefusalKind::from(&refusal);
        match refusal {
            Refusal::UnknownScopes { scopes: names } => scopes = Some(UnownedScopes { names }),
            Refusal::ClaimHeld { alert: held } => alert = held.as_ref().map(AlertKind::from),
            Refusal::RecordsBehind { version: newer } | Refusal::Superseded { version: newer } => {
                version = Some(newer)
            }
            Refusal::HandingOver { to_app: target } => to_app = Some(target.to_vec()),
            Refusal::SuccessorUnproven { install: successor } => install = Some(successor.to_vec()),
            Refusal::ErasureUnconfirmed { since_ms: since } => since_ms = Some(since),
            Refusal::ClockOff {
                device_ms,
                switch_ms,
            } => {
                measurements = Some(Measurements::ClockOff {
                    device_ms,
                    service_ms: switch_ms,
                });
            }
            Refusal::IdentityTooLarge { body, bytes, limit } => {
                measurements = Some(Measurements::IdentityTooLarge {
                    body: (&body).into(),
                    bytes,
                    limit,
                });
            }
            Refusal::KeyRecovery(why) => {
                stop = Some((&why).into());
                if let KeyRecoveryStop::ServiceBehind {
                    switch_version,
                    seen_version,
                } = why
                {
                    measurements = Some(Measurements::ServiceBehind {
                        service_version: switch_version,
                        seen_version,
                    });
                }
            }
            _ => {}
        }
        Self::Refused {
            kind,
            since_ms,
            version,
            to_app,
            install,
            stop,
            measurements,
            alert,
            scopes,
        }
    }
}

impl From<ProtocolError> for SignerFfiError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocols {
            kind: (&error).into(),
        }
    }
}

impl From<RecordsFault> for SignerFfiError {
    fn from(error: RecordsFault) -> Self {
        let kind = RecordsFailure::from(&error);
        let (record, line, column) = match error {
            RecordsFault::Undecodable {
                record,
                line,
                column,
            } => (
                Some(record),
                u64::try_from(line).ok(),
                u64::try_from(column).ok(),
            ),
            _ => (None, None, None),
        };
        let (write, size, cap) = match error {
            RecordsFault::WriteRefused(batch) => {
                let write = Some(WriteFailure::from(&batch));
                match batch {
                    BatchError::ValueTooLarge { size, cap }
                    | BatchError::BatchTooLarge { size, cap } => (write, Some(size), Some(cap)),
                    _ => (write, None, None),
                }
            }
            _ => (None, None, None),
        };
        Self::Records {
            kind,
            record,
            line,
            column,
            write,
            size,
            cap,
        }
    }
}

impl From<StoreError> for SignerFfiError {
    fn from(error: StoreError) -> Self {
        use StoreErrorKind as Kind;
        let (kind, size, cap) = match error {
            StoreError::InUse => (Kind::InUse, None, None),
            StoreError::NotOwner => (Kind::NotOwner, None, None),
            StoreError::Unavailable => (Kind::Unavailable, None, None),
            StoreError::Unknown => (Kind::Unknown, None, None),
            StoreError::Full => (Kind::Full, None, None),
            StoreError::Corrupt => (Kind::Corrupt, None, None),
            StoreError::Other(_) => (Kind::Other, None, None),
            StoreError::TooLarge { size, cap } => (Kind::TooLarge, Some(size), Some(cap)),
            _ => (Kind::Unrecognized, None, None),
        };
        Self::Store { kind, size, cap }
    }
}

fn transport_facts(error: TransportError) -> (TransportFailure, Option<u64>, Option<u16>) {
    let kind = TransportFailure::from(&error);
    match error {
        TransportError::TooLarge(size) => (kind, Some(size), None),
        TransportError::UnreadableSignedHeader { status } => (kind, None, Some(status)),
        _ => (kind, None, None),
    }
}

/// The typed facts in a verified error answer's `current`, on the codes that define them
/// (Switch wire 9.3, Switch account binding 3).
fn answer_detail(code: ErrorCode, current: &serde_json::Value) -> Option<ServiceDetail> {
    match code {
        ErrorCode::QuotaExceeded => {
            let limit = current.get("limit")?.as_str()?;
            let budget = QuotaBudget::from_wire(limit);
            // As the core reads it: only a positive count is one (Switch wire 9.3).
            let over = match budget {
                QuotaBudget::Deny => current
                    .get("over")
                    .and_then(serde_json::Value::as_u64)
                    .filter(|over| *over > 0),
                _ => None,
            };
            Some(ServiceDetail::Quota { budget, over })
        }
        ErrorCode::Conflict => {
            // A binding answer is the whole `current`, as the signer reads it: with another
            // member beside it, there is none.
            if current.as_object()?.len() != 1 {
                return None;
            }
            let binding = match current.get("binding")?.as_str()? {
                "expired" => BindingConflict::Expired,
                "changed" => BindingConflict::Changed,
                _ => BindingConflict::Unknown,
            };
            Some(ServiceDetail::Binding { conflict: binding })
        }
        _ => None,
    }
}

impl From<ClientError> for SignerFfiError {
    fn from(error: ClientError) -> Self {
        let retry = error.retry();
        let not_hosted = error.is_not_hosted();
        let kind = ServiceFailure::from(&error);
        // Only answers the client checks with the pinned key count. A chain failure doesn't:
        // a key the answer brought may have checked it before any key was pinned.
        let authenticated = matches!(
            kind,
            ServiceFailure::ErrorAnswer | ServiceFailure::BodyUnread | ServiceFailure::StaleAnswer
        );
        let mut status = None;
        let mut code = None;
        let mut retry_after_s = None;
        let mut known_version = None;
        let mut transport = None;
        let mut limit = None;
        let mut generation = None;
        let mut server_time_ms = None;
        let mut detail = None;
        match error {
            ClientError::OwnRecoveryRequired {
                generation: stopped,
            } => generation = Some(stopped),
            ClientError::Switch {
                status: http,
                code: wire,
                current,
                known_version: version,
                retry_after,
                ..
            } => {
                status = Some(http);
                code = Some(wire.as_str().to_owned());
                // Each hint is read only on the code that defines it (Switch wire 7.1, 7.6).
                retry_after_s = retry_after.filter(|_| wire == ErrorCode::RateLimited);
                known_version = version.filter(|_| wire == ErrorCode::IdentityNeeded);
                detail = answer_detail(wire, &current);
            }
            ClientError::BodyUnread {
                status: http,
                code: wire,
                retry_after,
            } => {
                status = Some(http);
                code = Some(wire.as_str().to_owned());
                retry_after_s = retry_after.filter(|_| wire == ErrorCode::RateLimited);
            }
            ClientError::Transport(e) => {
                let (kind, bytes, http) = transport_facts(e);
                transport = Some(kind);
                limit = bytes;
                status = http;
            }
            ClientError::BadServiceSignature { status: http } => status = Some(http),
            ClientError::StaleAnswer {
                server_time_ms: time,
            } => server_time_ms = Some(time),
            ClientError::BodyOverCap { cap } => limit = u64::try_from(cap).ok(),
            ClientError::Chain(e) => detail = Some(chain_facts(&e)),
            ClientError::Core(e) => detail = Some(ServiceDetail::Core { kind: (&e).into() }),
            _ => {}
        }
        Self::Service {
            kind,
            status,
            authenticated,
            code,
            retry_after_s,
            retry,
            not_hosted,
            known_version,
            transport,
            limit,
            generation,
            server_time_ms,
            detail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_key_failure_keeps_its_class() {
        let error = SignerFfiError::from(KeyError::Malformed);
        assert!(matches!(
            error,
            SignerFfiError::Key {
                kind: KeyFailure::Malformed
            }
        ));
        assert_eq!(error.to_string(), "identity key: Malformed");
    }

    #[test]
    fn test_error_crypto_text_stays_in_rust() {
        let error = SignerFfiError::from(KeyError::Crypto("inner text".to_owned()));
        assert!(matches!(
            error,
            SignerFfiError::Key {
                kind: KeyFailure::Crypto
            }
        ));
        assert!(!error.to_string().contains("inner text"));
        assert!(!format!("{error:?}").contains("inner text"));
    }

    use pubky_switch_core::http::not_hosted_current;
    use pubky_switch_signer::{SignerRecord, Source};

    // Text that must never cross the binding, and a 16-byte ID.
    const MARK: &str = "sentinel-inner-text";
    const ID: [u8; 16] = *b"sentinel-id-0001";

    fn checked(source: SignerError) -> SignerFfiError {
        let error = SignerFfiError::from(source);
        assert!(!error.to_string().contains(MARK));
        assert!(!format!("{error:?}").contains(MARK));
        error
    }

    fn rollback() -> Alert {
        Alert::Rollback {
            source: Source::Switch,
            version: Some(4),
            generation: Some(1),
            high_water_version: 5,
        }
    }

    fn equivocation() -> Alert {
        Alert::Equivocation {
            source: Source::Homeserver,
            version: 5,
        }
    }

    #[test]
    fn test_error_key() {
        for (source, expected) in [
            (
                KeyError::Vault(pubky_switch_signer::VaultError(MARK.into())),
                KeyFailure::Vault,
            ),
            (KeyError::Missing, KeyFailure::Missing),
            (KeyError::Occupied, KeyFailure::Occupied),
            (KeyError::Mismatch, KeyFailure::Mismatch),
            (KeyError::Malformed, KeyFailure::Malformed),
            (KeyError::Crypto(MARK.into()), KeyFailure::Crypto),
        ] {
            assert!(
                matches!(checked(SignerError::Key(source)), SignerFfiError::Key { kind } if kind == expected)
            );
        }
    }

    #[derive(Debug, Default, PartialEq)]
    struct Facts {
        since_ms: Option<u64>,
        version: Option<u64>,
        to_app: Option<Vec<u8>>,
        install: Option<Vec<u8>>,
        stop: Option<KeyRecoveryStopKind>,
        measurements: Option<RefusalMeasurements>,
        alert: Option<AlertKind>,
        scopes: Option<UnownedScopes>,
    }

    fn check_refusal(source: Refusal, expected: RefusalKind, facts: Facts) {
        let SignerFfiError::Refused {
            kind,
            since_ms,
            version,
            to_app,
            install,
            stop,
            measurements,
            alert,
            scopes,
        } = checked(source.into())
        else {
            panic!("expected a signer refusal")
        };
        assert_eq!(kind, expected);
        assert_eq!(
            Facts {
                since_ms,
                version,
                to_app,
                install,
                stop,
                measurements,
                alert,
                scopes,
            },
            facts
        );
    }

    #[test]
    fn test_error_refused() {
        use Refusal as R;
        use RefusalKind as K;
        for (source, kind) in [
            (R::Scopes(MARK.into()), K::Scopes),
            (
                R::ProtocolRule {
                    protocol: MARK.into(),
                    reason: MARK.into(),
                },
                K::ProtocolRule,
            ),
            (R::NotDeclinable { path: MARK.into() }, K::NotDeclinable),
            (R::AppRequest(MARK.into()), K::AppRequest),
            (R::ApprovalChanged, K::ApprovalChanged),
            (R::NotListed, K::NotListed),
            (R::NotJoined, K::NotJoined),
            (R::AlreadySetUp, K::AlreadySetUp),
            (R::CutOff, K::CutOff),
            (R::NotHandingOver, K::NotHandingOver),
            (R::Erased, K::Erased),
            (R::ErasureRefused, K::ErasureRefused),
            (R::NotErasing, K::NotErasing),
            (R::ErasureUnanswered, K::ErasureUnanswered),
            (R::TakingOver, K::TakingOver),
            (R::TargetNotCurrent, K::TargetNotCurrent),
            (R::RevocationOwed, K::RevocationOwed),
            (R::ClosingOwed, K::ClosingOwed),
            (R::StaleHandOver, K::StaleHandOver),
            (R::NothingToTakeBack, K::NothingToTakeBack),
            (R::NotTakingOver, K::NotTakingOver),
            (R::TakeOverCancelled, K::TakeOverCancelled),
            (R::NoBackup, K::NoBackup),
            (R::StaleBackup, K::StaleBackup),
            (R::NotRemoved, K::NotRemoved),
            (R::SwitchUnconfirmed, K::SwitchUnconfirmed),
            (R::NoPendingKeyRecovery, K::NoPendingKeyRecovery),
            (R::FirstEnrollmentUnavailable, K::FirstEnrollmentUnavailable),
            (R::FirstEnrollmentHeld, K::FirstEnrollmentHeld),
            (R::FirstAccountPresent, K::FirstAccountPresent),
            (R::NotSetUp, K::NotSetUp),
            (R::UnreadableBackup, K::UnreadableBackup),
            (R::FlowInProgress, K::FlowInProgress),
            (R::Recovering, K::Recovering),
            (R::HomeserverCopyMissing, K::HomeserverCopyMissing),
            (R::HomeserverCopyUnreadable, K::HomeserverCopyUnreadable),
            (R::ClaimHeld { alert: None }, K::ClaimHeld),
        ] {
            check_refusal(source, kind, Facts::default());
        }
        // Scopes that passed the scope rule cross in the order they were asked for.
        check_refusal(
            R::UnknownScopes {
                scopes: vec!["tasks".into(), "notes:shared".into()],
            },
            K::UnknownScopes,
            Facts {
                scopes: Some(UnownedScopes {
                    names: vec!["tasks".into(), "notes:shared".into()],
                }),
                ..Default::default()
            },
        );
        // A held claim tells a rollback from an equivocation.
        for (held, kind) in [
            (rollback(), AlertKind::Rollback),
            (equivocation(), AlertKind::Equivocation),
        ] {
            check_refusal(
                R::ClaimHeld { alert: Some(held) },
                K::ClaimHeld,
                Facts {
                    alert: Some(kind),
                    ..Default::default()
                },
            );
        }
        check_refusal(
            R::RecordsBehind { version: 11 },
            K::RecordsBehind,
            Facts {
                version: Some(11),
                ..Default::default()
            },
        );
        check_refusal(
            R::HandingOver { to_app: ID },
            K::HandingOver,
            Facts {
                to_app: Some(ID.to_vec()),
                ..Default::default()
            },
        );
        check_refusal(
            R::ClockOff {
                device_ms: 12,
                switch_ms: 19,
            },
            K::ClockOff,
            Facts {
                measurements: Some(RefusalMeasurements::ClockOff {
                    device_ms: 12,
                    service_ms: 19,
                }),
                ..Default::default()
            },
        );
        for (body, kind) in [
            (SizedBody::Delivery, SizedBodyKind::Delivery),
            (SizedBody::Enrollment, SizedBodyKind::Enrollment),
        ] {
            check_refusal(
                R::IdentityTooLarge {
                    body,
                    bytes: 44,
                    limit: 43,
                },
                K::IdentityTooLarge,
                Facts {
                    measurements: Some(RefusalMeasurements::IdentityTooLarge {
                        body: kind,
                        bytes: 44,
                        limit: 43,
                    }),
                    ..Default::default()
                },
            );
        }
        check_refusal(
            R::ErasureUnconfirmed { since_ms: 73 },
            K::ErasureUnconfirmed,
            Facts {
                since_ms: Some(73),
                ..Default::default()
            },
        );
        check_refusal(
            R::SuccessorUnproven { install: ID },
            K::SuccessorUnproven,
            Facts {
                install: Some(ID.to_vec()),
                ..Default::default()
            },
        );
        for (why, kind) in [
            (KeyRecoveryStop::NoCopy, KeyRecoveryStopKind::NoCopy),
            (KeyRecoveryStop::NotServing, KeyRecoveryStopKind::NotServing),
            (KeyRecoveryStop::SwitchCopy, KeyRecoveryStopKind::SwitchCopy),
            (
                KeyRecoveryStop::SurveyChanged,
                KeyRecoveryStopKind::SurveyChanged,
            ),
            (
                KeyRecoveryStop::UnknownMembers,
                KeyRecoveryStopKind::UnknownMembers,
            ),
        ] {
            check_refusal(
                R::KeyRecovery(why),
                K::KeyRecovery,
                Facts {
                    stop: Some(kind),
                    ..Default::default()
                },
            );
        }
        check_refusal(
            R::KeyRecovery(KeyRecoveryStop::ServiceBehind {
                switch_version: 4,
                seen_version: 8,
            }),
            K::KeyRecovery,
            Facts {
                stop: Some(KeyRecoveryStopKind::ServiceBehind),
                measurements: Some(RefusalMeasurements::ServiceBehind {
                    service_version: 4,
                    seen_version: 8,
                }),
                ..Default::default()
            },
        );
        check_refusal(
            R::Superseded { version: 17 },
            K::Superseded,
            Facts {
                version: Some(17),
                ..Default::default()
            },
        );
    }

    #[test]
    fn test_error_protocol() {
        use ProtocolError as P;
        for (source, expected) in [
            (P::NoProtocols, ProtocolFailure::NoProtocols),
            (P::BadName, ProtocolFailure::BadName),
            (
                P::ForeignRoot {
                    protocol: MARK.into(),
                    scope: MARK.into(),
                },
                ProtocolFailure::ForeignRoot,
            ),
            (
                P::DuplicateProtocol { name: MARK.into() },
                ProtocolFailure::DuplicateProtocol,
            ),
            (
                P::NoScopes {
                    protocol: MARK.into(),
                },
                ProtocolFailure::NoScopes,
            ),
            (
                P::BadScopeName {
                    protocol: MARK.into(),
                },
                ProtocolFailure::BadScopeName,
            ),
            (
                P::ScopeClaimedTwice {
                    scope: MARK.into(),
                    first: MARK.into(),
                    second: MARK.into(),
                },
                ProtocolFailure::ScopeClaimedTwice,
            ),
            (
                P::BadGrantPath {
                    protocol: MARK.into(),
                    rule: MARK,
                },
                ProtocolFailure::BadGrantPath,
            ),
        ] {
            assert!(
                matches!(checked(source.into()), SignerFfiError::Protocols { kind } if kind == expected)
            );
        }
    }

    fn core_errors() -> [(pubky_switch_core::Error, CoreFailure); 3] {
        use pubky_switch_core::Error as E;
        [
            (E::Invalid(MARK.into()), CoreFailure::Invalid),
            (E::Signature(MARK.into()), CoreFailure::Signature),
            (E::Crypto(MARK.into()), CoreFailure::Crypto),
        ]
    }

    #[test]
    fn test_error_invalid_data() {
        for (source, expected) in core_errors() {
            assert!(
                matches!(checked(SignerError::InvalidData(source)), SignerFfiError::InvalidData { kind } if kind == expected)
            );
        }
    }

    fn answer(code: ErrorCode, current: serde_json::Value) -> ClientError {
        ClientError::Switch {
            status: code.status(),
            code,
            message: MARK.into(),
            current,
            known_version: Some(81),
            retry_after: Some(23),
        }
    }

    #[test]
    fn test_error_service_answer() {
        // Every code crosses in its own wire spelling, as a verified, fully bound answer.
        for wire in ErrorCode::ALL {
            let SignerFfiError::Service {
                kind,
                status,
                authenticated,
                code,
                retry,
                ..
            } = checked(answer(wire, serde_json::Value::Null).into())
            else {
                panic!("expected a service failure")
            };
            assert_eq!(kind, ServiceFailure::ErrorAnswer);
            assert_eq!(status, Some(wire.status()));
            assert!(authenticated);
            assert_eq!(code.as_deref(), Some(wire.as_str()));
            assert_eq!(retry, Some(wire.retry()));
        }
        assert!(matches!(
            checked(answer(ErrorCode::RateLimited, serde_json::json!({"detail": MARK})).into()),
            SignerFfiError::Service {
                retry_after_s: Some(23),
                retry: Some(RetryKind::AfterRetryAfter),
                known_version: None,
                not_hosted: false,
                transport: None,
                detail: None,
                ..
            }
        ));
        assert!(matches!(
            checked(answer(ErrorCode::IdentityNeeded, serde_json::Value::Null).into()),
            SignerFfiError::Service {
                known_version: Some(81),
                retry_after_s: None,
                ..
            }
        ));
        // A hint on a code that doesn't define it doesn't cross.
        assert!(matches!(
            checked(answer(ErrorCode::Unavailable, serde_json::Value::Null).into()),
            SignerFfiError::Service {
                known_version: None,
                retry_after_s: None,
                ..
            }
        ));
    }

    #[test]
    fn test_error_service_not_hosted() {
        let missing = ClientError::Switch {
            status: 404,
            code: ErrorCode::NotFound,
            message: MARK.into(),
            current: not_hosted_current(),
            known_version: None,
            retry_after: None,
        };
        assert!(
            matches!(checked(missing.into()), SignerFfiError::Service { kind: ServiceFailure::ErrorAnswer, not_hosted: true, authenticated: true, status: Some(404), code: Some(code), .. } if code == "not_found")
        );
        let other = answer(ErrorCode::NotFound, serde_json::Value::Null);
        assert!(matches!(
            checked(other.into()),
            SignerFfiError::Service {
                not_hosted: false,
                ..
            }
        ));
    }

    #[test]
    fn test_error_service_answer_detail() {
        use serde_json::json;
        for (limit, budget) in [
            ("inbox", QuotaBudget::Inbox),
            ("sender_share", QuotaBudget::SenderShare),
            ("storage", QuotaBudget::Storage),
            ("record_keys", QuotaBudget::RecordKeys),
            ("claims", QuotaBudget::Claims),
            ("claim_share", QuotaBudget::ClaimShare),
            ("attempts", QuotaBudget::Attempts),
            ("open_attempts", QuotaBudget::OpenAttempts),
            ("kept_peers", QuotaBudget::KeptPeers),
            ("reply_peers", QuotaBudget::ReplyPeers),
            ("invite_codes", QuotaBudget::InviteCodes),
            ("connect_requests", QuotaBudget::ConnectRequests),
            (MARK, QuotaBudget::Unknown),
        ] {
            let error = answer(
                ErrorCode::QuotaExceeded,
                json!({ "limit": limit, "over": 3 }),
            );
            assert!(
                matches!(checked(error.into()), SignerFfiError::Service { detail: Some(ServiceDetail::Quota { budget: full, over: None }), .. } if full == budget)
            );
        }
        let deny = answer(
            ErrorCode::QuotaExceeded,
            json!({ "limit": "deny", "over": 3 }),
        );
        assert!(matches!(
            checked(deny.into()),
            SignerFfiError::Service {
                detail: Some(ServiceDetail::Quota {
                    budget: QuotaBudget::Deny,
                    over: Some(3)
                }),
                ..
            }
        ));
        // As the core reads it, a count of 0 is none.
        let none_over = answer(
            ErrorCode::QuotaExceeded,
            json!({ "limit": "deny", "over": 0 }),
        );
        assert!(matches!(
            checked(none_over.into()),
            SignerFfiError::Service {
                detail: Some(ServiceDetail::Quota {
                    budget: QuotaBudget::Deny,
                    over: None
                }),
                ..
            }
        ));
        for (binding, expected) in [
            ("expired", BindingConflict::Expired),
            ("changed", BindingConflict::Changed),
            (MARK, BindingConflict::Unknown),
        ] {
            let error = answer(ErrorCode::Conflict, json!({ "binding": binding }));
            assert!(
                matches!(checked(error.into()), SignerFfiError::Service { detail: Some(ServiceDetail::Binding { conflict: found }), .. } if found == expected)
            );
            // With another member beside it, the signer reads no binding answer.
            let error = answer(
                ErrorCode::Conflict,
                json!({ "binding": binding, "extra": 1 }),
            );
            assert!(matches!(
                checked(error.into()),
                SignerFfiError::Service { detail: None, .. }
            ));
        }
        // The facts are read only on the code that defines them.
        for error in [
            answer(ErrorCode::Conflict, json!({ "limit": "claims" })),
            answer(ErrorCode::QuotaExceeded, json!({ "binding": "expired" })),
            answer(ErrorCode::BadRequest, json!({ "limit": "claims" })),
            answer(ErrorCode::Conflict, json!({ "binding": 7 })),
        ] {
            assert!(matches!(
                checked(error.into()),
                SignerFfiError::Service { detail: None, .. }
            ));
        }
    }

    #[test]
    fn test_error_service_unbound() {
        let partial = ClientError::BodyUnread {
            status: 429,
            code: ErrorCode::RateLimited,
            retry_after: Some(7),
        };
        assert!(
            matches!(checked(partial.into()), SignerFfiError::Service { kind: ServiceFailure::BodyUnread, authenticated: true, status: Some(429), code: Some(code), retry_after_s: Some(7), retry: None, not_hosted: false, .. } if code == "rate_limited")
        );
        let early = ClientError::BodyUnread {
            status: 413,
            code: ErrorCode::TooLarge,
            retry_after: Some(7),
        };
        assert!(
            matches!(checked(early.into()), SignerFfiError::Service { kind: ServiceFailure::BodyUnread, code: Some(code), retry_after_s: None, .. } if code == "too_large")
        );
        assert!(matches!(
            checked(ClientError::BadServiceSignature { status: 404 }.into()),
            SignerFfiError::Service {
                kind: ServiceFailure::BadServiceSignature,
                authenticated: false,
                status: Some(404),
                code: None,
                retry: None,
                not_hosted: false,
                ..
            }
        ));
        assert!(matches!(
            checked(ClientError::Transport(TransportError::TooLarge(91)).into()),
            SignerFfiError::Service {
                kind: ServiceFailure::Transport,
                authenticated: false,
                code: None,
                transport: Some(TransportFailure::TooLarge),
                limit: Some(91),
                ..
            }
        ));
        assert!(matches!(
            checked(
                ClientError::Transport(TransportError::UnreadableSignedHeader { status: 502 })
                    .into()
            ),
            SignerFfiError::Service {
                kind: ServiceFailure::Transport,
                authenticated: false,
                status: Some(502),
                transport: Some(TransportFailure::UnreadableSignedHeader),
                limit: None,
                ..
            }
        ));
        assert!(matches!(
            checked(ClientError::BodyOverCap { cap: 92 }.into()),
            SignerFfiError::Service {
                kind: ServiceFailure::BodyOverCap,
                authenticated: false,
                limit: Some(92),
                ..
            }
        ));
        assert!(matches!(
            checked(ClientError::StaleAnswer { server_time_ms: 93 }.into()),
            SignerFfiError::Service {
                kind: ServiceFailure::StaleAnswer,
                authenticated: true,
                server_time_ms: Some(93),
                ..
            }
        ));
        assert!(matches!(
            checked(ClientError::OwnRecoveryRequired { generation: 94 }.into()),
            SignerFfiError::Service {
                kind: ServiceFailure::OwnRecoveryRequired,
                authenticated: false,
                generation: Some(94),
                ..
            }
        ));
        for (source, expected) in [
            (ClientError::Usage(MARK.into()), ServiceFailure::Usage),
            (ClientError::Unpinned, ServiceFailure::Unpinned),
            (
                ClientError::DisplayReadPending,
                ServiceFailure::DisplayReadPending,
            ),
            // A response that doesn't read may come from a call made without a pinned key,
            // such as the first discovery.
            (
                ClientError::InvalidResponse(MARK.into()),
                ServiceFailure::InvalidResponse,
            ),
        ] {
            assert!(
                matches!(checked(source.into()), SignerFfiError::Service { kind, authenticated: false, code: None, retry: None, detail: None, .. } if kind == expected)
            );
        }
    }

    #[test]
    fn test_error_service_core() {
        for (source, expected) in core_errors() {
            assert!(
                matches!(checked(ClientError::Core(source).into()), SignerFfiError::Service { kind: ServiceFailure::Core, authenticated: false, detail: Some(ServiceDetail::Core { kind }), .. } if kind == expected)
            );
        }
    }

    #[test]
    fn test_error_service_chain() {
        use ChainError as C;
        use ChainFailure as F;
        let batch = Some(ID.to_vec());
        for (source, expected, seq, batch_id) in [
            (C::Malformed(MARK.into()), F::Malformed, None, None),
            (C::ChainVersion { seq: 1 }, F::ChainVersion, Some(1), None),
            (C::ChainHash { seq: 2 }, F::ChainHash, Some(2), None),
            (C::Seq { seq: 3 }, F::Seq, Some(3), None),
            (C::Link { seq: 4 }, F::Link, Some(4), None),
            (C::Generation { seq: 5 }, F::Generation, Some(5), None),
            (C::Stamp { seq: 6 }, F::Stamp, Some(6), None),
            (
                C::PartialBatch {
                    seq: 7,
                    batch_id: ID,
                },
                F::PartialBatch,
                Some(7),
                batch.clone(),
            ),
            (C::BatchCount { seq: 8 }, F::BatchCount, Some(8), None),
            (
                C::RepeatedBatchId {
                    seq: 9,
                    batch_id: ID,
                },
                F::RepeatedBatchId,
                Some(9),
                batch.clone(),
            ),
            (
                C::FeedEndsInBatch { batch_id: ID },
                F::FeedEndsInBatch,
                None,
                batch.clone(),
            ),
            (C::Head { seq: 10 }, F::Head, Some(10), None),
            (
                C::HeadBeyondFeed { seq: 11 },
                F::HeadBeyondFeed,
                Some(11),
                None,
            ),
            (C::Item { seq: 12 }, F::Item, Some(12), None),
            (C::Checkpoint { seq: 13 }, F::Checkpoint, Some(13), None),
            (C::Proof(MARK.into()), F::Proof, None, None),
            (C::Signature(MARK.into()), F::Signature, None, None),
        ] {
            let error = checked(ClientError::Chain(source).into());
            let SignerFfiError::Service {
                kind: ServiceFailure::Chain,
                authenticated,
                detail: Some(detail),
                ..
            } = error
            else {
                panic!("expected a chain failure")
            };
            // The key that checked the chain may not be the pinned one.
            assert!(!authenticated);
            assert_eq!(
                detail,
                ServiceDetail::Chain {
                    kind: expected,
                    seq,
                    batch_id
                }
            );
        }
    }

    #[test]
    fn test_error_homeserver() {
        use TransportError as T;
        for (source, expected) in [
            (
                T::FirstSendUnavailable,
                TransportFailure::FirstSendUnavailable,
            ),
            (T::FirstSendExpired, TransportFailure::FirstSendExpired),
            (T::Refused(MARK.into()), TransportFailure::Refused),
            (T::Connect(MARK.into()), TransportFailure::Connect),
            (T::Timeout, TransportFailure::Timeout),
            (
                T::InvalidRequest(MARK.into()),
                TransportFailure::InvalidRequest,
            ),
            (T::Other(MARK.into()), TransportFailure::Other),
        ] {
            assert!(
                matches!(checked(SignerError::Homeserver(source)), SignerFfiError::Homeserver { kind, size: None, status: None } if kind == expected)
            );
        }
        assert!(matches!(
            checked(SignerError::Homeserver(T::TooLarge(16))),
            SignerFfiError::Homeserver {
                kind: TransportFailure::TooLarge,
                size: Some(16),
                status: None
            }
        ));
        assert!(matches!(
            checked(SignerError::Homeserver(T::UnreadableSignedHeader {
                status: 503
            })),
            SignerFfiError::Homeserver {
                kind: TransportFailure::UnreadableSignedHeader,
                size: None,
                status: Some(503)
            }
        ));
    }

    #[test]
    fn test_error_store() {
        for (source, expected) in [
            (StoreError::InUse, StoreErrorKind::InUse),
            (StoreError::NotOwner, StoreErrorKind::NotOwner),
            (StoreError::Unavailable, StoreErrorKind::Unavailable),
            (StoreError::Unknown, StoreErrorKind::Unknown),
            (StoreError::Full, StoreErrorKind::Full),
            (StoreError::Corrupt, StoreErrorKind::Corrupt),
            (StoreError::Other(MARK.into()), StoreErrorKind::Other),
        ] {
            assert!(
                matches!(checked(source.into()), SignerFfiError::Store { kind, size: None, cap: None } if kind == expected)
            );
        }
        assert!(matches!(
            checked(StoreError::TooLarge { size: 52, cap: 51 }.into()),
            SignerFfiError::Store {
                kind: StoreErrorKind::TooLarge,
                size: Some(52),
                cap: Some(51)
            }
        ));
    }

    #[test]
    fn test_error_records() {
        for (source, expected) in [
            (RecordsFault::InvalidHeader, RecordsFailure::InvalidHeader),
            (RecordsFault::OtherIdentity, RecordsFailure::OtherIdentity),
            (RecordsFault::Incomplete, RecordsFailure::Incomplete),
            (RecordsFault::Damaged(MARK), RecordsFailure::Damaged),
            (RecordsFault::Encode, RecordsFailure::Encode),
            (RecordsFault::Invariant(MARK), RecordsFailure::Invariant),
        ] {
            assert!(
                matches!(checked(source.into()), SignerFfiError::Records { kind, record: None, line: None, column: None, write: None, size: None, cap: None } if kind == expected)
            );
        }
        for (record, expected) in [
            (SignerRecord::State, RecordKind::State),
            (SignerRecord::Flow, RecordKind::Flow),
        ] {
            let source = RecordsFault::Undecodable {
                record,
                line: 8,
                column: 9,
            };
            assert!(
                matches!(checked(source.into()), SignerFfiError::Records { kind: RecordsFailure::Undecodable, record: Some(which), line: Some(8), column: Some(9), write: None, size: None, cap: None } if which == expected)
            );
        }
        for (batch, expected, bytes) in [
            (
                BatchError::ValueTooLarge { size: 8, cap: 6 },
                WriteFailure::ValueTooLarge,
                Some((8, 6)),
            ),
            (
                BatchError::BatchTooLarge { size: 9, cap: 7 },
                WriteFailure::BatchTooLarge,
                Some((9, 7)),
            ),
            (BatchError::Namespace, WriteFailure::Namespace, None),
        ] {
            assert!(
                matches!(checked(RecordsFault::WriteRefused(batch).into()), SignerFfiError::Records { kind: RecordsFailure::WriteRefused, write: Some(which), size, cap, .. } if which == expected && size == bytes.map(|v| v.0) && cap == bytes.map(|v| v.1))
            );
        }
    }

    #[test]
    fn test_error_stored_data() {
        for (source, expected) in core_errors() {
            assert!(
                matches!(checked(SignerError::StoredData(source)), SignerFfiError::StoredData { kind } if kind == expected)
            );
        }
    }

    #[test]
    fn test_error_not_named() {
        assert!(
            matches!(checked(SignerError::NotNamed { install: ID }), SignerFfiError::NotNamed { install } if install == ID)
        );
    }

    #[test]
    fn test_error_alarm() {
        use AlertKind as K;
        use pubky_switch_signer::{FirstEnrollmentStop, RenewalSkip};
        let app_id = ID;
        for (alert, expected) in [
            (
                Alert::FirstEnrollmentHeld {
                    reason: FirstEnrollmentStop::Expired,
                },
                K::FirstEnrollmentHeld,
            ),
            (rollback(), K::Rollback),
            (equivocation(), K::Equivocation),
            (
                Alert::ManagedByOtherInstall { install: ID },
                K::ManagedByOtherInstall,
            ),
            (Alert::BackupUnreadable, K::BackupUnreadable),
            (Alert::AdmissionNotEnded, K::AdmissionNotEnded),
            (
                Alert::UnreadableBackupBeforeEnrollment,
                K::UnreadableBackupBeforeEnrollment,
            ),
            (Alert::BackupMissing, K::BackupMissing),
            (
                Alert::RecordsBehind {
                    source: Source::Backup,
                    version: 3,
                    high_water_version: 2,
                },
                K::RecordsBehind,
            ),
            (
                Alert::ReductionNotClosed { apps: vec![ID] },
                K::ReductionNotClosed,
            ),
            (
                Alert::RotationSkipped {
                    app_id,
                    scopes: vec![MARK.into()],
                },
                K::RotationSkipped,
            ),
            (
                Alert::RenewalsStopped {
                    app_id,
                    expires_at: 1,
                },
                K::RenewalsStopped,
            ),
            (
                Alert::RenewalRefused {
                    app_id,
                    reduction: true,
                    by_user: false,
                },
                K::RenewalRefused,
            ),
            (
                Alert::LapsingWithOpenAttempts {
                    app_id,
                    expires_at: 1,
                    open_attempts: 2,
                },
                K::LapsingWithOpenAttempts,
            ),
            (
                Alert::RevokedWithOpenAttempts {
                    app_id,
                    open_attempts: 2,
                },
                K::RevokedWithOpenAttempts,
            ),
            (
                Alert::RenewalSkipped {
                    app_id,
                    reason: RenewalSkip::UnownedScopes {
                        scopes: vec![MARK.into()],
                    },
                },
                K::RenewalSkipped,
            ),
            (
                Alert::IdentityNearLimit {
                    bytes: 9,
                    limit: 10,
                },
                K::IdentityNearLimit,
            ),
            (Alert::ClockOff, K::ClockOff),
            (Alert::AccountNotHosted, K::AccountNotHosted),
            (Alert::ServiceHoldsNoAccount, K::ServiceHoldsNoAccount),
            (
                Alert::ServiceKeyTaken {
                    origin: MARK.into(),
                    pinned: [1; 32],
                    service_key: [2; 32],
                },
                K::ServiceKeyTaken,
            ),
            (
                Alert::ServiceKeyNotFollowed {
                    origin: MARK.into(),
                    kept: [1; 32],
                    answered: [2; 32],
                },
                K::ServiceKeyNotFollowed,
            ),
            (
                Alert::GrantRevocationOwed { app_id },
                K::GrantRevocationOwed,
            ),
            (
                Alert::RevocationUnconfirmed { app_id },
                K::RevocationUnconfirmed,
            ),
            (
                Alert::RemovedAtSwitch { app_id, left: true },
                K::RemovedAtSwitch,
            ),
            (
                Alert::RemovalTimeBounded {
                    app_id,
                    reported: 1,
                    distrust_from: 2,
                },
                K::RemovalTimeBounded,
            ),
            (Alert::FullBundleRefused { app_id }, K::FullBundleRefused),
            (
                Alert::RevocationPending {
                    app_id,
                    at_switch: true,
                },
                K::RevocationPending,
            ),
            (Alert::BackupNotWritten, K::BackupNotWritten),
            (Alert::HandOverRefused { to_app: ID }, K::HandOverRefused),
            (Alert::KeyNotInstalled, K::KeyNotInstalled),
            (Alert::TakeOverRefused, K::TakeOverRefused),
            (Alert::TakenBack { from: ID }, K::TakenBack),
            (
                Alert::EpochFloorBounded {
                    claimed: 4,
                    kept: 3,
                },
                K::EpochFloorBounded,
            ),
        ] {
            assert!(
                matches!(checked(SignerError::Alarm(alert)), SignerFfiError::Alarm { alert } if alert == expected)
            );
        }
    }

    #[test]
    fn test_error_handed_over() {
        assert!(
            matches!(checked(SignerError::HandedOver { install: ID }), SignerFfiError::HandedOver { install } if install == ID)
        );
    }
}
