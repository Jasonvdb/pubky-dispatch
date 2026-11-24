//! The bindings' typed errors. Each names a failure's class and the rule that failed; none
//! carries a secret, a decrypted value or an inner error's text that could hold either.

use pubky_switch_client::store::BatchError;
use pubky_switch_client::{ClientError, StoreError, TransportError};
use pubky_switch_signer::{
    KeyError, KeyRecoveryStop, ProtocolError, RecordsFault, Refusal, SignerError, SizedBody,
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
    /// The bindings' runtime couldn't start, or stopped before the call's answer (Switch spec 4.3).
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
        /// Whether the held claim still has an alert in signer status (Switch spec 4.3).
        alert_held: Option<bool>,
    },
    /// The registered protocol definitions cannot be used (Switch spec 3.2).
    #[error("protocol: {kind:?}")]
    Protocol {
        /// The failed protocol rule (Switch wire 3.1).
        kind: ProtocolFailure,
    },
    /// Input or a network document failed verification (Switch wire 2.1).
    #[error("invalid signer data")]
    InvalidData,
    /// A service call failed (Switch wire 7.6).
    #[error("switch: {kind:?}")]
    Switch {
        /// How the call failed (Switch wire 7.1).
        kind: SwitchFailure,
        /// The HTTP status when available (Switch wire 7.1).
        status: Option<u16>,
        /// True for the answers the client always checks with the pinned service key: a
        /// verified error, one given before the body was read (final for nothing), a stale
        /// signed time and a chain that fails. False says nothing either way (Switch wire 7.1).
        authenticated: bool,
        /// The service error code in wire spelling (Switch wire 7.1).
        code: Option<String>,
        /// The service retry interval in seconds (Switch wire 7.1).
        retry_after_s: Option<u64>,
        /// The retry rule for a fully bound error (Switch wire 7.1).
        retry: Option<RetryKind>,
        /// Whether the service confirms it does not host this identity (Switch wire 7.1).
        not_hosted: bool,
        /// The version in a signed identity-needed answer (Switch wire 7.1).
        known_version: Option<u64>,
        /// The transport failure class (Switch wire 7.1).
        transport: Option<TransportFailure>,
        /// The refused request or response byte limit (Switch wire 7.1).
        limit: Option<u64>,
        /// The generation in the local recovery notice (Switch wire 7.1).
        generation: Option<u64>,
        /// The time of a stale signed read (Switch wire 7.1).
        server_time_ms: Option<u64>,
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
    #[error("invalid stored signer data")]
    StoredData,
    /// Another install is named as signer (Switch spec 4.3).
    #[error("another install is named as signer")]
    NotNamed {
        /// The named install's 16-byte signer ID (Switch spec 4.3).
        install: Vec<u8>,
    },
    /// The signer stopped on an alarm. Its alert belongs to signer status (Switch spec 4.3).
    #[error("signer alarm")]
    Alarm,
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

/// The identity key's failures (the signer's `KeyError`).
/// These distinguish an unavailable key from one that cannot sign (Switch spec 3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum KeyFailure {
    /// The vault holds no identity secret.
    /// Offer setup or recovery as appropriate for this install (Switch spec 12.8).
    Missing,
    /// The vault already holds one.
    /// Preserve the existing identity when handling an import (Switch spec 12.8).
    Occupied,
    /// The secret isn't this identity's.
    /// Check which identity the user selected (Switch spec 3.1).
    Mismatch,
    /// A secret that isn't 32 bytes.
    /// Check the imported seed's length (Switch spec 3.1).
    Malformed,
    /// A key operation failed.
    /// Report that the identity key could not be used (Switch spec 3.1).
    Crypto,
    /// The host's vault failed.
    /// Restore vault access before retrying (Switch spec 3.1).
    Vault,
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
            _ => {
                return Self::Unknown {
                    reason: "identity key".to_owned(),
                };
            }
        };
        Self::Key { kind }
    }
}

/// Quantities compared when a signer rule refused an action (Switch spec 4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RefusalMeasurements {
    /// Device and service times disagree (Switch spec 10.1).
    ClockOff {
        /// The device's Unix time in milliseconds (Switch spec 10.1).
        device_ms: u64,
        /// The signed service time in milliseconds (Switch spec 10.1).
        switch_ms: u64,
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
        switch_version: u64,
        /// The newest version observed (Switch spec 12.8).
        seen_version: u64,
    },
}

// Keep each public kind beside the source pattern it represents.
macro_rules! failure_kinds {
    ($(#[$doc:meta])* pub enum $kind:ident for $source:ident {
        $($(#[$item:meta])* $case:ident $(($arg:pat))? $({ $($field:tt)* })?,)*
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
                    $($source::$case $(($arg))? $({ $($field)* })? => Self::$case,)*
                    _ => Self::Unknown,
                }
            }
        }
    };
}

failure_kinds! {
    /// How the host can proceed after a signer refusal (Switch spec 4.3).
    pub enum RefusalKind for Refusal {
        /// Ask the app for a request whose scopes follow the scope rule (Switch spec 3.3).
        Scopes(_),
        /// Offer a build that supports the requested scopes (Switch wire 3.9).
        UnknownScopes { .. },
        /// Ask the app for a request the protocol's rule allows, or decline fewer paths (Switch
        /// spec 3.4).
        ProtocolRule { .. },
        /// Decline only paths a protocol added that the app asks for (Switch spec 3.4).
        NotDeclinable { .. },
        /// Ask the app for a valid request (Switch wire 3.9).
        AppRequest(_),
        /// Show the current authority and obtain fresh confirmation (Switch spec 12.1).
        ApprovalChanged,
        /// Refresh the app list: the app isn't in the newest identity document (Switch spec 12.1).
        NotListed,
        /// Clear the alert if one is held, then resume to confirm the newest delivery (Switch spec
        /// 4.3).
        ClaimHeld { .. },
        /// Wait for the app to join before sending its certificate or bundle (Switch wire 6.2).
        NotJoined,
        /// Open the existing signer records (Switch spec 4.3).
        AlreadySetUp,
        /// Restore current signer records or survey recovery with the identity key (Switch wire 3.13).
        RecordsBehind { .. },
        /// Keep the revoked or departing app cut off (Switch spec 12.2).
        CutOff,
        /// Wait for the hand-over to take effect, or abort it to sign here again (Switch wire
        /// 3.12).
        HandingOver { .. },
        /// Correct the device clock before issuing a certificate (Switch spec 10.1).
        ClockOff { .. },
        /// Reduce the identity document until it fits both calls (Switch wire 3.7).
        IdentityTooLarge { .. },
        /// Dismiss the abort action when no hand-over is active (Switch wire 3.12).
        NotHandingOver,
        /// Stop signing for the erased account (Switch spec 12.7).
        Erased,
        /// Nothing was erased: ask again once the service no longer refuses, as after a move
        /// ends (Switch wire 7.4.16).
        ErasureRefused,
        /// Dismiss the abort action when no erasure is active (Switch spec 12.7).
        NotErasing,
        /// Resume to establish whether the service erased the account (Switch wire 7.4.16).
        ErasureUnanswered,
        /// Keep resuming: an unsigned absence that holds 24 hours completes it, and a signed
        /// answer ends the wait (Switch wire 7.4.16).
        ErasureUnconfirmed { .. },
        /// Resume the first delivery before signing other changes (Switch wire 3.12).
        TakingOver,
        /// Hand over only to a current app: renew the target's certificate, or choose another
        /// app if it is revoked or departing (Switch wire 3.12).
        TargetNotCurrent,
        /// Deliver the pending revocation before hand-over (Switch spec 12.2).
        RevocationOwed,
        /// Deliver the pending reduction's closing version before hand-over (Switch wire 3.8).
        ClosingOwed,
        /// Obtain a hand-over for the version the service holds now (Switch wire 3.12).
        StaleHandOver,
        /// Wait for the successor's backup; offer take-back only if that install is lost (Switch
        /// wire 3.12).
        SuccessorUnproven { .. },
        /// Hide take-back: nothing qualifies for it (Switch wire 3.12).
        NothingToTakeBack,
        /// Dismiss the take-over action when none is active (Switch wire 3.12).
        NotTakingOver,
        /// Obtain a new hand-over to start again (Switch wire 3.12).
        TakeOverCancelled,
        /// Survey recovery with the identity key and confirm the terms (Switch wire 3.13).
        NoBackup,
        /// Survey recovery with the identity key against the current copy (Switch wire 3.13).
        StaleBackup,
        /// Use the recovery stop to choose the next recovery action (Switch spec 12.8).
        KeyRecovery(_),
        /// Select an App ID listed among the removed apps (Switch spec 12.2).
        NotRemoved,
        /// Resume delivery to confirm the newest version (Switch spec 4.3).
        SwitchUnconfirmed,
        /// Resume any signed delivery or pending work (Switch spec 12.8).
        NoPendingKeyRecovery,
        /// Resume the saved enrollment or offer recovery (Switch spec 12.8).
        FirstEnrollmentUnavailable,
        /// Show the enrollment alert and wait for the user's choice (Switch spec 12.8).
        FirstEnrollmentHeld,
        /// Offer to restore the signer: an account or its mark exists for this identity (Switch
        /// spec 12.8).
        FirstAccountPresent,
        /// Set up or restore the signer before opening its records (Switch spec 12.8).
        NotSetUp,
        /// Offer key recovery on restore or resolve the backup before enrollment (Switch wire 3.13).
        UnreadableBackup,
        /// Resume the outstanding operation first (Switch wire 2.1).
        FlowInProgress,
        /// Resume provider loss or redeclare it at the selected service (Switch spec 12.6).
        Recovering,
        /// Confirm that no other install signs before declaring provider loss (Switch spec 12.6).
        HomeserverCopyMissing,
        /// Confirm sole signing authority before using local records (Switch spec 12.6).
        HomeserverCopyUnreadable,
        /// Review the adopted version and request the change again (Switch spec 4.3).
        Superseded { .. },
    }
}

failure_kinds! {
    /// Why key-only recovery stopped (Switch spec 12.8).
    pub enum KeyRecoveryStopKind for KeyRecoveryStop {
        /// Supply the service that hosts the account (Switch spec 12.8).
        NoCopy,
        /// Choose the service currently serving the account (Switch spec 12.8).
        NotServing,
        /// Resolve the missing or unverifiable service copy (Switch spec 12.8).
        SwitchCopy,
        /// Recover at a service holding the newest version or declare provider loss (Switch spec 12.8).
        ServiceBehind { .. },
        /// Survey again and confirm the new terms (Switch spec 12.8).
        SurveyChanged,
        /// Use a signer that understands the newer document (Switch spec 12.8).
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

/// Why a set of protocol rules cannot be used (Switch wire 3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ProtocolFailure {
    /// The set is empty (Switch wire 3.1).
    NoProtocols,
    /// A set has already been installed (Switch wire 3.1).
    AlreadyRegistered,
    /// A protocol name breaks the naming rule (Switch wire 3.1).
    BadName,
    /// A scope belongs to another root (Switch wire 3.1).
    ForeignRoot,
    /// Two protocols have the same name (Switch wire 3.1).
    DuplicateProtocol,
    /// A protocol owns no scopes (Switch wire 3.1).
    NoScopes,
    /// A declared scope name is invalid (Switch wire 3.1).
    BadScopeName,
    /// A scope is declared twice (Switch wire 3.1).
    ScopeClaimedTwice,
    /// A protocol grant path breaks the grant rule (Switch wire 3.1).
    BadGrantPath,
    /// An unrecognized registration failure (Switch wire 3.1).
    Unknown,
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
    /// Read the store again before continuing (Switch wire 2.1).
    Unknown,
    /// The store ran out of space (Switch wire 2.1).
    Full,
    /// A stored value failed validation (Switch wire 2.1).
    Corrupt,
    /// A value or batch exceeds its cap (Switch wire 2.1).
    TooLarge,
    /// Another store failure applied nothing (Switch wire 2.1).
    Other,
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
    pub enum SwitchFailure for ClientError {
        /// A recovery notice forbids the write (Switch wire 7.1).
        OwnRecoveryRequired { .. },
        /// Wait for the original display read (Switch wire 7.1).
        DisplayReadPending,
        /// A verified error binds the whole request (Switch wire 7.1).
        Switch { .. },
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
        /// A head or proof failed verification (Switch wire 7.1).
        Chain(_),
        /// A document failed validation (Switch wire 7.1).
        Core(_),
        /// The credentials or arguments do not permit the call (Switch wire 7.1).
        Usage(_),
    }
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
            SignerError::InvalidData(_) => Self::InvalidData,
            SignerError::Switch(e) => e.into(),
            SignerError::Homeserver(e) => {
                let (kind, size, status) = transport_facts(e);
                Self::Homeserver { kind, size, status }
            }
            SignerError::Store(e) => e.into(),
            SignerError::Records(e) => e.into(),
            SignerError::StoredData(_) => Self::StoredData,
            SignerError::NotNamed { install } => Self::NotNamed {
                install: install.to_vec(),
            },
            SignerError::Alarm(_) => Self::Alarm,
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
        let mut alert_held = None;
        let kind = RefusalKind::from(&refusal);
        match refusal {
            Refusal::ClaimHeld { alert } => alert_held = Some(alert.is_some()),
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
                    switch_ms,
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
                        switch_version,
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
            alert_held,
        }
    }
}

impl From<ProtocolError> for SignerFfiError {
    fn from(error: ProtocolError) -> Self {
        let kind = match error {
            ProtocolError::NoProtocols => ProtocolFailure::NoProtocols,
            ProtocolError::BadName => ProtocolFailure::BadName,
            ProtocolError::ForeignRoot { .. } => ProtocolFailure::ForeignRoot,
            ProtocolError::DuplicateProtocol { .. } => ProtocolFailure::DuplicateProtocol,
            ProtocolError::NoScopes { .. } => ProtocolFailure::NoScopes,
            ProtocolError::BadScopeName { .. } => ProtocolFailure::BadScopeName,
            ProtocolError::ScopeClaimedTwice { .. } => ProtocolFailure::ScopeClaimedTwice,
            ProtocolError::BadGrantPath { .. } => ProtocolFailure::BadGrantPath,
            _ => ProtocolFailure::Unknown,
        };
        Self::Protocol { kind }
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
            _ => (Kind::Unknown, None, None),
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

impl From<ClientError> for SignerFfiError {
    fn from(error: ClientError) -> Self {
        let retry = error.retry();
        let not_hosted = error.is_not_hosted();
        let kind = SwitchFailure::from(&error);
        let authenticated = matches!(
            kind,
            SwitchFailure::Switch
                | SwitchFailure::BodyUnread
                | SwitchFailure::StaleAnswer
                | SwitchFailure::Chain
        );
        let known_version = match &error {
            ClientError::Switch { known_version, .. } => *known_version,
            _ => None,
        };
        let mut status = None;
        let mut code = None;
        let mut retry_after_s = None;
        let mut transport = None;
        let mut limit = None;
        let mut generation = None;
        let mut server_time_ms = None;
        match error {
            ClientError::OwnRecoveryRequired {
                generation: stopped,
            } => generation = Some(stopped),
            ClientError::Switch {
                status: http,
                code: wire,
                retry_after,
                ..
            }
            | ClientError::BodyUnread {
                status: http,
                code: wire,
                retry_after,
            } => {
                status = Some(http);
                code = Some(wire.as_str().to_owned());
                retry_after_s = retry_after;
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
            _ => {}
        }
        Self::Switch {
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

    use pubky_switch_core::http::{ErrorCode, not_hosted_current};
    use pubky_switch_signer::{Alert, SignerRecord};

    const MARK: &str = "private-test-tag";
    const ID: [u8; 16] = *b"private-test-tag";

    fn checked(source: SignerError) -> SignerFfiError {
        let error = SignerFfiError::from(source);
        assert!(!error.to_string().contains(MARK));
        assert!(!format!("{error:?}").contains(MARK));
        error
    }

    #[test]
    fn test_error_key() {
        assert!(matches!(
            checked(KeyError::Vault(pubky_switch_signer::VaultError(MARK.into())).into()),
            SignerFfiError::Key {
                kind: KeyFailure::Vault
            }
        ));
    }

    #[derive(Debug, Default, PartialEq)]
    struct Facts {
        since_ms: Option<u64>,
        version: Option<u64>,
        to_app: Option<Vec<u8>>,
        install: Option<Vec<u8>>,
        stop: Option<KeyRecoveryStopKind>,
        measurements: Option<RefusalMeasurements>,
        alert_held: Option<bool>,
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
            alert_held,
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
                alert_held
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
                R::UnknownScopes {
                    scopes: vec![MARK.into()],
                },
                K::UnknownScopes,
            ),
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
        ] {
            check_refusal(source, kind, Facts::default());
        }
        check_refusal(
            R::ClaimHeld {
                alert: Some(Alert::BackupUnreadable),
            },
            K::ClaimHeld,
            Facts {
                alert_held: Some(true),
                ..Default::default()
            },
        );
        check_refusal(
            R::ClaimHeld { alert: None },
            K::ClaimHeld,
            Facts {
                alert_held: Some(false),
                ..Default::default()
            },
        );
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
                    switch_ms: 19,
                }),
                ..Default::default()
            },
        );
        check_refusal(
            R::IdentityTooLarge {
                body: SizedBody::Delivery,
                bytes: 44,
                limit: 43,
            },
            K::IdentityTooLarge,
            Facts {
                measurements: Some(RefusalMeasurements::IdentityTooLarge {
                    body: SizedBodyKind::Delivery,
                    bytes: 44,
                    limit: 43,
                }),
                ..Default::default()
            },
        );
        check_refusal(
            R::IdentityTooLarge {
                body: SizedBody::Enrollment,
                bytes: 44,
                limit: 43,
            },
            K::IdentityTooLarge,
            Facts {
                measurements: Some(RefusalMeasurements::IdentityTooLarge {
                    body: SizedBodyKind::Enrollment,
                    bytes: 44,
                    limit: 43,
                }),
                ..Default::default()
            },
        );
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
        check_refusal(
            R::KeyRecovery(KeyRecoveryStop::NoCopy),
            K::KeyRecovery,
            Facts {
                stop: Some(KeyRecoveryStopKind::NoCopy),
                ..Default::default()
            },
        );
        check_refusal(
            R::KeyRecovery(KeyRecoveryStop::NotServing),
            K::KeyRecovery,
            Facts {
                stop: Some(KeyRecoveryStopKind::NotServing),
                ..Default::default()
            },
        );
        check_refusal(
            R::KeyRecovery(KeyRecoveryStop::SwitchCopy),
            K::KeyRecovery,
            Facts {
                stop: Some(KeyRecoveryStopKind::SwitchCopy),
                ..Default::default()
            },
        );
        check_refusal(
            R::KeyRecovery(KeyRecoveryStop::ServiceBehind {
                switch_version: 4,
                seen_version: 8,
            }),
            K::KeyRecovery,
            Facts {
                stop: Some(KeyRecoveryStopKind::ServiceBehind),
                measurements: Some(RefusalMeasurements::ServiceBehind {
                    switch_version: 4,
                    seen_version: 8,
                }),
                ..Default::default()
            },
        );
        check_refusal(
            R::KeyRecovery(KeyRecoveryStop::SurveyChanged),
            K::KeyRecovery,
            Facts {
                stop: Some(KeyRecoveryStopKind::SurveyChanged),
                ..Default::default()
            },
        );
        check_refusal(
            R::KeyRecovery(KeyRecoveryStop::UnknownMembers),
            K::KeyRecovery,
            Facts {
                stop: Some(KeyRecoveryStopKind::UnknownMembers),
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
                matches!(checked(source.into()), SignerFfiError::Protocol { kind } if kind == expected)
            );
        }
    }

    #[test]
    fn test_error_invalid_data() {
        assert!(matches!(
            checked(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                MARK.into()
            ))),
            SignerFfiError::InvalidData
        ));
    }

    #[test]
    fn test_error_switch() {
        let signed = ClientError::Switch {
            status: 429,
            code: ErrorCode::RateLimited,
            message: MARK.into(),
            current: serde_json::json!({"detail": MARK}),
            known_version: None,
            retry_after: Some(23),
        };
        assert!(
            matches!(checked(signed.into()), SignerFfiError::Switch { kind: SwitchFailure::Switch, status: Some(429), authenticated: true, code: Some(code), retry_after_s: Some(23), retry: Some(RetryKind::AfterRetryAfter), known_version: None, not_hosted: false, transport: None, .. } if code == "rate_limited")
        );
        let missing = ClientError::Switch {
            status: 404,
            code: ErrorCode::NotFound,
            message: MARK.into(),
            current: not_hosted_current(),
            known_version: None,
            retry_after: None,
        };
        assert!(matches!(
            checked(missing.into()),
            SignerFfiError::Switch {
                not_hosted: true,
                authenticated: true,
                ..
            }
        ));
        let needed = ClientError::Switch {
            status: 409,
            code: ErrorCode::IdentityNeeded,
            message: MARK.into(),
            current: Default::default(),
            known_version: Some(81),
            retry_after: None,
        };
        assert!(matches!(
            checked(needed.into()),
            SignerFfiError::Switch {
                known_version: Some(81),
                kind: SwitchFailure::Switch,
                ..
            }
        ));
        let partial = ClientError::BodyUnread {
            status: 429,
            code: ErrorCode::RateLimited,
            retry_after: Some(7),
        };
        assert!(
            matches!(checked(partial.into()), SignerFfiError::Switch { kind: SwitchFailure::BodyUnread, authenticated: true, status: Some(429), code: Some(code), retry_after_s: Some(7), retry: None, not_hosted: false, .. } if code == "rate_limited")
        );
        assert!(matches!(
            checked(ClientError::BadServiceSignature { status: 404 }.into()),
            SignerFfiError::Switch {
                kind: SwitchFailure::BadServiceSignature,
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
            SignerFfiError::Switch {
                kind: SwitchFailure::Transport,
                authenticated: false,
                code: None,
                transport: Some(TransportFailure::TooLarge),
                limit: Some(91),
                ..
            }
        ));
        assert!(matches!(
            checked(ClientError::BodyOverCap { cap: 92 }.into()),
            SignerFfiError::Switch {
                kind: SwitchFailure::BodyOverCap,
                authenticated: false,
                limit: Some(92),
                ..
            }
        ));
        assert!(matches!(
            checked(ClientError::StaleAnswer { server_time_ms: 93 }.into()),
            SignerFfiError::Switch {
                kind: SwitchFailure::StaleAnswer,
                authenticated: true,
                server_time_ms: Some(93),
                ..
            }
        ));
        assert!(matches!(
            checked(ClientError::OwnRecoveryRequired { generation: 94 }.into()),
            SignerFfiError::Switch {
                kind: SwitchFailure::OwnRecoveryRequired,
                generation: Some(94),
                ..
            }
        ));
        for (source, expected) in [
            (ClientError::Usage(MARK.into()), SwitchFailure::Usage),
            (ClientError::Unpinned, SwitchFailure::Unpinned),
            (
                ClientError::DisplayReadPending,
                SwitchFailure::DisplayReadPending,
            ),
            (
                ClientError::InvalidResponse(MARK.into()),
                SwitchFailure::InvalidResponse,
            ),
            (
                ClientError::Chain(pubky_switch_core::chain::ChainError::Malformed(MARK.into())),
                SwitchFailure::Chain,
            ),
            (
                ClientError::Core(pubky_switch_core::Error::Invalid(MARK.into())),
                SwitchFailure::Core,
            ),
        ] {
            assert!(
                matches!(checked(source.into()), SignerFfiError::Switch { kind, code: None, retry: None, .. } if kind == expected)
            );
        }
        // A response that doesn't read may come from a call made without a pinned key, such
        // as the first discovery: it isn't counted as authenticated.
        assert!(matches!(
            checked(ClientError::InvalidResponse(MARK.into()).into()),
            SignerFfiError::Switch {
                kind: SwitchFailure::InvalidResponse,
                authenticated: false,
                ..
            }
        ));
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
        assert!(matches!(
            checked(SignerError::StoredData(
                pubky_switch_core::Error::Signature(MARK.into())
            )),
            SignerFfiError::StoredData
        ));
    }

    #[test]
    fn test_error_not_named() {
        assert!(
            matches!(checked(SignerError::NotNamed { install: ID }), SignerFfiError::NotNamed { install } if install == ID)
        );
    }

    #[test]
    fn test_error_alarm() {
        let alert = Alert::RotationSkipped {
            app_id: ID,
            scopes: vec![MARK.into()],
        };
        assert!(matches!(
            checked(SignerError::Alarm(alert)),
            SignerFfiError::Alarm
        ));
    }

    #[test]
    fn test_error_handed_over() {
        assert!(
            matches!(checked(SignerError::HandedOver { install: ID }), SignerFfiError::HandedOver { install } if install == ID)
        );
    }
}
