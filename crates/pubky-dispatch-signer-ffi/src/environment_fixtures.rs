//! A sample protocol and host checks for the signer environment (Dispatch spec 3.2).

use crate::{SignerFfiError, register_protocols};
use pubky_dispatch_core::scopes::{Permission, split};
use pubky_dispatch_signer::{Protocol, ScopeDef};
use std::sync::{Arc, OnceLock};

/// A protocol with one keyed scope and one dependent scope (Dispatch spec 3.2).
pub(crate) struct Sample;

impl Protocol for Sample {
    fn name(&self) -> &str {
        "sample"
    }

    fn scopes(&self) -> Vec<ScopeDef> {
        vec![ScopeDef::keyed("sample-a"), ScopeDef::unkeyed("sample-b")]
    }

    fn check_scopes(&self, scopes: &[&str]) -> Result<(), String> {
        if owns(scopes, "sample-b") && !owns(scopes, "sample-a") {
            return Err("sample-b requires sample-a".into());
        }
        Ok(())
    }

    fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
        let mut permissions = Vec::new();
        if owns(scopes, "sample-a") {
            permissions.push(Permission::ClaimsRead);
        }
        if owns(scopes, "sample-b") {
            permissions.push(Permission::ListsRead);
        }
        permissions
    }
}

fn owns(scopes: &[&str], root: &str) -> bool {
    scopes
        .iter()
        .any(|scope| split(scope).is_some_and(|(name, _)| name == root))
}

/// Install the sample scope rules once (Dispatch spec 3.2).
#[cfg_attr(feature = "test-fixtures", uniffi::export)]
pub fn register_sample_protocol() -> Result<(), SignerFfiError> {
    static SAMPLE: OnceLock<Result<(), SignerFfiError>> = OnceLock::new();
    SAMPLE
        .get_or_init(|| register_protocols(vec![Arc::new(Sample)]))
        .clone()
}

#[cfg(feature = "test-fixtures")]
pub use hosts::*;

#[cfg(feature = "test-fixtures")]
mod hosts {
    use super::*;
    use crate::environment::{check_file_size, session};
    use crate::{HostHomeserver, runtime};
    use pubky_dispatch_client::{ClientError, StoreError, TransportError};
    use pubky_dispatch_core::http::ErrorCode;
    use pubky_dispatch_signer::SignerError::Homeserver;
    use pubky_dispatch_signer::{
        Alert, KeyRecoveryStop, RecordsFault, Refusal, SignerError, SignerRecord,
    };

    /// A signer failure a host can inspect (Dispatch spec 4.3).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
    pub enum SampleFailure {
        /// The clocks differ (Dispatch spec 10.1).
        ClockOff,
        /// Hand-over names a target app (Dispatch spec 4.3).
        HandingOver,
        /// The service is behind the newest version seen (Dispatch spec 4.3).
        KeyRecovery,
        /// The local write exceeds its byte cap (Dispatch spec 4.3).
        StoreTooLarge,
        /// The response exceeds a transport limit (Dispatch spec 4.3).
        TransportTooLarge,
        /// A fully bound service answer asks for a retry (Dispatch wire 7.6).
        ErrorAnswer,
        /// A verified answer does not bind the request body (Dispatch wire 7.6).
        BodyUnread,
        /// A bare status has no authenticated error code (Dispatch wire 7.6).
        UnsignedStatus,
        /// The flow record has a decoder location (Dispatch spec 4.3).
        Undecodable,
        /// Another install is the named signer (Dispatch spec 4.3).
        NotNamed,
        /// The successor is named after hand-over (Dispatch spec 4.3).
        HandedOver,
        /// A received document is invalid (Dispatch spec 4.3).
        InvalidData,
        /// A retained document is invalid (Dispatch spec 4.3).
        StoredData,
        /// Signer status holds an alert (Dispatch spec 4.3).
        Alarm,
    }

    /// Every sample failure, so a host checks each one (Dispatch spec 4.3).
    #[uniffi::export]
    pub fn sample_failures() -> Vec<SampleFailure> {
        use SampleFailure::*;
        vec![
            ClockOff,
            HandingOver,
            KeyRecovery,
            StoreTooLarge,
            TransportTooLarge,
            ErrorAnswer,
            BodyUnread,
            UnsignedStatus,
            Undecodable,
            NotNamed,
            HandedOver,
            InvalidData,
            StoredData,
            Alarm,
        ]
    }

    /// Return the selected signer failure through its public mapping (Dispatch spec 4.3).
    #[uniffi::export]
    pub fn sample_failure(sample: SampleFailure) -> Result<(), SignerFfiError> {
        use SampleFailure::*;
        let invalid = || pubky_dispatch_core::Error::Invalid(crate::FIXTURE_TEXT.into());
        let error: SignerError = match sample {
            ClockOff => Refusal::ClockOff {
                device_ms: 5,
                dispatch_ms: 9,
            }
            .into(),
            HandingOver => Refusal::HandingOver { to_app: [3; 16] }.into(),
            KeyRecovery => Refusal::KeyRecovery(KeyRecoveryStop::ServiceBehind {
                dispatch_version: 2,
                seen_version: 4,
            })
            .into(),
            StoreTooLarge => StoreError::TooLarge { size: 13, cap: 12 }.into(),
            TransportTooLarge => ClientError::Transport(TransportError::TooLarge(64)).into(),
            ErrorAnswer => ClientError::Dispatch {
                status: 429,
                code: ErrorCode::RateLimited,
                message: crate::FIXTURE_TEXT.into(),
                current: Default::default(),
                known_version: None,
                retry_after: Some(37),
            }
            .into(),
            BodyUnread => ClientError::BodyUnread {
                status: 429,
                code: ErrorCode::RateLimited,
                retry_after: Some(19),
            }
            .into(),
            UnsignedStatus => ClientError::BadServiceSignature { status: 404 }.into(),
            Undecodable => RecordsFault::Undecodable {
                record: SignerRecord::Flow,
                line: 7,
                column: 11,
            }
            .into(),
            NotNamed => SignerError::NotNamed { install: [5; 16] },
            HandedOver => SignerError::HandedOver { install: [7; 16] },
            InvalidData => SignerError::InvalidData(invalid()),
            StoredData => SignerError::StoredData(invalid()),
            Alarm => SignerError::Alarm(Alert::BackupUnreadable),
        };
        Err(error.into())
    }

    /// Observations from a successful put and two successful deletions (Dispatch spec 4.1).
    #[derive(uniffi::Record)]
    pub struct HomeserverTrip {
        /// The file was absent before the write (Dispatch spec 4.1).
        pub absent_before: bool,
        /// The read after the write matched the supplied bytes (Dispatch spec 4.1).
        pub matched_after_put: bool,
        /// The file was absent after deleting it twice (Dispatch spec 12.7).
        pub absent_after: bool,
    }

    /// Exercise the session on an unused path, including a repeated deletion (Dispatch spec 4.1).
    #[uniffi::export]
    pub async fn homeserver_round_trip(
        homeserver: Box<dyn HostHomeserver>,
        path: String,
        bytes: Vec<u8>,
    ) -> Result<HomeserverTrip, SignerFfiError> {
        runtime::run(async move {
            check_file_size(bytes.len()).map_err(Homeserver)?;
            let home = session(
                Arc::from(homeserver),
                &pubky_dispatch_client::transport::HttpConfig::default(),
            );
            let absent_before = home.get(&path).await.map_err(Homeserver)?.is_none();
            if !absent_before {
                return Err(SignerFfiError::InvalidInput {
                    reason: "path must be absent".into(),
                });
            }
            home.put(&path, bytes.clone()).await.map_err(Homeserver)?;
            let read = home.get(&path).await.map_err(Homeserver)?;
            let matched_after_put = read.as_ref() == Some(&bytes);
            home.delete(&path).await.map_err(Homeserver)?;
            home.delete(&path).await.map_err(Homeserver)?;
            let absent_after = home.get(&path).await.map_err(Homeserver)?.is_none();
            Ok(HomeserverTrip {
                absent_before,
                matched_after_put,
                absent_after,
            })
        })
        .await
    }
}
