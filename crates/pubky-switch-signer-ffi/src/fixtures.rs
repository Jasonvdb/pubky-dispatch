//! Values the host programs check the redaction with: a record and an error that aren't on
//! the redaction script's public list, each carrying a known text. And a host callback
//! they check a callback's failure with, in a synchronous and an asynchronous form:
//! whatever it throws, Rust reads a failure, and none of the host's text. Built only with the `test-fixtures` feature, which no
//! production build enables.

use crate::{SignerFfiError, runtime};

/// The text the fixtures carry, which no generated description may show.
pub const FIXTURE_TEXT: &str = "fixture-text-not-to-show";

/// A record the generated bindings would describe field by field.
#[derive(Debug, uniffi::Record)]
pub struct RedactionFixture {
    /// The text not to show.
    pub hidden: String,
}

/// An error the generated bindings would describe field by field, named without the
/// `Error` suffix the generator turns into `Exception`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FixtureFailure {
    /// Carries the text not to show.
    #[error("fixture failure: {hidden}")]
    Hidden {
        /// The text not to show.
        hidden: String,
    },
}

/// A record carrying [`FIXTURE_TEXT`].
#[uniffi::export]
pub fn redaction_fixture() -> RedactionFixture {
    RedactionFixture {
        hidden: FIXTURE_TEXT.to_owned(),
    }
}

/// A failure carrying [`FIXTURE_TEXT`].
///
/// # Errors
///
/// Always [`FixtureFailure::Hidden`].
#[uniffi::export]
pub fn redaction_fixture_failure() -> Result<(), FixtureFailure> {
    Err(FixtureFailure::Hidden {
        hidden: FIXTURE_TEXT.to_owned(),
    })
}

/// A host callback that returns nothing: only the call's status tells Rust whether it
/// failed.
#[uniffi::export(callback_interface)]
pub trait FixtureCallback: Send + Sync {
    /// Called once by [`fixture_callback_outcome`].
    ///
    /// # Errors
    ///
    /// Whatever the host throws: [`FixtureCallbackFailure::Refused`] as it is, anything
    /// else as [`FixtureCallbackFailure::Unexpected`].
    fn call(&self) -> Result<(), FixtureCallbackFailure>;
}

/// What a [`FixtureCallback`] fails with.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FixtureCallbackFailure {
    /// The failure a host throws by its type.
    #[error("the fixture callback refused")]
    Refused,
    /// Anything else a host callback threw.
    #[error("the fixture callback failed")]
    Unexpected {
        /// What the bindings handed to Rust about it.
        reason: String,
    },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FixtureCallbackFailure {
    fn from(unexpected: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unexpected {
            reason: unexpected.reason,
        }
    }
}

/// How a [`FixtureCallback`] call ended, as Rust read it.
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FixtureCallbackOutcome {
    /// The callback returned.
    Returned,
    /// The callback threw [`FixtureCallbackFailure::Refused`].
    Refused,
    /// The callback threw anything else.
    Unexpected {
        /// What the bindings handed to Rust about it.
        reason: String,
    },
}

impl From<Result<(), FixtureCallbackFailure>> for FixtureCallbackOutcome {
    fn from(ended: Result<(), FixtureCallbackFailure>) -> Self {
        match ended {
            Ok(()) => Self::Returned,
            Err(FixtureCallbackFailure::Refused) => Self::Refused,
            Err(FixtureCallbackFailure::Unexpected { reason }) => Self::Unexpected { reason },
        }
    }
}

/// Call `callback` once and say how Rust read its end.
#[uniffi::export]
pub fn fixture_callback_outcome(callback: Box<dyn FixtureCallback>) -> FixtureCallbackOutcome {
    callback.call().into()
}

/// An asynchronous host callback that returns nothing: only its completion tells Rust
/// that it ended, and how.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait FixtureCallbackAsync: Send + Sync {
    /// Called once by [`fixture_callback_async_outcome`].
    ///
    /// # Errors
    ///
    /// Whatever the host throws: [`FixtureCallbackFailure::Refused`] as it is, anything
    /// else as [`FixtureCallbackFailure::Unexpected`].
    async fn call(&self) -> Result<(), FixtureCallbackFailure>;
}

/// Call `callback` once, wait for it, and say how Rust read its end.
///
/// # Errors
///
/// [`SignerFfiError::RuntimeUnavailable`] when the bindings' runtime can't start.
#[uniffi::export]
pub async fn fixture_callback_async_outcome(
    callback: Box<dyn FixtureCallbackAsync>,
) -> Result<FixtureCallbackOutcome, SignerFfiError> {
    runtime::run(async move { Ok(callback.call().await.into()) }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Callback(Option<fn() -> FixtureCallbackFailure>);

    impl FixtureCallback for Callback {
        fn call(&self) -> Result<(), FixtureCallbackFailure> {
            self.0.map_or(Ok(()), |failure| Err(failure()))
        }
    }

    #[async_trait::async_trait]
    impl FixtureCallbackAsync for Callback {
        async fn call(&self) -> Result<(), FixtureCallbackFailure> {
            FixtureCallback::call(self)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_fixtures_callback_async_outcome() {
        let refused: fn() -> FixtureCallbackFailure = || FixtureCallbackFailure::Refused;
        for (callback, outcome) in [
            (None, FixtureCallbackOutcome::Returned),
            (Some(refused), FixtureCallbackOutcome::Refused),
        ] {
            let read = fixture_callback_async_outcome(Box::new(Callback(callback))).await;
            assert_eq!(read.unwrap(), outcome);
        }
    }

    #[test]
    fn test_fixtures_callback_outcome() {
        let outcome = |callback| fixture_callback_outcome(Box::new(Callback(callback)));
        assert_eq!(outcome(None), FixtureCallbackOutcome::Returned);
        assert_eq!(
            outcome(Some(|| FixtureCallbackFailure::Refused)),
            FixtureCallbackOutcome::Refused
        );
        let unexpected = || uniffi::UnexpectedUniFFICallbackError::new("handed over").into();
        assert_eq!(
            outcome(Some(unexpected)),
            FixtureCallbackOutcome::Unexpected {
                reason: "handed over".to_owned()
            }
        );
    }

    #[test]
    fn test_fixtures_carry_their_text() {
        assert_eq!(redaction_fixture().hidden, FIXTURE_TEXT);
        assert!(
            redaction_fixture_failure()
                .unwrap_err()
                .to_string()
                .contains(FIXTURE_TEXT)
        );
    }
}
