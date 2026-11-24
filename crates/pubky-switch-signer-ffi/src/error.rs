//! The bindings' typed errors. Each names a failure's class and the rule that failed; none
//! carries a secret, a decrypted value or an inner error's text that could hold either.

use pubky_switch_signer::KeyError;

/// Why a call failed.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SignerFfiError {
    /// The identity key or the host's vault failed.
    #[error("identity key: {kind:?}")]
    Key {
        /// Which key failure.
        kind: KeyFailure,
    },
    /// The host passed something the call can't take, such as a secret already used.
    #[error("invalid input: {reason}")]
    InvalidInput {
        /// The rule the input broke.
        reason: String,
    },
    /// The bindings' runtime couldn't start, stopped before the call's answer, or had no
    /// thread free in time for the host callbacks the call needs.
    #[error("the bindings' runtime is unavailable")]
    RuntimeUnavailable,
    /// A failure these bindings don't name yet. A host treats it as the call's failure.
    #[error("signer failure: {reason}")]
    Unknown {
        /// Its class, never an inner error's text.
        reason: String,
    },
}

/// The identity key's failures (the signer's `KeyError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum KeyFailure {
    /// The vault holds no identity secret.
    Missing,
    /// The vault already holds one.
    Occupied,
    /// The secret isn't this identity's.
    Mismatch,
    /// A secret that isn't 32 bytes.
    Malformed,
    /// A key operation failed.
    Crypto,
    /// The host's vault failed.
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
}
