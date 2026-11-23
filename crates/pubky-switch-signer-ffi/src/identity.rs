//! Secrets a host hands to Rust, and the identity's public half.

use crate::{SignerFfiError, runtime};
use pubky_switch_core::{enc::pubky_id, keys::IdentityKey};
use pubky_switch_signer::IdentitySecret;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// The most bytes a secret handle takes: room for any of the signer's 32-byte secrets.
pub const MAX_SECRET_BYTES: usize = 64;

/// A secret the host hands to Rust, such as the identity's seed read from its vault, as an
/// opaque handle: the host can't read it back, and no description shows it. Its bytes are
/// used once and zeroized then; a second use is refused.
///
/// Rust zeroizes only the copy it holds. The host's own bytes, and the transfer buffer the
/// bindings fill to hand them over, which they free without a wipe, are the host's to wipe
/// as well as its platform allows.
#[derive(uniffi::Object)]
pub struct HostSecret {
    bytes: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl std::fmt::Debug for HostSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostSecret(..)")
    }
}

#[uniffi::export]
impl HostSecret {
    /// Hand `bytes` to Rust. The call that uses them checks their length for its secret.
    ///
    /// # Errors
    ///
    /// [`SignerFfiError::InvalidInput`] for more than [`MAX_SECRET_BYTES`]: no secret is
    /// that long, and a handle keeps nothing it can't use.
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Result<Arc<Self>, SignerFfiError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(SignerFfiError::InvalidInput {
                reason: format!("a secret is at most {MAX_SECRET_BYTES} bytes"),
            });
        }
        Ok(Arc::new(Self {
            bytes: Mutex::new(Some(bytes)),
        }))
    }
}

impl HostSecret {
    /// The bytes for their one use: zeroized when the returned value drops.
    fn take(&self) -> Result<Zeroizing<Vec<u8>>, SignerFfiError> {
        let mut held = self
            .bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        held.take().ok_or_else(|| SignerFfiError::InvalidInput {
            reason: "the secret was used already".to_owned(),
        })
    }
}

/// An identity's public half.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PublicIdentity {
    /// The identity's Pubky ID.
    pub pubky_id: String,
    /// Its 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
}

/// The public identity of `secret`, an identity's 32-byte seed (Switch spec 13.3): what a
/// host checks against the identity it expects before it adds an imported seed to its
/// vault. The secret is used up.
///
/// # Errors
///
/// [`SignerFfiError::Key`] with [`crate::KeyFailure::Malformed`] for a secret that isn't
/// 32 bytes, and [`SignerFfiError::InvalidInput`] for one used already.
#[uniffi::export]
pub async fn public_identity_of(secret: Arc<HostSecret>) -> Result<PublicIdentity, SignerFfiError> {
    runtime::run(async move {
        let bytes = secret.take()?;
        let secret = IdentitySecret::from_slice(&bytes)?;
        // The core's key zeroizes itself on drop, as the signer's secret does.
        let public = IdentityKey::from_secret(*secret.as_bytes()).public();
        Ok(PublicIdentity {
            pubky_id: pubky_id(&public),
            public_key: public.to_vec(),
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyFailure;

    /// The first identity of the Switch's key vectors: a fixed test seed, never a real one.
    fn vector_identity() -> (Vec<u8>, String, Vec<u8>) {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/keys.json"
        )))
        .unwrap();
        let identity = &vectors["identities"][0];
        let hex = |name: &str| {
            let text = identity[name].as_str().unwrap();
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        (
            hex("secret_hex"),
            identity["pubky_id"].as_str().unwrap().to_owned(),
            hex("public_hex"),
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_identity_public_of_the_vector_seed() {
        let (seed, pubky_id, public_key) = vector_identity();
        let identity = public_identity_of(HostSecret::new(seed).unwrap())
            .await
            .unwrap();
        assert_eq!(
            identity,
            PublicIdentity {
                pubky_id,
                public_key
            }
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_identity_short_secret_is_malformed() {
        let (mut seed, _, _) = vector_identity();
        seed.pop();
        let refused = public_identity_of(HostSecret::new(seed).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(
            refused,
            SignerFfiError::Key {
                kind: KeyFailure::Malformed
            }
        ));
    }

    #[test]
    fn test_identity_long_secret_is_refused_at_once() {
        assert!(HostSecret::new(vec![7; MAX_SECRET_BYTES]).is_ok());
        let refused = HostSecret::new(vec![7; MAX_SECRET_BYTES + 1]).unwrap_err();
        assert!(matches!(refused, SignerFfiError::InvalidInput { .. }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_identity_secret_is_used_once() {
        let (seed, _, _) = vector_identity();
        let secret = HostSecret::new(seed).unwrap();
        public_identity_of(Arc::clone(&secret)).await.unwrap();
        let again = public_identity_of(secret).await.unwrap_err();
        assert!(matches!(again, SignerFfiError::InvalidInput { .. }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_identity_secret_shows_in_no_text() {
        let (mut seed, _, _) = vector_identity();
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        let secret = HostSecret::new(seed.clone()).unwrap();
        assert_eq!(format!("{secret:?}"), "HostSecret(..)");
        seed.pop();
        let refused = public_identity_of(HostSecret::new(seed).unwrap())
            .await
            .unwrap_err();
        for text in [refused.to_string(), format!("{refused:?}")] {
            assert!(!text.contains(&hex[..16]), "{text}");
        }
    }
}
