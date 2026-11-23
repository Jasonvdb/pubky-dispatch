//! Kotlin and Swift bindings of the Pubky Switch signer, generated with UniFFI.
//!
//! Signing, verification, recovery decisions and retry ordering stay in Rust. A host gets
//! owned display values, opaque handles for what it must not read, and typed errors.
//!
//! # Secrets
//!
//! Every export follows one rule for secrets, such as the identity's seed:
//! - a secret only ever travels from the host into Rust, never back: no call returns it,
//!   and no error, description or log line carries it;
//! - it crosses once, into an opaque handle ([`HostSecret`]), never into a record or an
//!   enum the bindings would describe field by field;
//! - Rust zeroizes its copy as soon as it is used, and the handle can't be used again; the
//!   host wipes its own bytes, and the bindings' transfer buffer, as its platform allows.
//!
//! # Calls
//!
//! Asynchronous calls run on the bindings' own runtime, never on the thread the host calls
//! from: a host thread only waits for the answer.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
#[cfg(feature = "test-fixtures")]
mod fixtures;
mod identity;
mod runtime;

pub use error::{KeyFailure, SignerFfiError};
#[cfg(feature = "test-fixtures")]
pub use fixtures::{
    FIXTURE_TEXT, FixtureFailure, RedactionFixture, redaction_fixture, redaction_fixture_failure,
};
pub use identity::{HostSecret, MAX_SECRET_BYTES, PublicIdentity, public_identity_of};

uniffi::setup_scaffolding!();

/// The version of these bindings, the signer crate's version.
#[uniffi::export]
pub fn signer_ffi_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_is_the_crate_version() {
        assert_eq!(signer_ffi_version(), env!("CARGO_PKG_VERSION"));
        assert!(!signer_ffi_version().is_empty());
    }
}
