//! Kotlin and Swift bindings of the Pubky Switch signer, generated with UniFFI.
//!
//! Signing, verification, recovery decisions and retry ordering stay in Rust. A host gets
//! owned display values, opaque handles for what it must not read, and typed errors.
//!
//! # Secrets
//!
//! Every export follows one rule for secrets, such as the identity's seed:
//! - a secret crosses the boundary only (a) from the host into Rust, as the bytes of a
//!   [`HostSecret`] handle or as what a vault callback returns, and (b) from Rust to the
//!   host, as an argument of the vault callbacks that add a secret or delete the expected
//!   one. It is never what an export returns, and no event, error, description or log line
//!   carries it;
//! - it never crosses in a record or an enum the bindings would describe field by field;
//! - Rust zeroizes its copy as soon as it is used, and a handle can't be used again. The
//!   bindings' transfer copies (the vectors and buffers on the Rust heap and the
//!   host-language array) are freed without a wipe: a host limits them by keeping the
//!   secret in its vault and handing it over only at the call;
//! - a handle is used only through its own methods, never passed as an argument to a free
//!   function or to another object's method: only a method call goes through the bindings'
//!   guard against a handle the host closed, so a closed handle is refused, not used.
//!
//! # Calls
//!
//! Asynchronous calls run on the bindings' own runtime, never on the thread the host calls
//! from: a host thread only waits for the answer. Synchronous host callbacks, such as the
//! vault's, run on the runtime's small pool of blocking threads. What a host
//! callback's method throws is reported as a failure of the call it served, and its text
//! isn't handed to Rust; the crate's README says what the generated code around a
//! callback leaves outside that. Every callback method declares a failure for it.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Every export returns `SignerFfiError` by value, and the bindings copy it into the host's
// error at once: it carries one typed field per fact a host acts on, and boxing it would
// save no copy the bindings don't already make.
#![allow(clippy::result_large_err)]

mod environment;
#[cfg(feature = "test-fixtures")]
mod environment_fixtures;
mod error;
#[cfg(feature = "test-fixtures")]
mod fixtures;
mod identity;
mod protocol;
mod runtime;
mod store;
#[cfg(feature = "test-fixtures")]
mod store_fixtures;
mod vault;

// Empty until its bindings land.
#[allow(unused_imports)]
pub use environment::*;
#[cfg(feature = "test-fixtures")]
// Empty until its bindings land.
#[allow(unused_imports)]
pub use environment_fixtures::*;
pub use error::*;
#[cfg(feature = "test-fixtures")]
pub use fixtures::{
    FIXTURE_TEXT, FixtureCallback, FixtureCallbackAsync, FixtureCallbackFailure,
    FixtureCallbackOutcome, FixtureFailure, RedactionFixture, fixture_callback_async_outcome,
    fixture_callback_outcome, redaction_fixture, redaction_fixture_failure,
};
pub use identity::{HostSecret, MAX_SECRET_BYTES, PublicIdentity};
// Empty until its bindings land.
#[allow(unused_imports)]
pub use protocol::*;
// Empty until its bindings land.
#[allow(unused_imports)]
pub use store::*;
#[cfg(feature = "test-fixtures")]
// Empty until its bindings land.
#[allow(unused_imports)]
pub use store_fixtures::*;
pub use vault::*;

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
