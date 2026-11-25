//! Kotlin and Swift bindings of the Pubky Dispatch signer, generated with UniFFI.
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
//! - the bindings wipe what they hold of it as soon as it is used: the bytes of a
//!   [`HostSecret`], which can't be used again, and the bytes a vault's `load` handed
//!   over. The signer's secret and the core's key wipe themselves when dropped. Not wiped:
//!   the bindings' transfer copies (the vectors and buffers on the Rust heap and the
//!   host-language array), and what the hash and curve code keep on their own stack while
//!   they work. A host limits these by keeping the secret in its vault and handing it over
//!   only at the call;
//! - a handle is used only through its own methods, never passed as an argument to a free
//!   function or to another object's method: only a method call goes through the bindings'
//!   guard against a handle the host closed, so a closed handle is refused, not used.
//!
//! # Calls
//!
//! Asynchronous calls run on the bindings' own runtime, never on the thread the host calls
//! from: a host thread only waits for the answer. Synchronous host callbacks, such as the
//! vault's, run on the runtime's pool of ten blocking threads, never on the two workers
//! that serve the network and the timers. A signer's call has one of those threads to
//! itself while it runs, on which its vault callbacks run too, and takes one more for each
//! store call it makes. At most four signer calls run at once, over all signers, so each
//! always finds a thread for its store call, with two left for the store's releases and a
//! keyring's calls. A signer's close runs on a thread of its own, outside that pool, for
//! as long as it lasts, and so holds none of the threads its release needs. A host with
//! more than four signers working at the same moment sees the calls beyond four start
//! later, in turn; one that gets no place within 30 seconds fails with
//! [`SignerFfiError::RuntimeUnavailable`], having started nothing. What a host
//! callback's method throws is reported as a failure of the call it served, and its text
//! isn't handed to Rust; the crate's README says what the generated code around a
//! callback leaves outside that. Every callback method declares a failure for it.
//!
//! An interface a host implements, such as [`HostVault`], is bound as one only the host
//! implements: the bindings call its methods and export none of them.
//!
//! A host callback never waits for a call into the bindings:
//! - an asynchronous call it starts on its own thread before it returns is refused, and
//!   takes nothing. The synchronous calls, which read or build a handle and reach neither
//!   the host nor the runtime ([`HostSecret`]'s and [`SignerEnvironment`]'s constructors, a
//!   keyring's public key and Pubky ID, a signer's status, identity and install ID), aren't
//!   refused;
//! - a call it waits for from another thread isn't seen. The callback holds a blocking
//!   thread meanwhile, and so does every slow callback. Work that no blocking thread has
//!   taken up within a bound is given up, and its call fails with
//!   [`SignerFfiError::RuntimeUnavailable`]. Only the work the bindings start themselves
//!   is given up so: a keyring's calls, the start of a signer's call and a store's
//!   releases. A store's other calls, which the store client queues on the same pool, are
//!   not: [`HostStore`] says what a host sees then;
//! - work a thread has taken up isn't given up. A callback that waits for a call which
//!   then needs something the callback holds, such as a lock of the host's own, never
//!   returns: that is the host's own deadlock, and both threads are lost to it. A call of
//!   the signer whose call the callback serves is such a call, but for `status`, `identity`
//!   and `install_id`, which answer at once, and its `shutdown`, which answers within a
//!   bound. Every other call of the signer, its views among them, takes the signer's turn:
//!   [signer host guide, 2.4](https://github.com/pubky/pubky-dispatch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store).
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
mod signer;
#[cfg(feature = "test-fixtures")]
mod signer_fixtures;
mod status;
mod store;
#[cfg(feature = "test-fixtures")]
mod store_fixtures;
#[cfg(test)]
mod test_host;
mod vault;

pub use environment::*;
#[cfg(feature = "test-fixtures")]
pub use environment_fixtures::*;
pub use error::*;
#[cfg(feature = "test-fixtures")]
pub use fixtures::{
    FIXTURE_TEXT, FixtureCallback, FixtureCallbackAsync, FixtureCallbackFailure,
    FixtureCallbackOutcome, FixtureFailure, RedactionFixture, fixture_callback_async_outcome,
    fixture_callback_outcome, redaction_fixture, redaction_fixture_failure,
};
pub use identity::{HostSecret, MAX_SECRET_BYTES, PublicIdentity};
pub use protocol::*;
pub use signer::*;
#[cfg(feature = "test-fixtures")]
pub use signer_fixtures::*;
pub use status::*;
pub use store::*;
#[cfg(feature = "test-fixtures")]
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
