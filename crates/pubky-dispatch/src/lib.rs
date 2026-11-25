//! The Pubky Dispatch service: an inbox and coordination service for Pubky identities.
//!
//! One Dispatch hosts many identities, each with its own account. For each identity it keeps:
//!
//! - a sealed inbox, where admitted senders append signed, encrypted messages that the
//!   identity's own apps read in order from their feed;
//! - the claims and shared records the identity's own apps coordinate through, changed by
//!   batches of signed operations and answered with transition proofs and signed heads;
//! - the directory: the identity's newest `identity.json`, its apps' records, receive keys
//!   and key bundles.
//!
//! The service reads no message and no shared data, and knows no protocol: scopes, message
//! kinds and collections are opaque to it. It holds storage, the HTTP API and operations; the
//! formats come from `pubky-dispatch-core`.
//!
//! The behaviour is specified by the Pubky Dispatch spec and wire format, in this repository's
//! `spec/`.

pub mod account;
pub mod admin;
pub mod changes;
pub mod check_marks;
pub mod config;
pub mod http;
pub mod keys;
pub mod limits;
pub mod marks;
pub mod ratelimit;
pub mod retire;
pub mod service;
pub mod store;
pub mod telemetry;
pub mod time;
