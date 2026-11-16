//! Exclusive ownership of a host store namespace.

use std::sync::Arc;

use super::{MAX_BATCH_BYTES, StoreError, WriteBatch};

/// One acquisition's opaque identity. A new acquisition never intentionally reuses it.
///
/// The handle generates 32 random bytes; their collision resistance is the same assumption
/// as other random identifiers. The ID is not a secret or a substitute for actual exclusion.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StoreOwner([u8; 32]);

impl StoreOwner {
    pub(super) fn new() -> Result<Self, StoreError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes)
            .map_err(|_| StoreError::Other("ownership randomness unavailable".into()))?;
        Ok(Self(bytes))
    }

    /// The fixed bytes a host compares with its active ownership record.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for StoreOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreOwner(..)")
    }
}

/// The host's exclusive namespace ownership, released only when its last holder drops.
///
/// The concrete guard retains the actual exclusion resource across every handle, thread and
/// process sharing the physical store. It never expires or permits another owner while it
/// lives. A process death releases exclusion; a clock or a missing heartbeat does not prove
/// that death. Unsupported locking fails acquisition. The host keeps ownership metadata
/// separate from the opaque records it protects, and never replaces a live lock's inode.
///
/// This capability has no explicit unlock: a blocked store call may retain it after its
/// caller has been canceled. A host that implements this marker without those guarantees
/// does not provide a compliant store.
pub trait StoreLease: Send + Sync {}

/// The result of an atomic namespace acquisition.
pub enum AcquireOutcome {
    /// This owner holds the namespace until the last guard is dropped.
    Acquired(Arc<dyn StoreLease>),
    /// Another live owner holds it; nothing was changed.
    Busy,
}

impl std::fmt::Debug for AcquireOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Acquired(_) => "Acquired(..)",
            Self::Busy => "Busy",
        })
    }
}

/// The result of an atomic owner-conditioned commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Every write is durable.
    Applied,
    /// The exact owner is not active; no write was applied.
    NotOwner,
}

/// Check a conditional batch's namespace and complete size, including its condition.
///
/// The condition charges the namespace's UTF-8 bytes and the owner's 32 bytes in addition
/// to the batch's writes. Hosts use this same check before applying a direct trait call.
///
/// # Errors
///
/// A foreign namespace or a total over [`MAX_BATCH_BYTES`], with no writes applied.
pub fn check_owned_batch(ns: &str, batch: &WriteBatch) -> Result<(), StoreError> {
    batch.check_namespace(ns)?;
    let size = batch
        .size()
        .saturating_add(u64::try_from(ns.len()).unwrap_or(u64::MAX))
        .saturating_add(32);
    if size > MAX_BATCH_BYTES {
        return Err(StoreError::TooLarge {
            size,
            cap: MAX_BATCH_BYTES,
        });
    }
    Ok(())
}
