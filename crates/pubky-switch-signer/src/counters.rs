//! Counter floors for signing and replay (Switch spec 4.3, 12.8).

use pubky_switch_core::json::MAX_INT;
use pubky_switch_core::records::IdentityDoc;

use crate::error::{Refusal, Result};

/// Maximum absolute version floor without a verified document (Switch spec 12.8).
const VERSION_CEILING: u64 = 1 << 52;
/// Maximum absolute generation floor without a verified document (Switch spec 12.8).
const GENERATION_CEILING: u64 = 1 << 32;
/// Maximum absolute epoch without a verified document or bundle range.
const EPOCH_CEILING: u64 = 65_536;
/// Room for genuinely spent but unsent versions, including a reserved hand-over slot.
const MAX_LOCAL_AHEAD: u64 = 16;

/// A counter carried by the signed identity document (Switch wire 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Counter {
    /// The identity document version.
    Version,
    /// The service generation.
    Generation,
    /// The data epoch used for scope keys.
    Epoch,
}

impl Counter {
    fn ceiling(self) -> u64 {
        match self {
            Self::Version => VERSION_CEILING,
            Self::Generation => GENERATION_CEILING,
            Self::Epoch => EPOCH_CEILING,
        }
    }

    fn value(self, doc: &IdentityDoc) -> u64 {
        match self {
            Self::Version => doc.version(),
            Self::Generation => doc.generation(),
            Self::Epoch => doc.data_epoch(),
        }
    }

    /// Keep a nearby spent floor. A distant scalar alone cannot advance a verified head.
    pub(crate) fn floor(self, verified: u64, local: Option<u64>) -> u64 {
        local
            .filter(|n| {
                n.checked_sub(verified)
                    .is_some_and(|d| d <= MAX_LOCAL_AHEAD)
            })
            .unwrap_or(verified)
    }

    /// Repair a damaged hint on an authenticated read, preserving an unspent lower mark.
    pub(crate) fn repair(self, verified: u64, local: &mut u64) {
        if *local > verified {
            *local = self.floor(verified, Some(*local));
        }
    }

    /// Advance the floor, or copy it with a zero step. Verified steps may cross a ceiling.
    pub(crate) fn next(self, verified: u64, local: Option<u64>, step: u64) -> Result<u64> {
        let successor = verified
            .checked_add(step)
            .filter(|n| *n <= MAX_INT)
            .ok_or(Refusal::CounterExhausted { counter: self })?;
        let floor = self.floor(verified, local);
        if floor == verified {
            return Ok(successor);
        }
        // Reusing a plausibly spent slot could sign two bodies at the same version.
        // At the wire limit, obtain its signed copy before spending the final slot.
        floor
            .checked_add(step)
            .filter(|n| *n < MAX_INT)
            .ok_or_else(|| Refusal::CounterCopyNeeded { counter: self }.into())
    }

    /// A no-copy recovery can bootstrap only from a representable, bounded clock floor.
    pub(crate) fn clock_floor(self, value: Option<u64>) -> Result<u64> {
        value
            .filter(|n| *n <= self.ceiling())
            .ok_or_else(|| Refusal::CounterClock { counter: self }.into())
    }
}

/// A local copy above an absolute ceiling needs a published, delivered or backed-up witness.
pub(crate) fn needs_witness(doc: &IdentityDoc) -> bool {
    [Counter::Version, Counter::Generation, Counter::Epoch]
        .into_iter()
        .any(|counter| counter.value(doc) > counter.ceiling())
}

/// Check immutable signed bytes against independent evidence before their first use.
/// A zero step needs an existing witness for every counter. For delivery the spent floor
/// precedes the candidate by one, or by two for an abort (Switch wire 3.12).
pub(crate) fn check_copy<'a>(
    doc: &IdentityDoc,
    copies: impl IntoIterator<Item = &'a IdentityDoc>,
    version_step: u64,
) -> Result<()> {
    let counters = [Counter::Version, Counter::Generation, Counter::Epoch];
    let mut highest = [0; 3];
    let mut has_copy = false;
    for copy in copies {
        has_copy = true;
        for (floor, counter) in highest.iter_mut().zip(counters) {
            *floor = (*floor).max(counter.value(copy));
        }
    }
    for (verified, counter) in highest.into_iter().zip(counters) {
        let value = counter.value(doc);
        if value <= verified {
            counter.next(value, None, 0)?;
            continue;
        }
        if version_step == 0 {
            return Err(Refusal::CounterCopyNeeded { counter }.into());
        }
        let step = if has_copy && counter == Counter::Version {
            version_step
        } else {
            1
        };
        let step = step.min(value - verified);
        let spent = value.checked_sub(step).filter(|_| has_copy);
        if counter.next(verified, spent, step)? != value {
            return Err(Refusal::CounterCopyNeeded { counter }.into());
        }
    }
    Ok(())
}

/// A queued first recovery without a predecessor must fit the same clock floors as its signer.
pub(crate) fn check_bootstrap(doc: &IdentityDoc) -> Result<()> {
    for counter in [Counter::Version, Counter::Generation, Counter::Epoch] {
        let value = counter.value(doc);
        let floor = counter
            .clock_floor(value.checked_sub(1))
            .map_err(|_| Refusal::CounterCopyNeeded { counter })?;
        if (counter == Counter::Epoch && value != 1)
            || (counter == Counter::Generation && doc.body().recovery_from != Some(floor))
            || counter.next(floor, None, 1)? != value
        {
            return Err(Refusal::CounterCopyNeeded { counter }.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counters_steps_and_spent_slots() {
        assert_eq!(Counter::Version.next(40, None, 2).unwrap(), 42);
        assert_eq!(Counter::Version.next(40, Some(39), 1).unwrap(), 41);
        assert_eq!(Counter::Version.next(40, Some(56), 1).unwrap(), 57);
        assert_eq!(Counter::Version.next(40, Some(57), 1).unwrap(), 41);
        assert_eq!(Counter::Epoch.next(40, Some(MAX_INT), 0).unwrap(), 40);
    }

    #[test]
    fn test_counters_absolute_and_verified_limits() {
        for counter in [Counter::Version, Counter::Generation, Counter::Epoch] {
            let limit = counter.ceiling();
            assert_eq!(counter.clock_floor(Some(limit)).unwrap(), limit);
            assert!(counter.clock_floor(Some(limit + 1)).is_err());
            assert!(counter.clock_floor(None).is_err());
            assert_eq!(counter.next(limit + 1, None, 1).unwrap(), limit + 2);
            assert_eq!(counter.next(MAX_INT - 1, None, 1).unwrap(), MAX_INT);
            assert_eq!(
                counter.next(MAX_INT - 2, Some(MAX_INT - 1), 1),
                Err(Refusal::CounterCopyNeeded { counter }.into())
            );
            assert_eq!(
                counter.next(MAX_INT, None, 1),
                Err(Refusal::CounterExhausted { counter }.into())
            );
            assert!(counter.next(MAX_INT - 1, None, 2).is_err());
            assert!(counter.next(u64::MAX, None, 1).is_err());
        }
    }
}
