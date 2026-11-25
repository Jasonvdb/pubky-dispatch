//! Order verified own-account recovery observations at request handoff (Dispatch wire 7.6).

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

use pubky_dispatch_core::http::NoticeReason;
use serde::{Deserialize, Serialize};

use super::OwnAnswer;

/// A recovery notice verified by this app (Dispatch spec 12.6, Dispatch wire 7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryNotice {
    /// The generation the app holds the notice for.
    pub generation: u64,
    /// Why the service stopped, when all the signed notice's members were understood.
    pub reason: Option<NoticeReason>,
    /// Whether the service has retired this generation.
    pub permanent: bool,
    /// Device-clock time of the first notice for this generation, in Unix milliseconds.
    pub first_seen_ms: u64,
    /// The notice's signed service time, in Unix milliseconds.
    pub service_time_ms: u64,
}

/// A change for the single foreground store owner, in the order it was learned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Notice(Option<RecoveryNotice>),
    Rollback,
}

/// Shared only by clients for the same installation, account, origin, key and generation.
/// A detached handle never has access to the app store. Its verified answer reaches the
/// same owner even if the foreground operation following the wake cannot reach the service.
pub(crate) struct OwnReads {
    pub(super) generation: u64,
    state: Mutex<Ordered>,
}

struct Ordered {
    issued: u64,
    active: usize,
    display: bool,
    headed: u64,
    cleared: u64,
    notice: Option<(u64, RecoveryNotice)>,
    rollback: bool,
    pending: VecDeque<Decision>,
}

impl OwnReads {
    pub(crate) fn new(generation: u64, notice: Option<RecoveryNotice>) -> Self {
        Self {
            generation,
            state: Mutex::new(Ordered {
                issued: 0,
                active: 0,
                display: false,
                headed: 0,
                cleared: 0,
                notice: notice.map(|notice| (0, notice)),
                rollback: false,
                pending: VecDeque::new(),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, Ordered> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn issue(&self) -> Result<RequestOrder<'_>, super::ClientError> {
        let mut state = self.state();
        if state.display {
            return Err(super::ClientError::DisplayReadPending);
        }
        state.issued = state
            .issued
            .checked_add(1)
            .ok_or_else(|| super::ClientError::Usage("own request order exhausted".into()))?;
        state.active += 1;
        Ok(RequestOrder {
            reads: self,
            order: state.issued,
        })
    }

    pub(crate) fn reserve_display(&self) -> bool {
        let mut state = self.state();
        if state.active != 0 || state.display || !state.pending.is_empty() {
            return false;
        }
        state.display = true;
        true
    }

    /// A reserved transport owns the next observation exclusively. Release its
    /// place only when the store owner knows the terminal decision is durable.
    pub(crate) fn stored_display(&self, pending: bool, notice: Option<RecoveryNotice>) {
        let mut state = self.state();
        if state.display && !pending {
            // No other request could be in flight across this handoff. All subsequent
            // requests follow the notice (including a repeated temporary notice).
            state.notice = notice.map(|n| (state.issued, n));
        }
        state.display = pending;
    }

    pub(crate) fn display_pending(&self) -> bool {
        self.state().display
    }

    pub(crate) fn notice(&self) -> Option<RecoveryNotice> {
        let s = self.state();
        s.notice.map(|(_, n)| n).or_else(|| {
            s.pending.iter().find_map(|decision| match decision {
                Decision::Notice(notice) => *notice,
                Decision::Rollback => None,
            })
        })
    }

    pub(crate) fn rollback(&self) -> bool {
        self.state().rollback
    }

    pub(crate) fn held_generation(&self) -> Option<u64> {
        (self.rollback() || self.notice().is_some()).then_some(self.generation)
    }

    pub(crate) fn first(&self) -> Option<Decision> {
        self.state().pending.front().copied()
    }

    /// Only the state owner consumes changes, after its commit has been confirmed.
    pub(crate) fn committed(&self) {
        self.state().pending.pop_front();
    }

    pub(crate) fn observe(&self, order: u64, answer: OwnAnswer, observed_ms: u64) {
        let mut s = self.state();
        if s.rollback {
            return;
        }
        match answer {
            OwnAnswer::Notice { notice, time_ms } => {
                if order <= s.cleared
                    || notice.is_some_and(|n| {
                        n.generation > self.generation
                            || (n.generation < self.generation
                                && n.reason != NoticeReason::MarkLost)
                    })
                {
                    return;
                }
                let permanent = notice.is_some_and(|n| n.permanent);
                if s.headed > order {
                    if permanent {
                        s.rollback = true;
                        s.pending.push_back(Decision::Rollback);
                    } else {
                        s.cleared = s.cleared.max(s.headed);
                    }
                    return;
                }
                if let Some((held_order, old)) = s.notice
                    && (old.permanent || !permanent)
                {
                    // A repeated temporary notice still requires a success from a later request.
                    if !old.permanent {
                        s.notice = Some((held_order.max(order), old));
                    }
                    return;
                }
                let n = RecoveryNotice {
                    generation: self.generation,
                    reason: notice.map(|n| n.reason),
                    permanent,
                    first_seen_ms: s.notice.map_or(observed_ms, |(_, n)| n.first_seen_ms),
                    service_time_ms: time_ms,
                };
                s.notice = Some((order, n));
                s.pending.push_back(Decision::Notice(Some(n)));
            }
            OwnAnswer::Success(Some(generation)) if generation == self.generation => {
                s.headed = s.headed.max(order);
                if let Some((issued, held)) = s.notice
                    && order > issued
                {
                    if held.permanent {
                        s.rollback = true;
                        s.pending.push_back(Decision::Rollback);
                    } else {
                        s.notice = None;
                        s.cleared = order;
                        s.pending.push_back(Decision::Notice(None));
                    }
                }
            }
            _ => {}
        }
    }
}

/// Dropping a completed or cancelled network call releases its place before a portable display read.
pub(super) struct RequestOrder<'a> {
    reads: &'a OwnReads,
    pub(super) order: u64,
}
impl Drop for RequestOrder<'_> {
    fn drop(&mut self) {
        self.reads.state().active -= 1;
    }
}
