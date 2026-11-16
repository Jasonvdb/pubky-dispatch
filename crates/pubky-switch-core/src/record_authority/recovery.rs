//! Record witnesses and proposed cursor changes (Switch record lineage 7).

use serde_json::json;

use crate::Result;
use crate::enc::b64;
use crate::error::invalid;
use crate::json::MAX_INT;
use crate::ops::{CursorMove, Position, Refusal, check_cursor};
use crate::records::{IdentityDoc, VersionOrder};

/// Stored recovery-barrier facts, checked by [`RecordRecovery::restore`].
///
/// These fields alone do not authenticate the source or prove record absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryBarrier {
    /// The provider-loss recovery transition's position.
    pub position: Position,
    /// Fixed witness App IDs, sorted by decoded bytes, each once.
    pub witnesses: Vec<[u8; 16]>,
    /// Completed witnesses, sorted by decoded bytes, each once.
    pub complete: Vec<[u8; 16]>,
}

/// Account-local exclusions from currently applicable record witnesses.
///
/// The caller supplies the account's actual durable revocation and departure facts.
/// Missing registration, cursor lag and offline status are not exclusions.
#[derive(Clone, Copy, Debug)]
pub struct WitnessExclusions<'a> {
    /// App IDs revoked at the account.
    pub revoked: &'a [[u8; 16]],
    /// App IDs that departed the account.
    pub departed: &'a [[u8; 16]],
}

/// Inputs to one proposed cursor change, after request authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryCursor {
    /// The requested cursor position.
    pub position: Position,
    /// The exact barrier the caller says its record work completes.
    pub records_complete: Option<Position>,
    /// The cursor held for this caller in the same account transaction.
    pub held: Option<Position>,
    /// The newest sequence number given out before the batch.
    pub newest: u64,
    /// The generation whose sequence the current generation continues, if any.
    ///
    /// This comes from the account's verified transition state, not from the request.
    pub continued_from: Option<u64>,
}

/// A proposed barrier and cursor to persist together after the whole batch succeeds.
///
/// Producing this value neither changes the held model nor commits anything. The caller
/// must discard it on any batch failure, and must not acknowledge local completion after
/// an unknown commit outcome (Switch record lineage 7).
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RecoveryCursorProposal {
    recovery: RecordRecovery,
    cursor: Position,
}

impl RecoveryCursorProposal {
    /// The proposed recovery state. It is not evidence of a successful commit.
    pub fn recovery(&self) -> &RecordRecovery {
        &self.recovery
    }

    /// The proposed cursor, retained at its old position for a repeated/older request.
    pub fn cursor(&self) -> Position {
        self.cursor
    }

    /// Take both proposed values for the same durable transaction.
    pub fn into_parts(self) -> (RecordRecovery, Position) {
        (self.recovery, self.cursor)
    }
}

/// A checked fixed witness set with its verified originating identity document.
///
/// This model supplies recovery decisions, not record absence or reader authority. The
/// caller still authenticates requests, checks account/certificate standing and all batch
/// operations, and commits cursor and completion atomically. Only the app can account for
/// all its retained record duties before requesting completion.
///
/// There is no default or missing-source constructor: no barrier is valid only for a
/// history without provider loss, never as a substitute for unavailable provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordRecovery {
    source: IdentityDoc,
    barrier: RecoveryBarrier,
}

impl RecordRecovery {
    /// Capture the witnesses of a provider-loss recovery transition, all incomplete.
    ///
    /// The caller establishes that this document is the one applied at the supplied
    /// transition. This checks its identity, immediate lost generation and first sequence
    /// position (Switch spec 12.6, record lineage 7); it does not verify a chain proof.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for inconsistent source facts or too many witnesses.
    pub fn start(
        identity: &[u8; 32],
        source: IdentityDoc,
        position: Position,
        app_limit: usize,
    ) -> Result<Self> {
        let witnesses = source_witnesses(identity, &source, position, app_limit)?;
        Ok(Self {
            source,
            barrier: RecoveryBarrier {
                position,
                witnesses,
                complete: Vec::new(),
            },
        })
    }

    /// Check retained facts against their verified loss document without resetting bits.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for a wrong source, noncanonical membership or completion
    /// outside the fixed witness set (Switch record lineage 7).
    pub fn restore(
        identity: &[u8; 32],
        source: IdentityDoc,
        barrier: RecoveryBarrier,
        app_limit: usize,
    ) -> Result<Self> {
        let witnesses = source_witnesses(identity, &source, barrier.position, app_limit)?;
        if barrier.witnesses != witnesses {
            return invalid("Switch record lineage 7: witnesses differ from the loss document");
        }
        if barrier
            .complete
            .windows(2)
            .any(|w| matches!(w, [a, b] if a >= b))
            || barrier
                .complete
                .iter()
                .any(|app| witnesses.binary_search(app).is_err())
        {
            return invalid("Switch record lineage 7: completion is not a sorted witness subset");
        }
        Ok(Self { source, barrier })
    }

    /// The exact verified document that fixed membership and the lost-generation boundary.
    pub fn source(&self) -> &IdentityDoc {
        &self.source
    }

    /// The checked barrier facts, including completed bits of currently excluded witnesses.
    pub fn barrier(&self) -> &RecoveryBarrier {
        &self.barrier
    }

    /// Return incomplete witnesses that are currently listed and not revoked or departed.
    ///
    /// A listed app's open renewal is the same witness, not another bit. Removal or
    /// departure does not change membership/completion; an incomplete return counts again.
    /// This list alone does not decide the operation-specific birth exception or absence
    /// (Switch record lineage 7, record origins 2.2).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if the current document is of another identity, is older
    /// or equivocal, or has another provider-loss boundary.
    pub fn incomplete(
        &self,
        current: &IdentityDoc,
        exclusions: WitnessExclusions<'_>,
    ) -> Result<Vec<[u8; 16]>> {
        self.check_current(current)?;
        Ok(self
            .barrier
            .witnesses
            .iter()
            .filter(|app| {
                !self.completed(app)
                    && current.listed_cert(app).is_some()
                    && !current.lists_removed(app)
                    && !exclusions.revoked.contains(app)
                    && !exclusions.departed.contains(app)
            })
            .copied()
            .collect())
    }

    /// Propose a cursor and its witness completion without changing the held state.
    ///
    /// `caller` is the authenticated own app. Request permission, actual upload accounting
    /// and successful application of the entire batch remain caller obligations. Sequence
    /// facts must come from the same held account state as this barrier.
    ///
    /// # Errors
    ///
    /// `400 bad_request` for inconsistent input, a non-witness completion or an unreached
    /// barrier; `409 conflict` with the current barrier for a wrong completion position or
    /// an incomplete witness crossing without completion (Switch record lineage 7).
    pub fn propose_cursor(
        &self,
        current: &IdentityDoc,
        caller: &[u8; 16],
        request: RecoveryCursor,
    ) -> std::result::Result<RecoveryCursorProposal, Refusal> {
        self.check_current(current)?;
        self.check_cursor_state(current, caller, request)?;
        let movement = check_cursor(
            request.position,
            current.generation(),
            request.continued_from,
            request.newest,
            request.held.map(|p| p.seq),
        )?;
        let witness = self.barrier.witnesses.binary_search(caller).is_ok();
        if let Some(completion) = request.records_complete {
            if completion != self.barrier.position {
                return Err(self.conflict("Switch record lineage 7: another recovery barrier"));
            }
            if !witness || request.position.seq < self.barrier.position.seq {
                return Err(Refusal::bad_request(
                    "Switch record lineage 7: caller cannot complete this barrier at that cursor",
                ));
            }
        } else if witness
            && !self.completed(caller)
            && movement == CursorMove::Moves
            && request.position.seq >= self.barrier.position.seq
        {
            return Err(self.conflict("Switch record lineage 7: witness completion is required"));
        }
        let mut recovery = self.clone();
        if request.records_complete.is_some()
            && let Err(index) = recovery.barrier.complete.binary_search(caller)
        {
            recovery.barrier.complete.insert(index, *caller);
        }
        let cursor = match (movement, request.held) {
            (CursorMove::Stays, Some(held)) => held,
            _ => request.position,
        };
        Ok(RecoveryCursorProposal { recovery, cursor })
    }

    fn completed(&self, app: &[u8; 16]) -> bool {
        self.barrier.complete.binary_search(app).is_ok()
    }

    fn check_current(&self, current: &IdentityDoc) -> Result<()> {
        if current.identity() != self.source.identity()
            || matches!(
                self.source.compare(current),
                VersionOrder::Older | VersionOrder::Equivocation
            )
            || current.generation() > MAX_INT
            || current.body().recovery_from != self.source.body().recovery_from
        {
            return invalid(
                "Switch record lineage 7: current document does not continue this loss",
            );
        }
        Ok(())
    }

    fn check_cursor_state(
        &self,
        current: &IdentityDoc,
        caller: &[u8; 16],
        request: RecoveryCursor,
    ) -> Result<()> {
        let first = self.source.generation();
        if request.newest > MAX_INT
            || request.newest < self.barrier.position.seq
            || request
                .continued_from
                .is_some_and(|g| g < first || g >= current.generation())
            || request.held.is_some_and(|p| {
                p.generation < first
                    || p.generation > current.generation()
                    || p.seq > request.newest
                    || (self.barrier.witnesses.binary_search(caller).is_ok()
                        && !self.completed(caller)
                        && p.seq >= self.barrier.position.seq)
            })
        {
            return invalid("Switch record lineage 7: inconsistent held cursor sequence");
        }
        Ok(())
    }

    fn conflict(&self, reason: &str) -> Refusal {
        Refusal::conflict(reason).with_current(json!({
            "record_recovery": {
                "position": self.barrier.position.to_string(),
                "witnesses": self.barrier.witnesses.iter().map(|app| b64(app)).collect::<Vec<_>>(),
                "complete": self.barrier.complete.iter().map(|app| b64(app)).collect::<Vec<_>>(),
            }
        }))
    }
}

fn source_witnesses(
    identity: &[u8; 32],
    source: &IdentityDoc,
    position: Position,
    app_limit: usize,
) -> Result<Vec<[u8; 16]>> {
    if &source.identity() != identity
        || source.generation() <= 1
        || source.generation() > MAX_INT
        || source.body().recovery_from != source.generation().checked_sub(1)
        || position.generation != source.generation()
        || position.seq != 1
        || source.body().apps.len() > app_limit
    {
        return invalid("Switch record lineage 7: inconsistent recovery source or witness limit");
    }
    let mut witnesses: Vec<_> = source.body().apps.iter().map(|app| app.app_id).collect();
    witnesses.sort_unstable();
    Ok(witnesses)
}
