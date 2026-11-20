//! The app delivers feed items in order to each protocol (Switch spec 8.3). If one
//! protocol falls behind, the others can continue. A deny list change or gap stops
//! delivery to all protocols at that position.
//!
//! # What waits for a protocol
//!
//! `told/<name>` ([`Told`]) records how far the protocol has processed the feed.
//! [`App::may_tell`] checks that position and outstanding work before delivery.
//!
//! - Messages wait before validation, duplicate detection, local storage or disposal.
//!   A record write waits for the owner of its collection, or for all protocols if the
//!   app cannot identify the owner.
//! - A resend, missed-entries or deny list callback that fails or cannot run stays in
//!   `owed/` with its remaining owners. A listing due at a feed item stays in `list_due`.
//!   On retry, each protocol completes its listing before a call at the same position,
//!   including position zero. A deny list gap (`dgap`) waits for every owner's
//!   prerequisites.
//! - Retrying a locally stored entry, rereading a record marked by an upload, or opening
//!   a record with a newly available key waits until the owner has caught up with the
//!   read and completed its outstanding listing.
//!
//! # Resuming a read
//!
//! At the start of a read the app reconstructs each protocol's position
//! ([`App::settle_told`]) and retries eligible work in feed order. A retained call or
//! listing ahead of the cursor waits for the read to deliver earlier items to its owners.
//! A subsequent read can then retry the work even if the shared cursor still lags.
//!
//! A page walk resumes at `feed_at`, or at an earlier protocol position if that protocol
//! has a feed item to process. The walk starts no earlier than the cursor. A page,
//! callback or listing commits the position it advances. After a crash, the walk may
//! revisit an item whose effects already committed. `seen/` and the processed pair
//! identify a handled message, `asked/` and the remaining owners identify a handled
//! call, and the stored version identifies a handled record write.
//!
//! # Work outside feed order
//!
//! Explicit record reads and listings, replies to the app's own writes, outgoing messages,
//! and outbox, kept-batch, provider-change and restore reports follow their own calls.
//! A join, restore or new certificate requires listings before feed delivery begins.
//! A duty about a locally stored entry concerns an entry the owner already reached.
//!
//! A listing or post-upload read returns the record as it stands at read time. A receive
//! step can read another protocol's current record independently of that owner's
//! notifications. Receive steps and protocol batches can write only their owner's records.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::state::{Tx, key};
use super::{App, AppError};

/// Where an item stands in feed order, as [`App::feed_order`] gives it.
pub(crate) type FeedOrder = (u8, u64, u64);

/// `told/<name>`: how far protocol `name` has been told ([`Told`]).
pub(crate) const TOLD_PREFIX: &str = "told/";

/// No more events or calls are due to a departed app's protocols (Switch spec 12.3).
pub(super) fn clear_on_leave(tx: &mut Tx) -> Result<(), AppError> {
    tx.delete_prefixes(&[key::DUTY_PREFIX, key::OWED_PREFIX, TOLD_PREFIX])
}

fn told_key(name: &str) -> String {
    format!("{TOLD_PREFIX}{name}")
}

/// How far a protocol has been told: everything the read covered at or before
/// (`generation`, `seq`) that was for it. Absent for a protocol at the cursor, as after a
/// join or a restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Told {
    pub(crate) generation: u64,
    pub(crate) seq: u64,
}

/// Where the read's walk of the feed stands, for [`App::may_tell`]: inside a page, it
/// covered everything at or before this `seq` of the cursor's generation, and handles the
/// item after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Walk(pub(crate) u64);

/// Something the cursor passed, or may pass, that is kept for the protocols it names
/// until each takes it: a call (`owed/`) or the listing a feed item owes (`list_due`).
#[derive(Clone, Debug)]
pub(crate) struct Kept {
    pub(crate) generation: u64,
    pub(crate) seq: u64,
    pub(crate) names: Vec<String>,
    /// A call, whose item the walk doesn't handle again; not a listing.
    pub(crate) call: bool,
    /// A higher held cursor reported at this position, distinct from its ordinary item.
    pub(crate) held_gap: Option<u64>,
    /// A deny list change, which no protocol is handed anything past while it is kept.
    pub(crate) deny: bool,
}

/// What is kept past the cursor at one `seq` of the cursor's sequence: the protocols it
/// names, and whether a call is among it.
#[derive(Clone, Debug, Default)]
pub(crate) struct KeptAhead {
    pub(crate) names: Vec<String>,
    pub(crate) call: bool,
    /// A deny list change is among it: the read stops there for every protocol.
    pub(crate) deny: bool,
}

/// The callback's place among prerequisites at one feed position (Switch spec 8.3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handover {
    /// The listing precedes a call about the same item.
    Listing,
    /// A retained call follows its listing and all earlier calls.
    Call,
    /// Everything through the position precedes the next handover.
    Through,
}

impl App {
    /// How far protocol `name` has been told, (generation, `seq`).
    pub(crate) fn told(&self, name: &str) -> (u64, u64) {
        self.told
            .get(name)
            .copied()
            .unwrap_or((self.state.cursor.generation, self.state.cursor.seq))
    }

    fn told_order(&self, name: &str) -> FeedOrder {
        let (generation, seq) = self.told(name);
        self.feed_order(generation, seq)
    }

    /// The read's front: the furthest any protocol has been told through.
    fn front(&self) -> FeedOrder {
        let cursor = self.feed_order(self.state.cursor.generation, self.state.cursor.seq);
        self.protocols
            .iter()
            .map(|registered| self.told_order(&registered.name))
            .max()
            .unwrap_or(cursor)
    }

    /// The position a protocol must be told through to be told something now: inside a
    /// page, where the walk stands; otherwise the read's front.
    fn walked(&self) -> FeedOrder {
        match self.walk {
            Some(Walk(seq)) => self.feed_order(self.state.cursor.generation, seq),
            None => self.front(),
        }
    }

    /// May the app deliver to `name` at the current point in the read? On a page,
    /// check the position the walk has covered. Outside a page, require the protocol
    /// to have reached the front of the read and finished its outstanding listing.
    /// If the protocol is behind, the caller must hold the item or retain the call.
    pub(crate) fn may_tell(&self, name: &str) -> bool {
        if self.walk.is_none() && self.listing_due.at(name).is_some() {
            return false;
        }
        self.ready_at(name, self.walked(), Handover::Through)
    }

    /// A listing or retained call requires progress through the preceding item.
    /// A call also waits for a listing due at or before its position. A handover
    /// through `at` requires progress through `at` and completion of calls and record
    /// deletions there. Earlier calls and deletions block all three. Check pending
    /// work explicitly even at zero, where there is no preceding position (Switch spec 8.3).
    pub(crate) fn ready_at(&self, name: &str, at: FeedOrder, handover: Handover) -> bool {
        let through = match handover {
            Handover::Listing | Handover::Call => (at.0, at.1, at.2.saturating_sub(1)),
            Handover::Through => at,
        };
        if self.told_order(name) < through {
            return false;
        }
        if handover != Handover::Listing
            && self.listing_due.at(name).is_some_and(|listing| {
                listing.is_none_or(|(generation, seq)| self.feed_order(generation, seq) <= at)
            })
        {
            return false;
        }
        if self.owed_deletions().any(|d| {
            let order = self.feed_order(d.generation, d.seq);
            d.owner == name && (order < at || (order == at && handover == Handover::Through))
        }) {
            return false;
        }
        !self.pending_calls.iter().any(|kept| {
            let order = self.feed_order(kept.generation, kept.seq);
            kept.names.iter().any(|owner| owner == name)
                && (order < at || (handover == Handover::Through && order == at))
        })
    }

    /// A new retained call becomes a prerequisite before the read can hand over the
    /// next item, including a call kept at sequence zero (Switch spec 8.3).
    pub(crate) fn note_pending_call(&mut self, call: Kept) {
        self.pending_calls.retain(|kept| {
            (kept.generation, kept.seq, kept.held_gap) != (call.generation, call.seq, call.held_gap)
        });
        self.pending_calls.push(call);
    }

    /// [`App::may_tell`] for the protocol of a record's collection, or, for `None`, a
    /// record the app can't place with one protocol: every protocol then.
    pub(crate) fn may_tell_of(&self, protocol: Option<&str>) -> bool {
        match protocol {
            Some(name) => self.may_tell(name),
            None => self
                .protocols
                .iter()
                .all(|registered| self.may_tell(&registered.name)),
        }
    }

    /// Whether any protocol may be told the next item: a page with none stops.
    pub(crate) fn any_in_step(&self) -> bool {
        self.protocols
            .iter()
            .any(|registered| self.may_tell(&registered.name))
    }

    /// The walk handled the item at `seq`: each protocol that was in step with it, or is
    /// one of `run` (waiting only for the listing the item before owes), moves to `seq`,
    /// but one of `left`, which didn't take it, stays right before it.
    pub(crate) fn step_told(&mut self, seq: u64, left: &BTreeSet<String>, run: &BTreeSet<String>) {
        let generation = self.state.cursor.generation;
        let at = self.feed_order(generation, seq);
        let names = self.protocols.names();
        for name in names {
            if !self.may_tell(&name) && !run.contains(&name) {
                continue;
            }
            if left.contains(&name) {
                self.told.insert(name, (generation, seq.saturating_sub(1)));
            } else if self.told_order(&name) < at {
                self.told.insert(name, (generation, seq));
            }
        }
        if self.walk.is_some() && self.walked() < at {
            self.walk = Some(Walk(seq));
        }
    }

    /// Protocol `name` took the kept thing at (`generation`, `seq`): it is told through it.
    pub(crate) fn told_through(&mut self, name: &str, generation: u64, seq: u64) {
        if self.told_order(name) < self.feed_order(generation, seq) {
            self.told.insert(name.to_owned(), (generation, seq));
        }
    }

    /// Write, in `tx`, the positions that moved since they were last written (`told/`).
    pub(crate) fn put_told(&mut self, tx: &mut Tx) -> Result<(), AppError> {
        for (name, at) in &self.told {
            if self.told_kept.get(name) == Some(at) {
                continue;
            }
            let told = Told {
                generation: at.0,
                seq: at.1,
            };
            tx.put(&told_key(name), &told)?;
        }
        self.told_kept = self.told.clone();
        Ok(())
    }

    /// Read the positions from the store (`told/`), as a call that follows a reload does.
    /// One of a protocol that isn't registered, or of a generation past the newest own
    /// `identity.json` the app holds, or beyond every authenticated feed page read and the
    /// cursor, which no read writes, is a corrupt store: taken as
    /// it is, it would stand as the read's front, and no other protocol would ever be
    /// level with it.
    pub(crate) async fn load_told(&mut self) -> Result<(), AppError> {
        let stored = self.reader().scan::<Told>(TOLD_PREFIX).await?;
        let mut read = self.feed_order(self.state.cursor.generation, self.state.cursor.seq);
        if let Some(chain) = &self.state.chain {
            let scanned = self.feed_order(chain.read_through.0, chain.read_through.1);
            if scanned.0 == 2 {
                return Err(AppError::Store(crate::error::StoreError::Corrupt));
            }
            read = read.max(scanned);
        }
        let mut told = Positions::new();
        for (name, at) in stored {
            let order = self.feed_order(at.generation, at.seq);
            if !self.protocols.contains(&name) || order.0 == 2 || order > read {
                return Err(AppError::Store(crate::error::StoreError::Corrupt));
            }
            told.insert(name, (at.generation, at.seq));
        }
        self.told = told;
        self.told_kept = self.told.clone();
        self.walk = None;
        self.pending_calls.clear();
        self.told_loaded = true;
        Ok(())
    }

    /// Set each protocol's position by what is kept for it, `kept` in feed order
    /// ([`Kept`]): right before the first kept thing that names it, or, when that is past
    /// the cursor, between the cursor and it; at the cursor or further when nothing names
    /// it. Everything else for it at or before the cursor was told: the cursor never
    /// passes an item a protocol didn't take unless the item is kept for it.
    ///
    /// The one place this is derived, at each read's start and as the kept things are
    /// taken, so a restore, a provider change and a crash all leave it right.
    pub(crate) fn settle_told(&mut self, kept: &[Kept]) {
        self.pending_calls = kept.iter().filter(|item| item.call).cloned().collect();
        let cursor = (self.state.cursor.generation, self.state.cursor.seq);
        let cursor_at = self.feed_order(cursor.0, cursor.1);
        for name in self.protocols.names() {
            let held = self.told(&name);
            let at_least = if self.feed_order(held.0, held.1) < cursor_at {
                cursor
            } else {
                held
            };
            let first = kept
                .iter()
                .find(|kept| kept.names.contains(&name))
                .map(|kept| (kept.generation, kept.seq.saturating_sub(1)));
            let settled = match first {
                Some(before)
                    if self.feed_order(before.0, before.1)
                        < self.feed_order(at_least.0, at_least.1) =>
                {
                    before
                }
                _ => at_least,
            };
            self.told.insert(name, settled);
        }
    }

    /// The protocols whose next prerequisite is kept. Compare its preceding position,
    /// including zero itself when it has no predecessor: it still must be taken before
    /// the protocol can move in the walk (Switch spec 8.3).
    pub(crate) fn stuck_on(&self, kept: &[Kept]) -> BTreeSet<String> {
        let mut stuck = BTreeSet::new();
        for name in self.protocols.names() {
            let (generation, seq) = self.told(&name);
            let at = self.feed_order(generation, seq);
            if kept.iter().any(|kept| {
                kept.names.contains(&name)
                    && self.feed_order(kept.generation, kept.seq.saturating_sub(1)) == at
            }) {
                stuck.insert(name);
            }
        }
        stuck
    }

    /// Where the walk starts: at `from`, a `seq` of the cursor's generation, or at the
    /// position of a protocol behind it that can move, never before the cursor.
    pub(crate) fn walk_start(&self, from: u64, stuck: &BTreeSet<String>) -> u64 {
        let cursor = self.state.cursor;
        let cursor_at = self.feed_order(cursor.generation, cursor.seq);
        let mut start = from;
        for name in self.protocols.names() {
            if stuck.contains(&name) {
                continue;
            }
            let (generation, seq) = self.told(&name);
            let at = self.feed_order(generation, seq);
            // One behind the cursor waits for what is kept for it; one of another sequence
            // has nothing to walk here.
            if at < cursor_at || at.0 != cursor_at.0 {
                continue;
            }
            start = start.min(seq.max(cursor.seq));
        }
        start
    }
}

/// The in-memory positions, by protocol name.
pub(crate) type Positions = BTreeMap<String, (u64, u64)>;
