//! The order each protocol is told things in (Switch spec 8.3).
//!
//! Every notice a protocol can't take yet is kept in feed order, and the app tells that
//! protocol nothing later until it takes it. With several protocols the rule holds per
//! protocol, and one value per protocol decides it: how far that protocol has been told, in
//! feed order (`told/<name>`, [`Told`]). A protocol is told an item only when its position
//! has reached the item: everything the read covered before it was told to it. One that
//! doesn't take an item stays right before it, and is told nothing later, while the read
//! goes on for the others. [`App::may_tell`] is that one comparison, and every way the read
//! tells a protocol something asks it:
//!
//! - a message entry, before anything is done with it, its checks included
//!   (`check_and_apply`): held, the cursor staying before it, for a protocol whose position
//!   is behind it. So no entry is stored locally, dropped or found a duplicate for a
//!   protocol that is behind;
//! - a re-send, missed-entries or deny list call (`hand_call`): kept for the protocol
//!   (`owed/`, naming it) when it is behind the item or fails the call. A deny list change
//!   kept for a protocol stops the read there for every protocol, at that read and at each
//!   later one that reaches its item, so the cursor never passes a deny list change a
//!   protocol wasn't handed;
//! - a deny list gap (`tell_deny_gap_if_owed`): told once every protocol is told through
//!   its position; the read holds meanwhile;
//! - a record write the feed shows (`judge_write`), for the protocol of its collection, or
//!   for every protocol when the app can't place it: held like an entry;
//! - a listing a feed item owes (`list_due`): made for a protocol once it is told through
//!   everything before that item;
//! - what isn't in feed order: an entry stored locally and tried again, a record an upload
//!   marked and read again at a read's end, a record opened once its key comes. These reach
//!   only a protocol that is with the read, told through everything it covered.
//!
//! What the cursor passes without a protocol taking it is kept with the protocols it is
//! still for: a call (`owed/`), a listing (`list_due`), the deny list gap (`dgap`). Those
//! hold the content; the position holds the order. At the start of each read they are told
//! in feed order ([`App::settle_told`], `retry_owed`), a protocol's listing before a call at
//! the same item: the listing an item owes is not held by that item's own call, with one
//! protocol or several. A kept call or listing past the cursor waits for the read to reach
//! its item: the protocols it names stay right before it, and are told what is kept at the
//! start of the read after, whether or not the cursor got there. The item itself tells them
//! nothing new: a kept call's item is passed whole, and an item a listing is kept at was
//! handled for them when the read first met it (`asked/`, `seen/`, record versions).
//! A protocol a listing is still owed to is told nothing that isn't in feed order either.
//!
//! A read that stopped on its pages goes on from where it got (`feed_at`), unless a
//! protocol is behind that with a feed item next: then it starts at that protocol's
//! position, never before the cursor, so a protocol catches up in order before it is told
//! anything further on. What the read meets again on the way is not handled twice: an entry
//! by `seen/` and its processed pair, a call by `asked/` and the protocols its kept form
//! names, a record write by its version.
//!
//! The position is written in the commit of what moves it: a page's, a kept call's, a
//! listing's. One that lags behind what was committed, as after a crash between an effect's
//! commit and its page's, only starts the next read further back.
//!
//! A view read for a listing, or read again after an upload, shows the record as it stands
//! then, which may be later than the item that owed the read.
//!
//! Not in feed order, and told at once: what the host or a protocol asks for with a call
//! of its own (a read of a record, a listing it asks for, an own write's answer, a message
//! it sends), what the outbox, a kept batch, a provider change or a restore reports, the
//! listing a join, a restore or a certificate taken owes (made for every protocol before a
//! read hands anything), and a duty event about an entry stored locally: such an entry was
//! stored when its protocol's position had reached it, so it lies in that protocol's past.
//! A receive step and a protocol's batch write only that protocol's own records
//! (`refuse_foreign_target`), so none of those changes what another protocol sees.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::state::Tx;
use super::{App, AppError};

/// Where an item stands in feed order, as [`App::feed_order`] gives it.
pub(crate) type FeedOrder = (u8, u64, u64);

/// `told/<name>`: how far protocol `name` has been told ([`Told`]).
pub(crate) const TOLD_PREFIX: &str = "told/";

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

    /// Whether the app may tell protocol `name` something now (Switch spec 8.3): it has
    /// been told everything the read covered before it. Inside a page that is the item the
    /// walk handles; outside one, something that isn't in feed order, which reaches only a
    /// protocol that is with the read. "Not yet" means the caller holds or keeps the thing
    /// for it.
    ///
    /// Outside a page, a protocol whose listing the read could not make yet is told
    /// nothing: the listing comes before anything else.
    ///
    /// With one protocol this is false only once that protocol didn't take an item, and
    /// the read stops there.
    pub(crate) fn may_tell(&self, name: &str) -> bool {
        if self.walk.is_none() && self.listing_names.contains(name) {
            return false;
        }
        self.told_order(name) >= self.walked()
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
    /// `identity.json` the app holds, which no read writes, is a corrupt store: taken as
    /// it is, it would stand as the read's front, and no other protocol would ever be
    /// level with it.
    pub(crate) async fn load_told(&mut self) -> Result<(), AppError> {
        let stored = self.reader().scan::<Told>(TOLD_PREFIX).await?;
        let mut told = Positions::new();
        for (name, at) in stored {
            if !self.protocols.contains(&name) || self.feed_order(at.generation, at.seq).0 == 2 {
                return Err(AppError::Store(crate::error::StoreError::Corrupt));
            }
            told.insert(name, (at.generation, at.seq));
        }
        self.told = told;
        self.told_kept = self.told.clone();
        self.walk = None;
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

    /// The protocols that are stuck on a kept thing: one names them right after their
    /// position. They can't move in the walk until a read's start tells it to them.
    pub(crate) fn stuck_on(&self, kept: &[Kept]) -> BTreeSet<String> {
        let mut stuck = BTreeSet::new();
        for name in self.protocols.names() {
            let (generation, seq) = self.told(&name);
            let next = self.feed_order(generation, seq.saturating_add(1));
            if kept.iter().any(|kept| {
                kept.names.contains(&name) && self.feed_order(kept.generation, kept.seq) == next
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
