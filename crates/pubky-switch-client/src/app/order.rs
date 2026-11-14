//! The order each protocol is told things in (Switch spec 8.3).
//!
//! Every notice a protocol can't take yet is kept in feed order, and the app tells that
//! protocol nothing later until it takes it. With several protocols the rule holds per
//! protocol: one that owes a re-send or missed-entries call, or a listing of its
//! collections, is told nothing past the first of them, while the read goes on for the
//! others. [`App::may_tell`] is the one place that rule is decided. Every way the read tells
//! a protocol something asks it first:
//!
//! - a message entry, before its receive step (`apply`): held when told "not yet";
//! - a re-send, missed-entries or deny list call, before it is made (`hand_call`): owed
//!   behind the earlier call when told "not yet";
//! - a deny list gap, before it is told (`tell_deny_gap_if_owed`): it waits, and the read
//!   holds, while any protocol it goes to is told "not yet";
//! - a record write, a listed view or a view read again, before it is judged, marked or
//!   noted divergent for the protocol of its collection (`judge_write`): a feed write is
//!   held when told "not yet", and a listing leaves the collection out and owes that
//!   protocol a listing of its own;
//! - a record an upload marked, before it is read again at a read's end
//!   ([`App::may_reread`]): its mark stays, unread, while its protocol owes a call at or
//!   before the cursor or anything before the upload, or holds an item the cursor hasn't
//!   passed (`ghold/`), so it is read only after what comes before it;
//! - a duty event, as it is kept (`keep_duty_for`): one the gate refuses fails the commit,
//!   so no path keeps one past a call its protocol owes.
//!
//! The owed calls themselves are made in feed order by `retry_owed`, each protocol's
//! listing among them, and a protocol's first one still owed is where it is held
//! ([`App::owed_from`]).
//!
//! Not in feed order, and told at once ([`Place::Outside`]): what the host or a protocol asks
//! for with a call of its own (a read of a record, a listing it asks for, an own write's
//! answer, a message it sends), what the outbox, a kept batch, a provider change or a
//! restore reports, and what the app owes outside the feed and makes before the read hands
//! anything: the listing a join, a restore or a certificate never shown on this app's feed
//! owes, a provider loss's re-send question, and the opening of writes taken already once a
//! key comes. A protocol that owes a call is told those at the point it was held at,
//! before anything later.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::feed::{Owed, owed_place};
use super::state::{Tx, key};
use super::{App, AppError};

/// Where an item stands in feed order, as [`App::feed_order`] gives it.
pub(crate) type FeedOrder = (u8, u64, u64);

/// `listo/<name>`: a listing of the collections of protocol `name`, owed to it at a feed
/// position ([`OwedListing`]). A listing owed while it owed an earlier call left its
/// collections out; it is made in feed order among its owed calls (`retry_owed`).
pub(crate) const OWED_LISTING_PREFIX: &str = "listo/";

/// `listop/<name>`: how far the listing owed to protocol `name` got, in the commit of each
/// page it takes; deleted with it.
pub(crate) const OWED_LISTING_AT_PREFIX: &str = "listop/";

/// `ghold/<name>`: the furthest feed position, (generation, `seq`), of an item held for
/// protocol `name` because it owed something before it, in the commit of the page that
/// holds it; deleted in the commit of the page whose cursor passes it, every such item
/// before it passed too (the cursor stays before a held item).
pub(crate) const GATE_HELD_PREFIX: &str = "ghold/";

fn gate_held_key(name: &str) -> String {
    format!("{GATE_HELD_PREFIX}{name}")
}

pub(crate) fn owed_listing_key(name: &str) -> String {
    format!("{OWED_LISTING_PREFIX}{name}")
}

pub(crate) fn owed_listing_at_key(name: &str) -> String {
    format!("{OWED_LISTING_AT_PREFIX}{name}")
}

/// A listing of one protocol's collections, owed to it at the feed item whose handling
/// owed it (`generation`, `seq`). One a protocol is owed again while it holds one keeps
/// the earlier position and starts over: made later, it reads the records as they stand
/// then, and the protocol's later items follow it in feed order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwedListing {
    pub(crate) generation: u64,
    pub(crate) seq: u64,
}

/// Where something the app would tell a protocol stands in the order it tells things.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Place {
    /// Not in feed order (the module docs list what): told at once.
    Outside,
    /// The feed item at this place, or what its handling owes, such as the listing a
    /// `missed` item owes: told to a protocol that owes nothing before it. A call owed at
    /// this very item is the item's own: a `missed` item's listing goes with it.
    Item(FeedOrder),
    /// Noted after the item at this place, such as a deny list gap at the cursor: told to a
    /// protocol that owes nothing at or before it.
    After(FeedOrder),
}

impl App {
    /// Whether the app may tell protocol `protocol` something at `place` now, or, for
    /// `None`, something it can't place with one protocol (a record of a collection it
    /// can't tell): every protocol then (Switch spec 8.3). "Not yet" means a protocol owes
    /// a call or a listing before `place` ([`App::owed_from`]): the caller holds the item
    /// for it, and it is told once that protocol takes what it owes, in feed order.
    ///
    /// With one protocol a call it fails stops the read, so this only ever holds what no
    /// read reaches before the call is taken.
    pub(crate) fn may_tell(&self, protocol: Option<&str>, place: Place) -> bool {
        let allows = |name: &str| {
            let first = self.owed_from.get(name);
            match place {
                Place::Outside => true,
                Place::Item(at) => first.is_none_or(|first| at <= *first),
                Place::After(at) => first.is_none_or(|first| at < *first),
            }
        };
        match protocol {
            Some(name) => allows(name),
            None => self
                .protocols
                .iter()
                .all(|registered| allows(&registered.name)),
        }
    }

    /// Read again from the store where each protocol is first owed something
    /// ([`App::owed_from`]): its first owed call (`owed/`) or owed listing (`listo/`), in
    /// feed order. Made at the start of each read, before anything is handed, and after the
    /// owed calls are made.
    pub(crate) async fn refresh_owed_from(&mut self) -> Result<(), AppError> {
        let reader = self.reader();
        let calls = reader.scan::<Owed>(key::OWED_PREFIX).await?;
        let listings = reader.scan::<OwedListing>(OWED_LISTING_PREFIX).await?;
        let mut from: BTreeMap<String, FeedOrder> = BTreeMap::new();
        for (rest, owed) in calls {
            let (generation, seq) = owed_place(&rest)?;
            let at = self.feed_order(generation, seq);
            for name in owed.to {
                note_first(&mut from, name, at);
            }
        }
        for (name, listing) in listings {
            let at = self.feed_order(listing.generation, listing.seq);
            note_first(&mut from, name, at);
        }
        self.owed_from = from;
        Ok(())
    }

    /// Protocol `name` is owed something at `at`, in the read's open writes.
    pub(crate) fn note_owed(&mut self, name: &str, at: FeedOrder) {
        note_first(&mut self.owed_from, name.to_owned(), at);
    }

    /// Owe protocol `name` a listing of its collections at (`generation`, `seq`), in `tx`:
    /// a listing made while it owed an earlier call left them out. One it holds already
    /// keeps the earlier position; either way the listing starts over.
    pub(crate) async fn owe_listing_to(
        &mut self,
        name: &str,
        generation: u64,
        seq: u64,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let at = self.feed_order(generation, seq);
        let held: Option<OwedListing> = self.reader().get(&owed_listing_key(name)).await?;
        let listing = match held {
            Some(held) if self.feed_order(held.generation, held.seq) <= at => held,
            _ => OwedListing { generation, seq },
        };
        tx.put(&owed_listing_key(name), &listing)?;
        tx.delete(&owed_listing_at_key(name))?;
        self.note_owed(name, self.feed_order(listing.generation, listing.seq));
        Ok(())
    }

    /// Whether a record the `upload` transition at `at` marked may be read again now, at a
    /// read's end, and told to `protocol` (every protocol for `None`): the view read is the
    /// record as it stands then, so not while the protocol owes a call at or before the
    /// cursor, nor anything before the upload, nor while an item held for it
    /// (`ghold/<name>`) waits before the cursor (Switch spec 8.3). Once it takes what it
    /// owes and the cursor passes what was held for it, the read after reads it.
    pub(crate) async fn may_reread(
        &self,
        protocol: Option<&str>,
        at: FeedOrder,
    ) -> Result<bool, AppError> {
        let cursor = self.feed_order(self.state.cursor.generation, self.state.cursor.seq);
        if !self.may_tell(protocol, Place::After(cursor))
            || !self.may_tell(protocol, Place::Item(at))
        {
            return Ok(false);
        }
        let names = match protocol {
            Some(name) => vec![name.to_owned()],
            None => self.protocols.names(),
        };
        for name in names {
            if self.reader().exists(&gate_held_key(&name)).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Note, in `tx`, that the feed holds the item at (`generation`, `seq`) for `protocol`
    /// (every protocol for one the app can't place) because it owes something before it
    /// (`ghold/`).
    pub(crate) async fn note_gate_held(
        &self,
        protocol: Option<&str>,
        generation: u64,
        seq: u64,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let at = self.feed_order(generation, seq);
        let names = match protocol {
            Some(name) => vec![name.to_owned()],
            None => self.protocols.names(),
        };
        for name in names {
            let key = gate_held_key(&name);
            let held: Option<(u64, u64)> = match tx.pending_get(&key)? {
                Some(held) => held,
                None => self.reader().get(&key).await?,
            };
            if held.is_none_or(|(g, s)| self.feed_order(g, s) < at) {
                tx.put(&key, &(generation, seq))?;
            }
        }
        Ok(())
    }

    /// Forget, in `tx`, the items held for a protocol that the cursor has passed
    /// (`ghold/`): the commit of a page.
    pub(crate) async fn forget_gate_held_passed(&self, tx: &mut Tx) -> Result<(), AppError> {
        let cursor = self.feed_order(self.state.cursor.generation, self.state.cursor.seq);
        for (name, (generation, seq)) in self.reader().scan::<(u64, u64)>(GATE_HELD_PREFIX).await? {
            if tx.pending_state(&gate_held_key(&name)) != Some(true)
                && self.feed_order(generation, seq) <= cursor
            {
                tx.delete(&gate_held_key(&name))?;
            }
        }
        Ok(())
    }

    /// The listings owed to single protocols (`listo/`), by protocol name.
    pub(crate) async fn owed_listings(&self) -> Result<Vec<(String, OwedListing)>, AppError> {
        self.reader().scan::<OwedListing>(OWED_LISTING_PREFIX).await
    }
}

fn note_first(from: &mut BTreeMap<String, FeedOrder>, name: String, at: FeedOrder) {
    from.entry(name)
        .and_modify(|first| *first = (*first).min(at))
        .or_insert(at);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_order_note_first_keeps_the_earliest() {
        let mut from = BTreeMap::new();
        note_first(&mut from, "tasks".into(), (1, 0, 9));
        note_first(&mut from, "tasks".into(), (1, 0, 4));
        note_first(&mut from, "tasks".into(), (1, 0, 7));
        assert_eq!(from.get("tasks"), Some(&(1, 0, 4)));
    }
}
