//! The seen marks a backup carries and a restore installs (Switch spec 8.2, 12.4 "Seen
//! marks"): every record's entry the store holds at `hw/<key>`, a mark or the end of its
//! lifetime, each at the version of the write it was taken at; the records whose marks a
//! backup left out for room; and, for each protocol, the fact that a restore couldn't keep
//! every mark the backup knew of, with the feed position it holds from.

use std::collections::BTreeMap;

use pubky_switch_core::enc::{b64, serde_b64, unb64, unb64_array};
use pubky_switch_core::ops::RecordVersion;
use serde::{Deserialize, Serialize};

use super::protocol::MAX_SEEN_MARK_BYTES;
use super::protocols::ProtocolSet;
use super::records::{self, SEEN_PREFIX};
use super::state::{Reader, Tx, encode};
use super::{AppError, AppEvent, FeedPosition, corrupt};
use crate::store::MAX_BATCH_BYTES;

/// The protocols' facts that a restore couldn't keep every mark ([`LeftOut`]), by protocol.
const FACT_KEY: &str = "hwl";

/// A mark's bytes in base64, `null` for an ended lifetime.
mod mark_b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        mark: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match mark {
            Some(mark) => serializer.serialize_some(&super::b64(mark)),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| super::unb64(&text).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// A record's entry at `hw/<key>` (Switch spec 8.2, 12.4): the protocol's mark of what the
/// app has seen in it, or, with no mark, the end of the mark's lifetime at a verified
/// current deletion, which reads as no mark; each at the version of the write it was taken
/// at, with the record's collection. Where two entries of one record meet, the later
/// version's is kept, the store's at an equal one. Its `Debug` shows only the mark's size.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SeenMark {
    #[serde(with = "mark_b64")]
    mark: Option<Vec<u8>>,
    generation: u64,
    version: u64,
    collection: String,
}

impl std::fmt::Debug for SeenMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SeenMark({} bytes)", self.len())
    }
}

impl SeenMark {
    /// The mark `mark` of a record of `collection`, after its write at `version`.
    pub(crate) fn taken(mark: Vec<u8>, version: RecordVersion, collection: &str) -> Self {
        Self {
            mark: Some(mark),
            generation: version.generation,
            version: version.version,
            collection: collection.to_owned(),
        }
    }

    /// The end of the mark's lifetime at the verified current deletion at `version`.
    pub(crate) fn ended(version: RecordVersion, collection: &str) -> Self {
        Self {
            mark: None,
            generation: version.generation,
            version: version.version,
            collection: collection.to_owned(),
        }
    }

    /// What the app has seen, as the protocol's hooks get it: `None` for an ended lifetime.
    pub(crate) fn seen(&self) -> Option<&[u8]> {
        self.mark.as_deref()
    }

    /// [`Self::seen`], owned.
    pub(crate) fn into_seen(self) -> Option<Vec<u8>> {
        self.mark
    }

    /// The size of the mark.
    pub(crate) fn len(&self) -> usize {
        self.mark.as_ref().map_or(0, Vec::len)
    }

    /// The version of the write the entry was taken at.
    pub(crate) fn at(&self) -> (u64, u64) {
        (self.generation, self.version)
    }
}

/// Correct, in `tx`, the version of record `key`'s entry `entry` taken at `stale`, which a
/// proof of the same write puts at `proven`: the entry is of that write, and the later
/// version wins where two entries meet (Switch spec 12.4 "Seen marks").
pub(crate) fn reversion(
    tx: &mut Tx,
    key: &[u8; 32],
    entry: &SeenMark,
    stale: RecordVersion,
    proven: RecordVersion,
) -> Result<(), AppError> {
    if stale == proven || entry.at() != (stale.generation, stale.version) {
        return Ok(());
    }
    let corrected = SeenMark {
        generation: proven.generation,
        version: proven.version,
        ..entry.clone()
    };
    tx.put(&records::seen_key(key), &corrected)
}

/// A record's entry as a backup carries it.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CarriedMark {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    entry: SeenMark,
}

impl std::fmt::Debug for CarriedMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CarriedMark({} bytes)", self.entry.len())
    }
}

/// A record whose entry a backup left out, since it didn't fit the restore's one commit,
/// with the version of the write that entry was taken at and the record's collection.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LeftOutMark {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    generation: u64,
    version: u64,
    collection: String,
}

impl std::fmt::Debug for LeftOutMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LeftOutMark(..)")
    }
}

impl CarriedMark {
    /// This entry as a backup left it out.
    pub(crate) fn left_out(&self) -> LeftOutMark {
        LeftOutMark {
            key: self.key,
            generation: self.entry.generation,
            version: self.entry.version,
            collection: self.entry.collection.clone(),
        }
    }

    /// The record key.
    pub(crate) fn key(&self) -> [u8; 32] {
        self.key
    }
}

impl LeftOutMark {
    /// The record key.
    pub(crate) fn key(&self) -> [u8; 32] {
        self.key
    }

    fn at(&self) -> (u64, u64) {
        (self.generation, self.version)
    }
}

/// That a restore couldn't keep every mark the backup knew of, for one protocol (Switch spec
/// 12.4): how many records it couldn't keep at most, the feed position it holds from, and
/// whether the protocol acknowledged it, which ends its telling at each open, not the fact.
/// A record of the protocol's collections with no mark, whose current write is no later than
/// the position, can't be checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LeftOut {
    records: u64,
    generation: u64,
    seq: u64,
    acknowledged: bool,
}

impl LeftOut {
    /// At most how many records one restore couldn't keep the marks of.
    #[cfg(test)]
    pub(crate) fn records(&self) -> u64 {
        self.records
    }

    /// The feed position it holds from.
    #[cfg(test)]
    pub(crate) fn position(&self) -> (u64, u64) {
        (self.generation, self.seq)
    }

    /// Whether the protocol acknowledged it.
    #[cfg(test)]
    pub(crate) fn acknowledged(&self) -> bool {
        self.acknowledged
    }

    /// A fact of `records` records from `(generation, seq)`, not acknowledged.
    #[cfg(test)]
    pub(crate) fn at(records: u64, generation: u64, seq: u64) -> Self {
        Self {
            records,
            generation,
            seq,
            acknowledged: false,
        }
    }
}

/// The facts of the protocols, by name: of every protocol, registered here or not.
pub(crate) type LeftOutFacts = BTreeMap<String, LeftOut>;

/// The facts as `reader`'s store keeps them.
pub(crate) async fn facts_of(reader: &Reader) -> Result<LeftOutFacts, AppError> {
    Ok(reader.get(FACT_KEY).await?.unwrap_or_default())
}

/// Remove the facts, at a leave (Switch spec 12.3): only a leave, or a restore of a backup
/// that left nothing out and carries none, ends them.
pub(super) fn clear_on_leave(tx: &mut Tx) -> Result<(), AppError> {
    tx.delete(FACT_KEY)
}

/// The informational events that tell each registered protocol of its fact not yet
/// acknowledged, raised at every open (Switch spec 12.4).
pub(crate) fn told_at_open(facts: &LeftOutFacts, protocols: &ProtocolSet) -> Vec<AppEvent> {
    facts
        .iter()
        .filter(|(protocol, fact)| !fact.acknowledged && protocols.contains(protocol))
        .map(|(protocol, fact)| AppEvent::SeenMarksLeftOut {
            protocol: protocol.clone(),
            records: fact.records,
            position: FeedPosition {
                generation: fact.generation,
                seq: fact.seq,
            },
        })
        .collect()
}

/// Every entry `reader` holds, from the same read as the rest of the backup.
pub(crate) async fn carry(reader: &Reader) -> Result<Vec<CarriedMark>, AppError> {
    let mut out = Vec::new();
    for (rest, entry) in reader.scan::<SeenMark>(SEEN_PREFIX).await? {
        let key = unb64_array::<32>(&rest).map_err(|_| corrupt())?;
        out.push(CarriedMark { key, entry });
    }
    Ok(out)
}

/// A backup's entries and the records it left out, checked: each record once, and no mark
/// over [`MAX_SEEN_MARK_BYTES`], which no app keeps.
pub(crate) fn check(carried: &[CarriedMark], left_out: &[LeftOutMark]) -> Result<(), AppError> {
    let invalid = |why: &str| AppError::InvalidData(format!("the backup: {why}"));
    let mut keys = std::collections::BTreeSet::new();
    for mark in carried {
        if mark.entry.len() > MAX_SEEN_MARK_BYTES {
            return Err(invalid("a seen mark it carries is over the bound"));
        }
        if !keys.insert(mark.key) {
            return Err(invalid("it carries two seen marks of one record"));
        }
    }
    if left_out.iter().any(|left| !keys.insert(left.key)) {
        return Err(invalid("a record's seen mark is both carried and left out"));
    }
    Ok(())
}

/// The protocols a record of `collection` is counted for: its owner, or every protocol
/// when none registered here owns it.
fn owners(protocols: &ProtocolSet, collection: &str) -> Vec<String> {
    match protocols.of_collection(collection) {
        Some(owner) => vec![owner.name.clone()],
        None => protocols.names(),
    }
}

/// The marks a restore installs: the backup's, or, in place, the later of the store's and
/// the backup's.
pub(crate) struct Installing {
    marks: Vec<CarriedMark>,
    /// The records whose backup entries the restore couldn't keep, beside those it leaves
    /// out for room: those the backup left out, and those at the store's version whose entry
    /// differs from the store's.
    unkept: Vec<LeftOutMark>,
    /// The backup's facts.
    facts: LeftOutFacts,
    /// In place, the store's facts, which the restore keeps beside the backup's unless the
    /// backup left nothing out and carries none.
    store_facts: LeftOutFacts,
}

/// What [`Installing::write`] left out for room, which a backup's check moves to the records
/// its backup left out.
pub(crate) struct Written {
    pub(crate) left: Vec<LeftOutMark>,
}

impl Installing {
    /// The backup's entries, onto an empty store, with the backup's facts.
    pub(crate) fn of_backup(
        carried: &[CarriedMark],
        left_out: &[LeftOutMark],
        facts: &LeftOutFacts,
    ) -> Self {
        Self {
            marks: carried.to_vec(),
            unkept: left_out.to_vec(),
            facts: facts.clone(),
            store_facts: LeftOutFacts::new(),
        }
    }

    /// In place, the store's entries beside the backup's (`old`): for a record both hold an
    /// entry of, the one at the later version is kept, the store's at an equal one, which,
    /// when the two differ, the restore counts as one it couldn't keep. A store's entry older
    /// than the one the backup left out of the record goes: the record holds no mark, and is
    /// counted. The store's facts are kept beside the backup's, unless the backup left
    /// nothing out and carries none: that ends them.
    pub(crate) async fn in_place(
        old: &Reader,
        carried: &[CarriedMark],
        left_out: &[LeftOutMark],
        backup_facts: &LeftOutFacts,
    ) -> Result<Self, AppError> {
        let mut backup_marks: BTreeMap<[u8; 32], CarriedMark> = carried
            .iter()
            .map(|mark| (mark.key, mark.clone()))
            .collect();
        let backup_left: BTreeMap<[u8; 32], (u64, u64)> =
            left_out.iter().map(|left| (left.key, left.at())).collect();
        let mut unkept = left_out.to_vec();
        let mut marks = Vec::new();
        for live in carry(old).await? {
            // An entry the store holds is within the bound: it keeps none over it.
            if live.entry.len() > MAX_SEEN_MARK_BYTES {
                return Err(corrupt());
            }
            if backup_left
                .get(&live.key)
                .is_some_and(|at| *at > live.entry.at())
            {
                continue;
            }
            let Some(backup) = backup_marks.remove(&live.key) else {
                marks.push(live);
                continue;
            };
            if backup.entry.at() > live.entry.at() {
                marks.push(backup);
                continue;
            }
            if backup.entry.at() == live.entry.at() && backup.entry != live.entry {
                unkept.push(backup.left_out());
            }
            marks.push(live);
        }
        marks.extend(backup_marks.into_values());
        let store_facts = if backup_facts.is_empty() && left_out.is_empty() {
            LeftOutFacts::new()
        } else {
            facts_of(old).await?
        };
        Ok(Self {
            marks,
            unkept,
            facts: backup_facts.clone(),
            store_facts,
        })
    }

    /// Write the entries in `tx`, the restore's one commit, as its last writes, within the
    /// room the rest leaves of [`MAX_BATCH_BYTES`] less an owned store's overhead, and set
    /// each protocol's fact in the app, which [`super::App::restore`] writes in the commit
    /// right after this one: no room is kept for it here. Marks never refuse or shrink a
    /// restore: entries that don't fit are left out, largest first, the record key breaking
    /// a tie. For each protocol whose record the restore couldn't keep the entry of, one the
    /// backup left out, one left out now, or one unkept in place, the fact holds from the
    /// later of `start`, the backup's committed read position, and the latest write among
    /// those entries, in the app's feed order: a fact already held keeps the later position
    /// and the larger count, and is told again.
    pub(crate) fn write(
        self,
        app: &mut super::App,
        tx: &mut Tx,
        start: FeedPosition,
    ) -> Result<Written, AppError> {
        let ns = app.ns.clone();
        let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let room = MAX_BATCH_BYTES
            .saturating_sub(tx.size())
            .saturating_sub(len(ns.len()).saturating_add(32));
        let mut writes = Vec::with_capacity(self.marks.len());
        for mark in self.marks {
            let stored = encode(&mark.entry)?;
            let at = records::seen_key(&mark.key);
            let size = len(ns.len())
                .saturating_add(len(at.len()))
                .saturating_add(len(stored.len()));
            writes.push((mark, at, stored, size));
        }
        // Left out first: the largest, then the lowest key.
        writes.sort_by(|a, b| {
            b.0.entry
                .len()
                .cmp(&a.0.entry.len())
                .then(a.0.key.cmp(&b.0.key))
        });
        let mut kept_bytes = writes
            .iter()
            .fold(0u64, |sum, write| sum.saturating_add(write.3));
        let mut leave = 0;
        while kept_bytes > room {
            let Some(write) = writes.get(leave) else {
                break;
            };
            kept_bytes = kept_bytes.saturating_sub(write.3);
            leave += 1;
        }
        let kept = writes.split_off(leave);
        let left: Vec<LeftOutMark> = writes.iter().map(|write| write.0.left_out()).collect();
        for (_, at, stored, _) in kept {
            tx.put_raw(&at, stored)?;
        }
        // Each protocol whose record the restore couldn't keep holds the fact.
        let order = |at: (u64, u64)| app.feed_order(at.0, at.1);
        let later = |a: LeftOut, b: LeftOut| {
            let pos = if order((a.generation, a.seq)) >= order((b.generation, b.seq)) {
                (a.generation, a.seq)
            } else {
                (b.generation, b.seq)
            };
            LeftOut {
                records: a.records.max(b.records),
                generation: pos.0,
                seq: pos.1,
                acknowledged: a.acknowledged && b.acknowledged,
            }
        };
        let mut facts = self.facts;
        for (protocol, live) in self.store_facts {
            let fact = facts.entry(protocol).or_insert(live);
            *fact = later(*fact, live);
        }
        let protocols = app.protocols.clone();
        let mut set: BTreeMap<String, LeftOut> = BTreeMap::new();
        let mut keys = std::collections::BTreeSet::new();
        for unkept in self.unkept.iter().chain(&left) {
            if !keys.insert(unkept.key) {
                continue;
            }
            for name in owners(&protocols, &unkept.collection) {
                let entry = set.entry(name).or_insert(LeftOut {
                    records: 0,
                    generation: start.generation,
                    seq: start.seq,
                    acknowledged: false,
                });
                if order(unkept.at()) > order((entry.generation, entry.seq)) {
                    (entry.generation, entry.seq) = unkept.at();
                }
                entry.records = entry.records.saturating_add(1);
            }
        }
        for (name, new) in set {
            let fact = facts.entry(name).or_insert(new);
            *fact = LeftOut {
                acknowledged: false,
                ..later(*fact, new)
            };
        }
        app.state.seen_left_out = facts;
        Ok(Written { left })
    }
}

impl super::App {
    /// Keep the facts the restore set, in the commit right after the restore's own (Switch
    /// spec 12.4 "Seen marks"): only a crash between the two loses them for that restore.
    pub(crate) async fn keep_seen_facts(&mut self) -> Result<(), AppError> {
        if self.state.seen_left_out.is_empty() {
            return Ok(());
        }
        let mut tx = self.tx()?;
        tx.put(FACT_KEY, &self.state.seen_left_out)?;
        self.commit(tx).await
    }

    /// Whether a read of a record of `collection` that holds no mark, its current write
    /// applied at `applied` and dated (`dated`) or not, can't be checked (Switch spec 12.4):
    /// its owner holds the fact that a restore couldn't keep every mark, and the write is no
    /// later than the position the fact holds, in the app's feed order. A write nothing
    /// dates, as one taken from a recovery upload, counts as no later.
    pub(crate) fn marks_left_out_for(
        &self,
        collection: &str,
        applied: (u64, u64),
        dated: bool,
    ) -> bool {
        let Some(owner) = self.protocols.of_collection(collection) else {
            return false;
        };
        self.state
            .seen_left_out
            .get(&owner.name)
            .is_some_and(|fact| {
                !dated
                    || self.feed_order(applied.0, applied.1)
                        <= self.feed_order(fact.generation, fact.seq)
            })
    }

    /// Acknowledge `protocol`'s fact that a restore couldn't keep every mark: the app no
    /// longer tells it at each open ([`AppEvent::SeenMarksLeftOut`]). The fact itself stays,
    /// and its records still can't be checked (Switch spec 12.4). After a leave it does
    /// nothing.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn ack_seen_marks_left_out(&mut self, protocol: &str) -> Result<(), AppError> {
        if self.state.leave.is_some() {
            return Ok(());
        }
        self.ready_local().await?;
        let Some(fact) = self.state.seen_left_out.get(protocol).copied() else {
            return Ok(());
        };
        if fact.acknowledged {
            return Ok(());
        }
        let mut facts = self.state.seen_left_out.clone();
        facts.insert(
            protocol.to_owned(),
            LeftOut {
                acknowledged: true,
                ..fact
            },
        );
        let mut tx = self.tx()?;
        tx.put(FACT_KEY, &facts)?;
        self.commit(tx).await?;
        self.state.seen_left_out = facts;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seen_marks_debug_shows_only_sizes() {
        let mark = CarriedMark {
            key: [7; 32],
            entry: SeenMark::taken(
                b"the whole value".to_vec(),
                RecordVersion::new(1, 2),
                "sample.items",
            ),
        };
        assert_eq!(format!("{mark:?}"), "CarriedMark(15 bytes)");
        assert_eq!(format!("{:?}", mark.entry), "SeenMark(15 bytes)");
        assert_eq!(format!("{:?}", mark.left_out()), "LeftOutMark(..)");
    }

    #[test]
    fn test_seen_marks_ended_reads_as_no_mark_and_differs_from_an_empty_one() {
        let ended = SeenMark::ended(RecordVersion::new(1, 2), "sample.items");
        assert_eq!(ended.seen(), None);
        assert_eq!(ended.clone().into_seen(), None);
        let empty = SeenMark::taken(Vec::new(), RecordVersion::new(1, 2), "sample.items");
        assert_eq!(empty.seen(), Some(&[][..]));
        assert_ne!(ended, empty);
        let read: SeenMark = serde_json::from_slice(&serde_json::to_vec(&ended).unwrap()).unwrap();
        assert_eq!(read, ended);
        let read: SeenMark = serde_json::from_slice(&serde_json::to_vec(&empty).unwrap()).unwrap();
        assert_eq!(read, empty);
    }
}
