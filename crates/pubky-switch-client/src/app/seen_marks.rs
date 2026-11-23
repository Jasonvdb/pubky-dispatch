//! The seen marks a backup carries and a restore installs (Switch spec 8.2, 12.4 "Seen
//! marks"): every record's entry the store holds at `hw/<key>`, a mark or the end of its
//! lifetime, each at the version of the write it was taken at; the records whose marks a
//! backup left out for room; and, for each protocol, the fact that a restore couldn't keep
//! every mark the backup knew of, with the feed position it started from.

use std::collections::{BTreeMap, BTreeSet};

use pubky_switch_core::enc::{serde_b64, serde_b64_vec, unb64_array};
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

/// A record's entry at `hw/<key>` (Switch spec 8.2, 12.4): the protocol's mark of what the
/// app has seen in it, or the end of the mark's lifetime at a verified current deletion,
/// which reads as no mark; each at the version of the write it was taken at, with the
/// record's collection. Where two entries of one record meet, the later version's is kept,
/// the store's at an equal one. Its `Debug` shows only the mark's size.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SeenMark {
    #[serde(with = "serde_b64_vec")]
    mark: Vec<u8>,
    generation: u64,
    version: u64,
    collection: String,
    ended: bool,
}

impl std::fmt::Debug for SeenMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SeenMark({} bytes)", self.mark.len())
    }
}

impl SeenMark {
    /// The mark `mark` of a record of `collection`, after its write at `version`.
    pub(crate) fn taken(mark: Vec<u8>, version: RecordVersion, collection: &str) -> Self {
        Self {
            mark,
            generation: version.generation,
            version: version.version,
            collection: collection.to_owned(),
            ended: false,
        }
    }

    /// The end of the mark's lifetime at the verified current deletion at `version`.
    pub(crate) fn ended(version: RecordVersion, collection: &str) -> Self {
        Self {
            mark: Vec::new(),
            generation: version.generation,
            version: version.version,
            collection: collection.to_owned(),
            ended: true,
        }
    }

    /// What the app has seen, as the protocol's hooks get it: `None` for an ended lifetime.
    pub(crate) fn seen(&self) -> Option<&[u8]> {
        (!self.ended).then_some(self.mark.as_slice())
    }

    /// [`Self::seen`], owned.
    pub(crate) fn into_seen(self) -> Option<Vec<u8>> {
        (!self.ended).then_some(self.mark)
    }

    /// The size of the mark.
    pub(crate) fn len(&self) -> usize {
        self.mark.len()
    }

    fn at(&self) -> (u64, u64) {
        (self.generation, self.version)
    }
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

/// A record whose entry a backup left out, since it didn't fit the restore's one commit.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LeftOutMark {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    /// The size of the mark left out.
    mark_bytes: u64,
    collection: String,
}

impl std::fmt::Debug for LeftOutMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LeftOutMark({} bytes)", self.mark_bytes)
    }
}

impl CarriedMark {
    /// This entry as a backup left it out.
    pub(crate) fn left_out(&self) -> LeftOutMark {
        LeftOutMark {
            key: self.key,
            mark_bytes: u64::try_from(self.entry.len()).unwrap_or(u64::MAX),
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
}

/// That a restore couldn't keep every mark the backup knew of, for one protocol (Switch spec
/// 12.4): how many records it couldn't keep at most, the later feed position a restore that
/// set it started from, and whether the protocol acknowledged it, which ends its telling at
/// each open, not the fact. A record of the protocol's collections with no mark, whose
/// current write is no later than the position, can't be checked.
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

    /// The feed position the latest restore that set it started from.
    #[cfg(test)]
    pub(crate) fn position(&self) -> (u64, u64) {
        (self.generation, self.seq)
    }

    /// Whether the protocol acknowledged it.
    #[cfg(test)]
    pub(crate) fn acknowledged(&self) -> bool {
        self.acknowledged
    }
}

/// The facts of the protocols, by name.
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

/// The informational events that tell each protocol of its fact not yet acknowledged,
/// raised at every open (Switch spec 12.4).
pub(crate) fn told_at_open(facts: &LeftOutFacts) -> Vec<AppEvent> {
    facts
        .iter()
        .filter(|(_, fact)| !fact.acknowledged)
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

/// A backup's entries and the records it left out, checked: each record once, no mark over
/// [`MAX_SEEN_MARK_BYTES`], which no app keeps, and no bytes in an ended lifetime.
pub(crate) fn check(carried: &[CarriedMark], left_out: &[LeftOutMark]) -> Result<(), AppError> {
    let invalid = |why: &str| AppError::InvalidData(format!("the backup: {why}"));
    let mut keys = BTreeSet::new();
    for mark in carried {
        if mark.entry.len() > MAX_SEEN_MARK_BYTES {
            return Err(invalid("a seen mark it carries is over the bound"));
        }
        if mark.entry.ended && !mark.entry.mark.is_empty() {
            return Err(invalid("an ended seen mark it carries holds a mark"));
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

/// The later position of two facts and the larger count; acknowledged only when both are.
fn later(a: LeftOut, b: LeftOut) -> LeftOut {
    let (generation, seq) = (a.generation, a.seq).max((b.generation, b.seq));
    LeftOut {
        records: a.records.max(b.records),
        generation,
        seq,
        acknowledged: a.acknowledged && b.acknowledged,
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
    /// The facts the restore starts from: the backup's, and, in place, the store's.
    facts: LeftOutFacts,
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
        }
    }

    /// In place, the store's entries beside the backup's (`old`): for a record both hold an
    /// entry of, the one at the later version is kept, the store's at an equal one, which,
    /// when the two differ, the restore counts as one it couldn't keep. The facts are the
    /// later of the store's and the backup's, unless the backup left nothing out and carries
    /// none: that ends them.
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
        let mut unkept = left_out.to_vec();
        let mut marks = Vec::new();
        for live in carry(old).await? {
            // An entry the store holds is within the bound: it keeps none over it.
            if live.entry.len() > MAX_SEEN_MARK_BYTES {
                return Err(corrupt());
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
        let mut facts = backup_facts.clone();
        if !backup_facts.is_empty() || !left_out.is_empty() {
            for (protocol, live) in facts_of(old).await? {
                let fact = facts.entry(protocol).or_insert(live);
                *fact = later(*fact, live);
            }
        }
        Ok(Self {
            marks,
            unkept,
            facts,
        })
    }

    /// Write the entries in `tx`, the restore's one commit, as its last writes, within the
    /// room the rest leaves of [`MAX_BATCH_BYTES`] less an owned store's overhead, and keep
    /// each protocol's fact. Marks never refuse or shrink a restore: entries that don't fit
    /// are left out, largest first, the record key breaking a tie. For each protocol whose
    /// record the restore couldn't keep the entry of, one the backup left out, one left out
    /// now, or one unkept in place, the fact holds from `start`, the feed position the
    /// restore starts from: a fact already held keeps the later position and the larger
    /// count, and is told again. Room for the facts, a small record bounded by the protocols,
    /// comes before the marks'.
    ///
    /// When, with every mark left out, not even the facts fit, the restore holds them only for
    /// its run, and reports them as at an open; nothing durable keeps them.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub(crate) fn write(
        self,
        app: &mut super::App,
        tx: &mut Tx,
        start: FeedPosition,
    ) -> Result<Written, AppError> {
        let ns = app.ns.clone();
        let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let protocols = app.protocols.clone();
        let names = protocols.names();
        // The facts kept for the protocols registered here.
        let mut facts: LeftOutFacts = self
            .facts
            .into_iter()
            .filter(|(name, _)| names.contains(name))
            .collect();
        // The most the facts take: one for every protocol, each number at its widest.
        let widest: LeftOutFacts = names
            .iter()
            .map(|name| {
                let fact = LeftOut {
                    records: u64::MAX,
                    generation: u64::MAX,
                    seq: u64::MAX,
                    acknowledged: false,
                };
                (name.clone(), fact)
            })
            .collect();
        let facts_bytes = len(ns.len())
            .saturating_add(len(FACT_KEY.len()))
            .saturating_add(len(encode(&widest)?.len()));
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
        // The bytes the entries from `leave` on take.
        let mut kept_from = vec![0u64];
        for write in writes.iter().rev() {
            let last = kept_from.last().copied().unwrap_or(0);
            kept_from.push(last.saturating_add(write.3));
        }
        kept_from.reverse();
        let kept_bytes = |leave: usize| kept_from.get(leave).copied().unwrap_or(0);
        // The facts need room once any is held or any record is unkept.
        let held = !facts.is_empty() || !self.unkept.is_empty();
        let leave = (0..=writes.len())
            .find(|&leave| {
                let facts = if held || leave > 0 { facts_bytes } else { 0 };
                kept_bytes(leave).saturating_add(facts) <= room
            })
            .unwrap_or(writes.len());
        let kept = writes.split_off(leave);
        let left: Vec<LeftOutMark> = writes.iter().map(|write| write.0.left_out()).collect();
        // Each protocol whose record the restore couldn't keep holds the fact from `start`.
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut keys = BTreeSet::new();
        for unkept in self.unkept.iter().chain(&left) {
            if keys.insert(unkept.key) {
                for name in owners(&protocols, &unkept.collection) {
                    let count = counts.entry(name).or_default();
                    *count = count.saturating_add(1);
                }
            }
        }
        for (name, records) in counts {
            let set = LeftOut {
                records,
                generation: start.generation,
                seq: start.seq,
                acknowledged: false,
            };
            let fact = facts.entry(name).or_insert(set);
            *fact = LeftOut {
                acknowledged: false,
                ..later(*fact, set)
            };
        }
        // The facts are written within the room the rest leaves: when, with every mark left
        // out, not even they fit, nothing durable keeps them, and the restore reports them
        // from what it holds for this run (`App::restore`).
        if !facts.is_empty() {
            let stored = encode(&facts)?;
            let size = len(ns.len())
                .saturating_add(len(FACT_KEY.len()))
                .saturating_add(len(stored.len()));
            if kept_bytes(leave).saturating_add(size) <= room {
                tx.put_raw(FACT_KEY, stored)?;
            }
        }
        app.state.seen_left_out = facts;
        for (_, at, stored, _) in kept {
            tx.put_raw(&at, stored)?;
        }
        Ok(Written { left })
    }
}

impl super::App {
    /// Whether a read of a record of `collection` that holds no mark, its current write
    /// applied at `applied` and dated (`dated`) or not, can't be checked (Switch spec 12.4):
    /// its owner holds the fact that a restore couldn't keep every mark, and the write is no
    /// later than the position the fact holds. A write nothing dates, as one taken from a
    /// recovery upload, counts as no later.
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
            .is_some_and(|fact| !dated || applied <= (fact.generation, fact.seq))
    }

    /// Acknowledge `protocol`'s fact that a restore couldn't keep every mark: the app no
    /// longer tells it at each open ([`AppEvent::SeenMarksLeftOut`]). The fact itself stays,
    /// and its records still can't be checked (Switch spec 12.4).
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn ack_seen_marks_left_out(&mut self, protocol: &str) -> Result<(), AppError> {
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
        assert_eq!(format!("{:?}", mark.left_out()), "LeftOutMark(15 bytes)");
    }

    #[test]
    fn test_seen_marks_ended_reads_as_no_mark() {
        let ended = SeenMark::ended(RecordVersion::new(1, 2), "sample.items");
        assert_eq!(ended.seen(), None);
        assert_eq!(ended.clone().into_seen(), None);
        let taken = SeenMark::taken(b"a".to_vec(), RecordVersion::new(1, 1), "sample.items");
        assert_eq!(taken.seen(), Some(&b"a"[..]));
        assert!(ended.at() > taken.at());
    }

    #[test]
    fn test_seen_marks_later_fact_keeps_the_later_position_and_larger_count() {
        let fact = |records, seq, acknowledged| LeftOut {
            records,
            generation: 1,
            seq,
            acknowledged,
        };
        assert_eq!(later(fact(3, 9, true), fact(5, 4, true)), fact(5, 9, true));
        assert_eq!(
            later(fact(3, 9, true), fact(5, 4, false)),
            fact(5, 9, false)
        );
    }
}
