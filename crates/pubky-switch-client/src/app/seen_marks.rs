//! The seen marks a backup carries and a restore installs (Switch spec 8.2, 12.4 "Seen
//! marks"): every record's mark the store holds (`hw/<key>`), the record each is of when
//! the store holds it (`rec/<key>`, else the `hwr/<key>` a restore kept beside the mark),
//! and the records whose marks a backup left out for room.

use std::collections::{BTreeMap, BTreeSet};

use pubky_switch_core::enc::{b64, serde_b64, serde_b64_vec, unb64_array};
use pubky_switch_core::ops::RecordVersion;
use serde::{Deserialize, Serialize};

use super::events::{Duty, KeptDuty};
use super::protocol::MAX_SEEN_MARK_BYTES;
use super::protocols::ProtocolSet;
use super::records::{self, HeldRecord, SEEN_PREFIX, SeenMark};
use super::state::{Reader, Tx, encode, key};
use super::{AppError, corrupt};
use crate::store::MAX_BATCH_BYTES;

/// The record a restore installed a mark of, kept beside the mark while the store holds no
/// `rec/` of it: a backup taken before the record is read again carries it, so the
/// collection's owner can still merge and a mark left out still names its write.
const RECORD_PREFIX: &str = "hwr/";

fn record_key(key: &[u8; 32]) -> String {
    format!("{RECORD_PREFIX}{}", b64(key))
}

/// The version of the verified current deletion that ended the lifetime of a record's
/// mark (Switch spec 8.2), written in the commit that ends it ([`note_ended`]) and kept by
/// every restore in place that holds no mark of the record since: a restore of a backup
/// whose mark is of a write at or before it doesn't put that mark back.
const ENDED_PREFIX: &str = "hwe/";

fn ended_key(key: &[u8; 32]) -> String {
    format!("{ENDED_PREFIX}{}", b64(key))
}

/// Note in `tx`, the commit that takes it, the deletion at `version` that ended the lifetime
/// of record `key`'s mark (Switch spec 8.2, 12.4 "Seen marks").
pub(crate) fn note_ended(
    tx: &mut Tx,
    key: &[u8; 32],
    version: RecordVersion,
) -> Result<(), AppError> {
    tx.put(&ended_key(key), &(version.generation, version.version))
}

/// Remove what is kept beside the marks, at a leave (Switch spec 12.3).
pub(super) fn clear_on_leave(tx: &mut Tx) -> Result<(), AppError> {
    tx.delete_prefixes(&[RECORD_PREFIX, ENDED_PREFIX])
}

/// The record a mark is of, as the store held it when the mark was read: its collection,
/// whose owner merges the mark at a restore in place and is told of it when it can't be
/// kept, and the version of the write it last held, which a recorded end of the mark's
/// lifetime is weighed against.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MarkedRecord {
    collection: String,
    generation: u64,
    version: u64,
}

impl MarkedRecord {
    fn version(&self) -> (u64, u64) {
        (self.generation, self.version)
    }
}

/// A record's seen mark as a backup carries it, with the record it is of; `record` is
/// `None` when the store held neither the record nor what a restore kept of it. Its `Debug`
/// shows neither the key nor the mark, which may be the record's whole value.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CarriedMark {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    #[serde(with = "serde_b64_vec")]
    mark: Vec<u8>,
    record: Option<MarkedRecord>,
}

impl std::fmt::Debug for CarriedMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CarriedMark({} bytes)", self.mark.len())
    }
}

/// A record whose mark a backup left out, since it didn't fit the restore's one commit:
/// every restore of the backup tells its protocol the record can't be checked from then on.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LeftOutMark {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    /// The size of the mark left out.
    mark_bytes: u64,
    record: Option<MarkedRecord>,
}

impl std::fmt::Debug for LeftOutMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LeftOutMark({} bytes)", self.mark_bytes)
    }
}

impl CarriedMark {
    /// This mark as a backup left it out.
    pub(crate) fn left_out(&self) -> LeftOutMark {
        LeftOutMark {
            key: self.key,
            mark_bytes: u64::try_from(self.mark.len()).unwrap_or(u64::MAX),
            record: self.record.clone(),
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

fn marked(held: HeldRecord, key: &[u8; 32]) -> MarkedRecord {
    let shared = held.shared(key, false);
    MarkedRecord {
        collection: shared.collection,
        generation: shared.version.generation,
        version: shared.version.version,
    }
}

/// The record `reader` holds of `key`'s mark: `rec/` first, else what a restore kept.
async fn record_of(reader: &Reader, key: &[u8; 32]) -> Result<Option<MarkedRecord>, AppError> {
    match reader
        .get::<HeldRecord>(&records::record_key_of(key))
        .await?
    {
        Some(held) => Ok(Some(marked(held, key))),
        None => reader.get(&record_key(key)).await,
    }
}

/// Every mark `reader` holds, each with the record it is of, from the same read as the
/// rest of the backup.
pub(crate) async fn carry(reader: &Reader) -> Result<Vec<CarriedMark>, AppError> {
    let mut out = Vec::new();
    for (rest, seen) in reader.scan::<SeenMark>(SEEN_PREFIX).await? {
        let key = unb64_array::<32>(&rest).map_err(|_| corrupt())?;
        out.push(CarriedMark {
            key,
            mark: seen.mark,
            record: record_of(reader, &key).await?,
        });
    }
    Ok(out)
}

/// A backup's marks and the records it left out, checked: each record once, and no mark
/// over [`MAX_SEEN_MARK_BYTES`], which no app keeps (Switch spec 12.4 "Seen marks").
pub(crate) fn check(carried: &[CarriedMark], left_out: &[LeftOutMark]) -> Result<(), AppError> {
    let invalid = |why: &str| AppError::InvalidData(format!("the backup: {why}"));
    let mut keys = BTreeSet::new();
    for mark in carried {
        if mark.mark.len() > MAX_SEEN_MARK_BYTES {
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

/// The marks a restore installs: the backup's, or, in place, the store's beside them.
pub(crate) struct Installing {
    marks: Vec<CarriedMark>,
    /// The records whose backup marks the restore couldn't keep, beside those it leaves out
    /// for room: those the backup left out, and those whose merge it couldn't keep.
    unkept: Vec<LeftOutMark>,
    /// The ends of marks' lifetimes the store recorded, by record, for records the restore
    /// holds no mark of (`hwe/`).
    ended: BTreeMap<[u8; 32], (u64, u64)>,
}

/// What [`Installing::write`] left out: the marks left out for room, which a backup's check
/// moves to the records its backup left out, and how many records no durable notice could
/// count, which [`super::App::restore`] reports ([`super::AppEvent::SeenMarksUntold`]).
pub(crate) struct Written {
    pub(crate) left: Vec<LeftOutMark>,
    pub(crate) untold: u64,
}

impl Installing {
    /// The backup's marks, onto an empty store.
    pub(crate) fn of_backup(carried: &[CarriedMark], left_out: &[LeftOutMark]) -> Self {
        Self {
            marks: carried.to_vec(),
            unkept: left_out.to_vec(),
            ended: BTreeMap::new(),
        }
    }

    /// In place, the store's marks beside the backup's (`old`): one only the store holds is
    /// kept, and for a record both hold a mark of the collection's owner merges the two
    /// ([`super::Protocol::merge_seen_marks`]), the store's kept when it doesn't, and when
    /// the merge can't be kept, over the bound or with no record to name its owner, which
    /// the restore counts. A restore never replaces a mark with the backup's older one alone.
    /// One only the backup holds is installed, unless the store recorded that a verified
    /// current deletion at or after the write that mark is of ended the mark's lifetime
    /// (`hwe/`, Switch spec 8.2): the restore keeps that end, which a mark the store holds
    /// or one installed overrides. A record the backup left out keeps the store's mark.
    pub(crate) async fn in_place(
        old: &Reader,
        carried: &[CarriedMark],
        left_out: &[LeftOutMark],
        protocols: &ProtocolSet,
    ) -> Result<Self, AppError> {
        let mut backup_marks: BTreeMap<[u8; 32], CarriedMark> = carried
            .iter()
            .map(|mark| (mark.key, mark.clone()))
            .collect();
        let mut unkept = left_out.to_vec();
        let mut marks = Vec::new();
        let mut ended = BTreeMap::new();
        for (rest, at) in old.scan::<(u64, u64)>(ENDED_PREFIX).await? {
            ended.insert(unb64_array::<32>(&rest).map_err(|_| corrupt())?, at);
        }
        for live in carry(old).await? {
            // A mark the store holds is within the bound: it keeps none over it.
            if live.mark.len() > MAX_SEEN_MARK_BYTES {
                return Err(corrupt());
            }
            ended.remove(&live.key);
            let Some(backup) = backup_marks.remove(&live.key) else {
                marks.push(live);
                continue;
            };
            let record = live.record.clone().or_else(|| backup.record.clone());
            // The same mark twice needs no merge, and keeps the record either names.
            if backup.mark == live.mark {
                marks.push(CarriedMark { record, ..live });
                continue;
            }
            let Some(of) = &record else {
                // No owner to ask: the store's mark stands, and the backup's isn't kept.
                unkept.push(backup.left_out());
                marks.push(live);
                continue;
            };
            let merged = protocols.of_collection(&of.collection).and_then(|owner| {
                owner
                    .protocol
                    .merge_seen_marks(&of.collection, &live.mark, &backup.mark)
            });
            let mark = match merged {
                Some(merged) if merged.len() > MAX_SEEN_MARK_BYTES => {
                    unkept.push(LeftOutMark {
                        record: record.clone(),
                        ..backup.left_out()
                    });
                    live.mark
                }
                Some(merged) => merged,
                None => live.mark,
            };
            marks.push(CarriedMark {
                key: live.key,
                mark,
                record,
            });
        }
        for (key, backup) in backup_marks {
            let ends = ended
                .get(&key)
                .is_some_and(|at| backup.record.as_ref().is_none_or(|of| *at >= of.version()));
            if !ends {
                ended.remove(&key);
                marks.push(backup);
            }
        }
        Ok(Self {
            marks,
            unkept,
            ended,
        })
    }

    /// Write the marks in `tx`, the restore's one commit, as its last writes, each with the
    /// record it is of (`hwr/`), and the lifetime ends kept (`hwe/`), within the room the
    /// rest leaves of [`MAX_BATCH_BYTES`] less an owned store's overhead, and tell each
    /// protocol how many of its records the restore couldn't keep the backup's mark of.
    /// Marks and their notices never refuse a restore: marks that don't fit are left out,
    /// largest first, the record key breaking a tie. Each protocol whose records are counted
    /// gets one [`Duty::SeenMarksLeftOut`], its count added to `pending`, what the store owed
    /// it already; marks are left out until the notices fit, and when not even one fits, no
    /// notice is written and the count is returned for the restore to report.
    pub(crate) fn write(
        self,
        app: &mut super::App,
        tx: &mut Tx,
        pending: &BTreeMap<String, u64>,
    ) -> Result<Written, AppError> {
        let ns = app.ns.clone();
        let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let write_bytes = |at: &str, value: &[u8]| {
            len(ns.len())
                .saturating_add(len(at.len()))
                .saturating_add(len(value.len()))
        };
        let names = app.protocols.names();
        // The most one protocol's notice takes with the counter it moves: its key is of
        // fixed width, and the count at its widest.
        let mut notice = 0;
        for name in &names {
            let mut scratch = Tx::new(&ns);
            scratch.put(
                &key::duty(u64::MAX),
                &KeptDuty {
                    to: vec![name.clone()],
                    duty: Duty::SeenMarksLeftOut { records: u64::MAX },
                },
            )?;
            scratch.put(key::DUTY_NEXT, &u64::MAX)?;
            notice = notice.max(scratch.size());
        }
        let mut room = MAX_BATCH_BYTES
            .saturating_sub(tx.size())
            .saturating_sub(len(ns.len()).saturating_add(32));
        // The lifetime ends first: small, and what keeps a later restore from putting an
        // ended mark back.
        for (key, at) in &self.ended {
            let (stored, value) = (ended_key(key), encode(at)?);
            let size = write_bytes(&stored, &value);
            if size <= room {
                tx.put_raw(&stored, value)?;
                room = room.saturating_sub(size);
            }
        }
        // The protocols a record is counted for: its collection's owner, or every protocol
        // for a record no collection names.
        let owners = |left: &LeftOutMark| match &left.record {
            Some(record) => app.owners_of_collection(&record.collection),
            None => names.clone(),
        };
        let mut writes = Vec::with_capacity(self.marks.len());
        for mark in self.marks {
            let stored = encode(&SeenMark {
                mark: mark.mark.clone(),
            })?;
            let at = records::seen_key(&mark.key);
            let record = match &mark.record {
                Some(record) => Some((record_key(&mark.key), encode(record)?)),
                None => None,
            };
            let size = write_bytes(&at, &stored).saturating_add(
                record
                    .as_ref()
                    .map_or(0, |(at, value)| write_bytes(at, value)),
            );
            writes.push((mark, at, stored, record, size));
        }
        // Left out first: the largest, then the lowest key.
        writes.sort_by(|a, b| {
            b.0.mark
                .len()
                .cmp(&a.0.mark.len())
                .then(a.0.key.cmp(&b.0.key))
        });
        // What each protocol is owed, each record counted once.
        let mut counts: BTreeMap<String, u64> = pending.clone();
        let mut keys = BTreeSet::new();
        let count = |counts: &mut BTreeMap<String, u64>, to: Vec<String>| {
            for name in to {
                let n = counts.entry(name).or_default();
                *n = n.saturating_add(1);
            }
        };
        for left in &self.unkept {
            if keys.insert(left.key) {
                count(&mut counts, owners(left));
            }
        }
        // The bytes the marks from `leave` on take, and how many notices leaving `leave`
        // marks out owes: one for each protocol with a count.
        let mut kept_from = vec![0u64];
        for write in writes.iter().rev() {
            let last = kept_from.last().copied().unwrap_or(0);
            kept_from.push(last.saturating_add(write.4));
        }
        kept_from.reverse();
        let mut owed = BTreeSet::new();
        owed.extend(
            counts
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(name, _)| name.clone()),
        );
        let mut notices_at = vec![len(owed.len())];
        let mut owners_of = Vec::with_capacity(writes.len());
        for write in &writes {
            let to = if keys.contains(&write.0.key) {
                Vec::new()
            } else {
                owners(&write.0.left_out())
            };
            owed.extend(to.iter().cloned());
            notices_at.push(len(owed.len()));
            owners_of.push(to);
        }
        let kept_bytes = |leave: usize| kept_from.get(leave).copied().unwrap_or(0);
        let notices = |leave: usize| notices_at.get(leave).copied().unwrap_or(u64::MAX);
        let each = (0..=writes.len()).find(|&leave| {
            kept_bytes(leave).saturating_add(notices(leave).saturating_mul(notice)) <= room
        });
        // Failing room for every notice, all marks go so the most notices fit; with no room
        // for even one, the marks that fit stay and nothing durable tells the counts.
        let leave = match each {
            Some(leave) => leave,
            None if room >= notice => writes.len(),
            None => (0..=writes.len())
                .find(|&leave| kept_bytes(leave) <= room)
                .unwrap_or(writes.len()),
        };
        for to in owners_of.into_iter().take(leave) {
            count(&mut counts, to);
        }
        let kept = writes.split_off(leave);
        let left: Vec<LeftOutMark> = writes.iter().map(|write| write.0.left_out()).collect();
        let mut spare = room.saturating_sub(kept_bytes(leave));
        let mut untold = 0u64;
        for name in &names {
            let Some(records) = counts.get(name).copied().filter(|n| *n > 0) else {
                continue;
            };
            if spare >= notice {
                app.keep_duty_for(tx, vec![name.clone()], Duty::SeenMarksLeftOut { records })?;
                spare = spare.saturating_sub(notice);
            } else {
                untold = untold.saturating_add(records);
            }
        }
        for (_, at, stored, record, _) in kept {
            tx.put_raw(&at, stored)?;
            if let Some((at, stored)) = record {
                tx.put_raw(&at, stored)?;
            }
        }
        Ok(Written { left, untold })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seen_marks_debug_shows_only_sizes() {
        let mark = CarriedMark {
            key: [7; 32],
            mark: b"the whole value".to_vec(),
            record: None,
        };
        assert_eq!(format!("{mark:?}"), "CarriedMark(15 bytes)");
        assert_eq!(format!("{:?}", mark.left_out()), "LeftOutMark(15 bytes)");
    }
}
