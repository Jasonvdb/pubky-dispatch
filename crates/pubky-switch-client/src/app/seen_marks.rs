//! The seen marks a backup carries and a restore installs (Switch spec 8.2, 12.4 "Seen
//! marks"): every record's mark the store holds (`hw/<key>`), the record each is of when
//! the store holds it (`rec/<key>`, else the `hwr/<key>` a restore kept beside the mark),
//! and the records whose marks a backup left out for room.

use std::collections::{BTreeMap, BTreeSet};

use pubky_switch_core::enc::{b64, serde_b64, serde_b64_vec, unb64_array};
use serde::{Deserialize, Serialize};

use super::events::{Duty, KeptDuty};
use super::protocol::MAX_SEEN_MARK_BYTES;
use super::protocols::ProtocolSet;
use super::records::{self, HeldRecord, SEEN_PREFIX, SeenMark};
use super::state::{Reader, Tx, encode, key};
use super::{AppError, corrupt};
use crate::error::StoreError;
use crate::store::MAX_BATCH_BYTES;

/// The record a restore installed a mark of, kept beside the mark while the store holds no
/// `rec/` of it: a backup taken before the record is read again carries it, so the
/// collection's owner can still merge and a mark left out still names its write.
const RECORD_PREFIX: &str = "hwr/";

fn record_key(key: &[u8; 32]) -> String {
    format!("{RECORD_PREFIX}{}", b64(key))
}

/// Remove the records kept beside the marks, at a leave (Switch spec 12.3).
pub(super) fn clear_on_leave(tx: &mut Tx) -> Result<(), AppError> {
    tx.delete_prefixes(&[RECORD_PREFIX])
}

/// The record a mark is of, as the store held it when the mark was read: its collection,
/// whose owner merges the mark at a restore in place, and the write it last held, which
/// the duty event of a mark left out names.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MarkedRecord {
    collection: String,
    #[serde(with = "serde_b64")]
    writer: [u8; 16],
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

    /// The duty event that tells the record can't be checked: naming its write, or none
    /// when no record is known.
    fn duty(&self) -> Duty {
        match &self.record {
            Some(record) => Duty::RecordUncheckable {
                key: self.key,
                writer: record.writer,
                generation: record.generation,
                version: record.version,
                mark_bytes: self.mark_bytes,
            },
            None => Duty::SeenMarkLeftOut {
                key: self.key,
                mark_bytes: self.mark_bytes,
            },
        }
    }
}

fn marked(held: HeldRecord, key: &[u8; 32]) -> MarkedRecord {
    let shared = held.shared(key, false);
    MarkedRecord {
        collection: shared.collection,
        writer: shared.writer,
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
    /// The records the restore can't check from then on: those the backup left out, those
    /// whose merged mark is over the bound, and those whose marks can't be merged for want
    /// of their record.
    uncheckable: Vec<LeftOutMark>,
}

impl Installing {
    /// The backup's marks, onto an empty store.
    pub(crate) fn of_backup(carried: &[CarriedMark], left_out: &[LeftOutMark]) -> Self {
        Self {
            marks: carried.to_vec(),
            uncheckable: left_out.to_vec(),
        }
    }

    /// In place, the store's marks beside the backup's (`old`): one only the store holds is
    /// kept, and for a record both hold a mark of the collection's owner merges the two
    /// ([`super::Protocol::merge_seen_marks`]), the store's kept when it doesn't, or when the
    /// merged one is over the bound, which makes the record uncheckable. A restore never
    /// replaces a mark with the backup's older one alone. One only the backup holds is
    /// installed, unless the store took a write of the record after the one the backup's
    /// mark is of and holds no mark since, as when a deletion ended the mark's
    /// lifetime (Switch spec 8.2): the store's no mark stands. A record the backup left out
    /// keeps the store's mark, and is uncheckable.
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
        let mut uncheckable = left_out.to_vec();
        let mut marks = Vec::new();
        for live in carry(old).await? {
            // A mark the store holds is within the bound: it keeps none over it.
            if live.mark.len() > MAX_SEEN_MARK_BYTES {
                return Err(corrupt());
            }
            // The same mark twice needs no merge.
            let Some(backup) = backup_marks
                .remove(&live.key)
                .filter(|backup| backup.mark != live.mark)
            else {
                marks.push(live);
                continue;
            };
            let record = live.record.clone().or_else(|| backup.record.clone());
            let Some(of) = &record else {
                // No owner to ask: the store's mark stands, and the backup's can't be merged
                // into it, so the record is told, naming no write.
                uncheckable.push(backup.left_out());
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
                    uncheckable.push(LeftOutMark {
                        key: live.key,
                        mark_bytes: u64::try_from(merged.len()).unwrap_or(u64::MAX),
                        record: record.clone(),
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
            let newer = match old.get::<HeldRecord>(&records::record_key_of(&key)).await? {
                Some(held) => {
                    let held = marked(held, &key);
                    backup
                        .record
                        .as_ref()
                        .is_none_or(|of| held.version() > of.version())
                }
                None => false,
            };
            if !newer {
                marks.push(backup);
            }
        }
        Ok(Self { marks, uncheckable })
    }

    /// Write the marks in `tx`, the restore's one commit, as its last writes, each with the
    /// record it is of (`hwr/`), within the room the rest leaves of [`MAX_BATCH_BYTES`] less
    /// an owned store's overhead, and tell the protocol of each record that can't be checked.
    /// A mark can't be rebuilt from the service, and the restore is never refused for marks:
    /// those that don't fit are left out, largest first, the record key breaking a tie. Each
    /// record that can't be checked is told by a duty event of its own while they fit, and
    /// the rest by one [`Duty::SeenMarksLeftOut`] counting them, marks left out until it
    /// fits: room is kept back for it only then, so with no record to tell the outcome is
    /// the rest's alone, and a rest that leaves less than that one event is too large as it
    /// is. A record is told once, and not at all when `held`, the duty events the commit
    /// keeps already, tells it. Returns the marks left out for room, which a backup's check
    /// moves to the records its backup left out.
    pub(crate) fn write(
        self,
        app: &mut super::App,
        tx: &mut Tx,
        held: &BTreeSet<String>,
    ) -> Result<Vec<LeftOutMark>, AppError> {
        let ns = app.ns.clone();
        let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        // The most a duty event takes with the counter it moves: its key is of fixed width,
        // and each number at its widest.
        let duty_bytes = |duty: Duty| -> Result<u64, AppError> {
            let mut scratch = Tx::new(&ns);
            scratch.put(
                &key::duty(u64::MAX),
                &KeptDuty {
                    to: app.protocols.names(),
                    duty,
                },
            )?;
            scratch.put(key::DUTY_NEXT, &u64::MAX)?;
            Ok(scratch.size())
        };
        let one = duty_bytes(Duty::RecordUncheckable {
            key: [u8::MAX; 32],
            writer: [u8::MAX; 16],
            generation: u64::MAX,
            version: u64::MAX,
            mark_bytes: u64::MAX,
        })?
        .max(duty_bytes(Duty::SeenMarkLeftOut {
            key: [u8::MAX; 32],
            mark_bytes: u64::MAX,
        })?);
        let together = duty_bytes(Duty::SeenMarksLeftOut { records: u64::MAX })?;
        let overhead = len(ns.len()).saturating_add(32);
        let room = MAX_BATCH_BYTES
            .saturating_sub(tx.size())
            .saturating_sub(overhead);
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
            let size = [Some((&at, &stored)), record.as_ref().map(|(k, v)| (k, v))]
                .into_iter()
                .flatten()
                .fold(0u64, |sum, (k, v)| {
                    sum.saturating_add(len(ns.len()))
                        .saturating_add(len(k.len()))
                        .saturating_add(len(v.len()))
                });
            writes.push((mark, at, stored, record, size));
        }
        // Left out first: the largest, then the lowest key.
        writes.sort_by(|a, b| {
            b.0.mark
                .len()
                .cmp(&a.0.mark.len())
                .then(a.0.key.cmp(&b.0.key))
        });
        // Each record told once.
        let mut told: Vec<LeftOutMark> = Vec::new();
        let mut keys = BTreeSet::new();
        for left in self.uncheckable {
            if keys.insert(left.key) {
                told.push(left);
            }
        }
        // `leave` marks left out keep the rest within the room, each told on its own;
        // failing that, the rest within the room less the one event that counts them. The
        // bytes the marks from `leave` on take, and how many records leaving `leave` out
        // tells beside those told already.
        let mut kept_from = vec![0u64];
        for write in writes.iter().rev() {
            let last = kept_from.last().copied().unwrap_or(0);
            kept_from.push(last.saturating_add(write.4));
        }
        kept_from.reverse();
        let mut told_at = vec![len(told.len())];
        for write in &writes {
            let last = told_at.last().copied().unwrap_or(0);
            told_at.push(last.saturating_add(u64::from(!keys.contains(&write.0.key))));
        }
        let kept_bytes = |leave: usize| kept_from.get(leave).copied().unwrap_or(0);
        let told_with = |leave: usize| told_at.get(leave).copied().unwrap_or(u64::MAX);
        let each = (0..=writes.len()).find(|&leave| {
            kept_bytes(leave).saturating_add(told_with(leave).saturating_mul(one)) <= room
        });
        let (leave, alone) = match each {
            Some(leave) => (leave, usize::MAX),
            // Some can't be told one by one: room for the one event that counts them, all
            // marks left out if need be. A rest that leaves less than that is within one
            // event of the limit: too large as it is.
            None if room < together => {
                return Err(StoreError::TooLarge {
                    size: tx.size().saturating_add(overhead).saturating_add(together),
                    cap: MAX_BATCH_BYTES,
                }
                .into());
            }
            None => {
                let budget = room.saturating_sub(together);
                let leave = (0..=writes.len())
                    .find(|&leave| kept_bytes(leave) <= budget)
                    .unwrap_or(writes.len());
                let spare = budget.saturating_sub(kept_bytes(leave));
                let alone = usize::try_from(spare.checked_div(one).unwrap_or(0)).unwrap_or(0);
                (leave, alone)
            }
        };
        let kept = writes.split_off(leave);
        let left: Vec<LeftOutMark> = writes.iter().map(|write| write.0.left_out()).collect();
        for left in &left {
            if keys.insert(left.key) {
                told.push(left.clone());
            }
        }
        let said = |duty: &Duty| serde_json::to_string(duty).map_err(|_| corrupt());
        let mut counted = 0u64;
        for (n, left) in told.iter().enumerate() {
            let duty = left.duty();
            if held.contains(&said(&duty)?) {
                continue;
            }
            if n >= alone {
                counted = counted.saturating_add(1);
                continue;
            }
            let to = match &left.record {
                Some(record) => app.owners_of_collection(&record.collection),
                None => app.protocols.names(),
            };
            app.keep_duty_for(tx, to, duty)?;
        }
        if counted > 0 {
            let duty = Duty::SeenMarksLeftOut { records: counted };
            if !held.contains(&said(&duty)?) {
                let to = app.protocols.names();
                app.keep_duty_for(tx, to, duty)?;
            }
        }
        for (_, at, stored, record, _) in kept {
            tx.put_raw(&at, stored)?;
            if let Some((at, stored)) = record {
                tx.put_raw(&at, stored)?;
            }
        }
        Ok(left)
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
