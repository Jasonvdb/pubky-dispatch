//! The seen marks a backup carries and a restore installs (Switch spec 8.2, 12.4 "Seen
//! marks"): every record's mark the store holds (`hw/<key>`), the record each is of when
//! the store holds it, and the records whose marks a backup left out for room.

use std::collections::{BTreeMap, BTreeSet};

use pubky_switch_core::enc::{serde_b64, serde_b64_vec, unb64_array};
use pubky_switch_core::ops::RecordVersion;
use serde::{Deserialize, Serialize};

use super::events::{Duty, KeptDuty};
use super::protocol::MAX_SEEN_MARK_BYTES;
use super::protocols::ProtocolSet;
use super::records::{self, HeldRecord, SEEN_PREFIX, SeenMark};
use super::state::{Reader, Tx, encode, key};
use super::{AppError, corrupt};

/// The record a mark is of, as the store held it when the mark was read: its collection,
/// whose owner merges the mark at a restore in place, and the write it last held, which
/// the duty event of a mark left out names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MarkedRecord {
    collection: String,
    #[serde(with = "serde_b64")]
    writer: [u8; 16],
    generation: u64,
    version: u64,
}

/// A record's seen mark as a backup carries it, with the record it is of; `record` is
/// `None` when the store held the mark with no record, as after a restore that installed
/// the mark of a record deleted before its backup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CarriedMark {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    #[serde(with = "serde_b64_vec")]
    mark: Vec<u8>,
    record: Option<MarkedRecord>,
}

/// A record whose mark a backup left out, since it didn't fit the restore's one commit:
/// every restore of the backup tells its protocol the record can't be checked from then on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LeftOutMark {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    /// The size of the mark left out.
    mark_bytes: u64,
    record: Option<MarkedRecord>,
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

fn marked(held: Option<HeldRecord>, key: &[u8; 32]) -> Option<MarkedRecord> {
    held.map(|held| {
        let shared = held.shared(key, false);
        MarkedRecord {
            collection: shared.collection,
            writer: shared.writer,
            generation: shared.version.generation,
            version: shared.version.version,
        }
    })
}

/// Every mark `reader` holds, each with the record it is of, from the same read as the
/// rest of the backup.
pub(crate) async fn carry(reader: &Reader) -> Result<Vec<CarriedMark>, AppError> {
    let mut out = Vec::new();
    for (rest, seen) in reader.scan::<SeenMark>(SEEN_PREFIX).await? {
        let key = unb64_array::<32>(&rest).map_err(|_| corrupt())?;
        let held = reader
            .get::<HeldRecord>(&records::record_key_of(&key))
            .await?;
        out.push(CarriedMark {
            key,
            mark: seen.mark,
            record: marked(held, &key),
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
    /// The records the restore can't check from then on: those the backup left out, and
    /// those whose merged mark is over the bound.
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
    /// kept, one only the backup holds is installed, and for a record both hold a mark of
    /// the collection's owner merges the two ([`super::Protocol::merge_seen_marks`]), the
    /// store's kept when it doesn't, or when the merged one is over the bound, which makes
    /// the record uncheckable. A restore never replaces a mark with the backup's older one
    /// alone. A record the backup left out keeps the store's mark, and is uncheckable.
    pub(crate) async fn in_place(
        old: &Reader,
        carried: &[CarriedMark],
        left_out: &[LeftOutMark],
        protocols: &ProtocolSet,
    ) -> Result<Self, AppError> {
        let mut marks: BTreeMap<[u8; 32], CarriedMark> = carried
            .iter()
            .map(|mark| (mark.key, mark.clone()))
            .collect();
        let mut uncheckable = left_out.to_vec();
        for live in carry(old).await? {
            // A mark the store holds is within the bound: it keeps none over it.
            if live.mark.len() > MAX_SEEN_MARK_BYTES {
                return Err(corrupt());
            }
            let Some(backup) = marks.get(&live.key) else {
                marks.insert(live.key, live);
                continue;
            };
            let record = live.record.clone().or_else(|| backup.record.clone());
            let merged = record.as_ref().and_then(|record| {
                protocols
                    .of_collection(&record.collection)
                    .and_then(|owner| {
                        owner.protocol.merge_seen_marks(
                            &record.collection,
                            &live.mark,
                            &backup.mark,
                        )
                    })
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
            marks.insert(
                live.key,
                CarriedMark {
                    key: live.key,
                    mark,
                    record,
                },
            );
        }
        Ok(Self {
            marks: marks.into_values().collect(),
            uncheckable,
        })
    }

    /// Write the marks in `tx`, the restore's one commit, as its last writes, within the
    /// room the rest leaves of [`crate::store::MAX_BATCH_BYTES`], and keep a
    /// `RecordUncheckable` duty event for each record that can't be checked. A mark can't
    /// be rebuilt from the service, and the restore is never refused for marks: those that
    /// don't fit are left out, largest first, the record key breaking a tie, each record
    /// left out uncheckable. Returns the marks left out for room, which a backup's check
    /// moves to the records its backup left out.
    pub(crate) fn write(
        self,
        app: &mut super::App,
        tx: &mut Tx,
    ) -> Result<Vec<LeftOutMark>, AppError> {
        let ns = app.ns.clone();
        let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        // The most one duty event of an uncheckable record takes, with the counter it
        // moves: its key is of fixed width, and each number at its widest.
        let duty_bytes = {
            let mut scratch = Tx::new(&ns);
            scratch.put(
                &key::duty(u64::MAX),
                &KeptDuty {
                    to: app.protocols.names(),
                    duty: Duty::RecordUncheckable {
                        key: [u8::MAX; 32],
                        writer: [u8::MAX; 16],
                        generation: u64::MAX,
                        version: u64::MAX,
                        mark_bytes: u64::MAX,
                    },
                },
            )?;
            scratch.put(key::DUTY_NEXT, &u64::MAX)?;
            scratch.size()
        };
        let mut writes = Vec::with_capacity(self.marks.len());
        for mark in self.marks {
            let stored = encode(&SeenMark {
                mark: mark.mark.clone(),
            })?;
            let at = records::seen_key(&mark.key);
            let size = len(ns.len())
                .saturating_add(len(at.len()))
                .saturating_add(len(stored.len()));
            writes.push((mark, at, stored, size));
        }
        // Left out first: the largest, then the lowest key.
        writes.sort_by(|a, b| {
            b.0.mark
                .len()
                .cmp(&a.0.mark.len())
                .then(a.0.key.cmp(&b.0.key))
        });
        // The commit's own overhead at an owned store comes out of the room too.
        let room = crate::store::MAX_BATCH_BYTES
            .saturating_sub(tx.size())
            .saturating_sub(len(ns.len()).saturating_add(32));
        let base = len(self.uncheckable.len()).saturating_mul(duty_bytes);
        let mut total = writes
            .iter()
            .fold(base, |sum, (_, _, _, size)| sum.saturating_add(*size));
        let mut leave = 0;
        while total > room && leave < writes.len() {
            if let Some((_, _, _, size)) = writes.get(leave) {
                total = total.saturating_sub(*size).saturating_add(duty_bytes);
            }
            leave += 1;
        }
        let kept = writes.split_off(leave);
        let left: Vec<LeftOutMark> = writes.iter().map(|(mark, ..)| mark.left_out()).collect();
        for left in self.uncheckable.iter().chain(&left) {
            let to = match &left.record {
                Some(record) => app.owners_of_collection(&record.collection),
                None => app.protocols.names(),
            };
            let (writer, version) = match &left.record {
                Some(record) => (
                    record.writer,
                    RecordVersion::new(record.generation, record.version),
                ),
                // No write is known of a mark held without its record: the app's own
                // restore is what leaves it unchecked.
                None => (app.state.meta.app_id, RecordVersion::NONE),
            };
            app.keep_duty_for(
                tx,
                to,
                Duty::RecordUncheckable {
                    key: left.key,
                    writer,
                    generation: version.generation,
                    version: version.version,
                    mark_bytes: left.mark_bytes,
                },
            )?;
        }
        for (_, at, stored, _) in kept {
            tx.put_raw(&at, stored)?;
        }
        Ok(left)
    }
}
