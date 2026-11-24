//! The seen marks a backup carries and every restore installs (Dispatch spec 8.2, 12.4 "Seen
//! marks"): each record's mark the store holds at `hw/<key>`, in the store's own shape,
//! written last in the restore's one commit, in whatever room the rest leaves.

use std::collections::{BTreeSet, BinaryHeap};

use pubky_dispatch_core::enc::{serde_b64, unb64_array};
use serde::{Deserialize, Serialize};

use super::AppError;
use super::protocol::MAX_SEEN_MARK_BYTES;
use super::records::{self, SEEN_PREFIX, SeenMark};
use super::state::{Reader, Tx, decode, encode};
use crate::store::{MAX_BATCH_BYTES, StoreError};

/// A record's mark as a backup carries it: its key and the mark as the store holds it.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CarriedMark {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    mark: SeenMark,
}

impl std::fmt::Debug for CarriedMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CarriedMark({} bytes)", self.mark.mark.len())
    }
}

impl CarriedMark {
    /// The record key.
    pub(crate) fn key(&self) -> [u8; 32] {
        self.key
    }
}

/// What a restore's commit did with the backup's marks: those it left out for room, and
/// whether its marks are incomplete, these or the backup's own.
#[derive(Default)]
pub(crate) struct Installed {
    pub(crate) left: Vec<[u8; 32]>,
    pub(crate) incomplete: bool,
}

/// The bytes base64 without padding takes for `n` bytes.
fn b64_len(n: usize) -> u64 {
    let n = u64::try_from(n).unwrap_or(u64::MAX);
    n.saturating_mul(4).saturating_add(2) / 3
}

/// What a mark's stored value takes besides its base64: the store's own encoding of an empty
/// mark.
fn mark_overhead() -> Result<u64, AppError> {
    let empty = encode(&SeenMark { mark: Vec::new() })?;
    Ok(u64::try_from(empty.len()).unwrap_or(u64::MAX))
}

/// The bytes a mark of `mark_len` bytes takes in a commit to `ns`: namespace, key and value,
/// without encoding it.
fn written_len(ns: &str, overhead: u64, mark_len: usize) -> u64 {
    let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    len(ns.len())
        .saturating_add(len(SEEN_PREFIX.len()).saturating_add(43))
        .saturating_add(overhead)
        .saturating_add(b64_len(mark_len))
}

/// The most room a restore's one commit can leave marks in `ns`: the batch a store takes,
/// less an owned store's overhead.
fn most_room(ns: &str) -> u64 {
    MAX_BATCH_BYTES.saturating_sub(
        u64::try_from(ns.len())
            .unwrap_or(u64::MAX)
            .saturating_add(32),
    )
}

/// A mark held while the backup's marks are chosen, ordered so the one left out first is the
/// greatest: the largest, then the lowest key.
struct Candidate {
    size: u64,
    mark: CarriedMark,
}

impl Candidate {
    fn order(&self) -> (usize, std::cmp::Reverse<[u8; 32]>) {
        (self.mark.mark.mark.len(), std::cmp::Reverse(self.mark.key))
    }
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.order() == other.order()
    }
}

impl Eq for Candidate {}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.order().cmp(&other.order())
    }
}

/// The marks `reader` holds that a backup can carry, from the same read as the rest of the
/// backup, and whether its marks are incomplete (Dispatch spec 12.4).
pub(crate) async fn carry(reader: &Reader) -> Result<(Vec<CarriedMark>, bool), AppError> {
    let room = most_room(&reader.ns);
    carry_within(reader, room).await
}

/// [`carry`] keeping at most `room` bytes of marks as a commit writes them. The store is read
/// one scan page at a time, and of the marks read only those that can still fit are held:
/// once they take more than `room`, the one left out first goes, largest first, the lowest key
/// first among equals, as [`write`] leaves them out. So what is held is bounded by `room` plus
/// one mark and one scan page, whatever the store holds. A mark whose key or value doesn't
/// read is left out, and so are the rest when the store reports the marks' scan corrupt: the
/// marks are then incomplete, and nothing else of the backup depends on them.
pub(crate) async fn carry_within(
    reader: &Reader,
    room: u64,
) -> Result<(Vec<CarriedMark>, bool), AppError> {
    let ns = reader.ns.clone();
    let overhead = mark_overhead()?;
    let mut held = BinaryHeap::new();
    let mut total = 0u64;
    let mut incomplete = false;
    let scanned = reader
        .scan_bytes_each(SEEN_PREFIX, |rest, bytes| {
            let key = std::str::from_utf8(&rest)
                .ok()
                .and_then(|rest| unb64_array::<32>(rest).ok());
            match (key, decode::<SeenMark>(&bytes)) {
                (Some(key), Ok(mark)) if mark.mark.len() <= MAX_SEEN_MARK_BYTES => {
                    let size = written_len(&ns, overhead, mark.mark.len());
                    total = total.saturating_add(size);
                    held.push(Candidate {
                        size,
                        mark: CarriedMark { key, mark },
                    });
                    while total > room {
                        let Some(out) = held.pop() else { break };
                        total = total.saturating_sub(out.size);
                        incomplete = true;
                    }
                }
                _ => incomplete = true,
            }
        })
        .await;
    match scanned {
        Ok(()) => {}
        // Confined to the marks: the rest of the backup is read apart and reports its own.
        Err(AppError::Store(StoreError::Corrupt)) => incomplete = true,
        Err(error) => return Err(error),
    }
    let mut out: Vec<CarriedMark> = held.into_iter().map(|held| held.mark).collect();
    out.sort_by_key(|mark| mark.key);
    Ok((out, incomplete))
}

/// A backup's marks, checked: each record once, and none over [`MAX_SEEN_MARK_BYTES`], which
/// no app keeps.
pub(crate) fn check(carried: &[CarriedMark]) -> Result<(), AppError> {
    let invalid = |why: &str| AppError::InvalidData(format!("the backup: {why}"));
    let mut keys = BTreeSet::new();
    for mark in carried {
        if mark.mark.mark.len() > MAX_SEEN_MARK_BYTES {
            return Err(invalid("a seen mark it carries is over the bound"));
        }
        if !keys.insert(mark.key) {
            return Err(invalid("it carries two seen marks of one record"));
        }
    }
    Ok(())
}

/// Write `marks` in `tx`, the restore's one commit, as its last writes, in the room the rest
/// leaves of [`MAX_BATCH_BYTES`] less an owned store's overhead (Dispatch spec 12.4). No size
/// check counts them and nothing is refused or left out for them: those that don't fit are
/// left out, largest first, the record key breaking a tie, and only those written are
/// encoded. Returns the keys left out.
pub(crate) fn write(
    ns: &str,
    tx: &mut Tx,
    marks: &[CarriedMark],
) -> Result<Vec<[u8; 32]>, AppError> {
    let room = most_room(ns).saturating_sub(tx.size());
    let overhead = mark_overhead()?;
    let mut order: Vec<(&CarriedMark, u64)> = marks
        .iter()
        .map(|mark| (mark, written_len(ns, overhead, mark.mark.mark.len())))
        .collect();
    // Left out first: the largest, then the lowest key.
    order.sort_by(|a, b| {
        b.0.mark
            .mark
            .len()
            .cmp(&a.0.mark.mark.len())
            .then(a.0.key.cmp(&b.0.key))
    });
    let mut kept = order
        .iter()
        .fold(0u64, |sum, (_, size)| sum.saturating_add(*size));
    let mut leave = 0;
    while kept > room {
        let Some((_, size)) = order.get(leave) else {
            break;
        };
        kept = kept.saturating_sub(*size);
        leave += 1;
    }
    let installed = order.split_off(leave);
    for (mark, _) in installed {
        tx.put_raw(&records::seen_key(&mark.key), encode(&mark.mark)?)?;
    }
    Ok(order.iter().map(|(mark, _)| mark.key).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seen_marks_written_len_is_the_encoded_size() {
        let overhead = mark_overhead().unwrap();
        for n in [0, 1, 2, 3, 4, 100, 60_000, MAX_SEEN_MARK_BYTES] {
            let stored = encode(&SeenMark { mark: vec![7; n] }).unwrap();
            let key = records::seen_key(&[1; 32]);
            assert_eq!(
                written_len("client/app", overhead, n),
                ("client/app".len() + key.len() + stored.len()) as u64,
                "{n}"
            );
        }
    }
}
