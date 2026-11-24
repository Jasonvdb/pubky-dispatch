//! The seen marks a backup carries and every restore installs (Switch spec 8.2, 12.4 "Seen
//! marks"): each record's mark the store holds at `hw/<key>`, in the store's own shape,
//! written last in the restore's one commit, in whatever room the rest leaves.

use std::collections::BTreeSet;

use pubky_switch_core::enc::{serde_b64, unb64_array};
use serde::{Deserialize, Serialize};

use super::AppError;
use super::protocol::MAX_SEEN_MARK_BYTES;
use super::records::{self, SEEN_PREFIX, SeenMark};
use super::state::{Reader, Tx, decode, encode};
use crate::store::MAX_BATCH_BYTES;

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

/// Every mark `reader` holds, from the same read as the rest of the backup, and whether one
/// didn't read: an entry whose key or value is malformed is left out, never a reason to
/// refuse the backup, and the marks are then incomplete (Switch spec 12.4).
pub(crate) async fn carry(reader: &Reader) -> Result<(Vec<CarriedMark>, bool), AppError> {
    let mut out = Vec::new();
    let mut unread = false;
    for (rest, bytes) in reader.scan_raw(SEEN_PREFIX).await? {
        match (unb64_array::<32>(&rest), decode::<SeenMark>(&bytes)) {
            (Ok(key), Ok(mark)) if mark.mark.len() <= MAX_SEEN_MARK_BYTES => {
                out.push(CarriedMark { key, mark });
            }
            _ => unread = true,
        }
    }
    Ok((out, unread))
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
/// leaves of [`MAX_BATCH_BYTES`] less an owned store's overhead (Switch spec 12.4). No size
/// check counts them and nothing is refused or left out for them: those that don't fit are
/// left out, largest first, the record key breaking a tie. Returns the keys left out.
pub(crate) fn write(
    ns: &str,
    tx: &mut Tx,
    marks: &[CarriedMark],
) -> Result<Vec<[u8; 32]>, AppError> {
    let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    let room = MAX_BATCH_BYTES
        .saturating_sub(tx.size())
        .saturating_sub(len(ns.len()).saturating_add(32));
    let mut writes = Vec::with_capacity(marks.len());
    for mark in marks {
        let stored = encode(&mark.mark)?;
        let at = records::seen_key(&mark.key);
        let size = len(ns.len())
            .saturating_add(len(at.len()))
            .saturating_add(len(stored.len()));
        writes.push((mark, at, stored, size));
    }
    // Left out first: the largest, then the lowest key.
    writes.sort_by(|a, b| {
        b.0.mark
            .mark
            .len()
            .cmp(&a.0.mark.mark.len())
            .then(a.0.key.cmp(&b.0.key))
    });
    let mut kept = writes
        .iter()
        .fold(0u64, |sum, write| sum.saturating_add(write.3));
    let mut leave = 0;
    while kept > room {
        let Some(write) = writes.get(leave) else {
            break;
        };
        kept = kept.saturating_sub(write.3);
        leave += 1;
    }
    let installed = writes.split_off(leave);
    for (_, at, stored, _) in installed {
        tx.put_raw(&at, stored)?;
    }
    Ok(writes.iter().map(|write| write.0.key).collect())
}
