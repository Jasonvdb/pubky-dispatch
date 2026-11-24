//! Peer facts learned from a completed list read or a visible operation (Switch spec 7).

use pubky_switch_core::admission::{ReplyGrant, ReplyOrigin};
use pubky_switch_core::enc::{b64, pubky_key, serde_b64_vec, unb64_array};
use pubky_switch_core::time::MAX_TIME_MS;
use serde::{Deserialize, Serialize};

use super::super::list_settlement::{EFFECT_CUTOFF, order_key};
use super::super::state::{Reader, SCHEMA_VERSION, Tx};
use super::super::{AppError, AppState, FeedPosition, feed};
use super::LIST_POSITION;
use crate::error::StoreError;

/// A successful repeat says the peer may reply. Only a signed list row or the
/// service's original invitation grant can identify its writer and creation time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::app) enum ReplyObservation {
    Present,
    Observed { grant: ReplyGrant, as_of_ms: u64 },
}

pub(in crate::app) const REPLIES: &str = "lc/r/";

/// The value of a kept row a restore brought back that nothing has verified since; a
/// verified kept row is empty. A reply row says the same with [`RESTORED_REPLY`] in its tag.
/// Such a row is the backup's view, which the service may no longer hold. It shows in the
/// app's copy, but doesn't admit, doesn't count as a held reply grant, and a cooperative
/// move doesn't keep the peer again from it; a send writes its reply grant again, a repeat
/// if it is held. A verified change to the row, or a complete list read, writes the row
/// without the mark (Switch spec 7, 12.4). At a provider loss the app's copy is the only
/// one left, and its kept peers are contributed whether verified or not (Switch spec 12.6).
pub(in crate::app) const RESTORED_KEPT: &[u8] = &[1];
const RESTORED_REPLY: u8 = 0x80;

/// Whether a kept row's stored value marks it restored and unverified. A value that is
/// neither empty nor the mark reads as the mark too: the row doesn't admit, and the next
/// list read or the app's own write on the peer writes it anew.
pub(in crate::app) fn kept_row_restored(value: &[u8]) -> bool {
    !value.is_empty()
}

/// Whether `who` has a kept (`kept`) or reply row that is held and verified. A reply row
/// that doesn't read back counts as not held, so the app writes its grant again, and the
/// grant's settlement writes the row anew.
pub(in crate::app) async fn verified_row(
    reader: &Reader,
    kept: bool,
    who: &[u8; 32],
) -> Result<bool, AppError> {
    let reason = if kept {
        pubky_switch_core::admission::PeerReason::Kept
    } else {
        pubky_switch_core::admission::PeerReason::Reply
    };
    let Some(value) = reader
        .get_raw(super::allow_key(reason, who).as_bytes())
        .await?
    else {
        return Ok(false);
    };
    Ok(if kept {
        !kept_row_restored(&value)
    } else {
        ReplyObservation::read_row(&value).is_ok_and(|(_, restored)| !restored)
    })
}

pub(in crate::app) fn reply_key(who: &[u8; 32]) -> String {
    format!("{REPLIES}{}", b64(who))
}

impl ReplyObservation {
    // A byte for the schema and a tag for the writer. The times are big-endian
    // milliseconds. The last-use time is absent until the grant has been used.
    pub(in crate::app) fn bytes(self) -> Vec<u8> {
        let mut value = vec![SCHEMA_VERSION as u8];
        match self {
            Self::Present => value.push(0),
            Self::Observed { grant, as_of_ms } => {
                match grant.origin {
                    ReplyOrigin::App(id) => {
                        value.push(1);
                        value.extend(id);
                    }
                    ReplyOrigin::Invite(hash) => {
                        value.push(2);
                        value.extend(hash);
                    }
                }
                value.extend(grant.at.to_be_bytes());
                value.extend(as_of_ms.to_be_bytes());
                if let Some(last) = grant.last_used {
                    value.extend(last.to_be_bytes());
                }
            }
        }
        value
    }

    /// The stored row: the observation, with the restore's mark when `restored`.
    pub(in crate::app) fn row_bytes(self, restored: bool) -> Vec<u8> {
        let mut value = self.bytes();
        if restored && let Some(tag) = value.get_mut(1) {
            *tag |= RESTORED_REPLY;
        }
        value
    }

    /// A stored row: the observation, and whether a restore brought it back unverified.
    pub(in crate::app) fn read_row(value: &[u8]) -> Result<(Self, bool), StoreError> {
        let mut value = value.to_vec();
        let restored = match value.get_mut(1) {
            Some(tag) if *tag & RESTORED_REPLY != 0 => {
                *tag &= !RESTORED_REPLY;
                true
            }
            Some(_) => false,
            None => return Err(StoreError::Corrupt),
        };
        Ok((Self::read(&value)?, restored))
    }

    pub(in crate::app) fn read(mut value: &[u8]) -> Result<Self, StoreError> {
        fn take<const N: usize>(value: &mut &[u8]) -> Result<[u8; N], StoreError> {
            let (head, tail) = value.split_first_chunk::<N>().ok_or(StoreError::Corrupt)?;
            *value = tail;
            Ok(*head)
        }
        fn time(value: &mut &[u8]) -> Result<u64, StoreError> {
            let ms = u64::from_be_bytes(take(value)?);
            (ms <= MAX_TIME_MS).then_some(ms).ok_or(StoreError::Corrupt)
        }
        let [version, tag] = take(&mut value)?;
        if u32::from(version) != SCHEMA_VERSION {
            return Err(StoreError::Corrupt);
        }
        let origin = match tag {
            0 if value.is_empty() => return Ok(Self::Present),
            1 => ReplyOrigin::App(take(&mut value)?),
            2 => ReplyOrigin::Invite(take(&mut value)?),
            _ => return Err(StoreError::Corrupt),
        };
        let at = time(&mut value)?;
        let as_of_ms = time(&mut value)?;
        let last_used = (!value.is_empty()).then(|| time(&mut value)).transpose()?;
        // Nothing follows the last use, which is never before the grant, and nothing is
        // observed before the grant it observes.
        if !value.is_empty() || last_used.is_some_and(|last| last < at) || as_of_ms < at {
            return Err(StoreError::Corrupt);
        }
        Ok(Self::Observed {
            grant: ReplyGrant {
                origin,
                at,
                last_used,
            },
            as_of_ms,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SavedReply {
    id: String,
    #[serde(with = "serde_b64_vec")]
    observation: Vec<u8>,
}

/// The current membership observations. The independently owed upload, if any,
/// belongs to the provider loss. Neither source grants authority at another service.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::app) struct SavedPeers {
    kept: Vec<String>,
    replies: Vec<SavedReply>,
    deny: Vec<String>,
    /// The signed position of the last complete list read, when one was made.
    last_read: Option<Option<FeedPosition>>,
    ahead: Vec<(String, FeedPosition)>,
    /// What the backup left out of the lists because they didn't fit beside the rest.
    left_out: crate::app::ListsLeftOut,
}

impl SavedPeers {
    /// Whether the backup carries no copy of the lists: the restored app then reads them
    /// before it relies on them, as after a provider loss (Switch spec 7).
    pub(in crate::app) fn is_empty(&self) -> bool {
        self.kept.is_empty()
            && self.replies.is_empty()
            && self.deny.is_empty()
            && self.last_read.is_none()
            && self.ahead.is_empty()
    }

    /// What a backup carries when these don't fit beside the rest: the deny entries alone,
    /// with their positions and that of the last complete read, and then nothing. A size
    /// limit drops the kept peers and reply grants, which only narrows admission, before it
    /// drops a deny entry (Switch spec 7).
    pub(in crate::app) fn smaller(&self) -> Self {
        use crate::app::ListsLeftOut;
        let everything = || Self {
            left_out: ListsLeftOut::Everything,
            ..Self::default()
        };
        if self.left_out != ListsLeftOut::Nothing {
            return everything();
        }
        // Without kept peers or reply grants to leave out, the step leaves out only their
        // positions, and says nothing was left out; one that changes nothing goes on.
        let denies_only = Self {
            kept: Vec::new(),
            replies: Vec::new(),
            deny: self.deny.clone(),
            last_read: self.last_read,
            ahead: self
                .ahead
                .iter()
                .filter(|(key, _)| key.starts_with("deny/"))
                .cloned()
                .collect(),
            left_out: if self.kept.is_empty() && self.replies.is_empty() {
                ListsLeftOut::Nothing
            } else {
                ListsLeftOut::KeptAndReplies
            },
        };
        if denies_only == *self {
            everything()
        } else {
            denies_only
        }
    }

    /// What the backup left out of its lists.
    pub(in crate::app) fn left_out(&self) -> crate::app::ListsLeftOut {
        self.left_out
    }

    /// How many kept peers and reply grants are carried.
    pub(in crate::app) fn unverified_counts(&self) -> (u64, u64) {
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        (count(self.kept.len()), count(self.replies.len()))
    }

    /// The deny entries carried, sorted.
    pub(in crate::app) fn denies(&self) -> &[String] {
        &self.deny
    }

    pub(in crate::app) async fn collect(
        state: &AppState,
        reader: &Reader,
        cursor: FeedPosition,
    ) -> Result<Self, AppError> {
        let members = |rows: Vec<(String, Vec<u8>)>| rows.into_iter().map(|(id, _)| id).collect();
        let mut replies = Vec::new();
        for (id, row) in reader.scan_raw(REPLIES).await? {
            unb64_array::<32>(&id)?;
            // The backup carries the observation without the mark: a restore marks every
            // row it brings back.
            let (observation, _) = ReplyObservation::read_row(&row)?;
            replies.push(SavedReply {
                id,
                observation: observation.bytes(),
            });
        }
        let last_read = reader.get::<Option<FeedPosition>>(LIST_POSITION).await?;
        Ok(Self {
            kept: members(reader.scan_raw("lc/kept/").await?),
            replies,
            deny: members(reader.scan_raw("lc/deny/").await?),
            last_read,
            ahead: reader
                .scan::<FeedPosition>(EFFECT_CUTOFF)
                .await?
                .into_iter()
                .filter(|(_, pos)| {
                    feed::received_order(state, cursor, *pos).is_none_or(|order| order.is_lt())
                })
                .collect(),
            left_out: crate::app::ListsLeftOut::Nothing,
        })
    }

    pub(in crate::app) fn install(&self, tx: &mut Tx, generation: u64) -> Result<(), AppError> {
        let invalid = || AppError::InvalidData("invalid peer observation in backup".into());
        // What a backup left out isn't there.
        let left_out_present = match self.left_out {
            crate::app::ListsLeftOut::Nothing => false,
            crate::app::ListsLeftOut::KeptAndReplies => {
                !self.kept.is_empty() || !self.replies.is_empty()
            }
            crate::app::ListsLeftOut::Everything => !self.is_empty(),
        };
        if left_out_present {
            return Err(invalid());
        }
        for (ids, prefix) in [(&self.kept, "lc/kept/"), (&self.deny, "lc/deny/")] {
            if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(invalid());
            }
            for id in ids {
                pubky_key(id).map_err(|_| invalid())?;
                let value = if prefix == "lc/kept/" {
                    RESTORED_KEPT.to_vec()
                } else {
                    Vec::new()
                };
                tx.put_raw(&format!("{prefix}{id}"), value)?;
            }
        }
        if self.replies.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(invalid());
        }
        for saved in &self.replies {
            let who = unb64_array::<32>(&saved.id).map_err(|_| invalid())?;
            let observation = ReplyObservation::read(&saved.observation).map_err(|_| invalid())?;
            tx.put_raw(&reply_key(&who), observation.row_bytes(true))?;
        }
        if self.ahead.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(invalid());
        }
        for (key, pos) in &self.ahead {
            let (kind, id) = key.split_once('/').ok_or_else(invalid)?;
            let who = unb64_array::<32>(id).map_err(|_| invalid())?;
            if !matches!(kind, "reply" | "kept" | "deny")
                || pos.generation == 0
                || pos.generation > generation
                || pos.seq == 0
            {
                return Err(invalid());
            }
            tx.put(&order_key(kind, &who), pos)?;
        }
        if let Some(position) = self.last_read {
            if position.is_some_and(|pos| pos.generation == 0 || pos.generation > generation) {
                return Err(invalid());
            }
            tx.put(LIST_POSITION, &position)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(origin: ReplyOrigin, last_used: Option<u64>) -> ReplyObservation {
        ReplyObservation::Observed {
            grant: ReplyGrant {
                origin,
                at: 10,
                last_used,
            },
            as_of_ms: 20,
        }
    }

    #[test]
    fn test_reply_observation_round_trips() {
        for observation in [
            ReplyObservation::Present,
            observed(ReplyOrigin::App([7; 16]), None),
            observed(ReplyOrigin::App([7; 16]), Some(15)),
            observed(ReplyOrigin::Invite([8; 32]), Some(10)),
        ] {
            assert_eq!(
                ReplyObservation::read(&observation.bytes()).unwrap(),
                observation
            );
        }
    }

    #[test]
    fn test_reply_observation_refuses_every_other_shape() {
        let good = observed(ReplyOrigin::Invite([8; 32]), Some(15)).bytes();
        let mut other_version = good.clone();
        other_version[0] = other_version[0].wrapping_add(1);
        let mut unknown_tag = good.clone();
        unknown_tag[1] = 3;
        let mut trailing = good.clone();
        trailing.push(0);
        let mut membership_with_payload = ReplyObservation::Present.bytes();
        membership_with_payload.push(0);
        let used_before = observed(ReplyOrigin::App([7; 16]), Some(5)).bytes();
        let mut observed_before = observed(ReplyOrigin::App([7; 16]), None).bytes();
        let len = observed_before.len();
        observed_before[len - 8..].copy_from_slice(&5u64.to_be_bytes());
        let mut past_time = observed(ReplyOrigin::App([7; 16]), None).bytes();
        let len = past_time.len();
        past_time[len - 8..].copy_from_slice(&(MAX_TIME_MS + 1).to_be_bytes());
        for (name, bytes) in [
            ("another schema version", other_version),
            ("an unknown tag", unknown_tag),
            ("bytes after the last use", trailing),
            ("membership with a payload", membership_with_payload),
            ("cut short", good[..good.len() - 3].to_vec()),
            ("a last use before the grant", used_before),
            ("observed before the grant", observed_before),
            ("a time past the range", past_time),
            ("empty", Vec::new()),
        ] {
            assert!(ReplyObservation::read(&bytes).is_err(), "{name}");
        }
    }

    #[test]
    fn test_saved_peers_install_refuses_what_a_store_never_holds() {
        let peer = |n: u8| pubky_switch_core::enc::pubky_id(&[n; 32]);
        let position = |generation, seq| FeedPosition { generation, seq };
        let good = SavedPeers {
            kept: vec![peer(1), peer(2)],
            replies: Vec::new(),
            deny: vec![peer(3)],
            last_read: Some(Some(position(2, 4))),
            ahead: vec![(format!("deny/{}", b64(&[3; 32])), position(2, 5))],
            left_out: crate::app::ListsLeftOut::Nothing,
        };
        let mut sorted = good.kept.clone();
        sorted.sort();
        let good = SavedPeers {
            kept: sorted,
            ..good
        };
        good.install(&mut Tx::new("app"), 2).unwrap();
        let with = |change: &dyn Fn(&mut SavedPeers)| {
            let mut peers = good.clone();
            change(&mut peers);
            peers.install(&mut Tx::new("app"), 2).is_err()
        };
        assert!(with(&|p| p.kept.reverse()), "out of order");
        assert!(with(&|p| p.deny.push(p.deny[0].clone())), "repeated");
        assert!(
            with(&|p| p.kept.push("not a pubky".into())),
            "not a Pubky ID"
        );
        assert!(
            with(&|p| p.replies.push(SavedReply {
                id: b64(&[4; 32]),
                observation: vec![0xff],
            })),
            "an observation that doesn't read"
        );
        assert!(
            with(&|p| p.ahead[0].0 = format!("other/{}", b64(&[3; 32]))),
            "another kind"
        );
        assert!(with(&|p| p.ahead[0].1 = position(0, 5)), "generation 0");
        assert!(
            with(&|p| p.ahead[0].1 = position(3, 5)),
            "past the backup's generation"
        );
        assert!(with(&|p| p.ahead[0].1 = position(2, 0)), "seq 0");
        assert!(
            with(&|p| p.last_read = Some(Some(position(3, 1)))),
            "a read past the backup"
        );
        assert!(
            with(&|p| p.last_read = Some(Some(position(0, 1)))),
            "a read at generation 0"
        );
        let reply = |n: u8| SavedReply {
            id: b64(&[n; 32]),
            observation: ReplyObservation::Present.bytes(),
        };
        assert!(
            with(&|p| p.replies = vec![reply(6), reply(5)]),
            "replies out of order"
        );
        assert!(
            with(&|p| p
                .ahead
                .insert(0, (format!("deny/{}", b64(&[9; 32])), position(2, 6)))),
            "positions out of order"
        );
        assert!(
            with(&|p| p.ahead[0].0 = "deny/not-a-key".into()),
            "a position of no peer"
        );
        assert!(
            with(&|p| p.left_out = crate::app::ListsLeftOut::KeptAndReplies),
            "kept peers a backup says it left out"
        );
        assert!(
            with(&|p| p.left_out = crate::app::ListsLeftOut::Everything),
            "lists a backup says it left out"
        );
        assert!(SavedPeers::default().is_empty() && !good.is_empty());
    }

    #[test]
    fn test_saved_peers_install_refuses_a_kept_position_under_the_old_kind() {
        let position = FeedPosition {
            generation: 2,
            seq: 5,
        };
        let with = |kind: &str| SavedPeers {
            ahead: vec![(format!("{kind}/{}", b64(&[1; 32])), position)],
            ..SavedPeers::default()
        };
        let mut tx = Tx::new("app");
        with("kept").install(&mut tx, 2).unwrap();
        assert!(tx.pending_state(&order_key("kept", &[1; 32])) == Some(true));
        // A backup from before kept peers were named `kept` carries `contact/`: refused, never
        // read as a kept position.
        assert!(with("contact").install(&mut Tx::new("app"), 2).is_err());
    }

    #[test]
    fn test_saved_peers_smaller_keeps_the_deny_entries_and_then_nothing() {
        let peer = |n: u8| pubky_switch_core::enc::pubky_id(&[n; 32]);
        let position = FeedPosition {
            generation: 2,
            seq: 5,
        };
        let full = SavedPeers {
            kept: vec![peer(1)],
            replies: vec![SavedReply {
                id: b64(&[4; 32]),
                observation: ReplyObservation::Present.bytes(),
            }],
            deny: vec![peer(3)],
            last_read: Some(Some(position)),
            ahead: vec![
                (format!("deny/{}", b64(&[3; 32])), position),
                (format!("kept/{}", b64(&[1; 32])), position),
            ],
            left_out: crate::app::ListsLeftOut::Nothing,
        };
        let denies = full.smaller();
        assert_eq!(
            denies,
            SavedPeers {
                deny: vec![peer(3)],
                last_read: Some(Some(position)),
                ahead: vec![(format!("deny/{}", b64(&[3; 32])), position)],
                left_out: crate::app::ListsLeftOut::KeptAndReplies,
                ..SavedPeers::default()
            }
        );
        // Without kept peers or replies, the first step says nothing was left out.
        let positions_only = SavedPeers {
            kept: Vec::new(),
            replies: Vec::new(),
            ..full.clone()
        }
        .smaller();
        assert_eq!(positions_only.left_out(), crate::app::ListsLeftOut::Nothing);
        assert_eq!(
            positions_only.smaller().left_out(),
            crate::app::ListsLeftOut::Everything
        );
        // A backup that doesn't say what it left out is refused.
        let mut value = serde_json::to_value(&full).unwrap();
        value.as_object_mut().unwrap().remove("left_out");
        assert!(serde_json::from_value::<SavedPeers>(value).is_err());
        let none = denies.smaller();
        assert!(none.is_empty());
        assert_eq!(none.left_out(), crate::app::ListsLeftOut::Everything);
        assert_eq!(none.smaller(), none);
    }

    #[test]
    fn test_restored_rows_carry_their_mark_in_the_row() {
        for observation in [
            ReplyObservation::Present,
            observed(ReplyOrigin::Invite([5; 32]), Some(15)),
        ] {
            for restored in [false, true] {
                let row = observation.row_bytes(restored);
                assert_eq!(
                    ReplyObservation::read_row(&row).unwrap(),
                    (observation, restored)
                );
                // The backup's form is the observation alone.
                assert_eq!(ReplyObservation::read(&row).is_ok(), !restored);
            }
        }
        assert!(ReplyObservation::read_row(&[]).is_err());
        assert!(!kept_row_restored(&[]));
        assert!(kept_row_restored(RESTORED_KEPT));
        // A value that is neither reads as restored: it doesn't admit, and is written anew.
        assert!(kept_row_restored(&[2]));
    }
}
