//! Peer facts learned from a completed list read or a visible operation (Switch spec 7).

use pubky_switch_core::admission::{ReplyGrant, ReplyOrigin};
use pubky_switch_core::enc::{b64, pubky_key, serde_b64_vec, unb64_array};
use pubky_switch_core::time::MAX_TIME_MS;
use serde::{Deserialize, Serialize};

use super::super::list_settlement::{EFFECT_CUTOFF, order_key};
use super::super::state::{Reader, SCHEMA_VERSION, Tx};
use super::super::{App, AppError, FeedPosition};
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

/// Kept and reply rows a restore brought back that nothing has verified since: the
/// backup's view, which the service may no longer hold. They show in the app's copy, but
/// never drive a write that widens admission: the move and a loss don't restore a kept peer
/// from them, and a send writes its reply grant again (a repeat if it is held). A verified
/// change to the row, or a complete list read, clears its mark (Switch spec 7, 12.4).
pub(in crate::app) const UNVERIFIED: &str = "lc/unverified/";
pub(in crate::app) const UNVERIFIED_KEPT: &str = "lc/unverified/kept/";
const UNVERIFIED_REPLY: &str = "lc/unverified/reply/";

/// The mark of a restored, unverified kept (`kept`) or reply row of `who`.
pub(in crate::app) fn unverified_key(kept: bool, who: &[u8; 32]) -> String {
    if kept {
        format!("{UNVERIFIED_KEPT}{}", pubky_switch_core::enc::pubky_id(who))
    } else {
        format!("{UNVERIFIED_REPLY}{}", b64(who))
    }
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

#[derive(Clone, Serialize, Deserialize)]
struct SavedReply {
    id: String,
    #[serde(with = "serde_b64_vec")]
    observation: Vec<u8>,
}

/// The current membership observations. The independently owed upload, if any,
/// belongs to the provider loss. Neither source grants authority at another service.
#[derive(Clone, Default, Serialize, Deserialize)]
pub(in crate::app) struct SavedPeers {
    kept: Vec<String>,
    replies: Vec<SavedReply>,
    deny: Vec<String>,
    /// The signed position of the last complete list read, when one was made.
    last_read: Option<Option<FeedPosition>>,
    ahead: Vec<(String, FeedPosition)>,
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

    /// The deny entries carried, sorted.
    pub(in crate::app) fn denies(&self) -> &[String] {
        &self.deny
    }

    pub(in crate::app) async fn collect(
        app: &App,
        reader: &Reader,
        cursor: FeedPosition,
    ) -> Result<Self, AppError> {
        let members = |rows: Vec<(String, Vec<u8>)>| rows.into_iter().map(|(id, _)| id).collect();
        let mut replies = Vec::new();
        for (id, observation) in reader.scan_raw(REPLIES).await? {
            unb64_array::<32>(&id)?;
            ReplyObservation::read(&observation)?;
            replies.push(SavedReply { id, observation });
        }
        let last_read = reader.get::<Option<FeedPosition>>(LIST_POSITION).await?;
        Ok(Self {
            kept: members(reader.scan_raw("lc/contact/").await?),
            replies,
            deny: members(reader.scan_raw("lc/deny/").await?),
            last_read,
            ahead: reader
                .scan::<FeedPosition>(EFFECT_CUTOFF)
                .await?
                .into_iter()
                .filter(|(_, pos)| !app.feed_covers(cursor, *pos))
                .collect(),
        })
    }

    pub(in crate::app) fn install(&self, tx: &mut Tx, generation: u64) -> Result<(), AppError> {
        let invalid = || AppError::InvalidData("invalid peer observation in backup".into());
        for (ids, prefix) in [(&self.kept, "lc/contact/"), (&self.deny, "lc/deny/")] {
            if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(invalid());
            }
            for id in ids {
                let who = pubky_key(id).map_err(|_| invalid())?;
                tx.put_raw(&format!("{prefix}{id}"), Vec::new())?;
                if prefix == "lc/contact/" {
                    tx.put(&unverified_key(true, &who), &())?;
                }
            }
        }
        if self.replies.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(invalid());
        }
        for saved in &self.replies {
            let who = unb64_array::<32>(&saved.id).map_err(|_| invalid())?;
            ReplyObservation::read(&saved.observation).map_err(|_| invalid())?;
            tx.put_raw(&reply_key(&who), saved.observation.clone())?;
            tx.put(&unverified_key(false, &who), &())?;
        }
        if self.ahead.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(invalid());
        }
        for (key, pos) in &self.ahead {
            let (kind, id) = key.split_once('/').ok_or_else(invalid)?;
            let who = unb64_array::<32>(id).map_err(|_| invalid())?;
            if !matches!(kind, "reply" | "contact" | "deny")
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
        assert!(SavedPeers::default().is_empty() && !good.is_empty());
    }
}
