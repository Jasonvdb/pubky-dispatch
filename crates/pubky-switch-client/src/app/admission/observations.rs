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
pub(in crate::app) const READ_TIME: &str = "lc/peer_list_time";

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
        if !value.is_empty() || last_used.is_some_and(|last| last < at) {
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
    last_read: Option<(Option<FeedPosition>, u64)>,
    ahead: Vec<(String, FeedPosition)>,
}

impl SavedPeers {
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
        let last_read = match reader.get::<u64>(READ_TIME).await? {
            Some(at) => Some((
                reader
                    .get(LIST_POSITION)
                    .await?
                    .ok_or(StoreError::Corrupt)?,
                at,
            )),
            None => None,
        };
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
                pubky_key(id).map_err(|_| invalid())?;
                tx.put_raw(&format!("{prefix}{id}"), Vec::new())?;
            }
        }
        if self.replies.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(invalid());
        }
        for saved in &self.replies {
            let who = unb64_array::<32>(&saved.id).map_err(|_| invalid())?;
            ReplyObservation::read(&saved.observation).map_err(|_| invalid())?;
            tx.put_raw(&reply_key(&who), saved.observation.clone())?;
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
        if let Some((position, at)) = self.last_read {
            if at > MAX_TIME_MS || position.is_some_and(|pos| pos.generation > generation) {
                return Err(invalid());
            }
            tx.put(LIST_POSITION, &position)?;
            tx.put(READ_TIME, &at)?;
        }
        Ok(())
    }
}
