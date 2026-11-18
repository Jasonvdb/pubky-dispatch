//! Complete recovery evidence in the account's independent mark (account binding 3.3).

use super::{AccountMark, MAX_MARK_FILE, MarkRead, MarkStoreError};
use crate::keys::hex_bytes;
use crate::store::KeptAppId;
use pubky_switch_core::{
    enc::pubky_id,
    json::MAX_INT,
    records::{Limits, MAX_APP_LIMIT},
    time::MAX_TIME_MS,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PriorDocument {
    #[serde(with = "hex_bytes")]
    pub(crate) hash: [u8; 32],
    pub(crate) version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoverySource {
    #[serde(with = "hex_bytes")]
    pub(crate) store_id: [u8; 16],
    #[serde(with = "hex_bytes")]
    pub(crate) identity: [u8; 32],
    pub(crate) generation_floor: u64,
    pub(crate) prior: Option<PriorDocument>,
    pub(crate) recovery_only: bool,
    pub(crate) stamped_ms: u64,
    pub(crate) directory_version: u64,
    pub(crate) apps_version: u64,
    pub(crate) had_reachable_apps: bool,
    pub(crate) limits: Limits,
    pub(crate) kept: Vec<KeptAppId>,
    pub(crate) held: Vec<HeldId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HeldId(#[serde(with = "hex_bytes")] pub(crate) [u8; 16]);

impl RecoverySource {
    // Even the shortest entry needs the 32 hex digits of an App ID.
    pub(crate) const MAX_ROWS: usize = MAX_MARK_FILE as usize / 32;

    fn belongs_to(&self, identity: &str, store_id: &str) -> bool {
        pubky_id(&self.identity) == identity && hex::encode(self.store_id) == store_id
    }

    fn is_valid(&self) -> bool {
        self.generation_floor <= MAX_INT
            && self
                .prior
                .as_ref()
                .is_none_or(|doc| (1..=MAX_INT).contains(&doc.version))
            && self.stamped_ms <= MAX_TIME_MS
            && self.directory_version <= MAX_INT
            && self.apps_version <= MAX_INT
            && self.limits.app_limit <= MAX_APP_LIMIT
            && self
                .kept
                .windows(2)
                .all(|pair| pair[0].app_id < pair[1].app_id)
            && self.held.windows(2).all(|pair| pair[0].0 < pair[1].0)
            && self.kept.iter().all(|app| {
                let document = app.reason == crate::store::KeptReason::Document;
                document == app.at_ms.is_none()
                    && (!document || (app.data_epoch.is_none() && !app.rotated))
                    && app.at_ms.is_none_or(|at| at <= MAX_TIME_MS)
                    && app.data_epoch.is_none_or(|epoch| epoch <= MAX_INT)
            })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteMark<T> {
    position: AccountMark,
    recovery: T,
}

/// The complete durable record last seen at a path. In particular, changing just the
/// exclusions in a live file is a different record even if its chain position is equal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Observed {
    pub(super) position: MarkRead,
    pub(super) recovery: Option<Arc<RecoverySource>>,
}

impl From<MarkRead> for Observed {
    fn from(position: MarkRead) -> Self {
        Self {
            position,
            recovery: None,
        }
    }
}

impl Observed {
    pub(super) fn read(bytes: Option<&[u8]>) -> Self {
        let Some(bytes) = bytes else {
            return MarkRead::Missing.into();
        };
        if bytes.len() as u64 > MAX_MARK_FILE {
            return MarkRead::NotAMark.into();
        }
        if let Ok(position) = serde_json::from_slice::<AccountMark>(bytes)
            && position.is_valid()
        {
            return MarkRead::Mark(position).into();
        }
        match serde_json::from_slice::<CompleteMark<RecoverySource>>(bytes) {
            Ok(record) if record.position.is_valid() && record.recovery.is_valid() => Self {
                position: MarkRead::Mark(record.position),
                recovery: Some(Arc::new(record.recovery)),
            },
            _ => MarkRead::NotAMark.into(),
        }
    }

    pub(super) fn checked(self, identity: &str, store_id: &str) -> Self {
        if self
            .recovery
            .as_ref()
            .is_some_and(|source| !source.belongs_to(identity, store_id))
        {
            MarkRead::NotAMark.into()
        } else {
            self
        }
    }

    pub(super) fn encode(
        position: AccountMark,
        source: Option<&RecoverySource>,
    ) -> Result<Vec<u8>, MarkStoreError> {
        let encoding_error = |error| MarkStoreError::Io(std::io::Error::other(error));
        if let Some(recovery) = source {
            // A later time-only write must still fit. Confirmation changes false to true
            // and cannot increase the size.
            let remaining_floor_digits = MAX_TIME_MS
                .to_string()
                .len()
                .saturating_sub(position.time_floor_ms.to_string().len());
            let mut bytes = vec![0; MAX_MARK_FILE as usize - remaining_floor_digits];
            let mut output = std::io::Cursor::new(bytes.as_mut_slice());
            match serde_json::to_writer(&mut output, &CompleteMark { position, recovery }) {
                Ok(()) => {
                    let len = output.position() as usize;
                    bytes.truncate(len);
                    return Ok(bytes);
                }
                Err(error) if error.io_error_kind() == Some(std::io::ErrorKind::WriteZero) => {}
                Err(error) => return Err(encoding_error(error)),
            }
        }
        serde_json::to_vec(&position).map_err(encoding_error)
    }
}
