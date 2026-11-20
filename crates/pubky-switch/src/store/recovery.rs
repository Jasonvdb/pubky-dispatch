//! A provider loss at this service (Switch spec 12.6; Switch wire 3.3, 3.7, 7.4.2): the
//! recovery a generation begins with, the App IDs held for the next generation, and the
//! account starting afresh.

use futures_util::TryStreamExt;
use sqlx::Row;

use super::{AccountTxn, KeptAppId, StoreError, from_db, identity::time_to_db, to_db};
use crate::marks::coverage::{HeldId, RecoverySource};

/// The recovery the generation the account serves began with (Switch wire 7.4.12
/// `recovery`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// The generation it declares lost, the one before the account's.
    pub recovery_from: u64,
    /// The `recovery` transition's service time.
    pub declared_at_ms: u64,
    /// Whether admission is staged still (Switch spec 12.6 step 2).
    pub admission_staged: bool,
}

/// The tables of an account's state for one generation at this service, which a recovery in
/// place empties (Switch wire 3.3): its chain, its own apps and what they wrote, its lists,
/// invites, batches and inbox, its flagged senders and pending connect requests, a hand-over,
/// the counterparties' copies and their floors, and its apps' push registrations and their
/// queued deliveries.
const GENERATION_STATE: &[&str] = &[
    // Its keys owed first (`start_recovery_in_place`); their queued deliveries go with them.
    "push_registrations",
    "push_deliveries",
    "chain_items",
    "chain_retention",
    "apps",
    "receive_keys",
    "key_bundle_parts",
    "shared_records",
    "claims",
    "peer_admissions",
    "denied_peers",
    "invite_codes",
    "batches",
    "inbox_entries",
    "sender_flags",
    "handovers",
    "app_listings",
    "peer_copies",
    "peer_floors",
    "connect_requests",
];

/// Every table with an account column that a recovery in place keeps (Switch wire 3.3,
/// 3.7): the App IDs kept for good, the enrollment answers, the push keys owed deleting, and the account's retained count tags.
/// The account's row stays too, its service time and the directory's two versions with it.
pub const RECOVERY_KEEPS: &[&str] = &[
    "kept_app_ids",
    "enrollment_answers",
    "erased_keys",
    "state_history",
];

/// Every table with an account column that a recovery in place empties: the generation's own state,
/// `claim_entries` with their claims, `divergent_uploads` with their records, and
/// `held_revoked_apps`, which joins `kept_app_ids`.
/// A table added later with an account column must be classed here or in
/// [`RECOVERY_KEEPS`], which a test of every such table checks.
pub fn recovery_clears() -> Vec<&'static str> {
    let mut tables = GENERATION_STATE.to_vec();
    tables.extend(["claim_entries", "held_revoked_apps"]);
    // A record's divergent uploads (Switch wire 7.4.14) go with their record.
    tables.push("divergent_uploads");
    tables
}

impl super::Store {
    /// The generation declared lost at `id`, read without the account's lock, while it
    /// serves the generation a recovery began; `None` otherwise. A recovery upload judged
    /// with it compares it with what it reads under the lock before it takes the judgment.
    pub async fn recovery_from_of(&self, id: &str) -> Result<Option<u64>, StoreError> {
        let row = sqlx::query("SELECT recovery_from, generation FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(StoreError::from_db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let from: Option<i64> = row.try_get("recovery_from")?;
        let generation: i64 = row.try_get("generation")?;
        let Some(from) = from else {
            return Ok(None);
        };
        let from = from_db(from, "recovery_from")?;
        Ok((from.checked_add(1) == Some(from_db(generation, "generation")?)).then_some(from))
    }
}

impl AccountTxn {
    /// The recovery the generation the account serves began with, if it began with one: a
    /// recovery the account records for an earlier generation counts for nothing.
    pub async fn recovery(&mut self) -> Result<Option<Recovery>, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT recovery_from, recovery_declared_at_ms, admission_staged FROM accounts \
             WHERE id = $1",
        )
        .bind(id)
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let from: Option<i64> = row.try_get("recovery_from")?;
        let at: Option<i64> = row.try_get("recovery_declared_at_ms")?;
        let (Some(from), Some(at)) = (from, at) else {
            return Ok(None);
        };
        let recovery = Recovery {
            recovery_from: from_db(from, "recovery_from")?,
            declared_at_ms: from_db(at, "recovery_declared_at_ms")?,
            admission_staged: row.try_get("admission_staged")?,
        };
        Ok(
            (recovery.recovery_from.checked_add(1) == Some(self.head().generation))
                .then_some(recovery),
        )
    }

    /// Whether admission is staged at the account: after a recovery it began with, until the
    /// signer or a qualifying upload ends it (Switch spec 12.6 step 2).
    pub async fn admission_staged(&mut self) -> Result<bool, StoreError> {
        Ok(self.recovery().await?.is_some_and(|r| r.admission_staged))
    }

    /// End staged admission: whether it was staged, and is no longer. Ending it when it isn't
    /// staged writes nothing (Switch wire 7.4.14).
    pub async fn end_admission(&mut self) -> Result<bool, StoreError> {
        if !self.admission_staged().await? {
            return Ok(false);
        }
        let id = self.head().id.clone();
        sqlx::query("UPDATE accounts SET admission_staged = false WHERE id = $1")
            .bind(id)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        Ok(true)
    }

    /// The App IDs held for the next generation: the `revoked_apps` of the enrollments
    /// answered at the serving account since its current generation began (Switch wire 3.7).
    pub async fn held_revoked_apps(&mut self) -> Result<Vec<[u8; 16]>, StoreError> {
        let id = self.head().id.clone();
        let rows: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT app_id FROM held_revoked_apps WHERE account_id = $1")
                .bind(id)
                .fetch_all(self.conn())
                .await
                .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|app| {
                <[u8; 16]>::try_from(app.as_slice())
                    .map_err(|_| StoreError::Corrupt("held revoked app_id"))
            })
            .collect()
    }

    /// The complete ordered exclusions that can be candidates for one inline mark
    /// (account binding 3). An extra row or excess encoded bytes selects SQL instead.
    pub(crate) async fn recovery_exclusions(
        &mut self,
    ) -> Result<Option<(Vec<KeptAppId>, Vec<HeldId>)>, StoreError> {
        let id = self.head().id.clone();
        let mut kept = Vec::new();
        let mut bytes = 0;
        let mut rows = sqlx::query(
            "SELECT app_id, reason, at_ms, data_epoch, rotated FROM kept_app_ids \
             WHERE account_id = $1 ORDER BY app_id LIMIT $2",
        )
        .bind(&id)
        .bind(RecoverySource::MAX_ROWS as i64 + 1)
        .fetch(self.conn());
        while let Some(row) = rows.try_next().await? {
            let app = KeptAppId::from_row(&row)?;
            bytes += app.encoded_len()? + 1;
            if bytes > crate::marks::MAX_MARK_FILE as usize
                || kept.len() == RecoverySource::MAX_ROWS
            {
                return Ok(None);
            }
            kept.push(app);
        }
        drop(rows);
        let room = RecoverySource::MAX_ROWS - kept.len();
        let mut rows = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT app_id FROM held_revoked_apps WHERE account_id = $1 ORDER BY app_id LIMIT $2",
        )
        .bind(id)
        .bind(room as i64 + 1)
        .fetch(self.conn());
        let mut held = Vec::new();
        while let Some(row) = rows.try_next().await? {
            // Two quotes, 32 hex digits and the separator.
            bytes += 35;
            if bytes > crate::marks::MAX_MARK_FILE as usize || held.len() == room {
                return Ok(None);
            }
            held.push(HeldId(
                row.try_into()
                    .map_err(|_| StoreError::Corrupt("held revoked app_id"))?,
            ));
        }
        Ok(Some((kept, held)))
    }

    /// Hold `apps`, an enrollment's `revoked_apps` answered at the serving account, until a
    /// delivery starts the next generation (Switch wire 3.7).
    pub async fn hold_revoked_apps(&mut self, apps: &[[u8; 16]]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        for app in apps {
            sqlx::query(
                "INSERT INTO held_revoked_apps (account_id, app_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&id)
            .bind(app.as_slice())
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        }
        Ok(())
    }

    /// Join the App IDs held for the next generation to the account's tombstones, dated
    /// `at_ms`, and hold none any more: a delivery starts the next generation (Switch wire
    /// 3.3, 3.7).
    pub async fn join_held_revoked_apps(&mut self, at_ms: u64) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms) \
             SELECT account_id, app_id, 'enrolled', $2 FROM held_revoked_apps \
             WHERE account_id = $1 ON CONFLICT DO NOTHING",
        )
        .bind(&id)
        .bind(time_to_db(at_ms)?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        sqlx::query("DELETE FROM held_revoked_apps WHERE account_id = $1")
            .bind(&id)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Start the recovery of a staged account that holds no document, at the first
    /// document's `generation` (Switch wire 3.3, 7.4.2): the account takes that generation,
    /// its key stays, and its chain starts empty, for the `recovery` transition. Recorded as
    /// the recovery of `recovery_from` at `at_ms`, with admission staged when `stages` (Switch
    /// spec 12.6 step 2). The chain must be empty: a staged account holds none.
    pub async fn start_recovery(
        &mut self,
        generation: u64,
        recovery_from: u64,
        at_ms: u64,
        stages: bool,
    ) -> Result<(), StoreError> {
        if self.head().chain.is_some() {
            return Err(StoreError::Corrupt("a staged account with a chain"));
        }
        self.set_generation(generation, recovery_from, at_ms, stages)
            .await
    }

    /// Start the account afresh at `generation`, the recovery of `recovery_from` at `at_ms`
    /// (Switch wire 3.3, 3.7, 7.3 Table 2): a provider loss in place, or the start a failing
    /// or bounded account takes. Admission is staged when `stages` (Switch spec 12.6 step 2).
    ///
    /// It keeps the account's service time, the directory's `directory_version` and
    /// `apps_version`, which are columns of its row and never restart for an account (Switch
    /// wire 7.4.10), its App IDs kept for good, joined by those held for the next generation,
    /// and the enrollments it answered. Everything else of the generation goes
    /// (`GENERATION_STATE`), and so does the held `identity.json`, which the caller replaces
    /// in the same transaction. The push keys of the registrations that go are owed
    /// deleting (Switch wire 8.1).
    pub async fn start_afresh(
        &mut self,
        generation: u64,
        recovery_from: u64,
        at_ms: u64,
        stages: bool,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        // The push registrations go with the generation, their keys owed (Switch wire 8.1).
        self.drop_push_registrations(None).await?;
        for table in GENERATION_STATE {
            sqlx::query(&format!("DELETE FROM {table} WHERE account_id = $1"))
                .bind(&id)
                .execute(self.conn())
                .await
                .map_err(StoreError::from_db)?;
        }
        self.join_held_revoked_apps(at_ms).await?;
        sqlx::query("UPDATE accounts SET identity_doc = NULL, identity_proof = NULL WHERE id = $1")
            .bind(&id)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        self.set_generation(generation, recovery_from, at_ms, stages)
            .await
    }

    /// Write `generation` and the recovery of `recovery_from` at `at_ms`, staging admission
    /// when `stages`, to the account's row, and take them as its position, its chain empty.
    async fn set_generation(
        &mut self,
        generation: u64,
        recovery_from: u64,
        at_ms: u64,
        stages: bool,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "UPDATE accounts SET generation = $2, recovery_from = $3, \
             recovery_declared_at_ms = $4, admission_staged = $5, activation_requirement = 'ordinary' WHERE id = $1",
        )
        .bind(&id)
        .bind(to_db(generation, "generation")?)
        .bind(to_db(recovery_from, "recovery_from")?)
        .bind(time_to_db(at_ms)?)
        .bind(stages)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        self.start_recovery_head(generation);
        Ok(())
    }
}
