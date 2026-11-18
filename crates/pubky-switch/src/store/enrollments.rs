//! Exact enrollment receipts associated with an account and mark store
//! (Switch wire 3.7, 9.1; Switch account binding 3).

use sqlx::Row;

use super::{AccountTxn, StoreError, from_db, identity::time_to_db, to_db};

/// The durable association of an exact signed enrollment with its application result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollmentReceipt {
    /// The account creation at which the enrollment was applied.
    pub created_at_ms: u64,
    /// The external mark-store identity at application.
    pub store_id: [u8; 16],
    /// The original committed answer time.
    pub answered_at_ms: u64,
}

impl AccountTxn {
    /// Read an exact receipt under the account lock. Absence never proves non-application
    /// (Switch account binding 3).
    pub async fn enrollment_answer(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<Option<EnrollmentReceipt>, StoreError> {
        let id = self.head().id.clone();
        read(self.conn(), &id, hash).await
    }

    /// Keep the exact account/store association before answering the enrollment.
    /// The oldest answers beyond `max` drop, but the creating enrollment's stays.
    pub async fn keep_enrollment_answer(
        &mut self,
        hash: &[u8; 32],
        at_ms: u64,
        max: u64,
        store_id: [u8; 16],
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        let receipt = EnrollmentReceipt {
            created_at_ms: self.head().created_at_ms,
            store_id,
            answered_at_ms: at_ms,
        };
        keep(self.conn(), &id, hash, &receipt, max, false).await
    }
}

async fn read(
    conn: &mut sqlx::PgConnection,
    id: &str,
    hash: &[u8; 32],
) -> Result<Option<EnrollmentReceipt>, StoreError> {
    let row = sqlx::query("SELECT created_at_ms, store_id, answered_at_ms FROM enrollment_answers WHERE account_id = $1 AND enrollment_hash = $2")
        .bind(id).bind(hash.as_slice()).fetch_optional(conn).await?;
    row.map(|row| {
        let store: Vec<u8> = row.try_get("store_id")?;
        Ok(EnrollmentReceipt {
            created_at_ms: from_db(row.try_get("created_at_ms")?, "enrollment created_at_ms")?,
            store_id: store
                .try_into()
                .map_err(|_| StoreError::Corrupt("enrollment store identity"))?,
            answered_at_ms: from_db(row.try_get("answered_at_ms")?, "enrollment answered_at_ms")?,
        })
    })
    .transpose()
}

pub(super) async fn keep(
    conn: &mut sqlx::PgConnection,
    id: &str,
    hash: &[u8; 32],
    receipt: &EnrollmentReceipt,
    max: u64,
    creating: bool,
) -> Result<(), StoreError> {
    if creating || max > 1 {
        sqlx::query(
        "INSERT INTO enrollment_answers (account_id, enrollment_hash, created_at_ms, store_id, answered_at_ms, creating) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind(id).bind(hash.as_slice()).bind(time_to_db(receipt.created_at_ms)?).bind(receipt.store_id.as_slice())
    .bind(time_to_db(receipt.answered_at_ms)?).bind(creating)
    .execute(&mut *conn).await.map_err(StoreError::from_db)?;
        let held = read(conn, id, hash)
            .await?
            .ok_or(StoreError::Corrupt("missing enrollment receipt"))?;
        if held.created_at_ms != receipt.created_at_ms || held.store_id != receipt.store_id {
            return Err(StoreError::Corrupt("enrollment receipt association"));
        }
    }
    sqlx::query(
        "DELETE FROM enrollment_answers WHERE account_id = $1 AND enrollment_hash IN ( \
         SELECT enrollment_hash FROM enrollment_answers WHERE account_id = $1 \
         AND NOT creating ORDER BY kept_order DESC OFFSET $2)",
    )
    .bind(id)
    // The creating answer counts towards `max` too.
    .bind(to_db(max.saturating_sub(1), "max_enrollments")?)
    .execute(&mut *conn)
    .await
    .map_err(StoreError::from_db)?;
    Ok(())
}
