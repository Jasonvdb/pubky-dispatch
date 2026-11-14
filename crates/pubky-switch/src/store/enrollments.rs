//! The enrollments an account answered (Switch wire 3.7, 9.1): each answer names the service
//! key and the limits the account announced, so the same enrollment again gets the same
//! answer, built again.

use super::{AccountTxn, StoreError, identity::time_to_db, to_db};

impl AccountTxn {
    /// Keep that the enrollment with document hash `hash` was answered at `at_ms`; the
    /// oldest answers beyond `max` drop, but the creating enrollment's (Switch wire 9.1).
    pub async fn keep_enrollment_answer(
        &mut self,
        hash: &[u8; 32],
        at_ms: u64,
        max: u64,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        keep(self.conn(), &id, hash, at_ms, max, false).await
    }
}

/// Keep an enrollment answer on `conn`, for account `id`; `creating` for the enrollment
/// that creates the account, which never drops. The others drop, the oldest first, beyond
/// `max`.
pub(super) async fn keep(
    conn: &mut sqlx::PgConnection,
    id: &str,
    hash: &[u8; 32],
    at_ms: u64,
    max: u64,
    creating: bool,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO enrollment_answers (account_id, enrollment_hash, answered_at_ms, \
         creating) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(hash.as_slice())
    .bind(time_to_db(at_ms)?)
    .bind(creating)
    .execute(&mut *conn)
    .await
    .map_err(StoreError::from_db)?;
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
