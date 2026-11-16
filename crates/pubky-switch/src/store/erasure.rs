//! A deletion's outcome is committed with the deletion, never inferred from absence
//! after a connection failure or database restore (Switch wire 7.3 Table 3).

use super::{IdentityLock, LockFreshness, StoreError};
use crate::marks::ErasureAttempt;
use sqlx::{PgConnection, Row};

fn bytes(attempt: &ErasureAttempt) -> Result<Vec<u8>, StoreError> {
    attempt
        .bytes()
        .map_err(|_| StoreError::Corrupt("erasure attempt"))
}

pub(super) async fn record(
    conn: &mut PgConnection,
    identity: &str,
    attempt: &ErasureAttempt,
    committed: bool,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO erasure_outcomes (identity, attempt, committed) VALUES ($1, $2, $3) \
                 ON CONFLICT (identity) DO UPDATE SET attempt = EXCLUDED.attempt, committed = EXCLUDED.committed")
        .bind(identity).bind(bytes(attempt)?).bind(committed).execute(conn).await.map_err(StoreError::from_db)?;
    Ok(())
}

impl IdentityLock {
    /// Only a receipt for this exact attempt says whether its deletion committed.
    pub(crate) async fn erasure_outcome(
        &mut self,
        attempt: &ErasureAttempt,
    ) -> Result<Option<bool>, StoreError> {
        let row =
            sqlx::query("SELECT attempt, committed FROM erasure_outcomes WHERE identity = $1")
                .bind(&self.id)
                .fetch_optional(&mut *self.tx)
                .await
                .map_err(StoreError::from_db)?;
        match row {
            Some(row) if row.try_get::<Vec<u8>, _>("attempt")? == bytes(attempt)? => {
                Ok(Some(row.try_get("committed")?))
            }
            _ => Ok(None),
        }
    }

    /// The caller established a definitive rejection; commit that evidence before
    /// removing the external attempt. Failure here leaves its outcome unresolved.
    pub(crate) async fn reject_erasure(
        mut self,
        attempt: &ErasureAttempt,
        freshness: Option<&LockFreshness>,
    ) -> Result<(), StoreError> {
        record(&mut self.tx, &self.id, attempt, false).await?;
        require_fresh(freshness)?;
        self.tx.commit().await.map_err(StoreError::from_db)
    }
}

/// Check at the irreversible boundary, after receipt storage has awaited PostgreSQL.
pub(super) fn require_fresh(freshness: Option<&LockFreshness>) -> Result<(), StoreError> {
    if freshness.is_some_and(|freshness| !freshness.is_fresh()) {
        return Err(StoreError::Raced("the instance lock is stale"));
    }
    Ok(())
}

impl IdentityLock {
    /// The external attempt is durably gone; this receipt is no longer needed.
    pub(crate) async fn forget_erasure_outcome(
        mut self,
        freshness: Option<&LockFreshness>,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM erasure_outcomes WHERE identity = $1")
            .bind(&self.id)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        require_fresh(freshness)?;
        self.tx.commit().await.map_err(StoreError::from_db)
    }
}

impl super::Store {
    /// Bounded pages for startup reconciliation; ordinary requests touch one identity.
    pub(crate) async fn erasure_outcome_ids(&self, after: &str) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar(
            "SELECT identity FROM erasure_outcomes WHERE identity > $1 ORDER BY identity LIMIT 100",
        )
        .bind(after)
        .fetch_all(self.pool())
        .await
        .map_err(StoreError::from_db)
    }
}
