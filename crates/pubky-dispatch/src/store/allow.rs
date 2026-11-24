//! Lists read from the same service-time snapshot (Dispatch wire 7.4.6).

use sqlx::Row;

use super::{SnapshotRead, StoreError, from_db, to_db};

/// A live invite code as `GET /allow` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowInvite {
    /// `hash(code bytes)`.
    pub code_hash: [u8; 32],
    /// When it expires.
    pub expires_at_ms: u64,
    /// How many appends it admits.
    pub max_uses: u64,
    /// How many it admitted.
    pub uses: u64,
    /// The writing app.
    pub writer: [u8; 16],
}

fn array<const N: usize>(bytes: &[u8], what: &'static str) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(bytes).map_err(|_| StoreError::Corrupt(what))
}

impl SnapshotRead {
    /// The senders flagged at least `min_hits` times (Dispatch wire 9.4 Flags), the most
    /// frequent first, then by Pubky ID.
    pub async fn flagged_senders(
        &mut self,
        min_hits: u64,
    ) -> Result<Vec<([u8; 32], u64)>, StoreError> {
        let id = self.id.clone();
        let rows = sqlx::query(
            "SELECT pubky, hits FROM sender_flags WHERE account_id = $1 AND hits >= $2 \
             ORDER BY hits DESC, pubky",
        )
        .bind(id)
        .bind(to_db(min_hits, "flag_after")?)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let pubky: Vec<u8> = row.try_get("pubky")?;
                Ok((
                    array(&pubky, "pubky")?,
                    from_db(row.try_get("hits")?, "hits")?,
                ))
            })
            .collect()
    }

    /// The invite codes live at `now_ms`, with uses left and unexpired, by code hash.
    pub async fn live_invite_codes(&mut self, now_ms: u64) -> Result<Vec<AllowInvite>, StoreError> {
        let id = self.id.clone();
        let rows = sqlx::query(
            "SELECT code_hash, expires_at_ms, max_uses, uses, writer FROM invite_codes \
             WHERE account_id = $1 AND uses < max_uses AND expires_at_ms > $2 ORDER BY code_hash",
        )
        .bind(id)
        .bind(to_db(now_ms, "now_ms")?)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let hash: Vec<u8> = row.try_get("code_hash")?;
                let writer: Vec<u8> = row.try_get("writer")?;
                Ok(AllowInvite {
                    code_hash: array(&hash, "code_hash")?,
                    expires_at_ms: from_db(row.try_get("expires_at_ms")?, "expires_at_ms")?,
                    max_uses: from_db(row.try_get("max_uses")?, "max_uses")?,
                    uses: from_db(row.try_get("uses")?, "uses")?,
                    writer: array(&writer, "writer")?,
                })
            })
            .collect()
    }
}
