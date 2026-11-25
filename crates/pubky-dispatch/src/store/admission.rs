//! Peer admission and deny entries (Dispatch wire 6.2, 7.4.6).

use pubky_dispatch_core::{
    admission::{PeerEntry, ReplyGrant, ReplyOrigin},
    enc::pubky_id,
};
use sqlx::{Row, postgres::PgRow};

use super::{AccountTxn, SnapshotRead, StoreError, from_db, ops::keys, to_db};

fn peer_entry(row: &PgRow) -> Result<PeerEntry, StoreError> {
    let writer: Option<Vec<u8>> = row.try_get("reply_writer")?;
    let code: Option<Vec<u8>> = row.try_get("reply_code_hash")?;
    let at: Option<i64> = row.try_get("reply_at_ms")?;
    let last: Option<i64> = row.try_get("last_used_ms")?;
    let origin = match (writer, code) {
        (Some(app), None) => Some(ReplyOrigin::App(
            app.try_into()
                .map_err(|_| StoreError::Corrupt("reply writer"))?,
        )),
        (None, Some(hash)) => Some(ReplyOrigin::Invite(
            hash.try_into()
                .map_err(|_| StoreError::Corrupt("reply code hash"))?,
        )),
        (None, None) => None,
        _ => return Err(StoreError::Corrupt("reply origin")),
    };
    let kept = row.try_get("kept")?;
    let reply = match (origin, at) {
        (Some(origin), Some(at)) => Some(ReplyGrant {
            origin,
            at: from_db(at, "reply time")?,
            last_used: last.map(|ms| from_db(ms, "last reply use")).transpose()?,
        }),
        (None, None) if kept && last.is_none() => None,
        _ => return Err(StoreError::Corrupt("peer admission")),
    };
    let peer: Vec<u8> = row.try_get("pubky")?;
    Ok(PeerEntry {
        pubky: peer
            .try_into()
            .map_err(|_| StoreError::Corrupt("admitted peer"))?,
        kept,
        reply,
    })
}

fn peer_keys(rows: Vec<Vec<u8>>) -> Result<Vec<[u8; 32]>, StoreError> {
    rows.into_iter()
        .map(|p| p.try_into().map_err(|_| StoreError::Corrupt("denied peer")))
        .collect()
}

impl AccountTxn {
    /// The current reasons for each named peer (Dispatch wire 6.2).
    pub async fn peer_admissions(
        &mut self,
        peers: &[[u8; 32]],
    ) -> Result<Vec<PeerEntry>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT pubky, kept, reply_writer, reply_code_hash, reply_at_ms, last_used_ms
            FROM peer_admissions WHERE account_id = $1 AND pubky = ANY($2)",
        )
        .bind(id)
        .bind(keys(peers))
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        rows.iter().map(peer_entry).collect()
    }

    /// The named denied peers.
    pub async fn denied_peers(&mut self, peers: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query_scalar(
            "SELECT pubky FROM denied_peers WHERE account_id = $1 AND pubky = ANY($2)",
        )
        .bind(id)
        .bind(keys(peers))
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        peer_keys(rows)
    }

    /// Whether either reason admits this identity, and whether the deny list names it.
    pub async fn peer_standing(&mut self, peer: &[u8; 32]) -> Result<(bool, bool), StoreError> {
        let id = self.head().id.clone();
        sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM peer_admissions WHERE account_id = $1 AND pubky = $2),
            EXISTS(SELECT 1 FROM denied_peers WHERE account_id = $1 AND pubky = $2)",
        )
        .bind(id)
        .bind(peer.as_slice())
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)
    }

    /// Counts of kept peers and reply grants outside the current batch (Dispatch wire 9.3).
    pub async fn admission_counts(
        &mut self,
        excluding: &[[u8; 32]],
    ) -> Result<(u64, u64), StoreError> {
        let id = self.head().id.clone();
        let (kept, reply): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE kept), count(reply_at_ms)
             FROM peer_admissions WHERE account_id = $1 AND NOT (pubky = ANY($2))",
        )
        .bind(id)
        .bind(keys(excluding))
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok((
            from_db(kept, "kept peers")?,
            from_db(reply, "reply grants")?,
        ))
    }

    /// Count deny entries outside the current batch.
    pub async fn deny_count(&mut self, excluding: &[[u8; 32]]) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let count = sqlx::query_scalar(
            "SELECT count(*) FROM denied_peers WHERE account_id = $1 AND NOT (pubky = ANY($2))",
        )
        .bind(id)
        .bind(keys(excluding))
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        from_db(count, "denied peers")
    }

    /// Add kept peers from a loss upload in key order while there is room. An existing
    /// reply grant survives the keep (Dispatch wire 7.4.14).
    pub async fn restore_kept(
        &mut self,
        peers: &[[u8; 32]],
        limit: u64,
    ) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        let (count, _) = self.admission_counts(&[]).await?;
        let room = i64::try_from(limit.saturating_sub(count)).unwrap_or(i64::MAX);
        sqlx::query_scalar(
            "WITH added AS (
                 INSERT INTO peer_admissions (account_id, pubky, kept)
                 SELECT $1, candidate, TRUE FROM (SELECT DISTINCT unnest($2::bytea[]) AS candidate) AS peers
                 WHERE NOT EXISTS (
                     SELECT 1 FROM peer_admissions WHERE account_id = $1 AND pubky = candidate AND kept
                 )
                 ORDER BY candidate LIMIT $3
                 ON CONFLICT (account_id, pubky) DO UPDATE SET kept = TRUE
                 RETURNING pubky
             ), answered AS (
                 DELETE FROM connect_requests WHERE account_id = $1 AND pubky IN (SELECT pubky FROM added)
             ) SELECT EXISTS(SELECT 1 FROM added)",
        )
        .bind(id)
        .bind(keys(peers))
        .bind(room)
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)
    }

    /// The entries of `peers` the deny list holds already, which a loss upload doesn't add
    /// (Dispatch wire 7.4.14 "Lists").
    pub async fn held_deny_entries(
        &mut self,
        peers: &[[u8; 32]],
    ) -> Result<std::collections::HashSet<[u8; 32]>, StoreError> {
        let id = self.head().id.clone();
        let held: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT pubky FROM denied_peers WHERE account_id = $1 AND pubky = ANY($2::bytea[])",
        )
        .bind(id)
        .bind(keys(peers))
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        held.into_iter()
            .map(|key| {
                <[u8; 32]>::try_from(key.as_slice()).map_err(|_| StoreError::Corrupt("denied peer"))
            })
            .collect()
    }

    /// Add every deny entry of a loss upload the list doesn't hold yet. The caller has
    /// checked that they fit: a deny entry is never dropped, since a dropped one could
    /// admit a peer the uploader's copy denies (Dispatch wire 7.4.14 "Lists").
    pub async fn restore_deny(&mut self, peers: &[[u8; 32]]) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        sqlx::query_scalar(
            "WITH added AS (
                 INSERT INTO denied_peers (account_id, pubky)
                 SELECT $1, candidate FROM (SELECT DISTINCT unnest($2::bytea[]) AS candidate) AS peers
                 WHERE NOT EXISTS (
                     SELECT 1 FROM denied_peers WHERE account_id = $1 AND pubky = candidate
                 )
                 RETURNING pubky
             ), answered AS (
                 DELETE FROM connect_requests WHERE account_id = $1 AND pubky IN (SELECT pubky FROM added)
             ) SELECT EXISTS(SELECT 1 FROM added)",
        )
        .bind(id)
        .bind(keys(peers))
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)
    }

    /// Persist both reasons from the committed batch decision (Dispatch wire 6.4).
    pub async fn put_admission(&mut self, peer: &PeerEntry) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        let mut writer = None;
        let mut code = None;
        let mut at = None;
        let mut last = None;
        if let Some(reply) = &peer.reply {
            match &reply.origin {
                ReplyOrigin::App(app) => writer = Some(app.as_slice()),
                ReplyOrigin::Invite(hash) => code = Some(hash.as_slice()),
            }
            at = Some(to_db(reply.at, "reply time")?);
            last = reply
                .last_used
                .map(|ms| to_db(ms, "last reply use"))
                .transpose()?;
        }
        sqlx::query(
            "INSERT INTO peer_admissions
                (account_id, pubky, kept, reply_writer, reply_code_hash, reply_at_ms, last_used_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (account_id, pubky) DO UPDATE SET
                kept = EXCLUDED.kept,
                reply_writer = EXCLUDED.reply_writer,
                reply_code_hash = EXCLUDED.reply_code_hash,
                reply_at_ms = EXCLUDED.reply_at_ms,
                last_used_ms = EXCLUDED.last_used_ms",
        )
        .bind(id)
        .bind(peer.pubky.as_slice())
        .bind(peer.kept)
        .bind(writer)
        .bind(code)
        .bind(at)
        .bind(last)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Remove a peer when its final reason ends.
    pub async fn delete_admission(&mut self, peer: &[u8; 32]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM peer_admissions WHERE account_id = $1 AND pubky = $2")
            .bind(id)
            .bind(peer.as_slice())
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Record a deny entry (Dispatch wire 6.2).
    pub async fn put_deny(&mut self, peer: &[u8; 32]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO denied_peers (account_id, pubky) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(peer.as_slice())
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Remove a deny entry (Dispatch wire 6.2).
    pub async fn delete_deny(&mut self, peer: &[u8; 32]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM denied_peers WHERE account_id = $1 AND pubky = $2")
            .bind(id)
            .bind(peer.as_slice())
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }
}

impl SnapshotRead {
    /// All admission rows in their signed list order (Dispatch wire 7.4.6).
    pub async fn admission_rows(&mut self) -> Result<Vec<PeerEntry>, StoreError> {
        let rows = sqlx::query(
            "SELECT pubky, kept, reply_writer, reply_code_hash, reply_at_ms, last_used_ms
            FROM peer_admissions WHERE account_id = $1",
        )
        .bind(&self.id)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(StoreError::from_db)?;
        let mut peers = rows.iter().map(peer_entry).collect::<Result<Vec<_>, _>>()?;
        peers.sort_by_cached_key(|entry| pubky_id(&entry.pubky));
        Ok(peers)
    }

    /// All deny entries in the account snapshot.
    pub async fn deny_rows(&mut self) -> Result<Vec<[u8; 32]>, StoreError> {
        let rows = sqlx::query_scalar(
            "SELECT pubky FROM denied_peers WHERE account_id = $1 ORDER BY pubky",
        )
        .bind(&self.id)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(StoreError::from_db)?;
        peer_keys(rows)
    }
}
