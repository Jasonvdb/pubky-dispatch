//! The SQL contents of a fresh account before its first counted write (Dispatch account
//! binding 3). An identical creation time or an empty chain does not identify those rows.

use futures_util::TryStreamExt;
use pubky_dispatch_core::enc::lp;
use pubky_dispatch_core::records::{IdentityDoc, Limits, MAX_ENROLLMENT_BYTES};
use pubky_dispatch_core::sig::SignedDoc;
use sqlx::{PgConnection, Row};

use super::{AccountTxn, StoreError, from_db};
use crate::marks::coverage::{PriorDocument, RecoverySource};

// Each distinct exclusion in the creating enrollment needs at least its 16 raw ID bytes.
// The complete signed enrollment, including its optional signed identity, fits 256 KiB.
const MAX_ROWS: i64 = MAX_ENROLLMENT_BYTES as i64 / 16;

pub(crate) struct OpeningContents {
    pub(crate) anchor: [u8; 32],
    pub(super) material: [u8; 32],
    pub(crate) recovery: Option<RecoverySource>,
}

// The signed enrollment hash binds its origin, nonce and identity. The current service
// signs the answer with its own key under wire 7.4.1. All remaining result fields are
// fixed for this opening, including each of the seven announced limits.
fn receipt_anchor(
    material: &[u8; 32],
    store_id: &[u8; 16],
    identity: &[u8; 32],
    enrollment: &[u8; 32],
    created: u64,
    limits: &Limits,
) -> [u8; 32] {
    pubky_dispatch_core::enc::hash(&lp(&[
        b"pubky-dispatch/v1/creation-anchor",
        material,
        store_id,
        identity,
        enrollment,
        &created.to_be_bytes(),
        &limits.app_limit.to_be_bytes(),
        &limits.max_envelope.to_be_bytes(),
        &limits.max_sealed_value.to_be_bytes(),
        &limits.quota_bytes.to_be_bytes(),
        &limits.max_batch.to_be_bytes(),
        &limits.record_quota_bytes.to_be_bytes(),
        &limits.max_import_bytes.to_be_bytes(),
    ]))
}

pub(super) async fn contents(
    conn: &mut PgConnection,
    id: &str,
    store_id: [u8; 16],
    enrollment: [u8; 32],
    capture_recovery: bool,
) -> Result<OpeningContents, StoreError> {
    let corrupt = StoreError::Corrupt("fresh enrollment contents");
    let row = sqlx::query(
        "SELECT identity_key, created_at_ms, stamped_time_ms, generation, announced_limits, identity_doc, \
         directory_version, apps_version, activation_requirement, \
         EXISTS (SELECT 1 FROM apps WHERE account_id = $1) AS has_apps, \
         EXISTS (SELECT 1 FROM held_revoked_apps WHERE account_id = $1) AS has_held \
         FROM accounts WHERE id = $1 AND octet_length(announced_limits) <= 1024 \
         AND (identity_doc IS NULL OR octet_length(identity_doc) <= $2)",
    )
    .bind(id)
    .bind(MAX_ENROLLMENT_BYTES as i64)
    .fetch_one(&mut *conn)
    .await?;
    let identity: [u8; 32] = row
        .try_get::<Vec<u8>, _>("identity_key")?
        .try_into()
        .map_err(|_| corrupt)?;
    let limits: Limits = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("announced_limits")?)
        .map_err(|_| StoreError::Corrupt("announced limits"))?;
    let doc = row
        .try_get::<Option<Vec<u8>>, _>("identity_doc")?
        .map(|bytes| {
            let signed: SignedDoc =
                serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt("identity_doc"))?;
            IdentityDoc::verify(&signed, &identity).map_err(|_| StoreError::Corrupt("identity_doc"))
        })
        .transpose()?;
    let directory: i64 = row.try_get("directory_version")?;
    let apps: i64 = row.try_get("apps_version")?;
    if directory != 0
        || apps != 0
        || row.try_get::<bool, _>("has_apps")?
        || row.try_get::<bool, _>("has_held")?
        || row.try_get::<String, _>("activation_requirement")? != "ordinary"
    {
        return Err(StoreError::Corrupt(
            "fresh enrollment directory or exclusions",
        ));
    }
    let created = from_db(row.try_get("created_at_ms")?, "created_at_ms")?;
    let generation = from_db(row.try_get("generation")?, "generation")?;
    let stamped_ms = from_db(row.try_get("stamped_time_ms")?, "stamped_time_ms")?;
    let mut recovery = capture_recovery.then(|| RecoverySource {
        identity,
        store_id,
        generation_floor: generation.max(doc.as_ref().map_or(0, IdentityDoc::generation)),
        prior: doc.as_ref().map(|doc| PriorDocument {
            hash: doc.hash(),
            version: doc.version(),
        }),
        recovery_only: false,
        stamped_ms,
        directory_version: 0,
        apps_version: 0,
        had_reachable_apps: false,
        limits,
        kept: Vec::new(),
        held: Vec::new(),
    });
    let doc_hash = doc.as_ref().map(IdentityDoc::hash);
    let mut hash = blake3::Hasher::new();
    hash.update(&lp(&[
        b"pubky-dispatch/v1/creation-material",
        &generation.to_be_bytes(),
        doc_hash.as_ref().map_or(&[][..], |bytes| bytes.as_slice()),
        &directory.to_be_bytes(),
        &apps.to_be_bytes(),
        &[0],
    ]));
    let mut rows = sqlx::query(
        "SELECT app_id, reason, at_ms, data_epoch, rotated FROM kept_app_ids \
         WHERE account_id = $1 ORDER BY app_id LIMIT $2",
    )
    .bind(id)
    .bind(MAX_ROWS + 1)
    .fetch(&mut *conn);
    let mut count = 0;
    let mut kept_bytes = 0;
    while let Some(row) = rows.try_next().await? {
        count += 1;
        if count > MAX_ROWS {
            return Err(StoreError::Corrupt("fresh enrollment exclusion bound"));
        }
        if let Some(source) = &mut recovery {
            let kept = super::KeptAppId::from_row(&row)?;
            kept_bytes += kept.encoded_len()? + 1;
            if source.kept.len() == RecoverySource::MAX_ROWS
                || kept_bytes > crate::marks::MAX_MARK_FILE as usize
            {
                recovery = None;
            } else {
                source.kept.push(kept);
            }
        }
        let app: Vec<u8> = row.try_get("app_id")?;
        let reason: String = row.try_get("reason")?;
        let at: Option<i64> = row.try_get("at_ms")?;
        let epoch: Option<i64> = row.try_get("data_epoch")?;
        let rotated: bool = row.try_get("rotated")?;
        let time = at.map(i64::to_be_bytes);
        let epoch = epoch.map(i64::to_be_bytes);
        hash.update(&lp(&[
            &app,
            reason.as_bytes(),
            time.as_ref().map_or(&[][..], |n| n.as_slice()),
            epoch.as_ref().map_or(&[][..], |n| n.as_slice()),
            &[u8::from(rotated)],
        ]));
    }
    let material = *hash.finalize().as_bytes();
    let anchor = receipt_anchor(
        &material,
        &store_id,
        &identity,
        &enrollment,
        created,
        &limits,
    );
    if anchor == [0; 32] {
        return Err(StoreError::Corrupt("zero creation anchor"));
    }
    Ok(OpeningContents {
        anchor,
        material,
        recovery,
    })
}

/// Recover the SQL witness before this transaction can change the opening contents.
/// The unique creating receipt supplies the original store and document hash. The mark
/// remains the independent authority for using the resulting commitment.
pub(super) async fn opening_origin(
    conn: &mut PgConnection,
    head: &super::AccountHead,
    stored: &[u8],
) -> Result<Option<[u8; 32]>, StoreError> {
    let receipt: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT store_id, enrollment_hash FROM enrollment_answers \
         WHERE account_id = $1 AND creating AND created_at_ms = $2",
    )
    .bind(&head.id)
    .bind(super::to_db(head.created_at_ms, "created_at_ms")?)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((store, enrollment)) = receipt else {
        return Ok(None);
    };
    let (Ok(store), Ok(enrollment)) = (store.try_into(), enrollment.try_into()) else {
        return Ok(None);
    };
    match contents(conn, &head.id, store, enrollment, false).await {
        Ok(opening) => Ok((opening.anchor.as_slice() == stored).then_some(opening.anchor)),
        Err(
            StoreError::Corrupt(_)
            | StoreError::OutOfRange(_)
            | StoreError::Database(sqlx::Error::RowNotFound),
        ) => Ok(None),
        Err(error) => Err(error),
    }
}

impl AccountTxn {
    /// Check the SQL source for a recovery snapshot at a healthy locked position
    /// (account binding 3). A later descendant of just the opening cannot establish
    /// later exclusions. The caller checks the ordinary chain verdict.
    pub(crate) async fn covers_recovery_state(
        &mut self,
        store_id: [u8; 16],
        limits: &Limits,
        mark: &crate::marks::AccountMark,
    ) -> Result<bool, StoreError> {
        if !matches!(
            mark.creation_anchor,
            crate::marks::CreationAnchor::Bound {
                confirmed: true,
                ..
            }
        ) || (mark.state_version == 0 && self.loaded().state_version != 0)
            || (mark.state_version > 0 && mark.state_tag == [0; 16])
        {
            return Ok(false);
        }
        self.covers_marked_opening(store_id, None, limits, mark)
            .await
    }

    /// Verify a retried creating enrollment's own receipt at the marked position.
    pub(crate) async fn covers_opening_receipt(
        &mut self,
        store_id: [u8; 16],
        enrollment: [u8; 32],
        limits: &Limits,
        mark: &crate::marks::AccountMark,
    ) -> Result<bool, StoreError> {
        self.covers_marked_opening(store_id, Some(enrollment), limits, mark)
            .await
    }

    // The common verdict checks the chain. Both callers still need the original
    // receipt and its actual retained state position (account binding 3).
    async fn covers_marked_opening(
        &mut self,
        store_id: [u8; 16],
        enrollment: Option<[u8; 32]>,
        limits: &Limits,
        mark: &crate::marks::AccountMark,
    ) -> Result<bool, StoreError> {
        let head = self.loaded();
        let Some(anchor) = mark.creation_anchor.for_creation(head.created_at_ms) else {
            return Ok(false);
        };
        if mark.created_at_ms != head.created_at_ms
            || self.creation_origin() != Some(anchor)
            || mark.state_version > head.state_version
        {
            return Ok(false);
        }
        if head.state_version == 0 && (mark.generation != 0 || head.last_seq != 0) {
            return Ok(false);
        }
        self.covers_creation_receipt_at(
            store_id,
            enrollment,
            limits,
            anchor,
            mark.state_version,
            mark.state_tag,
        )
        .await
    }

    async fn covers_creation_receipt_at(
        &mut self,
        store_id: [u8; 16],
        enrollment: Option<[u8; 32]>,
        limits: &Limits,
        anchor: [u8; 32],
        count: u64,
        tag: [u8; 16],
    ) -> Result<bool, StoreError> {
        let head = self.loaded();
        let identity = head.identity_key;
        let created = head.created_at_ms;
        let id = head.id.clone();
        // A positive marked position must carry this same origin at its tagged history
        // row. A zero mark can attest to the immutable opening receipt only; it never
        // establishes coverage of later exclusion changes.
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT a.opening_material, e.enrollment_hash FROM accounts a JOIN enrollment_answers e ON e.account_id = a.id \
             WHERE a.id = $1 AND a.opening_material IS NOT NULL AND ($2::bytea IS NULL OR e.enrollment_hash = $2) AND \
             e.store_id = $3 AND e.creating AND e.created_at_ms = a.created_at_ms AND ($4::bigint = 0 OR EXISTS( \
             SELECT 1 FROM state_history WHERE account_id = $1 AND state_version = $4 \
             AND state_tag = $5 AND creation_anchor = $6))",
        )
        .bind(id)
        .bind(enrollment.as_ref().map(|hash| hash.as_slice()))
        .bind(store_id.as_slice())
        .bind(super::to_db(count, "state_version")?)
        .bind(tag.as_slice())
        .bind(anchor.as_slice())
        .fetch_optional(self.conn())
        .await?;
        let Some((material, enrollment)) = row else {
            return Ok(false);
        };
        let (Ok(material), Ok(enrollment)) = (material.try_into(), enrollment.try_into()) else {
            return Ok(false);
        };
        Ok(receipt_anchor(
            &material,
            &store_id,
            &identity,
            &enrollment,
            created,
            limits,
        ) == anchor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opening_receipt_binds_the_request_and_returned_limits() {
        let first = [1; 32];
        let second = [2; 32];
        let limits = Limits::default();
        let anchor = |enrollment: &[u8; 32], actual: Limits| {
            receipt_anchor(&[3; 32], &[4; 16], &[5; 32], enrollment, 17, &actual)
        };
        let original = anchor(&first, limits);
        assert_ne!(anchor(&second, limits), original);
        for other in [
            Limits {
                app_limit: limits.app_limit + 1,
                ..limits
            },
            Limits {
                max_envelope: limits.max_envelope + 1,
                ..limits
            },
            Limits {
                max_sealed_value: limits.max_sealed_value + 1,
                ..limits
            },
            Limits {
                quota_bytes: limits.quota_bytes + 1,
                ..limits
            },
            Limits {
                max_batch: limits.max_batch + 1,
                ..limits
            },
            Limits {
                record_quota_bytes: limits.record_quota_bytes + 1,
                ..limits
            },
            Limits {
                max_import_bytes: limits.max_import_bytes + 1,
                ..limits
            },
        ] {
            assert_ne!(anchor(&first, other), original);
        }
    }
}
