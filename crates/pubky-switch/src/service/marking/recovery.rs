//! Ordinary commits retain the bounded facts used for recovery (Switch account binding 3).

use std::sync::Arc;

use pubky_switch_core::records::{AccountActivation, IdentityDoc};

use crate::{
    http::error::ApiError,
    marks::{
        AccountMark, CreationAnchor, MarkStore,
        coverage::{PriorDocument, RecoverySource, RecoveryUpdate},
    },
    service::{Service, batch, store_error},
    store::{AccountTxn, Committed, MarkCoverage},
};

impl Service {
    /// Commit with the bounded recovery facts whose position this response will acknowledge.
    pub(in crate::service) async fn commit_marked(
        marks: &MarkStore,
        mut txn: AccountTxn,
        coverage: MarkCoverage,
        prior: Option<AccountMark>,
        refresh_enrollment: bool,
    ) -> Result<(Committed, Option<Arc<RecoveryUpdate>>), ApiError> {
        let prior = prior.filter(|mark| {
            matches!(
                mark.creation_anchor,
                CreationAnchor::Bound {
                    confirmed: true,
                    ..
                }
            ) && mark.created_at_ms == txn.loaded().created_at_ms
                && mark
                    .creation_anchor
                    .for_creation(mark.created_at_ms)
                    .is_some_and(|anchor| txn.creation_origin() == Some(anchor))
        });
        let changes = txn
            .pending_changes(prior.is_some())
            .await
            .map_err(|e| store_error(&e))?;
        let update = if let Some(prior) = prior
            && (changes.counts || refresh_enrollment)
            && let Some(position) = marks
                .recovery_position(&txn.loaded().id, prior)
                .await
                .map_err(|_| ApiError::unavailable("7.6: recovery mark unavailable"))?
        {
            let source = if changes.recovery_changed || refresh_enrollment {
                Self::recovery_source(&mut txn, position.store_id, &prior).await?
            } else {
                let loaded = txn.loaded();
                let pristine = prior.generation == 0
                    && prior.seq == 0
                    && prior.state_version == 0
                    && loaded.last_seq == 0;
                let same = prior.state_version == loaded.state_version
                    && prior.state_tag == loaded.state_tag
                    && (prior.head() == loaded.chain_tip() || pristine);
                if same { position.material() } else { None }
            };
            source.map(|source| position.with_material(source))
        } else {
            None
        };
        let committed = txn
            .commit_prepared(coverage, changes)
            .await
            .map_err(|e| store_error(&e))?;
        Ok((committed, update))
    }

    /// Complete recovery facts at this transaction's position, or SQL-required coverage
    /// when the actual exclusions exceed the inline budget (account binding 3).
    async fn recovery_source(
        txn: &mut AccountTxn,
        store_id: [u8; 16],
        prior: &AccountMark,
    ) -> Result<Option<Arc<RecoverySource>>, ApiError> {
        let limits = txn.announced_limits().await.map_err(|e| store_error(&e))?;
        if !txn
            .covers_recovery_state(store_id, &limits, prior)
            .await
            .map_err(|e| store_error(&e))?
        {
            return Ok(None);
        }
        let doc = txn
            .held_identity()
            .await
            .map_err(|e| store_error(&e))?
            .map(|held| IdentityDoc::verify(&held.doc, &txn.head().identity_key))
            .transpose()
            .map_err(|_| ApiError::unavailable("7.6: stored identity document unavailable"))?;
        let doc = doc.as_ref();
        let Some((kept, held)) = txn
            .recovery_exclusions()
            .await
            .map_err(|e| store_error(&e))?
        else {
            return Ok(None);
        };
        let (directory_version, apps_version) = txn
            .directory_versions()
            .await
            .map_err(|e| store_error(&e))?;
        let had_reachable_apps = batch::had_reachable_apps(txn, doc)
            .await
            .map_err(|e| store_error(&e))?;
        let head = txn.head();
        Ok(Some(Arc::new(RecoverySource {
            store_id,
            identity: head.identity_key,
            generation_floor: head.generation.max(doc.map_or(0, IdentityDoc::generation)),
            prior: doc.map(|doc| PriorDocument {
                hash: doc.hash(),
                version: doc.version(),
            }),
            recovery_only: head.activation == AccountActivation::Recovery,
            stamped_ms: head.stamped_time_ms,
            directory_version,
            apps_version,
            had_reachable_apps,
            limits,
            kept,
            held,
        })))
    }
}
