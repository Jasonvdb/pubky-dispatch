//! What an account holds of its identity: the newest `identity.json` with the proof of the
//! delivery that took it, the app limit, and the App IDs kept for good
//! (Dispatch wire 3.3, 3.7, 9.1). Every read and write runs in the request's transaction.

use pubky_dispatch_core::{records::IdentityDoc, sig::SignedDoc};
use sqlx::Row;

use super::{AccountTxn, StoreError, to_db};

/// A signed document in its carrying form, as the store keeps it.
pub(super) fn encode_doc(doc: &SignedDoc) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(doc).map_err(|_| StoreError::Corrupt("a signed document doesn't encode"))
}

pub(super) fn decode_doc(bytes: &[u8], what: &'static str) -> Result<SignedDoc, StoreError> {
    serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt(what))
}

/// The newest `identity.json` an account holds, with the proof of the delivery that took
/// it, if this service took it by `PUT /identity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldIdentity {
    /// The document as signed.
    pub doc: SignedDoc,
    /// The delivery's transition proof; `None` for a version the account was enrolled with.
    pub proof: Option<SignedDoc>,
}

impl AccountTxn {
    /// The newest `identity.json` the account holds.
    pub async fn held_identity(&mut self) -> Result<Option<HeldIdentity>, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query("SELECT identity_doc, identity_proof FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_one(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        let doc: Option<Vec<u8>> = row.try_get("identity_doc")?;
        let proof: Option<Vec<u8>> = row.try_get("identity_proof")?;
        let Some(doc) = doc else {
            return Ok(None);
        };
        Ok(Some(HeldIdentity {
            doc: decode_doc(&doc, "identity_doc")?,
            proof: proof
                .map(|proof| decode_doc(&proof, "identity_proof"))
                .transpose()?,
        }))
    }

    /// Hold `held` as the newest `identity.json`. A new version ends a hand-over the account
    /// holds, whichever signer delivered it (Dispatch wire 7.4.17): so every writer of a version
    /// drops it, and a retry of the same bytes, which writes nothing, keeps it.
    pub async fn set_identity(&mut self, held: &HeldIdentity) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        let checked =
            pubky_dispatch_core::records::IdentityDoc::verify(&held.doc, &self.head().identity_key)
                .map_err(|_| StoreError::Corrupt("identity_doc"))?;
        super::apps::note_removed(self.conn(), &id, &checked).await?;
        let doc = encode_doc(&held.doc)?;
        let proof = held.proof.as_ref().map(encode_doc).transpose()?;
        sqlx::query("UPDATE accounts SET identity_doc = $2, identity_proof = $3 WHERE id = $1")
            .bind(id)
            .bind(doc)
            .bind(proof)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        self.delete_handover().await?;
        self.note_change();
        Ok(())
    }

    /// The limits announced at the account's first enrollment.
    pub async fn announced_limits(
        &mut self,
    ) -> Result<pubky_dispatch_core::records::Limits, StoreError> {
        let id = self.head().id.clone();
        let bytes: Vec<u8> =
            sqlx::query_scalar("SELECT announced_limits FROM accounts WHERE id = $1")
                .bind(id)
                .fetch_one(self.conn())
                .await
                .map_err(StoreError::from_db)?;
        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt("announced_limits"))
    }

    /// The App IDs the account keeps for good: revoked, departed, or named by an
    /// enrollment or a verified identity document.
    pub async fn kept_app_ids(&mut self) -> Result<Vec<[u8; 16]>, StoreError> {
        let id = self.head().id.clone();
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT app_id FROM kept_app_ids WHERE account_id = $1 ORDER BY app_id",
        )
        .bind(id)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|app_id| {
                <[u8; 16]>::try_from(app_id.as_slice())
                    .map_err(|_| StoreError::Corrupt("kept app_id"))
            })
            .collect()
    }
}

pub(super) fn listed_ids(document: &IdentityDoc) -> Vec<Vec<u8>> {
    document
        .body()
        .apps
        .iter()
        .map(|app| app.app_id.to_vec())
        .collect()
}

/// Keep `at_ms` within the store's range.
pub(super) fn time_to_db(at_ms: u64) -> Result<i64, StoreError> {
    to_db(at_ms, "time")
}
