//! The identity-signed document at the start of the recovered account (Switch spec 12.6).

use pubky_switch_core::chain::{ItemType, ServiceTransition, Verifier};
use pubky_switch_core::enc::b64;
use pubky_switch_core::ops::Position;
use pubky_switch_core::records::{IdentityDoc, VersionOrder};
use pubky_switch_core::sig::SignedDoc;

use super::{App, AppError, FeedItem, FeedQuery, LossRecord, keys};
use crate::app::chain::ChainView;
use crate::app::error::Alarm;
use crate::app::state::{Tx, key};
use crate::client::answers::FeedPage;

/// The two chain items the service commits together to open the generation (Switch wire
/// 7.4.2). Start at the zero hash even when the ordinary feed already passed the pair.
pub(super) fn opening(
    first: &FeedItem,
    second: &FeedItem,
    held: &IdentityDoc,
    loss: &LossRecord,
) -> Option<IdentityDoc> {
    let (FeedItem::Chain(first), FeedItem::Chain(second)) = (first, second) else {
        return None;
    };
    let generation = first.stub.open().ok()?.generation;
    if generation > loss.generation {
        return None;
    }
    let service_key = held.service_key_of(generation)?;
    let mut verifier = Verifier::new(generation);
    for (item, seq, kind) in [
        (first, 1, ItemType::Service),
        (second, 2, ItemType::Identity),
    ] {
        let envelope = verifier.push(&item.stub).ok()?;
        if envelope.seq != seq
            || item.seq != seq
            || envelope.generation != generation
            || item.item_type != kind
        {
            return None;
        }
        Verifier::check_item(&envelope, kind, &item.item.doc_bytes().ok()?).ok()?;
    }
    let ServiceTransition::Recovery { recovery_from, .. } =
        ServiceTransition::verify(&first.item, &service_key, &held.identity()).ok()?
    else {
        return None;
    };
    let doc = IdentityDoc::verify(&second.item, &held.identity()).ok()?;
    (doc.generation() == generation
        && doc.inbox().service_key == service_key
        && recovery_from >= loss.lost_generation
        && held.body().recovery_from == Some(recovery_from)
        && doc.body().recovery_from == Some(recovery_from)
        && (matches!(
            doc.compare(held),
            VersionOrder::Same | VersionOrder::SameBody
        ) || doc.check_successor(held).is_ok()))
    .then_some(doc)
}

impl App {
    pub(super) async fn keep_recovery_opening(
        &mut self,
        doc: &IdentityDoc,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let key = key::ident_body(&doc.identity(), doc.version());
        let hash = pubky_switch_core::enc::b64(&doc.body_hash());
        if self
            .reader()
            .get::<String>(&key)
            .await?
            .is_some_and(|seen| seen != hash)
        {
            return Err(self
                .raise(Alarm::Equivocation {
                    version: doc.version(),
                })
                .await);
        }
        tx.put(&key, &hash)?;
        tx.put(keys::OPENING, doc.signed())?;
        self.keep_roster_removals(doc, &self.state.own_doc, tx)
            .await
    }

    pub(crate) async fn note_roster_removals(
        &self,
        doc: &IdentityDoc,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if doc.body().recovery_from.is_some()
            && !doc.body().removed.is_empty()
            && let Some(signed) = self.reader().get::<SignedDoc>(keys::OPENING).await?
        {
            let opening =
                IdentityDoc::verify(&signed, &doc.identity()).map_err(|_| super::corrupt())?;
            self.keep_roster_removals(&opening, doc, tx).await?;
        }
        Ok(())
    }

    async fn keep_roster_removals(
        &self,
        opening: &IdentityDoc,
        doc: &IdentityDoc,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if opening.body().recovery_from != doc.body().recovery_from
            || opening.check_successor(doc).is_err()
        {
            return Ok(());
        }
        let reader = self.reader();
        let mut added = false;
        for removed in &doc.body().removed {
            let id = &removed.app_id;
            if opening.listed_cert(id).is_some() {
                let index = format!("loss/removed/{}", b64(id));
                if !reader.exists(&index).await? {
                    tx.put(&index, &doc.version())?;
                    added = true;
                }
            }
        }
        if added {
            tx.put(&format!("loss/removal/{}", doc.version()), doc.signed())?;
        }
        Ok(())
    }

    /// The accepted identity-signed successor that explicitly removed an app from the
    /// opening roster (Switch spec 4.3, 12.2, 12.6). The app keeps this evidence after the
    /// signer purges the removal. Returns `None` until it has seen the opening and removal.
    ///
    /// # Errors
    ///
    /// As [`Self::recovery_roster`].
    pub async fn recovery_removal(
        &mut self,
        app_id: &[u8; 16],
    ) -> Result<Option<IdentityDoc>, AppError> {
        let Some(opening) = Box::pin(self.recovery_roster()).await? else {
            return Ok(None);
        };
        if opening.listed_cert(app_id).is_none() {
            return Ok(None);
        }
        let reader = self.reader();
        let Some(version) = reader
            .get::<u64>(&format!("loss/removed/{}", b64(app_id)))
            .await?
        else {
            return Ok(None);
        };
        let signed = reader
            .get::<SignedDoc>(&format!("loss/removal/{version}"))
            .await?
            .ok_or_else(super::corrupt)?;
        let doc =
            IdentityDoc::verify(&signed, &opening.identity()).map_err(|_| super::corrupt())?;
        if doc.version() != version
            || doc.body().recovery_from != opening.body().recovery_from
            || !doc.lists_removed(app_id)
            || opening.check_successor(&doc).is_err()
        {
            return Err(super::corrupt());
        }
        Ok(Some(doc))
    }

    /// The identity-signed document that opened the most recent loss followed by this
    /// app (Switch spec 12.6). Its `apps` fix the roster, including an app removed later.
    /// Its `recovery_from` identifies the generation the signer declared lost.
    ///
    /// The verified document survives a reload and a cooperative move. If it has not been
    /// kept, read the first two chain items. A missing loss or unavailable prefix returns
    /// `None`. The document alone gives no evidence of any app's upload.
    ///
    /// # Errors
    ///
    /// A store, service or chain verification error, or a state in which the app has stopped.
    pub async fn recovery_roster(&mut self) -> Result<Option<IdentityDoc>, AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        let Some(loss) = self.loss_record().await? else {
            return Ok(None);
        };
        if let Some(signed) = self.reader().get::<SignedDoc>(keys::OPENING).await? {
            let doc = IdentityDoc::verify(&signed, &self.state.meta.identity)
                .map_err(|_| super::corrupt())?;
            if doc.generation() > loss.generation || doc.body().recovery_from.is_none() {
                return Err(super::corrupt());
            }
            return Ok(
                (doc.body().recovery_from == self.state.own_doc.body().recovery_from)
                    .then_some(doc),
            );
        }
        let generation = self.state.meta.generation;
        let Some(mut chain) = self.state.chain.clone() else {
            return Ok(None);
        };
        let page = self
            .recovery_prefix_page(&mut chain, generation, 0, 2)
            .await?;
        let Some(first) = page.items.first() else {
            return Ok(None);
        };
        let next;
        let second = match page.items.get(1) {
            Some(item) => item,
            None if page.more && page.scanned_through == 1 && first.seq() == 1 => {
                next = self
                    .recovery_prefix_page(&mut chain, generation, 1, 1)
                    .await?;
                let Some(item) = next.items.first() else {
                    return Ok(None);
                };
                item
            }
            None => return Ok(None),
        };
        let Some(doc) = opening(first, second, &self.state.own_doc, &loss) else {
            return Ok(None);
        };
        let mut tx = self.tx()?;
        self.keep_recovery_opening(&doc, &mut tx).await?;
        self.commit(tx).await?;
        Ok(Some(doc))
    }

    async fn recovery_prefix_page(
        &mut self,
        chain: &mut ChainView,
        generation: u64,
        seq: u64,
        limit: u32,
    ) -> Result<FeedPage, AppError> {
        let query = FeedQuery {
            after: Some(Position { generation, seq }),
            limit: Some(limit),
            wait: None,
        };
        let result = self.client.feed(query).await;
        let page = self.take(result).await?;
        // A historical lookup must not move the ordinary feed or its checkpoint.
        match chain.feed_page(&page, self.now(), self.state.device.multi_device) {
            Err(AppError::Alarm(alarm)) => return Err(self.raise(alarm).await),
            result => {
                result?;
            }
        }
        Ok(page)
    }
}
