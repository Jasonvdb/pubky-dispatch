//! Which certificate the service used to filter a collection (Switch wire 3.8, 7.4.9).

use pubky_switch_core::chain::{ItemType, SignedHead};
use pubky_switch_core::ops::{OpKind, Position, SignedOp};
use serde::{Deserialize, Serialize};

use super::{ListProgress, serde_b64};
use crate::app::renewal::Listed;
use crate::app::{App, AppError};
use crate::client::answers::{Directory, FeedItem, FeedQuery};

pub(super) const READER_RENEWAL: &str = "record_reader_renewal";

#[derive(PartialEq, Eq)]
pub(in crate::app) struct PageReader {
    service: [u8; 32],
    head: SignedHead,
    cert: [u8; 32],
}

/// A search for the account's signed renewal is independent of delivery to the
/// protocol. The normal feed cursor stays before its outstanding listing.
#[derive(Serialize, Deserialize)]
struct RenewalSearch {
    #[serde(with = "serde_b64")]
    service: [u8; 32],
    generation: u64,
    #[serde(with = "serde_b64")]
    cert: [u8; 32],
    after: u64,
}

impl App {
    /// A matching own record and listed certificate settle either branch of the
    /// service's certificate selection. The directory must describe the page's
    /// exact authenticated account head.
    pub(super) async fn unconfirmed_page_reader(
        &mut self,
        head: SignedHead,
        progress: &ListProgress,
    ) -> Result<Option<Directory>, AppError> {
        let reader = PageReader {
            service: self.state.meta.service_key,
            head,
            cert: self.state.cert.hash(),
        };
        // Opening a returned write can refresh the app's identity. Its new
        // certificate cannot complete a range begun under the earlier one.
        let same_reader = progress.cert == reader.cert && progress.generation == head.generation;
        if same_reader && self.record_page_reader.as_ref() == Some(&reader) {
            return Ok(None);
        }
        let result = self.client.directory_with_head(None).await;
        let (directory, at) = self
            .take(result)
            .await
            .inspect_err(|_| self.last_collection_read = None)?;
        let me = self.app_id();
        if same_reader
            && at == Some(head)
            && head.generation == self.state.meta.generation
            && directory.identity.generation() == head.generation
            && directory.identity.listed_cert(&me) == Some(reader.cert)
            && directory
                .apps
                .iter()
                .any(|entry| entry.app_id == me && entry.record.cert().hash() == reader.cert)
        {
            self.record_page_reader = Some(reader);
            return Ok(None);
        }
        self.last_collection_read = None;
        Ok(Some(directory))
    }

    /// Acquire only the listed account-signed certificate, even when every
    /// protocol is held before its listing. Its normal ordered feed still owes
    /// all entries, including any messages before the renewal.
    pub(super) async fn follow_page_reader(
        &mut self,
        directory: Directory,
    ) -> Result<(), AppError> {
        let me = self.app_id();
        let listed = directory.identity.listed_cert(&me);
        if matches!(
            self.take_directory_cert(directory).await?,
            Listed::NotCurrentHere
        ) {
            return Ok(());
        }
        let Some(cert) = listed.filter(|hash| {
            *hash != self.state.cert.hash() && self.state.own_doc.listed_cert(&me) == Some(*hash)
        }) else {
            return Ok(());
        };
        let generation = self.state.meta.generation;
        let service = self.state.meta.service_key;
        let delivered = if self.state.cursor.generation == generation {
            self.state.cursor.seq
        } else {
            0
        };
        let prior = self.reader().get::<RenewalSearch>(READER_RENEWAL).await?;
        let after = prior
            .filter(|search| {
                search.service == service && search.generation == generation && search.cert == cert
            })
            .map_or(delivered, |search| search.after.max(delivered));
        let result = self
            .client
            .feed(FeedQuery {
                after: Some(Position {
                    generation,
                    seq: after,
                }),
                limit: Some(self.config.page()),
                wait: None,
            })
            .await;
        let page = self.take(result).await?;
        if page.service_key != service
            || page.head.generation != generation
            || page.next.generation != generation
            || page.freeze.is_some()
            || page.scanned_through < after
        {
            return Ok(());
        }
        let mut tx = self.tx()?;
        for member in &page.items {
            let FeedItem::Chain(item) = member else {
                continue;
            };
            if item.item_type != ItemType::Op
                || item.seq <= after
                || item.seq > page.scanned_through
            {
                continue;
            }
            let own = self.identity();
            let Ok(op) = SignedOp::verify(&item.item, &own, &own, None) else {
                continue;
            };
            if let OpKind::CertPut {
                target_app_id,
                cert: signed,
            } = &op.body().kind
                && target_app_id == &me
                && signed.doc_hash()? == cert
            {
                self.note_renewal(signed, &mut tx)?;
                tx.delete(READER_RENEWAL)?;
                self.commit(tx).await?;
                self.adopt_renewal(None).await?;
                return Ok(());
            }
        }
        if page.scanned_through > after {
            tx.put(
                READER_RENEWAL,
                &RenewalSearch {
                    service,
                    generation,
                    cert,
                    after: page.scanned_through,
                },
            )?;
            self.commit(tx).await?;
        }
        Ok(())
    }
}
