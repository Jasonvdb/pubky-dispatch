//! Which certificate the service used to filter a collection (Switch wire 3.8, 7.4.9).

use pubky_switch_core::chain::{ItemType, SignedHead};
use pubky_switch_core::ops::{OpKind, Position, SignedOp};
use serde::{Deserialize, Serialize};

use super::{FeedPosition, ListProgress, position, serde_b64};
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
    /// Check the reader at the returned page's head. With no page to read, a
    /// fresh own directory establishes whether the grant really reads nothing.
    pub(super) async fn unconfirmed_page_reader(
        &mut self,
        page: Option<SignedHead>,
        progress: &ListProgress,
        upload: Option<FeedPosition>,
    ) -> Result<Option<(Directory, SignedHead)>, AppError> {
        let service = self.state.meta.service_key;
        let cert = self.state.cert.hash();
        // Opening a returned write can refresh the app's identity. Its new
        // certificate cannot complete a range begun under the earlier one.
        let same_reader =
            progress.cert == cert && progress.generation == self.state.meta.generation;
        if same_reader
            && let Some(head) = page
            && self.record_page_reader.as_ref()
                == Some(&PageReader {
                    service,
                    head,
                    cert,
                })
        {
            return Ok(None);
        }
        let result = self.client.own_directory().await;
        let (directory, head) = self.take(result).await.inspect_err(|_| {
            self.record_page_reader = None;
            self.last_collection_read = None;
        })?;
        let me = self.app_id();
        if same_reader
            && head.generation == self.state.meta.generation
            && directory.identity.generation() == head.generation
            && directory.identity.listed_cert(&me) == Some(cert)
            && directory
                .apps
                .iter()
                .any(|entry| entry.app_id == me && entry.record.cert().hash() == cert)
            && match page {
                Some(expected) => expected == head,
                None => self.current_directory_head(head, upload).await?,
            }
        {
            self.record_page_reader = Some(PageReader {
                service,
                head,
                cert,
            });
            return Ok(None);
        }
        self.record_page_reader = None;
        self.last_collection_read = None;
        Ok(Some((directory, head)))
    }

    /// An empty enumeration has no record page to qualify its ending. Its
    /// own directory must cover the known account history and pending upload.
    async fn current_directory_head(
        &mut self,
        head: SignedHead,
        upload: Option<FeedPosition>,
    ) -> Result<bool, AppError> {
        self.current_at(head, None).await?;
        if upload.is_some_and(|at| !self.covers_upload(position(head.generation, head.seq), at)) {
            return Ok(false);
        }
        let mut tx = self.tx()?;
        let Some(chain) = self.state.chain.as_mut() else {
            return Ok(false);
        };
        if chain.newest != Some(head) || chain.verified_seq() > head.seq {
            return Ok(false);
        }
        chain.write(&mut tx)?;
        self.commit(tx).await?;
        Ok(true)
    }

    pub(super) async fn reader_ready_without_a_page(
        &mut self,
        progress: &ListProgress,
        upload: Option<FeedPosition>,
    ) -> Result<bool, AppError> {
        if let Some(directory) = self.unconfirmed_page_reader(None, progress, upload).await? {
            Box::pin(self.follow_page_reader(directory)).await?;
            return Ok(false);
        }
        Ok(true)
    }

    /// Acquire only the listed account-signed certificate, even when every
    /// protocol is held before its listing. Its normal ordered feed still owes
    /// all entries, including any messages before the renewal.
    pub(super) async fn follow_page_reader(
        &mut self,
        (directory, head): (Directory, SignedHead),
    ) -> Result<(), AppError> {
        let me = self.app_id();
        let listed = directory.identity.listed_cert(&me);
        if matches!(
            self.take_directory_cert(directory, head).await?,
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
                if let Some(renewal) = self.renewal_from_feed(signed) {
                    // The account already lists this renewal. Take it at its
                    // feed position before retiring the search, so a failed
                    // adoption can replay the same ordered grant after a restart.
                    self.events.push(crate::app::AppEvent::RenewalSeen);
                    self.take_listed_renewal(renewal, (generation, item.seq))
                        .await?;
                }
                tx.delete(READER_RENEWAL)?;
                self.commit(tx).await?;
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
