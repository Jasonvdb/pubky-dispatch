//! Current collection membership across a bounded listing and subsequent writes
//! (Switch spec 8.2, 8.3, 10.3; Switch wire 7.4.9).

use std::collections::BTreeMap;
use std::sync::Arc;

use pubky_switch_core::ops::Position;

use super::*;
use crate::app::ReceiveReport;
use crate::client::answers::RecordPage;

const PAGES_PREFIX: &str = "clpage/";
const WRITES_PREFIX: &str = "clwrite/";

pub(super) fn clear_on_leave(tx: &mut Tx) -> Result<(), AppError> {
    tx.delete_prefixes(&[PAGES_PREFIX, WRITES_PREFIX])
}

/// The readable records of one collection after a completed feed read, including
/// subsequent local writes. A decision requiring every value must wait while any
/// key in `uncertain_keys` remains unresolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentCollection {
    /// The account whose records were read.
    pub identity: [u8; 32],
    /// The final feed position covered by the read.
    pub through: Position,
    /// The verified chain head returned with that feed page.
    pub head: SignedHead,
    /// Current, readable live values in the requested policy.
    pub live: Vec<SharedRecord>,
    /// Current members whose contents or ordering could not be verified.
    pub uncertain_keys: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Member {
    Shown(#[serde(with = "revision_serde")] ApplicationRef),
    Uncertain,
    Absent,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ListedMember {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    pub(super) member: Member,
}

impl ListedMember {
    pub(super) fn new(
        view: &SharedRecordView,
        id: &[u8; 32],
        read: WriteRead,
        covers: bool,
    ) -> Self {
        let member = if covers
            && view.collection == *id
            && matches!(read, WriteRead::Taken | WriteRead::Equal)
        {
            Member::Shown(view.revision)
        } else {
            Member::Uncertain
        };
        Self {
            key: view.key,
            member,
        }
    }
}

/// A listing says what is present, including absence, over just its key range.
/// Each range has its own position since writes can occur between pages.
#[derive(Serialize, Deserialize)]
struct InventoryPage {
    #[serde(with = "serde_b64")]
    cert: [u8; 32],
    at: FeedPosition,
    next: Option<String>,
    members: Vec<ListedMember>,
    complete: bool,
}

#[derive(Serialize, Deserialize)]
struct Observation {
    at: FeedPosition,
    member: Member,
}

impl App {
    pub(super) fn keep_inventory_page(
        &self,
        collection: &Collection,
        after: Option<[u8; 32]>,
        page: &RecordPage,
        members: Vec<ListedMember>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let prefix = format!("{PAGES_PREFIX}{}/", b64(&collection.id(&self.identity())));
        let after = after.as_ref().map(|key| b64(key)).unwrap_or_default();
        if after.is_empty() {
            tx.delete_prefix(&prefix)?;
        }
        let next = page.next.as_ref().map(|key| b64(key));
        let mut previous = after.clone();
        let ordered = members.iter().all(|entry| {
            let key = b64(&entry.key);
            let advances = key > previous;
            previous = key;
            advances
        }) && next
            .as_ref()
            .is_none_or(|next| !members.is_empty() && *next == previous);
        // An old listing can supply historical writes. Its omissions cannot fill a
        // gap that extends past its snapshot or past the chain head it came with.
        let covers_owner = self
            .protocols
            .of_collection(&collection.name)
            .is_some_and(|owner| {
                let (generation, seq) = self.told(&owner.name);
                generation == page.head.generation && seq <= page.seq
            });
        let current = page.head.generation == self.state.cursor.generation
            && page.seq >= self.state.cursor.seq.max(page.head.seq)
            && self.state.chain.as_ref().is_some_and(|chain| {
                chain.newest == Some(page.head) && chain.verified_seq() <= page.head.seq
            });
        tx.put(
            &format!("{prefix}{after}"),
            &InventoryPage {
                cert: self.state.cert.hash(),
                at: position(page.head.generation, page.seq),
                next,
                members,
                complete: ordered && covers_owner && current,
            },
        )
    }

    pub(super) async fn observe_collection_write(
        &self,
        put: &RecordPut,
        envelope: &ChainEnvelope,
        read: WriteRead,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if !self
            .protocols
            .collections()
            .iter()
            .any(|c| c.id(&self.identity()) == put.collection)
        {
            return Ok(());
        }
        let at = position(envelope.generation, envelope.seq);
        let member = if matches!(read, WriteRead::Taken | WriteRead::Equal) {
            Member::Shown(ApplicationRef {
                generation: at.generation,
                seq: at.seq,
                item_hash: envelope.item_hash,
            })
        } else {
            Member::Uncertain
        };
        self.observe_member(&put.collection, &put.key, at, member, tx)
            .await
    }

    pub(super) async fn observe_member(
        &self,
        id: &[u8; 32],
        key: &[u8; 32],
        at: FeedPosition,
        member: Member,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if at.generation != self.state.meta.generation {
            return Ok(());
        }
        let path = format!("{WRITES_PREFIX}{}/{}", b64(id), b64(key));
        if let Some(old) = self.read_in::<Observation>(&path, tx).await?
            && old.at.generation == at.generation
            && (old.at.seq > at.seq || (old.at == at && old.member == member))
        {
            return Ok(());
        }
        tx.put(&path, &Observation { at, member })
    }

    /// The current membership of a registered readable collection as of this app's
    /// most recent completed read, plus writes committed locally since. Returns
    /// `None` until its listing and feed are complete and its owner has taken all
    /// earlier items. A missing or outdated baseline schedules the registered owner's
    /// bounded listing for a later receive. This call sends no requests.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn current_collection(
        &mut self,
        collection: &Collection,
        report: &ReceiveReport,
    ) -> Result<Option<CurrentCollection>, AppError> {
        let Some(coverage) = report.coverage.as_ref() else {
            return Ok(None);
        };
        let Some(owner) = self.protocols.of_collection(&collection.name) else {
            return Ok(None);
        };
        if !self
            .last_collection_read
            .as_ref()
            .is_some_and(|last| Arc::ptr_eq(last, coverage))
            || coverage.identity != self.identity()
            || coverage.cert != self.state.cert.hash()
            || coverage.through.generation != self.state.meta.generation
            || self.refuse_when_stopped().is_err()
            || self.not_current_here().is_some()
            || !owner.protocol.collections().contains(collection)
            || !collection.readable_by(&self.state.cert)
        {
            return Ok(None);
        }
        let owner = owner.name.clone();
        let (generation, seq) = self.told(&owner);
        if generation != coverage.through.generation
            || seq < coverage.through.seq
            || self
                .reader()
                .get::<ListDue>(LIST_DUE)
                .await?
                .is_some_and(|due| due.at(&owner).is_some())
            || self.collection_reread_pending(collection).await?
        {
            return Ok(None);
        }
        let id = b64(&collection.id(&coverage.identity));
        let changes: BTreeMap<_, _> = self
            .reader()
            .scan::<Observation>(&format!("{WRITES_PREFIX}{id}/"))
            .await?
            .into_iter()
            .collect();
        let mut live = Vec::new();
        let mut uncertain_keys = Vec::new();
        let mut after = String::new();
        loop {
            let page = self
                .reader()
                .get::<InventoryPage>(&format!("{PAGES_PREFIX}{id}/{after}"))
                .await?;
            let Some(page) = page.filter(|page| {
                page.complete && page.cert == coverage.cert && page.at.generation == generation
            }) else {
                let mut due = self
                    .reader()
                    .get::<ListDue>(LIST_DUE)
                    .await?
                    .unwrap_or_default();
                due.to.push((owner, None));
                let mut tx = self.tx()?;
                put_list_due(&mut tx, &due)?;
                self.commit(tx).await?;
                return Ok(None);
            };
            if page.at.seq > coverage.through.seq {
                return Ok(None);
            }
            if page.next.as_ref().is_some_and(|next| next <= &after) {
                return Err(store_corrupt());
            }
            let mut members: BTreeMap<_, _> = page
                .members
                .into_iter()
                .map(|m| (b64(&m.key), m.member))
                .collect();
            use std::ops::Bound::{Excluded, Included, Unbounded};
            let end = page.next.as_ref().map_or(Unbounded, Included);
            for (key, change) in changes.range::<String, _>((Excluded(&after), end)) {
                if change.at.generation == generation && change.at.seq > page.at.seq {
                    members.insert(key.clone(), change.member);
                }
            }
            for (key, member) in members {
                let key = unb64_array(&key).map_err(|_| store_corrupt())?;
                if member == Member::Absent {
                    continue;
                }
                if let Member::Shown(revision) = member
                    && let Some(held) = self.held_record(&key).await?
                    && held.collection == collection.name
                    && held.applied == revision
                    && held.base_write().1 == revision
                {
                    let record = held.shared(&key, self.is_divergent(&key).await?);
                    if record.authenticated
                        && !record.doubtful
                        && !record.flagged
                        && !record.not_taken
                        && !record.different_write_at_held_version
                        && !record.divergent
                    {
                        if !collection.admits(&record.policy)
                            || !self.state.cert.holds_scope(&record.policy.read_scope)
                        {
                            continue;
                        }
                        match record.content {
                            RecordContent::Deleted => continue,
                            RecordContent::Value(_) => {
                                live.push(record);
                                continue;
                            }
                            RecordContent::Unreadable(_) => {}
                        }
                    }
                }
                uncertain_keys.push(key);
            }
            match page.next {
                Some(next) => after = next,
                None => break,
            }
        }
        Ok(Some(CurrentCollection {
            identity: coverage.identity,
            through: coverage.through,
            head: coverage.head,
            live,
            uncertain_keys,
        }))
    }
}
