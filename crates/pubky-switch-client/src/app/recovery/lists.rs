//! The contacts and denies this installation can contribute after a provider loss
//! (Switch spec 8.3, 12.6 step 2).

use std::collections::BTreeSet;

use pubky_switch_core::enc::{pubky_id, pubky_key, serde_b64_vec};
use serde::{Deserialize, Serialize};

use super::{App, AppError, LossRecord, RecoveryStep, Refusal, corrupt, keys};
use crate::app::state::{Reader, Tx};
use crate::store::Write;

const CONTACTS: &str = "lc/contact/";
const DENIES: &str = "lc/deny/";
const INPUT: &str = "loss/list-input";
const REMAINING: &str = "loss/list-remaining";
const OBSERVED: &str = "loss/list-observed";
const REMOVED: &str = "loss/list-removed/";

/// The original contribution. Its packed, sorted IDs are independent of both
/// the replacement's signed list and later per-peer changes at that service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::app) struct ListInput {
    source: u64,
    target: u64,
    #[serde(with = "serde_b64_vec")]
    contacts: Vec<u8>,
    #[serde(with = "serde_b64_vec")]
    deny: Vec<u8>,
}

fn packed(ids: BTreeSet<[u8; 32]>) -> Vec<u8> {
    ids.into_iter().flatten().collect()
}

fn ids(bytes: &[u8]) -> Result<&[[u8; 32]], AppError> {
    let (rows, remainder) = bytes.as_chunks::<32>();
    if !remainder.is_empty() || rows.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(corrupt());
    }
    Ok(rows)
}

impl ListInput {
    fn check(&self) -> Result<(), AppError> {
        if self.source >= self.target {
            return Err(corrupt());
        }
        ids(&self.contacts)?;
        ids(&self.deny)?;
        Ok(())
    }

    /// The kept peers the input contributes.
    pub(in crate::app) fn contact_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.contacts
            .chunks_exact(32)
            .filter_map(|id| <[u8; 32]>::try_from(id).ok())
    }

    /// The deny entries the input contributes.
    pub(in crate::app) fn deny_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.deny
            .chunks_exact(32)
            .filter_map(|id| <[u8; 32]>::try_from(id).ok())
    }

    pub(super) fn has_denies(&self) -> bool {
        !self.deny.is_empty()
    }

    pub(super) fn upload(
        &self,
        manage: bool,
    ) -> Result<crate::client::answers::UploadLists, AppError> {
        let wire_order = |bytes: &[u8]| -> Result<Vec<[u8; 32]>, AppError> {
            let mut ordered = ids(bytes)?.to_vec();
            ordered.sort_by_cached_key(pubky_id);
            Ok(ordered)
        };
        Ok(crate::client::answers::UploadLists {
            kept: manage.then(|| wire_order(&self.contacts)).transpose()?,
            deny: wire_order(&self.deny)?,
        })
    }
}

// A recovery can combine several permitted lists. Store raw ID pages below the
// per-value limit. A new loss uses the inactive bank; its rows become visible
// only with the loss transaction that installs their descriptor.
const PARTS: &str = "loss-list-parts/";
const PART_BYTES: usize = 1 << 20;
const STAGING: &str = "loss/list-staging";

#[derive(PartialEq, Eq, Serialize, Deserialize)]
struct Staging {
    source: u64,
    target: u64,
    bank: bool,
    contacts: [u8; 32],
    deny: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct StoredList {
    source: u64,
    target: u64,
    lengths: [usize; 2],
    bank: bool,
}

impl StoredList {
    fn of(input: &ListInput, bank: bool) -> Self {
        Self {
            source: input.source,
            target: input.target,
            lengths: [input.contacts.len(), input.deny.len()],
            bank,
        }
    }

    fn prefix(name: &str, bank: bool) -> String {
        format!("{PARTS}{}/{name}/", u8::from(bank))
    }

    fn pages<'a>(
        &self,
        name: &str,
        input: &'a ListInput,
    ) -> impl Iterator<Item = (String, &'a [u8])> {
        let prefix = Self::prefix(name, self.bank);
        [&input.contacts, &input.deny]
            .into_iter()
            .enumerate()
            .flat_map(move |(kind, bytes)| {
                let prefix = prefix.clone();
                bytes
                    .chunks(PART_BYTES)
                    .enumerate()
                    .map(move |(i, page)| (format!("{prefix}{kind}/{i}"), page))
            })
    }

    fn install(name: &str, input: &ListInput, tx: &mut Tx) -> Result<(), AppError> {
        let stored = Self::of(input, false);
        for (key, bytes) in stored.pages(name, input) {
            tx.put_raw(&key, bytes.to_vec())?;
        }
        tx.put(name, &stored)
    }

    async fn read(reader: &Reader, name: &str) -> Result<Option<ListInput>, AppError> {
        let Some(stored) = reader.get::<Self>(name).await? else {
            return Ok(None);
        };
        let prefix = Self::prefix(name, stored.bank);
        let mut parts = [Vec::new(), Vec::new()];
        for (kind, result) in parts.iter_mut().enumerate() {
            let length = stored.lengths[kind];
            if !length.is_multiple_of(32) {
                return Err(corrupt());
            }
            for i in 0..length.div_ceil(PART_BYTES) {
                let key = format!("{prefix}{kind}/{i}");
                let page = reader.get_raw(key.as_bytes()).await?.ok_or_else(corrupt)?;
                if page.len() != (length - result.len()).min(PART_BYTES) {
                    return Err(corrupt());
                }
                result.extend_from_slice(&page);
            }
        }
        let [contacts, deny] = parts;
        let input = ListInput {
            source: stored.source,
            target: stored.target,
            contacts,
            deny,
        };
        input.check()?;
        Ok(Some(input))
    }

    fn clear(name: &str, tx: &mut Tx) -> Result<(), AppError> {
        tx.delete(name)?;
        for bank in [true, false] {
            tx.delete_prefix(&Self::prefix(name, bank))?;
        }
        Ok(())
    }
}

fn removed_prefix(peers: &str) -> String {
    format!("{REMOVED}{peers}")
}

/// Read one list as the transaction will leave it, including signed changes
/// it already settled. Prefix deletes are ordered with the exact puts/deletes.
async fn members(reader: &Reader, tx: &Tx, prefix: &str) -> Result<BTreeSet<[u8; 32]>, AppError> {
    let mut keys: BTreeSet<Vec<u8>> = reader
        .scan_raw(prefix)
        .await?
        .into_iter()
        .map(|(key, _)| key.into_bytes())
        .collect();
    let prefix = prefix.as_bytes();
    for write in tx.pending_writes() {
        match write {
            Write::Put { key, .. } => {
                if let Some(id) = key.strip_prefix(prefix) {
                    keys.insert(id.to_vec());
                }
            }
            Write::Delete { key, .. } => {
                if let Some(id) = key.strip_prefix(prefix) {
                    keys.remove(id);
                }
            }
            Write::DeletePrefix {
                prefix: removed, ..
            } => {
                if prefix.starts_with(removed) {
                    keys.clear();
                } else if let Some(tail) = removed.strip_prefix(prefix) {
                    keys.retain(|key| !key.starts_with(tail));
                }
            }
        }
    }
    keys.into_iter()
        .map(|key| {
            pubky_key(std::str::from_utf8(&key).map_err(|_| corrupt())?).map_err(|_| corrupt())
        })
        .collect()
}

/// Only the replacement's own observations are superseded by a newer full read
/// there. Keep them apart from the contribution that still awaits submission.
async fn observed(
    reader: &Reader,
    tx: &Tx,
    source: u64,
    target: u64,
) -> Result<ListInput, AppError> {
    // Every kept peer of the app's copy is contributed, a restored one nothing verified
    // since too: with the old service gone the copy is the only evidence left (Switch spec
    // 12.6 step 2). One the user removed after the backup is kept again at the new service
    // until the user removes it; the deny entries contributed beside it still win.
    let mut observed = ListInput {
        source,
        target,
        contacts: packed(members(reader, tx, CONTACTS).await?),
        deny: packed(members(reader, tx, DENIES).await?),
    };
    if let Some(restored) = StoredList::read(reader, OBSERVED).await? {
        observed.merge(&with_removals(reader, tx, restored).await?)?;
    }
    Ok(observed)
}

async fn with_removals(
    reader: &Reader,
    tx: &Tx,
    mut saved: ListInput,
) -> Result<ListInput, AppError> {
    saved.check()?;
    for (prior, prefix) in [(&mut saved.contacts, CONTACTS), (&mut saved.deny, DENIES)] {
        let removed = members(reader, tx, &removed_prefix(prefix)).await?;
        if !removed.is_empty() {
            *prior = ids(prior)?
                .iter()
                .filter(|key| !removed.contains(*key))
                .flatten()
                .copied()
                .collect();
        }
    }
    Ok(saved)
}

impl ListInput {
    fn merge(&mut self, other: &Self) -> Result<(), AppError> {
        for (current, saved) in [
            (&mut self.contacts, &other.contacts),
            (&mut self.deny, &other.deny),
        ] {
            let union = ids(current)?.iter().chain(ids(saved)?).copied().collect();
            *current = packed(union);
        }
        Ok(())
    }

    fn empty(&self) -> bool {
        self.contacts.is_empty() && self.deny.is_empty()
    }
}

async fn fallback(reader: &Reader) -> Result<Option<ListInput>, AppError> {
    match StoredList::read(reader, REMAINING).await? {
        Some(reduced) => Ok(Some(reduced)),
        None => StoredList::read(reader, INPUT).await,
    }
}

impl App {
    pub(super) async fn install_loss_lists(
        &self,
        input: &ListInput,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let reader = self.reader();
        let old = reader.get::<StoredList>(INPUT).await?;
        let bank = old.as_ref().is_none_or(|stored| !stored.bank);
        let new = StoredList::of(input, bank);
        let inactive = StoredList::prefix(INPUT, bank);
        // An interrupted write must leave the active bank readable. Resume
        // only the exact contribution; the source can change before a retry.
        if input.contacts.len().saturating_add(input.deny.len()) > PART_BYTES {
            let staging = Staging {
                source: input.source,
                target: input.target,
                bank,
                contacts: pubky_switch_core::enc::hash(&input.contacts),
                deny: pubky_switch_core::enc::hash(&input.deny),
            };
            let resume = reader.get::<Staging>(STAGING).await?.as_ref() == Some(&staging);
            if !resume {
                let mut clear = Tx::new(&self.ns);
                clear.delete_prefix(&inactive)?;
                clear.put(STAGING, &staging)?;
                clear.commit(&self.env.store).await?;
            }
            for (key, bytes) in new.pages(INPUT, input) {
                if resume && reader.get_raw(key.as_bytes()).await?.as_deref() == Some(bytes) {
                    continue;
                }
                let mut page = Tx::new(&self.ns);
                page.put_raw(&key, bytes.to_vec())?;
                page.commit(&self.env.store).await?;
            }
        } else {
            tx.delete_prefix(&inactive)?;
            for (key, bytes) in new.pages(INPUT, input) {
                tx.put_raw(&key, bytes.to_vec())?;
            }
        }
        tx.put(INPUT, &new)?;
        tx.delete_prefix(&StoredList::prefix(INPUT, !bank))?;
        StoredList::clear(REMAINING, tx)?;
        StoredList::clear(OBSERVED, tx)
    }

    pub(super) async fn collect_loss_lists(
        &self,
        source: u64,
        target: u64,
        tx: &Tx,
    ) -> Result<ListInput, AppError> {
        let reader = self.reader();
        let mut current = observed(&reader, tx, source, target).await?;
        if let Some(previous) = fallback(&reader).await? {
            if previous.target > target {
                return Err(corrupt());
            }
            current.merge(&with_removals(&reader, tx, previous).await?)?;
        }
        Ok(current)
    }

    /// A subsequent removal narrows what can be contributed to another loss;
    /// it does not edit the still-owed original POST. Retain a removal only for
    /// a member of that snapshot, so distinct unrelated removes cannot grow it.
    pub(in crate::app) async fn note_loss_list_change(
        &self,
        key: &str,
        pubky: &[u8; 32],
        present: bool,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let removed = format!("{REMOVED}{key}");
        if present {
            if self.read_in::<()>(&removed, tx).await?.is_some() {
                tx.delete(&removed)?;
            }
        } else {
            let reader = self.reader();
            for input in [
                fallback(&reader).await?,
                StoredList::read(&reader, OBSERVED).await?,
            ]
            .into_iter()
            .flatten()
            {
                let prior = if key.starts_with(CONTACTS) {
                    &input.contacts
                } else {
                    &input.deny
                };
                if ids(prior)?.binary_search(pubky).is_ok() {
                    tx.put(&removed, &())?;
                    break;
                }
            }
        }
        Ok(())
    }

    pub(in crate::app) async fn list_read_after_upload(&self, tx: &mut Tx) -> Result<(), AppError> {
        let reader = self.reader();
        if reader.exists(OBSERVED).await? {
            StoredList::clear(OBSERVED, tx)?;
        }
        if !reader.exists(PENDING).await?
            && reader.exists(INPUT).await?
            && self
                .loss_record()
                .await?
                .is_none_or(|loss| loss.step > RecoveryStep::Lists)
        {
            StoredList::clear(INPUT, tx)?;
            StoredList::clear(REMAINING, tx)?;
            tx.delete_prefix(REMOVED)?;
        }
        Ok(())
    }

    pub(super) async fn original_list_input(
        &self,
        loss: &LossRecord,
    ) -> Result<ListInput, AppError> {
        let input: ListInput = StoredList::read(&self.reader(), INPUT)
            .await?
            .ok_or_else(corrupt)?;
        if (input.source, input.target) != (loss.lost_generation, loss.generation) {
            return Err(corrupt());
        }
        Ok(input)
    }
}

/// The recoverable list input in a plain or layered backup. Only the Lists step
/// can resume from these fields: it has already registered and uploaded the
/// evidence it held. Later steps retain only the locally recoverable membership.
#[derive(Clone, Serialize, Deserialize)]
pub(in crate::app) struct SavedLists {
    input: ListInput,
    waiting: Option<ListResume>,
    remaining: Option<ListInput>,
    observed: Option<ListInput>,
}

/// The completed registration and evidence steps leave just these values for
/// the remaining callbacks and their public recovery information. No earlier
/// signed batch or evidence upload is replayed from this checkpoint.
#[derive(Clone, Serialize, Deserialize)]
struct ListResume {
    cursor: ListCursor,
    key_n: u64,
    declared_at_ms: u64,
    cursor_time_ms: u64,
    clock_offset_ms: u64,
    claim_entries_left_out: u64,
}

impl ListResume {
    fn of(loss: &LossRecord, cursor: ListCursor) -> Result<Self, AppError> {
        if loss.step != RecoveryStep::Lists
            || !loss.batch.is_empty()
            || !loss.callback_owners.is_empty()
            || loss.answered != 0
            || !loss.reply_peers.is_empty()
        {
            return Err(corrupt());
        }
        Ok(Self {
            cursor,
            key_n: loss.key_n,
            declared_at_ms: loss.declared_at_ms.ok_or_else(corrupt)?,
            cursor_time_ms: loss.cursor_time_ms,
            clock_offset_ms: loss.clock_offset_ms,
            claim_entries_left_out: loss.claim_entries_left_out,
        })
    }

    fn resume(&self, input: &ListInput) -> LossRecord {
        LossRecord {
            lost_generation: input.source,
            generation: input.target,
            step: RecoveryStep::Lists,
            newest_head: None,
            cursor_time_ms: self.cursor_time_ms,
            declared_at_ms: Some(self.declared_at_ms),
            old_offset_ms: None,
            clock_offset_ms: self.clock_offset_ms,
            key_n: self.key_n,
            batch: Vec::new(),
            reply_peers: Vec::new(),
            reply_peers_left_out: 0,
            claim_entries_left_out: self.claim_entries_left_out,
            callback_owners: Vec::new(),
            answered: 0,
        }
    }
}

pub(super) const PENDING: &str = "loss/lists-pending";
pub(in crate::app) const FINISHED: &str = "loss-lists-finished";

impl SavedLists {
    pub(in crate::app) fn waiting_for_upload(&self) -> bool {
        self.waiting.is_some()
    }

    pub(in crate::app) async fn read(reader: &Reader) -> Result<Option<Self>, AppError> {
        let Some(input) = StoredList::read(reader, INPUT).await? else {
            return Ok(None);
        };
        input.check()?;
        let loss = reader.get::<LossRecord>(keys::LOSS).await?;
        let waiting = if let Some(cursor) = reader.get(PENDING).await? {
            let loss = loss.ok_or_else(corrupt)?;
            if loss.step < RecoveryStep::Lists {
                // Restoring the preceding registration or evidence step requires
                // its own inputs. Neither is represented as an applied list step.
                return Ok(None);
            }
            if loss.step != RecoveryStep::Lists
                || (loss.lost_generation, loss.generation) != (input.source, input.target)
            {
                return Err(corrupt());
            }
            Some(ListResume::of(&loss, cursor)?)
        } else {
            if reader.get::<u64>(FINISHED).await? != Some(input.target) {
                return Ok(None);
            }
            None
        };
        let tx = Tx::new(&reader.ns);
        let mut remaining = fallback(reader).await?.ok_or_else(corrupt)?;
        remaining = with_removals(reader, &tx, remaining).await?;
        let observed = observed(reader, &tx, input.source, input.target).await?;
        let remaining = (remaining != input).then_some(remaining);
        let observed = (!observed.empty()).then_some(observed);
        Ok(Some(Self {
            input,
            waiting,
            remaining,
            observed,
        }))
    }

    pub(in crate::app) fn check(
        &self,
        backup: &crate::app::AppBackup,
        own: &pubky_switch_core::records::IdentityDoc,
    ) -> Result<(), AppError> {
        let invalid = || AppError::InvalidData("the backup's list recovery is inconsistent".into());
        self.input.check().map_err(|_| invalid())?;
        let source = self.input.source;
        let target = self.input.target;
        if target > backup.meta.generation
            || own.generation() < target
            || own.body().recovery_from.is_none_or(|lost| {
                lost < source || (own.generation() == backup.meta.generation && lost >= target)
            })
        {
            return Err(invalid());
        }
        for remaining in [&self.remaining, &self.observed].into_iter().flatten() {
            remaining.check().map_err(|_| invalid())?;
            if (remaining.source, remaining.target) != (source, target) {
                return Err(invalid());
            }
        }
        if let Some(remaining) = &self.remaining {
            // A later observation may reduce the original contribution. Peers
            // learned at the replacement have their own origin in the backup.
            for (old, reduced) in [
                (&self.input.contacts, &remaining.contacts),
                (&self.input.deny, &remaining.deny),
            ] {
                let old = ids(old).map_err(|_| invalid())?;
                if ids(reduced)
                    .map_err(|_| invalid())?
                    .iter()
                    .any(|id| old.binary_search(id).is_err())
                {
                    return Err(invalid());
                }
            }
        }
        let completed = backup.finished_list_upload == Some(target);
        if self.waiting.is_none() != completed
            || backup
                .finished_list_upload
                .is_some_and(|done| done > target)
        {
            return Err(invalid());
        }
        if let Some(loss) = &self.waiting {
            let max_time = pubky_switch_core::time::MAX_TIME_MS;
            if loss.declared_at_ms > max_time
                || loss.cursor_time_ms > max_time
                || !loss.cursor.valid(&self.input)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(in crate::app) async fn check_destination(
        reader: &Reader,
        incoming: Option<&Self>,
        incoming_generation: u64,
        incoming_finished: Option<u64>,
    ) -> Result<Option<u64>, AppError> {
        let live = reader.get::<LossRecord>(keys::LOSS).await?;
        let finished = reader.get::<u64>(FINISHED).await?;
        let pending = incoming
            .filter(|saved| saved.waiting.is_some())
            .map(|saved| saved.input.target);
        let held = || {
            AppError::from(Refusal::NotNow(
                "the backup predates the installation's list recovery".into(),
            ))
        };
        if finished.is_some_and(|done| done > incoming_generation)
            || pending.is_some_and(|next| finished.is_some_and(|done| done >= next))
        {
            return Err(held());
        }
        if let Some(live) = live
            && reader.exists(PENDING).await?
            && live.step == RecoveryStep::Lists
            && pending.is_none_or(|next| next < live.generation)
        {
            return Err(held());
        }
        if let Some(current) = Self::read(reader).await? {
            match incoming {
                Some(next) if next.input.target > current.input.target => {}
                Some(next)
                    if next.input == current.input
                        && next.remaining == current.remaining
                        && next.observed == current.observed
                        && match (&next.waiting, &current.waiting) {
                            (Some(next), Some(old)) => next.cursor.covers(old.cursor),
                            (None, _) => true,
                            _ => false,
                        } => {}
                _ => return Err(held()),
            }
        } else if incoming
            .is_some_and(|next| finished.is_some_and(|done| done >= next.input.target))
        {
            // A signed full read retired the fallback held by this backup.
            return Err(held());
        }
        Ok(finished.max(incoming_finished))
    }

    pub(in crate::app) fn restore(&self, tx: &mut Tx) -> Result<(), AppError> {
        StoredList::install(INPUT, &self.input, tx)?;
        if let Some(remaining) = &self.remaining {
            StoredList::install(REMAINING, remaining, tx)?;
        }
        if let Some(observed) = &self.observed {
            StoredList::install(OBSERVED, observed, tx)?;
        }
        if let Some(loss) = &self.waiting {
            tx.put(keys::LOSS, &loss.resume(&self.input))?;
            tx.put(PENDING, &loss.cursor)?;
        }
        Ok(())
    }
}

/// Confirmed progress through one immutable list submission. Denials are
/// submitted first. The first page with contacts ends staged admission, while
/// any remaining contacts continue as an ordinary recovery upload.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub(super) struct ListCursor {
    contacts: bool,
    deny_sent: usize,
    contacts_sent: usize,
}

impl ListCursor {
    pub(super) fn new(contacts: bool) -> Self {
        Self {
            contacts,
            deny_sent: 0,
            contacts_sent: 0,
        }
    }

    pub(super) fn save(self, tx: &mut Tx) -> Result<(), AppError> {
        tx.put(PENDING, &self)
    }

    fn covers(self, previous: Self) -> bool {
        self.contacts == previous.contacts
            && self.contacts_sent >= previous.contacts_sent
            && self.deny_sent >= previous.deny_sent
    }

    fn valid(self, input: &ListInput) -> bool {
        self.deny_sent <= input.deny.len() / 32
            && self.contacts_sent <= input.contacts.len() / 32
            && (self.contacts_sent == 0
                || (self.contacts && self.deny_sent == input.deny.len() / 32))
    }

    pub(super) fn owes_contacts(self) -> bool {
        self.contacts
    }

    pub(super) fn page(
        self,
        input: &ListInput,
        cap: usize,
    ) -> Result<(Vec<u8>, ListStep), AppError> {
        use crate::client::answers::{RecoveryUpload, UploadLists};
        if !self.valid(input) {
            return Err(corrupt());
        }
        // Pubky IDs have a fixed encoded length. Count JSON quotes and the
        // comma conservatively, and measure the actual codec's empty shape.
        let empty_size = RecoveryUpload {
            lists: Some(UploadLists {
                kept: Some(Vec::new()),
                deny: Vec::new(),
            }),
            ..Default::default()
        }
        .to_json()
        .len();
        let room = cap.saturating_sub(empty_size) / (pubky_id(&[0; 32]).len() + 3);
        if room == 0 {
            return Err(crate::error::ClientError::BodyOverCap { cap }.into());
        }
        let all = input.upload(self.contacts)?;
        let denies = &all.deny[self.deny_sent..];
        let contacts = all.kept.as_deref().unwrap_or_default();
        let take_deny = denies.len().min(room);
        let take_contacts = (contacts.len() - self.contacts_sent).min(room - take_deny);
        let include_contacts = self.contacts
            && take_deny == denies.len()
            && (take_contacts > 0 || contacts.is_empty());
        let wire = UploadLists {
            kept: include_contacts
                .then(|| contacts[self.contacts_sent..self.contacts_sent + take_contacts].to_vec()),
            deny: denies[..take_deny].to_vec(),
        };
        let next = Self {
            contacts: self.contacts,
            deny_sent: self.deny_sent + take_deny,
            contacts_sent: self.contacts_sent + take_contacts,
        };
        let end = next.deny_sent == all.deny.len()
            && next.contacts_sent == contacts.len()
            && (!self.contacts || include_contacts);
        let body = RecoveryUpload {
            lists: Some(wire),
            ..Default::default()
        }
        .to_json();
        if body.len() > cap {
            return Err(crate::error::ClientError::BodyOverCap { cap }.into());
        }
        Ok((
            body,
            if end {
                ListStep::Submitted
            } else {
                ListStep::More(next)
            },
        ))
    }
}

pub(super) enum ListStep {
    Nothing,
    More(ListCursor),
    Submitted,
}

pub(super) fn submitted(tx: &mut Tx, generation: u64) -> Result<(), AppError> {
    tx.delete(PENDING)?;
    tx.put(FINISHED, &generation)
}

pub(in crate::app) fn clear_on_leave(tx: &mut Tx) -> Result<(), AppError> {
    tx.delete(INPUT)?;
    tx.delete(REMAINING)?;
    tx.delete(PENDING)?;
    tx.delete(OBSERVED)?;
    tx.delete(FINISHED)?;
    tx.delete(STAGING)?;
    tx.delete_prefix(PARTS)?;
    tx.delete_prefix(REMOVED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MAX_BATCH_BYTES;

    #[test]
    fn test_default_recovery_lists_fit_as_original_and_reduced_backup_inputs() {
        // Switch wire 9.1: the default quotas permit 100,000 contacts and denies
        // each. Two complete sets can coexist if observations changed before
        // the Lists-step backup. Use the actual protected value and batch codec.
        let peers = |domain: u8| {
            let mut result = Vec::with_capacity(100_000 * 32);
            for n in 0u32..100_000 {
                let mut peer = [domain; 32];
                peer[28..].copy_from_slice(&n.to_be_bytes());
                result.extend_from_slice(&peer);
            }
            result
        };
        let input = ListInput {
            source: 1,
            target: 2,
            contacts: peers(1),
            deny: peers(2),
        };
        let remaining = ListInput {
            source: 1,
            target: 2,
            contacts: peers(3),
            deny: peers(4),
        };
        input.check().unwrap();
        remaining.check().unwrap();
        let mut tx = Tx::new(&"a".repeat(120));
        StoredList::install(INPUT, &input, &mut tx).unwrap();
        StoredList::install(REMAINING, &remaining, &mut tx).unwrap();
        ListCursor::new(true).save(&mut tx).unwrap();
        assert!(tx.size() < MAX_BATCH_BYTES);
        assert!(tx.size() > 12_800_000);
        let mut union = input;
        union.merge(&remaining).unwrap();
        // Two individually legal default observations exceed both the old
        // protected JSON value and the upload body. Both current pages fit.
        assert!(
            crate::app::state::encode(&union).unwrap().len()
                > crate::store::MAX_VALUE_BYTES as usize
        );
        let cap = pubky_switch_core::http::body_cap("POST", "/v1/account/recovery/upload").unwrap();
        let cursor = ListCursor::new(true);
        let (first, ListStep::More(next)) = cursor.page(&union, cap).unwrap() else {
            panic!("expected another page")
        };
        assert!(first.len() <= cap);
        assert_eq!(next.deny_sent, 200_000);
        assert!(next.contacts_sent > 0 && next.contacts_sent < 200_000);
        let (last, ListStep::Submitted) = next.page(&union, cap).unwrap() else {
            panic!("expected the last page")
        };
        assert!(last.len() <= cap);
        let last: serde_json::Value = serde_json::from_slice(&last).unwrap();
        assert_eq!(last["lists"]["deny"].as_array().unwrap().len(), 0);
        assert_eq!(
            last["lists"]["kept"].as_array().unwrap().len(),
            200_000 - next.contacts_sent
        );
        let mut restored = Tx::new("app");
        StoredList::install(INPUT, &union, &mut restored).unwrap();
        assert!(restored.size() < MAX_BATCH_BYTES);
    }
}
