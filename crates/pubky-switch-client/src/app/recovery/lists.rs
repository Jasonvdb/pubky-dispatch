//! The kept peers and denies this installation can contribute after a provider loss
//! (Switch spec 8.3, 12.6 step 2).

use std::collections::BTreeSet;

use pubky_switch_core::enc::{pubky_id, pubky_key, serde_b64_vec};
use pubky_switch_core::scopes::Permission;
use serde::{Deserialize, Serialize};

use super::{App, AppError, LossRecord, RecoveryStep, Refusal, corrupt, keys};
use crate::app::state::{Reader, Tx};
use crate::store::Write;

const KEPT: &str = "lc/kept/";
const DENIES: &str = "lc/deny/";
const INPUT: &str = "loss/list-input";
const REMAINING: &str = "loss/list-remaining";
const OBSERVED: &str = "loss/list-observed";
const REMOVED: &str = "loss/list-removed/";
/// Entries the user removed while the owed list upload still carried them unsent, by list:
/// the pages leave them out, so the upload never undoes the removal (Switch wire 7.4.14
/// "Lists").
const LEFT_OUT: &str = "loss/list-left-out/";
const LEFT_OUT_KEPT: &str = "loss/list-left-out/kept/";
const LEFT_OUT_DENY: &str = "loss/list-left-out/deny/";
/// Set when the owed contribution came from a backup: its kept peers then have no verified
/// row behind them, and a later loss counts them as unverified (Switch spec 12.6 step 2).
pub(in crate::app) const RESTORED_INPUT: &str = "loss/list-restored";
/// Set when the owed list upload was refused for want of deny room: reads don't send it
/// again until its entries or the room change (Switch wire 7.4.14).
pub(in crate::app) const WAITS: &str = "loss/list-waits";
/// Deny rows of the copy of the lists that a list read didn't hold, put there for the owed
/// upload's sake (`App::replace_lists`), under `loss/list-held/lc/deny/<pubky>`. A row a
/// read or a write holds again loses the mark.
pub(in crate::app) const HELD: &str = "loss/list-held/";
/// How long a read leaves a waiting upload before it tries again: one try an hour takes
/// little of the service's upload rate for the app (Switch wire 9.2).
pub(in crate::app) const WAIT_RETRY_MS: u64 = 60 * 60 * 1000;

/// The original contribution. Its packed, sorted IDs are independent of both
/// the replacement's signed list and later per-peer changes at that service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::app) struct ListInput {
    source: u64,
    target: u64,
    #[serde(with = "serde_b64_vec")]
    kept: Vec<u8>,
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
        ids(&self.kept)?;
        ids(&self.deny)?;
        Ok(())
    }

    /// The kept peers the input contributes.
    pub(in crate::app) fn kept_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.kept.as_chunks::<32>().0.iter().copied()
    }

    /// The deny entries the input contributes.
    pub(in crate::app) fn deny_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.deny.as_chunks::<32>().0.iter().copied()
    }

    pub(super) fn has_denies(&self) -> bool {
        !self.deny.is_empty()
    }

    /// The deny entries, in key order.
    pub(super) fn denied(&self) -> Result<Vec<[u8; 32]>, AppError> {
        Ok(ids(&self.deny)?.to_vec())
    }

    /// Whether the kept list holds `pubky`.
    fn keeps(&self, pubky: &[u8; 32]) -> Result<bool, AppError> {
        Ok(ids(&self.kept)?.binary_search(pubky).is_ok())
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
            kept: manage.then(|| wire_order(&self.kept)).transpose()?,
            deny: wire_order(&self.deny)?,
        })
    }
}

/// The peers left out of the owed upload, by list ([`LEFT_OUT`]).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::app) struct LeftOut {
    pub(in crate::app) kept: BTreeSet<[u8; 32]>,
    pub(in crate::app) deny: BTreeSet<[u8; 32]>,
}

impl LeftOut {
    async fn read(reader: &Reader) -> Result<Self, AppError> {
        let set = |rows: Vec<(String, Vec<u8>)>| -> Result<BTreeSet<[u8; 32]>, AppError> {
            rows.into_iter()
                .map(|(id, _)| pubky_key(&id).map_err(|_| corrupt()))
                .collect()
        };
        Ok(Self {
            kept: set(reader.scan_raw(LEFT_OUT_KEPT).await?)?,
            deny: set(reader.scan_raw(LEFT_OUT_DENY).await?)?,
        })
    }

    fn install(&self, tx: &mut Tx) -> Result<(), AppError> {
        tx.delete_prefix(LEFT_OUT)?;
        for (prefix, peers) in [(LEFT_OUT_KEPT, &self.kept), (LEFT_OUT_DENY, &self.deny)] {
            for peer in peers {
                tx.put(&format!("{prefix}{}", pubky_id(peer)), &())?;
            }
        }
        Ok(())
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
    kept: [u8; 32],
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
            lengths: [input.kept.len(), input.deny.len()],
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
        [&input.kept, &input.deny]
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
        let [kept, deny] = parts;
        let input = ListInput {
            source: stored.source,
            target: stored.target,
            kept,
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
        kept: packed(members(reader, tx, KEPT).await?),
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
    for (prior, prefix) in [(&mut saved.kept, KEPT), (&mut saved.deny, DENIES)] {
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
        for (current, saved) in [(&mut self.kept, &other.kept), (&mut self.deny, &other.deny)] {
            let union = ids(current)?.iter().chain(ids(saved)?).copied().collect();
            *current = packed(union);
        }
        Ok(())
    }

    fn empty(&self) -> bool {
        self.kept.is_empty() && self.deny.is_empty()
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
        if input.kept.len().saturating_add(input.deny.len()) > PART_BYTES {
            let staging = Staging {
                source: input.source,
                target: input.target,
                bank,
                kept: pubky_switch_core::enc::hash(&input.kept),
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
        tx.delete_prefix(LEFT_OUT)?;
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
            // Written again, the row is the list's own.
            tx.delete(&format!("{HELD}{key}"))?;
        } else {
            let reader = self.reader();
            for input in [
                fallback(&reader).await?,
                StoredList::read(&reader, OBSERVED).await?,
            ]
            .into_iter()
            .flatten()
            {
                let prior = if key.starts_with(KEPT) {
                    &input.kept
                } else {
                    &input.deny
                };
                if ids(prior)?.binary_search(pubky).is_ok() {
                    tx.put(&removed, &())?;
                    break;
                }
            }
            // A removal the app sees, its own or another app's, of an entry the owed list
            // upload still carries unsent is left out of it, so the upload never undoes it
            // (Switch spec 12.6 step 3).
            let list = if key.starts_with(KEPT) {
                List::Kept
            } else {
                List::Deny
            };
            if self.upload_still_carries(list, pubky).await? {
                self.leave_out(tx, list, pubky, true).await?;
            }
            // A deny entry removed at the new service may have made room there: a read
            // sends a waiting upload again.
            if list == List::Deny {
                tx.delete(WAITS)?;
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
            tx.delete(RESTORED_INPUT)?;
            tx.delete_prefix(HELD)?;
            tx.delete_prefix(REMOVED)?;
            tx.delete_prefix(LEFT_OUT)?;
        }
        Ok(())
    }

    /// The kept peers a list upload resumed from a backup carries, when it is done: its
    /// contribution's kept peers, less those left out of it, those it still denies and those
    /// a verified row confirms. The host is told of them as of a loss's contribution (Switch
    /// spec 12.4, 12.6 step 2); a later loss doesn't count them again.
    pub(super) async fn restored_kept_sent(&self, loss: &LossRecord) -> Result<u64, AppError> {
        let reader = self.reader();
        if !self.state.cert.has_permission(Permission::ListsManage)
            || !reader.exists(RESTORED_INPUT).await?
        {
            return Ok(0);
        }
        let input = self.original_list_input(loss).await?;
        let left = LeftOut::read(&reader).await?;
        // A deny entry left out of the upload no longer denies the peer at the new service.
        let denied: BTreeSet<[u8; 32]> = input
            .deny_ids()
            .filter(|who| !left.deny.contains(who))
            .collect();
        let mut count = 0u64;
        for who in input.kept_ids() {
            if left.kept.contains(&who)
                || denied.contains(&who)
                || crate::app::admission::observations::verified_row(&reader, true, &who).await?
            {
                continue;
            }
            count = count.saturating_add(1);
        }
        Ok(count)
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

    /// The peers left out of the owed upload.
    pub(super) async fn left_out(&self) -> Result<LeftOut, AppError> {
        LeftOut::read(&self.reader()).await
    }

    /// Whether the owed list upload still carries `pubky` in `list` in a page no answer has
    /// confirmed: then a removal the user makes also leaves it out of the upload, so the upload
    /// doesn't undo it. Once its page is confirmed the upload landed first, and the removal
    /// at the service stands (Switch wire 7.4.14 "Lists").
    pub(in crate::app) async fn upload_still_carries(
        &self,
        list: List,
        pubky: &[u8; 32],
    ) -> Result<bool, AppError> {
        let Some(loss) = self.loss_record().await? else {
            return Ok(false);
        };
        if loss.step != RecoveryStep::Lists {
            return Ok(false);
        }
        let reader = self.reader();
        let manage = self.state.cert.has_permission(Permission::ListsManage);
        let cursor = reader
            .get::<ListCursor>(PENDING)
            .await?
            .unwrap_or_else(|| ListCursor::new(manage));
        cursor.carries_unsent(&self.original_list_input(&loss).await?, list, pubky)
    }

    /// The deny entries the owed list upload carries, in key order, each with whether the
    /// same upload also keeps the peer: empty when no list upload is owed (Switch wire 7.4.14).
    /// Show them when the upload doesn't fit ([`super::Refusal::DenyListFull`]). For an app
    /// with `lists.manage`, unblocking one with [`App::undeny`] frees room, and so does
    /// unblocking a peer the new service denies that isn't among them. An app with
    /// `lists.read` alone only leaves entries out of the upload: one the new service already
    /// holds frees nothing, and [`App::allow_list`] shows which those are. A peer the upload
    /// also keeps is admitted once unblocked.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn recovery_deny_entries(&self) -> Result<Vec<RecoveryDenyEntry>, AppError> {
        let Some(loss) = self.loss_record().await? else {
            return Ok(Vec::new());
        };
        if loss.step != RecoveryStep::Lists {
            return Ok(Vec::new());
        }
        let input = self.original_list_input(&loss).await?;
        let left = self.left_out().await?;
        let manage = self.state.cert.has_permission(Permission::ListsManage);
        let cursor = self
            .reader()
            .get::<ListCursor>(PENDING)
            .await?
            .unwrap_or_else(|| ListCursor::new(manage));
        let keeps = cursor.owes_kept_peers();
        // Only the entries of pages not yet accepted: one already accepted is at the new
        // service, and leaving it out frees nothing.
        let unsent: BTreeSet<[u8; 32]> = input
            .upload(cursor.kept)?
            .deny
            .into_iter()
            .skip(cursor.deny_sent)
            .collect();
        let mut entries = Vec::new();
        for pubky in input.denied()? {
            if left.deny.contains(&pubky) || !unsent.contains(&pubky) {
                continue;
            }
            let also_kept = keeps && !left.kept.contains(&pubky) && input.keeps(&pubky)?;
            entries.push(RecoveryDenyEntry { pubky, also_kept });
        }
        Ok(entries)
    }

    /// The deny entries of the loss's own contribution while its list upload is owed, less
    /// those left out; none once the list step is done, when a list read is owed instead
    /// (Switch spec 12.6 step 2).
    pub(in crate::app) async fn owed_contributed_denies(
        &self,
    ) -> Result<BTreeSet<[u8; 32]>, AppError> {
        if self
            .loss_record()
            .await?
            .is_some_and(|loss| loss.step <= RecoveryStep::Lists)
        {
            self.contributed_denies().await
        } else {
            Ok(BTreeSet::new())
        }
    }

    /// The deny entries of the loss's own contribution, sent or not, less those the user left
    /// out: until a list read after the upload replaces the copy, the copy may lack them
    /// (Switch spec 12.6 step 2).
    pub(in crate::app) async fn contributed_denies(&self) -> Result<BTreeSet<[u8; 32]>, AppError> {
        let Some(input) = StoredList::read(&self.reader(), INPUT).await? else {
            return Ok(BTreeSet::new());
        };
        let left = self.left_out().await?;
        // A removal made after its page was accepted stands too (Switch spec 12.6 step 3).
        let mut removed = BTreeSet::new();
        for (id, _) in self.reader().scan_raw(&removed_prefix(DENIES)).await? {
            removed.insert(pubky_key(&id).map_err(|_| corrupt())?);
        }
        Ok(input
            .denied()?
            .into_iter()
            .filter(|peer| !left.deny.contains(peer) && !removed.contains(peer))
            .collect())
    }
}

/// A deny entry of the owed list upload ([`App::recovery_deny_entries`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryDenyEntry {
    /// The denied peer.
    pub pubky: [u8; 32],
    /// Whether the same upload also keeps the peer: unblocking it admits it.
    pub also_kept: bool,
}

/// One of the two lists an upload restores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::app) enum List {
    Kept,
    Deny,
}

impl App {
    /// Leave `pubky` out of `list` in the owed list upload, and out of a later loss's
    /// contribution (Switch wire 7.4.14 "Lists"). `in_feed` is a removal the feed showed,
    /// or this app's own settled at the service, at a place in the feed's order.
    pub(in crate::app) async fn leave_out(
        &self,
        tx: &mut Tx,
        list: List,
        pubky: &[u8; 32],
        in_feed: bool,
    ) -> Result<(), AppError> {
        if list == List::Deny {
            // A row the copy holds only for the upload's sake. Removed at the new service,
            // in the feed's order, it denies no longer. Left out with no removal there, the
            // new service may hold the entry by now, from an upload the app hasn't read or
            // a page whose answer was lost: the row stays, and the lists are taken again as
            // at a gap, which keeps or removes it (Switch spec 8.3, 12.6 step 2).
            let row = crate::app::admission::deny_key(pubky);
            let held = format!("{HELD}{row}");
            if self.read_in::<()>(&held, tx).await?.is_some() {
                tx.delete(&held)?;
                if in_feed {
                    tx.delete(&row)?;
                } else {
                    let cursor = self.state.cursor;
                    self.note_deny_gap(cursor.generation, cursor.seq, tx)
                        .await?;
                }
            }
        }
        leave_out_rows(tx, list, pubky)
    }
}

fn leave_out_rows(tx: &mut Tx, list: List, pubky: &[u8; 32]) -> Result<(), AppError> {
    // A deny entry left out may make room: a read sends the upload again. A kept peer left
    // out frees no deny room.
    if list == List::Deny {
        tx.delete(WAITS)?;
    }
    let id = pubky_id(pubky);
    let (left, copy) = match list {
        List::Kept => (LEFT_OUT_KEPT, KEPT),
        List::Deny => (LEFT_OUT_DENY, DENIES),
    };
    tx.put(&format!("{left}{id}"), &())?;
    tx.put(&removed_prefix(&format!("{copy}{id}")), &())
}

/// The recoverable list input in a plain or layered backup. Only the Lists step
/// can resume from these fields: it has already registered and uploaded the
/// evidence it held. Later steps retain only the locally recoverable membership.
#[derive(Clone, Serialize, Deserialize)]
pub(in crate::app) struct SavedLists {
    input: ListInput,
    left_out: LeftOut,
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
        // A restore keeps the user's removals: the peers left out stay out of the upload.
        let left_out = LeftOut::read(reader).await?;
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
            left_out,
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
                (&self.input.kept, &remaining.kept),
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
                        && next.left_out.kept.is_superset(&current.left_out.kept)
                        && next.left_out.deny.is_superset(&current.left_out.deny)
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

    /// The deny entries the owed contribution carries.
    pub(in crate::app) fn deny_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.input.deny_ids()
    }

    pub(in crate::app) fn restore(&self, tx: &mut Tx) -> Result<(), AppError> {
        StoredList::install(INPUT, &self.input, tx)?;
        self.left_out.install(tx)?;
        tx.put(RESTORED_INPUT, &())?;
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
/// submitted first. The first page with kept peers ends staged admission, while
/// any remaining kept peers continue as an ordinary recovery upload.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub(super) struct ListCursor {
    kept: bool,
    deny_sent: usize,
    kept_sent: usize,
}

impl ListCursor {
    pub(super) fn new(kept: bool) -> Self {
        Self {
            kept,
            deny_sent: 0,
            kept_sent: 0,
        }
    }

    pub(super) fn save(self, tx: &mut Tx) -> Result<(), AppError> {
        tx.put(PENDING, &self)
    }

    fn covers(self, previous: Self) -> bool {
        self.kept == previous.kept
            && self.kept_sent >= previous.kept_sent
            && self.deny_sent >= previous.deny_sent
    }

    fn valid(self, input: &ListInput) -> bool {
        self.deny_sent <= input.deny.len() / 32
            && self.kept_sent <= input.kept.len() / 32
            && (self.kept_sent == 0 || (self.kept && self.deny_sent == input.deny.len() / 32))
    }

    pub(super) fn owes_kept_peers(self) -> bool {
        self.kept
    }

    /// Whether a page this cursor hasn't confirmed carries `pubky` in `list`: its place in
    /// the wire order is at or past what the confirmed pages sent.
    fn carries_unsent(
        self,
        input: &ListInput,
        list: List,
        pubky: &[u8; 32],
    ) -> Result<bool, AppError> {
        let all = input.upload(self.kept)?;
        let (entries, sent) = match list {
            List::Kept => (all.kept.unwrap_or_default(), self.kept_sent),
            List::Deny => (all.deny, self.deny_sent),
        };
        Ok(entries
            .iter()
            .position(|peer| peer == pubky)
            .is_some_and(|at| at >= sent))
    }

    /// The next page of `input`, less the peers in `left`. The page boundaries are cut on
    /// the whole input, so the cursor's counts never move when a peer is left out later;
    /// a page left empty is still sent, and its answer moves the cursor as any page's.
    pub(super) fn page(
        self,
        input: &ListInput,
        cap: usize,
        left: &LeftOut,
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
        let all = input.upload(self.kept)?;
        let denies = &all.deny[self.deny_sent..];
        let kept = all.kept.as_deref().unwrap_or_default();
        let take_deny = denies.len().min(room);
        let take_kept_peers = (kept.len() - self.kept_sent).min(room - take_deny);
        let include_kept_peers =
            self.kept && take_deny == denies.len() && (take_kept_peers > 0 || kept.is_empty());
        let kept_out = |peer: &&[u8; 32]| !left.kept.contains(*peer);
        let deny_out = |peer: &&[u8; 32]| !left.deny.contains(*peer);
        let wire = UploadLists {
            kept: include_kept_peers.then(|| {
                kept[self.kept_sent..self.kept_sent + take_kept_peers]
                    .iter()
                    .filter(kept_out)
                    .copied()
                    .collect()
            }),
            deny: denies[..take_deny]
                .iter()
                .filter(deny_out)
                .copied()
                .collect(),
        };
        let next = Self {
            kept: self.kept,
            deny_sent: self.deny_sent + take_deny,
            kept_sent: self.kept_sent + take_kept_peers,
        };
        let end = next.deny_sent == all.deny.len()
            && next.kept_sent == kept.len()
            && (!self.kept || include_kept_peers);
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
    tx.delete(RESTORED_INPUT)?;
    tx.delete(WAITS)?;
    tx.delete_prefix(HELD)?;
    tx.delete(INPUT)?;
    tx.delete(REMAINING)?;
    tx.delete(PENDING)?;
    tx.delete(OBSERVED)?;
    tx.delete(FINISHED)?;
    tx.delete(STAGING)?;
    tx.delete_prefix(PARTS)?;
    tx.delete_prefix(REMOVED)?;
    tx.delete_prefix(LEFT_OUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MAX_BATCH_BYTES;

    #[test]
    fn test_default_recovery_lists_fit_as_original_and_reduced_backup_inputs() {
        // Switch wire 9.1, 9.2: the default quotas permit 100,000 kept peers, and the
        // deny list holds fewer; 100,000 of each bounds both. Two complete sets can
        // coexist if observations changed before the Lists-step backup. Use the
        // actual protected value and batch codec.
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
            kept: peers(1),
            deny: peers(2),
        };
        let remaining = ListInput {
            source: 1,
            target: 2,
            kept: peers(3),
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
        let (first, ListStep::More(next)) = cursor.page(&union, cap, &LeftOut::default()).unwrap()
        else {
            panic!("expected another page")
        };
        assert!(first.len() <= cap);
        assert_eq!(next.deny_sent, 200_000);
        assert!(next.kept_sent > 0 && next.kept_sent < 200_000);
        let (last, ListStep::Submitted) = next.page(&union, cap, &LeftOut::default()).unwrap()
        else {
            panic!("expected the last page")
        };
        assert!(last.len() <= cap);
        let last: serde_json::Value = serde_json::from_slice(&last).unwrap();
        assert_eq!(last["lists"]["deny"].as_array().unwrap().len(), 0);
        assert_eq!(
            last["lists"]["kept"].as_array().unwrap().len(),
            200_000 - next.kept_sent
        );
        let mut restored = Tx::new("app");
        StoredList::install(INPUT, &union, &mut restored).unwrap();
        assert!(restored.size() < MAX_BATCH_BYTES);
    }

    #[test]
    fn test_recovery_list_pages_send_no_kept_peer_before_its_deny_entry() {
        // A kept peer the app also denies goes only in or after the page that carries its deny
        // entry, so no accepted page leaves it admitted (Switch wire 7.4.14 "Lists").
        use crate::client::answers::{RecoveryUpload, UploadLists};
        let peer = |n: u8| [n; 32];
        let sorted = |peers: &[[u8; 32]]| packed(peers.iter().copied().collect());
        let deny: Vec<_> = (1..=7).map(peer).collect();
        let kept: Vec<_> = (5..=9).map(peer).collect();
        let input = ListInput {
            source: 1,
            target: 2,
            kept: sorted(&kept),
            deny: sorted(&deny),
        };
        input.check().unwrap();
        let empty = RecoveryUpload {
            lists: Some(UploadLists {
                kept: Some(Vec::new()),
                deny: Vec::new(),
            }),
            ..Default::default()
        }
        .to_json()
        .len();
        let cap = empty + 3 * (pubky_id(&[0; 32]).len() + 3);
        let mut cursor = ListCursor::new(true);
        let mut denied = BTreeSet::new();
        let mut restored = BTreeSet::new();
        let mut pages = 0;
        loop {
            let (body, step) = cursor.page(&input, cap, &LeftOut::default()).unwrap();
            pages += 1;
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let read = |member: &str| -> Vec<[u8; 32]> {
                body["lists"][member]
                    .as_array()
                    .map(|ids| {
                        ids.iter()
                            .map(|id| pubky_key(id.as_str().unwrap()).unwrap())
                            .collect()
                    })
                    .unwrap_or_default()
            };
            denied.extend(read("deny"));
            for kept in read("kept") {
                assert!(
                    !deny.contains(&kept) || denied.contains(&kept),
                    "a kept peer went before its deny entry"
                );
                restored.insert(kept);
            }
            match step {
                ListStep::More(next) => cursor = next,
                ListStep::Submitted => break,
                ListStep::Nothing => unreachable!(),
            }
        }
        assert!(pages > 2);
        assert_eq!(denied, deny.into_iter().collect());
        assert_eq!(restored, kept.into_iter().collect());
    }

    #[test]
    fn test_recovery_list_pages_send_an_empty_kept_list_only_after_every_deny_entry() {
        // A managing app that keeps no peer still ends staged admission with `kept: []`, but
        // only in the page that carries its last deny entry (Switch wire 7.4.14).
        use crate::client::answers::{RecoveryUpload, UploadLists};
        let deny: Vec<[u8; 32]> = (1..=7).map(|n| [n; 32]).collect();
        let input = ListInput {
            source: 1,
            target: 2,
            kept: Vec::new(),
            deny: packed(deny.iter().copied().collect()),
        };
        let empty = RecoveryUpload {
            lists: Some(UploadLists {
                kept: Some(Vec::new()),
                deny: Vec::new(),
            }),
            ..Default::default()
        }
        .to_json()
        .len();
        let cap = empty + 3 * (pubky_id(&[0; 32]).len() + 3);
        let mut cursor = ListCursor::new(true);
        let mut sent = 0;
        loop {
            let (body, step) = cursor.page(&input, cap, &LeftOut::default()).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            sent += body["lists"]["deny"].as_array().unwrap().len();
            let last = sent == deny.len();
            assert_eq!(
                body["lists"].get("kept").is_some(),
                last,
                "kept goes with the last deny entries only"
            );
            match step {
                ListStep::More(next) => cursor = next,
                ListStep::Submitted => break,
                ListStep::Nothing => unreachable!(),
            }
        }
        assert_eq!(sent, deny.len());
    }

    #[test]
    fn test_recovery_list_removals_leave_out_every_entry_not_yet_confirmed() {
        // A removal leaves its entry out of any page not yet confirmed, before the first page
        // or between two; one already sent stays sent. The page boundaries are cut on the
        // whole input, so the cursor counts don't move, and a page left empty is still sent
        // (Switch wire 7.4.14 "Lists").
        use crate::client::answers::{RecoveryUpload, UploadLists};
        let input = ListInput {
            source: 1,
            target: 2,
            kept: packed((10..=18).map(|n| [n; 32]).collect()),
            deny: packed([[1; 32], [2; 32]].into_iter().collect()),
        };
        let wire = input.upload(true).unwrap();
        let kept = wire.kept.clone().unwrap();
        let empty = RecoveryUpload {
            lists: Some(UploadLists {
                kept: Some(Vec::new()),
                deny: Vec::new(),
            }),
            ..Default::default()
        }
        .to_json()
        .len();
        let cap = empty + 3 * (pubky_id(&[0; 32]).len() + 3);
        let read = |body: &[u8], member: &str| -> Vec<[u8; 32]> {
            let body: serde_json::Value = serde_json::from_slice(body).unwrap();
            body["lists"][member]
                .as_array()
                .map(|ids| {
                    ids.iter()
                        .map(|id| pubky_key(id.as_str().unwrap()).unwrap())
                        .collect()
                })
                .unwrap_or_default()
        };
        // Without removals: the deny entries and one kept peer, then 3, 3 and 2 kept peers.
        let mut plain = Vec::new();
        let mut cursor = ListCursor::new(true);
        loop {
            let (_, step) = cursor.page(&input, cap, &LeftOut::default()).unwrap();
            match step {
                ListStep::More(next) => {
                    plain.push((next.deny_sent, next.kept_sent));
                    cursor = next;
                }
                ListStep::Submitted => break,
                ListStep::Nothing => unreachable!(),
            }
        }
        assert_eq!(plain, [(2, 1), (2, 4), (2, 7)]);
        // A deny entry removed before any page, then three kept peers once the first page
        // is confirmed: one it sent, which stays sent, and the whole second page.
        let mut left = LeftOut::default();
        let first = ListCursor::new(true);
        assert!(
            first
                .carries_unsent(&input, List::Deny, &wire.deny[1])
                .unwrap()
        );
        left.deny.insert(wire.deny[1]);
        let (body, ListStep::More(cursor)) = first.page(&input, cap, &left).unwrap() else {
            panic!("more pages")
        };
        assert_eq!(read(&body, "deny"), [wire.deny[0]]);
        assert_eq!(read(&body, "kept"), [kept[0]]);
        assert!(!cursor.carries_unsent(&input, List::Kept, &kept[0]).unwrap());
        assert!(
            !cursor
                .carries_unsent(&input, List::Deny, &wire.deny[0])
                .unwrap()
        );
        for peer in &kept[1..4] {
            assert!(cursor.carries_unsent(&input, List::Kept, peer).unwrap());
            left.kept.insert(*peer);
        }
        left.kept.insert(kept[0]);
        let mut cursor = cursor;
        let mut counts = vec![(cursor.deny_sent, cursor.kept_sent)];
        let mut sent = vec![kept[0]];
        loop {
            let (body, step) = cursor.page(&input, cap, &left).unwrap();
            assert!(read(&body, "deny").is_empty());
            sent.extend(read(&body, "kept"));
            match step {
                ListStep::More(next) => {
                    counts.push((next.deny_sent, next.kept_sent));
                    cursor = next;
                }
                ListStep::Submitted => break,
                ListStep::Nothing => unreachable!(),
            }
        }
        assert_eq!(counts, plain, "the cursor counts don't move");
        let mut expected: Vec<_> = std::iter::once(kept[0])
            .chain(kept[4..].iter().copied())
            .collect();
        expected.sort();
        sent.sort();
        assert_eq!(sent, expected);
    }
}
