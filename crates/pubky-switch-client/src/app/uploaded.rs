//! What a recovery upload changed, the app's side (Switch wire 7.4.14, Switch spec 12.6
//! step 3).
//!
//! An upload merges evidence into the switch's state without a chain item for what it
//! changed: a record taken from it has no `record.put` at the service, and a claim it
//! rebuilt or made divergent no entry. Its `upload` transition lists the keys, as the
//! uploader's answer does: every app, the uploader included, reads the transition in its
//! feed and marks keys to read again, in the commit that passes the transition, so a crash
//! loses no mark:
//!
//! - **claims it holds** (`clread/<claim_key>`, as after a stub), by an app with
//!   `claims.read`: read again by [`App::reread_claims`], which raises
//!   [`super::AppEvent::ClaimChanged`] for a held view the read changed. A divergent claim is
//!   doubtful, so no automatic attempt relies on it ([`App::claim_doubt`]). A claim the app
//!   doesn't hold isn't marked: it reads it when it first attempts on it. So the claim marks
//!   are bounded by the claims the app holds, whatever the switch lists.
//! - **records** (`rcread/<key>`): read again by [`App::reread_records`] with
//!   `GET /records/{key}`, and taken as any read write is, after the checks of Switch spec
//!   10.3: its version is the service's word, since no proof dates it. At most
//!   [`MAX_RECORD_MARKS`] are kept: an upload past it drops them and owes a listing of the
//!   protocol's collections instead (`list_due`); the marks of records the app holds
//!   outside those collections, which no listing reads, stay.
//!
//! A record the app holds whose latest view shows `divergent` is held so (`rcdiv/<key>`,
//! [`SharedRecord::divergent`]): uploads conflict with its current write, which the app
//! still takes as it would any other. It stays so until a view shows it isn't, until the
//! app takes a newer write at the service, its own or one from the feed, which clears the
//! switch's divergent uploads (Switch wire 7.4.14), or until a provider loss, whose new
//! service holds none of them. What to do about it, such as writing the record again, is
//! the protocol's.
//!
//! [`SharedRecord::divergent`]: super::records::SharedRecord::divergent

use std::collections::BTreeMap;

use pubky_switch_core::enc::{b64, unb64_array};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::scopes::Permission;

use super::claims::{claim_key_of, reread_key};
use super::events::Duty;
use super::records::{RecordAnswer, WriteRead, record_key_of};
use super::state::Tx;
use super::{App, AppError, FeedPosition};
use crate::error::{ClientError, StoreError};

/// A record the app reads again after an upload listed it (`rcread/<key>`), with when it
/// was marked, device time: the oldest marks go first.
const RECORD_REREAD_PREFIX: &str = "rcread/";
/// A record whose latest view the app read shows divergent uploads (`rcdiv/<key>`).
pub(super) const DIVERGENT_PREFIX: &str = "rcdiv/";

/// The most records one read reads again after an upload listed them. Each is a request of
/// its own (`GET /records/{key}`), so the bound keeps a read's cost and time bounded after
/// an upload that changed many records, as [`super::claims::CLAIM_REREADS_PER_READ`] does
/// for claims. The records past it stay marked, oldest mark first, for the next read.
pub const RECORD_REREADS_PER_READ: usize = 16;

/// The most records the app keeps marked to read again. Each is a request of its own, 16 a
/// read; past 1,000, a listing of the collections, a request per 1,000 records, reads them
/// in fewer requests, and it bounds what a switch that chains uploads of fresh keys can
/// make the app store. An upload that would mark past it drops the marks and owes the
/// listing instead, keeping only those of records the app holds outside the collections
/// the listing reads.
pub const MAX_RECORD_MARKS: usize = 1_000;

/// The most keys of each kind, records and claims, the app marks for one upload: an
/// `upload` transition names at most 14,742 keys (Switch wire 10.3, the `chain` part's
/// size). A list longer than that comes from no service that keeps the wire's caps, and
/// the keys past it are left unmarked.
const MAX_MARKED_KEYS: usize = 14_742;

/// What one mark takes in a commit, at most: its namespace, key and value.
const MARK_BYTES: u64 = 256;

// The marks of one upload fit the room a feed item has in its read's commit.
const _: () = assert!(2 * (MAX_MARKED_KEYS as u64) * MARK_BYTES <= super::feed::ITEM_ROOM_BYTES);

fn record_reread_key(key: &[u8; 32]) -> String {
    format!("{RECORD_REREAD_PREFIX}{}", b64(key))
}

pub(super) fn divergent_key(key: &[u8; 32]) -> String {
    format!("{DIVERGENT_PREFIX}{}", b64(key))
}

/// The device time orders work. The verified feed position determines which answers
/// can fulfill the upload's read (Switch wire 7.4.14).
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
struct RecordReread {
    marked_ms: u64,
    upload: FeedPosition,
}

impl App {
    /// An upload's mark on a key whose collection is unknown can belong to any
    /// readable collection until its current view arrives.
    pub(super) async fn collection_reread_pending(
        &self,
        collection: &super::Collection,
    ) -> Result<bool, AppError> {
        for (key, _) in self
            .reader()
            .scan::<RecordReread>(RECORD_REREAD_PREFIX)
            .await?
        {
            let key = unb64_array::<32>(&key).map_err(|_| AppError::Store(StoreError::Corrupt))?;
            if self
                .held_collection(&key)
                .await?
                .is_none_or(|held| held.name == collection.name)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) async fn record_upload(
        &self,
        key: &[u8; 32],
    ) -> Result<Option<FeedPosition>, AppError> {
        Ok(self
            .reader()
            .get::<RecordReread>(&record_reread_key(key))
            .await?
            .map(|mark| mark.upload))
    }

    pub(super) async fn record_upload_in(
        &self,
        key: &[u8; 32],
        tx: &Tx,
    ) -> Result<Option<FeedPosition>, AppError> {
        Ok(self
            .read_in::<RecordReread>(&record_reread_key(key), tx)
            .await?
            .map(|mark| mark.upload))
    }

    /// A replay before the cursor can revisit an earlier upload. Retain the higher
    /// verified position when individual obligations or listings are combined.
    pub(super) fn latest_upload(
        &self,
        a: FeedPosition,
        b: FeedPosition,
    ) -> Result<FeedPosition, AppError> {
        match self.received_order(a, b) {
            Some(std::cmp::Ordering::Less) => Ok(b),
            Some(_) => Ok(a),
            None => Err(super::Refusal::NotNow(
                "the outstanding upload positions cannot be ordered".into(),
            )
            .into()),
        }
    }

    /// Mark for reading again the records an upload changed or made divergent, and the
    /// claims among those it lists that the app holds, from its `upload` transition in the
    /// feed (Switch wire 7.4.14), in `tx`. A key already marked is marked again, at the
    /// transition's read. An app without `claims.read` can't read claims, and marks none; a
    /// record it may not read is unmarked when the switch refuses its read. Records past
    /// [`MAX_RECORD_MARKS`], counting those marked before, drop the record marks and owe a
    /// listing instead, but for records the app holds outside the protocol's collections:
    /// returns the newest upload the listing must cover.
    pub(crate) async fn mark_uploaded(
        &self,
        upload: FeedPosition,
        mut records: Vec<[u8; 32]>,
        mut claims: Vec<[u8; 32]>,
        tx: &mut Tx,
    ) -> Result<Option<FeedPosition>, AppError> {
        let at = self.now();
        let mark = RecordReread {
            marked_ms: at,
            upload,
        };
        let mut listing = None;
        records.truncate(MAX_MARKED_KEYS);
        claims.truncate(MAX_MARKED_KEYS);
        if !records.is_empty() {
            // The marks held, at most: those committed, unless `tx` dropped them (a key no
            // mark has shows the drop), and those `tx` puts.
            let dropped = tx.pending_state(&format!("{RECORD_REREAD_PREFIX}~")) == Some(false);
            let mut held: BTreeMap<String, RecordReread> = if dropped {
                BTreeMap::new()
            } else {
                self.reader()
                    .scan(RECORD_REREAD_PREFIX)
                    .await?
                    .into_iter()
                    .collect()
            };
            let staged = tx.pending_put_keys(RECORD_REREAD_PREFIX);
            let capped = held
                .len()
                .saturating_add(staged.len())
                .saturating_add(records.len())
                > MAX_RECORD_MARKS;
            for rest in staged {
                let entry = format!("{RECORD_REREAD_PREFIX}{rest}");
                let prior = tx
                    .pending_get::<RecordReread>(&entry)?
                    .flatten()
                    .ok_or(StoreError::Corrupt)?;
                held.insert(rest, prior);
            }
            for key in records {
                let rest = b64(&key);
                let mut next = mark;
                if let Some(prior) = held.get(&rest) {
                    next.upload = self.latest_upload(upload, prior.upload)?;
                }
                if capped {
                    held.insert(rest, next);
                } else {
                    tx.put(&record_reread_key(&key), &next)?;
                }
            }
            if capped {
                let collections = self.protocols.collections();
                let mut minimum = upload;
                let mut keep = Vec::new();
                for (rest, mark) in held {
                    let key = unb64_array::<32>(&rest).map_err(|_| StoreError::Corrupt)?;
                    if let Some(collection) = self.held_collection(&key).await?
                        && !collections
                            .iter()
                            .any(|listed| listed.name == collection.name)
                    {
                        keep.push((key, mark));
                    } else {
                        minimum = self.latest_upload(minimum, mark.upload)?;
                    }
                }
                tx.delete_prefix(RECORD_REREAD_PREFIX)?;
                for (key, mark) in keep {
                    tx.put(&record_reread_key(&key), &mark)?;
                }
                listing = Some(minimum);
            }
        }
        if self.state.cert.has_permission(Permission::ClaimsRead) {
            for claim_key in &claims {
                let held = claim_key_of(claim_key);
                let holds = match tx.pending_state(&held) {
                    Some(held) => held,
                    None => self.reader().exists(&held).await?,
                };
                if holds {
                    tx.put(&reread_key(claim_key), &at)?;
                }
            }
        }
        Ok(listing)
    }

    /// At the end of a read: read again the records an upload listed (Switch wire 7.4.14),
    /// at most [`RECORD_REREADS_PER_READ`] of them, the oldest marks first, one request
    /// each, and take each view as any read write is. A record read is unmarked in the
    /// commit of what it read, and so is one the switch doesn't know (`404` at an account it
    /// hosts, which is absence: the rollback alarm for a permanent record the app holds live,
    /// Switch spec 10.3.1 "Absence"), one whose read scope the app lacks (`403
    /// permission_missing`). An earlier or unordered observation, or a view naming another
    /// key, leaves the read owed. Any other failure on the network or an answer the switch
    /// may change, such as `403
    /// cert_expired` before a renewal or the signed `404` saying it doesn't host the identity
    /// (Switch spec 12.7 step 5), stops the reads here, its record and the rest still marked,
    /// and the feed's read still succeeds; an alarm or a store failure fails it.
    ///
    /// A record is read again as it stands then, not in feed order: only for a protocol
    /// that is with the read, told through everything it covered ([`App::may_tell`], Switch
    /// spec 8.3). The mark of a record whose protocol is behind, or that the app can't
    /// place while any protocol is behind, stays, untouched and unread, until then; the
    /// others' marks are read meanwhile, the read's window taken from them alone.
    ///
    /// Returns whether marks are left that this read could read and didn't reach, past its
    /// budget of [`RECORD_REREADS_PER_READ`] or its time
    /// ([`super::AppConfig::call_budget_ms`]): the next read goes on with them
    /// ([`super::ReceiveReport::more`]). Marks waiting for a protocol that is behind aren't
    /// that: the read that brings it level reaches them.
    pub(crate) async fn reread_records(
        &mut self,
        budget: Option<&super::CallBudget>,
    ) -> Result<bool, AppError> {
        let mut marks = self
            .reader()
            .scan::<RecordReread>(RECORD_REREAD_PREFIX)
            .await?;
        marks.sort_by(|(a, x), (b, y)| x.marked_ms.cmp(&y.marked_ms).then(a.cmp(b)));
        let mut due = Vec::new();
        let mut left = false;
        for (rest, mark) in marks {
            let key = unb64_array::<32>(&rest).map_err(|_| AppError::Store(StoreError::Corrupt))?;
            let protocol = self.record_protocol(&key).await?;
            if !self.may_tell_of(protocol.as_deref()) {
                continue;
            }
            if due.len() == RECORD_REREADS_PER_READ {
                left = true;
                break;
            }
            due.push((key, mark.upload));
        }
        for (index, (key, upload)) in due.into_iter().enumerate() {
            if index > 0 && budget.is_some_and(|budget| self.spent(budget)) {
                return Ok(true);
            }
            let view = match self.record_answer(&key, [Some(upload), None]).await {
                Ok(RecordAnswer::View(record))
                    if record.view.key == key && record.covers_uploads =>
                {
                    Some((record.view, record.at))
                }
                Ok(RecordAnswer::Absent) => None,
                Ok(
                    RecordAnswer::Inconclusive | RecordAnswer::NotHosted(_) | RecordAnswer::View(_),
                ) => {
                    return Ok(false);
                }
                Err(AppError::Switch(ClientError::Switch {
                    code: ErrorCode::PermissionMissing,
                    ..
                })) => None,
                Err(AppError::Transport(_) | AppError::Switch(_)) => return Ok(false),
                Err(error) => return Err(error),
            };
            // A record the app holds is read as its collection, the protocol's or not, as
            // any read of it is; another as the protocol's collections take it.
            let collection = self.held_collection(&key).await?;
            let mut tx = self.tx()?;
            if let Some((view, at)) = view {
                let read = self
                    .take_view(
                        &view,
                        at,
                        collection.as_ref().map(|c| (&key, c)),
                        true,
                        &mut tx,
                    )
                    .await?;
                let waiting = match read {
                    WriteRead::Overtaken(..) => {
                        !self.upload_view_already_held(&view, upload, &tx).await?
                    }
                    WriteRead::Unordered | WriteRead::Waits => true,
                    _ => false,
                };
                if waiting {
                    self.commit(tx).await?;
                    return Ok(false);
                }
            }
            tx.delete(&record_reread_key(&key))?;
            self.commit(tx).await?;
        }
        Ok(left)
    }

    /// Hold what a view of record `key` says of divergent uploads, once its write is judged
    /// (Switch wire 7.4.9, 7.4.14): only while the app holds a record there, `tx`'s writes
    /// included; otherwise no flag stays.
    pub(crate) async fn note_view_divergence(
        &mut self,
        key: &[u8; 32],
        divergent: bool,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let record = record_key_of(key);
        let held = match tx.pending_state(&record) {
            Some(held) => held,
            None => self.reader().exists(&record).await?,
        };
        self.note_divergent(key, divergent && held, tx).await
    }

    /// Hold the divergent uploads of record `key`, `tx`'s writes included:
    /// [`super::AppEvent::RecordDivergent`] once the record becomes divergent, not again while it
    /// stays so, a duty event kept in `tx` beside the mark, so no crash separates the two
    /// and a mark cleared later in the same read doesn't take the event with it.
    pub(crate) async fn note_divergent(
        &mut self,
        key: &[u8; 32],
        divergent: bool,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let mark = divergent_key(key);
        let held = match tx.pending_state(&mark) {
            Some(held) => held,
            None => self.reader().exists(&mark).await?,
        };
        if divergent && !held {
            tx.put(&mark, &())?;
            // For the protocol of the record's collection, as far as the app knows it, `tx`'s
            // writes included: the protocol its judging was admitted for.
            let to = match self.record_protocol_in(key, tx).await? {
                Some(name) => vec![name],
                None => self.protocols.names(),
            };
            self.keep_duty_for(tx, to, Duty::RecordDivergent { key: *key })?;
        } else if !divergent && held {
            tx.delete(&mark)?;
        }
        Ok(())
    }

    /// Whether the latest view the app read of record `key` shows divergent uploads, not
    /// cleared since.
    pub(crate) async fn is_divergent(&self, key: &[u8; 32]) -> Result<bool, AppError> {
        self.reader().exists(&divergent_key(key)).await
    }
}
