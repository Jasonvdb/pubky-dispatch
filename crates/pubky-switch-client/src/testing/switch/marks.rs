//! The account's mark at the scripted switch and the verdict it gives with the account
//! (Switch wire 7.3, "Accounts and marks", Tables 1 to 3; Switch spec 6.5), with the test
//! controls that put the two out of step: a restore behind the mark, a fork, a lost or
//! corrupt mark, a mark store that can't be read, a lost account, and a retired generation.
//!
//! The mark store lies apart from the account's state, as at the service: what resets the
//! account (an erasure, a lost account, a recovery in place) keeps it.

use std::collections::BTreeSet;

use pubky_switch_core::chain::{ChainTip, ZERO_HASH};
use pubky_switch_core::http::{
    ErrorCode, NoticeReason, RecoveryNotice, header, not_hosted_current,
};
use pubky_switch_core::records::{AccountActivation, AccountAssociation};
use pubky_switch_core::time::rfc3339;
use serde_json::json;

use super::{Answer, Inner, ScriptedSwitch, bad};
use crate::transport::{Request, Response};

/// A mark: the newest head the switch signed for the identity, or at a serving account
/// before its first chain item its generation with `seq` 0; the account's count of changed
/// state as of its last acknowledged change, with its tag; the service key the account is
/// answered with; and the time the account was created (Switch wire 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mark {
    pub(crate) generation: u64,
    pub(crate) seq: u64,
    pub(crate) chain_hash: [u8; 32],
    pub(crate) state_version: u64,
    pub(crate) state_tag: u64,
    pub(crate) key: [u8; 32],
    pub(crate) created_at_ms: u64,
}

impl Mark {
    /// A mark that records nothing: (0, 0), count 0, the zero tag.
    fn zero(key: [u8; 32], created_at_ms: u64) -> Self {
        Self {
            generation: 0,
            seq: 0,
            chain_hash: ZERO_HASH,
            state_version: 0,
            state_tag: 0,
            key,
            created_at_ms,
        }
    }

    fn records_head(&self) -> bool {
        self.seq != 0
    }

    /// A head, or a count above 0: what makes an identity without an account lost.
    fn records_acknowledged(&self) -> bool {
        self.records_head() || self.state_version != 0
    }
}

/// What the mark store holds for the identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum MarkSlot {
    /// No mark.
    #[default]
    Missing,
    /// A file that doesn't read as a mark.
    Corrupt,
    /// The mark.
    At(Mark),
}

/// The identity's part of the mark store: its mark, its retired generations and its
/// erasure's record, and whether the store can be read (Switch wire 7.3, "The store").
#[derive(Clone, Debug)]
pub(crate) struct MarkStore {
    /// The store identity, absent only if its initial generation failed.
    pub(crate) identity: Option<[u8; 16]>,
    pub(crate) slot: MarkSlot,
    pub(crate) unreadable: bool,
    pub(crate) retired: BTreeSet<u64>,
    /// The time of the erasure's record for the identity, if there is one.
    pub(crate) erasure_at_ms: Option<u64>,
    pub(super) attempt: Option<super::erasure::Attempt>,
}

impl Default for MarkStore {
    fn default() -> Self {
        Self {
            identity: pubky_switch_core::enc::random_bytes().ok(),
            slot: MarkSlot::Missing,
            unreadable: false,
            retired: BTreeSet::new(),
            erasure_at_ms: None,
            attempt: None,
        }
    }
}

impl MarkStore {
    fn mark(&self) -> Option<&Mark> {
        match &self.slot {
            MarkSlot::At(mark) => Some(mark),
            MarkSlot::Missing | MarkSlot::Corrupt => None,
        }
    }
}

/// The verdict of Table 1 (Switch wire 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The switch doesn't host the identity; with `delete_mark`, the mark is an erasure's
    /// leftover.
    NotHosted { delete_mark: bool },
    /// A staged account at its (0, 0) mark.
    Staged,
    /// The account's state is at or past its mark.
    Healthy,
    /// A staged account holding no chain, bounded by its mark.
    Bounded(RecoveryNotice),
    /// The account fails stop.
    Failing(RecoveryNotice),
    /// No account, and a mark that records a head.
    Lost(RecoveryNotice),
    /// The mark store can't be read.
    Unknown,
}

/// A request, by the columns of Table 2 (Switch wire 7.3) the scripted switch answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// An own signed request, another identity's caller, or the public read.
    Ordinary,
    /// `POST /v1/enroll`.
    Enroll,
    /// `PUT /identity`: the document's generation and `recovery_from`, where it reads.
    PutIdentity {
        generation: u64,
        recovery_from: Option<u64>,
    },
    /// `POST /recovery/upload`, the one step of a move the switch has a route for.
    Upload,
    /// `POST /erase`.
    Erase,
}

fn class_of(request: &Request) -> Class {
    // The route, without the query.
    let path = request.path_and_query.split('?').next().unwrap_or_default();
    match request.method.as_str() {
        "POST" if path == "/v1/enroll" => Class::Enroll,
        "POST" if path.ends_with("/erase") => Class::Erase,
        "POST" if path.ends_with("/recovery/upload") => Class::Upload,
        "PUT" if path.ends_with("/identity") => {
            let read = pubky_switch_core::http::IdentityDelivery::parse(&request.body)
                .ok()
                .and_then(|delivery| {
                    serde_json::from_slice::<serde_json::Value>(
                        &delivery.identity.body_bytes().ok()?,
                    )
                    .ok()
                });
            let generation = read
                .as_ref()
                .and_then(|doc| doc.get("generation"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let recovery_from = read
                .as_ref()
                .and_then(|doc| doc.get("recovery_from"))
                .and_then(serde_json::Value::as_u64);
            Class::PutIdentity {
                generation,
                recovery_from,
            }
        }
        _ => Class::Ordinary,
    }
}

impl Inner {
    /// Only a recovery above both the held document and readable mark starts (Switch wire
    /// 7.3, Table 2). The notice still names the chain generation where one is held (7.6).
    pub(super) fn starts_recovery(&self, generation: u64, from: Option<u64>) -> bool {
        let retained_sql = if self.hosts()
            && (self.activation == AccountActivation::Recovery
                || self
                    .marks
                    .mark()
                    .is_some_and(|mark| mark.created_at_ms != self.created_at_ms))
        {
            self.tip.generation
        } else {
            0
        };
        let floor = self
            .doc
            .as_ref()
            .map_or(0, |doc| doc.generation())
            .max(retained_sql)
            .max(self.marks.mark().map_or(0, |mark| mark.generation));
        generation > floor && from.is_some_and(|from| generation.checked_sub(1) == Some(from))
    }

    /// Whether the switch holds an account for the identity.
    pub(crate) fn hosts(&self) -> bool {
        self.enrolled.is_some() && !self.not_hosted_unpinned
    }

    /// The account's state: the head of the chain it holds, none for a staged account that
    /// holds no chain (Switch wire 7.3, "The state").
    fn state(&self) -> Option<ChainTip> {
        (!(self.staged && self.seq == 0)).then_some(self.tip)
    }

    /// The account's generation here (Switch wire 7.6): its state's, else its document's, 0
    /// with neither.
    fn account_generation(&self) -> u64 {
        match self.state() {
            Some(state) => state.generation,
            None => self.doc.as_ref().map_or(0, |doc| doc.generation()),
        }
    }

    /// Judge the account and its mark together (Switch wire 7.3, Table 1). The first row,
    /// an account created at or before an erasure's record, isn't reached: nothing here
    /// brings an erased account back.
    pub(crate) fn judge(&self) -> Verdict {
        let marks = &self.marks;
        if marks.unreadable || marks.attempt.is_some() {
            return Verdict::Unknown;
        }
        if self.not_hosted_unpinned {
            return Verdict::NotHosted { delete_mark: false };
        }
        let Ok(binding) = self.account_binding() else {
            return Verdict::Unknown;
        };
        let mark = marks
            .mark()
            .filter(|mark| binding.created() == Some(mark.created_at_ms));
        if binding.association() != AccountAssociation::Account {
            let Some(mark) = mark else {
                return Verdict::NotHosted { delete_mark: false };
            };
            if marks
                .erasure_at_ms
                .is_some_and(|erased_at| erased_at >= mark.created_at_ms)
            {
                return Verdict::NotHosted { delete_mark: true };
            }
            let permanent = marks.retired.contains(&mark.generation);
            return if mark.records_acknowledged() || permanent {
                Verdict::Lost(RecoveryNotice {
                    generation: mark.generation,
                    reason: NoticeReason::Behind,
                    permanent,
                })
            } else {
                Verdict::NotHosted { delete_mark: false }
            };
        }
        let state = self.state();
        let retired_generation = mark.map_or(self.account_generation(), |mark| mark.generation);
        let retired = marks.retired.contains(&retired_generation)
            && state.is_none_or(|state| state.generation <= retired_generation);
        let generation = self
            .account_generation()
            .max(mark.map_or(0, |mark| mark.generation));
        let notice = |reason, permanent| RecoveryNotice {
            generation,
            reason,
            permanent,
        };
        if self.activation == AccountActivation::Recovery {
            return match mark {
                Some(_) => Verdict::Bounded(notice(NoticeReason::Behind, retired)),
                None => Verdict::Failing(notice(NoticeReason::MarkLost, retired)),
            };
        }
        let Some(state) = state else {
            // Row "Staged, holding no chain".
            return match mark {
                None => Verdict::Failing(notice(NoticeReason::MarkLost, retired)),
                Some(mark) if retired || mark.records_head() => {
                    Verdict::Bounded(notice(NoticeReason::Behind, retired))
                }
                Some(_) => Verdict::Staged,
            };
        };
        // Rows "Staged, holding an activated import", "Serving" and "Frozen".
        let by_count = |mark: &Mark| {
            if state.generation < mark.generation || self.state_version < mark.state_version {
                // Fewer changes than the mark covers: an acknowledged one was lost, as the
                // service's one rule judges it (Switch wire 7.3, Table 1).
                Some(NoticeReason::Behind)
            } else if (mark.state_version > 0
                && self.state_history.get(&mark.state_version) != Some(&mark.state_tag))
                || (self.state_version == mark.state_version && self.state_tag != mark.state_tag)
            {
                Some(NoticeReason::Fork)
            } else {
                None
            }
        };
        let reason = match mark {
            None => Some(NoticeReason::MarkLost),
            Some(mark) if !mark.records_head() => by_count(mark),
            Some(mark) => {
                let at = (state.generation, state.seq);
                let marked = (mark.generation, mark.seq);
                if at < marked {
                    Some(NoticeReason::Behind)
                } else if at == marked && state.chain_hash != mark.chain_hash {
                    Some(NoticeReason::Fork)
                } else if at > marked
                    && self.tips.iter().any(|tip| {
                        (tip.generation, tip.seq) == marked && tip.chain_hash != mark.chain_hash
                    })
                {
                    // A state past the mark with another chain hash at the mark's `seq`.
                    Some(NoticeReason::Fork)
                } else {
                    by_count(mark)
                }
            }
        };
        match (retired, reason) {
            (true, reason) => {
                Verdict::Failing(notice(reason.unwrap_or(NoticeReason::Behind), true))
            }
            (false, Some(reason)) => Verdict::Failing(notice(reason, false)),
            (false, None) => Verdict::Healthy,
        }
    }

    /// The notice of a verdict that gives one.
    pub(crate) fn notice(&self) -> Option<RecoveryNotice> {
        match self.judge() {
            Verdict::Bounded(notice) | Verdict::Failing(notice) | Verdict::Lost(notice) => {
                Some(notice)
            }
            Verdict::NotHosted { .. } | Verdict::Staged | Verdict::Healthy | Verdict::Unknown => {
                None
            }
        }
    }

    /// Table 2's read-only route decision, also used when authentication fails before
    /// any request-dependent effect (Switch wire 7.3).
    pub(super) fn verdict_refusal(&self, request: &Request, verdict: Verdict) -> Option<Answer> {
        Some(match (verdict, class_of(request)) {
            (Verdict::Unknown, _) => bad(
                ErrorCode::Unavailable,
                "Switch wire 7.3: the mark store can't be read",
                json!(null),
            ),
            (Verdict::NotHosted { .. }, Class::Enroll) => return None,
            (Verdict::NotHosted { .. }, _) => not_hosted(),
            (Verdict::Staged | Verdict::Healthy, _) => return None,
            (Verdict::Bounded(_) | Verdict::Failing(_) | Verdict::Lost(_), Class::Enroll) => {
                return None;
            }
            (
                Verdict::Bounded(_) | Verdict::Failing(_),
                Class::PutIdentity {
                    generation,
                    recovery_from,
                },
            ) if self.starts_recovery(generation, recovery_from) => return None,
            (Verdict::Bounded(_), Class::Upload)
                if self.activation == AccountActivation::Ordinary =>
            {
                return None;
            }
            (Verdict::Bounded(_) | Verdict::Failing(_), Class::Erase) => return None,
            (Verdict::Lost(_), Class::Erase) => return None,
            (Verdict::Bounded(notice) | Verdict::Failing(notice) | Verdict::Lost(notice), _) => {
                notice_answer(&notice)
            }
        })
    }

    /// Step 2 of Switch wire 7.3: the answer Table 2 gives in place of whatever the later
    /// steps would, a `401` or a `403` before authentication included; `None` where the
    /// request goes on. Deletes an erasure's leftover mark, and answers the erasure at a lost
    /// identity, which no later step reaches.
    pub(super) fn step_two(&mut self, request: &Request) -> Option<Response> {
        if let Some(answer) = self.pending_erasure(request) {
            return Some(answer);
        }
        let class = class_of(request);
        let verdict = self.judge();
        let unknown = matches!(verdict, Verdict::Unknown);
        if let Verdict::NotHosted { delete_mark: true } = verdict {
            self.marks.slot = MarkSlot::Missing;
        }
        let answer =
            if !self.hosts() && matches!((verdict, class), (Verdict::Lost(_), Class::Erase)) {
                self.erase_lost(request)
            } else {
                self.verdict_refusal(request, verdict)?
            };
        let (status, body) = answer;
        if self.not_hosted_unpinned {
            let other = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
            return Some(self.respond_signed(&other, request, status, &body, self.now(), None));
        }
        // Signed with the one key, with no head: the notice and the not-hosted `404` at the
        // time base; the `503`, which commits nothing, at the last time stamped where the
        // switch holds the account, else the time base (Switch wire 7.1 Timestamp).
        let at = if unknown && self.enrolled.is_some() {
            self.stamped_ms
        } else {
            self.now()
        };
        Some(self.respond_signed(&self.service, request, status, &body, at, None))
    }

    /// A staged import bars erasure while its abort can go through (Switch wire 7.3,
    /// Table 2). At a failing or bounded account only a mark above the generation imported
    /// by `continue_into` rules the abort out; a lost mark always allows it.
    pub(super) fn import_bars_erasure(&self) -> bool {
        if !self.staged || !self.holds_import {
            return false;
        }
        match self.judge() {
            Verdict::Bounded(_) | Verdict::Failing(_) => self.marks.mark().is_none_or(|mark| {
                self.continued_from
                    .is_some_and(|generation| mark.generation <= generation)
            }),
            _ => true,
        }
    }

    /// `POST /erase` at a lost identity (Switch wire 7.4.16, 7.3 Tables 2 and 3): it goes
    /// through whatever `identity_hash` it names when it names the mark's creation time
    /// ([`Inner::erasure_binding`]); the record is written, then the mark deleted.
    fn erase_lost(&mut self, request: &Request) -> Answer {
        if let Some(refusal) = self.erasure_timestamp_refusal(request) {
            return refusal;
        }
        let created = match self.erasure_binding(request) {
            Ok(created) => created,
            Err(refusal) => return refusal,
        };
        self.marks.erasure_at_ms = Some(self.now().max(created));
        self.marks.slot = MarkSlot::Missing;
        (200, json!({ "erased": true }))
    }

    /// An erasure's `401 stale_timestamp`: a `Switch-Timestamp` more than 5 minutes from the
    /// switch's time (Switch wire 7.4.16, 7.1).
    pub(super) fn erasure_timestamp_refusal(&self, request: &Request) -> Option<Answer> {
        let now = self.now();
        let at = request
            .header(header::TIMESTAMP)
            .and_then(|text| pubky_switch_core::time::parse_rfc3339(text).ok())?;
        (at.abs_diff(now) > pubky_switch_core::records::CLOCK_TOLERANCE_MS).then(|| {
            bad(
                ErrorCode::StaleTimestamp,
                "Switch wire 7.1: too far from the service's time",
                json!({ "server_time": rfc3339(now) }),
            )
        })
    }

    /// The account's creation time (Switch wire 3.7, 7.3): the one in its mark, or the
    /// later physical lifetime when both SQL and the mark survive (account binding 1.1).
    pub(super) fn creation_time(&self) -> u64 {
        self.marks.mark().map_or(self.created_at_ms, |mark| {
            if self.hosts() {
                mark.created_at_ms.max(self.created_at_ms)
            } else {
                mark.created_at_ms
            }
        })
    }

    /// What binds an erasure to the account it erases (Switch wire 7.4.16), in one place, as
    /// the service checks it: its body `{ "created", "identity_hash" }` names the account's
    /// creation time ([`Inner::creation_time`]), then the hash of the newest `identity.json`
    /// the account holds, left out only where it holds none; at a lost identity no document
    /// is held to compare, and the mark's creation time binds it. The creation time it names.
    ///
    /// `400` for a body of another shape; `409 conflict` for another creation time or none,
    /// another document, a hash where none is held or none where one is: each carries
    /// `current.created`, and, at an account that answers the notice, the copy it holds, at a
    /// lost identity `identity: null`.
    pub(super) fn erasure_binding(&self, request: &Request) -> Result<u64, Answer> {
        let named = pubky_switch_core::http::parse_erase_body(&request.body)
            .map_err(|error| bad(ErrorCode::BadRequest, &error.to_string(), json!(null)))?;
        let binding = self.account_binding()?;
        let created = binding.created().ok_or_else(not_hosted)?;
        let lost = binding.association() != AccountAssociation::Account;
        let conflict = |why: &str| {
            let mut current = json!({ "created": rfc3339(created) });
            if lost {
                current["identity"] = serde_json::Value::Null;
            } else if self.notice().is_some() {
                current["identity"] = json!(self.doc.as_ref().map(|doc| doc.signed().clone()));
            }
            bad(ErrorCode::Conflict, why, current)
        };
        if named.created != Some(created) {
            return Err(conflict("7.4.16: the account was created at another time"));
        }
        if lost {
            return Ok(created);
        }
        let held = self
            .doc
            .as_ref()
            .map(pubky_switch_core::records::IdentityDoc::hash);
        if named.identity_hash != held {
            return Err(conflict("7.4.16: the account holds another identity.json"));
        }
        Ok(created)
    }

    /// An enrollment that creates an account (Switch wire 7.3, Table 3): at an identity
    /// without a mark, (0, 0) with the current key and the creation time, before the account;
    /// at a (0, 0) mark left with no account, or a lost account's mark, the new account
    /// takes it over with the current key and its own creation time, its generation, `seq`,
    /// chain hash and retirements staying, its count and tag the new account's, 0 and the
    /// zero tag; a mark that records no head becomes (0, 0).
    pub(super) fn mark_new_account(&mut self, created: u64) {
        let key = self.service.verifying_key().to_bytes();
        self.created_at_ms = created;
        self.marks.slot = MarkSlot::At(match self.marks.slot {
            MarkSlot::At(mark) if !mark.records_head() => Mark::zero(key, created),
            MarkSlot::At(mark) => Mark {
                key,
                created_at_ms: created,
                state_version: 0,
                state_tag: 0,
                ..mark
            },
            MarkSlot::Missing | MarkSlot::Corrupt => Mark::zero(key, created),
        });
    }

    /// Move the mark to the account's state, count and tag after a request (Switch wire
    /// 7.3, "Moving it", Table 3): only while the account is healthy, so never while it is
    /// behind or a fork; before its first chain item only once the count has moved; and
    /// only forward: a later generation, or the mark's with neither the head's `seq` nor the
    /// count lower and one higher.
    pub(super) fn settle_mark(&mut self) {
        if self.judge() != Verdict::Healthy || (self.tip.seq == 0 && self.state_version == 0) {
            return;
        }
        let (tip, state_version, state_tag) = (self.tip, self.state_version, self.state_tag);
        let key = self.service.verifying_key().to_bytes();
        if let MarkSlot::At(mark) = &mut self.marks.slot
            && (tip.generation > mark.generation
                || (tip.generation == mark.generation
                    && tip.seq >= mark.seq
                    && state_version >= mark.state_version
                    && (tip.seq, state_version) != (mark.seq, mark.state_version)))
        {
            mark.generation = tip.generation;
            mark.seq = tip.seq;
            mark.chain_hash = tip.chain_hash;
            mark.state_version = state_version;
            mark.state_tag = state_tag;
            mark.key = key;
        }
    }

    /// A delivery that started a generation moves the mark to its first head, and where the
    /// mark is lost writes it there anew with the account's creation time (Switch wire 7.3,
    /// Table 3).
    pub(super) fn mark_generation_start(&mut self) {
        let created = self.created_at_ms;
        self.marks.slot = MarkSlot::At(Mark {
            generation: self.tip.generation,
            seq: self.tip.seq,
            chain_hash: self.tip.chain_hash,
            state_version: self.state_version,
            state_tag: self.state_tag,
            key: self.service.verifying_key().to_bytes(),
            created_at_ms: created,
        });
    }

    /// A mark at the account's state, for a switch made at it: (0, 0) before its first
    /// item.
    pub(super) fn mark_at_state(&mut self) {
        self.created_at_ms = self.now();
        let key = self.service.verifying_key().to_bytes();
        self.marks.slot = MarkSlot::At(if self.seq == 0 {
            Mark::zero(key, self.created_at_ms)
        } else {
            Mark {
                generation: self.tip.generation,
                seq: self.tip.seq,
                chain_hash: self.tip.chain_hash,
                state_version: self.state_version,
                state_tag: self.state_tag,
                key,
                created_at_ms: self.created_at_ms,
            }
        });
    }
}

/// The `404 not_found` of an identity the switch doesn't host (Switch wire 7.3 step 2).
pub(super) fn not_hosted() -> Answer {
    bad(
        ErrorCode::NotFound,
        "Switch wire 7.3: no account for this identity",
        not_hosted_current(),
    )
}

/// The notice, `503 recovery_required` (Switch wire 7.6).
pub(super) fn notice_answer(notice: &RecoveryNotice) -> Answer {
    bad(
        ErrorCode::RecoveryRequired,
        "Switch wire 7.3: the account awaits a recovery",
        notice.to_current(),
    )
}

impl ScriptedSwitch {
    /// The account's mark, as (generation, `seq`, chain hash), `None` where it is missing
    /// or doesn't read as a mark.
    pub fn mark(&self) -> Option<(u64, u64, [u8; 32])> {
        match self.lock().marks.slot {
            MarkSlot::At(mark) => Some((mark.generation, mark.seq, mark.chain_hash)),
            MarkSlot::Missing | MarkSlot::Corrupt => None,
        }
    }

    /// The count the mark covers (Switch wire 7.3, "The mark"), `None` where it is missing or
    /// doesn't read as a mark.
    pub fn mark_state_version(&self) -> Option<u64> {
        match self.lock().marks.slot {
            MarkSlot::At(mark) => Some(mark.state_version),
            MarkSlot::Missing | MarkSlot::Corrupt => None,
        }
    }

    /// The account's count of changed state (Switch wire 7.3, "The state").
    pub fn state_version(&self) -> u64 {
        self.lock().state_version
    }

    /// The account's creation time, as its enrollment answer names it (Switch wire 3.7): the
    /// one in its mark, or the account's own where the mark is lost.
    pub fn created(&self) -> u64 {
        self.lock().creation_time()
    }

    /// Restore only the SQL account's creation field, leaving the separately retained
    /// mark unchanged (Switch account binding 1.1).
    pub fn restore_account_creation(&self, created_at_ms: u64) {
        self.lock().created_at_ms = created_at_ms;
    }

    /// The physical account's creation, independently of its retained mark.
    pub fn stored_creation(&self) -> Option<u64> {
        let inner = self.lock();
        inner.hosts().then_some(inner.created_at_ms)
    }

    /// The time of the erasure's record for the identity, if there is one.
    pub fn erasure_record(&self) -> Option<u64> {
        self.lock().marks.erasure_at_ms
    }

    /// A restore of the account's state to `seq` of its generation, as it was when `seq` was
    /// given out, its count with it, the mark staying where it is: below the mark's head or
    /// count, the account fails stop, `behind` (Switch wire 7.3, Table 3 "A restore of the
    /// state"). The `identity.json` the account holds goes back with it: a
    /// delivery past `seq` is undone, and the newest one at or below it is held again.
    pub fn restore_to(&self, seq: u64) {
        let mut inner = self.lock();
        let is_delivery = |item: &super::Item| {
            matches!(
                item,
                super::Item::Chain {
                    item_type: pubky_switch_core::chain::ItemType::Identity,
                    ..
                }
            )
        };
        if inner
            .items
            .iter()
            .any(|item| item.seq() > seq && is_delivery(item))
        {
            let identity = inner.identity.public();
            inner.doc = inner
                .items
                .iter()
                .rev()
                .filter(|item| item.seq() <= seq && is_delivery(item))
                .find_map(|item| match item {
                    super::Item::Chain { item, .. } => {
                        pubky_switch_core::records::IdentityDoc::verify(item, &identity).ok()
                    }
                    _ => None,
                });
        }
        inner.items.retain(|item| item.seq() <= seq);
        if let Some(tip) = inner.tips.iter().rev().find(|tip| tip.seq <= seq).copied() {
            inner.tip = tip;
        }
        inner.tips.retain(|tip| tip.seq <= seq);
        inner.seq = seq;
        // The count goes back to what it was as `seq` was given out: every change after it
        // is lost with the restore.
        // Before any `seq` the switch gave out, as it was made: count 0, the zero tag.
        match inner.versions.iter().rposition(|(given, ..)| *given <= seq) {
            Some(at) => {
                (_, inner.state_version, inner.state_tag) = inner.versions[at];
                inner.versions.truncate(at + 1);
            }
            None => {
                (inner.state_version, inner.state_tag) = (0, 0);
                inner.versions.clear();
            }
        }
        let (version, tag) = (inner.state_version, inner.state_tag);
        inner.state_history.retain(|count, _| *count <= version);
        if version > 0 {
            inner.state_history.insert(version, tag);
        }
    }

    /// The mark records another chain hash at the state's pair, as after a restore that took
    /// other writes up to the mark's `seq`: the account fails stop, `fork`.
    pub fn fork_mark(&self) {
        let mut inner = self.lock();
        let (tip, state_version, state_tag) = (inner.tip, inner.state_version, inner.state_tag);
        if let MarkSlot::At(mark) = &mut inner.marks.slot {
            mark.generation = tip.generation;
            mark.seq = tip.seq;
            mark.chain_hash = tip.chain_hash;
            mark.chain_hash[0] ^= 0xff;
            mark.state_version = state_version;
            mark.state_tag = state_tag;
        }
    }

    /// The mark is lost: missing from a store that reads (`mark_lost`).
    pub fn lose_mark(&self) {
        self.lock().marks.slot = MarkSlot::Missing;
    }

    /// The mark doesn't read as a mark (`mark_lost`).
    pub fn corrupt_mark(&self) {
        self.lock().marks.slot = MarkSlot::Corrupt;
    }

    /// The mark store can't be read (`true`) or reads again: every answer is `503
    /// unavailable` meanwhile, and no mark is created, moved or deleted.
    pub fn set_mark_store_unreadable(&self, unreadable: bool) {
        self.lock().marks.unreadable = unreadable;
    }

    /// The account is lost, its mark staying: a restore to before the enrollment, or a lost
    /// database. Every call then gets the notice, `behind` at the mark's generation, but the
    /// enrollment, which makes a staged account that takes the mark over, and the erasure.
    pub fn lose_account(&self) {
        self.lock().drop_account();
    }

    /// The operator retires `generation` for the identity (Switch spec 6.5): one-way.
    pub fn retire(&self, generation: u64) {
        self.lock().marks.retired.insert(generation);
    }
}
