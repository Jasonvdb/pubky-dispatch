//! The signer's calls at the scripted switch: enrollment (Switch wire 3.7, 7.4.1), the
//! `identity.json` delivery (Switch wire 3.3, 7.4.2) and the app list (Switch wire 7.4.12).
//! The delivery is judged by the core's `check_delivery`, the rule the service applies.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use pubky_switch_core::chain::{ItemType, ProofState, ServiceTransition, item_hash};
use pubky_switch_core::claims::Outcome;
use pubky_switch_core::enc::{b64, zbase32_encode};
use pubky_switch_core::http::{ErrorCode, IdentityDelivery};
use pubky_switch_core::json::parse_json;
use pubky_switch_core::records::{
    AccountView, Delivery, DeliveryRefusal, Enrollment, EnrollmentAnswer, GenerationChange,
    IdentityDoc, KeptProofs, Limits, check_delivery, needed_generations,
};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Value, json};

use super::{Answer, Inner, SWITCH_ORIGIN, ScriptedSwitch, bad};
use crate::clock::TestClock;
use crate::testing::ScriptError;

/// A generation and the service key that verifies its proofs (Switch wire 3.3).
type GenerationKey = (u64, [u8; 32]);

/// What an enrolled account holds of its enrollments (Switch wire 3.7).
#[derive(Clone, Debug, Default)]
pub(crate) struct Enrolled {
    /// The limits the answers announce.
    pub(crate) limits: Limits,
    /// The answer to each enrollment taken, by enrollment hash, so the same enrollment again
    /// gets the same answer.
    pub(crate) answers: HashMap<[u8; 32], Value>,
}

impl ScriptedSwitch {
    /// A switch at [`SWITCH_ORIGIN`] where `identity` has no account yet: every call is the
    /// `404` of an identity it doesn't host until the signer enrolls (Switch wire 3.7, 7.3
    /// step 2, 7.4.1). The enrollment makes the account, staged; the switch's one key is the
    /// one from `service_secret`.
    pub fn unenrolled(
        identity: &pubky_switch_core::keys::IdentityKey,
        service_secret: [u8; 32],
        clock: Arc<TestClock>,
    ) -> Arc<Self> {
        Self::unenrolled_at(identity, service_secret, clock, SWITCH_ORIGIN)
    }

    /// [`ScriptedSwitch::unenrolled`], at `origin`: the origin an enrollment must name, so
    /// two signers can enroll at two scripted switches of different origins.
    pub fn unenrolled_at(
        identity: &pubky_switch_core::keys::IdentityKey,
        service_secret: [u8; 32],
        clock: Arc<TestClock>,
        origin: &str,
    ) -> Arc<Self> {
        let switch = Self::new(identity, service_secret, clock);
        {
            let mut inner = switch.lock();
            inner.enrolled = None;
            inner.staged = true;
            inner.origin = origin.to_owned();
            // No account, and no mark yet (Switch wire 7.3).
            inner.marks = super::marks::MarkStore::default();
        }
        switch
    }

    /// The epoch ranges of the key bundle parts the switch holds for `app`, in order.
    pub fn bundles_of(&self, app: &[u8; 16]) -> Vec<(u64, u64)> {
        self.lock()
            .bundles
            .get(app)
            .map(|parts| {
                parts
                    .iter()
                    .map(|(part, _)| (part.first_epoch, part.last_epoch))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The hand-over the switch holds, its target and its `PUT` body, as a test keeps it to
    /// store again ([`ScriptedSwitch::store_handover_again`]).
    pub fn stored_handover_body(&self) -> Option<([u8; 16], Value)> {
        self.lock().handover.clone()
    }

    /// A switch that stores, or serves again, a hand-over it dropped: as a lost answer's
    /// resend would, or a faulty switch (Switch wire 7.4.17).
    pub fn store_handover_again(&self, held: ([u8; 16], Value)) {
        self.lock().handover = Some(held);
    }

    /// The target of the hand-over the switch holds, if any (Switch wire 7.4.17).
    pub fn stored_handover(&self) -> Option<[u8; 16]> {
        self.lock().stored_handover()
    }

    /// Forget the transition proof of the newest delivery, so a retry of it answers with no
    /// proof, as for a version the service took by enrollment or import (Switch wire 7.4.2).
    pub fn forget_delivery_proof(&self) {
        self.lock().delivery_proof = None;
    }

    /// A faulty service: it no longer holds `app`'s key bundle parts, which `bundle_ranges`
    /// then stops showing (Switch wire 7.4.12).
    pub fn forget_bundle_parts(&self, app: &[u8; 16]) {
        self.lock().bundles.remove(app);
    }

    /// The key bundle parts the switch holds for `app`, in order.
    pub fn bundle_parts_of(&self, app: &[u8; 16]) -> Vec<pubky_switch_core::ops::KeyBundlePut> {
        self.lock()
            .bundles
            .get(app)
            .map(|parts| parts.iter().map(|(part, _)| part.clone()).collect())
            .unwrap_or_default()
    }

    /// Announce `limits` at the enrollment that makes the account, in place of the defaults.
    pub fn set_enroll_limits(&self, limits: Limits) {
        self.lock().enroll_limits = limits;
    }

    /// Whether the account is erased (Switch wire 7.4.16): no account, and the erasure's
    /// record.
    pub fn erased(&self) -> bool {
        let inner = self.lock();
        !inner.hosts() && inner.marks.erasure_at_ms.is_some()
    }

    /// The App IDs the account keeps for good from the enrollment that made it.
    pub fn kept_app_ids(&self) -> Vec<[u8; 16]> {
        self.lock().kept_app_ids.clone()
    }
}

impl Inner {
    /// `POST /v1/enroll` (Switch wire 3.7, 7.4.1).
    pub(super) fn enroll(
        &mut self,
        request: &crate::transport::Request,
    ) -> Result<Answer, ScriptError> {
        let identity = self.identity.public();
        let body: Value = match parse_json(&request.body) {
            Ok(value) => value,
            Err(_) => return Ok(bad(ErrorCode::BadRequest, "malformed body", json!(null))),
        };
        let Some(signed) = body
            .get("enrollment")
            .and_then(|e| serde_json::from_value::<SignedDoc>(e.clone()).ok())
        else {
            return Ok(bad(ErrorCode::BadRequest, "no enrollment", json!(null)));
        };
        let enrollment = match Enrollment::verify(&signed, &identity, &self.origin) {
            Ok(enrollment) => enrollment,
            Err(_) => return Ok(bad(ErrorCode::BadRequest, "bad enrollment", json!(null))),
        };
        // The same enrollment again gets its kept answer, with no other effect (Switch wire
        // 3.7, 7.4.1).
        if let Some(answer) = self
            .enrolled
            .as_ref()
            .and_then(|e| e.answers.get(&enrollment.hash()))
            .cloned()
        {
            return Ok((200, answer));
        }
        // A switch a test made answer as for an identity it doesn't host makes a new account.
        if self.not_hosted_unpinned {
            self.drop_account();
        }
        let creating = !self.hosts();
        // An enrollment that creates the account writes its mark first (Switch wire 7.3,
        // Table 3): (0, 0), or the mark a crash or a lost account left, taken over.
        if creating {
            self.mark_new_account();
        }
        // At a serving account the App IDs it names are held for the next generation
        // (Switch wire 3.7).
        if !creating && self.doc.is_some() && !self.staged {
            for app in enrollment.revoked_apps() {
                if !self.held_app_ids.contains(app) {
                    self.held_app_ids.push(*app);
                }
            }
        }
        let limits = self.enroll_limits;
        // The one key it names, at every account (Switch wire 7.4.1).
        let service_key = self.service.verifying_key().to_bytes();
        // The account's creation time, fixed for the account (Switch wire 3.7).
        let created = self.creation_time();
        let enrolled = self.enrolled.get_or_insert_with(|| Enrolled {
            limits,
            answers: HashMap::new(),
        });
        let answer = EnrollmentAnswer::new(&enrollment, service_key, enrolled.limits, created);
        let value: Value = serde_json::from_slice(&answer.to_json()?)?;
        enrolled.answers.insert(enrollment.hash(), value.clone());
        // The enrollment that makes the account names the App IDs it keeps for good; another
        // enrollment for an existing account changes nothing (Switch wire 3.7).
        if creating {
            let kept: BTreeSet<[u8; 16]> = enrollment.revoked_apps().iter().copied().collect();
            self.kept_app_ids = kept.into_iter().collect();
            self.kept_at = self.now();
        }
        Ok((200, value))
    }

    /// The account is gone, its mark store staying: after an erasure, or for a lost account
    /// (Switch wire 7.3, 7.4.16). Nothing of what it held stays, its enrollments, its kept
    /// App IDs and its counts included; the service key is the switch's, not the account's,
    /// and what a test set of the switch's configuration stays set. An enrollment then makes
    /// a new, staged account, whose first `identity.json` is the next generation's, as at a
    /// service that never hosted the identity.
    pub(super) fn drop_account(&mut self) {
        // A read still held is answered for an account the switch doesn't host.
        self.wake_held();
        let tip = pubky_switch_core::chain::ChainTip {
            generation: 1,
            seq: 0,
            chain_hash: pubky_switch_core::chain::ZERO_HASH,
        };
        let mut fresh = Inner::fresh(
            super::clone_key(&self.identity),
            self.service.clone(),
            Arc::clone(&self.clock),
            tip,
        );
        // Nothing enrolled at it yet, and it serves only once it takes its first document.
        fresh.enrolled = None;
        fresh.staged = true;
        fresh.marks = std::mem::take(&mut self.marks);
        fresh.stamped_ms = self.stamped_ms;
        fresh.origin = self.origin.clone();
        fresh.enroll_limits = self.enroll_limits;
        fresh.uploads_per_app_per_hour = self.uploads_per_app_per_hour;
        fresh.max_contacts = self.max_contacts;
        fresh.max_deny = self.max_deny;
        fresh.feed_limit = self.feed_limit;
        fresh.max_page_bytes = self.max_page_bytes;
        fresh.max_page_scan = self.max_page_scan;
        fresh.keep_passed = self.keep_passed;
        fresh.open_admission = self.open_admission;
        fresh.faults = std::mem::take(&mut self.faults);
        // A read held before drops its number when it ends.
        fresh.held_ids = self.held_ids;
        *self = fresh;
    }

    /// Start the account afresh at `generation`, as a recovery in place does, and the start
    /// a failing or bounded account takes: its creation time, its mark store, its service
    /// time, its enrollments and the App IDs to refuse stay, those held for this generation
    /// among them, and everything else goes (Switch spec 12.6 step 1, wire 3.3, 3.7).
    fn start_afresh(&mut self, generation: u64) {
        // The held reads look again, and find the generation changed (Switch wire 7.4.4);
        // their numbers go on, so none is taken for another's.
        self.wake_held();
        let tip = pubky_switch_core::chain::ChainTip {
            generation,
            seq: 0,
            chain_hash: pubky_switch_core::chain::ZERO_HASH,
        };
        let mut fresh = Inner::fresh(
            super::clone_key(&self.identity),
            self.service.clone(),
            Arc::clone(&self.clock),
            tip,
        );
        fresh.stamped_ms = self.stamped_ms;
        fresh.origin = self.origin.clone();
        fresh.marks = std::mem::take(&mut self.marks);
        fresh.created_at_ms = self.created_at_ms;
        fresh.enrolled = self.enrolled.take();
        fresh.enroll_limits = self.enroll_limits;
        // The upload limits are the service's configuration, and its upload counts are kept
        // by account and app, which a recovery in place doesn't forget (Switch wire 9.4).
        fresh.uploads_per_app_per_hour = self.uploads_per_app_per_hour;
        fresh.max_contacts = self.max_contacts;
        fresh.max_deny = self.max_deny;
        fresh.upload_counts = std::mem::take(&mut self.upload_counts);
        // The directory's versions are the account's, not the generation's: they go on
        // counting, as at the service, so a sender's copy from before the loss never
        // carries a version the new generation gives another set of apps (Switch wire
        // 7.4.3 step 5, 7.4.10).
        fresh.apps_version = self.apps_version;
        fresh.directory_version = self.directory_version;
        // What a test set of the switch's configuration stays set, as a service's does.
        fresh.feed_limit = self.feed_limit;
        fresh.max_page_bytes = self.max_page_bytes;
        fresh.max_page_scan = self.max_page_scan;
        fresh.keep_passed = self.keep_passed;
        fresh.open_admission = self.open_admission;
        fresh.faults = std::mem::take(&mut self.faults);
        // A read held before the recovery drops its number when it ends; numbering anew would
        // let it drop a later read's waker under the same number.
        fresh.held_ids = self.held_ids;
        fresh.kept_at = self.kept_at;
        fresh.kept_app_ids = std::mem::take(&mut self.kept_app_ids);
        for (id, app) in &self.apps {
            if app.departed && !fresh.kept_app_ids.contains(id) {
                fresh.kept_app_ids.push(*id);
            }
        }
        for id in std::mem::take(&mut self.held_app_ids) {
            if !fresh.kept_app_ids.contains(&id) {
                fresh.kept_app_ids.push(id);
            }
        }
        *self = fresh;
    }

    /// Chain a delivered `identity.json` and hold it; returns the delivery's transition
    /// proof. A document naming this switch's origin and service key makes a staged switch
    /// serve, and
    /// one at a later generation moves the chain on to it (Switch wire 6.5 "Import").
    pub(super) fn chain_identity(&mut self, doc: &IdentityDoc) -> Result<SignedDoc, ScriptError> {
        if doc.generation() > self.tip.generation {
            self.tip.generation = doc.generation();
        }
        // The staged gate: the document names this service, its origin and its key
        // (Switch wire 3.7, 7.3 step 7).
        if doc.inbox().url == self.origin
            && doc.inbox().service_key == self.service.verifying_key().to_bytes()
        {
            self.staged = false;
        }
        let was = self.current_app_ids();
        let bytes = doc.signed().doc_bytes()?;
        let hash = item_hash(ItemType::Identity, &bytes);
        let state = ProofState::Identity {
            version: doc.version(),
            generation: doc.generation(),
            data_epoch: doc.data_epoch(),
        };
        let proof = self.chain_item(
            ItemType::Identity,
            doc.signed().clone(),
            hash,
            None,
            "identity",
            &state,
            super::Readers::Every,
        )?;
        // The first listing's epoch is kept; a later listing never dates it again (Switch
        // wire 7.4.12).
        for app in &doc.body().apps {
            self.listed_at_epoch
                .entry(app.app_id)
                .or_insert(doc.data_epoch());
        }
        // A departure's rotation is done once a version removes the app at a higher data
        // epoch than at its departure, and stays done, also after a purge (Switch wire 7.4.12).
        for (id, app) in &mut self.apps {
            if let Some((_, epoch)) = app.departed_at
                && doc.data_epoch() > epoch
                && doc.body().removed.iter().any(|r| &r.app_id == id)
            {
                app.rotated = true;
            }
        }
        self.doc = Some(doc.clone());
        // The next version, whoever delivered it, ends a stored hand-over (Switch wire 7.4.17).
        self.handover = None;
        self.delivery_proof = Some(proof.clone());
        self.directory_version += 1;
        // After its chain item: an app it no longer makes current departs at it (Switch wire
        // 7.4.4).
        self.after_departure(was);
        // The removed apps it leaves in neither list go, as at the service (Switch wire 9.1).
        self.purge_removed(None);
        Ok(proof)
    }

    /// `POST /v1/{id}/recovery/admission` from the signer (Switch wire 7.4.14): ends staged
    /// admission with the `admission` transition's proof, or answers none when it isn't
    /// staged; `404` without a recovery.
    pub(super) fn recovery_admission(&mut self, body: &[u8]) -> Result<Answer, ScriptError> {
        if !body.is_empty() {
            return Ok(bad(ErrorCode::BadRequest, "the body is empty", json!(null)));
        }
        if self.recovery_from.is_none() {
            return Ok(bad(ErrorCode::NotFound, "no recovery", json!(null)));
        }
        let mut proofs = Vec::new();
        if self.admission_staged {
            self.admission_staged = false;
            let at = self.now();
            proofs.push(self.service_transition(ServiceTransition::Admission { at })?);
        }
        Ok((
            200,
            json!({ "proofs": proofs, "head": self.head().to_value() }),
        ))
    }

    /// `PUT /v1/{id}/identity` from the signer, judged by the core's rules (Switch wire 3.3,
    /// 7.4.2).
    pub(super) fn put_identity(&mut self, body: &[u8]) -> Result<Answer, ScriptError> {
        let Ok(delivery) = IdentityDelivery::parse(body) else {
            return Ok(bad(
                ErrorCode::BadRequest,
                "malformed delivery",
                json!(null),
            ));
        };
        let Ok(doc) = IdentityDoc::verify(&delivery.identity, &self.identity.public()) else {
            return Ok(bad(
                ErrorCode::BadRequest,
                "the document doesn't verify",
                json!(null),
            ));
        };
        let app_limit = self.enrolled.as_ref().map_or(0, |e| e.limits.app_limit);
        // The App IDs enrollments named, and those revoked or seen departing (Switch wire 3.3).
        let mut kept = self.kept_app_ids.clone();
        for (id, app) in &self.apps {
            if app.departed && !kept.contains(id) {
                kept.push(*id);
            }
        }
        let generation_before = self.tip.generation;
        // At a failing or bounded account step 2 let through only the start of a generation
        // above both the held document's and the mark's, with `recovery_from` (Switch wire
        // 7.3, Table 2): it starts the account afresh, so it is judged as the first document
        // of the account it starts.
        let mut started_afresh = false;
        if self.notice().is_some() {
            let mut refused = kept.clone();
            refused.extend(self.held_app_ids.iter().copied());
            let fresh = AccountView {
                held: None,
                app_limit,
                staged: false,
                origin: &self.origin,
                pending_key: None,
                kept_app_ids: &refused,
                kept_proofs: KeptProofs::default(),
            };
            if let Err(refusal) = check_delivery(&fresh, &doc, None) {
                return Ok(self.refusal(refusal));
            }
            // It names this switch: its origin and its key (Switch wire 7.4.2).
            if doc.inbox().url != self.origin
                || doc.inbox().service_key != self.service.verifying_key().to_bytes()
            {
                return Ok(bad(
                    ErrorCode::BadRequest,
                    "a recovery's first document names this service",
                    json!(null),
                ));
            }
            self.start_afresh(doc.generation());
            kept = self.kept_app_ids.clone();
            started_afresh = true;
        }
        let (records, claim_entries) = self.kept_proof_keys();
        let view = AccountView {
            held: self.doc.as_ref(),
            app_limit,
            staged: self.staged,
            origin: &self.origin,
            // The next generation in place names the key the enrollments answer: the one
            // key (Switch wire 3.3, 3.7).
            pending_key: (!self.staged).then(|| self.service.verifying_key().to_bytes()),
            kept_app_ids: &kept,
            kept_proofs: KeptProofs {
                records: &records,
                claim_entries: &claim_entries,
            },
        };
        // The start a failing or bounded account takes is exempt from the compare-and-swap
        // (Switch wire 3.3).
        let prev = delivery.prev.filter(|_| !started_afresh);
        match check_delivery(&view, &doc, prev.as_ref()) {
            Ok(Delivery::New(change)) => {
                match change {
                    // A service key change names another key than the ending generation's;
                    // this switch has one (Switch wire 3.3).
                    Some(GenerationChange::KeyRotation) => {
                        return Ok(bad(
                            ErrorCode::BadRequest,
                            "Switch wire 3.3: a key change names another key",
                            json!(null),
                        ));
                    }
                    // A provider loss in place starts the account afresh, keeping only its
                    // service time and the App IDs to refuse (Switch spec 12.6 step 1, wire
                    // 3.3); the App IDs held for this generation are refused from the start.
                    Some(GenerationChange::ProviderLoss) => {
                        if doc
                            .body()
                            .apps
                            .iter()
                            .any(|app| self.held_app_ids.contains(&app.app_id))
                        {
                            return Ok(bad(
                                ErrorCode::BadRequest,
                                "the document lists an App ID its enrollment revoked",
                                json!(null),
                            ));
                        }
                        self.start_afresh(doc.generation());
                    }
                    Some(GenerationChange::Staged) | None => {}
                }
                // A first document that starts a recovery, as at the service: the account
                // takes its generation, and its chain starts with the `recovery` transition
                // (Switch wire 3.3, 7.4.2), unless the switch was made recovering, which
                // chained it already.
                if self.doc.is_none()
                    && self.recovery_from.is_none()
                    && let Some(recovery_from) = doc.body().recovery_from
                {
                    // It names this switch: its origin and its key (Switch wire 7.4.2).
                    if doc.inbox().url != self.origin
                        || doc.inbox().service_key != self.service.verifying_key().to_bytes()
                    {
                        return Ok(bad(
                            ErrorCode::BadRequest,
                            "a recovery's first document names this service",
                            json!(null),
                        ));
                    }
                    // An app's first receive key may carry any `n` (Switch spec 3.6).
                    self.any_first_n = true;
                    self.tip.generation = doc.generation();
                    let at = self.now();
                    self.recovery_from = Some(recovery_from);
                    self.recovery_declared_at = Some(at);
                    // Staged whenever the document lists an app (Switch spec 12.6 step 2).
                    self.admission_staged = !doc.body().apps.is_empty();
                    self.service_transition(ServiceTransition::Recovery { recovery_from, at })?;
                }
                let proof = self.chain_identity(&doc)?;
                // A delivery that starts a generation moves the mark to its first head
                // (Switch wire 7.3, Table 3).
                if self.tip.generation != generation_before {
                    self.mark_generation_start();
                }
                Ok((
                    200,
                    json!({ "proofs": [proof], "head": self.head().to_value() }),
                ))
            }
            Ok(Delivery::Retry) => {
                let proofs: Vec<&SignedDoc> = self.delivery_proof.iter().collect();
                Ok((
                    200,
                    json!({ "proofs": proofs, "head": self.head().to_value() }),
                ))
            }
            Err(refusal) => Ok(self.refusal(refusal)),
        }
    }

    /// The answer to a delivery the core's rules refuse (Switch wire 7.4.2).
    fn refusal(&self, refusal: DeliveryRefusal) -> Answer {
        match refusal {
            DeliveryRefusal::BadRequest(why) => bad(ErrorCode::BadRequest, why, json!(null)),
            DeliveryRefusal::StaleIdentity(why) => {
                let current = self.doc.as_ref().map_or(json!(null), |held| {
                    json!({ "version": held.version(), "generation": held.generation(),
                            "hash": b64(&held.hash()), "identity": held.signed() })
                });
                bad(ErrorCode::StaleIdentity, why, current)
            }
            DeliveryRefusal::Conflict { proof_generations } => bad(
                ErrorCode::Conflict,
                "a needed service key is left out",
                json!({ "proof_generations": proof_generations }),
            ),
        }
    }

    /// The newest data epoch through which `app` holds every key (Switch wire 7.4.12), by
    /// the core's rule: the epoch of the first version that listed it, if kept, raised by each
    /// stored part its cursor has passed that continues it, from epoch 1 when the start is
    /// unknown; `None` when nothing shows any.
    pub(super) fn keys_through(&self, app: &[u8; 16]) -> Option<u64> {
        let start = self.listed_at_epoch.get(app).copied();
        let spans: Vec<pubky_switch_core::ops::StoredPart> = self
            .bundles
            .get(app)
            .map(|parts| {
                parts
                    .iter()
                    .map(|(p, seq)| pubky_switch_core::ops::StoredPart {
                        first_epoch: p.first_epoch,
                        last_epoch: p.last_epoch,
                        seq: *seq,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let cursor = self.apps.get(app).map_or(0, |a| a.cursor);
        pubky_switch_core::ops::keys_through(start, &spans, cursor)
    }

    /// The kept proofs' generations, each with the key that verifies its proofs: an earlier
    /// generation's an import carried, else this switch's own (Switch wire 3.3 "Service
    /// keys"); held records' first, then live claims' entries'.
    fn kept_proof_keys(&self) -> (Vec<GenerationKey>, Vec<GenerationKey>) {
        let own = self.service.verifying_key().to_bytes();
        let keyed = |generations: Vec<u64>| -> Vec<GenerationKey> {
            generations
                .into_iter()
                .map(|g| (g, self.proof_keys.get(&g).copied().unwrap_or(own)))
                .collect()
        };
        let (records, entries) = self.shared.kept_proof_generations();
        (keyed(records), keyed(entries))
    }

    /// `POST /v1/{id}/apps/{app_id}/revoke` from the signer (Switch wire 7.4.12): the
    /// `revoke` transition's proof, none for an app revoked or departed already, `404` for an
    /// app neither the switch nor `identity.json` knows.
    pub(super) fn revoke_answer(&mut self, route: &str) -> Result<Answer, ScriptError> {
        let id = route
            .strip_prefix("apps/")
            .and_then(|r| r.strip_suffix("/revoke"))
            .and_then(|id| pubky_switch_core::enc::app_id_decode(id).ok());
        let known = id.is_some_and(|id| {
            self.apps.contains_key(&id)
                || self.doc.as_ref().is_some_and(|doc| {
                    doc.listed_cert(&id).is_some()
                        || doc.body().removed.iter().any(|r| r.app_id == id)
                })
        });
        let Some(id) = id.filter(|_| known) else {
            return Ok(bad(ErrorCode::NotFound, "no such app", json!(null)));
        };
        let proofs: Vec<SignedDoc> = self.revoke(id)?.into_iter().collect();
        Ok((
            200,
            json!({ "proofs": proofs, "head": self.head().to_value() }),
        ))
    }

    /// `PUT /v1/{id}/handover` from the signer (Switch wire 7.4.17): the core's checks of a
    /// stored hand-over, for a current target, then kept, replacing any it held.
    pub(super) fn put_handover(&mut self, body: &[u8]) -> Answer {
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return bad(ErrorCode::BadRequest, "malformed hand-over", json!(null));
        };
        let known = ["app_id", "handover"];
        let unknown = value
            .as_object()
            .is_none_or(|o| o.keys().any(|k| !known.contains(&k.as_str())));
        let target = value
            .get("app_id")
            .and_then(Value::as_str)
            .and_then(|id| pubky_switch_core::enc::app_id_decode(id).ok());
        let handover = value.get("handover").and_then(read_handover);
        let (Some(target), Some(handover), false) = (target, handover, unknown) else {
            return bad(ErrorCode::BadRequest, "malformed hand-over", json!(null));
        };
        if !self.app_current(&self.apps, &target) {
            return bad(ErrorCode::Conflict, "the target isn't current", json!(null));
        }
        let Some(cert) = self.checked_cert(&target) else {
            return bad(ErrorCode::Conflict, "the target isn't current", json!(null));
        };
        let identity = self.identity.public();
        if let Err(error) = handover.check_stored(&identity, &target, &cert.bundle_key()) {
            return bad(ErrorCode::BadRequest, &error.to_string(), json!(null));
        }
        let parts = handover.envelopes().len();
        self.handover = Some((target, value));
        (
            200,
            json!({ "app_id": zbase32_encode(&target), "parts": parts }),
        )
    }

    /// `GET /v1/{id}/handover` (Switch wire 7.4.17): the stored body, for the signer
    /// (`caller` `None`) or its target app; `404` for any other caller, or when none is held.
    pub(super) fn handover_answer(&self, caller: Option<[u8; 16]>) -> Answer {
        match &self.handover {
            Some((target, body)) if caller.is_none_or(|app| app == *target) => (200, body.clone()),
            _ => bad(ErrorCode::NotFound, "no hand-over", json!(null)),
        }
    }

    /// `POST /v1/{id}/erase` from the signer (Switch wire 7.4.16): a move in progress refuses
    /// it (`409 conflict`): a frozen account that doesn't fail stop, whose export this switch
    /// doesn't track, and a staged one holding an import. Then its binding to the account
    /// ([`Inner::erasure_binding`]): the creation time, then the `identity.json` it follows.
    /// Every `409` carries `current.created`. Then the erasure's record is written, dated no
    /// earlier than the creation time it named, the account goes, and its mark with it: every
    /// later call, a retry included, gets the `404` of an identity the switch doesn't host.
    /// The answer is signed with the one key, without a head; an app's call is `403
    /// permission_missing`.
    pub(super) fn erase_answer(&mut self, request: &crate::transport::Request) -> Answer {
        if let Some(refusal) = self.erasure_timestamp_refusal(request) {
            return refusal;
        }
        let fails_stop = self.notice().is_some();
        if (self.frozen.is_some() && !fails_stop) || (self.staged && self.holds_import) {
            return bad(
                ErrorCode::Conflict,
                "a move is in progress",
                json!({ "created": pubky_switch_core::time::rfc3339(self.creation_time()) }),
            );
        }
        let created = match self.erasure_binding(request) {
            Ok(created) => created,
            Err(refusal) => return refusal,
        };
        // The record first, then the deletion, then the mark (Switch wire 7.3, Table 3); all
        // at once here.
        self.marks.erasure_at_ms = Some(self.now().max(created));
        self.drop_account();
        self.marks.slot = super::marks::MarkSlot::Missing;
        (200, json!({ "erased": true }))
    }

    /// The stored hand-over, as the test reads it.
    pub(super) fn stored_handover(&self) -> Option<[u8; 16]> {
        self.handover.as_ref().map(|(target, _)| *target)
    }

    /// `GET /v1/{id}/apps` (Switch wire 7.4.12): every app the switch holds or the newest
    /// `identity.json` lists, the recovery in progress, the newest document, and the
    /// generations the kept proofs name but those the newest document declares lost, the
    /// member left out when there are none. It lists the App IDs an enrollment named too,
    /// revoked from the enrollment's time.
    pub(super) fn apps_answer(&self) -> Answer {
        let mut ids: BTreeSet<[u8; 16]> = self.apps.keys().copied().collect();
        ids.extend(self.kept_app_ids.iter().copied());
        if let Some(doc) = &self.doc {
            ids.extend(doc.body().apps.iter().map(|a| a.app_id));
        }
        let apps: Vec<Value> = ids
            .iter()
            .map(|id| {
                let held = self.apps.get(id);
                let enrolled_kept = self.kept_app_ids.contains(id);
                let kept = enrolled_kept || held.is_some_and(|a| a.departed);
                let listed = self
                    .doc
                    .as_ref()
                    .is_some_and(|d| d.listed_cert(id).is_some());
                let ranges: Vec<Value> = self
                    .bundles
                    .get(id)
                    .map(|parts| {
                        parts
                            .iter()
                            .map(|(part, _)| json!([part.first_epoch, part.last_epoch]))
                            .collect()
                    })
                    .unwrap_or_default();
                json!({
                    "app_id": zbase32_encode(id),
                    // Spec 3.4's sense once the app has a record: listed with its certificate,
                    // or renewed and open, not revoked or departed. Expiry isn't part of it:
                    // `cert_expires_at` carries that (Switch wire 7.4.12).
                    "current": if held.is_some_and(|a| a.cert.is_some()) {
                        !enrolled_kept && self.app_current_by(&self.apps, id, false)
                    } else {
                        listed && !kept
                    },
                    "last_seen": held.and_then(|a| a.last_seen).map(pubky_switch_core::time::rfc3339),
                    "revoked_at": held
                        .and_then(|a| a.revoked_at)
                        .or(enrolled_kept.then_some(self.kept_at))
                        .map(pubky_switch_core::time::rfc3339),
                    "departed_at": held
                        .and_then(|a| a.departed_at)
                        .map(|(at, _)| pubky_switch_core::time::rfc3339(at)),
                    "awaiting_rotation": held.is_some_and(|a| a.departed_at.is_some() && !a.rotated),
                    "open_attempts": self.open_attempts(id),
                    "unread_entries": self.unread_counts(id).0,
                    "sole_target_unread": self.unread_counts(id).1,
                    "record_cert": held.and_then(|a| a.cert.as_ref()).map(|c| b64(&c.hash())),
                    "record_at": held.and_then(|a| a.record_at).map(pubky_switch_core::time::rfc3339),
                    "lagging": held.is_some_and(|a| a.lagging),
                    "keys_through": self.keys_through(id),
                    "full_bundle_requested": held
                        .and_then(|a| a.full_requested)
                        .map(pubky_switch_core::time::rfc3339),
                    "bundle_ranges": ranges,
                    "cert_expires_at": self
                        .checked_cert(id)
                        .map(|cert| pubky_switch_core::time::rfc3339(cert.expires_at())),
                })
            })
            .collect();
        let recovery = self.recovery_from.map(|from| {
            let declared_at = self.recovery_declared_at.unwrap_or_default();
            json!({ "recovery_from": from,
                    "declared_at": pubky_switch_core::time::rfc3339(declared_at),
                    "admission_staged": self.admission_staged })
        });
        let (records, entries) = self.shared.kept_proof_generations();
        let recovery_from = self.doc.as_ref().and_then(|d| d.body().recovery_from);
        let proof_generations = needed_generations(&records, &entries, recovery_from);
        let identity = self
            .doc
            .as_ref()
            .and_then(|doc| serde_json::to_value(doc.signed()).ok())
            .unwrap_or(Value::Null);
        let mut answer = json!({ "apps": apps, "identity": identity, "recovery": recovery });
        // Left out when no kept proof names a generation (Switch wire 7.4.12).
        if !proof_generations.is_empty() {
            answer["proof_generations"] = json!(proof_generations);
        }
        (200, answer)
    }

    /// The attempts `app` owns that are open or `unknown`, as `GET /apps` lists them (Switch
    /// wire 7.4.12).
    fn open_attempts(&self, app: &[u8; 16]) -> Vec<Value> {
        self.shared
            .claims
            .iter()
            .flat_map(|(claim_key, claim)| {
                claim
                    .attempts
                    .iter()
                    .filter(|attempt| &attempt.owner == app)
                    .filter(|attempt| matches!(attempt.outcome, Outcome::Open | Outcome::Unknown))
                    .map(move |attempt| {
                        json!({ "claim_key": b64(claim_key),
                                "attempt_id": b64(&attempt.attempt_id),
                                "outcome": attempt.outcome.as_str() })
                    })
            })
            .collect()
    }
}

/// A hand-over's `{ "envelopes": [b64], "sig": b64 }`, as the switch reads it without
/// opening anything (Switch wire 3.12).
fn read_handover(value: &Value) -> Option<pubky_switch_core::records::SignerHandover> {
    // Unknown members are `400`, as at the service (Switch wire 7.4.17, 1.1).
    pubky_switch_core::json::reject_unknown_members(value, &["envelopes", "sig"], "the hand-over")
        .ok()?;
    let envelopes = value
        .get("envelopes")?
        .as_array()?
        .iter()
        .map(|e| {
            e.as_str()
                .and_then(|s| pubky_switch_core::enc::unb64(s).ok())
        })
        .collect::<Option<Vec<Vec<u8>>>>()?;
    let sig = pubky_switch_core::enc::unb64_array::<64>(value.get("sig")?.as_str()?).ok()?;
    Some(pubky_switch_core::records::SignerHandover::from_parts(
        envelopes, sig,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scripted switch's answer to an enrollment of `identity`'s with `nonce`.
    fn enroll_at(
        switch: &ScriptedSwitch,
        identity: &pubky_switch_core::keys::IdentityKey,
        nonce: u8,
        revoked: Option<Vec<[u8; 16]>>,
    ) -> (u16, Value) {
        let body = pubky_switch_core::records::EnrollmentBody {
            identity: identity.public(),
            origin: SWITCH_ORIGIN.to_owned(),
            nonce: [nonce; 16],
            policy: pubky_switch_core::records::IdentityPolicy::default(),
            identity_doc: None,
            revoked_apps: revoked,
        };
        let enrollment = Enrollment::sign(identity, body).unwrap();
        let request = crate::transport::Request {
            method: "POST".into(),
            origin: SWITCH_ORIGIN.into(),
            path_and_query: "/v1/enroll".into(),
            headers: Vec::new(),
            body: json!({ "enrollment": enrollment.signed() })
                .to_string()
                .into_bytes(),
            timeout: crate::transport::TimeoutClass::default(),
        };
        switch.lock().enroll(&request).unwrap()
    }

    #[test]
    fn test_scripted_open_attempt_refuses_a_second_open_one() {
        // As the service refuses the entry: a claim takes one open attempt at a time, and a
        // new one once that one has failed (Switch wire 6.8).
        let identity = pubky_switch_core::keys::IdentityKey::from_secret([1; 32]);
        let switch = ScriptedSwitch::new(
            &identity,
            [2; 32],
            Arc::new(crate::clock::TestClock::new(0)),
        );
        switch.open_attempt([1; 32], [1; 16], [3; 16]).unwrap();
        assert!(switch.open_attempt([1; 32], [2; 16], [3; 16]).is_err());
        switch.fail_attempt([1; 32], [1; 16], [3; 16]);
        switch.open_attempt([1; 32], [2; 16], [3; 16]).unwrap();
    }

    #[test]
    fn test_scripted_enrollment_after_an_erasure_makes_a_new_account() {
        // As at the service, where the erased account doesn't exist any more (Switch wire
        // 7.4.16, Switch spec 12.7 step 4): the same one key, a new (0, 0) mark, and nothing
        // of what the erased account kept.
        use pubky_switch_core::records::{IdentityBody, IdentityPolicy, Inbox};
        let identity = pubky_switch_core::keys::IdentityKey::from_secret([1; 32]);
        let clock = Arc::new(crate::clock::TestClock::new(1_700_000_000_000));
        let switch = ScriptedSwitch::unenrolled_at(&identity, [2; 32], clock, SWITCH_ORIGIN);
        let (status, first) = enroll_at(&switch, &identity, 1, Some(vec![[7; 16]]));
        assert_eq!(status, 200);
        assert_eq!(switch.kept_app_ids(), vec![[7; 16]]);
        {
            // What a serving account holds: its document, an app, a contact, a pending
            // connect request, and versions that have moved.
            let mut inner = switch.lock();
            let inbox = Inbox {
                url: inner.origin.clone(),
                service_key: inner.service.verifying_key().to_bytes(),
            };
            let body =
                IdentityBody::first(identity.public(), [3; 16], inbox, IdentityPolicy::default());
            inner.doc = Some(IdentityDoc::sign(&identity, body).unwrap());
            inner.staged = false;
            inner
                .apps
                .insert([3; 16], super::super::SwitchApp::default());
            inner.apps_version = 4;
            inner.directory_version = 3;
            inner.shared.contacts.insert([5; 32]);
            inner.shared.connect.push(([6; 32], 1));
            inner.uploads_per_app_per_hour = 7;
            let hash = inner.doc.as_ref().unwrap().hash();
            let erasure = crate::transport::Request {
                method: "POST".into(),
                origin: SWITCH_ORIGIN.into(),
                path_and_query: "/v1/x/erase".into(),
                headers: Vec::new(),
                body: pubky_switch_core::http::erase_body(Some(inner.creation_time()), Some(&hash)),
                timeout: crate::transport::TimeoutClass::default(),
            };
            assert_eq!(inner.erase_answer(&erasure).0, 200);
        }
        assert!(switch.erased());
        assert_eq!(switch.mark(), None, "the mark went with the account");

        let (status, second) = enroll_at(&switch, &identity, 2, Some(vec![[9; 16]]));
        assert_eq!(status, 200);
        assert_eq!(second["service_key"], first["service_key"], "the one key");
        assert!(!switch.erased());
        assert_eq!(
            switch.mark(),
            Some((0, 0, pubky_switch_core::chain::ZERO_HASH))
        );
        {
            // Created after the erasure's record, so the record doesn't cover it.
            let inner = switch.lock();
            assert!(inner.created_at_ms > inner.marks.erasure_at_ms.unwrap());
        }
        // The erased account's kept App ID went with it; the new enrollment names its own.
        assert_eq!(switch.kept_app_ids(), vec![[9; 16]]);
        {
            // Nothing of the erased account is left, and the new one serves only once it
            // takes its first document.
            let inner = switch.lock();
            assert!(inner.staged);
            assert!(inner.doc.is_none());
            assert!(inner.apps.is_empty());
            assert!(inner.shared.contacts.is_empty());
            assert!(inner.shared.connect.is_empty());
            assert_eq!((inner.apps_version, inner.directory_version), (0, 0));
            // The switch's configuration stays.
            assert_eq!(inner.uploads_per_app_per_hour, 7);
        }
        // The same enrollment again gets the same answer, and makes no further account.
        let (status, again) = enroll_at(&switch, &identity, 2, Some(vec![[9; 16]]));
        assert_eq!((status, again), (200, second));
    }

    #[test]
    fn test_scripted_stale_enrollment_is_refused_before_it_is_looked_at() {
        // As at the service: an enrollment whose timestamp is more than 5 minutes from the
        // switch's time is `401 stale_timestamp`, signed with the one key, whether it
        // is new or the switch holds its answer (Switch wire 7.1, 7.4.1).
        let identity = pubky_switch_core::keys::IdentityKey::from_secret([1; 32]);
        let now = 1_700_000_000_000;
        let clock = Arc::new(crate::clock::TestClock::new(now));
        let switch =
            ScriptedSwitch::unenrolled_at(&identity, [2; 32], clock.clone(), SWITCH_ORIGIN);
        let body = pubky_switch_core::records::EnrollmentBody {
            identity: identity.public(),
            origin: SWITCH_ORIGIN.to_owned(),
            nonce: [1; 16],
            policy: pubky_switch_core::records::IdentityPolicy::default(),
            identity_doc: None,
            revoked_apps: None,
        };
        let enrollment = Enrollment::sign(&identity, body).unwrap();
        let sent_at = |at: u64| crate::transport::Request {
            method: "POST".into(),
            origin: SWITCH_ORIGIN.into(),
            path_and_query: "/v1/enroll".into(),
            headers: vec![crate::transport::Header::new(
                pubky_switch_core::http::header::TIMESTAMP,
                &pubky_switch_core::time::rfc3339(at),
            )],
            body: json!({ "enrollment": enrollment.signed() })
                .to_string()
                .into_bytes(),
            timeout: crate::transport::TimeoutClass::default(),
        };
        let refused = |answer: &crate::transport::Response| {
            let body: Value = serde_json::from_slice(&answer.body).unwrap();
            let signature = pubky_switch_core::enc::unb64_array::<64>(
                answer
                    .header(pubky_switch_core::http::header::SERVICE_SIGNATURE)
                    .unwrap(),
            )
            .unwrap();
            let key = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
            let by_switch = pubky_switch_core::http::verify_response(
                &key.verifying_key().to_bytes(),
                &pubky_switch_core::http::ResponseParts {
                    status: answer.status,
                    method: "POST",
                    path: "/v1/enroll",
                    request_signature: None,
                    server_time: answer
                        .header(pubky_switch_core::http::header::SERVER_TIME)
                        .unwrap(),
                    head: answer.header(pubky_switch_core::http::header::HEAD),
                    body: &answer.body,
                },
                &signature,
            )
            .is_ok();
            (
                answer.status,
                body["code"].as_str().map(str::to_owned),
                by_switch,
            )
        };
        let tolerance = pubky_switch_core::records::CLOCK_TOLERANCE_MS;
        let stale = switch.handle(&sent_at(now - tolerance - 1_000)).unwrap();
        assert_eq!(refused(&stale), (401, Some("stale_timestamp".into()), true));
        assert!(switch.lock().enrolled.is_none(), "nothing was enrolled");
        // At the edge of the window it is taken.
        assert_eq!(
            switch.handle(&sent_at(now - tolerance)).unwrap().status,
            200
        );
        // The same enrollment once its timestamp is stale: its kept answer isn't given.
        clock.advance_ms(2_000);
        let again = switch.handle(&sent_at(now - tolerance)).unwrap();
        assert_eq!(refused(&again), (401, Some("stale_timestamp".into()), true));
    }

    #[test]
    fn test_scripted_recovery_in_place_keeps_the_one_key_and_the_held_app_ids() {
        // As at the service: an enrollment at a serving account names the one key and holds
        // the App IDs it names for the next generation, whose start refuses a document
        // listing one and then keeps them; every enrollment's kept answer stays (Switch
        // wire 3.3, 3.7).
        let identity = pubky_switch_core::keys::IdentityKey::from_secret([1; 32]);
        let switch = ScriptedSwitch::unenrolled_at(
            &identity,
            [2; 32],
            Arc::new(crate::clock::TestClock::new(0)),
            SWITCH_ORIGIN,
        );
        let (status, first) = enroll_at(&switch, &identity, 1, None);
        assert_eq!(status, 200);
        let key = |answer: &Value| answer["service_key"].as_str().unwrap().to_owned();
        let outgoing = key(&first);
        let service = switch.lock().service.verifying_key().to_bytes();
        let doc = IdentityDoc::sign(
            &identity,
            pubky_switch_core::records::IdentityBody::first(
                identity.public(),
                [3; 16],
                pubky_switch_core::records::Inbox::new(SWITCH_ORIGIN, service),
                pubky_switch_core::records::IdentityPolicy::default(),
            ),
        )
        .unwrap();
        let delivery = json!({ "identity": doc.signed(), "prev": null }).to_string();
        assert_eq!(
            switch.lock().put_identity(delivery.as_bytes()).unwrap().0,
            200
        );
        let (status, second) = enroll_at(&switch, &identity, 2, Some(vec![[7; 16]]));
        assert_eq!(status, 200);
        assert_eq!(key(&second), outgoing, "the one key at a serving account");
        assert_eq!(switch.lock().held_app_ids, vec![[7; 16]]);
        // The same enrollment again: its kept answer.
        let (status, replayed) = enroll_at(&switch, &identity, 2, Some(vec![[7; 16]]));
        assert_eq!((status, replayed), (200, second.clone()));
        let mut body = doc.body().clone();
        body.version = 2;
        body.generation = 2;
        body.recovery_from = Some(1);
        // One listing an App ID held for the next generation is refused, as at the service.
        let mut listing = body.clone();
        listing.apps.push(pubky_switch_core::records::ListedApp {
            app_id: [7; 16],
            cert: [8; 32],
        });
        let listing = IdentityDoc::sign(&identity, listing).unwrap();
        let delivery = json!({ "identity": listing.signed(), "prev": null }).to_string();
        assert_eq!(
            switch.lock().put_identity(delivery.as_bytes()).unwrap().0,
            400
        );
        {
            let mut inner = switch.lock();
            inner.uploads_per_app_per_hour = 7;
            inner.upload_counts.insert([5; 16], (1, 3));
            inner.apps_version = 4;
            inner.directory_version = 9;
            inner.feed_limit = Some(3);
            inner.max_page_bytes = 4_096;
            inner.keep_passed = true;
            inner.open_admission = true;
            inner.shared.connect.push(([4; 32], 1));
        }
        let recovery = IdentityDoc::sign(&identity, body).unwrap();
        let delivery = json!({ "identity": recovery.signed(), "prev": null }).to_string();
        assert_eq!(
            switch.lock().put_identity(delivery.as_bytes()).unwrap().0,
            200
        );
        assert!(
            switch.kept_app_ids().contains(&[7; 16]),
            "the App ID held for the generation is kept"
        );
        assert_eq!(
            switch.mark().map(|(g, _, _)| g),
            Some(2),
            "the mark at its start"
        );
        // The upload limits and counts stay, as the service's do (Switch wire 9.4).
        {
            let inner = switch.lock();
            assert_eq!(inner.uploads_per_app_per_hour, 7);
            assert_eq!(inner.upload_counts.get(&[5; 16]), Some(&(1, 3)));
            // The directory's versions go on from where they stood: the account started
            // afresh never shows a version it showed before for another set of apps.
            assert_eq!(inner.apps_version, 4);
            assert!(inner.directory_version >= 9, "{}", inner.directory_version);
            // And so does what a test configured.
            assert_eq!((inner.feed_limit, inner.max_page_bytes), (Some(3), 4_096));
            assert!(inner.keep_passed && inner.open_admission);
            // Pending connect requests don't outlive it (Switch spec 12.6 step 1, wire 7.4.7).
            assert!(inner.shared.connect.is_empty());
        }
        let (status, again) = enroll_at(&switch, &identity, 1, None);
        assert_eq!((status, again), (200, first));
    }

    #[test]
    fn test_scripted_erasure_naming_a_hash_with_no_identity_json_held_is_conflict() {
        // A fresh account holds no `identity.json`: a hash can't match, so the erasure is
        // `409 conflict` and erases nothing; a body without one erases it, writing the
        // erasure's record and deleting the mark (Switch wire 7.4.16, 7.3 Table 3).
        use pubky_switch_core::http::erase_body;
        let identity = pubky_switch_core::keys::IdentityKey::from_secret([1; 32]);
        let switch = ScriptedSwitch::new(
            &identity,
            [2; 32],
            Arc::new(crate::clock::TestClock::new(0)),
        );
        let mut inner = switch.lock();
        let created = Some(inner.creation_time());
        let erasure = |hash: Option<&[u8; 32]>| crate::transport::Request {
            method: "POST".into(),
            origin: SWITCH_ORIGIN.into(),
            path_and_query: "/v1/x/erase".into(),
            headers: Vec::new(),
            body: erase_body(created, hash),
            timeout: crate::transport::TimeoutClass::default(),
        };
        assert!(inner.doc.is_none());
        let (status, body) = inner.erase_answer(&erasure(Some(&[9; 32])));
        assert_eq!((status, body["code"].clone()), (409, json!("conflict")));
        assert!(inner.hosts());
        let (status, _) = inner.erase_answer(&erasure(None));
        assert_eq!(status, 200);
        assert!(!inner.hosts());
        assert!(inner.marks.erasure_at_ms.is_some());
        assert_eq!(inner.marks.slot, super::super::marks::MarkSlot::Missing);
    }

    #[test]
    fn test_scripted_first_document_of_a_recovery_starts_its_generation() {
        // As at the service: the account takes the first document's generation, its chain
        // starts with the `recovery` transition, and `GET /apps` reports the recovery; a
        // `recovery_from` that isn't the generation less one is `400` (Switch wire 3.3, 7.4.2).
        use pubky_switch_core::records::{IdentityBody, IdentityPolicy, Inbox};
        let identity = pubky_switch_core::keys::IdentityKey::from_secret([1; 32]);
        let switch = ScriptedSwitch::new(
            &identity,
            [2; 32],
            Arc::new(crate::clock::TestClock::new(1_000)),
        );
        let mut inner = switch.lock();
        let (origin, key) = (
            inner.origin.clone(),
            inner.service.verifying_key().to_bytes(),
        );
        let first = |generation: u64, recovery_from: u64| {
            let mut body = IdentityBody::first(
                identity.public(),
                [3; 16],
                Inbox {
                    url: origin.clone(),
                    service_key: key,
                },
                IdentityPolicy::default(),
            );
            body.generation = generation;
            body.recovery_from = Some(recovery_from);
            let doc = IdentityDoc::sign(&identity, body).unwrap();
            IdentityDelivery {
                identity: doc.signed().clone(),
                prev: None,
            }
            .to_json()
        };
        let wrong = first(3, 1);
        let (status, _) = inner.put_identity(&wrong).unwrap();
        assert_eq!(status, 400);
        let elsewhere = {
            let mut body = IdentityBody::first(
                identity.public(),
                [3; 16],
                Inbox {
                    url: "https://elsewhere.example".into(),
                    service_key: key,
                },
                IdentityPolicy::default(),
            );
            body.generation = 3;
            body.recovery_from = Some(2);
            let doc = IdentityDoc::sign(&identity, body).unwrap();
            IdentityDelivery {
                identity: doc.signed().clone(),
                prev: None,
            }
            .to_json()
        };
        let (status, _) = inner.put_identity(&elsewhere).unwrap();
        assert_eq!(status, 400, "another service");
        let right = first(3, 2);
        let (status, _) = inner.put_identity(&right).unwrap();
        assert_eq!(status, 200);
        assert_eq!((inner.tip.generation, inner.tip.seq), (3, 2));
        assert_eq!(inner.recovery_from, Some(2));
        assert_eq!(inner.recovery_declared_at, Some(1_000));
        assert!(inner.any_first_n);
        // It lists no app: admission isn't staged, and ending it chains nothing.
        assert!(!inner.admission_staged);
        let (status, body) = inner.recovery_admission(&[]).unwrap();
        assert_eq!((status, body["proofs"].clone()), (200, json!([])));
    }

    #[test]
    fn test_scripted_recovery_listing_an_app_stages_admission_until_the_signer_ends_it() {
        // As at the service: staged at a recovery whose document lists an app; the signer's
        // call ends it with the `admission` transition, and again chains nothing (Switch
        // spec 12.6 step 2; wire 7.4.14).
        use pubky_switch_core::records::{IdentityBody, IdentityPolicy, Inbox, ListedApp};
        let identity = pubky_switch_core::keys::IdentityKey::from_secret([1; 32]);
        let switch = ScriptedSwitch::new(
            &identity,
            [2; 32],
            Arc::new(crate::clock::TestClock::new(1_000)),
        );
        let mut inner = switch.lock();
        assert_eq!(inner.recovery_admission(&[]).unwrap().0, 404, "no recovery");
        let mut body = IdentityBody::first(
            identity.public(),
            [3; 16],
            Inbox {
                url: inner.origin.clone(),
                service_key: inner.service.verifying_key().to_bytes(),
            },
            IdentityPolicy::default(),
        );
        body.generation = 2;
        body.recovery_from = Some(1);
        body.apps.push(ListedApp {
            app_id: [4; 16],
            cert: [5; 32],
        });
        let doc = IdentityDoc::sign(&identity, body).unwrap();
        let delivery = IdentityDelivery {
            identity: doc.signed().clone(),
            prev: None,
        }
        .to_json();
        assert_eq!(inner.put_identity(&delivery).unwrap().0, 200);
        assert!(inner.admission_staged);
        let (status, body) = inner.recovery_admission(&[]).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body["proofs"].as_array().unwrap().len(), 1);
        assert!(!inner.admission_staged);
        let seq = inner.tip.seq;
        let (_, body) = inner.recovery_admission(&[]).unwrap();
        assert_eq!(body["proofs"], json!([]));
        assert_eq!(inner.tip.seq, seq, "nothing chained");
    }

    #[test]
    fn test_scripted_handover_refuses_unknown_members() {
        let sig = pubky_switch_core::enc::b64(&[0u8; 64]);
        assert!(read_handover(&json!({ "envelopes": [], "sig": sig })).is_some());
        assert!(read_handover(&json!({ "envelopes": [], "sig": sig, "x": 1 })).is_none());
    }
}
