//! The signer's calls at the scripted Dispatch: enrollment (Dispatch wire 3.7, 7.4.1), the
//! `identity.json` delivery (Dispatch wire 3.3, 7.4.2) and the app list (Dispatch wire 7.4.12).
//! The delivery is judged by the core's `check_delivery`, the rule the service applies.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use pubky_dispatch_core::chain::{ItemType, ProofState, ServiceTransition, item_hash};
use pubky_dispatch_core::claims::Outcome;
use pubky_dispatch_core::enc::{b64, zbase32_encode};
use pubky_dispatch_core::http::{ErrorCode, IdentityDelivery};
use pubky_dispatch_core::json::parse_json;
use pubky_dispatch_core::records::{
    AccountActivation, AccountAssociation, AccountView, Delivery, DeliveryRefusal, Enrollment,
    EnrollmentAnswer, GenerationChange, IdentityDoc, KeptProofs, Limits, check_delivery,
    needed_generations, recovery_apps_version,
};
use pubky_dispatch_core::sig::SignedDoc;
use serde_json::{Value, json};

use super::{Answer, DISPATCH_ORIGIN, DispatchApp, Inner, ScriptedDispatch, bad};
use crate::clock::TestClock;
use crate::testing::ScriptError;

/// A generation and the service key that verifies its proofs (Dispatch wire 3.3).
type GenerationKey = (u64, [u8; 32]);

#[derive(Clone, Copy, Debug)]
struct OpeningEnrollment {
    enrollment_hash: [u8; 32],
    store_id: [u8; 16],
    material: [u8; 32],
    digest: [u8; 32],
}

impl OpeningEnrollment {
    fn commitment(
        material: [u8; 32],
        store_id: [u8; 16],
        enrollment: [u8; 32],
        identity: [u8; 32],
        created: u64,
        limits: Limits,
    ) -> Result<[u8; 32], ScriptError> {
        let fields = (material, store_id, enrollment, identity, created, limits);
        Ok(pubky_dispatch_core::enc::hash(&serde_json::to_vec(
            &fields,
        )?))
    }
}

/// What an enrolled account holds of its enrollments (Dispatch wire 3.7).
#[derive(Clone, Debug, Default)]
pub(crate) struct Enrolled {
    opening: Option<OpeningEnrollment>,
    /// The limits the answers announce.
    pub(crate) limits: Limits,
    /// The answer to each enrollment taken, by enrollment hash, so the same enrollment again
    /// gets the same answer.
    pub(crate) answers: HashMap<[u8; 32], EnrollmentReceipt>,
}

/// An exact completed enrollment and the account/store to which it applied (account
/// binding 3). Keeping the result never authorizes another application of its intent.
#[derive(Clone, Debug)]
pub(crate) struct EnrollmentReceipt {
    created: u64,
    store_id: [u8; 16],
    answer: EnrollmentAnswer,
}

impl ScriptedDispatch {
    /// A Dispatch at [`DISPATCH_ORIGIN`] where `identity` has no account yet: every call is the
    /// `404` of an identity it doesn't host until the signer enrolls (Dispatch wire 3.7, 7.3
    /// step 2, 7.4.1). The enrollment makes the account, staged; the Dispatch's one key is the
    /// one from `service_secret`.
    pub fn unenrolled(
        identity: &pubky_dispatch_core::keys::IdentityKey,
        service_secret: [u8; 32],
        clock: Arc<TestClock>,
    ) -> Arc<Self> {
        Self::unenrolled_at(identity, service_secret, clock, DISPATCH_ORIGIN)
    }

    /// [`ScriptedDispatch::unenrolled`], at `origin`: the origin an enrollment must name, so
    /// two signers can enroll at two scripted Dispatches of different origins.
    pub fn unenrolled_at(
        identity: &pubky_dispatch_core::keys::IdentityKey,
        service_secret: [u8; 32],
        clock: Arc<TestClock>,
        origin: &str,
    ) -> Arc<Self> {
        let dispatch = Self::new(identity, service_secret, clock);
        {
            let mut inner = dispatch.lock();
            inner.enrolled = None;
            inner.staged = true;
            inner.origin = origin.to_owned();
            // No account, and no mark yet (Dispatch wire 7.3).
            inner.marks = super::marks::MarkStore::default();
        }
        dispatch
    }

    /// An unenrolled account in the service store identified by `store_id`.
    /// Accounts at one service origin share this identity across enrollment and erasure;
    /// another service store is constructed with another identity.
    pub fn unenrolled_at_in_store(
        identity: &pubky_dispatch_core::keys::IdentityKey,
        service_secret: [u8; 32],
        clock: Arc<TestClock>,
        origin: &str,
        store_id: [u8; 16],
    ) -> Arc<Self> {
        let dispatch = Self::unenrolled_at(identity, service_secret, clock, origin);
        dispatch.lock().marks.identity = Some(store_id);
        dispatch
    }

    /// The epoch ranges of the key bundle parts the Dispatch holds for `app`, in order.
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

    /// The hand-over the Dispatch holds, its target and its `PUT` body, as a test keeps it to
    /// store again ([`ScriptedDispatch::store_handover_again`]).
    pub fn stored_handover_body(&self) -> Option<([u8; 16], Value)> {
        self.lock().handover.clone()
    }

    /// A Dispatch that stores, or serves again, a hand-over it dropped: as a lost answer's
    /// resend would, or a faulty Dispatch (Dispatch wire 7.4.17).
    pub fn store_handover_again(&self, held: ([u8; 16], Value)) {
        self.lock().handover = Some(held);
    }

    /// The target of the hand-over the Dispatch holds, if any (Dispatch wire 7.4.17).
    pub fn stored_handover(&self) -> Option<[u8; 16]> {
        self.lock().stored_handover()
    }

    /// Forget the transition proof of the newest delivery, so a retry of it answers with no
    /// proof, as for a version the service took by enrollment or import (Dispatch wire 7.4.2).
    pub fn forget_delivery_proof(&self) {
        self.lock().delivery_proof = None;
    }

    /// A faulty service: it no longer holds `app`'s key bundle parts, which `bundle_ranges`
    /// then stops showing (Dispatch wire 7.4.12).
    pub fn forget_bundle_parts(&self, app: &[u8; 16]) {
        self.lock().bundles.remove(app);
    }

    /// The key bundle parts the Dispatch holds for `app`, in order.
    pub fn bundle_parts_of(&self, app: &[u8; 16]) -> Vec<pubky_dispatch_core::ops::KeyBundlePut> {
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

    /// Whether the account is erased (Dispatch wire 7.4.16): no account, and the erasure's
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
    /// Authenticate the wrapper and exact enrollment before a mark/erasure judgement can
    /// mutate state (Dispatch account binding 3).
    pub(super) fn check_enrollment(
        &self,
        request: &crate::transport::Request,
    ) -> Result<Enrollment, Answer> {
        self.authenticate_signer(request)?;
        let body: Value = parse_json(&request.body)
            .map_err(|_| bad(ErrorCode::BadRequest, "malformed body", Value::Null))?;
        let signed = body
            .get("enrollment")
            .and_then(|value| serde_json::from_value::<SignedDoc>(value.clone()).ok())
            .ok_or_else(|| bad(ErrorCode::BadRequest, "no enrollment", Value::Null))?;
        let enrollment = Enrollment::verify(&signed, &self.identity.public(), &self.origin)
            .map_err(|error| match error {
                pubky_dispatch_core::Error::Signature(_) => bad(
                    ErrorCode::BadSignature,
                    "invalid enrollment signature",
                    Value::Null,
                ),
                _ => bad(ErrorCode::BadRequest, "invalid enrollment", Value::Null),
            })?;
        let created = request
            .header(pubky_dispatch_core::http::header::CREATED)
            .map(pubky_dispatch_core::http::parse_created)
            .transpose()
            .map_err(|_| bad(ErrorCode::BadRequest, "invalid creation", Value::Null))?;
        if created != enrollment.body().intent.created() {
            return Err(bad(
                ErrorCode::BadRequest,
                "header and enrollment intent differ",
                Value::Null,
            ));
        }
        Ok(enrollment)
    }

    /// The scripted store's fresh enrollment contents (Dispatch account binding 3).
    fn opening_anchor(
        &self,
        enrollment_hash: [u8; 32],
        store_id: [u8; 16],
    ) -> Result<Option<OpeningEnrollment>, ScriptError> {
        let max_rows = pubky_dispatch_core::records::MAX_ENROLLMENT_BYTES / 16;
        if self.apps.len() > max_rows
            || self.kept_app_ids.len() > max_rows
            || !self.held_app_ids.is_empty()
            || self.directory_version != 0
            || self.apps_version != 0
        {
            return Ok(None);
        }
        let permanent: Vec<_> = self
            .apps
            .iter()
            .map(|(id, app)| {
                (
                    id,
                    app.departed,
                    app.revoked_at,
                    app.departed_at,
                    app.rotated,
                    app.receive_key.is_some(),
                )
            })
            .collect();
        let facts = (
            self.tip.generation,
            self.doc.as_ref().map(IdentityDoc::hash),
            &self.kept_app_ids,
            self.kept_at,
            permanent,
        );
        let Some(enrolled) = &self.enrolled else {
            return Ok(None);
        };
        let material = pubky_dispatch_core::enc::hash(&serde_json::to_vec(&facts)?);
        let digest = OpeningEnrollment::commitment(
            material,
            store_id,
            enrollment_hash,
            self.identity.public(),
            self.created_at_ms,
            enrolled.limits,
        )?;
        Ok(Some(OpeningEnrollment {
            enrollment_hash,
            store_id,
            material,
            digest,
        }))
    }

    /// Read the SQL-side origin before any changes to the simulated transaction.
    pub(super) fn opening_origin(&self) -> Option<[u8; 32]> {
        let opening = self.enrolled.as_ref()?.opening?;
        let found = if self.state_version == 0 && self.seq == 0 {
            self.opening_anchor(opening.enrollment_hash, opening.store_id)
                .ok()?
                .map(|actual| actual.digest)
        } else {
            let (tag, stored) = self.state_history.get(&self.state_version)?;
            (*tag == self.state_tag).then_some(*stored).flatten()
        };
        found.filter(|found| *found == opening.digest)
    }

    fn covers_opening_receipt(&self, enrollment: &Enrollment, receipt: &EnrollmentReceipt) -> bool {
        let Some(enrolled) = self.enrolled.as_ref() else {
            return false;
        };
        let Some(opening) = enrolled.opening else {
            return false;
        };
        let super::marks::MarkSlot::At(mark) = self.marks.slot else {
            return false;
        };
        let answer = &receipt.answer;
        let digest = OpeningEnrollment::commitment(
            opening.material,
            receipt.store_id,
            enrollment.hash(),
            self.identity.public(),
            receipt.created,
            answer.limits,
        );
        if answer.check(enrollment).is_err()
            || answer.limits != enrolled.limits
            || answer.created != receipt.created
            || digest.ok() != Some(opening.digest)
            || opening.enrollment_hash != enrollment.hash()
            || opening.store_id != receipt.store_id
            || self.creation_origin != Some(opening.digest)
            || mark.created_at_ms != receipt.created
            || mark.creation_anchor != Some((receipt.created, opening.digest))
            || mark.state_version > self.state_version
            || (self.state_version == 0 && (self.seq != 0 || mark.generation != 0))
        {
            return false;
        }
        matches!(
            self.judge(),
            super::marks::Verdict::Staged | super::marks::Verdict::Healthy
        ) && (mark.state_version == 0
            || self.state_history.get(&mark.state_version)
                == Some(&(mark.state_tag, self.creation_origin)))
    }

    /// `POST /v1/enroll` after authentication and the current locked judgement (Dispatch
    /// wire 3.7, 7.4.1; account binding 3).
    pub(super) fn enroll(&mut self, enrollment: &Enrollment) -> Result<Answer, ScriptError> {
        let store_id = match self.confirmed_store() {
            Ok(id) => id,
            Err(answer) => return Ok(answer),
        };
        let binding = match self.account_binding() {
            Ok(binding) => binding,
            Err(answer) => return Ok(answer),
        };
        // The same enrollment again gets its kept answer, with no other effect (Dispatch wire
        // 3.7, 7.4.1).
        if let Some(mut answer) = self
            .enrolled
            .as_ref()
            .filter(|_| {
                binding.association() == pubky_dispatch_core::records::AccountAssociation::Account
            })
            .and_then(|e| e.answers.get(&enrollment.hash()))
            .cloned()
        {
            if Some(answer.created) != binding.created() || answer.store_id != store_id {
                return Ok(super::account::binding_changed());
            }
            if matches!(
                enrollment.body().intent,
                pubky_dispatch_core::records::EnrollmentIntent::Create { .. }
            ) {
                if !self.covers_opening_receipt(enrollment, &answer) {
                    return Ok(bad(
                        ErrorCode::Unavailable,
                        "account binding: fresh enrollment contents unavailable",
                        Value::Null,
                    ));
                }
                // The result key follows the current signing key (Dispatch wire 7.4.1).
                answer.answer.service_key = self.service.verifying_key().to_bytes();
            }
            return Ok((200, serde_json::to_value(answer.answer)?));
        }
        if let Err(answer) = self.authorize_enrollment(enrollment, store_id) {
            return Ok(answer);
        }
        // A Dispatch a test made answer as for an identity it doesn't host makes a new account.
        if self.not_hosted_unpinned {
            self.drop_account();
        }
        let creating = binding.association() != AccountAssociation::Account;
        if creating {
            let replacing = self.hosts();
            let now = self.now();
            let previous = binding
                .created()
                .into_iter()
                .chain(self.marks.erasure_at_ms)
                .chain(replacing.then_some(self.created_at_ms));
            if previous.into_iter().any(|created| created >= now)
                || (replacing && self.stamped_ms > now)
            {
                return Ok(bad(
                    ErrorCode::Unavailable,
                    "account binding: creation time is unavailable",
                    Value::Null,
                ));
            }
            let baseline = replacing.then(|| self.doc.clone()).flatten();
            let generation = if replacing {
                self.tip
                    .generation
                    .max(baseline.as_ref().map_or(0, IdentityDoc::generation))
                    .max(match self.marks.slot {
                        super::marks::MarkSlot::At(mark) => mark.generation,
                        _ => 0,
                    })
            } else {
                enrollment.identity_doc().map_or(1, IdentityDoc::generation)
            };
            let exclusions = if replacing {
                self.exclusions()
            } else {
                BTreeMap::new()
            };
            // The mark precedes replacement. The remaining state changes are atomic
            // under this mutex (Dispatch account binding 3.1).
            self.mark_new_account(now);
            self.drop_account();
            self.created_at_ms = now;
            self.tip.generation = generation;
            self.tips = vec![self.tip];
            self.activation = if replacing {
                AccountActivation::Recovery
            } else {
                AccountActivation::Ordinary
            };
            self.doc = if replacing {
                baseline
            } else {
                enrollment.identity_doc().cloned()
            };
            self.staged = replacing
                || self.doc.as_ref().is_none_or(|doc| {
                    doc.inbox().url != self.origin
                        || doc.inbox().service_key != self.service.verifying_key().to_bytes()
                });
            self.apps = exclusions;
            self.kept_app_ids = self.apps.keys().copied().collect();
        }
        self.stamped_ms = self.stamped_ms.max(self.now()).max(self.created_at_ms);
        // At a serving account the App IDs it names are held for the next generation
        // (Dispatch wire 3.7).
        if !creating
            && self.doc.is_some()
            && (!self.staged || self.activation == AccountActivation::Recovery)
        {
            for app in enrollment.revoked_apps() {
                if !self.held_app_ids.contains(app) {
                    self.held_app_ids.push(*app);
                }
            }
        }
        let limits = self.enroll_limits;
        // The one key it names, at every account (Dispatch wire 7.4.1).
        let service_key = self.service.verifying_key().to_bytes();
        // The account's creation time, fixed for the account (Dispatch wire 3.7).
        let created = self.created_at_ms;
        let enrolled = self.enrolled.get_or_insert_with(|| Enrolled {
            opening: None,
            limits,
            answers: HashMap::new(),
        });
        let answer = EnrollmentAnswer::new(enrollment, service_key, enrolled.limits, created);
        let value: Value = serde_json::from_slice(&answer.to_json()?)?;
        enrolled.answers.insert(
            enrollment.hash(),
            EnrollmentReceipt {
                created,
                store_id,
                answer,
            },
        );
        // The enrollment that makes the account names the App IDs it keeps for good; another
        // enrollment for an existing account changes nothing (Dispatch wire 3.7).
        if creating {
            let kept: BTreeSet<[u8; 16]> = self
                .kept_app_ids
                .iter()
                .chain(enrollment.revoked_apps())
                .copied()
                .collect();
            self.kept_app_ids = kept.into_iter().collect();
            self.kept_at = self.now();
            if let Some(doc) = self.doc.clone() {
                self.keep_document_exclusions(&doc);
            }
        }
        if matches!(
            enrollment.body().intent,
            pubky_dispatch_core::records::EnrollmentIntent::Create { .. }
        ) {
            let opening = self.opening_anchor(enrollment.hash(), store_id)?;
            if let Some(held) = &mut self.enrolled {
                held.opening = opening;
            }
            let anchor = opening.map(|opening| opening.digest);
            self.creation_origin = anchor;
            if let super::marks::MarkSlot::At(mark) = &mut self.marks.slot {
                mark.creation_anchor = anchor.map(|digest| (created, digest));
            }
        }
        Ok((200, value))
    }

    /// Only irrevocable app exclusions survive a loss of the account state
    /// (Dispatch account binding 3.1); records, certificates and cursors do not.
    fn exclusions(&self) -> BTreeMap<[u8; 16], DispatchApp> {
        let mut kept = BTreeMap::new();
        for (id, app) in &self.apps {
            if app.departed {
                kept.insert(
                    *id,
                    DispatchApp {
                        departed: true,
                        revoked_at: app.revoked_at,
                        departed_at: app.departed_at,
                        rotated: app.rotated,
                        ..DispatchApp::default()
                    },
                );
            }
        }
        for id in &self.kept_app_ids {
            kept.entry(*id).or_insert_with(|| DispatchApp {
                departed: true,
                revoked_at: Some(self.kept_at),
                ..DispatchApp::default()
            });
        }
        for id in &self.held_app_ids {
            kept.entry(*id).or_insert_with(|| DispatchApp {
                departed: true,
                revoked_at: Some(self.now()),
                ..DispatchApp::default()
            });
        }
        kept
    }

    fn keep_document_exclusions(&mut self, doc: &IdentityDoc) {
        for removed in &doc.body().removed {
            let enrolled_at = self
                .kept_app_ids
                .contains(&removed.app_id)
                .then_some(self.kept_at);
            let app = self
                .apps
                .entry(removed.app_id)
                .or_insert_with(|| DispatchApp {
                    revoked_at: enrolled_at,
                    ..DispatchApp::default()
                });
            app.departed = true;
            if !self.kept_app_ids.contains(&removed.app_id) {
                self.kept_app_ids.push(removed.app_id);
            }
        }
    }

    /// The account is gone, its mark store staying: after an erasure, or for a lost account
    /// (Dispatch wire 7.3, 7.4.16). Nothing of what it held stays, its enrollments, its kept
    /// App IDs and its counts included; the service key is the Dispatch's, not the account's,
    /// and what a test set of the Dispatch's configuration stays set. An enrollment then makes
    /// a new, staged account, whose first `identity.json` is the next generation's, as at a
    /// service that never hosted the identity.
    pub(super) fn drop_account(&mut self) {
        // A read still held is answered for an account the Dispatch doesn't host.
        self.wake_held();
        let tip = pubky_dispatch_core::chain::ChainTip {
            generation: 1,
            seq: 0,
            chain_hash: pubky_dispatch_core::chain::ZERO_HASH,
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
        fresh.tags_made = self.tags_made;
        fresh.stamped_ms = self.stamped_ms;
        fresh.origin = self.origin.clone();
        fresh.enroll_limits = self.enroll_limits;
        fresh.uploads_per_app_per_hour = self.uploads_per_app_per_hour;
        fresh.max_kept_peers = self.max_kept_peers;
        fresh.max_reply_peers = self.max_reply_peers;
        fresh.retention = self.retention;
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
    /// among them, and everything else goes (Dispatch spec 12.6 step 1, wire 3.3, 3.7).
    fn start_afresh(&mut self, generation: u64) -> Result<(), Answer> {
        let had_reachable_apps = self.current_app_ids().iter().any(|id| {
            self.apps
                .get(id)
                .is_some_and(|app| app.receive_key.is_some())
        });
        let apps_version = recovery_apps_version(
            self.directory_version,
            self.apps_version,
            had_reachable_apps,
        )
        .ok_or_else(|| {
            bad(
                ErrorCode::Unavailable,
                "7.6: a temporary failure",
                Value::Null,
            )
        })?;
        // The held reads look again, and find the generation changed (Dispatch wire 7.4.4);
        // their numbers go on, so none is taken for another's.
        self.wake_held();
        let tip = pubky_dispatch_core::chain::ChainTip {
            generation,
            seq: 0,
            chain_hash: pubky_dispatch_core::chain::ZERO_HASH,
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
        fresh.creation_origin = self.creation_origin;
        fresh.state_version = self.state_version;
        fresh.state_tag = self.state_tag;
        fresh.tags_made = self.tags_made;
        fresh.enroll_limits = self.enroll_limits;
        // The upload limits are the service's configuration, and its upload counts are kept
        // by account and app, which a recovery in place doesn't forget (Dispatch wire 9.4).
        fresh.uploads_per_app_per_hour = self.uploads_per_app_per_hour;
        fresh.max_kept_peers = self.max_kept_peers;
        fresh.max_reply_peers = self.max_reply_peers;
        fresh.upload_counts = std::mem::take(&mut self.upload_counts);
        // The directory's versions are the account's, not the generation's: they go on
        // counting, as at the service, so a sender's copy from before the loss never
        // carries a version the new generation gives another set of apps (Dispatch wire
        // 7.4.3 step 5, 7.4.10).
        fresh.apps_version = apps_version;
        fresh.directory_version = self.directory_version;
        // What a test set of the Dispatch's configuration stays set, as a service's does.
        fresh.retention = self.retention;
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
        fresh.apps = self.exclusions();
        fresh.kept_app_ids = fresh.apps.keys().copied().collect();
        *self = fresh;
        Ok(())
    }

    /// Chain a delivered `identity.json` and hold it; returns the delivery's transition
    /// proof. A document naming this Dispatch's origin and service key makes a staged Dispatch
    /// serve, and
    /// one at a later generation moves the chain on to it (Dispatch wire 6.5 "Import").
    pub(super) fn chain_identity(&mut self, doc: &IdentityDoc) -> Result<SignedDoc, ScriptError> {
        if doc.generation() > self.tip.generation {
            self.tip.generation = doc.generation();
        }
        // The staged gate: the document names this service, its origin and its key
        // (Dispatch wire 3.7, 7.3 step 7).
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
        // The first listing's epoch is kept; a later listing never dates it again (Dispatch
        // wire 7.4.12).
        for app in &doc.body().apps {
            self.listed_at_epoch
                .entry(app.app_id)
                .or_insert(doc.data_epoch());
        }
        // A departure's rotation is done once a version removes the app at a higher data
        // epoch than at its departure, and stays done, also after a purge (Dispatch wire 7.4.12).
        for (id, app) in &mut self.apps {
            if let Some((_, epoch)) = app.departed_at
                && doc.data_epoch() > epoch
                && doc.body().removed.iter().any(|r| &r.app_id == id)
            {
                app.rotated = true;
            }
        }
        self.keep_document_exclusions(doc);
        self.doc = Some(doc.clone());
        // The next version, whoever delivered it, ends a stored hand-over (Dispatch wire 7.4.17).
        self.handover = None;
        self.delivery_proof = Some(proof.clone());
        self.directory_version += 1;
        // After its chain item: an app it no longer makes current departs at it (Dispatch wire
        // 7.4.4).
        self.after_departure(was);
        // The removed apps it leaves in neither list go, as at the service (Dispatch wire 9.1).
        self.purge_removed(None);
        Ok(proof)
    }

    /// `POST /v1/{id}/recovery/admission` from the signer (Dispatch wire 7.4.14): ends staged
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

    /// `PUT /v1/{id}/identity` from the signer, judged by the core's rules (Dispatch wire 3.3,
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
        // The App IDs enrollments named, and those revoked or seen departing (Dispatch wire 3.3).
        let mut kept = self.kept_app_ids.clone();
        for (id, app) in &self.apps {
            if app.departed && !kept.contains(id) {
                kept.push(*id);
            }
        }
        if let Some(held) = &self.doc {
            for removed in &held.body().removed {
                if !kept.contains(&removed.app_id) {
                    kept.push(removed.app_id);
                }
            }
        }
        let generation_before = self.tip.generation;
        // At a failing or bounded account step 2 let through only the start of a generation
        // above both the held document's and the mark's, with `recovery_from` (Dispatch wire
        // 7.3, Table 2): it starts the account afresh, so it is judged as the first document
        // of the account it starts.
        let mut started_afresh = false;
        if let Some(notice) = self.notice() {
            if !self.starts_recovery(doc.generation(), doc.body().recovery_from) {
                return Ok(super::marks::notice_answer(&notice));
            }
            // Exempt from the compare-and-swap of `prev` only: it still needs a higher version
            // than the one held (Dispatch wire 3.3).
            if self
                .doc
                .as_ref()
                .is_some_and(|held| doc.version() <= held.version())
            {
                return Ok(self.refusal(DeliveryRefusal::StaleIdentity(
                    "Dispatch wire 3.3: not a higher version than the one held",
                )));
            }
            let mut refused = kept.clone();
            refused.extend(self.held_app_ids.iter().copied());
            let fresh = AccountView {
                held: None,
                app_limit,
                staged: false,
                origin: &self.origin,
                enrollment_key: None,
                kept_app_ids: &refused,
                kept_proofs: KeptProofs::default(),
            };
            if let Err(refusal) = check_delivery(&fresh, &doc, None) {
                return Ok(self.refusal(refusal));
            }
            // It names this Dispatch: its origin and its key (Dispatch wire 7.4.2).
            if doc.inbox().url != self.origin
                || doc.inbox().service_key != self.service.verifying_key().to_bytes()
            {
                return Ok(bad(
                    ErrorCode::BadRequest,
                    "a recovery's first document names this service",
                    json!(null),
                ));
            }
            if let Err(answer) = self.start_afresh(doc.generation()) {
                return Ok(answer);
            }
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
            // key (Dispatch wire 3.3, 3.7).
            enrollment_key: (!self.staged).then(|| self.service.verifying_key().to_bytes()),
            kept_app_ids: &kept,
            kept_proofs: KeptProofs {
                records: &records,
                claim_entries: &claim_entries,
            },
        };
        // The start a failing or bounded account takes is exempt from the compare-and-swap
        // (Dispatch wire 3.3).
        let prev = delivery.prev.filter(|_| !started_afresh);
        match check_delivery(&view, &doc, prev.as_ref()) {
            Ok(Delivery::New(change)) => {
                match change {
                    // A service key change names another key than the ending generation's;
                    // this Dispatch has one (Dispatch wire 3.3).
                    Some(GenerationChange::KeyRotation) => {
                        return Ok(bad(
                            ErrorCode::BadRequest,
                            "Dispatch wire 3.3: a key change names another key",
                            json!(null),
                        ));
                    }
                    // A provider loss in place starts the account afresh, keeping only its
                    // service time and the App IDs to refuse (Dispatch spec 12.6 step 1, wire
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
                        if let Err(answer) = self.start_afresh(doc.generation()) {
                            return Ok(answer);
                        }
                    }
                    Some(GenerationChange::Staged) | None => {}
                }
                // A first document that starts a recovery, as at the service: the account
                // takes its generation, and its chain starts with the `recovery` transition
                // (Dispatch wire 3.3, 7.4.2), unless the Dispatch was made recovering, which
                // chained it already.
                if self.doc.is_none()
                    && self.recovery_from.is_none()
                    && let Some(recovery_from) = doc.body().recovery_from
                {
                    // It names this Dispatch: its origin and its key (Dispatch wire 7.4.2).
                    if doc.inbox().url != self.origin
                        || doc.inbox().service_key != self.service.verifying_key().to_bytes()
                    {
                        return Ok(bad(
                            ErrorCode::BadRequest,
                            "a recovery's first document names this service",
                            json!(null),
                        ));
                    }
                    // An app's first receive key may carry any `n` (Dispatch spec 3.6).
                    self.any_first_n = true;
                    self.tip.generation = doc.generation();
                    let at = self.now();
                    self.recovery_from = Some(recovery_from);
                    self.recovery_declared_at = Some(at);
                    // Staged whenever the document lists an app (Dispatch spec 12.6 step 2).
                    self.admission_staged = !doc.body().apps.is_empty();
                    self.service_transition(ServiceTransition::Recovery { recovery_from, at })?;
                }
                let proof = self.chain_identity(&doc)?;
                // A delivery that starts a generation moves the mark to its first head
                // (Dispatch wire 7.3, Table 3).
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

    /// The answer to a delivery the core's rules refuse (Dispatch wire 7.4.2).
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

    /// The newest data epoch through which `app` holds every key (Dispatch wire 7.4.12), by
    /// the core's rule: the epoch of the first version that listed it, if kept, raised by each
    /// stored part its cursor has passed that continues it, from epoch 1 when the start is
    /// unknown; `None` when nothing shows any.
    pub(super) fn keys_through(&self, app: &[u8; 16]) -> Option<u64> {
        let start = self.listed_at_epoch.get(app).copied();
        let spans: Vec<pubky_dispatch_core::ops::StoredPart> = self
            .bundles
            .get(app)
            .map(|parts| {
                parts
                    .iter()
                    .map(|(p, seq)| pubky_dispatch_core::ops::StoredPart {
                        first_epoch: p.first_epoch,
                        last_epoch: p.last_epoch,
                        seq: *seq,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let cursor = self.apps.get(app).map_or(0, |a| a.cursor);
        pubky_dispatch_core::ops::keys_through(start, &spans, cursor)
    }

    /// The kept proofs' generations, each with the key that verifies its proofs: an earlier
    /// generation's an import carried, else this Dispatch's own (Dispatch wire 3.3 "Service
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

    /// `POST /v1/{id}/apps/{app_id}/revoke` from the signer (Dispatch wire 7.4.12): the
    /// `revoke` transition's proof, none for an app revoked or departed already, `404` for an
    /// app neither the Dispatch nor `identity.json` knows.
    pub(super) fn revoke_answer(&mut self, route: &str) -> Result<Answer, ScriptError> {
        let id = route
            .strip_prefix("apps/")
            .and_then(|r| r.strip_suffix("/revoke"))
            .and_then(|id| pubky_dispatch_core::enc::app_id_decode(id).ok());
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

    /// `PUT /v1/{id}/handover` from the signer (Dispatch wire 7.4.17): the core's checks of a
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
            .and_then(|id| pubky_dispatch_core::enc::app_id_decode(id).ok());
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

    /// `GET /v1/{id}/handover` (Dispatch wire 7.4.17): the stored body, for the signer
    /// (`caller` `None`) or its target app; `404` for any other caller, or when none is held.
    pub(super) fn handover_answer(&self, caller: Option<[u8; 16]>) -> Answer {
        match &self.handover {
            Some((target, body)) if caller.is_none_or(|app| app == *target) => (200, body.clone()),
            _ => bad(ErrorCode::NotFound, "no hand-over", json!(null)),
        }
    }

    /// `POST /v1/{id}/erase` from the signer (Dispatch wire 7.4.16): a move in progress refuses
    /// it (`409 conflict`): a frozen account that doesn't fail stop, whose export this Dispatch
    /// doesn't track, and a staged one holding an import that can still be aborted. Then its
    /// binding to the account
    /// ([`Inner::erasure_binding`]): the creation time, then the `identity.json` it follows.
    /// Every `409` carries `current.created`. Then the erasure's record is written, dated no
    /// earlier than the creation time it named, the account goes, and its mark with it: every
    /// later call, a retry included, gets the `404` of an identity the Dispatch doesn't host.
    /// The answer is signed with the one key, without a head; an app's call is `403
    /// permission_missing`.
    pub(super) fn erase_answer(&mut self, request: &crate::transport::Request) -> Answer {
        if let Some(refusal) = self.erasure_timestamp_refusal(request) {
            return refusal;
        }
        let fails_stop = self.notice().is_some();
        if (self.frozen.is_some() && !fails_stop) || self.import_bars_erasure() {
            return bad(
                ErrorCode::Conflict,
                "a move is in progress",
                json!({ "created": pubky_dispatch_core::time::rfc3339(self.creation_time()) }),
            );
        }
        let created = match self.erasure_binding(request) {
            Ok(created) => created,
            Err(refusal) => return refusal,
        };
        if let Some(answer) = self.erasure_fault(created) {
            return answer;
        }
        // Completed erasure evidence and deletion are atomic under this mutex (wire 7.3,
        // Table 3). The service's intermediate durable attempts are described in FAKES.md.
        self.marks.erasure_at_ms = Some(self.now().max(created));
        self.drop_account();
        self.marks.slot = super::marks::MarkSlot::Missing;
        (200, json!({ "erased": true }))
    }

    /// The stored hand-over, as the test reads it.
    pub(super) fn stored_handover(&self) -> Option<[u8; 16]> {
        self.handover.as_ref().map(|(target, _)| *target)
    }

    /// `GET /v1/{id}/apps` (Dispatch wire 7.4.12): every app the Dispatch holds or the newest
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
                    // `cert_expires_at` carries that (Dispatch wire 7.4.12).
                    "current": if held.is_some_and(|a| a.cert.is_some()) {
                        !enrolled_kept && self.app_current_by(&self.apps, id, false)
                    } else {
                        listed && !kept
                    },
                    "last_seen": held.and_then(|a| a.last_seen).map(pubky_dispatch_core::time::rfc3339),
                    "revoked_at": held
                        .and_then(|a| a.revoked_at)
                        .or((enrolled_kept && held.is_none()).then_some(self.kept_at))
                        .map(pubky_dispatch_core::time::rfc3339),
                    "departed_at": held
                        .and_then(|a| a.departed_at)
                        .map(|(at, _)| pubky_dispatch_core::time::rfc3339(at)),
                    "awaiting_rotation": held.is_some_and(|a| a.departed_at.is_some() && !a.rotated),
                    "open_attempts": self.open_attempts(id),
                    "unread_entries": self.unread_counts(id).0,
                    "sole_target_unread": self.unread_counts(id).1,
                    "record_cert": held.and_then(|a| a.cert.as_ref()).map(|c| b64(&c.hash())),
                    "record_at": held.and_then(|a| a.record_at).map(pubky_dispatch_core::time::rfc3339),
                    "lagging": held.is_some_and(|a| a.lagging),
                    "keys_through": self.keys_through(id),
                    "full_bundle_requested": held
                        .and_then(|a| a.full_requested)
                        .map(pubky_dispatch_core::time::rfc3339),
                    "bundle_ranges": ranges,
                    "cert_expires_at": self
                        .checked_cert(id)
                        .map(|cert| pubky_dispatch_core::time::rfc3339(cert.expires_at())),
                })
            })
            .collect();
        let recovery = self.recovery_from.map(|from| {
            let declared_at = self.recovery_declared_at.unwrap_or_default();
            json!({ "recovery_from": from,
                    "declared_at": pubky_dispatch_core::time::rfc3339(declared_at),
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
        // Left out when no kept proof names a generation (Dispatch wire 7.4.12).
        if !proof_generations.is_empty() {
            answer["proof_generations"] = json!(proof_generations);
        }
        (200, answer)
    }

    /// The attempts `app` owns that are open or `unknown`, as `GET /apps` lists them (Dispatch
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

/// A hand-over's `{ "envelopes": [b64], "sig": b64 }`, as the Dispatch reads it without
/// opening anything (Dispatch wire 3.12).
fn read_handover(value: &Value) -> Option<pubky_dispatch_core::records::SignerHandover> {
    // Unknown members are `400`, as at the service (Dispatch wire 7.4.17, 1.1).
    pubky_dispatch_core::json::reject_unknown_members(
        value,
        &["envelopes", "sig"],
        "the hand-over",
    )
    .ok()?;
    let envelopes = value
        .get("envelopes")?
        .as_array()?
        .iter()
        .map(|e| {
            e.as_str()
                .and_then(|s| pubky_dispatch_core::enc::unb64(s).ok())
        })
        .collect::<Option<Vec<Vec<u8>>>>()?;
    let sig = pubky_dispatch_core::enc::unb64_array::<64>(value.get("sig")?.as_str()?).ok()?;
    Some(pubky_dispatch_core::records::SignerHandover::from_parts(
        envelopes, sig,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Clock;

    #[test]
    fn test_scripted_staged_import_erasure_follows_abort_eligibility() {
        use super::super::marks::MarkSlot;
        use crate::testing::{ProtocolSpec, Seeds, TestHomeserver, TestIdentity, TestSigner};

        // Both staged rows of Table 1, with and without a retirement: a missing mark
        // permits abort, as does a mark at or below the enrollment's generation.
        // Only a higher mark rules abort out (Dispatch wire 7.3, Table 2).
        for holds_chain in [false, true] {
            for retired in [false, true] {
                for mark_generation in [None, Some(0), Some(1), Some(2)] {
                    let alice = TestSigner::new(
                        TestIdentity::new(&Seeds::default(), "alice"),
                        Arc::new(TestClock::new(crate::testing::START_MS)),
                        Arc::new(TestHomeserver::new()),
                        ProtocolSpec::default(),
                    );
                    alice.next_doc(|_| {}).unwrap();
                    let target = alice.dispatch().import_into([45; 32]);
                    let mut inner = target.lock();
                    let held = inner.doc.as_ref().unwrap().hash();
                    let created = inner.creation_time();
                    if !holds_chain {
                        inner.seq = 0;
                    }
                    let MarkSlot::At(mut mark) = inner.marks.slot else {
                        panic!("the activated import has a mark");
                    };
                    if let Some(generation) = mark_generation {
                        mark.generation = generation;
                        if generation == 0 {
                            mark.seq = 0;
                            mark.chain_hash = pubky_dispatch_core::chain::ZERO_HASH;
                            mark.state_version = 0;
                            mark.state_tag = 0;
                        }
                        inner.marks.slot = MarkSlot::At(mark);
                    } else {
                        inner.marks.slot = MarkSlot::Missing;
                    }
                    if retired {
                        inner
                            .marks
                            .retired
                            .insert(mark_generation.unwrap_or(1).max(1));
                    }
                    let before = inner.marks.slot;
                    let request = crate::transport::Request {
                        method: "POST".into(),
                        origin: DISPATCH_ORIGIN.into(),
                        path_and_query: format!(
                            "/v1/{}/erase",
                            pubky_dispatch_core::enc::pubky_id(&inner.identity.public())
                        ),
                        headers: Vec::new(),
                        body: json!({ "created": pubky_dispatch_core::time::rfc3339(created),
                                      "identity_hash": b64(&held) })
                        .to_string()
                        .into_bytes(),
                        timeout: crate::transport::TimeoutClass::Bulk,
                    };
                    let (status, body) = inner.erase_answer(&request);
                    if mark_generation == Some(2) {
                        assert_eq!(
                            status, 200,
                            "{holds_chain} {retired} {mark_generation:?}: {body}"
                        );
                        assert!(!inner.hosts());
                        assert_eq!(inner.marks.slot, MarkSlot::Missing);
                        assert!(inner.marks.erasure_at_ms.is_some());
                    } else {
                        assert_eq!(
                            status, 409,
                            "{holds_chain} {retired} {mark_generation:?}: {body}"
                        );
                        assert_eq!(body["code"], "conflict");
                        assert_eq!(
                            body["current"]["created"],
                            pubky_dispatch_core::time::rfc3339(created)
                        );
                        assert!(inner.hosts());
                        assert_eq!(inner.doc.as_ref().unwrap().hash(), held);
                        assert_eq!(inner.marks.slot, before);
                        assert_eq!(inner.marks.erasure_at_ms, None);
                    }
                }
            }
        }
    }

    fn signed_request(
        identity: &pubky_dispatch_core::keys::IdentityKey,
        method: &str,
        path: &str,
        body: Vec<u8>,
        created: Option<u64>,
        at: u64,
    ) -> crate::transport::Request {
        use pubky_dispatch_core::http::{self, RequestHeaders, RequestTarget, header};
        let fields = RequestHeaders {
            identity: identity.id(),
            timestamp: pubky_dispatch_core::time::rfc3339_seconds(at),
            created: created.map(pubky_dispatch_core::time::rfc3339),
            ..RequestHeaders::default()
        };
        let signature = http::sign_request(
            identity,
            &RequestTarget {
                method,
                path_and_query: path,
                body: &body,
                origin: DISPATCH_ORIGIN,
            },
            &fields,
        );
        let mut headers = vec![
            crate::transport::Header::new(header::IDENTITY, &fields.identity),
            crate::transport::Header::new(header::TIMESTAMP, &fields.timestamp),
            crate::transport::Header::new(header::SIGNATURE, &b64(&signature)),
        ];
        if let Some(created) = fields.created {
            headers.push(crate::transport::Header::new(header::CREATED, &created));
        }
        crate::transport::Request {
            method: method.into(),
            origin: DISPATCH_ORIGIN.into(),
            path_and_query: path.into(),
            headers,
            body,
            timeout: crate::transport::TimeoutClass::Bulk,
        }
    }

    fn creation_observation(
        dispatch: &ScriptedDispatch,
        identity: &pubky_dispatch_core::keys::IdentityKey,
    ) -> pubky_dispatch_core::records::CarriedAccountObservation {
        use pubky_dispatch_core::http::header;
        let now = dispatch.lock().now();
        let request = signed_request(
            identity,
            "GET",
            &format!("/v1/{}/account", identity.id()),
            vec![],
            None,
            now,
        );
        let answer = dispatch.handle(&request).unwrap();
        assert_eq!(answer.status, 200);
        let carried = pubky_dispatch_core::records::CarriedAccountObservation {
            body: answer.body.clone(),
            sig: pubky_dispatch_core::enc::unb64_array(
                answer.header(header::SERVICE_SIGNATURE).unwrap(),
            )
            .unwrap(),
            request_timestamp: request.header(header::TIMESTAMP).unwrap().to_owned(),
            request_signature: pubky_dispatch_core::enc::unb64_array(
                request.header(header::SIGNATURE).unwrap(),
            )
            .unwrap(),
        };
        assert_eq!(
            carried
                .verify(&identity.public(), DISPATCH_ORIGIN)
                .unwrap()
                .body()
                .created,
            None
        );
        carried
    }

    /// Make one distinct intent. A retry keeps the returned signed enrollment unchanged.
    fn enrollment_for(
        dispatch: &ScriptedDispatch,
        identity: &pubky_dispatch_core::keys::IdentityKey,
        nonce: u8,
        revoked: Option<Vec<[u8; 16]>>,
    ) -> Enrollment {
        let current = {
            let inner = dispatch.lock();
            inner.hosts().then(|| inner.creation_time())
        };
        let intent = match current {
            Some(created) => pubky_dispatch_core::records::EnrollmentIntent::Existing { created },
            None => pubky_dispatch_core::records::EnrollmentIntent::Create {
                observation: creation_observation(dispatch, identity),
            },
        };
        Enrollment::sign(
            identity,
            pubky_dispatch_core::records::EnrollmentBody {
                identity: identity.public(),
                origin: DISPATCH_ORIGIN.to_owned(),
                nonce: [nonce; 16],
                intent,
                policy: pubky_dispatch_core::records::IdentityPolicy::default(),
                identity_doc: None,
                revoked_apps: revoked,
            },
        )
        .unwrap()
    }

    fn enroll_at(
        dispatch: &ScriptedDispatch,
        identity: &pubky_dispatch_core::keys::IdentityKey,
        enrollment: &Enrollment,
    ) -> (u16, Value) {
        let now = dispatch.lock().now();
        let request = signed_request(
            identity,
            "POST",
            "/v1/enroll",
            json!({ "enrollment": enrollment.signed() })
                .to_string()
                .into_bytes(),
            enrollment.body().intent.created(),
            now,
        );
        let response = dispatch.handle(&request).unwrap();
        (
            response.status,
            serde_json::from_slice(&response.body).unwrap(),
        )
    }

    #[test]
    fn test_scripted_open_attempt_refuses_a_second_open_one() {
        // As the service refuses the entry: a claim takes one open attempt at a time, and a
        // new one once that one has failed (Dispatch wire 6.8).
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let dispatch = ScriptedDispatch::new(
            &identity,
            [2; 32],
            Arc::new(crate::clock::TestClock::new(0)),
        );
        dispatch.open_attempt([1; 32], [1; 16], [3; 16]).unwrap();
        assert!(dispatch.open_attempt([1; 32], [2; 16], [3; 16]).is_err());
        dispatch.fail_attempt([1; 32], [1; 16], [3; 16]);
        dispatch.open_attempt([1; 32], [2; 16], [3; 16]).unwrap();
    }

    #[test]
    fn test_scripted_enrollment_after_an_erasure_makes_a_new_account() {
        // As at the service, where the erased account doesn't exist any more (Dispatch wire
        // 7.4.16, Dispatch spec 12.7 step 4): the same one key, a new (0, 0) mark, and nothing
        // of what the erased account kept.
        use pubky_dispatch_core::records::{IdentityBody, IdentityPolicy, Inbox};
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let clock = Arc::new(crate::clock::TestClock::new(1_700_000_000_000));
        let dispatch =
            ScriptedDispatch::unenrolled_at(&identity, [2; 32], clock.clone(), DISPATCH_ORIGIN);
        let first_enrollment = enrollment_for(&dispatch, &identity, 1, Some(vec![[7; 16]]));
        let (status, first) = enroll_at(&dispatch, &identity, &first_enrollment);
        assert_eq!(status, 200);
        assert_eq!(dispatch.kept_app_ids(), vec![[7; 16]]);
        {
            // What a serving account holds: its document, an app, a kept peer, a pending
            // connect request, and versions that have moved.
            let mut inner = dispatch.lock();
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
                .insert([3; 16], super::super::DispatchApp::default());
            inner.apps_version = 4;
            inner.directory_version = 3;
            inner.shared.kept.insert([5; 32]);
            inner.shared.connect.push(([6; 32], 1));
            inner.uploads_per_app_per_hour = 7;
            let hash = inner.doc.as_ref().unwrap().hash();
            let erasure = crate::transport::Request {
                method: "POST".into(),
                origin: DISPATCH_ORIGIN.into(),
                path_and_query: "/v1/x/erase".into(),
                headers: Vec::new(),
                body: pubky_dispatch_core::http::erase_body(
                    Some(inner.creation_time()),
                    Some(&hash),
                ),
                timeout: crate::transport::TimeoutClass::Bulk,
            };
            assert_eq!(inner.erase_answer(&erasure).0, 200);
        }
        assert!(dispatch.erased());
        assert_eq!(dispatch.mark(), None, "the mark went with the account");

        clock.advance_ms(1);
        let second_enrollment = enrollment_for(&dispatch, &identity, 2, Some(vec![[9; 16]]));
        let (status, second) = enroll_at(&dispatch, &identity, &second_enrollment);
        assert_eq!(status, 200);
        assert_eq!(second["service_key"], first["service_key"], "the one key");
        assert!(!dispatch.erased());
        assert_eq!(
            dispatch.mark(),
            Some((0, 0, pubky_dispatch_core::chain::ZERO_HASH))
        );
        {
            // Created after the erasure's record, so the record doesn't cover it.
            let inner = dispatch.lock();
            assert!(inner.created_at_ms > inner.marks.erasure_at_ms.unwrap());
        }
        // The erased account's kept App ID went with it; the new enrollment names its own.
        assert_eq!(dispatch.kept_app_ids(), vec![[9; 16]]);
        {
            // Nothing of the erased account is left, and the new one serves only once it
            // takes its first document.
            let inner = dispatch.lock();
            assert!(inner.staged);
            assert!(inner.doc.is_none());
            assert!(inner.apps.is_empty());
            assert!(inner.shared.kept.is_empty());
            assert!(inner.shared.connect.is_empty());
            assert_eq!((inner.apps_version, inner.directory_version), (0, 0));
            // The Dispatch's configuration stays.
            assert_eq!(inner.uploads_per_app_per_hour, 7);
        }
        // The same enrollment again gets the same answer, and makes no further account.
        let (status, again) = enroll_at(&dispatch, &identity, &second_enrollment);
        assert_eq!((status, again), (200, second));
    }

    #[test]
    fn test_scripted_stale_enrollment_is_refused_before_it_is_looked_at() {
        // As at the service: an enrollment whose timestamp is more than 5 minutes from the
        // Dispatch's time is `401 stale_timestamp`, signed with the one key, whether it
        // is new or the Dispatch holds its answer (Dispatch wire 7.1, 7.4.1).
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let now = 1_700_000_000_000;
        let clock = Arc::new(crate::clock::TestClock::new(now));
        let dispatch =
            ScriptedDispatch::unenrolled_at(&identity, [2; 32], clock.clone(), DISPATCH_ORIGIN);
        let enrollment = enrollment_for(&dispatch, &identity, 1, None);
        let sent_at = |at: u64| {
            signed_request(
                &identity,
                "POST",
                "/v1/enroll",
                json!({ "enrollment": enrollment.signed() })
                    .to_string()
                    .into_bytes(),
                enrollment.body().intent.created(),
                at,
            )
        };
        let refused = |request: &crate::transport::Request, answer: &crate::transport::Response| {
            let body: Value = serde_json::from_slice(&answer.body).unwrap();
            let signature = pubky_dispatch_core::enc::unb64_array::<64>(
                answer
                    .header(pubky_dispatch_core::http::header::SERVICE_SIGNATURE)
                    .unwrap(),
            )
            .unwrap();
            let key = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
            let by_dispatch = pubky_dispatch_core::http::verify_response(
                &key.verifying_key().to_bytes(),
                &pubky_dispatch_core::http::ResponseParts {
                    status: answer.status,
                    request: crate::client::SentRequest::of(request).received(true),
                    server_time: answer
                        .header(pubky_dispatch_core::http::header::SERVER_TIME)
                        .unwrap(),
                    head: answer.header(pubky_dispatch_core::http::header::HEAD),
                    body: &answer.body,
                },
                &signature,
            )
            .is_ok();
            (
                answer.status,
                body["code"].as_str().map(str::to_owned),
                by_dispatch,
            )
        };
        let tolerance = pubky_dispatch_core::records::CLOCK_TOLERANCE_MS;
        let stale_request = sent_at(now - tolerance - 1_000);
        let stale = dispatch.handle(&stale_request).unwrap();
        assert_eq!(
            refused(&stale_request, &stale),
            (401, Some("stale_timestamp".into()), true)
        );
        assert!(dispatch.lock().enrolled.is_none(), "nothing was enrolled");
        // At the edge of the window it is taken.
        assert_eq!(
            dispatch.handle(&sent_at(now - tolerance)).unwrap().status,
            200
        );
        // The same enrollment once its timestamp is stale: its kept answer isn't given.
        clock.advance_ms(2_000);
        let again_request = sent_at(now - tolerance);
        let again = dispatch.handle(&again_request).unwrap();
        assert_eq!(
            refused(&again_request, &again),
            (401, Some("stale_timestamp".into()), true)
        );
    }

    #[test]
    fn test_scripted_recovery_in_place_keeps_the_one_key_and_the_held_app_ids() {
        // As at the service: an enrollment at a serving account names the one key and holds
        // the App IDs it names for the next generation, whose start refuses a document
        // listing one and then keeps them; every enrollment's kept answer stays (Dispatch
        // wire 3.3, 3.7).
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let dispatch = ScriptedDispatch::unenrolled_at(
            &identity,
            [2; 32],
            Arc::new(crate::clock::TestClock::new(0)),
            DISPATCH_ORIGIN,
        );
        let first_enrollment = enrollment_for(&dispatch, &identity, 1, None);
        let (status, first) = enroll_at(&dispatch, &identity, &first_enrollment);
        assert_eq!(status, 200);
        let key = |answer: &Value| answer["service_key"].as_str().unwrap().to_owned();
        let outgoing = key(&first);
        let service = dispatch.lock().service.verifying_key().to_bytes();
        let doc = IdentityDoc::sign(
            &identity,
            pubky_dispatch_core::records::IdentityBody::first(
                identity.public(),
                [3; 16],
                pubky_dispatch_core::records::Inbox::new(DISPATCH_ORIGIN, service),
                pubky_dispatch_core::records::IdentityPolicy::default(),
            ),
        )
        .unwrap();
        let delivery = json!({ "identity": doc.signed(), "prev": null }).to_string();
        assert_eq!(
            dispatch.lock().put_identity(delivery.as_bytes()).unwrap().0,
            200
        );
        let second_enrollment = enrollment_for(&dispatch, &identity, 2, Some(vec![[7; 16]]));
        let (status, second) = enroll_at(&dispatch, &identity, &second_enrollment);
        assert_eq!(status, 200);
        assert_eq!(key(&second), outgoing, "the one key at a serving account");
        assert_eq!(dispatch.lock().held_app_ids, vec![[7; 16]]);
        // The same enrollment again: its kept answer.
        let (status, replayed) = enroll_at(&dispatch, &identity, &second_enrollment);
        assert_eq!((status, replayed), (200, second.clone()));
        let mut body = doc.body().clone();
        body.version = 2;
        body.generation = 2;
        body.recovery_from = Some(1);
        // One listing an App ID held for the next generation is refused, as at the service.
        let mut listing = body.clone();
        listing.apps.push(pubky_dispatch_core::records::ListedApp {
            app_id: [7; 16],
            cert: [8; 32],
        });
        let listing = IdentityDoc::sign(&identity, listing).unwrap();
        let delivery = json!({ "identity": listing.signed(), "prev": null }).to_string();
        assert_eq!(
            dispatch.lock().put_identity(delivery.as_bytes()).unwrap().0,
            400
        );
        {
            let mut inner = dispatch.lock();
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
            dispatch.lock().put_identity(delivery.as_bytes()).unwrap().0,
            200
        );
        assert!(
            dispatch.kept_app_ids().contains(&[7; 16]),
            "the App ID held for the generation is kept"
        );
        assert_eq!(
            dispatch.mark().map(|(g, _, _)| g),
            Some(2),
            "the mark at its start"
        );
        // The upload limits and counts stay, as the service's do (Dispatch wire 9.4).
        {
            let inner = dispatch.lock();
            assert_eq!(inner.uploads_per_app_per_hour, 7);
            assert_eq!(inner.upload_counts.get(&[5; 16]), Some(&(1, 3)));
            // The directory's versions go on from where they stood: the account started
            // afresh never shows a version it showed before for another set of apps.
            assert_eq!(inner.apps_version, 4);
            assert!(inner.directory_version >= 9, "{}", inner.directory_version);
            // And so does what a test configured.
            assert_eq!((inner.feed_limit, inner.max_page_bytes), (Some(3), 4_096));
            assert!(inner.keep_passed && inner.open_admission);
            // Pending connect requests don't outlive it (Dispatch spec 12.6 step 1, wire 7.4.7).
            assert!(inner.shared.connect.is_empty());
        }
        let (status, again) = enroll_at(&dispatch, &identity, &first_enrollment);
        assert_eq!((status, again), (200, first));
    }

    #[test]
    fn test_scripted_erasure_naming_a_hash_with_no_identity_json_held_is_conflict() {
        // A fresh account holds no `identity.json`: a hash can't match, so the erasure is
        // `409 conflict` and erases nothing; a body without one erases it, writing the
        // erasure's record and deleting the mark (Dispatch wire 7.4.16, 7.3 Table 3).
        use pubky_dispatch_core::http::erase_body;
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let dispatch = ScriptedDispatch::new(
            &identity,
            [2; 32],
            Arc::new(crate::clock::TestClock::new(0)),
        );
        let mut inner = dispatch.lock();
        let created = Some(inner.creation_time());
        let erasure = |hash: Option<&[u8; 32]>| crate::transport::Request {
            method: "POST".into(),
            origin: DISPATCH_ORIGIN.into(),
            path_and_query: "/v1/x/erase".into(),
            headers: Vec::new(),
            body: erase_body(created, hash),
            timeout: crate::transport::TimeoutClass::Bulk,
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
        // `recovery_from` that isn't the generation less one is `400` (Dispatch wire 3.3, 7.4.2).
        use pubky_dispatch_core::records::{IdentityBody, IdentityPolicy, Inbox};
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let dispatch = ScriptedDispatch::new(
            &identity,
            [2; 32],
            Arc::new(crate::clock::TestClock::new(1_000)),
        );
        let mut inner = dispatch.lock();
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
        // call ends it with the `admission` transition, and again chains nothing (Dispatch
        // spec 12.6 step 2; wire 7.4.14).
        use pubky_dispatch_core::records::{IdentityBody, IdentityPolicy, Inbox, ListedApp};
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let dispatch = ScriptedDispatch::new(
            &identity,
            [2; 32],
            Arc::new(crate::clock::TestClock::new(1_000)),
        );
        let mut inner = dispatch.lock();
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
        let sig = pubky_dispatch_core::enc::b64(&[0u8; 64]);
        assert!(read_handover(&json!({ "envelopes": [], "sig": sig })).is_some());
        assert!(read_handover(&json!({ "envelopes": [], "sig": sig, "x": 1 })).is_none());
    }

    fn recovery_beside_earlier_chain(generation: u64) -> (Arc<ScriptedDispatch>, Vec<u8>) {
        use pubky_dispatch_core::{
            keys::IdentityKey,
            records::{IdentityBody, IdentityPolicy, Inbox},
        };
        let identity = IdentityKey::from_secret([1; 32]);
        let dispatch = ScriptedDispatch::new(&identity, [2; 32], Arc::new(TestClock::new(1_000)));
        let mut inner = dispatch.lock();
        let first = IdentityDoc::sign(
            &identity,
            IdentityBody::first(
                identity.public(),
                [3; 16],
                Inbox::new(DISPATCH_ORIGIN, inner.service.verifying_key().to_bytes()),
                IdentityPolicy::default(),
            ),
        )
        .unwrap();
        let delivery = |doc: &IdentityDoc| {
            IdentityDelivery {
                identity: doc.signed().clone(),
                prev: None,
            }
            .to_json()
        };
        assert_eq!(inner.put_identity(&delivery(&first)).unwrap().0, 200);
        let mut newer = first.body().clone();
        newer.version += 1;
        newer.generation = 3;
        newer.recovery_from = Some(2);
        let newer = IdentityDoc::sign(&identity, newer).unwrap();
        // A valid current document restored beside its earlier chain (Dispatch wire 7.3).
        inner.doc = Some(newer.clone());
        inner.marks.slot = super::super::marks::MarkSlot::Missing;
        let mut candidate = newer.body().clone();
        candidate.version += 1;
        candidate.generation = generation;
        candidate.recovery_from = Some(generation - 1);
        let candidate = IdentityDoc::sign(&identity, candidate).unwrap();
        drop(inner);
        (dispatch, delivery(&candidate))
    }

    #[test]
    fn test_scripted_recovery_route_uses_held_document_floor() {
        for generation in [2, 3] {
            let (dispatch, body) = recovery_beside_earlier_chain(generation);
            let mut inner = dispatch.lock();
            let request = crate::transport::Request {
                method: "PUT".into(),
                origin: DISPATCH_ORIGIN.into(),
                path_and_query: "/v1/alice/identity".into(),
                headers: Vec::new(),
                body,
                timeout: crate::transport::TimeoutClass::Bulk,
            };
            let answer = inner.step_two(&request).expect("recovery notice");
            let body: Value = serde_json::from_slice(&answer.body).unwrap();
            assert_eq!(answer.status, 503);
            assert_eq!(body["code"], "recovery_required");
            assert_eq!(
                body["current"],
                json!({"generation":1,"reason":"mark_lost","permanent":false})
            );
            assert_eq!(inner.doc.as_ref().unwrap().generation(), 3);
        }
    }

    #[test]
    fn test_scripted_recovery_write_uses_held_document_floor() {
        for generation in [2, 3] {
            let (dispatch, body) = recovery_beside_earlier_chain(generation);
            let mut inner = dispatch.lock();
            let tip = inner.tip;
            let (status, answer) = inner.put_identity(&body).unwrap();
            assert_eq!(status, 503);
            assert_eq!(answer["code"], "recovery_required");
            assert_eq!(
                answer["current"],
                json!({"generation":1,"reason":"mark_lost","permanent":false})
            );
            assert_eq!(inner.doc.as_ref().unwrap().generation(), 3);
            assert_eq!(inner.tip, tip);
            assert_eq!(inner.marks.slot, super::super::marks::MarkSlot::Missing);
        }
    }

    #[test]
    fn test_scripted_recovery_above_held_document_remains_available() {
        let (dispatch, body) = recovery_beside_earlier_chain(4);
        let mut inner = dispatch.lock();
        let request = crate::transport::Request {
            method: "PUT".into(),
            origin: DISPATCH_ORIGIN.into(),
            path_and_query: "/v1/alice/identity".into(),
            headers: Vec::new(),
            body: body.clone(),
            timeout: crate::transport::TimeoutClass::Bulk,
        };
        assert!(inner.step_two(&request).is_none());
        assert_eq!(inner.put_identity(&body).unwrap().0, 200);
        assert_eq!(inner.doc.as_ref().unwrap().generation(), 4);
        assert_eq!((inner.tip.generation, inner.tip.seq), (4, 2));
    }
    fn retention_chain(
        dispatch: &ScriptedDispatch,
        identity: &pubky_dispatch_core::keys::IdentityKey,
        first_version: u64,
        count: u64,
    ) -> IdentityDoc {
        use pubky_dispatch_core::records::{IdentityBody, IdentityPolicy, Inbox};
        let mut body = dispatch.identity_doc().map_or_else(
            || {
                IdentityBody::first(
                    identity.public(),
                    [3; 16],
                    Inbox::new(DISPATCH_ORIGIN, dispatch.service_key()),
                    IdentityPolicy::default(),
                )
            },
            |doc| doc.body().clone(),
        );
        for version in first_version..first_version + count {
            body.version = version;
            let doc = IdentityDoc::sign(identity, body.clone()).unwrap();
            dispatch.deliver_identity(&doc).unwrap();
        }
        dispatch.identity_doc().unwrap()
    }

    fn retention_read(
        dispatch: &ScriptedDispatch,
        identity: &pubky_dispatch_core::keys::IdentityKey,
    ) {
        let (created, now) = {
            let inner = dispatch.lock();
            (inner.creation_time(), inner.now())
        };
        let request = signed_request(
            identity,
            "GET",
            &format!("/v1/{}/apps", identity.id()),
            vec![],
            Some(created),
            now,
        );
        assert_eq!(dispatch.handle(&request).unwrap().status, 200);
    }

    #[test]
    fn test_scripted_retention_after_creation_keeps_the_configured_sweep() {
        use super::super::Retention;
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let clock = Arc::new(TestClock::new(crate::testing::START_MS));
        let dispatch = ScriptedDispatch::unenrolled_at(
            &identity,
            [2; 32],
            Arc::clone(&clock),
            DISPATCH_ORIGIN,
        );
        dispatch.set_retention(Some(Retention {
            checkpoint_behind: 3,
            per_request: 8,
            ..Retention::default()
        }));
        let enrollment = enrollment_for(&dispatch, &identity, 1, None);
        assert_eq!(enroll_at(&dispatch, &identity, &enrollment).0, 200);
        retention_chain(&dispatch, &identity, 1, 12);
        clock.advance_ms(31 * 24 * 60 * 60 * 1_000);
        retention_read(&dispatch, &identity);
        let (checkpoint, through) = dispatch.retained();
        assert_eq!(
            through, 8,
            "the first request prunes only its configured budget"
        );
        assert_eq!(checkpoint.unwrap().seq, 8);
        retention_read(&dispatch, &identity);
        let (checkpoint, through) = dispatch.retained();
        assert_eq!(
            through, 11,
            "the next request prunes the remaining old stubs"
        );
        assert_eq!(checkpoint.unwrap().seq, 11);
        assert_eq!(dispatch.tip_seq(), 12, "the head remains");
    }

    #[test]
    fn test_scripted_retention_after_erasure_keeps_disabled_sweeps() {
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let clock = Arc::new(TestClock::new(crate::testing::START_MS));
        let dispatch = ScriptedDispatch::unenrolled_at(
            &identity,
            [2; 32],
            Arc::clone(&clock),
            DISPATCH_ORIGIN,
        );
        dispatch.set_retention(None);
        let enrollment = enrollment_for(&dispatch, &identity, 1, None);
        assert_eq!(enroll_at(&dispatch, &identity, &enrollment).0, 200);
        let doc = retention_chain(&dispatch, &identity, 1, 1);
        let created = dispatch.lock().creation_time();
        let erase = signed_request(
            &identity,
            "POST",
            &format!("/v1/{}/erase", identity.id()),
            pubky_dispatch_core::http::erase_body(Some(created), Some(&doc.hash())),
            Some(created),
            clock.now_ms(),
        );
        assert_eq!(dispatch.handle(&erase).unwrap().status, 200);
        assert!(dispatch.erased());
        assert_eq!(dispatch.lock().retention, None);
        clock.advance_ms(1);
        let enrollment = enrollment_for(&dispatch, &identity, 2, None);
        assert_eq!(enroll_at(&dispatch, &identity, &enrollment).0, 200);
        assert!(!dispatch.erased());
        assert!(dispatch.identity_doc().is_none());
        assert_eq!(dispatch.tip_seq(), 0);
        assert_eq!(dispatch.lock().retention, None);
        retention_chain(&dispatch, &identity, 1, 1_002);
        clock.advance_ms(31 * 24 * 60 * 60 * 1_000);
        retention_read(&dispatch, &identity);
        assert_eq!(dispatch.retained(), (None, 0));
        assert_eq!(dispatch.tip_seq(), 1_002);
    }

    #[test]
    fn test_scripted_retention_after_recovery_keeps_the_configured_sweep() {
        use super::super::Retention;
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let clock = Arc::new(TestClock::new(crate::testing::START_MS));
        let dispatch = ScriptedDispatch::unenrolled_at(
            &identity,
            [2; 32],
            Arc::clone(&clock),
            DISPATCH_ORIGIN,
        );
        let enrollment = enrollment_for(&dispatch, &identity, 1, None);
        assert_eq!(enroll_at(&dispatch, &identity, &enrollment).0, 200);
        let doc = retention_chain(&dispatch, &identity, 1, 1);
        // Set the configuration after creation so this exercises the generation reset.
        dispatch.set_retention(Some(Retention {
            checkpoint_behind: 3,
            per_request: 8,
            ..Retention::default()
        }));
        let mut body = doc.body().clone();
        body.version = 2;
        body.generation = 2;
        body.recovery_from = Some(1);
        let recovery = IdentityDoc::sign(&identity, body).unwrap();
        let delivery = signed_request(
            &identity,
            "PUT",
            &format!("/v1/{}/identity", identity.id()),
            json!({ "identity": recovery.signed(), "prev": b64(&doc.hash()) })
                .to_string()
                .into_bytes(),
            Some(dispatch.lock().creation_time()),
            clock.now_ms(),
        );
        let response = dispatch.handle(&delivery).unwrap();
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        assert_eq!((dispatch.generation(), dispatch.tip_seq()), (2, 2));
        retention_chain(&dispatch, &identity, 3, 10);
        clock.advance_ms(31 * 24 * 60 * 60 * 1_000);
        retention_read(&dispatch, &identity);
        let (checkpoint, through) = dispatch.retained();
        assert_eq!(through, 8);
        assert_eq!(
            (checkpoint.unwrap().generation, dispatch.generation()),
            (2, 2)
        );
        assert_eq!(dispatch.tip_seq(), 12);
    }
}
