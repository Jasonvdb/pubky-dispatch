//! Unsigned protocol members retained with their expiry asks (Switch spec 4.2).

use std::collections::BTreeMap;

use pubky_switch_core::json::check_json;
use pubky_switch_core::ops::MAX_OP_BYTES;
use pubky_switch_core::records::AppRecord;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::next_body::NextBody;
use super::own_record::{RecordExpiries, RecordExpiry};
use super::protocols::ProtocolSet;
use super::state::key;
use super::{App, AppError, Refusal};

/// A registered protocol's desired record member and its own expiry policy.
/// This is local writer state, not evidence that the Switch or Homeserver accepted it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolRecord {
    /// The desired member; `None` removes it.
    pub member: Option<Map<String, Value>>,
    /// This owner's policy, independently of any earlier expiry another owner asks for.
    pub expiry: RecordExpiry,
    /// An unsigned member edit of this run is retained. A later signature in this run
    /// applies it or waits; the next load or restore holds it aside
    /// ([`super::AppEvent::RecordEditsHeld`], [`App::held_record_edit`]). `false` does not establish delivery; use
    /// the publication result for that.
    pub pending: bool,
}

/// An unsigned edit of a protocol's member held aside ([`App::held_record_edit`]).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct HeldRecordEdit {
    /// The member asked for; `None` removes it.
    pub member: Option<Map<String, Value>>,
    /// The expiry policy asked with it.
    pub expiry: RecordExpiry,
    /// Whether it asked to renew the record with the member as it was.
    pub renew: bool,
}

/// The unsigned edits an earlier run or a backup left, held aside: one key a protocol
/// (`rheld/<protocol>`), so each is read, written and cleared alone and none grows a
/// value with the others, and the accepted kinds one asked for (`rhelda`). No signing
/// code reads them.
#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct HeldEdits {
    pub members: BTreeMap<String, HeldRecordEdit>,
    pub accepts: Option<Vec<String>>,
}

impl HeldEdits {
    pub fn is_empty(&self) -> bool {
        self.members.is_empty() && self.accepts.is_none()
    }

    /// Keep only what the app could hold as an edit now: the members of registered
    /// protocols, and of the accepted kinds asked those a registered protocol owns. So
    /// nothing held aside can fail a backup's check or its restore.
    pub fn fit(mut self, protocols: &ProtocolSet) -> Self {
        self.members.retain(|name, _| protocols.contains(name));
        if let Some(kinds) = &mut self.accepts {
            kinds.retain(|kind| protocols.of_kind(kind).is_some());
        }
        self
    }

    /// What the store `reader` holds aside, as it fits `protocols` now.
    pub async fn read(
        reader: &super::state::Reader,
        protocols: &ProtocolSet,
    ) -> Result<Self, AppError> {
        let held = Self {
            members: reader
                .scan::<HeldRecordEdit>(key::RECORD_HELD_PREFIX)
                .await?
                .into_iter()
                .collect(),
            accepts: reader.get(key::RECORD_HELD_ACCEPTS).await?,
        };
        Ok(held.fit(protocols))
    }

    /// Put these over what the store holds aside, in `tx`: each member under its own key.
    pub fn put(&self, tx: &mut super::state::Tx) -> Result<(), AppError> {
        for (name, edit) in &self.members {
            tx.put(&held_key(name), edit)?;
        }
        if let Some(kinds) = &self.accepts {
            tx.put(key::RECORD_HELD_ACCEPTS, kinds)?;
        }
        Ok(())
    }

    /// The part of these the store didn't hold `before`, as they are: what a hold tells.
    pub fn since(&self, before: &Self) -> Self {
        Self {
            members: self
                .members
                .iter()
                .filter(|(name, edit)| before.members.get(*name) != Some(*edit))
                .map(|(name, edit)| (name.clone(), edit.clone()))
                .collect(),
            accepts: self
                .accepts
                .clone()
                .filter(|_| self.accepts != before.accepts),
        }
    }
}

fn held_key(protocol: &str) -> String {
    format!("{}{protocol}", key::RECORD_HELD_PREFIX)
}

/// Absence means no edit; a present `None` is an explicit removal. The matching policy
/// lives in `RECORD_EXPIRIES`, changed in the same transaction, never copied here.
pub(super) type RecordMembers = BTreeMap<String, Option<Map<String, Value>>>;

/// The unsigned choices share one row. Protocol names cannot start with an underscore,
/// so `_changes` is never a member's owner.
#[derive(Clone, Default, Deserialize, Serialize)]
pub(super) struct RecordEdits {
    #[serde(flatten)]
    pub members: RecordMembers,
    #[serde(
        rename = "_changes",
        default,
        skip_serializing_if = "RecordChanges::is_empty"
    )]
    pub changes: RecordChanges,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct RecordChanges {
    pub accepts: Option<Vec<String>>,
    pub policies: BTreeMap<String, PendingPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct PendingPolicy {
    /// The owner's policy before the first unsigned change, restored if the edit lapses.
    pub previous: Option<RecordExpiry>,
    pub renew: bool,
}

impl RecordChanges {
    pub fn is_empty(&self) -> bool {
        self.accepts.is_none() && self.policies.is_empty()
    }
}

impl RecordEdits {
    pub fn is_empty(&self) -> bool {
        self.members.is_empty() && self.changes.accepts.is_none()
    }

    /// `expiries` as the signed record has them: each policy an edit changed goes back to
    /// the one before its first unsigned change.
    pub fn without(&self, mut expiries: RecordExpiries) -> RecordExpiries {
        for (name, policy) in &self.changes.policies {
            match policy.previous {
                Some(previous) => expiries.insert(name.clone(), previous),
                None => expiries.remove(name),
            };
        }
        expiries
    }

    /// Put these edits in `held`, over what it holds, each with the expiry `expiries`
    /// gives its owner: the one it asked.
    pub fn hold(&self, expiries: &RecordExpiries, held: &mut HeldEdits) {
        for (name, member) in &self.members {
            let edit = HeldRecordEdit {
                member: member.clone(),
                expiry: expiries.get(name).copied().unwrap_or(RecordExpiry::Never),
                renew: self.changes.policies.get(name).is_some_and(|p| p.renew),
            };
            held.members.insert(name.clone(), edit);
        }
        if let Some(accepts) = &self.changes.accepts {
            held.accepts = Some(accepts.clone());
        }
    }

    pub fn renews(&self) -> bool {
        self.changes.policies.values().any(|policy| policy.renew)
    }

    pub fn apply(&self, body: &mut NextBody) {
        for (name, member) in &self.members {
            body.set_member(name.clone(), member.clone());
        }
        if let Some(accepts) = &self.changes.accepts {
            body.set_accepts(accepts.clone());
        }
    }
}

pub(super) fn check_members(edits: &RecordEdits, protocols: &ProtocolSet) -> Result<(), AppError> {
    let invalid = || Refusal::Usage("the pending record members are invalid or too large".into());
    let members = &edits.members;
    if members.keys().any(|name| !protocols.contains(name))
        // Every member edit is written with the policy it changes.
        || members
            .keys()
            .any(|name| !edits.changes.policies.contains_key(name))
        || edits.changes.policies.iter().any(|(name, policy)| {
            !members.contains_key(name) || policy.previous.is_some_and(|p| !p.valid())
        })
        || edits
            .changes
            .accepts
            .as_ref()
            .is_some_and(|kinds| kinds.iter().any(|kind| protocols.of_kind(kind).is_none()))
    {
        return Err(invalid().into());
    }
    let bytes = serde_json::to_vec(members).map_err(|_| invalid())?;
    if bytes.len() > MAX_OP_BYTES {
        return Err(invalid().into());
    }
    // Check at the depth a record gives the member, including the protocols object.
    let bytes =
        serde_json::to_vec(&serde_json::json!({ "protocols": members })).map_err(|_| invalid())?;
    check_json(&bytes).map_err(|_| invalid())?;
    Ok(())
}

/// Check the unsigned edits a backup carries, each on its own: they are held aside, never
/// signed together, so each member is bounded alone, and a policy without its member or a
/// name twice is refused as in a pending row.
pub(super) fn check_carried(edits: &RecordEdits, protocols: &ProtocolSet) -> Result<(), AppError> {
    let mut rest = edits.changes.clone();
    for (name, member) in &edits.members {
        let mut one = RecordEdits::default();
        one.members.insert(name.clone(), member.clone());
        if let Some(policy) = rest.policies.remove(name) {
            one.changes.policies.insert(name.clone(), policy);
        }
        check_members(&one, protocols)?;
    }
    // What is left: the accepted kinds, and any policy without a member, which is refused.
    check_members(
        &RecordEdits {
            members: RecordMembers::new(),
            changes: rest,
        },
        protocols,
    )
}

impl App {
    /// Move, at a load, the unsigned record edits an earlier run kept out of the signing
    /// path: held aside (`rheld`), their expiry policies put back as the signed record has
    /// them, and the protocols told in the same commit
    /// ([`super::AppEvent::RecordEditsHeld`]). No signing code reads what is held aside.
    ///
    /// The row is read as it is, unchecked: an edit that no longer fits what is registered
    /// is held like any other, and never fails the load.
    pub(super) async fn hold_earlier_record_edits(&mut self) -> Result<(), AppError> {
        let reader = self.reader();
        let Some(edits) = reader.get::<RecordEdits>(key::RECORD_MEMBERS).await? else {
            return Ok(());
        };
        // A member edit without the policy it changed is a row no writer produces: its
        // expiry couldn't be put back.
        if edits
            .members
            .keys()
            .any(|name| !edits.changes.policies.contains_key(name))
        {
            return Err(super::corrupt());
        }
        let expiries: RecordExpiries = reader.get(key::RECORD_EXPIRIES).await?.unwrap_or_default();
        let before = HeldEdits::read(&reader, &self.protocols).await?;
        let mut held = HeldEdits::default();
        edits.hold(&expiries, &mut held);
        let held = held.fit(&self.protocols);
        let mut tx = self.tx()?;
        tx.put(key::RECORD_EXPIRIES, &edits.without(expiries))?;
        tx.delete(key::RECORD_MEMBERS)?;
        self.keep_held_record_edits(&mut tx, &held.since(&before))?;
        self.commit(tx).await
    }

    /// Put `held`, the edits newly held aside, over what the store holds, in `tx`, and
    /// keep [`super::AppEvent::RecordEditsHeld`] for them: for the protocols they name,
    /// and for every protocol when they hold a change of the accepted kinds. An edit the
    /// store held already, unchanged, is told no second time.
    pub(super) fn keep_held_record_edits(
        &mut self,
        tx: &mut super::state::Tx,
        held: &HeldEdits,
    ) -> Result<(), AppError> {
        if held.is_empty() {
            return Ok(());
        }
        held.put(tx)?;
        let protocols: Vec<String> = held.members.keys().cloned().collect();
        let accepts = held.accepts.is_some();
        let to = if accepts {
            self.protocols.names()
        } else {
            protocols.clone()
        };
        self.keep_duty_for(
            tx,
            to,
            super::events::Duty::RecordEditsHeld { protocols, accepts },
        )
    }

    /// The unsigned edit of `protocol`'s member that an earlier run or a backup left, held
    /// aside at this store's load or restore ([`super::AppEvent::RecordEditsHeld`]): the
    /// member it asked for, or its removal, with the expiry it asked. Nothing signs it: the
    /// protocol submits it again if it still wants it, and clears it once it has decided
    /// ([`App::clear_held_record_edit`]). A later unsigned edit of the same protocol held
    /// aside replaces it; an entry goes with its protocol's retirement only once cleared.
    ///
    /// To submit it again: [`App::set_protocol_member_with_expiry`] with its `member` and
    /// `expiry`, which signs when either differs from the record's. When `renew` is set
    /// and that call signed nothing, the member and policy being the record's already, the
    /// renewal is asked with the same policy: [`App::renew_record`] for
    /// [`RecordExpiry::Never`] (`None`) and [`RecordExpiry::At`], and
    /// [`App::renew_record_with_lifetime`] for [`RecordExpiry::Lifetime`].
    ///
    /// # Errors
    ///
    /// An unknown protocol, a stopped app, or a store failure.
    pub async fn held_record_edit(
        &mut self,
        protocol: &str,
    ) -> Result<Option<HeldRecordEdit>, AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        self.check_registered(protocol)?;
        self.reader().get(&held_key(protocol)).await
    }

    /// The change of the record's accepted kinds held aside as [`App::held_record_edit`]
    /// holds a member's: the kinds an earlier run asked for, those a registered protocol
    /// still owns. [`App::update_accepts`] signs what the registration gives now.
    ///
    /// # Errors
    ///
    /// A stopped app, or a store failure.
    pub async fn held_accepts(&mut self) -> Result<Option<Vec<String>>, AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        Ok(HeldEdits::read(&self.reader(), &self.protocols)
            .await?
            .accepts)
    }

    /// Forget the edit held aside for `protocol` ([`App::held_record_edit`]); nothing
    /// changes when none is held.
    ///
    /// # Errors
    ///
    /// An unknown protocol, a stopped app, or a store failure.
    pub async fn clear_held_record_edit(&mut self, protocol: &str) -> Result<(), AppError> {
        if self.held_record_edit(protocol).await?.is_none() {
            return Ok(());
        }
        let mut tx = self.tx()?;
        tx.delete(&held_key(protocol))?;
        self.commit(tx).await
    }

    /// Forget the change of the accepted kinds held aside ([`App::held_accepts`]).
    ///
    /// # Errors
    ///
    /// A stopped app, or a store failure.
    pub async fn clear_held_accepts(&mut self) -> Result<(), AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        if !self.reader().exists(key::RECORD_HELD_ACCEPTS).await? {
            return Ok(());
        }
        let mut tx = self.tx()?;
        tx.delete(key::RECORD_HELD_ACCEPTS)?;
        self.commit(tx).await
    }

    /// What a backup carries of unsigned edits: this run's, and under them those held
    /// aside, in the form a pending edit has (the expiry asked in the policies, the signed
    /// one as its `previous`). Every restore holds them aside.
    pub(super) async fn carried_record_edits(
        &self,
    ) -> Result<(RecordEdits, RecordExpiries), AppError> {
        let mut edits = self.record_members().await?;
        let mut expiries = self.record_expiries().await?;
        let held = HeldEdits::read(&self.reader(), &self.protocols).await?;
        for (name, edit) in held.members {
            if edits.members.contains_key(&name) {
                continue;
            }
            let policy = PendingPolicy {
                previous: expiries.get(&name).copied(),
                renew: edit.renew,
            };
            edits.changes.policies.insert(name.clone(), policy);
            expiries.insert(name.clone(), edit.expiry);
            edits.members.insert(name, edit.member);
        }
        if edits.changes.accepts.is_none() {
            edits.changes.accepts = held.accepts;
        }
        Ok((edits, expiries))
    }

    /// Read the desired member and typed expiry of a registered owner, including an
    /// unsigned change this run retains (Switch spec 4.2). The held signed record
    /// remains available separately through [`App::record`].
    ///
    /// # Errors
    ///
    /// An unknown owner, a stopped app, or a store or retained-state failure. An unsigned
    /// edit is reported as pending, never as published.
    pub async fn protocol_record(&mut self, protocol: &str) -> Result<ProtocolRecord, AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        self.check_registered(protocol)?;
        let edits = self.record_members().await?;
        let expiries = self.record_expiries().await?;
        let held = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
        Ok(ProtocolRecord {
            member: edits
                .members
                .get(protocol)
                .cloned()
                .unwrap_or_else(|| held.body().protocols.get(protocol).cloned()),
            expiry: expiries
                .get(protocol)
                .copied()
                .unwrap_or(RecordExpiry::Never),
            pending: edits.members.contains_key(protocol),
        })
    }

    pub(super) async fn record_members(&self) -> Result<RecordEdits, AppError> {
        let edits = self
            .reader()
            .get(key::RECORD_MEMBERS)
            .await?
            .unwrap_or_default();
        self.check_record_members(&edits)
            .map_err(|_| super::corrupt())?;
        let expiries = self.record_expiries().await?;
        if edits
            .members
            .keys()
            .any(|name| !expiries.contains_key(name))
        {
            return Err(super::corrupt());
        }
        Ok(edits)
    }

    pub(super) fn check_record_members(&self, members: &RecordEdits) -> Result<(), AppError> {
        check_members(members, &self.protocols)
    }
}
