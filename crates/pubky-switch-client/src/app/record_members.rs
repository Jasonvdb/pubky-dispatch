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
    /// An unsigned member edit is retained. A later signature must apply it or wait.
    /// `false` does not establish delivery; use the publication result for that.
    pub pending: bool,
}

/// Absence means no edit; a present `None` is an explicit removal. The matching policy
/// lives in `RECORD_EXPIRIES`, changed in the same transaction, never copied here.
pub(super) type RecordMembers = BTreeMap<String, Option<Map<String, Value>>>;

/// The unsigned choices share one row. Protocol names cannot start with an underscore,
/// so a row containing only the original member map still reads as the same edits.
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

impl App {
    /// Drop, at a load, the unsigned record edits an earlier run kept, with their expiry
    /// policies, and tell the protocols in the same commit ([`super::AppEvent::RecordEditsDropped`]).
    pub(super) async fn drop_earlier_record_edits(&mut self) -> Result<(), AppError> {
        let edits = self.record_members().await?;
        if edits.is_empty() {
            return Ok(());
        }
        let expiries = edits.without(self.record_expiries().await?);
        let mut tx = self.tx()?;
        tx.put(key::RECORD_EXPIRIES, &expiries)?;
        tx.delete(key::RECORD_MEMBERS)?;
        self.keep_record_edits_dropped(&mut tx, &edits)?;
        self.commit(tx).await
    }

    /// Keep [`super::AppEvent::RecordEditsDropped`] for `edits`, in `tx`: for the registered
    /// protocols they name, and for every protocol when they change the accepted kinds.
    pub(super) fn keep_record_edits_dropped(
        &mut self,
        tx: &mut super::state::Tx,
        edits: &RecordEdits,
    ) -> Result<(), AppError> {
        let protocols: Vec<String> = edits
            .members
            .keys()
            .filter(|name| self.protocols.contains(name))
            .cloned()
            .collect();
        let accepts = edits.changes.accepts.is_some();
        if protocols.is_empty() && !accepts {
            return Ok(());
        }
        let to = if accepts {
            self.protocols.names()
        } else {
            protocols.clone()
        };
        self.keep_duty_for(
            tx,
            to,
            super::events::Duty::RecordEditsDropped { protocols, accepts },
        )
    }

    /// Read the desired member and typed expiry of a registered owner, including an
    /// unsigned change retained across reopen (Switch spec 4.2). The held signed record
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
