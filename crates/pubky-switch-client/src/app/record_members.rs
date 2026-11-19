//! Unsigned protocol members retained with their expiry asks (Switch spec 4.2).

use std::collections::BTreeMap;

use pubky_switch_core::json::check_json;
use pubky_switch_core::ops::MAX_OP_BYTES;
use pubky_switch_core::records::AppRecord;
use serde_json::{Map, Value};

use super::next_body::NextBody;
use super::own_record::RecordExpiry;
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

pub(super) fn check_members(
    members: &RecordMembers,
    protocols: &ProtocolSet,
) -> Result<(), AppError> {
    let invalid = || Refusal::Usage("the pending record members are invalid or too large".into());
    if members.keys().any(|name| !protocols.contains(name)) {
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
        let members = self.record_members().await?;
        let expiries = self.record_expiries().await?;
        let held = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
        Ok(ProtocolRecord {
            member: members
                .get(protocol)
                .cloned()
                .unwrap_or_else(|| held.body().protocols.get(protocol).cloned()),
            expiry: expiries
                .get(protocol)
                .copied()
                .unwrap_or(RecordExpiry::Never),
            pending: members.contains_key(protocol),
        })
    }

    pub(super) async fn record_members(&self) -> Result<RecordMembers, AppError> {
        let members = self
            .reader()
            .get(key::RECORD_MEMBERS)
            .await?
            .unwrap_or_default();
        self.check_record_members(&members)
            .map_err(|_| super::corrupt())?;
        let expiries = self.record_expiries().await?;
        if members.keys().any(|name| !expiries.contains_key(name)) {
            return Err(super::corrupt());
        }
        Ok(members)
    }

    pub(super) fn check_record_members(&self, members: &RecordMembers) -> Result<(), AppError> {
        check_members(members, &self.protocols)
    }

    pub(super) async fn apply_record_members(&self, body: &mut NextBody) -> Result<bool, AppError> {
        let members = self.record_members().await?;
        let pending = !members.is_empty();
        for (name, member) in members {
            body.set_member(name, member);
        }
        Ok(pending)
    }
}
