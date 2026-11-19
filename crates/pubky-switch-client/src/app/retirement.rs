//! Remove one idle registration at an app upgrade (Switch spec 3.3, 4.2 and 12.4).

use super::feed::{DENY_GAP, OwedGap};
use super::next_body::NextBody;
use super::own_record::RecordExpiry;
use super::records::{LIST_DUE, ListDue};
use super::state::{JoinStep, key};
use super::{App, AppError, Refusal};

fn busy(name: &str, action: &str) -> AppError {
    Refusal::NotNow(format!("to retire `{name}`, {action}")).into()
}

impl App {
    /// Retire one idle protocol from this installation. Open the app with its full set
    /// and serialize access to its store. Success records the smaller set and any owed
    /// app-record change together. Load with the remaining protocols and call
    /// [`App::receive`] to finish delivery. Earlier layered backups need the old set.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an unknown name, the final protocol or a certificate
    /// with an unowned root. [`Refusal::NotNow`] names work to finish with the original
    /// registration. A refusal leaves the original roster in the store.
    pub async fn retire_protocol(mut self, name: &str) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.check_registered(name)?;
            let remaining = self.protocols.without(name)?;
            remaining.check_cert(&self.state.cert)?;
            remaining.check_own_certificate(&self.state.cert)?;
            if let Some(cert) = &self.state.renewal {
                remaining.check_cert(cert)?;
                remaining.check_own_certificate(cert)?;
            }
            let reader = self.reader();
            let mut names: Vec<String> = reader
                .get(key::PROTOCOLS)
                .await?
                .ok_or_else(super::missing)?;
            super::check_protocol_names(&names, &self.protocols)?;
            if self.state.join != JoinStep::Done
                || self.reconcile_mode()
                || self.loss_record().await?.is_some_and(|loss| !loss.done())
                || reader.exists(super::provider::keys::MOVE).await?
            {
                return Err(busy(
                    name,
                    "finish joining, reconciliation or the provider change",
                ));
            }
            self.check_retirement_work(name).await?;

            let mut body = NextBody::held(&self.state)?;
            if body.body().protocols.contains_key(name) {
                return Err(busy(name, "remove its published protocol member"));
            }
            let mut expiries = self.record_expiries().await?;
            if expiries
                .get(name)
                .is_some_and(|policy| *policy != RecordExpiry::Never)
            {
                return Err(busy(name, "clear its record expiry"));
            }
            let had_expiry = expiries.remove(name).is_some();
            if self.state.pending_record.is_some() || self.state.pending_publish.is_some() {
                return Err(busy(name, "finish publishing the pending app record"));
            }
            let accepts: Vec<_> = body
                .body()
                .accepts
                .iter()
                .filter(|kind| self.protocols.of_kind(kind).is_none_or(|r| r.name != name))
                .cloned()
                .collect();
            let record = if accepts != body.body().accepts || self.record_needs_new_delivery() {
                body.set_accepts(accepts);
                let at = self.next_record_time(body.body().updated_at).await?;
                Some(self.sign_record_at(body, &expiries, at)?)
            } else {
                None
            };
            let mut tx = self.tx()?;
            if let Some(record) = record {
                self.stage_own_record(&record, &mut tx)?;
            }
            if had_expiry {
                tx.put(key::RECORD_EXPIRIES, &expiries)?;
            }
            // These receipts accompany only this owner's completed local writes. A
            // live deletion or settlement still needs its owner and was checked above.
            for receipt in self
                .state
                .deletion_receipts
                .values()
                .filter(|r| r.owner == name)
            {
                tx.delete(&receipt.store_key())?;
            }
            names.retain(|registered| registered != name);
            tx.put(key::PROTOCOLS, &names)?;
            tx.delete(&format!("{}{name}", super::order::TOLD_PREFIX))?;
            tx.delete(&super::recovery::keys::checkpoint(name))?;
            self.commit(tx).await
        })
        .await
    }

    async fn check_retirement_work(&self, name: &str) -> Result<(), AppError> {
        let prefix = [
            super::state::PROTOCOL_PREFIX,
            &super::protocols::qualified_key(name, b""),
        ]
        .concat();
        if !self
            .env
            .store
            .scan(&self.ns, &prefix, None, 1)
            .await?
            .is_empty()
        {
            return Err(busy(name, "finish and clear its local state"));
        }
        let reader = self.reader();
        if self
            .kept_duties_owned()
            .await?
            .iter()
            .any(|d| d.owners.iter().any(|n| n == name))
        {
            return Err(busy(name, "handle and acknowledge its outstanding events"));
        }
        if self
            .owed_calls()
            .await?
            .iter()
            .any(|(_, call)| call.to.iter().any(|n| n == name))
            || reader
                .get::<ListDue>(LIST_DUE)
                .await?
                .is_some_and(|due| due.at(name).is_some())
            || reader
                .get::<OwedGap>(DENY_GAP)
                .await?
                .is_some_and(|gap| gap.to.iter().any(|n| n == name))
        {
            return Err(busy(
                name,
                "finish its outstanding feed callbacks and listings",
            ));
        }
        let owned = |kind: &str| self.protocols.of_kind(kind).is_some_and(|r| r.name == name);
        if self
            .state
            .held
            .keys()
            .any(|seq| !self.state.seen.contains(seq))
            || self
                .state
                .pending_effect
                .as_ref()
                .is_some_and(|effect| owned(&effect.kind))
            || self.state.parked.values().any(|entry| {
                super::protocols::kind_of_plaintext(&entry.plaintext)
                    .is_none_or(|kind| owned(&kind))
            })
        {
            return Err(busy(
                name,
                "resolve held feed entries and its parked messages",
            ));
        }
        if self.state.deletions.values().any(|v| v.owner == name)
            || self
                .state
                .put_backs
                .values()
                .any(|v| v.observation.owner == name)
        {
            return Err(busy(name, "finish its record settlements"));
        }
        if self.owes_record_reread(name).await? {
            return Err(busy(
                name,
                "let the app finish reading records marked by an upload",
            ));
        }
        if self
            .kept_batches()
            .await?
            .iter()
            .any(|(_, b)| b.protocol.as_deref() == Some(name))
            || self.has_retained_messages_for(name).await?
        {
            return Err(busy(
                name,
                "finish its saved batches and deliveries and let sent copies expire",
            ));
        }
        Ok(())
    }
}
