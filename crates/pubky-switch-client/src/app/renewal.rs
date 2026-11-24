//! Certificate renewal, the app's side (Switch spec 3.2 steps 3 and 4; Switch wire 3.8).
//!
//! The signer stores the app's renewed certificate at the service (`cert.put`, in the
//! feed), then delivers an `identity.json` listing its hash. The app keeps the certificate
//! from `cert.put` and takes it once its own `identity.json` lists it: it presents it from
//! then on, and delivers its record carrying it (`app.put`), signed once and kept before it
//! is sent. An app without the `cert.put`, such as one restored from a backup older than
//! the renewal, or one that was offline while another device of the app took the renewal
//! and put its record (the feed then shows the `cert.put` only as a stub), takes the
//! listed certificate from its own record in its directory, under the checks of Switch
//! spec 3.2 step 3: after a restore, and at a read's start while its own `identity.json`
//! lists another certificate (Switch wire 7.2 "How an own app reads it").

use pubky_switch_core::chain::SignedHead;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{Condition, OpKind};
use pubky_switch_core::records::{AppCert, AppRecord, AppRecordBody, IdentityDoc, is_renewal};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use super::events::{AppEvent, Duty};
use super::next_body::{CertBody, NextBody};
use super::own_record::RecordExpiries;
use super::record_members::RecordMembers;
use super::state::{PendingRecord, Tx, key};
use super::{App, AppError, Publication};
use crate::client::Batch;
use crate::client::answers::Directory;
use crate::error::ClientError;

/// The signed renewal and the feed position at which its widening belongs. Its
/// listing can come later than the certificate itself (Switch spec 3.2, 8.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct KeptRenewal<C> {
    pub(crate) cert: C,
    pub(crate) at: (u64, u64),
}

impl KeptRenewal<AppCert> {
    pub(super) fn keep(&self, tx: &mut Tx) -> Result<(), AppError> {
        tx.put(
            key::CERT_RENEWAL,
            &KeptRenewal {
                cert: self.cert.signed(),
                at: self.at,
            },
        )
    }
}

impl App {
    pub(super) fn kept_renewal(&self) -> Option<&AppCert> {
        self.state.renewal.as_ref().map(|kept| &kept.cert)
    }

    /// A `cert.put` for this app seen in the feed: kept if it renews the certificate the
    /// app presents (the same App ID, signing key and bundle key, a later `issued_at`).
    pub(crate) fn note_renewal(
        &mut self,
        signed: &SignedDoc,
        at: (u64, u64),
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if let Some(cert) = self.renewal_from_feed(signed) {
            let renewal = KeptRenewal { cert, at };
            renewal.keep(tx)?;
            self.state.renewal = Some(renewal);
            self.events.push(AppEvent::RenewalSeen);
        }
        Ok(())
    }

    pub(super) fn renewal_from_feed(&self, signed: &SignedDoc) -> Option<AppCert> {
        let cert = AppCert::verify(signed, &self.state.meta.identity).ok()?;
        let newer_than_kept = self
            .kept_renewal()
            .is_none_or(|kept| cert.issued_at() > kept.issued_at());
        (is_renewal(&self.state.cert, &cert) && newer_than_kept).then_some(cert)
    }

    /// Take the kept renewal once the own `identity.json` lists it, and deliver the record
    /// carrying it. Returns whether the certificate changed.
    pub(crate) async fn adopt_renewal(&mut self, at: Option<(u64, u64)>) -> Result<bool, AppError> {
        let Some(renewal) = self.state.renewal.clone() else {
            return Ok(false);
        };
        self.take_listed_renewal(renewal.cert, at.unwrap_or(renewal.at))
            .await
    }

    pub(super) async fn take_listed_renewal(
        &mut self,
        renewal: AppCert,
        at: (u64, u64),
    ) -> Result<bool, AppError> {
        let me = self.state.meta.app_id;
        if self.state.own_doc.listed_cert(&me) != Some(renewal.hash()) {
            return Ok(false);
        }
        // One the protocols can't run with is refused before anything is built for it.
        if let Some(refusal) = self.protocols.certificate_refusal(&renewal) {
            self.refuse_cert(&renewal, refusal).await?;
            return Ok(false);
        }
        // Another device may have taken it first: its record is built on, not over.
        let later = match self.state.device.multi_device {
            true => Box::pin(self.later_under(&renewal)).await?,
            false => None,
        };
        let took = match later {
            Some(later) => Box::pin(self.take_later(renewal, later, Some(at))).await?,
            None => {
                let old = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
                let judged =
                    Box::pin(self.judge_for_cert(&renewal, old.updated_at(), None)).await?;
                Box::pin(self.take_cert(renewal, Taken::Judged(judged), None, Some(at))).await?
            }
        };
        if took {
            self.deliver_record().await?;
        }
        Ok(took)
    }

    /// The own record the switch's directory holds when it carries `cert`.
    async fn later_under(&mut self, cert: &AppCert) -> Result<Option<AppRecord>, AppError> {
        let result = self.client.directory(None).await;
        let me = self.state.meta.app_id;
        Ok(self
            .take(result)
            .await?
            .apps
            .into_iter()
            .find(|app| app.app_id == me)
            .map(|entry| entry.record)
            .filter(|record| record.cert().hash() == cert.hash()))
    }

    /// Take `cert` with `later`, the record of the app the switch holds under it, another
    /// device's: as it is ([`App::took_elsewhere`]), or, with a record change kept here,
    /// signed anew over it, later than both ([`NextBody::over`]).
    async fn take_later(
        &mut self,
        cert: AppCert,
        later: AppRecord,
        at: Option<(u64, u64)>,
    ) -> Result<bool, AppError> {
        if let Some(refusal) = self.protocols.certificate_refusal(&cert) {
            self.refuse_cert(&cert, refusal).await?;
            return Ok(false);
        }
        let taken = later.signed().clone();
        let record =
            if self.state.pending_record.is_some() || !self.record_members().await?.is_empty() {
                let old = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
                let previous = old.updated_at().max(later.updated_at());
                Taken::Judged(self.judge_for_cert(&cert, previous, Some(&later)).await?)
            } else {
                Taken::AsIs(taken.clone())
            };
        self.take_cert(cert, record, Some(taken), at).await
    }

    /// The record held, signed once under `cert`, a renewal about to be taken, later than
    /// `previous`, from the protocols' answers for it ([`CertBody::judged`]), with its
    /// `app.put`; nothing is kept here. A record whose `app.put` is over the operation size
    /// is an error, before anything changes.
    /// Built `over` a later record under `cert` when given, whose other members were given
    /// for `cert` already.
    async fn judge_for_cert(
        &mut self,
        cert: &AppCert,
        previous: u64,
        over: Option<&AppRecord>,
    ) -> Result<Judged, AppError> {
        let asks = self.record_expiries().await?;
        let edits = self.record_members().await?;
        let updated_at = self.next_record_time(previous).await?;
        self.record_base_known()?;
        let max_age = self.state.own_doc.record_max_age_ms();
        let held = NextBody::held(&self.state)?;
        let accepted = match &self.state.accepted {
            Some(accepted) => Some(AppRecord::verify(accepted, &self.state.meta.identity)?),
            None => None,
        };
        let mut asks = asks;
        let (mut held, changed) = match over {
            Some(later) => {
                let accepted = accepted.as_ref().map(AppRecord::body);
                let before = held.body().clone();
                let (built, changed) = held.over(accepted, later, &self.protocols);
                keep_asks(&mut asks, &before, built.body(), &edits.members);
                (built, changed)
            }
            None => (held, Vec::new()),
        };
        edits.apply(&mut held);
        let judging = CertBody::judged(held, cert, &self.protocols, &asks, |ask| {
            ask.at(updated_at, max_age).is_some()
        });
        let expires_at = self.resolve_record_expiries(&judging.asks, updated_at)?;
        let record = judging
            .body
            .sign(&self.state.keys, updated_at, expires_at)?;
        let record = self.read_back(&record)?;
        let batch = self.record_batch(record.signed())?;
        Ok(Judged {
            record: record.signed().clone(),
            pending: PendingRecord {
                body: batch.body().to_vec(),
            },
            asks: judging.asks,
            dropped: judging.dropped,
            changed,
        })
    }

    /// `taken`, a record of the app another device signed, replaces the one held, in `tx`:
    /// each registered protocol whose member changed, is gone or is new is told
    /// ([`AppEvent::MemberChanged`]); an ask goes with its member, and one whose member was
    /// absent already stays ([`keep_asks`]).
    async fn took_elsewhere(&mut self, tx: &mut Tx, taken: &SignedDoc) -> Result<(), AppError> {
        let identity = self.state.meta.identity;
        let held = AppRecord::verify(&self.state.record, &identity)?;
        let taken = AppRecord::verify(taken, &identity)?;
        let mut asks = self.record_expiries().await?;
        let edits = self.record_members().await?;
        if keep_asks(&mut asks, held.body(), taken.body(), &edits.members) {
            tx.put(key::RECORD_EXPIRIES, &asks)?;
        }
        let changed = self.changed_from(held.body(), taken.body());
        self.tell_changed(tx, changed)
    }

    /// After a restore, take `published`, the record the switch holds for the app, as the
    /// base the next record builds on when it is newer than the one held (the later
    /// `updated_at` wins, Switch spec 4.2) and verifies under the certificate the app
    /// presents, each protocol whose member it changes told ([`App::took_elsewhere`]). One
    /// under another certificate is the renewal checks' to take; an equal or older one
    /// changes nothing.
    async fn take_published_base(&mut self, published: &AppRecord) -> Result<(), AppError> {
        let held = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
        if self.state.pending_record.is_some() {
            return Ok(());
        }
        // The held record itself: the switch accepted it, as the store it came from knew
        // or not.
        if published.signed() == &self.state.record {
            if self.state.accepted.as_ref() != Some(&self.state.record) {
                let record = self.state.record.clone();
                let mut tx = self.tx()?;
                self.note_accepted(&record, &mut tx)?;
                self.commit(tx).await?;
                self.took_accepted(record);
            }
            return Ok(());
        }
        if published.cert().hash() != self.state.cert.hash()
            || published.updated_at() <= held.updated_at()
        {
            return Ok(());
        }
        let later = published.signed().clone();
        let mut tx = self.tx()?;
        self.took_elsewhere(&mut tx, &later).await?;
        tx.put(key::RECORD, &later)?;
        tx.put(key::ACCEPTED_RECORD, &later)?;
        self.commit(tx).await?;
        self.state.record = later.clone();
        self.state.accepted = Some(later);
        self.published_check = None;
        Ok(())
    }

    /// The registered protocols whose member is new, changed or gone from `held` to `taken`.
    fn changed_from(&self, held: &AppRecordBody, taken: &AppRecordBody) -> Vec<String> {
        self.protocols
            .names()
            .into_iter()
            .filter(|name| held.protocols.get(name) != taken.protocols.get(name))
            .collect()
    }

    /// Take `later`, a record of the app another device signed under the certificate the
    /// app presents and later than the one it holds, as it is ([`App::took_elsewhere`]),
    /// in `tx`, as the feed or the published copy shows it. Not while a change is kept
    /// here: its delivery meets `later` and goes over it. Returns whether it waits for a
    /// protocol it changes that the read can't tell yet (`order` module).
    pub(crate) async fn take_own_later(
        &mut self,
        later: &SignedDoc,
        tx: &mut Tx,
    ) -> Result<bool, AppError> {
        let identity = self.state.meta.identity;
        let held = AppRecord::verify(&self.state.record, &identity)?;
        let Ok(record) = AppRecord::verify(later, &identity) else {
            return Ok(false);
        };
        if self.state.pending_record.is_some()
            || !self.record_members().await?.is_empty()
            || record.cert().hash() != self.state.cert.hash()
            || record.updated_at() <= held.updated_at()
        {
            return Ok(false);
        }
        let changed = self.changed_from(held.body(), record.body());
        if !changed.iter().all(|name| self.may_tell(name)) {
            return Ok(true);
        }
        self.took_elsewhere(tx, later).await?;
        tx.put(key::RECORD, later)?;
        tx.put(key::ACCEPTED_RECORD, later)?;
        self.state.record = later.clone();
        self.state.accepted = Some(later.clone());
        self.published_check = None;
        Ok(false)
    }

    /// Tell each protocol of `changed` its member is new, changed or gone, in `tx`
    /// ([`AppEvent::MemberChanged`]).
    fn tell_changed(&mut self, tx: &mut Tx, changed: Vec<String>) -> Result<(), AppError> {
        for name in changed {
            let duty = Duty::MemberChanged {
                protocol: name.clone(),
            };
            self.keep_duty_for(tx, vec![name], duty)?;
        }
        Ok(())
    }

    /// Present `cert` from now on, with the record `taken`: one signed here is kept with its
    /// `app.put` and asks, each member it dropped told ([`AppEvent::MemberDropped`]).
    /// If the certificate can read a collection member the earlier certificate couldn't,
    /// the same commit schedules a listing for the next read. Earlier writes to that
    /// member appeared as stubs in the feed (Switch spec 8.3, Switch wire 7.4.9).
    ///
    /// With `accepted`, a record the switch holds that carries `cert`, that record is noted
    /// as the newest the switch accepted, in the same commit, and the published copy is
    /// checked against it at the next publication check.
    ///
    /// A certificate the app's protocols can't run with, one holding a scope root no
    /// registered protocol owns or one a protocol refuses, as a join or a load would, isn't
    /// taken: the app would never load again with it ([`App::refuse_cert`]). Returns
    /// whether `cert` was taken.
    async fn take_cert(
        &mut self,
        cert: AppCert,
        taken: Taken,
        accepted: Option<SignedDoc>,
        at: Option<(u64, u64)>,
    ) -> Result<bool, AppError> {
        if let Some(refusal) = self.protocols.certificate_refusal(&cert) {
            self.refuse_cert(&cert, refusal).await?;
            return Ok(false);
        }
        let issued_at = cert.issued_at();
        // A later renewal the app holds, of the certificate taken, stays held: it is taken
        // in turn once its listing comes (`adopt_renewal`).
        let keep_renewal = self
            .kept_renewal()
            .is_some_and(|held| is_renewal(&cert, held));
        // Only newly accessible collection members need the renewal listing
        // (Switch spec 3.3, 8.3).
        let widened = self.protocols.collections().iter().any(|collection| {
            collection.any_read_scope(&cert, |scope| !self.state.cert.holds_scope(scope))
        });
        // A certificate that adds `lists.read`: the feed showed the deny list's changes
        // before it as stubs, so neither the copy of the lists nor the protocol follows
        // from them. The copy is marked not complete, in the same commit, and the next
        // read tells the protocol a deny list gap with the list it takes the copy from
        // (`App::refresh_lists_if_owed`, Switch spec 8.3). A refusal of lists too large is
        // removed with it, so that read doesn't wait out its day for the baseline.
        let lists_read_added = cert.has_permission(Permission::ListsRead)
            && !self.state.cert.has_permission(Permission::ListsRead);
        let client = self.own_read_client_for(&cert)?;
        let mut tx = self.tx()?;
        if widened {
            // Every protocol is owed the listing: outside the feed, made before the next
            // read hands anything, but for a protocol behind the feed item that lists the
            // certificate, which is owed it at that item, after what it is told first
            // (Switch spec 8.3, `order` module).
            let mut due = super::records::list_due_in(&self.reader(), &tx).await?;
            for name in self.protocols.names() {
                let place = at.filter(|_| !self.may_tell(&name));
                match (due.at(&name), place) {
                    // Owed outside the feed already, or from an earlier item it is behind.
                    (Some(None), _) | (Some(Some(_)), Some(_)) => {}
                    _ => {
                        due.to.retain(|(named, _)| *named != name);
                        due.to.push((name, place));
                    }
                }
            }
            super::records::put_list_due(&mut tx, &due)?;
        }
        if lists_read_added {
            tx.delete(super::admission::LISTS_AT)?;
            tx.delete(super::admission::LISTS_TOO_LARGE)?;
        }
        // A renewal may give a permission the owed list upload was refused for.
        tx.delete(super::recovery::lists::WAITS)?;
        let (record, judged) = match taken {
            Taken::Judged(judged) => (judged.record.clone(), Some(judged)),
            Taken::AsIs(record) => (record, None),
        };
        tx.put(key::CERT, cert.signed())?;
        tx.renewal = Some(Box::new(super::RenewalChanges {
            cursor: self.state.cursor,
            next_duty: self.state.next_duty,
            ..Default::default()
        }));
        // Keep put-back cleanup off the receive stack while the new client waits for the save.
        Box::pin(self.put_backs_after_renewal(&cert, &mut tx)).await?;
        tx.put(key::RECORD, &record)?;
        tx.delete(key::CERT_REFUSED)?;
        if !keep_renewal {
            tx.delete(key::CERT_RENEWAL)?;
        }
        if let Some(accepted) = &accepted {
            tx.put(key::ACCEPTED_RECORD, accepted)?;
        }
        let (pending, dropped) = match judged {
            Some(judged) => {
                tx.put(key::PENDING_RECORD, &judged.pending)?;
                tx.put(key::RECORD_EXPIRIES, &judged.asks)?;
                tx.delete(key::RECORD_MEMBERS)?;
                self.tell_changed(&mut tx, judged.changed)?;
                (Some(judged.pending), judged.dropped)
            }
            None => {
                Box::pin(self.took_elsewhere(&mut tx, &record)).await?;
                (None, Vec::new())
            }
        };
        self.commit(tx).await?;
        self.state.cert = cert;
        self.time_fresh_at = None;
        self.install_client(client);
        if let Some(pending) = pending {
            self.state.pending_record = Some(pending);
        }
        self.state.record = record;
        if !keep_renewal {
            self.state.renewal = None;
        }
        if let Some(accepted) = accepted {
            self.state.accepted = Some(accepted);
            self.published_check = None;
        }
        self.events.push(AppEvent::CertificateTaken { issued_at });
        for protocol in dropped {
            self.events.push(AppEvent::MemberDropped {
                issued_at,
                protocol,
            });
        }
        Ok(true)
    }

    /// Refuse a renewed certificate the app's protocols can't run with: the app keeps the
    /// certificate it presents, and a renewal held from `cert.put` that is `cert` goes, so
    /// no read takes it. The host is told once, by a duty event for every protocol, in the
    /// same commit as `cert/refused`, which names the certificate: a read that finds it
    /// again, listed in the own record another device put, refuses it with no second
    /// event. A later renewal is checked on its own.
    async fn refuse_cert(
        &mut self,
        cert: &AppCert,
        refusal: super::events::CertificateRefusal,
    ) -> Result<(), AppError> {
        let hash = pubky_switch_core::enc::b64(&cert.hash());
        let told = self
            .reader()
            .get::<String>(key::CERT_REFUSED)
            .await?
            .is_some_and(|refused| refused == hash);
        let held = self
            .kept_renewal()
            .is_some_and(|renewal| renewal.hash() == cert.hash());
        if told && !held {
            return Ok(());
        }
        let mut tx = self.tx()?;
        if held {
            tx.delete(key::CERT_RENEWAL)?;
        }
        if !told {
            tx.put(key::CERT_REFUSED, &hash)?;
            self.keep_duty(
                &mut tx,
                Duty::CertificateRefused {
                    issued_at: cert.issued_at(),
                    refusal,
                },
            )?;
        }
        self.commit(tx).await?;
        if held {
            self.state.renewal = None;
        }
        Ok(())
    }

    /// The `app.put` batch. It is kept and may be sent again after the cursor moved on: a
    /// cursor move in it could take the service's cursor back, so it carries none (Switch
    /// spec 8.2).
    pub(crate) fn record_batch(&self, record: &SignedDoc) -> Result<Batch, AppError> {
        self.sign_ops(
            vec![(
                Vec::<Condition>::new(),
                OpKind::AppPut {
                    record: record.clone(),
                },
            )],
            None,
        )
    }

    /// Deliver what is owed of the record, then publish it (`own_record.rs`).
    pub(crate) async fn deliver_record(&mut self) -> Result<Publication, AppError> {
        let accepted = self.deliver_pending_record().await?;
        self.publish_owed(false, accepted).await
    }

    /// Send the kept `app.put` until answered; returns whether the switch accepted a record
    /// in this call. A `409 conflict` naming a record of this app with an `updated_at` at or
    /// after this one's (another device's) is written again once, later than the held one
    /// (Switch spec 4.2). One naming no record that verifies answers a re-send of a batch
    /// the switch applied and holds without its proofs (Switch wire 6.4 step 5), so the
    /// switch's directory decides it: a directory that shows this very record makes it
    /// delivered; one that shows a later record of the app, which another device put after
    /// it, makes it superseded (Switch spec 4.2 "The later `updated_at` wins"). The kept
    /// record is then dropped, and the later record taken in the same commit as the newest
    /// the switch accepted, and as the record the app presents when it carries the
    /// certificate the app presents: the app's next record builds on it, so this older body
    /// is never signed again over it. A later record carrying a renewal another device
    /// took is presented with that renewal when the newest `identity.json` lists it, and
    /// one under any other certificate is never taken ([`App::take_superseding`]).
    /// Otherwise it is refused, and nothing is noted or published. Once the switch holds the record, an app that publishes owes it to the
    /// Homeserver, in the commit that records the answer.
    pub(crate) async fn deliver_pending_record(&mut self) -> Result<bool, AppError> {
        Box::pin(self.prepare_pending_members()).await?;
        let Some(pending) = self.state.pending_record.clone() else {
            return Ok(false);
        };
        let mut batch = Batch::from_body(pending.body)?;
        let result = self.submit(&batch).await;
        let held = match result {
            Ok(_) => None,
            Err(error) if error.code() == Some(ErrorCode::Conflict) => {
                let named = match &error {
                    AppError::Switch(ClientError::Switch { current, .. }) => current
                        .get("record")
                        .and_then(|value| SignedDoc::from_strict_value(value).ok())
                        .and_then(|doc| AppRecord::verify(&doc, &self.state.meta.identity).ok()),
                    _ => None,
                };
                // Boxed: the directory read is rare, and would otherwise widen every future
                // that delivers a record.
                if named.is_none() {
                    match Box::pin(self.switch_holds(&batch)).await? {
                        Held::This => {}
                        Held::Later(later) => {
                            let (later, identity) = *later;
                            Box::pin(self.take_superseding(later, identity)).await?;
                            return Ok(false);
                        }
                        Held::Other => return Err(error),
                    }
                }
                named
            }
            Err(error) => return Err(error),
        };
        if let Some(held) = held {
            let mine = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
            if held.cert().app_id() != self.state.meta.app_id {
                return Err(AppError::InvalidData(
                    "Switch wire 6.2: an app.put conflict naming another app's record".into(),
                ));
            }
            // Another device's record under this certificate: its members are built on.
            let mut body = NextBody::held(&self.state)?;
            let mut changed = Vec::new();
            if held.cert().hash() == self.state.cert.hash() {
                let accepted = match &self.state.accepted {
                    Some(accepted) => Some(AppRecord::verify(accepted, &self.state.meta.identity)?),
                    None => None,
                };
                let accepted = accepted.as_ref().map(AppRecord::body);
                (body, changed) = body.over(accepted, &held, &self.protocols);
            }
            // The asks of members gone from it go before it is signed.
            let mut asks = Box::pin(self.record_expiries()).await?;
            let edits = Box::pin(self.record_members()).await?;
            let cleared = keep_asks(&mut asks, mine.body(), body.body(), &edits.members);
            edits.apply(&mut body);
            let previous = held.updated_at().max(mine.updated_at());
            let updated_at = Box::pin(self.next_record_time(previous)).await?;
            let record = self.sign_record_at(body, &asks, updated_at)?;
            batch = self.record_batch(record.signed())?;
            let mut tx = self.tx()?;
            if cleared {
                tx.put(key::RECORD_EXPIRIES, &asks)?;
            }
            self.tell_changed(&mut tx, changed)?;
            tx.delete(key::RECORD_MEMBERS)?;
            tx.put(key::RECORD, record.signed())?;
            let pending = PendingRecord {
                body: batch.body().to_vec(),
            };
            tx.put(key::PENDING_RECORD, &pending)?;
            self.state.record = record.signed().clone();
            self.state.pending_record = Some(pending);
            self.commit(tx).await?;
            self.submit(&batch).await?;
        }
        let delivered = delivered_record(&batch)?;
        let mut tx = self.tx()?;
        tx.delete(key::PENDING_RECORD)?;
        tx.put(key::CURSOR, &self.state.cursor)?;
        self.note_accepted(&delivered, &mut tx)?;
        self.state.pending_record = None;
        self.commit(tx).await?;
        self.took_accepted(delivered);
        Ok(true)
    }

    /// Drop the kept record that `later`, a record of the app the switch holds, superseded,
    /// and take `later` in the same commit, as the newest record the switch accepted and
    /// as the record the app presents, when it carries the certificate the app presents.
    /// Nothing is owed to the Homeserver for it: the device that put it publishes it, and
    /// the next check compares the copy with it.
    ///
    /// A `later` carrying a renewal another device took, whose `cert.put` the feed shows
    /// only as a stub once the record carries it, is taken with that certificate first, as
    /// after a restore (Switch spec 3.2 step 3): when `identity`, the own `identity.json`
    /// the same directory answer carried, or the newer one held, lists it, and it renews
    /// the certificate held under the app's own keys. It is presented as it is, so nothing
    /// is signed over it, also when the app already holds that renewal's `cert.put`.
    ///
    /// A `later` under any other certificate, which only a faulty switch shows, is never
    /// taken: the kept record is dropped alone, nothing is noted as accepted, and nothing
    /// of it is published.
    async fn take_superseding(
        &mut self,
        later: AppRecord,
        identity: IdentityDoc,
    ) -> Result<(), AppError> {
        let me = self.state.meta.app_id;
        let newer = identity.version() > self.state.own_doc.version();
        let listed = if newer {
            identity.listed_cert(&me)
        } else {
            self.state.own_doc.listed_cert(&me)
        };
        let cert = later.cert();
        if cert.hash() != self.state.cert.hash()
            && listed == Some(cert.hash())
            && cert.signing_key() == self.state.keys.signing_public()
            && cert.bundle_key() == self.state.keys.bundle_public()
            && is_renewal(&self.state.cert, cert)
        {
            if !self.record_members().await?.is_empty() {
                // Unsigned edits still belong to the certificate they were given for.
                // Judge them for this renewal before any signature can carry them.
                self.take_later(cert.clone(), later, None).await?;
                if newer {
                    self.take_own_copy(identity).await?;
                }
                return Ok(());
            }
            // Before the newer document is taken, which would sign a renewal the app holds
            // into the dropped body; and before the drop, so a crash between the two leaves
            // the kept record, whose re-send then finds the later record under the
            // certificate presented.
            self.take_cert(
                cert.clone(),
                Taken::AsIs(later.signed().clone()),
                None,
                None,
            )
            .await?;
        }
        if newer {
            self.take_own_copy(identity).await?;
        }
        let taken = later.cert().hash() == self.state.cert.hash();
        let signed = later.signed().clone();
        let mut tx = self.tx()?;
        tx.delete(key::PENDING_RECORD)?;
        if taken {
            self.took_elsewhere(&mut tx, &signed).await?;
            tx.put(key::ACCEPTED_RECORD, &signed)?;
            tx.put(key::RECORD, &signed)?;
        }
        self.commit(tx).await?;
        self.state.pending_record = None;
        if taken {
            self.state.record = signed.clone();
            self.state.accepted = Some(signed);
            self.published_check = None;
        }
        Ok(())
    }

    /// Take a renewal another device of the app took (Switch wire 7.2 "How an own app reads
    /// it", spec 3.2 step 3): the own `identity.json` lists another certificate than the
    /// one the app presents, and the app holds no `cert.put` for it, which the feed showed
    /// only as a stub once that device's record carried it. Without it every write is
    /// refused `403 not_current`. Taken from the own record in the directory, as after a
    /// restore ([`App::take_listed_cert`]). Only a directory read tells whether that record
    /// carries it yet, so a look that doesn't find it, or fails, is made again at most every
    /// [`super::DOC_CACHE_MS`] while the listing lasts, and the read goes on; a refusal of
    /// the app's record write under the earlier certificate makes the next read look at
    /// once. `None` when no look was due or it failed.
    pub(crate) async fn take_renewal_listed_elsewhere(
        &mut self,
    ) -> Result<Option<Listed>, AppError> {
        let me = self.state.meta.app_id;
        let doc = &self.state.own_doc;
        let Some(listed) = doc.listed_cert(&me) else {
            return Ok(None);
        };
        let held = self.kept_renewal().is_some_and(|r| r.hash() == listed);
        if listed == self.state.cert.hash() || held || doc.lists_removed(&me) {
            return Ok(None);
        }
        let now = self.now();
        if self
            .renewal_looked_ms
            .is_some_and(|at| now >= at && now - at < super::DOC_CACHE_MS)
        {
            return Ok(None);
        }
        // A look that fails, on the network or with an answer the app won't read, is paced
        // as one that found nothing, and the read goes on: only a record write is refused
        // under the earlier certificate, and the next look may find it.
        let found = match Box::pin(self.take_listed_cert()).await {
            Ok(found) => found,
            Err(AppError::Transport(_) | AppError::Switch(_) | AppError::InvalidData(_)) => {
                self.renewal_looked_ms = Some(now);
                // The look may have failed after it took a newer own document, such as at
                // the key fetch an epoch rise makes, refused for an app that document
                // removes: the read stops at that document all the same.
                if self.not_current_here().is_some() {
                    return Ok(Some(Listed::NotCurrentHere));
                }
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let listed_now = self.state.own_doc.listed_cert(&me);
        self.renewal_looked_ms =
            (listed_now.is_some_and(|l| l != self.state.cert.hash())).then_some(now);
        Ok(Some(found))
    }

    /// What the switch's directory shows it holds for this app, beside the record `batch`
    /// delivers.
    async fn switch_holds(&mut self, batch: &Batch) -> Result<Held, AppError> {
        let record = delivered_record(batch)?;
        let mine = AppRecord::verify(&record, &self.state.meta.identity)?;
        let me = self.state.meta.app_id;
        let result = self.client.directory(None).await;
        let directory = self.take(result).await?;
        let Some(entry) = directory.apps.iter().find(|app| app.app_id == me) else {
            return Ok(Held::Other);
        };
        Ok(if entry.record.signed() == &record {
            Held::This
        } else if entry.record.updated_at() > mine.updated_at() {
            Held::Later(Box::new((entry.record.clone(), directory.identity.clone())))
        } else {
            Held::Other
        })
    }

    /// The listed certificate from the own record in the directory, when the own
    /// `identity.json` lists another certificate than the one the app presents and it holds
    /// no `cert.put` for it (Switch spec 3.2 step 3): taken only if the record is signed
    /// with the app's own signing key, and its certificate renews the one held and has the
    /// listed hash. The service holds that record, so nothing is delivered.
    ///
    /// It runs after a restore, whose own `identity.json` is the backup's: a renewal that
    /// another device of the app took since is listed only in a later one, and its
    /// `cert.put` shows as a stub once the record carries it. So the directory's own
    /// `identity.json` is taken first when it is newer, and the certificate it lists is the
    /// one checked (Switch spec 12.4 step 1 "Certificate"). A newer document that removes
    /// the app or names another generation is taken and nothing more is done here
    /// ([`Listed::NotCurrentHere`]): the read stops, or follows the provider change, and
    /// registers nothing at this switch. Otherwise it returns the own receive key record the
    /// same directory shows, which the restore's key check reads ([`Listed::Key`]).
    pub(crate) async fn take_listed_cert(&mut self) -> Result<Listed, AppError> {
        let (directory, head) = self.read_own_directory().await?;
        self.take_directory_cert(directory, head).await
    }

    /// A directory can carry the newer identity-signed document that its head sends us
    /// to (Switch wire 7.1, 7.4.10). Both certificate readers stop at that document.
    pub(super) async fn read_own_directory(&mut self) -> Result<(Directory, SignedHead), AppError> {
        let result = self.client.own_directory().await;
        let later = Box::pin(self.observe_own_answer()).await?;
        let (directory, head) = self.take_answer(result, true).await?;
        if later.is_some_and(|generation| directory.identity.generation() != generation) {
            return Err(Self::later_generation_answer());
        }
        Ok((directory, head))
    }

    pub(super) async fn take_directory_cert(
        &mut self,
        directory: Directory,
        head: SignedHead,
    ) -> Result<Listed, AppError> {
        let me = self.state.meta.app_id;
        let at = (head.generation == directory.identity.generation())
            .then_some((head.generation, head.seq));
        if directory.identity.version() > self.state.own_doc.version() {
            self.take_own_copy_with(
                directory.identity.clone(),
                at,
                Some(head.generation),
                |_| Ok(()),
            )
            .await?;
        }
        if self.not_current_here().is_some() {
            return Ok(Listed::NotCurrentHere);
        }
        if head.generation > self.state.meta.generation {
            // The directory's document did not advance the held identity.
            return Err(Self::later_generation_answer());
        }
        let Some(entry) = directory.apps.into_iter().find(|app| app.app_id == me) else {
            // No record published: the held one is the base.
            self.record_base_read = true;
            return Ok(Listed::Key(None));
        };
        if !self.record_base_read {
            self.take_published_base(&entry.record).await?;
            self.record_base_read = true;
        }
        let key = entry.receive_key.clone();
        let Some(listed) = self.state.own_doc.listed_cert(&me) else {
            return Ok(Listed::Key(key));
        };
        if listed == self.state.cert.hash() {
            return Ok(Listed::Key(key));
        }
        if self.kept_renewal().is_some_and(|r| r.hash() == listed) {
            self.adopt_renewal(at).await?;
            return Ok(Listed::Key(key));
        }
        let cert = entry.record.cert().clone();
        if cert.signing_key() == self.state.keys.signing_public()
            && cert.bundle_key() == self.state.keys.bundle_public()
            && is_renewal(&self.state.cert, &cert)
            && cert.hash() == listed
        {
            // The switch holds that record: it is the newest it accepted, and the published
            // copy is checked against it. A record change kept under the earlier certificate
            // is signed anew under this one, later than both records, and delivered by the
            // read, as `adopt_renewal` builds on a kept one: sent as it is, it would be
            // refused for its certificate, and read as the app not current.
            // One the protocols can't run with is refused, and the app goes on with the
            // certificate it presents.
            Box::pin(self.take_later(cert, entry.record, at)).await?;
        }
        Ok(Listed::Key(key))
    }
}

/// What the switch's directory shows for the app, beside a kept `app.put`'s record.
enum Held {
    /// That very record, byte for byte.
    This,
    /// A record of the app with a later `updated_at`, verified for the identity and the
    /// App ID as every directory entry is, with the own `identity.json` the same answer
    /// carried.
    Later(Box<(AppRecord, IdentityDoc)>),
    /// Another record, or none.
    Other,
}

/// What [`App::take_listed_cert`] found.
pub(crate) enum Listed {
    /// The app is current here: the own receive key record the directory shows, if any.
    Key(Option<pubky_switch_core::records::ReceiveKeyRecord>),
    /// The newest own `identity.json` removes the app or names another generation.
    NotCurrentHere,
}

/// The record a kept `app.put` batch delivers.
pub(crate) fn delivered_record(batch: &Batch) -> Result<SignedDoc, AppError> {
    batch
        .ops()
        .iter()
        .find_map(|op| match &op.body().kind {
            OpKind::AppPut { record } => Some(record.clone()),
            _ => None,
        })
        .ok_or_else(|| AppError::InvalidData("a kept app.put batch carries no record".into()))
}

/// The record [`App::take_cert`] presents with the certificate it takes.
enum Taken {
    /// The record held, signed here under that certificate ([`App::judge_for_cert`]).
    Judged(Judged),
    /// One another device signed, presented as it is: that device's protocols gave its
    /// members ([`App::took_elsewhere`]).
    AsIs(SignedDoc),
}

/// [`App::judge_for_cert`]: the record, its `app.put`, the asks it was signed with, and the
/// protocols whose member it dropped.
struct Judged {
    record: SignedDoc,
    pending: PendingRecord,
    asks: RecordExpiries,
    dropped: Vec<String>,
    /// The registered protocols whose member held is another, gone or new in it.
    changed: Vec<String>,
}

/// Keep in `asks` only those of members `built` carries, and those whose member `held`
/// lacked already, plus the asks paired with unsigned edits; returns whether any went.
fn keep_asks(
    asks: &mut RecordExpiries,
    held: &AppRecordBody,
    built: &AppRecordBody,
    members: &RecordMembers,
) -> bool {
    let before = asks.len();
    asks.retain(|name, _| {
        members.contains_key(name)
            || built.protocols.contains_key(name)
            || !held.protocols.contains_key(name)
    });
    asks.len() != before
}
