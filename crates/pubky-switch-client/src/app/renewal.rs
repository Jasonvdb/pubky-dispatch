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

use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{Condition, OpKind};
use pubky_switch_core::records::{AppCert, AppRecord, AppRecordBody, IdentityDoc, is_renewal};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use super::events::{AppEvent, Duty};
use super::next_body::{CertBody, NextBody};
use super::own_record::RecordExpiries;
use super::state::{PendingRecord, Tx, key};
use super::{App, AppError, Publication};
use crate::client::Batch;
use crate::error::ClientError;

impl App {
    /// A `cert.put` for this app seen in the feed: kept if it renews the certificate the
    /// app presents (the same App ID, signing key and bundle key, a later `issued_at`).
    pub(crate) fn note_renewal(&mut self, signed: &SignedDoc, tx: &mut Tx) -> Result<(), AppError> {
        let Ok(cert) = AppCert::verify(signed, &self.state.meta.identity) else {
            return Ok(());
        };
        let newer_than_kept = self
            .state
            .renewal
            .as_ref()
            .is_none_or(|kept| cert.issued_at() > kept.issued_at());
        if is_renewal(&self.state.cert, &cert) && newer_than_kept {
            tx.put(key::CERT_RENEWAL, cert.signed())?;
            self.state.renewal = Some(cert);
            self.events.push(AppEvent::RenewalSeen);
        }
        Ok(())
    }

    /// Take the kept renewal once the own `identity.json` lists it, and deliver the record
    /// carrying it. Returns whether the certificate changed.
    pub(crate) async fn adopt_renewal(&mut self, at: Option<(u64, u64)>) -> Result<bool, AppError> {
        let Some(renewal) = self.state.renewal.clone() else {
            return Ok(false);
        };
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
            true => self.later_under(&renewal).await?,
            false => None,
        };
        let took = match later {
            Some(later) => self.take_later(renewal, later, at).await?,
            None => {
                let old = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
                let judged = self
                    .judge_for_cert(&renewal, old.updated_at(), None)
                    .await?;
                self.take_cert(renewal, Taken::Judged(judged), None, at)
                    .await?
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
        let record = if self.state.pending_record.is_some() {
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
        let updated_at = self.next_record_time(previous).await?;
        let max_age = self.state.own_doc.record_max_age_ms();
        let held = NextBody::held(&self.state)?;
        let accepted = match &self.state.accepted {
            Some(accepted) => Some(AppRecord::verify(accepted, &self.state.meta.identity)?),
            None => None,
        };
        let (held, changed) = match over {
            Some(later) => {
                let accepted = accepted.as_ref().map(AppRecord::body);
                held.over(accepted, later, &self.protocols)
            }
            None => (held, Vec::new()),
        };
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
    /// ([`AppEvent::MemberChanged`]), and the ask of a member gone goes with it.
    async fn took_elsewhere(&mut self, tx: &mut Tx, taken: &SignedDoc) -> Result<(), AppError> {
        let identity = self.state.meta.identity;
        let held = AppRecord::verify(&self.state.record, &identity)?;
        let taken = AppRecord::verify(taken, &identity)?;
        let changed = self
            .protocols
            .names()
            .into_iter()
            .filter(|name| held.body().protocols.get(name) != taken.body().protocols.get(name))
            .collect();
        self.tell_changed(tx, changed, Some(taken.body())).await
    }

    /// Take `later`, a record of the app another device signed under the certificate the
    /// app presents and later than the one it holds, as it is ([`App::took_elsewhere`]),
    /// as the feed or the published copy shows it. Not while a change is kept here: its
    /// delivery meets `later` and goes over it.
    pub(crate) async fn take_own_later(&mut self, later: &SignedDoc) -> Result<(), AppError> {
        let identity = self.state.meta.identity;
        let held = AppRecord::verify(&self.state.record, &identity)?;
        let Ok(record) = AppRecord::verify(later, &identity) else {
            return Ok(());
        };
        if self.state.pending_record.is_some()
            || record.cert().hash() != self.state.cert.hash()
            || record.updated_at() <= held.updated_at()
        {
            return Ok(());
        }
        let mut tx = self.tx()?;
        self.took_elsewhere(&mut tx, later).await?;
        tx.put(key::RECORD, later)?;
        tx.put(key::ACCEPTED_RECORD, later)?;
        self.commit(tx).await?;
        self.state.record = later.clone();
        self.state.accepted = Some(later.clone());
        self.published_checked_ms = None;
        Ok(())
    }

    /// Tell each protocol of `changed` its member changed or is gone, in `tx`
    /// ([`AppEvent::MemberChanged`]); with `members`, the record's, drop the asks of
    /// protocols without one.
    async fn tell_changed(
        &mut self,
        tx: &mut Tx,
        changed: Vec<String>,
        members: Option<&AppRecordBody>,
    ) -> Result<(), AppError> {
        if let Some(members) = members.map(|body| &body.protocols) {
            let mut asks = self.record_expiries().await?;
            let before = asks.len();
            asks.retain(|name, _| members.contains_key(name));
            if asks.len() != before {
                tx.put(key::RECORD_EXPIRIES, &asks)?;
            }
        }
        for name in changed {
            let duty = Duty::MemberChanged {
                protocol: name.clone(),
            };
            self.keep_duty_for(tx, vec![name], duty)?;
        }
        Ok(())
    }

    /// Present `cert` from now on, with the record `taken`: one signed here is kept with its
    /// `app.put` and asks, each member it dropped told ([`AppEvent::MemberDropped`]). A certificate that reads a member of a collection of the protocol
    /// the one before didn't owes a listing, in the same commit, so the next read lists it (Switch
    /// spec 8.3, Switch wire 7.4.9): the writes made there before it were stubs in the feed.
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
            .state
            .renewal
            .as_ref()
            .is_some_and(|held| is_renewal(&cert, held));
        // Member by member: a scope of the new certificate that reads a collection's member,
        // its fixed read scope or a sub-scope of its family, and that the one before doesn't
        // hold (Switch spec 3.3).
        let collections = self.protocols.collections();
        let widened = cert.scopes().iter().any(|scope| {
            !self.state.cert.holds_scope(scope)
                && collections.iter().any(|c| c.read_by_scope(scope))
        });
        // A certificate that adds `lists.read`: the feed showed the deny list's changes
        // before it as stubs, so neither the copy of the lists nor the protocol follows
        // from them. The copy is marked not complete, in the same commit, and the next
        // read tells the protocol a deny list gap with the list it takes the copy from
        // (`App::refresh_lists_if_owed`, Switch spec 8.3). A refusal of lists too large is
        // removed with it, so that read doesn't wait out its day for the baseline.
        let lists_read_added = cert.has_permission(Permission::ListsRead)
            && !self.state.cert.has_permission(Permission::ListsRead);
        self.state.cert = cert;
        self.rebuild_client()?;
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
        let (record, judged) = match taken {
            Taken::Judged(judged) => (judged.record.clone(), Some(judged)),
            Taken::AsIs(record) => (record, None),
        };
        tx.put(key::CERT, self.state.cert.signed())?;
        tx.put(key::RECORD, &record)?;
        tx.delete(key::CERT_REFUSED)?;
        if !keep_renewal {
            tx.delete(key::CERT_RENEWAL)?;
        }
        if let Some(accepted) = &accepted {
            tx.put(key::ACCEPTED_RECORD, accepted)?;
        }
        let mut dropped = Vec::new();
        match judged {
            Some(judged) => {
                tx.put(key::PENDING_RECORD, &judged.pending)?;
                tx.put(key::RECORD_EXPIRIES, &judged.asks)?;
                self.state.pending_record = Some(judged.pending);
                dropped = judged.dropped;
                self.tell_changed(&mut tx, judged.changed, None).await?;
            }
            None => self.took_elsewhere(&mut tx, &record).await?,
        }
        self.state.record = record;
        if !keep_renewal {
            self.state.renewal = None;
        }
        self.commit(tx).await?;
        if let Some(accepted) = accepted {
            self.state.accepted = Some(accepted);
            self.published_checked_ms = None;
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
            .state
            .renewal
            .as_ref()
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
            let members = body.body().clone();
            let record = self
                .sign_next_record(body, held.updated_at().max(mine.updated_at()))
                .await?;
            batch = self.record_batch(record.signed())?;
            let mut tx = self.tx()?;
            self.tell_changed(&mut tx, changed, Some(&members)).await?;
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
            self.published_checked_ms = None;
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
        let held = self
            .state
            .renewal
            .as_ref()
            .is_some_and(|r| r.hash() == listed);
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
        let me = self.state.meta.app_id;
        let result = self.client.directory(None).await;
        let directory = self.take(result).await?;
        if directory.identity.version() > self.state.own_doc.version() {
            self.take_own_copy(directory.identity.clone()).await?;
        }
        if self.not_current_here().is_some() {
            return Ok(Listed::NotCurrentHere);
        }
        let Some(entry) = directory.apps.into_iter().find(|app| app.app_id == me) else {
            return Ok(Listed::Key(None));
        };
        let key = entry.receive_key.clone();
        let Some(listed) = self.state.own_doc.listed_cert(&me) else {
            return Ok(Listed::Key(key));
        };
        if listed == self.state.cert.hash() {
            return Ok(Listed::Key(key));
        }
        if self
            .state
            .renewal
            .as_ref()
            .is_some_and(|r| r.hash() == listed)
        {
            self.adopt_renewal(None).await?;
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
            self.take_later(cert, entry.record, None).await?;
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
