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
use pubky_switch_core::records::{AppCert, AppRecord, IdentityDoc, is_renewal};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use std::collections::BTreeSet;

use super::events::{AppEvent, Duty};
use super::next_body::{CertBody, MemberRefusal, NextBody};
use super::own_record::RecordExpiries;
use super::state::{PendingRecord, RenewalWait, Tx, key};
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
    /// carrying it, with each protocol's member judged for it ([`App::judge_for_cert`]).
    /// Returns whether the certificate changed.
    pub(crate) async fn adopt_renewal(&mut self, at: Option<(u64, u64)>) -> Result<bool, AppError> {
        let Some(renewal) = self.state.renewal.clone() else {
            return Ok(false);
        };
        let me = self.state.meta.app_id;
        if self.state.own_doc.listed_cert(&me) != Some(renewal.hash()) {
            return Ok(false);
        }
        let old = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
        let Judgement::Judged(judged) = self.judge_for_cert(&renewal, old.updated_at()).await?
        else {
            return Ok(false);
        };
        if !self
            .take_cert(renewal, Taken::Judged(judged), None, at)
            .await?
        {
            return Ok(false);
        }
        self.deliver_record().await?;
        Ok(true)
    }

    /// The record the app holds, signed under `cert`, a certificate it is about to take,
    /// later than `previous`, with its `app.put`: `accepts` and every member as the
    /// registered protocols give them for `cert` ([`CertBody::judged`]), and the expiry the
    /// protocols asked for, without the ask of a protocol whose member is removed. The whole
    /// body is built first, then signed once and checked as [`App::set_protocol_member`]
    /// checks a record: read back the same way, and in an `app.put` the switch would take.
    /// Nothing is kept or sent here.
    ///
    /// Nothing is taken when `cert` isn't: one the protocols can't run with is refused
    /// ([`App::refuse_cert`]); one a protocol refuses to give a member for, or whose record
    /// the check refuses, leaves the certificate and record held, and the renewal owed for a
    /// later read ([`App::renewal_waits`]).
    async fn judge_for_cert(
        &mut self,
        cert: &AppCert,
        previous: u64,
    ) -> Result<Judgement, AppError> {
        if let Some(refusal) = self.protocols.certificate_refusal(cert) {
            self.refuse_cert(cert, refusal).await?;
            return Ok(Judgement::Refused);
        }
        let held = NextBody::held(&self.state)?;
        let body = match CertBody::judged(held, cert, &self.protocols) {
            Ok(body) => body,
            Err(refusal) => {
                let protocol = refusal.protocol.clone();
                self.renewal_waits(cert, refusal).await?;
                return Ok(Judgement::Waits(protocol));
            }
        };
        // A removed member's expiry ask goes with it, as when its protocol removes it.
        let mut expiries = self.record_expiries().await?;
        for name in body.removed() {
            expiries.remove(name);
        }
        let updated_at = self.next_record_time(previous).await?;
        let expires_at = self.resolve_record_expiries(&expiries, updated_at)?;
        let check = |body: &CertBody| {
            body.sign(&self.state.keys, updated_at, expires_at)
                .map_err(AppError::from)
                .and_then(|record| self.read_back(&record))
                .and_then(|record| Ok((self.record_batch(record.signed())?, record)))
        };
        match check(&body) {
            Ok((batch, record)) => Ok(Judgement::Judged(Judged {
                record: record.signed().clone(),
                pending: PendingRecord {
                    body: batch.body().to_vec(),
                },
                expiries,
                dropped: body.dropped().to_vec(),
            })),
            Err(error) => {
                // Named by none when the check refuses the certificate and kinds alone, else
                // by the first member it refuses alone, else by the largest: each body checked
                // holds only what was given for `cert`.
                let names = self.protocols.names();
                let refused = |name: Option<&str>| {
                    body.only(name).is_some_and(|alone| check(&alone).is_err())
                };
                let protocol = if refused(None) {
                    None
                } else {
                    names
                        .iter()
                        .find(|name| refused(Some(name)))
                        .or_else(|| {
                            names
                                .iter()
                                .filter(|name| body.member_len(name) > 0)
                                .max_by_key(|name| body.member_len(name))
                        })
                        .cloned()
                };
                let refusal = MemberRefusal {
                    protocol: protocol.clone(),
                    reason: error.to_string(),
                };
                self.renewal_waits(cert, refusal).await?;
                Ok(Judgement::Waits(protocol))
            }
        }
    }

    /// A protocol refused `cert`, a listed renewal ([`App::judge_for_cert`]): nothing of it
    /// is taken, and the record changes kept wait unsent ([`App::renewal_waits_here`]).
    /// Noted in `cert/waits` with the protocols told of, so the host is told once per
    /// certificate and protocol ([`AppEvent::RenewalWaits`]), however the refusals alternate.
    async fn renewal_waits(
        &mut self,
        cert: &AppCert,
        refusal: MemberRefusal,
    ) -> Result<(), AppError> {
        let hash = pubky_switch_core::enc::b64(&cert.hash());
        let mut wait = match self.state.renewal_waits.clone() {
            Some(wait) if wait.cert == hash => wait,
            _ => RenewalWait {
                cert: hash,
                told: BTreeSet::new(),
            },
        };
        if !wait.told.insert(refusal.protocol.clone()) {
            return Ok(());
        }
        let mut tx = self.tx()?;
        tx.put(key::CERT_WAITS, &wait)?;
        self.commit(tx).await?;
        self.events.push(AppEvent::RenewalWaits {
            issued_at: cert.issued_at(),
            protocol: refusal.protocol,
            reason: refusal.reason,
        });
        self.state.renewal_waits = Some(wait);
        Ok(())
    }

    /// Whether the certificate the own `identity.json` lists is one a protocol refused
    /// ([`App::renewal_waits`]): the record the app holds carries the earlier one, so its
    /// kept `app.put` would be refused `403 not_current` (Switch wire 6.2), and waits unsent
    /// until the renewal is taken, signed anew then under it.
    pub(crate) fn renewal_waits_here(&self) -> bool {
        let me = self.state.meta.app_id;
        match (
            &self.state.renewal_waits,
            self.state.own_doc.listed_cert(&me),
        ) {
            (Some(wait), Some(listed)) => {
                listed != self.state.cert.hash()
                    && wait.cert == pubky_switch_core::enc::b64(&listed)
            }
            _ => false,
        }
    }

    /// Present `cert` from now on, with the record `taken`; one signed here
    /// ([`Taken::Judged`]) is kept with its `app.put` for delivery, with the expiry asks it
    /// was signed with, and each member it dropped is told ([`AppEvent::MemberDropped`]). A
    /// certificate that reads a member of a collection of the protocol the one before didn't
    /// owes a listing, in the same commit, so the next read lists it (Switch spec 8.3, Switch
    /// wire 7.4.9): the writes made there before it were stubs in the feed.
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
        let (record, judged, change_dropped) = match taken {
            Taken::Judged(judged) => (judged.record.clone(), Some(judged), None),
            Taken::AsIs(record) => (record, None, None),
            Taken::OverChange { record, refused } => (record, None, Some(refused)),
        };
        tx.put(key::CERT, self.state.cert.signed())?;
        tx.put(key::RECORD, &record)?;
        tx.delete(key::CERT_REFUSED)?;
        tx.delete(key::CERT_WAITS)?;
        if !keep_renewal {
            tx.delete(key::CERT_RENEWAL)?;
        }
        if let Some(accepted) = &accepted {
            tx.put(key::ACCEPTED_RECORD, accepted)?;
        }
        let mut dropped = Vec::new();
        if let Some(judged) = judged {
            tx.put(key::PENDING_RECORD, &judged.pending)?;
            tx.put(key::RECORD_EXPIRIES, &judged.expiries)?;
            self.state.pending_record = Some(judged.pending);
            dropped = judged.dropped;
        }
        if let Some(protocol) = change_dropped {
            tx.delete(key::PENDING_RECORD)?;
            self.state.pending_record = None;
            self.keep_duty(
                &mut tx,
                Duty::RecordChangeDropped {
                    issued_at,
                    protocol,
                },
            )?;
        }
        self.state.record = record;
        self.state.renewal_waits = None;
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
        let waits = self
            .state
            .renewal_waits
            .as_ref()
            .is_some_and(|wait| wait.cert == hash);
        if told && !held && !waits {
            return Ok(());
        }
        let mut tx = self.tx()?;
        if held {
            tx.delete(key::CERT_RENEWAL)?;
        }
        if waits {
            tx.delete(key::CERT_WAITS)?;
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
        if waits {
            self.state.renewal_waits = None;
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
        if self.state.pending_record.is_some() && self.renewal_waits_here() {
            return Ok(Publication::RenewalWaits);
        }
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
    /// While a protocol refuses the listed renewal, the kept record waits unsent
    /// ([`App::renewal_waits_here`]).
    pub(crate) async fn deliver_pending_record(&mut self) -> Result<bool, AppError> {
        let Some(pending) = self.state.pending_record.clone() else {
            return Ok(false);
        };
        if self.renewal_waits_here() {
            return Ok(false);
        }
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
            let body = NextBody::held(&self.state)?;
            let record = self
                .sign_next_record(body, held.updated_at().max(mine.updated_at()))
                .await?;
            batch = self.record_batch(record.signed())?;
            let mut tx = self.tx()?;
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
        // A held renewal a protocol refuses is looked for too: another device may have
        // taken it.
        let waits = self.renewal_waits_here();
        if listed == self.state.cert.hash() || (held && !waits) || doc.lists_removed(&me) {
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
            && (self.adopt_renewal(None).await? || !self.renewal_waits_here())
        {
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
            // is signed anew under this one, with each protocol's member judged for it,
            // later than both records, and delivered by the read, as `adopt_renewal` builds
            // on a kept one: sent as it is, it would be refused for its certificate, and read
            // as the app not current. While a protocol refuses to give a member for it, that
            // record is taken as it is all the same, its device's protocols having given its
            // members, and the change is given up, the protocols told: it can't go under
            // either certificate. So is a renewal the app holds from `cert.put` and a
            // protocol refuses, once another device took it.
            let taken = entry.record.signed().clone();
            let record = if self.state.pending_record.is_some() {
                let old = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
                let previous = old.updated_at().max(entry.record.updated_at());
                match self.judge_for_cert(&cert, previous).await? {
                    Judgement::Judged(judged) => Taken::Judged(judged),
                    Judgement::Waits(refused) => Taken::OverChange {
                        record: taken.clone(),
                        refused,
                    },
                    Judgement::Refused => return Ok(Listed::Key(key)),
                }
            } else {
                Taken::AsIs(taken.clone())
            };
            // One the protocols can't run with is refused, and the app goes on with the
            // certificate it presents.
            self.take_cert(cert, record, Some(taken), None).await?;
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
    /// One signed here under that certificate ([`App::judge_for_cert`]).
    Judged(Judged),
    /// One another device signed and the switch holds, presented as it is: that device's
    /// protocols gave its members.
    AsIs(SignedDoc),
    /// One another device signed, as [`Taken::AsIs`], over a record change kept here that
    /// `refused` (a protocol, or the record check with `None`) refused under that
    /// certificate: the change is given up, in the same commit, and the protocols told
    /// ([`AppEvent::RecordChangeDropped`]).
    OverChange {
        record: SignedDoc,
        refused: Option<String>,
    },
}

/// What [`App::judge_for_cert`] found.
enum Judgement {
    /// The record signed under the certificate, its members judged for it.
    Judged(Judged),
    /// A protocol refused, or the record check with `None`: the renewal waits.
    Waits(Option<String>),
    /// The protocols can't run with the certificate: it is refused for good.
    Refused,
}

/// The record held, signed under a certificate the app is about to take, its members
/// judged for it ([`App::judge_for_cert`]).
struct Judged {
    record: SignedDoc,
    /// Its `app.put`, kept for delivery in the commit that takes the certificate.
    pending: PendingRecord,
    /// The protocols' expiry asks it was signed with, without those of members removed.
    expiries: RecordExpiries,
    /// The protocols not registered here whose member it dropped.
    dropped: Vec<String>,
}
