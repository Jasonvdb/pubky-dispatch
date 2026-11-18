//! The app's own record and its own signatures: what a protocol changes in the record, and
//! signing under a protocol's own label.
//!
//! **The record** (Switch spec 4.2, Switch wire 3.2). The app record carries one member per
//! protocol under `protocols`, the kinds the app takes in `accepts`, and an `expires_at` of
//! the app's choice. Whenever one of them changes, the app signs a new record with an
//! `updated_at` later than every record of it before, and delivers it to its switch with
//! `app.put` (Switch wire 6.2). An app whose protocol needs public data also publishes the
//! same record on its identity's Homeserver, at `/pub/pubky-switch/v1/apps/<app_id>.json`
//! (Switch spec 3.4, 4.1), as the carrying form of Switch wire 2.2.
//!
//! **Order of the writes.** Each record is signed once and kept (`record`, `pending/record`)
//! before its `app.put` is first sent, and sent again byte for byte until answered. Once the
//! switch holds it, the commit that records the answer keeps it under `pending/publish`, for
//! an app that publishes, and only then is it written to the Homeserver: the record
//! published is the one delivered, in the same bytes (Switch spec 4.2: an app delivers its
//! record with `app.put` before it publishes it, and publishes again a publication that
//! failed; Switch wire 2.1 "Sign once"). A delivery that fails keeps the record and goes
//! again at the next read, before anything is published; a Homeserver write that fails
//! stays owed, and goes again at the next read or with the next change, without failing the
//! read. Until then, readers of the Homeserver see the record published before.
//!
//! **Renewal.** The Switch sets no schedule for renewing a record: `expires_at` is the app's
//! choice (Switch spec 4.2). A protocol whose readers rely on its apps' records picks one
//! and calls [`App::renew_record`] by it.
//!
//! **One expiry for every protocol.** The record has one `expires_at` (Switch wire 3.2), and
//! each protocol's rules on it are its own (Switch spec 4.2): a protocol may require one. The
//! app keeps each protocol's fixed deadline, relative lifetime or no-expiry policy (`rexp`), and signs
//! the record with the earliest of them, so the record never outlives what any protocol
//! asked for, resolving lifetimes at the exact new signed timestamp, within the identity's age limit.
//! It does not expire only while no protocol asks for an expiry. A protocol
//! that asked for a later one renews the record by its own schedule. A backup carries the
//! expiries asked, and a restore keeps them.
//!
//! **A protocol's signatures** (Switch spec 1, 13.2; Switch wire 2.3). A protocol's own
//! formats sign `lp(label, fields...)` with the app's signing key under a label of the
//! protocol's, never under one that starts with `pubky-switch/`, of any version, so no input
//! of a protocol's format is an input of one of the Switch's, now or later.

use pubky_switch_core::labels::is_switch_label;
use pubky_switch_core::records::{AppRecord, app_record_path};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::MAX_TIME_MS;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use std::collections::BTreeMap;

use super::events::AppEvent;
use super::next_body::NextBody;
use super::state::{PendingRecord, key};
use super::{App, AppError, Refusal};
use crate::error::TransportError;
use crate::transport::BoxFuture;

/// Writes the app's public files on its own identity's Homeserver.
///
/// Object-safe; the app holds an `Arc<dyn HomeserverWriter>`. The host implements it on the
/// Pubky session of the app's grant, which covers the app's record path (Switch spec 3.4);
/// tests fake it.
pub trait HomeserverWriter: Send + Sync {
    /// Put `bytes` at `path` on `identity`'s Homeserver, replacing what is there. `Ok` only
    /// once the write is durable there: the app then owes nothing more of it.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when the Homeserver can't be written now.
    fn put(
        &self,
        identity: [u8; 32],
        path: String,
        bytes: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), TransportError>>;

    /// Delete the file at `path` on `identity`'s Homeserver; one that isn't there is
    /// deleted already. `Ok` only once the delete is durable on the Homeserver: the app
    /// calls `leave` on it, and from then on nothing would delete the file again (Switch
    /// spec 12.3).
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when the Homeserver can't be written now.
    fn delete(&self, identity: [u8; 32], path: String)
    -> BoxFuture<'_, Result<(), TransportError>>;
}

/// How often, at most, an app that owes no publication reads its Homeserver copy to compare
/// it with the newest record the switch accepted: the readers' cache of 10 minutes
/// ([`super::DOC_CACHE_MS`]), the app's choice. [`App::publish_record`] reads it whenever
/// called.
pub const PUBLISHED_CHECK_MS: u64 = super::DOC_CACHE_MS;

/// Where the app's record stands on the Homeserver after a call (Switch spec 4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Publication {
    /// The app doesn't publish its record ([`super::AppConfig::publishes_record`]): the switch
    /// alone holds it.
    NotPublishing,
    /// The switch has accepted no record of the app that this app knows of, as after a
    /// provider loss until the new service answers the re-registration, or after a restore
    /// from a backup that carries none: nothing is published until one is accepted.
    NothingAccepted,
    /// The Homeserver holds the newest record the switch accepted: nothing is owed.
    Published,
    /// The Homeserver holds a record of the app with a later `updated_at` than the newest
    /// the switch accepted, as after a restore from an older backup: nothing is written over
    /// it (Switch spec 4.2).
    Superseded,
    /// The switch holds the record, and its Homeserver read or write failed: it stays owed,
    /// and goes again at the next read or with the next change.
    Owed {
        /// Why the write failed.
        error: TransportError,
    },
    /// Nothing is owed, and the read that checks the Homeserver copy failed: the copy is
    /// read again at the next read.
    Unchecked {
        /// Why the read failed.
        error: TransportError,
    },
    /// The Homeserver copy is missing, and the app runs on devices that share its keys:
    /// another device may have deleted it to leave, so the copy is written back only once
    /// the switch has shown the app current: at the next read, after its feed, or right
    /// after the switch accepts the app's `app.put` (Switch spec 4.2). It stays owed until
    /// then.
    AwaitingRead,
}

/// A protocol's own expiry ask of the app's record, resolved only for a newly signed record
/// (Switch spec 4.2): the record's `expires_at` is the earliest asked.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordExpiry {
    /// No expiry.
    Never,
    /// An absolute time, Unix milliseconds.
    At(u64),
    /// A lifetime in milliseconds from each newly signed record's `updated_at`, capped by
    /// the identity's `record_max_age`.
    Lifetime(u64),
}

impl RecordExpiry {
    pub(super) fn valid(self) -> bool {
        match self {
            Self::Never => true,
            Self::At(at) | Self::Lifetime(at) => at > 0 && at <= MAX_TIME_MS,
        }
    }

    pub(super) fn at(self, updated_at: u64, max_age: u64) -> Option<Option<u64>> {
        match self {
            Self::Never => Some(None),
            Self::At(at) => (at > updated_at && at <= MAX_TIME_MS).then_some(Some(at)),
            Self::Lifetime(lifetime) => {
                let requested = updated_at.checked_add(lifetime)?;
                if lifetime == 0 || requested > MAX_TIME_MS {
                    return None;
                }
                let at = updated_at.checked_add(lifetime.min(max_age))?;
                (at > updated_at).then_some(Some(at))
            }
        }
    }
}

pub(super) type RecordExpiries = BTreeMap<String, RecordExpiry>;

fn expiry_refused(protocol: &str) -> AppError {
    Refusal::Usage(format!(
        "the record expiry `{protocol}` asked for must be writable and later than its signed timestamp"
    ))
    .into()
}

impl App {
    /// Set the member the registered protocol `protocol` adds to the app's record, under its
    /// name, or remove it with `None`, and the expiry `protocol` asks of the record, `None`
    /// for none (Switch spec 4.2). The record's `expires_at` is the earliest expiry any
    /// protocol of the app asked for, `None` while none did. The new record is signed
    /// once, kept with the expiry asked, delivered with `app.put`, and then published on
    /// the Homeserver by an app that publishes. When the record doesn't change, nothing is
    /// signed, the expiry asked is kept, and only what is owed of an earlier record goes.
    ///
    /// The switch checks only the member's form: it follows the JSON rules of the rest of
    /// the record (Switch wire 1.1, 3.2). What goes inside it, and whether a protocol
    /// requires `expires_at`, are the protocol's.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a name no protocol of the app is registered under, an
    /// expiry asked (this protocol's or another's) at or before the next signed timestamp, naming the protocol
    /// that asked for it, a member the switch would refuse, or a record over the operation
    /// cap, before anything is signed. When another protocol's expiry has lapsed, this
    /// protocol's `expires_at`, if later than that timestamp or `None`, is kept for the next signing,
    /// and its `member` is not: the next record signed, at any protocol's change, carries
    /// the expiry with the member the record held. [`Refusal::Stopped`], [`Refusal::Left`] or
    /// [`Refusal::Gone`]; a store failure;
    /// the error of the delivery, after which the record is kept and goes again at the next
    /// read.
    pub async fn set_protocol_member(
        &mut self,
        protocol: &str,
        member: Option<Map<String, Value>>,
        expires_at: Option<u64>,
    ) -> Result<Publication, AppError> {
        self.set_member_expiry(
            protocol,
            member,
            expires_at.map_or(RecordExpiry::Never, RecordExpiry::At),
            false,
        )
        .await
    }

    /// Set a protocol member with an expiry measured from the exact `updated_at` the
    /// writer signs, even when the device clock goes back (Switch spec 4.2).
    /// `None` asks for no expiry; the earliest expiry any protocol asked for still wins.
    /// An unchanged member preserves its expiry policy and finishes owed delivery. A
    /// restored unaccepted record is signed anew; an accepted or pending record keeps
    /// its signed bytes. Use [`App::renew_record_with_lifetime`] to change only the policy.
    /// Removing the member clears its policy. Other protocols' members and policies
    /// remain unchanged.
    ///
    /// The lifetime applies to each new signed record, including changes by another
    /// protocol or a certificate renewal, and is capped by the current identity's record
    /// age limit. Use [`App::set_protocol_member`] for a fixed absolute deadline.
    /// The policy and signed bytes are kept together before delivery; an exact retry
    /// sends those bytes without extending their lifetime. On clock rollback, a new
    /// signing first obtains verified service time; failure keeps no new candidate.
    ///
    /// # Errors
    ///
    /// As [`App::set_protocol_member`], also [`Refusal::Usage`] for a zero lifetime,
    /// an expiry outside the wire time range, or an unadvanceable `updated_at`.
    pub async fn set_protocol_member_with_lifetime(
        &mut self,
        protocol: &str,
        member: Option<Map<String, Value>>,
        lifetime_ms: Option<u64>,
    ) -> Result<Publication, AppError> {
        self.set_member_expiry(
            protocol,
            member,
            lifetime_ms.map_or(RecordExpiry::Never, RecordExpiry::Lifetime),
            true,
        )
        .await
    }

    async fn set_member_expiry(
        &mut self,
        protocol: &str,
        member: Option<Map<String, Value>>,
        expiry: RecordExpiry,
        preserve_unchanged: bool,
    ) -> Result<Publication, AppError> {
        let protocol = protocol.to_owned();
        Box::pin(async move {
            let mut body = self.own_record_body().await?;
            self.check_registered(&protocol)?;
            if !expiry.valid() {
                return Err(expiry_refused(&protocol));
            }
            if body.body().protocols.get(&protocol) == member.as_ref() {
                if preserve_unchanged {
                    return self.put_own_record(body, false, None).await;
                }
                let policies = self.record_expiries().await?;
                if policies.get(&protocol) == Some(&expiry) && !self.record_needs_new_delivery() {
                    let now = self.now().max(self.highest_service_time().unwrap_or(0));
                    for (name, policy) in &policies {
                        if matches!(policy, RecordExpiry::At(at) if *at <= now) {
                            return Err(expiry_refused(name));
                        }
                    }
                    return self.deliver_record().await;
                }
            }
            let expiry = if preserve_unchanged && member.is_none() {
                RecordExpiry::Never
            } else {
                expiry
            };
            let (expiries, updated_at) = self.asked_expiries(&protocol, expiry).await?;
            body.set_member(protocol, member);
            body.set_expires_at(self.resolve_record_expiries(&expiries, updated_at)?);
            self.put_own_record(body, false, Some((&expiries, updated_at)))
                .await
        })
        .await
    }

    /// Renew the app's record for the registered protocol `protocol`, with the expiry it
    /// asks of the record, `None` for none: sign it again with a new `updated_at` and the
    /// earliest expiry any protocol of the app asked for as its `expires_at`, the rest
    /// unchanged, deliver it and publish it (Switch spec 4.2).
    ///
    /// The Switch sets no schedule for it: when to renew is the protocol's to choose, and a
    /// protocol whose readers rely on its apps' records must choose one, or its records
    /// lapse. Readers trust a record until the earlier of its `expires_at` and its
    /// `updated_at` plus the identity's record age limit (Switch spec 4.3,
    /// `record_max_age`), so a schedule renews within both.
    ///
    /// # Errors
    ///
    /// As [`App::set_protocol_member`].
    pub async fn renew_record(
        &mut self,
        protocol: &str,
        expires_at: Option<u64>,
    ) -> Result<Publication, AppError> {
        self.renew_record_expiry(
            protocol,
            expires_at.map_or(RecordExpiry::Never, RecordExpiry::At),
        )
        .await
    }

    /// Renew with an expiry measured from the exact new `updated_at`, preserving every
    /// protocol member (Switch spec 4.2). `None` asks for no expiry; other protocols'
    /// earlier expiry requests remain in force. This call always signs a new record.
    /// Choosing when to renew, including after clock rollback, remains the caller's duty.
    ///
    /// # Errors
    ///
    /// As [`App::set_protocol_member_with_lifetime`].
    pub async fn renew_record_with_lifetime(
        &mut self,
        protocol: &str,
        lifetime_ms: Option<u64>,
    ) -> Result<Publication, AppError> {
        self.renew_record_expiry(
            protocol,
            lifetime_ms.map_or(RecordExpiry::Never, RecordExpiry::Lifetime),
        )
        .await
    }

    async fn renew_record_expiry(
        &mut self,
        protocol: &str,
        expiry: RecordExpiry,
    ) -> Result<Publication, AppError> {
        let protocol = protocol.to_owned();
        Box::pin(async move {
            let mut body = self.own_record_body().await?;
            self.check_registered(&protocol)?;
            let (expiries, updated_at) = self.asked_expiries(&protocol, expiry).await?;
            body.set_expires_at(self.resolve_record_expiries(&expiries, updated_at)?);
            self.put_own_record(body, true, Some((&expiries, updated_at)))
                .await
        })
        .await
    }

    /// The expiry each protocol asked of the record (`rexp`), with `protocol`'s now
    /// `expires_at`.
    ///
    /// Each protocol's ask is its own: one that is later than the next signed time, or `None`, is kept, in a
    /// commit of its own, even while another protocol's has lapsed and the record can't be
    /// signed, so two protocols whose expiries lapsed each renew in turn, and the record is
    /// signed once neither is lapsed. The host may renew for a protocol that doesn't.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] when `expires_at` is at or before the next signed time, naming `protocol`, with
    /// nothing kept; or when another protocol's is, naming it, with `protocol`'s ask kept:
    /// a record signed with it would have lapsed already, so nothing is signed or sent until
    /// that protocol asks for a later one.
    async fn asked_expiries(
        &mut self,
        protocol: &str,
        expiry: RecordExpiry,
    ) -> Result<(RecordExpiries, u64), AppError> {
        if !expiry.valid() {
            return Err(expiry_refused(protocol));
        }
        let mut expiries = self.record_expiries().await?;
        let held = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
        let updated_at = self.next_record_time(held.updated_at()).await?;
        expiry
            .at(updated_at, self.state.own_doc.record_max_age_ms())
            .ok_or_else(|| expiry_refused(protocol))?;
        let changed = expiries.get(protocol) != Some(&expiry);
        expiries.insert(protocol.to_owned(), expiry);
        if let Err(error) = self.resolve_record_expiries(&expiries, updated_at) {
            // Keep a valid caller's ask while another protocol prevents signing, so the
            // protocols can each renew in turn (Switch spec 4.2).
            if changed {
                let mut tx = self.tx()?;
                tx.put(key::RECORD_EXPIRIES, &expiries)?;
                self.commit(tx).await?;
            }
            return Err(error);
        }
        Ok((expiries, updated_at))
    }

    pub(super) async fn record_expiries(&self) -> Result<RecordExpiries, AppError> {
        let expiries: RecordExpiries = self
            .reader()
            .get(key::RECORD_EXPIRIES)
            .await?
            .unwrap_or_default();
        if expiries
            .iter()
            .any(|(name, expiry)| !self.protocols.contains(name) || !expiry.valid())
        {
            return Err(super::corrupt());
        }
        Ok(expiries)
    }

    pub(super) fn resolve_record_expiries(
        &self,
        expiries: &RecordExpiries,
        updated_at: u64,
    ) -> Result<Option<u64>, AppError> {
        let mut earliest = None;
        for (name, expiry) in expiries {
            if let Some(at) = expiry
                .at(updated_at, self.state.own_doc.record_max_age_ms())
                .ok_or_else(|| expiry_refused(name))?
            {
                earliest = Some(earliest.map_or(at, |held: u64| held.min(at)));
            }
        }
        Ok(earliest)
    }

    /// Bring the record's `accepts` to the kinds [`super::Protocol::accepts`] gives for the
    /// certificate the app presents, which are never wider than what its scopes receive
    /// (Switch spec 3.4). When they differ from the record's, the record is signed again,
    /// delivered and published; otherwise only what is owed goes.
    ///
    /// # Errors
    ///
    /// As [`App::set_protocol_member`].
    pub async fn update_accepts(&mut self) -> Result<Publication, AppError> {
        Box::pin(async move {
            let mut body = self.own_record_body().await?;
            body.set_accepts(self.protocols.accepts(&self.state.cert));
            self.put_own_record(body, false, None).await
        })
        .await
    }

    /// Send what is owed of the app's record: its delivery, then its Homeserver write. The
    /// Homeserver copy is read and, when it differs from the newest record the switch
    /// accepted, that record is written again, unless the copy is later. A read
    /// ([`App::receive`]) does the same, reading the copy at most once per
    /// [`PUBLISHED_CHECK_MS`] while nothing is owed.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`], [`Refusal::Left`] or [`Refusal::Gone`]; a store failure; the
    /// error of the delivery.
    pub async fn publish_record(&mut self) -> Result<Publication, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            // The copy is read whatever the last check.
            self.published_checked_ms = None;
            self.deliver_record().await
        })
        .await
    }

    /// Sign `lp(label, fields...)` with the app's signing key, for a format of a protocol on
    /// the Switch, such as a grant its verifiers check with the key the app's certificate
    /// names (Switch spec 1, 13.2; Switch wire 2.1, 2.3). The fields are encoded as Switch
    /// wire 1.4 gives; the label is the protocol's own. Sign once: the caller keeps the
    /// signature with the bytes it signed, and never signs the same body again.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a label that starts with `pubky-switch/`, of any version,
    /// which only the Switch's formats use (Switch spec 13.2 "Labels");
    /// [`Refusal::Stopped`], [`Refusal::Left`] or [`Refusal::Gone`].
    pub fn sign_protocol(&self, label: &str, fields: &[&[u8]]) -> Result<[u8; 64], AppError> {
        self.refuse_when_stopped()?;
        if is_switch_label(label) {
            return Err(Refusal::Usage(
                "Switch spec 13.2: a protocol signs under labels of its own, never a \
                 pubky-switch/ label"
                    .into(),
            )
            .into());
        }
        Ok(self.state.keys.sign(label, fields))
    }

    /// The body of the record the app presents, once the app may change it.
    async fn own_record_body(&mut self) -> Result<NextBody, AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        Ok(NextBody::held(&self.state)?)
    }

    /// Sign `body` as the app's next record, unless it is the record held and `renew` is
    /// false; keep it with its `app.put`, and `expiries` as the expiries the protocols asked
    /// for (`rexp`) when given, in one commit, then deliver and publish.
    async fn put_own_record(
        &mut self,
        body: NextBody,
        renew: bool,
        expiries: Option<(&RecordExpiries, u64)>,
    ) -> Result<Publication, AppError> {
        let identity = self.state.meta.identity;
        let held = AppRecord::verify(&self.state.record, &identity)?;
        // A record held that the switch never accepted, with no delivery of it kept, as
        // after a restore from a backup taken while its `app.put` was refused or unanswered,
        // goes again with this change, signed anew: the backup carries the accepted record
        // apart, and only that one is published (Switch spec 4.2).
        let unaccepted = self.record_needs_new_delivery();
        if renew || unaccepted || body.body() != held.body() {
            let record = match expiries {
                Some((expiries, updated_at)) => self.sign_record_at(body, expiries, updated_at)?,
                None => self.sign_next_record(body, held.updated_at()).await?,
            };
            let batch = self.record_batch(record.signed()).map_err(refused)?;
            let pending = PendingRecord {
                body: batch.body().to_vec(),
            };
            let mut tx = self.tx()?;
            tx.put(key::RECORD, record.signed())?;
            tx.put(key::PENDING_RECORD, &pending)?;
            if let Some((expiries, _)) = expiries {
                tx.put(key::RECORD_EXPIRIES, expiries)?;
            }
            self.commit(tx).await?;
            self.state.record = record.signed().clone();
            self.state.pending_record = Some(pending);
        } else if let Some((expiries, _)) = expiries {
            let mut tx = self.tx()?;
            tx.put(key::RECORD_EXPIRIES, expiries)?;
            self.commit(tx).await?;
        }
        self.deliver_record().await
    }

    fn record_needs_new_delivery(&self) -> bool {
        self.state.pending_record.is_none()
            && self
                .state
                .accepted
                .as_ref()
                .is_some_and(|accepted| accepted != &self.state.record)
    }

    /// Every new signature uses one timestamp and resolves every protocol policy at it.
    pub(super) async fn sign_next_record(
        &mut self,
        body: NextBody,
        previous: u64,
    ) -> Result<AppRecord, AppError> {
        let expiries = self.record_expiries().await?;
        let updated_at = self.next_record_time(previous).await?;
        self.sign_record_at(body, &expiries, updated_at)
    }

    fn sign_record_at(
        &self,
        body: NextBody,
        expiries: &RecordExpiries,
        updated_at: u64,
    ) -> Result<AppRecord, AppError> {
        let expires_at = self.resolve_record_expiries(expiries, updated_at)?;
        let record = body
            .sign(&self.state.keys, updated_at, expires_at)
            .map_err(refused)?;
        self.read_back(&record)
    }

    /// `record`, signed by the app, as the switch and its readers read it.
    pub(super) fn read_back(&self, record: &AppRecord) -> Result<AppRecord, AppError> {
        AppRecord::verify(record.signed(), &self.state.meta.identity).map_err(refused)
    }

    pub(super) async fn next_record_time(&mut self, held: u64) -> Result<u64, AppError> {
        let next = held
            .checked_add(1)
            .filter(|next| *next <= MAX_TIME_MS)
            .ok_or_else(|| Refusal::Usage("the record time cannot advance".into()))?;
        let now = self.now();
        if now > MAX_TIME_MS {
            return Err(
                Refusal::Usage("the record time is outside the writable range".into()).into(),
            );
        }
        if now < held {
            self.fresh_service_time().await?;
        }
        let verified = self
            .state
            .service_time
            .filter(|time| time.key == self.state.meta.service_key)
            .map_or(0, |time| time.highest_ms);
        let next = next.max(self.now()).max(verified);
        if next > MAX_TIME_MS {
            return Err(
                Refusal::Usage("the record time is outside the writable range".into()).into(),
            );
        }
        Ok(next)
    }

    /// Keep `record`, which the switch has just accepted, as the newest accepted record, in
    /// `tx`, the commit that records the acceptance; for an app that publishes, owe its
    /// Homeserver write there too (Switch spec 4.2). A record the switch refused is never
    /// noted.
    pub(crate) fn note_accepted(
        &self,
        record: &SignedDoc,
        tx: &mut super::state::Tx,
    ) -> Result<(), AppError> {
        tx.put(key::ACCEPTED_RECORD, record)?;
        if self.config.publishes_record {
            tx.put(key::PENDING_PUBLISH, record)?;
        }
        Ok(())
    }

    /// After the commit of [`App::note_accepted`]: the same in memory.
    pub(crate) fn took_accepted(&mut self, record: SignedDoc) {
        if self.config.publishes_record {
            self.state.pending_publish = Some(record.clone());
        }
        self.state.accepted = Some(record);
    }

    /// Publish the newest record the switch accepted, when it is owed or the Homeserver
    /// copy differs from it (Switch spec 4.2, wire 3.2 "Deliver, then publish"). The copy
    /// is read first: one that is the record already settles what is owed, and one with a
    /// later `updated_at`, as after a restore from an older backup, is never written over
    /// ([`Publication::Superseded`]). With nothing owed the copy is read at most once per
    /// [`PUBLISHED_CHECK_MS`], unless `check`. Nothing is published once the app has begun
    /// to leave, from the commit before it deletes its Homeserver record (Switch spec
    /// 12.3): every call that leads here refuses a leaving app first.
    ///
    /// `current` is whether this call has shown the app current: the switch accepted its
    /// record in it, or a read read its feed to the end. An app whose devices share its
    /// keys writes a missing copy back only then, since another device may have deleted it
    /// to leave ([`Publication::AwaitingRead`]). A write that fails leaves the publication
    /// owed, and so does a read that fails while one is owed, both reported
    /// ([`AppEvent::RecordPublishFailed`]); a read that fails while nothing is owed is
    /// tried again at the next read ([`Publication::Unchecked`]). Only the store's failure
    /// is an error.
    pub(crate) async fn publish_owed(
        &mut self,
        check: bool,
        current: bool,
    ) -> Result<Publication, AppError> {
        if !self.config.publishes_record {
            return Ok(Publication::NotPublishing);
        }
        let Some(record) = self.state.accepted.clone() else {
            return Ok(Publication::NothingAccepted);
        };
        let owed = self.state.pending_publish.is_some();
        let now = self.now();
        let checked_lately = self
            .published_checked_ms
            .is_some_and(|at| at <= now && now - at < PUBLISHED_CHECK_MS);
        if !owed && !check && checked_lately {
            return Ok(Publication::Published);
        }
        let writer = self.publisher()?;
        let identity = self.state.meta.identity;
        let path = app_record_path(&self.state.meta.app_id);
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| AppError::InvalidData("the record doesn't serialize".into()))?;
        let copy = match self.env.homeserver.get(identity, path.clone()).await {
            Ok(copy) => copy,
            Err(error) if owed => return Ok(self.publication_failed(error)),
            Err(error) => return Ok(Publication::Unchecked { error }),
        };
        let outcome = match copy {
            Some(held) if held == bytes => Publication::Published,
            Some(held) if self.later_copy(&held, &record) => Publication::Superseded,
            None if self.state.device.multi_device && !current => {
                self.owe_publication(&record).await?;
                return Ok(Publication::AwaitingRead);
            }
            _ => {
                if let Err(error) = writer.put(identity, path, bytes).await {
                    // A repair that failed stays owed, so the next read tries it again
                    // without waiting out the check's interval.
                    self.owe_publication(&record).await?;
                    return Ok(self.publication_failed(error));
                }
                Publication::Published
            }
        };
        if owed {
            let mut tx = self.tx()?;
            tx.delete(key::PENDING_PUBLISH)?;
            self.commit(tx).await?;
            self.state.pending_publish = None;
        }
        // The check counts only once what it found is committed. Set before, a check whose
        // owed write-back failed to commit would leave nothing owed in the store and skip
        // the next read's repair for the interval; the branches that owe a publication
        // need no mark, since what is owed goes at every call.
        self.published_checked_ms = Some(now);
        Ok(outcome)
    }

    /// Owe the publication of `record`, the newest accepted, from a check that found the
    /// Homeserver copy missing or different (`pending/publish`).
    async fn owe_publication(&mut self, record: &SignedDoc) -> Result<(), AppError> {
        if self.state.pending_publish.is_some() {
            return Ok(());
        }
        let mut tx = self.tx()?;
        tx.put(key::PENDING_PUBLISH, record)?;
        self.commit(tx).await?;
        self.state.pending_publish = Some(record.clone());
        Ok(())
    }

    /// A publication that couldn't be made now: reported, and owed.
    fn publication_failed(&mut self, error: TransportError) -> Publication {
        self.events.push(AppEvent::RecordPublishFailed {
            error: error.to_string(),
        });
        Publication::Owed { error }
    }

    /// Whether the Homeserver copy `held` is a record of this app with an `updated_at`
    /// later than `record`'s. A copy that doesn't read as one is written over.
    fn later_copy(&self, held: &[u8], record: &SignedDoc) -> bool {
        let identity = self.state.meta.identity;
        let Ok(held) = serde_json::from_slice::<SignedDoc>(held) else {
            return false;
        };
        let (Ok(held), Ok(record)) = (
            AppRecord::verify(&held, &identity),
            AppRecord::verify(record, &identity),
        ) else {
            return false;
        };
        held.cert().app_id() == self.state.meta.app_id && held.updated_at() > record.updated_at()
    }

    /// The first step of a publishing app's leave (Switch spec 12.3): delete its Homeserver
    /// record. The leave's state is committed before, so nothing republishes it after,
    /// across a restart too.
    pub(crate) async fn unpublish_to_leave(&mut self) -> Result<(), AppError> {
        if !self.config.publishes_record {
            return Ok(());
        }
        let writer = self.publisher()?;
        let path = app_record_path(&self.state.meta.app_id);
        writer
            .delete(self.state.meta.identity, path)
            .await
            .map_err(AppError::Transport)
    }

    /// The Homeserver writer of an app that publishes its record.
    pub(crate) fn publisher(&self) -> Result<std::sync::Arc<dyn HomeserverWriter>, AppError> {
        check_publisher(&self.env, &self.config)?;
        self.env
            .homeserver_writer
            .clone()
            .ok_or_else(|| Refusal::Usage(NO_WRITER.into()).into())
    }
}

const NO_WRITER: &str = "an app that publishes its record needs a Homeserver writer";

/// An app that publishes its record needs a Homeserver writer in its environment.
pub(crate) fn check_publisher(
    env: &super::AppEnv,
    config: &super::AppConfig,
) -> Result<(), AppError> {
    if config.publishes_record && env.homeserver_writer.is_none() {
        return Err(Refusal::Usage(NO_WRITER.into()).into());
    }
    Ok(())
}

/// A record the core or the switch would refuse is the caller's to fix.
fn refused(error: impl std::fmt::Display) -> AppError {
    Refusal::Usage(format!("the app record: {error}")).into()
}
