//! The app's own record and its own signatures: what a protocol changes in the record, and
//! signing under a protocol's own label.
//!
//! **The record** (Dispatch spec 4.2, Dispatch wire 3.2). The app record carries one member per
//! protocol under `protocols`, the kinds the app takes in `accepts`, and an `expires_at` of
//! the app's choice. Whenever one of them changes, the app signs a new record with an
//! `updated_at` later than every record of it before, and delivers it to its Dispatch with
//! `app.put` (Dispatch wire 6.2). An app whose protocol needs public data also publishes the
//! same record on its identity's Homeserver, at `/pub/pubky-dispatch/v1/apps/<app_id>.json`
//! (Dispatch spec 3.4, 4.1), as the carrying form of Dispatch wire 2.2.
//!
//! **Order of the writes.** Each record is signed once and kept (`record`, `pending/record`)
//! before its `app.put` is first sent, and sent again byte for byte until answered. Once the
//! Dispatch holds it, the commit that records the answer keeps it under `pending/publish`, for
//! an app that publishes, and only then is it written to the Homeserver: the record
//! published is the one delivered, in the same bytes (Dispatch spec 4.2: an app delivers its
//! record with `app.put` before it publishes it, and publishes again a publication that
//! failed; Dispatch wire 2.1 "Sign once"). A delivery that fails keeps the record and goes
//! again at the next read, before anything is published; a Homeserver write that fails
//! stays owed, and goes again at the next read or with the next change, without failing the
//! read. Until then, readers of the Homeserver see the record published before.
//!
//! **Renewal.** The Dispatch sets no schedule for renewing a record: `expires_at` is the app's
//! choice (Dispatch spec 4.2). A protocol whose readers rely on its apps' records picks one
//! and calls [`App::renew_record`] by it.
//!
//! **One expiry for every protocol.** The record has one `expires_at` (Dispatch wire 3.2), and
//! each protocol's rules on it are its own (Dispatch spec 4.2): a protocol may require one. The
//! app keeps each protocol's fixed deadline, relative lifetime or no-expiry policy (`rexp`), and signs
//! the record with the earliest of them, so the record never outlives what any protocol
//! asked for, resolving lifetimes at the exact new signed timestamp, within the identity's age limit.
//! It does not expire only while no protocol asks for an expiry. A protocol
//! that asked for a later one renews the record by its own schedule. A backup carries the
//! expiries asked, and a restore keeps them.
//!
//! **A protocol's signatures** (Dispatch spec 1, 13.2; Dispatch wire 2.3). A protocol's own
//! formats sign `lp(label, fields...)` with the app's signing key under a label of the
//! protocol's, never under one that starts with `pubky-dispatch/`, of any version, so no input
//! of a protocol's format is an input of one of the Dispatch's, now or later.

use pubky_dispatch_core::labels::is_dispatch_label;
use pubky_dispatch_core::records::{AppRecord, app_record_path};
use pubky_dispatch_core::sig::SignedDoc;
use pubky_dispatch_core::time::MAX_TIME_MS;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use std::collections::BTreeMap;

use super::events::{AppEvent, RecordBaseCause};
use super::next_body::NextBody;
use super::record_members::{PendingPolicy, RecordEdits};
use super::state::{PendingRecord, Tx, key};
use super::{App, AppError, Refusal};
use crate::error::TransportError;
use crate::transport::BoxFuture;

/// Writes the app's public files on its own identity's Homeserver.
///
/// Object-safe; the app holds an `Arc<dyn HomeserverWriter>`. The host implements it on the
/// Pubky session of the app's grant, which covers the app's record path (Dispatch spec 3.4);
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
    /// calls `leave` on it, and from then on nothing would delete the file again (Dispatch
    /// spec 12.3).
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when the Homeserver can't be written now.
    fn delete(&self, identity: [u8; 32], path: String)
    -> BoxFuture<'_, Result<(), TransportError>>;
}

/// How often, at most, an app that owes no publication reads its Homeserver copy to compare
/// it with the newest record the Dispatch accepted: the readers' cache of 10 minutes
/// ([`super::DOC_CACHE_MS`]), the app's choice. [`App::publish_record`] reads it whenever
/// called.
pub const PUBLISHED_CHECK_MS: u64 = super::DOC_CACHE_MS;

/// Where the app's record stands on the Homeserver after a call (Dispatch spec 4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Publication {
    /// The app doesn't publish its record ([`super::AppConfig::publishes_record`]): the Dispatch
    /// alone holds it.
    NotPublishing,
    /// The Dispatch has accepted no record of the app that this app knows of, as after a
    /// provider loss until the new service answers the re-registration, or after a restore
    /// from a backup that carries none: nothing is published until one is accepted.
    NothingAccepted,
    /// The Homeserver holds the newest record the Dispatch accepted: nothing is owed.
    Published,
    /// A newer local record choice is unresolved. An unsigned owner change must be
    /// signed and delivered, an edit held aside decided by its owner
    /// ([`App::clear_held_record_edit`], [`App::clear_held_accepts`]), or the held newer
    /// record accepted or verifiably superseded, before repairing the older accepted copy
    /// (Dispatch spec 4.2). Reads can still complete.
    AwaitingRecord,
    /// The Homeserver holds a record of the app with a later `updated_at` than the newest
    /// the Dispatch accepted, as after a restore from an older backup: nothing is written over
    /// it (Dispatch spec 4.2).
    Superseded,
    /// The Dispatch holds the record, and its Homeserver read or write failed: it stays owed,
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
    /// the Dispatch has shown the app current: at the next read, after its feed, or right
    /// after the Dispatch accepts the app's `app.put` (Dispatch spec 4.2). It stays owed until
    /// then. Also what a publication answers inside the app before the first read after a
    /// restore, or while a read left the record the Dispatch holds unread
    /// ([`super::RecordBaseCause`]): nothing is written then, and [`App::publish_record`]
    /// itself is refused.
    AwaitingRead,
}

/// A protocol's own expiry ask of the app's record, resolved only for a newly signed record
/// (Dispatch spec 4.2): the record's `expires_at` is the earliest asked.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
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

/// What a refusal says while a read left the base unread ([`App::record_base_known`]).
fn base_unread_text(cause: RecordBaseCause) -> &'static str {
    match cause {
        RecordBaseCause::EntryUnverified => {
            "the app's entry at the Dispatch doesn't verify: read (receive) again, or go on \
             from the record held (build_on_held_record), then submit the change or publish \
             again"
        }
        RecordBaseCause::CertificateRefused => {
            "the app's record at the Dispatch is under a renewed certificate the app refused: \
             once a renewal its protocols run with is taken at a read, submit the change or \
             publish again"
        }
        RecordBaseCause::OtherCertificate => {
            "the app's record at the Dispatch is under a certificate the app doesn't present: \
             read (receive) again, then submit the change or publish again"
        }
    }
}

fn expiry_refused(protocol: &str) -> AppError {
    Refusal::Usage(format!(
        "the record expiry `{protocol}` asked for must be writable and later than its signed timestamp"
    ))
    .into()
}

fn after_record_time(held: u64) -> Result<u64, AppError> {
    held.checked_add(1)
        .filter(|next| *next <= MAX_TIME_MS)
        .ok_or_else(|| Refusal::Usage("the record time cannot advance".into()).into())
}

enum MemberChange {
    Set(Option<Map<String, Value>>),
    SetWithLifetime(Option<Map<String, Value>>),
    Renew,
}

impl App {
    /// Set the member the registered protocol `protocol` adds to the app's record, under its
    /// name, or remove it with `None`, and the expiry `protocol` asks of the record, `None`
    /// for none (Dispatch spec 4.2). The record's `expires_at` is the earliest expiry any
    /// protocol of the app asked for, `None` while none did. The new record is signed
    /// once, kept with the expiry asked, delivered with `app.put`, and then published on
    /// the Homeserver by an app that publishes. When the record doesn't change, nothing is
    /// signed, the expiry asked is kept, and only what is owed of an earlier record goes.
    ///
    /// The Dispatch checks only the member's form: it follows the JSON rules of the rest of
    /// the record (Dispatch wire 1.1, 3.2). What goes inside it, and whether a protocol
    /// requires `expires_at`, are the protocol's.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a name no protocol of the app is registered under, an
    /// expiry asked (this protocol's or another's) at or before the next signed timestamp, naming the protocol
    /// that asked for it, a member the Dispatch would refuse, or a record over the operation
    /// cap, before anything is signed. When another protocol's expiry has lapsed, this
    /// valid member change and expiry are kept together for the next signing. The call
    /// still fails: nothing new has been signed or published. Every later signature
    /// applies the pending members or waits for their owners' valid expiry choices.
    /// [`Refusal::Stopped`], [`Refusal::Left`] or [`Refusal::Gone`]; a store failure;
    /// the error of the delivery, after which the record is kept and goes again at the next
    /// read.
    /// Signing uses verified service time or one millisecond after the previous record,
    /// whichever is later. A failed time read returns its error and leaves the unsigned
    /// edit and its expiry saved for the next read. If the edit's own deadline has
    /// passed then, the read discards it and returns its expiry refusal once.
    pub async fn set_protocol_member(
        &mut self,
        protocol: &str,
        member: Option<Map<String, Value>>,
        expires_at: Option<u64>,
    ) -> Result<Publication, AppError> {
        self.set_member_expiry(
            protocol,
            MemberChange::Set(member),
            expires_at.map_or(RecordExpiry::Never, RecordExpiry::At),
        )
        .await
    }

    /// Set a protocol member with an expiry measured from the exact `updated_at` the
    /// writer signs, even when the device clock goes back (Dispatch spec 4.2).
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
    /// sends those bytes without extending their lifetime.
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
            MemberChange::SetWithLifetime(member),
            lifetime_ms.map_or(RecordExpiry::Never, RecordExpiry::Lifetime),
        )
        .await
    }

    /// Set a registered protocol's member and its explicit expiry policy together
    /// (Dispatch spec 4.2). Unlike the lifetime convenience setter, an unchanged member
    /// also adopts the supplied policy. Use [`App::protocol_record`] to read the desired
    /// member and policy, including an unsigned edit held by another protocol's expiry.
    ///
    /// # Errors
    ///
    /// As [`App::set_protocol_member`]. A refused signing can retain the pair locally;
    /// it never reports publication of that unsigned edit.
    pub async fn set_protocol_member_with_expiry(
        &mut self,
        protocol: &str,
        member: Option<Map<String, Value>>,
        expiry: RecordExpiry,
    ) -> Result<Publication, AppError> {
        self.set_member_expiry(protocol, MemberChange::Set(member), expiry)
            .await
    }

    async fn set_member_expiry(
        &mut self,
        protocol: &str,
        change: MemberChange,
        expiry: RecordExpiry,
    ) -> Result<Publication, AppError> {
        let protocol = protocol.to_owned();
        Box::pin(async move {
            let (mut body, old_edits) = self.own_record_body().await?;
            old_edits.apply(&mut body);
            self.check_registered(&protocol)?;
            if !expiry.valid() {
                return Err(expiry_refused(&protocol));
            }
            let renew = matches!(change, MemberChange::Renew);
            let preserve_unchanged = matches!(change, MemberChange::SetWithLifetime(_));
            let current = body.body().protocol(&protocol);
            let member = match change {
                MemberChange::Set(member) | MemberChange::SetWithLifetime(member) => member,
                MemberChange::Renew => current.cloned(),
            };
            if !renew && current == member.as_ref() {
                if preserve_unchanged {
                    return self.put_own_record(body, false, None).await;
                }
                let policies = self.record_expiries().await?;
                if policies.get(&protocol) == Some(&expiry)
                    && !self.record_needs_new_delivery()
                    && old_edits.is_empty()
                {
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
            let old_expiries = self.record_expiries().await?;
            let mut expiries = old_expiries.clone();
            expiries.insert(protocol.clone(), expiry);
            let mut edits = old_edits.clone();
            // Kept from the first unsigned change: a later one of this run leaves it.
            let previous = old_expiries.get(&protocol).copied();
            let policy = edits
                .changes
                .policies
                .entry(protocol.clone())
                .or_insert(PendingPolicy {
                    previous,
                    renew: false,
                });
            policy.renew |= renew;
            edits.members.insert(protocol.clone(), member.clone());
            body.set_member(protocol.clone(), member);
            self.put_record_edits(
                body,
                &edits,
                &expiries,
                (&old_edits, &old_expiries),
                Some((&protocol, expiry)),
            )
            .await
        })
        .await
    }

    /// Keep the unsigned choice before reading the service time. Only a refusal of
    /// this edit restores the previous choice; a sibling's lapsed policy can be renewed.
    async fn put_record_edits(
        &mut self,
        mut body: NextBody,
        edits: &RecordEdits,
        expiries: &RecordExpiries,
        before: (&RecordEdits, &RecordExpiries),
        owner: Option<(&str, RecordExpiry)>,
    ) -> Result<Publication, AppError> {
        let previous = body.body().updated_at;
        let verified = self
            .state
            .service_time
            .filter(|time| time.key == self.state.meta.service_key)
            .map_or(0, |time| time.highest_ms);
        let earliest = after_record_time(previous)?.max(verified);
        let max_age = self.state.own_doc.record_max_age_ms();
        let check_owner = |at| -> Result<(), AppError> {
            if let Some((name, expiry)) = owner {
                expiry.at(at, max_age).ok_or_else(|| expiry_refused(name))?;
            }
            Ok(())
        };
        check_owner(earliest)?;
        self.check_record_members(edits)?;
        body.check_writable(self.state.meta.generation, earliest, None)
            .map_err(refused)?;
        self.save_record_members(edits, expiries).await?;

        let updated_at = self.next_record_time(previous).await?;
        let expires_at = self.resolve_record_expiries(expiries, updated_at);
        let writable = check_owner(updated_at).and_then(|()| {
            if let Ok(at) = expires_at {
                body.check_writable(self.state.meta.generation, updated_at, at)
                    .map_err(refused)?;
            }
            Ok(())
        });
        if let Err(error) = writable {
            self.save_record_members(before.0, before.1).await?;
            return Err(error);
        }
        body.set_expires_at(expires_at?);
        self.put_own_record(body, edits.renews(), Some((expiries, updated_at)))
            .await
    }

    async fn save_record_members(
        &mut self,
        members: &RecordEdits,
        expiries: &RecordExpiries,
    ) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.put(key::RECORD_EXPIRIES, expiries)?;
        if members.is_empty() {
            tx.delete(key::RECORD_MEMBERS)?;
        } else {
            tx.put(key::RECORD_MEMBERS, members)?;
        }
        self.commit(tx).await
    }

    /// A read with verified service time can finish an unsigned edit. It reports a
    /// draft past its own deadline once. A lapsed signed policy waits for its owner.
    pub(super) async fn prepare_pending_members(&mut self) -> Result<(), AppError> {
        let mut edits = self.record_members().await?;
        if edits.is_empty() {
            return Ok(());
        }
        let mut body = NextBody::held(&self.state)?;
        let updated_at = self.next_record_time(body.body().updated_at).await?;
        let mut expiries = self.record_expiries().await?;
        let expired = expiries.iter().find(|(name, expiry)| {
            edits.members.contains_key(*name)
                && matches!(expiry, RecordExpiry::At(at) if *at <= updated_at)
        });
        if let Some((name, _)) = expired {
            let name = name.clone();
            edits.members.remove(&name);
            let previous = edits
                .changes
                .policies
                .remove(&name)
                .and_then(|policy| policy.previous);
            match previous {
                Some(policy) => expiries.insert(name.clone(), policy),
                None => expiries.remove(&name),
            };
            self.save_record_members(&edits, &expiries).await?;
            return Err(expiry_refused(&name));
        }
        edits.apply(&mut body);
        let Ok(expires_at) = self.resolve_record_expiries(&expiries, updated_at) else {
            return Ok(());
        };
        // A finite expiry may put an otherwise valid draft over the operation size.
        if body
            .check_writable(self.state.meta.generation, updated_at, expires_at)
            .is_err()
        {
            return Ok(());
        }
        body.set_expires_at(expires_at);
        self.keep_own_record(body, edits.renews(), Some((&expiries, updated_at)))
            .await
    }

    /// Renew the app's record for the registered protocol `protocol`, with the expiry it
    /// asks of the record, `None` for none: sign it again with a new `updated_at` and the
    /// earliest expiry any protocol of the app asked for as its `expires_at`, the rest
    /// unchanged, deliver it and publish it (Dispatch spec 4.2).
    ///
    /// The Dispatch sets no schedule for it: when to renew is the protocol's to choose, and a
    /// protocol whose readers rely on its apps' records must choose one, or its records
    /// lapse. Readers trust a record until the earlier of its `expires_at` and its
    /// `updated_at` plus the identity's record age limit (Dispatch spec 4.3,
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
        self.set_member_expiry(
            protocol,
            MemberChange::Renew,
            expires_at.map_or(RecordExpiry::Never, RecordExpiry::At),
        )
        .await
    }

    /// Renew with an expiry measured from the exact new `updated_at`, preserving every
    /// protocol member (Dispatch spec 4.2). `None` asks for no expiry; other protocols'
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
        self.set_member_expiry(
            protocol,
            MemberChange::Renew,
            lifetime_ms.map_or(RecordExpiry::Never, RecordExpiry::Lifetime),
        )
        .await
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
    /// (Dispatch spec 3.4). When they differ from the record's, the record is signed again,
    /// delivered and published; otherwise only what is owed goes.
    ///
    /// # Errors
    ///
    /// As [`App::set_protocol_member`].
    pub async fn update_accepts(&mut self) -> Result<Publication, AppError> {
        Box::pin(async move {
            let (mut body, old_edits) = self.own_record_body().await?;
            let accepts = self.protocols.accepts(&self.state.cert);
            let changed = accepts != body.body().accepts;
            old_edits.apply(&mut body);
            if accepts == body.body().accepts {
                return self.put_own_record(body, false, None).await;
            }
            body.set_accepts(accepts.clone());
            let mut edits = old_edits.clone();
            let expiries = self.record_expiries().await?;
            edits.changes.accepts = changed.then_some(accepts);
            if edits.changes.accepts.is_none() {
                self.save_record_members(&edits, &expiries).await?;
                return self.put_own_record(body, false, None).await;
            }
            self.put_record_edits(body, &edits, &expiries, (&old_edits, &expiries), None)
                .await
        })
        .await
    }

    /// Send what is owed of the app's record: its delivery, then its Homeserver write. The
    /// Homeserver copy is read and, when it differs from the newest record the Dispatch
    /// accepted, that record is written again, unless the copy is later or a newer local
    /// record choice is unresolved, an edit held aside included
    /// ([`Publication::AwaitingRecord`]). A read
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
            // After a restore nothing of the backup's is published before the first read.
            self.record_base_known()?;
            // The copy is read whatever the last check.
            self.published_check = None;
            self.deliver_record().await
        })
        .await
    }

    /// Sign `lp(label, fields...)` with the app's signing key, for a format of a protocol on
    /// the Dispatch, such as a grant its verifiers check with the key the app's certificate
    /// names (Dispatch spec 1, 13.2; Dispatch wire 2.1, 2.3). The fields are encoded as Dispatch
    /// wire 1.4 gives; the label is the protocol's own. Sign once: the caller keeps the
    /// signature with the bytes it signed, and never signs the same body again.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a label that starts with `pubky-dispatch/`, of any version,
    /// which only the Dispatch's formats use (Dispatch spec 13.2 "Labels");
    /// [`Refusal::Stopped`], [`Refusal::Left`] or [`Refusal::Gone`].
    pub fn sign_protocol(&self, label: &str, fields: &[&[u8]]) -> Result<[u8; 64], AppError> {
        self.refuse_when_stopped()?;
        if is_dispatch_label(label) {
            return Err(Refusal::Usage(
                "Dispatch spec 13.2: a protocol signs under labels of its own, never a \
                 pubky-dispatch/ label"
                    .into(),
            )
            .into());
        }
        Ok(self.state.keys.sign(label, fields))
    }

    /// The signed body and its pending edits, once the app may change them.
    async fn own_record_body(&mut self) -> Result<(NextBody, RecordEdits), AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        // Before the base is known nothing is saved either: an edit worked out against the
        // backup's record could say something else on the record published since.
        self.record_gate()?;
        Ok((NextBody::held(&self.state)?, self.record_members().await?))
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
        self.keep_own_record(body, renew, expiries).await?;
        self.deliver_record().await
    }

    async fn keep_own_record(
        &mut self,
        body: NextBody,
        renew: bool,
        expiries: Option<(&RecordExpiries, u64)>,
    ) -> Result<(), AppError> {
        let identity = self.state.meta.identity;
        let held = AppRecord::verify(&self.state.record, &identity)?;
        // A record held that the Dispatch never accepted, with no delivery of it kept, as
        // after a restore from a backup taken while its `app.put` was refused or unanswered,
        // goes again with this change, signed anew: the backup carries the accepted record
        // apart, and only that one is published (Dispatch spec 4.2).
        let unaccepted = self.record_needs_new_delivery();
        let pending_members = expiries.is_none() && !self.record_members().await?.is_empty();
        if renew || unaccepted || pending_members || body.body() != held.body() {
            let record = match expiries {
                Some((expiries, updated_at)) => self.sign_record_at(body, expiries, updated_at)?,
                None => self.sign_next_record(body, held.updated_at()).await?,
            };
            let mut tx = self.tx()?;
            let pending = self.stage_own_record(&record, &mut tx)?;
            if let Some((expiries, _)) = expiries {
                tx.put(key::RECORD_EXPIRIES, expiries)?;
            }
            tx.delete(key::RECORD_MEMBERS)?;
            self.commit(tx).await?;
            self.state.record = record.signed().clone();
            self.state.pending_record = Some(pending);
        } else if let Some((expiries, _)) = expiries {
            let mut tx = self.tx()?;
            tx.put(key::RECORD_EXPIRIES, expiries)?;
            tx.delete(key::RECORD_MEMBERS)?;
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// Keep the signed record with the exact batch that will deliver it (Dispatch wire 6.2).
    pub(super) fn stage_own_record(
        &self,
        record: &AppRecord,
        tx: &mut Tx,
    ) -> Result<PendingRecord, AppError> {
        let batch = self.record_batch(record.signed()).map_err(refused)?;
        let pending = PendingRecord {
            body: batch.body().to_vec(),
        };
        tx.put(key::RECORD, record.signed())?;
        tx.put(key::PENDING_RECORD, &pending)?;
        Ok(pending)
    }

    pub(super) fn record_needs_new_delivery(&self) -> bool {
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

    pub(super) fn sign_record_at(
        &self,
        body: NextBody,
        expiries: &RecordExpiries,
        updated_at: u64,
    ) -> Result<AppRecord, AppError> {
        self.record_gate()?;
        let expires_at = self.resolve_record_expiries(expiries, updated_at)?;
        body.check_writable(self.state.meta.generation, updated_at, expires_at)
            .map_err(refused)?;
        let record = body
            .sign(&self.state.keys, updated_at, expires_at)
            .map_err(refused)?;
        self.read_back(&record)
    }

    /// After a restore, no change of the app's record is taken or signed, and nothing is
    /// published, until the restore's first read took the record the Dispatch holds
    /// ([`App::take_listed_cert`]) and finished its check: the next one builds on the
    /// newest of the held and that one, never on the backup's alone (Dispatch spec 4.2, the
    /// later `updated_at` wins). Nor while a read left that record unread
    /// ([`RecordBaseCause`]), until a read takes one or, for an entry that doesn't verify,
    /// the user goes on from the record held ([`App::build_on_held_record`]). A load or
    /// join holds its newest record and needs no read.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] until then, naming the cause and what goes on from it: the
    /// caller submits the change, or publishes, again after it.
    pub(super) fn record_base_known(&self) -> Result<(), AppError> {
        if self
            .state
            .restore
            .as_ref()
            .is_some_and(|restore| !restore.key_checked)
        {
            return Err(Refusal::NotNow(
                "the app's record published since the restore isn't read yet: read (receive), \
                 then submit the change or publish again"
                    .into(),
            )
            .into());
        }
        match self.base_unread_now() {
            None => Ok(()),
            Some(cause) => Err(Refusal::NotNow(base_unread_text(cause).into()).into()),
        }
    }

    /// The base left unread as the gates see it: an entry that doesn't verify is passed
    /// while the user's go-ahead for it holds, in memory, at the generation it was given
    /// at ([`App::build_on_held_record`]). `rbase` stays until a read settles it.
    pub(super) fn base_unread_now(&self) -> Option<RecordBaseCause> {
        match self.state.base_unread {
            Some(RecordBaseCause::EntryUnverified)
                if self.state.held_taken == Some(self.state.meta.generation) =>
            {
                None
            }
            cause => cause,
        }
    }

    /// Whether the own `identity.json` lists for the app a renewed certificate the app
    /// refused ([`AppEvent::CertificateRefused`]): the Dispatch then refuses a record under the
    /// one it presents (`403 not_current`, Dispatch wire 6.2), and a kept one would be refused
    /// at every read before its feed.
    fn listing_refused(&self) -> bool {
        let Some(listed) = self.state.own_doc.listed_cert(&self.state.meta.app_id) else {
            return false;
        };
        listed != self.state.cert.hash()
            && self
                .state
                .cert_refused
                .as_deref()
                .is_some_and(|refused| refused == pubky_dispatch_core::enc::b64(&listed))
    }

    /// The gate where a record of the app is signed, and so taken or kept: a base known
    /// ([`App::record_base_known`]), and no listed renewal the app refused
    /// ([`App::record_send_gate`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`], naming the cause and what goes on from it.
    pub(super) fn record_gate(&self) -> Result<(), AppError> {
        self.record_base_known()?;
        self.record_send_gate()
    }

    /// The gate where a record of the app is sent (`app.put`): no base a read after a
    /// restore left unread, and no listed renewal the app refused, under which the Dispatch
    /// refuses it. A restore's own check isn't part of it: the paths that send before it,
    /// a provider change's registration, read the base where they register first
    /// ([`App::read_before_registering`]), and every other one passes [`App::record_gate`].
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`], naming the cause and what goes on from it: a renewal the
    /// protocols run with, taken at a read, for a refused one.
    pub(super) fn record_send_gate(&self) -> Result<(), AppError> {
        if let Some(cause) = self.base_unread_now() {
            return Err(Refusal::NotNow(base_unread_text(cause).into()).into());
        }
        if self.listing_refused() {
            return Err(Refusal::NotNow(
                "the app's identity.json lists a renewed certificate the app refused, so a \
                 record under the one it presents is refused at the dispatch: once a renewal \
                 its protocols run with is taken at a read, submit the change again"
                    .into(),
            )
            .into());
        }
        Ok(())
    }

    /// The user's go-ahead is gone: at a load, and wherever the state is rebuilt from the
    /// store, as after a failed or unknown commit. While a cause is held, it is told again
    /// unless an event of exactly that cause is retained, so the user is asked again
    /// (`STATE.md`, "The restored base"). Every place that drops the go-ahead calls this.
    pub(super) async fn go_ahead_lost(&mut self) -> Result<(), AppError> {
        self.state.held_taken = None;
        let Some(cause) = self.state.base_unread else {
            return Ok(());
        };
        let retained = self.kept_duties().await?.into_iter().any(|event| {
            matches!(event, AppEvent::RecordBaseUnread { cause: kept, .. } if kept == cause)
        });
        if retained {
            return Ok(());
        }
        let mut tx = self.tx()?;
        self.keep_duty(&mut tx, super::events::Duty::RecordBaseUnread { cause })?;
        self.commit(tx).await
    }

    /// Go on from the record this installation holds after a restore whose read found the
    /// app's entry at the Dispatch not verifying ([`RecordBaseCause::EntryUnverified`]): the
    /// next change of the record builds on the held one, and its `app.put` replaces that
    /// entry. The user's decision, never the app's: an entry this build can't read may hold
    /// a record that another build of the app signed later, which that change replaces.
    /// The go-ahead is kept in memory only, for the generation it is given at: `rbase`
    /// stays until a read settles it, and after a reload the base is unread again, told
    /// again, and the user is asked again. Nothing changes when no base is unread.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] before the first read after a restore, with no base left unread
    /// yet; [`Refusal::Usage`] when the base is unread for another cause, naming what goes on from it; a stopped app or
    /// a store failure.
    pub async fn build_on_held_record(&mut self) -> Result<(), AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        match self.state.base_unread {
            // Nothing unread: before the first read after a restore, that read comes first.
            None => self.record_base_known(),
            // Also before the restore's own check, which waits behind a registration at a
            // service a provider change took the app to, where the entry was read.
            // In memory only: `rbase` stays until a read settles it, and a reload asks again.
            Some(RecordBaseCause::EntryUnverified) => {
                self.state.held_taken = Some(self.state.meta.generation);
                Ok(())
            }
            Some(
                cause @ (RecordBaseCause::CertificateRefused | RecordBaseCause::OtherCertificate),
            ) => Err(Refusal::Usage(format!(
                "going on from the record held is for an entry at the Dispatch that doesn't \
                 verify; here {}",
                base_unread_text(cause)
            ))
            .into()),
        }
    }

    /// `record`, signed by the app, as the Dispatch and its readers read it.
    pub(super) fn read_back(&self, record: &AppRecord) -> Result<AppRecord, AppError> {
        AppRecord::verify(record.signed(), &self.state.meta.identity).map_err(refused)
    }

    /// The next writable timestamp, at least one millisecond after the held record.
    pub(super) async fn next_record_time(&mut self, held: u64) -> Result<u64, AppError> {
        let next = after_record_time(held)?;
        // Keep the signed feed read off the stack when receive dates a renewed record.
        Box::pin(self.fresh_service_time()).await?;
        let verified = self.time_fresh_at.as_ref().ok_or_else(|| {
            AppError::InvalidData("the service time read returned no stamped time".into())
        })?;
        Ok(next.max(verified.service_ms))
    }

    /// Keep `record`, which the Dispatch has just accepted, as the newest accepted record, in
    /// `tx`, the commit that records the acceptance; for an app that publishes, owe its
    /// Homeserver write there too (Dispatch spec 4.2). A record the Dispatch refused is never
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

    /// Publish the newest record the Dispatch accepted, when it is owed or the Homeserver
    /// copy differs from it (Dispatch spec 4.2, wire 3.2 "Deliver, then publish"). The copy
    /// is read first: one that is the record already settles what is owed, and one with a
    /// later `updated_at`, as after a restore from an older backup, is never written over
    /// ([`Publication::Superseded`]). A newer unresolved local choice defers the older
    /// accepted copy ([`Publication::AwaitingRecord`]), without failing the read that can
    /// settle that choice. With nothing owed the copy is read at most once per
    /// [`PUBLISHED_CHECK_MS`], unless `check`. Nothing is published once the app has begun
    /// to leave, from the commit before it deletes its Homeserver record (Dispatch spec
    /// 12.3): every call that leads here refuses a leaving app first.
    ///
    /// `current` is whether this call has shown the app current: the Dispatch accepted its
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
        // After a restore the accepted record is the backup's until the first read took the
        // one the Dispatch holds: nothing is published, repaired or written over before it.
        if self.record_base_known().is_err() {
            return Ok(Publication::AwaitingRead);
        }
        let Some(record) = self.state.accepted.clone() else {
            return Ok(Publication::NothingAccepted);
        };
        let awaiting_record = self.publication_waits_for_record().await?;
        let owed = self.state.pending_publish.is_some();
        let now = self.now();
        let checked_lately = self
            .published_check
            .as_ref()
            .is_some_and(|(at, signature)| {
                signature == &record.sig
                    && now
                        .checked_sub(*at)
                        .is_some_and(|age| age < PUBLISHED_CHECK_MS)
            });
        if !awaiting_record && !owed && !check && checked_lately {
            return Ok(Publication::Published);
        }
        self.published_check = None;
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
            Some(held) if self.later_copy(&held, &record) => {
                if let Ok(copy) = serde_json::from_slice::<SignedDoc>(&held) {
                    let mut tx = self.tx()?;
                    if !Box::pin(self.take_own_later(&copy, &mut tx)).await? {
                        self.commit(tx).await?;
                    }
                }
                if self.publication_waits_for_record().await? {
                    return Ok(Publication::AwaitingRecord);
                }
                Publication::Superseded
            }
            _ if awaiting_record => return Ok(Publication::AwaitingRecord),
            Some(held) if held == bytes => Publication::Published,
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
        self.published_check = (outcome == Publication::Published).then_some((now, record.sig));
        Ok(outcome)
    }

    /// Current unsigned owner edits and strictly newer signed intent take precedence over
    /// repairing an older accepted copy (Dispatch spec 4.2). Equal or older signed bytes
    /// do not keep repair waiting after the current choice has been superseded.
    async fn publication_waits_for_record(&self) -> Result<bool, AppError> {
        if !self.record_members().await?.is_empty() || self.holds_record_edits_aside().await? {
            return Ok(true);
        }
        self.record_is_newer_than_accepted()
    }

    /// Signed ordering, shared by publication and an exact held record seen in the feed.
    pub(super) fn record_is_newer_than_accepted(&self) -> Result<bool, AppError> {
        let identity = self.state.meta.identity;
        let held = AppRecord::verify(&self.state.record, &identity)?;
        let accepted = self
            .state
            .accepted
            .as_ref()
            .map(|accepted| AppRecord::verify(accepted, &identity))
            .transpose()?;
        Ok(accepted.is_none_or(|accepted| held.updated_at() > accepted.updated_at()))
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
    /// later than `record`'s. A copy ahead of the reader's clock does not participate in
    /// comparison or adoption (Dispatch spec 4.2, wire 3.2).
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
        held.cert().app_id() == self.state.meta.app_id
            && !held.is_ahead(self.now())
            && held.updated_at() > record.updated_at()
    }

    /// The first step of a publishing app's leave (Dispatch spec 12.3): delete its Homeserver
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

/// A record the core or the Dispatch would refuse is the caller's to fix.
fn refused(error: impl std::fmt::Display) -> AppError {
    Refusal::Usage(format!("the app record: {error}")).into()
}
