//! Routing: counterparties' `identity.json` and directories, the receive key checks, and
//! the deliveries of the own `identity.json` to their Dispatches (Dispatch spec 4.3, 6.1, 8.1,
//! 12.2 step 5; Dispatch wire 3.8, 7.4.3, 7.4.5, 7.4.10).
//!
//! - **`identity.json`** of a counterparty is the newest copy the app took from any source
//!   (its Homeserver, its Dispatch's directory), under the version floor and the equivocation
//!   check part 1 keeps (`ident/`). A copy older than 10 minutes is read again before a send;
//!   if the Homeserver can't be read the held copy still routes, as a cached directory may.
//! - **A directory** (`dir/<pubky>`) is cached while the counterparty's `identity.json`
//!   names the same Dispatch and generation, and only for the `identity.json` version it was
//!   read under: a newer version, a newer `directory_version` in an append answer, or an
//!   answer naming apps no longer current, has it read again before the next send.
//! - **Recipients** are the current apps whose certificate allows receiving the kind and
//!   whose record lists it in `accepts`, narrowed by the protocol, each with a receive key
//!   record that passes the six checks of Dispatch spec 8.1 against the highest `n` seen for
//!   the app (`rkn/<pubky>/<app_id>`). An app that fails one counts as unreachable, and the
//!   message goes to the others.
//! - **The own `identity.json`** goes to a counterparty's Dispatch (`PUT /peers`) before the
//!   first append there and whenever an answer shows the Dispatch holds an older version
//!   (`peer/<pubky>`, from `known_version`), and, after an own delivery that removes an app
//!   or closes a renewal, to the Dispatches the app wrote to in the last 30 days.

use std::collections::{HashMap, HashSet};

use pubky_dispatch_core::enc::{b64, pubky_id, serde_b64, zbase32_encode};
use pubky_dispatch_core::envelope::Recipient;
use pubky_dispatch_core::http::ErrorCode;
use pubky_dispatch_core::message::Message;
use pubky_dispatch_core::records::{AppRecord, IdentityDoc, ReceiveKeyRecord, VersionOrder};
use pubky_dispatch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::context::LocalView;
use super::error::{Alarm, Refusal};
use super::events::AppEvent;
use super::identity::{self, DOC_CACHE_MS};
use super::state::{SourceReads, Tx};
use super::{App, AppError};
use crate::client::answers::Directory;
use crate::client::read::Obj;
use crate::client::{Credentials, DispatchClient};
use crate::error::{ClientError, StoreError};

/// How long the app keeps delivering its own `identity.json` to the Dispatches it wrote to:
/// the 30 days senders keep sent messages (Dispatch spec 12.2 step 5).
pub const PEER_DELIVERY_MS: u64 = 30 * pubky_dispatch_core::records::DAY_MS;

const DIR_PREFIX: &str = "dir/";
const PEER_PREFIX: &str = "peer/";
const PEERS_DOC: &str = "peers_doc";

fn dir_key(pubky: &[u8; 32]) -> String {
    format!("{DIR_PREFIX}{}", pubky_id(pubky))
}

fn peer_key(pubky: &[u8; 32]) -> String {
    format!("{PEER_PREFIX}{}", pubky_id(pubky))
}

/// Write what the app keeps of `pubky`'s Dispatch into `tx`.
pub(crate) fn put_peer(
    tx: &mut super::state::Tx,
    pubky: &[u8; 32],
    peer: &PeerDispatch,
) -> Result<(), AppError> {
    tx.put(&peer_key(pubky), peer)
}

fn highest_n_key(pubky: &[u8; 32], app_id: &[u8; 16]) -> String {
    format!("rkn/{}/{}", pubky_id(pubky), zbase32_encode(app_id))
}

/// One app of a cached directory, as signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CachedApp {
    #[serde(with = "serde_b64")]
    pub(crate) app_id: [u8; 16],
    pub(crate) record: SignedDoc,
    pub(crate) receive_key: Option<SignedDoc>,
}

/// `dir/<pubky>`: a counterparty's directory as the app read it (Dispatch spec 8.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CachedDirectory {
    pub(crate) origin: String,
    #[serde(with = "serde_b64")]
    pub(crate) service_key: [u8; 32],
    pub(crate) generation: u64,
    /// The `identity.json` version it was read under.
    pub(crate) identity_version: u64,
    pub(crate) directory_version: u64,
    pub(crate) apps_version: u64,
    pub(crate) apps: Vec<CachedApp>,
    /// Read again before the next send.
    pub(crate) stale: bool,
    /// When it was read, app clock.
    pub(crate) read_ms: u64,
}

impl CachedDirectory {
    /// The directory without its apps, always stale, for one too large to keep: what the
    /// next read compares with, the Dispatch, generation, versions and read time, so a
    /// provider loss since is still found and its re-sends made (Dispatch spec 8.1). It
    /// sends to nothing: a stale copy is read again before any send.
    fn stub(&self) -> Self {
        Self {
            apps: Vec::new(),
            stale: true,
            ..self.clone()
        }
    }
}

/// `peer/<pubky>`: what a counterparty's Dispatch holds of the own `identity.json`, and when
/// the app last wrote there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PeerDispatch {
    /// The version its last answer named (`known_version`); `None` when it holds none.
    pub(crate) known_version: Option<u64>,
    /// When the Dispatch last accepted a message from the app, app clock.
    pub(crate) last_sent_ms: Option<u64>,
}

/// `peers_doc`: the own `identity.json` the deliveries of Dispatch spec 12.2 step 5 were last
/// judged against: its version, removed apps and closed renewals, and the counterparties
/// whose Dispatches are still owed the delivery.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PeersDoc {
    version: u64,
    removed: Vec<String>,
    closed: Vec<String>,
    /// The Pubky IDs of the counterparties still owed the delivery, tried again at each
    /// call until it goes or they stop being recent: those a call's budget left untried
    /// first, then those whose delivery failed, in the order they failed.
    owed: Vec<String>,
    /// How many of `owed`, from its start, the pass under way hasn't tried yet. While it is
    /// above zero, a call tries only those; at zero, the next call starts a pass over all.
    #[serde(default, skip_serializing_if = "is_zero")]
    untried: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// `ident/<pubky>/dispatch_read`: when the app last looked up a counterparty's Dispatch copy of its
/// `identity.json`, and whether the read succeeded (Dispatch spec 4.3, "The Dispatch's copy").
/// `lookup` is the number the lookup took when it began ([`dispatch_lookups_key`]): which
/// lookup is the newer is judged by it, not by the clock, which may give two lookups the
/// same millisecond or move back between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DispatchRead {
    at_ms: u64,
    outcome: DispatchCopy,
    version: u64,
    lookup: u64,
}

fn dispatch_read_key(pubky: &[u8; 32]) -> String {
    format!("ident/{}/dispatch_read", pubky_id(pubky))
}

/// `ident/<pubky>/dispatch_lookups`: the number of the last Dispatch lookup begun for a counterparty, one
/// higher at each. It is kept in the store with the lookup's outcome, so the order holds
/// across restarts as the outcome does.
fn dispatch_lookups_key(pubky: &[u8; 32]) -> String {
    format!("ident/{}/dispatch_lookups", pubky_id(pubky))
}

/// Where a counterparty's copy came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CopySource {
    /// Its Homeserver, read now.
    Homeserver(u64),
    /// Its Dispatch's public read (Dispatch wire 7.4.15), bounded by request and service time.
    Dispatch(u64),
    /// A directory answer of its Dispatch: no fresh read of the document.
    Directory,
}

/// Whether the Homeserver's copy of a counterparty's `identity.json` was read at a lookup
/// ([`App::identity_of`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HomeserverCopy {
    /// Read at this lookup, and taken under the version floor.
    Read,
    /// Not read at this lookup: the Homeserver couldn't be read, or publishes no
    /// `identity.json`. The document stands on the copies held.
    Unavailable,
    /// Not read at this lookup: the copy held and the last Dispatch lookup were under 10
    /// minutes old ([`super::DOC_CACHE_MS`]).
    Held,
}

/// Whether a counterparty's Dispatch confirmed its `identity.json` (Dispatch spec 4.3, "The
/// Dispatch's copy"). A lookup's answer counts until the next lookup, once the copy is more
/// than 10 minutes old.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DispatchCopy {
    /// The Dispatch's copy was read with the Homeserver's, and the higher version taken.
    Read,
    /// The Dispatch's copy couldn't be read: the document stands on the Homeserver's copy
    /// and the copies held. An action that relies on it goes ahead only as the protocol
    /// allows without the Dispatch's confirmation (Dispatch spec 4.3, "No silent fallback").
    Unavailable,
    /// The pinned service signed an answer outside the reader's time window. Retry later.
    Stale,
    /// The Dispatch's half of this lookup is still running ([`DispatchLookup`]).
    Pending,
}

/// Who starts an action on a counterparty's public app records (Dispatch spec 4.3, "No
/// silent fallback").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Initiator {
    /// The user starts it, and can confirm it.
    User,
    /// The app acts without the user.
    Automatic,
}

/// Whether an action on a counterparty's public app records may go ahead on a lookup's
/// copy, by Dispatch spec 4.3, "The Dispatch's copy" ([`PeerIdentity::may_act`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MayAct {
    /// The Dispatch confirmed the copy within the last 10 minutes: act on it.
    Now,
    /// The Dispatch's lookup is still running and the grace hasn't passed: wait for it, at
    /// most until this time, app clock, and ask again.
    WaitUntil(u64),
    /// The Dispatch couldn't confirm the copy in time: the action, which the user started,
    /// goes ahead only once the user explicitly confirms it although the identity's Dispatch
    /// couldn't confirm the identity's apps, and the app records an event for it. A lookup
    /// still running keeps running: an answer that arrives before the action takes effect
    /// is still used ([`App::finish_identity_lookup`]).
    IfUserConfirms,
    /// An action without the user: wait for the Dispatch's lookup, with the client's usual
    /// timeout. It never acts on the Homeserver's copy alone.
    WaitForLookup,
    /// An action without the user, and the Dispatch's lookup failed: it isn't taken on this
    /// copy. It may look up once more ([`App::identity_of`] with `refresh`); if that fails
    /// too, the action isn't taken.
    No,
    /// The copy is more than 10 minutes old: look it up again before acting.
    LookUpAgain,
}

/// A counterparty's `identity.json` as a lookup found it ([`App::identity_of`]), with what
/// was read and when, so a protocol applies Dispatch spec 4.3 to it ([`PeerIdentity::may_act`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerIdentity {
    /// The newest copy held: the higher of the Homeserver's and the Dispatch's, under the
    /// version floor the app keeps.
    pub doc: IdentityDoc,
    /// When the copy held was last read from the Homeserver or the Dispatch, app clock: not
    /// the lookup's time when neither could be read at it. A directory-only version has no time.
    pub read_at_ms: Option<u64>,
    /// Whether the Homeserver's copy was read at this lookup.
    pub homeserver: HomeserverCopy,
    /// When the Homeserver last supplied this version, on the app clock.
    pub homeserver_read_ms: Option<u64>,
    /// What the last lookup of the Dispatch's copy found: at this lookup, or, with
    /// [`HomeserverCopy::Held`], at the one before.
    pub dispatch_copy: DispatchCopy,
    /// When the Dispatch was looked up, app clock: when the lookup began while it is
    /// [`DispatchCopy::Pending`], otherwise bounded by the request and signed response time.
    pub dispatch_lookup_ms: u64,
    /// When a public Dispatch read last supplied this version, on the app clock.
    pub dispatch_read_ms: Option<u64>,
}

impl PeerIdentity {
    /// Until when the copy is used without reading it again, app clock: 10 minutes from
    /// the earlier of its last read and the last Dispatch lookup ([`super::DOC_CACHE_MS`]).
    pub fn fresh_until_ms(&self) -> u64 {
        self.read_at_ms.map_or(0, |at| {
            at.min(self.dispatch_lookup_ms).saturating_add(DOC_CACHE_MS)
        })
    }

    /// Whether an action on the counterparty's public app records, such as acting on data
    /// one of them publishes, may go ahead on this copy now (Dispatch spec 4.3, "The Dispatch's
    /// copy"): only once the Dispatch confirmed it, unless the Dispatch's lookup failed or
    /// hasn't answered within `grace_ms` after the Homeserver's read, when a user's action
    /// goes ahead on the user's explicit confirmation and an automatic one waits or isn't
    /// taken. A copy more than 10 minutes old is looked up again first; while a lookup
    /// still runs on such a copy, every action waits for it. `now_ms` is the app clock.
    pub fn may_act(&self, now_ms: u64, by: Initiator, grace_ms: u64) -> MayAct {
        let stale = self.read_at_ms.is_none_or(|at| at > now_ms)
            || self.dispatch_lookup_ms > now_ms
            || now_ms >= self.fresh_until_ms();
        let grace_end = self.dispatch_lookup_ms.saturating_add(grace_ms);
        match (self.dispatch_copy, by) {
            (DispatchCopy::Pending, _) if now_ms < grace_end => MayAct::WaitUntil(grace_end),
            (DispatchCopy::Pending, _) if stale => MayAct::WaitForLookup,
            _ if stale => MayAct::LookUpAgain,
            (DispatchCopy::Read, _) => MayAct::Now,
            (
                DispatchCopy::Pending | DispatchCopy::Unavailable | DispatchCopy::Stale,
                Initiator::User,
            ) => MayAct::IfUserConfirms,
            (DispatchCopy::Pending, Initiator::Automatic) => MayAct::WaitForLookup,
            (DispatchCopy::Unavailable | DispatchCopy::Stale, Initiator::Automatic) => MayAct::No,
        }
    }
}

/// A lookup of a counterparty's `identity.json` for acting on its public app records,
/// begun ([`App::begin_identity_lookup`]): what the Homeserver's read found, and the
/// Dispatch's half, still to run.
#[derive(Debug)]
pub struct IdentityLookup {
    /// The copy as it stands after the Homeserver's read: [`DispatchCopy::Pending`] while
    /// `dispatch` is to run. With [`HomeserverCopy::Held`] the copy held was fresh, and
    /// nothing is to run.
    pub identity: PeerIdentity,
    /// The Dispatch's half: a future that runs apart from the app, so the caller waits for it
    /// at most a grace and lets it run on (Dispatch spec 4.3, "No added latency"). Its answer
    /// goes to [`App::finish_identity_lookup`]. `None` when the copy held was fresh.
    pub dispatch: Option<DispatchLookup>,
}

/// The Dispatch's half of a lookup (Dispatch wire 7.4.15): the public read of the Dispatch the
/// newest copy names, following a freeze once to the next service. It runs apart from the
/// app, on the caller's executor. Dropping it abandons the lookup. Each verified copy
/// retains its own observation time.
pub struct DispatchLookup {
    future: crate::transport::BoxFuture<'static, DispatchAnswer>,
}

impl std::fmt::Debug for DispatchLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DispatchLookup")
    }
}

impl std::future::Future for DispatchLookup {
    type Output = DispatchAnswer;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<DispatchAnswer> {
        self.get_mut().future.as_mut().poll(cx)
    }
}

/// What the Dispatch's half of a lookup found ([`DispatchLookup`]), for
/// [`App::finish_identity_lookup`]. Its copies are verified with the identity's key, and
/// still go through the version floor and the equivocation check there. Its freshness
/// counts from its request and signed response time, however long the answer is held before it is
/// finished (Dispatch spec 4.3); whether it is newer than another lookup's outcome is judged
/// by the order the lookups began in.
#[derive(Clone, Debug)]
pub struct DispatchAnswer {
    pubky: [u8; 32],
    homeserver: HomeserverCopy,
    lookup: u64,
    read_ms: u64,
    version: u64,
    outcome: DispatchCopy,
    copies: Vec<(IdentityDoc, u64)>,
    terminal_read: bool,
}

impl DispatchAnswer {
    /// The counterparty looked up.
    pub fn identity(&self) -> [u8; 32] {
        self.pubky
    }

    /// Whether the whole Dispatch lookup succeeded. Finish the answer even after a failed
    /// successor lookup to retain a verified copy from the preceding service.
    pub fn read(&self) -> bool {
        self.outcome == DispatchCopy::Read
    }

    /// Whether the successful terminal service response supplied this exact signed
    /// document. A staged successor can complete [`Self::read`] without confirming any
    /// document. A failed, stale or frozen successor confirms none either.
    ///
    /// Check the already authorized document before passing this answer to
    /// [`App::finish_identity_lookup`]. Before acting, require its returned document to
    /// still match and apply [`PeerIdentity::may_act`] and the current-app checks. This
    /// observation does not replace the version floor, equivocation or freshness checks.
    pub fn confirms(&self, expected: &IdentityDoc) -> bool {
        self.read()
            && self.terminal_read
            && self
                .copies
                .last()
                .is_some_and(|(doc, _)| doc.signed() == expected.signed())
    }

    /// Whether the lookup learned nothing from any service: no verified copy of the
    /// identity, and so no freeze or version, was obtained, as when the Dispatch can't be
    /// reached or answers only with an error. A lookup that failed after a service gave a
    /// verified copy or a freeze is not one: [`Self::read`] is `false` for it too, but it
    /// carries what that service answered.
    pub fn learned_nothing(&self) -> bool {
        self.copies.is_empty()
    }

    /// The lookup start, capped by the signed time of each service needed to complete it.
    pub fn read_ms(&self) -> u64 {
        self.read_ms
    }
}

fn lookup_failure(error: &ClientError) -> DispatchCopy {
    match error {
        ClientError::StaleAnswer { .. } => DispatchCopy::Stale,
        _ => DispatchCopy::Unavailable,
    }
}

/// One recipient app of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) app_id: [u8; 16],
    pub(crate) recipient: Recipient,
}

impl App {
    // ---------------------------------------------------------------------------------
    // identity.json of a counterparty

    /// The newest `identity.json` of `pubky`: the own one, or a copy at most 10 minutes old,
    /// read again from the Homeserver otherwise (`force` reads it again whatever its age). A
    /// held copy routes on when the Homeserver can't be read.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] for an identity seen equivocating, or one the app can get no copy
    /// of.
    pub(crate) fn peer_identity<'a>(
        &'a mut self,
        pubky: &'a [u8; 32],
        force: bool,
    ) -> crate::transport::BoxFuture<'a, Result<IdentityDoc, AppError>> {
        // Boxed where it is made, as `App::try_item` says.
        Box::pin(self.peer_identity_inner(pubky, force))
    }

    async fn peer_identity_inner(
        &mut self,
        pubky: &[u8; 32],
        force: bool,
    ) -> Result<IdentityDoc, AppError> {
        if *pubky == self.state.meta.identity {
            return Ok(self.state.own_doc.clone());
        }
        let reader = self.reader();
        if reader
            .exists(&super::state::key::ident_equivocated(pubky))
            .await?
        {
            return Err(Refusal::NotNow(
                "Dispatch spec 4.3: the counterparty's identity.json equivocated".into(),
            )
            .into());
        }
        let held = identity::held_copy(&reader, pubky).await?;
        let now = self.now();
        if let Some((doc, reads)) = &held
            && !force
            && reads.is_fresh(now)
        {
            return Ok(doc.clone());
        }
        match identity::read_homeserver(self.env.homeserver.as_ref(), pubky).await {
            Ok(Some(fetched)) => {
                self.take_peer_copy(pubky, fetched, CopySource::Homeserver(now))
                    .await
            }
            Ok(None) | Err(_) => held.map(|(doc, _)| doc).ok_or_else(|| {
                AppError::Refused(Refusal::NotNow(
                    "Dispatch spec 4.3: no identity.json of the counterparty can be read".into(),
                ))
            }),
        }
    }

    /// A counterparty's `identity.json` for acting on its public app records (Dispatch spec
    /// 4.3, "The Dispatch's copy"): the copy held while it and the last Dispatch lookup are
    /// under 10 minutes old ([`super::DOC_CACHE_MS`]), unless `refresh`; otherwise the
    /// Homeserver copy, then the public copy of the Dispatch the newest document names
    /// (following a freeze once to the next service), the higher version taken. Every copy
    /// goes through the version floor and the equivocation check the app keeps (Dispatch spec
    /// 4.3): another body at a version seen marks the identity, reported as
    /// [`super::AppEvent::PeerEquivocation`], and no copy of it is used from then on.
    ///
    /// The call waits for the Dispatch's read to end. A caller that waits for it at most a
    /// grace after the Homeserver's read, as Dispatch spec 4.3 "No added latency" has it,
    /// uses [`App::begin_identity_lookup`] and [`App::finish_identity_lookup`] instead.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for the own identity ([`App::own_identity`]); [`Refusal::NotNow`]
    /// for an identity seen equivocating, or one the app can get no copy of; a store
    /// failure.
    pub async fn identity_of(
        &mut self,
        pubky: &[u8; 32],
        refresh: bool,
    ) -> Result<PeerIdentity, AppError> {
        Box::pin(async move {
            let lookup = self.begin_inner(pubky, refresh).await?;
            match lookup.dispatch {
                None => Ok(lookup.identity),
                Some(dispatch) => {
                    let answer = dispatch.await;
                    self.finish_inner(answer).await
                }
            }
        })
        .await
    }

    /// The first half of [`App::identity_of`]: the copy held when it is fresh, or else the
    /// Homeserver's copy, read and taken now, and the Dispatch's half as a future that runs
    /// apart from the app (Dispatch spec 4.3, "No added latency"). The caller races it against
    /// its grace ([`PeerIdentity::may_act`]), lets it run on while the user confirms, and
    /// hands its answer to [`App::finish_identity_lookup`].
    ///
    /// # Errors
    ///
    /// As [`App::identity_of`].
    pub async fn begin_identity_lookup(
        &mut self,
        pubky: &[u8; 32],
        refresh: bool,
    ) -> Result<IdentityLookup, AppError> {
        Box::pin(self.begin_inner(pubky, refresh)).await
    }

    /// The second half of [`App::identity_of`]: take the copies the Dispatch's half read,
    /// under the version floor and the equivocation check, and keep when the Dispatch was
    /// looked up and whether it answered, which counts until the next lookup. The answer
    /// counts from the request and signed response time ([`DispatchAnswer::read_ms`]):
    /// one held more than 10 minutes gives a copy to look up again. An answer of a lookup
    /// begun before the one whose outcome is kept leaves that outcome standing, whatever
    /// the clock read at either.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] for an identity seen equivocating, or that equivocates now; a
    /// store failure.
    pub async fn finish_identity_lookup(
        &mut self,
        answer: DispatchAnswer,
    ) -> Result<PeerIdentity, AppError> {
        Box::pin(self.finish_inner(answer)).await
    }

    async fn refuse_equivocated(&self, pubky: &[u8; 32]) -> Result<(), AppError> {
        if self
            .reader()
            .exists(&super::state::key::ident_equivocated(pubky))
            .await?
        {
            return Err(Refusal::NotNow(
                "Dispatch spec 4.3: the counterparty's identity.json equivocated".into(),
            )
            .into());
        }
        Ok(())
    }

    /// The copy held of `pubky`, with what was read and when.
    async fn peer_identity_held(
        &self,
        pubky: &[u8; 32],
        homeserver: HomeserverCopy,
        dispatch_copy: DispatchCopy,
        dispatch_lookup_ms: u64,
    ) -> Result<PeerIdentity, AppError> {
        let reader = self.reader();
        let Some((doc, reads)) = identity::held_copy(&reader, pubky).await? else {
            return Err(Refusal::NotNow(
                "Dispatch spec 4.3: no identity.json of the counterparty can be read".into(),
            )
            .into());
        };
        Ok(PeerIdentity {
            doc,
            read_at_ms: reads.latest(),
            homeserver,
            homeserver_read_ms: reads.homeserver_ms,
            dispatch_copy,
            dispatch_lookup_ms,
            dispatch_read_ms: reads.dispatch_ms,
        })
    }

    async fn begin_inner(
        &mut self,
        pubky: &[u8; 32],
        refresh: bool,
    ) -> Result<IdentityLookup, AppError> {
        self.ready_local().await?;
        if *pubky == self.state.meta.identity {
            return Err(Refusal::Usage("the own identity.json is the app's own".into()).into());
        }
        self.refuse_equivocated(pubky).await?;
        let reader = self.reader();
        let now = self.now();
        let held = identity::held_copy(&reader, pubky).await?;
        let last: Option<DispatchRead> = reader.get(&dispatch_read_key(pubky)).await?;
        let fresh = |at: u64| now.checked_sub(at).is_some_and(|age| age < DOC_CACHE_MS);
        if !refresh
            && let (Some((doc, reads)), Some(last)) = (&held, last)
            && last.version == doc.version()
            && reads.is_fresh(now)
            && fresh(last.at_ms)
        {
            let identity = self
                .peer_identity_held(pubky, HomeserverCopy::Held, last.outcome, last.at_ms)
                .await?;
            return Ok(IdentityLookup {
                identity,
                dispatch: None,
            });
        }
        // The Homeserver's copy first; one that can't be read leaves the copy held.
        let home_started = self.now();
        let (named, homeserver) =
            match identity::read_homeserver(self.env.homeserver.as_ref(), pubky).await {
                Ok(Some(fetched)) => (
                    Some(
                        self.take_peer_copy(pubky, fetched, CopySource::Homeserver(home_started))
                            .await?,
                    ),
                    HomeserverCopy::Read,
                ),
                Ok(None) | Err(_) => (held.map(|(doc, _)| doc), HomeserverCopy::Unavailable),
            };
        let Some(named) = named else {
            return Err(Refusal::NotNow(
                "Dispatch spec 4.3: no identity.json of the counterparty can be read".into(),
            )
            .into());
        };
        // Then the Dispatch's copy, at the Dispatch the newest copy names. The lookup takes the
        // next number now, so a later one is newer whatever the clock does.
        let lookup = self
            .reader()
            .get::<u64>(&dispatch_lookups_key(pubky))
            .await?
            .unwrap_or(0)
            .saturating_add(1);
        let mut tx = self.tx()?;
        tx.put(&dispatch_lookups_key(pubky), &lookup)?;
        self.commit(tx).await?;
        let started = self.now();
        let identity = self
            .peer_identity_held(pubky, homeserver, DispatchCopy::Pending, started)
            .await?;
        let dispatch = self.dispatch_lookup(pubky, &named, homeserver, lookup);
        Ok(IdentityLookup {
            identity,
            dispatch: Some(dispatch),
        })
    }

    async fn finish_inner(&mut self, answer: DispatchAnswer) -> Result<PeerIdentity, AppError> {
        self.ready_local().await?;
        let pubky = answer.pubky;
        self.refuse_equivocated(&pubky).await?;
        for (copy, read_ms) in answer.copies {
            self.take_peer_copy(&pubky, copy, CopySource::Dispatch(read_ms))
                .await?;
        }
        // An answer of a lookup begun before the last outcome does not replace it: a
        // lookup begun later, perhaps on a newer copy, that failed still counts until the
        // reader looks up again (Dispatch spec 4.3). The order is the lookups' numbers, not
        // their times, which may be equal or run backward.
        let last: Option<DispatchRead> = self.reader().get(&dispatch_read_key(&pubky)).await?;
        let outcome = match last {
            Some(last) if last.lookup >= answer.lookup => last,
            _ => {
                let outcome = DispatchRead {
                    at_ms: answer.read_ms.min(self.now()),
                    outcome: answer.outcome,
                    version: answer.version,
                    lookup: answer.lookup,
                };
                let mut tx = self.tx()?;
                tx.put(&dispatch_read_key(&pubky), &outcome)?;
                self.commit(tx).await?;
                outcome
            }
        };
        let mut identity = self
            .peer_identity_held(&pubky, answer.homeserver, outcome.outcome, outcome.at_ms)
            .await?;
        if identity.doc.version() != outcome.version && identity.dispatch_copy == DispatchCopy::Read
        {
            identity.dispatch_copy = DispatchCopy::Unavailable;
        }
        Ok(identity)
    }

    /// The Dispatch's half of a lookup of `pubky`, at the Dispatch `doc` names, and, when it is
    /// frozen, at the next service its freeze names, once (Dispatch wire 7.4.15). Each
    /// verified answer keeps its copy even when the complete lookup fails. A fresh staged
    /// answer leaves the first service's copy in use.
    fn dispatch_lookup(
        &self,
        pubky: &[u8; 32],
        doc: &IdentityDoc,
        homeserver: HomeserverCopy,
        lookup: u64,
    ) -> DispatchLookup {
        let first = self.peer_client(pubky, doc).ok();
        let credentials = Credentials::App {
            identity: self.state.meta.identity,
            keys: self.state.keys.clone(),
            cert: self.state.cert.clone(),
        };
        let transport = std::sync::Arc::clone(&self.env.transport);
        let clock = std::sync::Arc::clone(&self.env.clock);
        let account = *pubky;
        let version = doc.version();
        let future = async move {
            let started = clock.now_ms();
            let mut answer = DispatchAnswer {
                pubky: account,
                homeserver,
                lookup,
                version,
                read_ms: started,
                outcome: DispatchCopy::Unavailable,
                copies: Vec::new(),
                terminal_read: false,
            };
            let Some(first) = first else { return answer };
            let public = match first.public_identity().await {
                Ok(public) => public,
                Err(error) => {
                    answer.outcome = lookup_failure(&error);
                    return answer;
                }
            };
            let observed = started.min(public.server_time_ms()).min(clock.now_ms());
            answer.read_ms = observed;
            answer.version = answer.version.max(public.identity.version());
            answer.copies.push((public.identity, observed));
            answer.terminal_read = public.freeze.is_none();
            if let Some(freeze) = public.freeze {
                let Ok(next) = DispatchClient::new(
                    &freeze.next().url,
                    account,
                    credentials,
                    Some(freeze.next().service_key),
                    transport,
                    std::sync::Arc::clone(&clock),
                ) else {
                    return answer;
                };
                let next_started = clock.now_ms();
                let mut signed_time = None;
                match next.public_identity_with_time(&mut signed_time).await {
                    Ok(public) => {
                        let observed = next_started
                            .min(public.server_time_ms())
                            .min(clock.now_ms());
                        answer.version = answer.version.max(public.identity.version());
                        answer.copies.push((public.identity, observed));
                        if public.freeze.is_some() {
                            return answer;
                        }
                        answer.terminal_read = true;
                    }
                    Err(ClientError::Dispatch {
                        code: ErrorCode::Staged,
                        ..
                    }) => {}
                    Err(error) => {
                        answer.outcome = lookup_failure(&error);
                        return answer;
                    }
                }
                let Some(signed_time) = signed_time else {
                    return answer;
                };
                answer.read_ms = answer
                    .read_ms
                    .min(next_started)
                    .min(signed_time)
                    .min(clock.now_ms());
            }
            answer.outcome = DispatchCopy::Read;
            answer
        };
        DispatchLookup {
            future: Box::pin(future),
        }
    }

    /// Take a counterparty's copy, from its Homeserver, its Dispatch's public read or a
    /// directory answer, and return the newest held. A Homeserver or public read is kept as
    /// its source's last read of that version, measured from the request. It refreshes the copy
    /// held only when it gave that copy or a newer one ([`identity::take_peer_read`]).
    async fn take_peer_copy(
        &mut self,
        pubky: &[u8; 32],
        doc: IdentityDoc,
        source: CopySource,
    ) -> Result<IdentityDoc, AppError> {
        self.observe_peer_copy(pubky, doc, source)
            .await?
            .map(|(doc, _)| doc)
            .ok_or_else(|| {
                Refusal::NotNow(
                    "Dispatch spec 4.3: the counterparty's identity.json equivocated".into(),
                )
                .into()
            })
    }

    /// Apply the same source and version rule to lookup and receive (Dispatch spec 4.3).
    pub(super) async fn observe_peer_copy(
        &mut self,
        pubky: &[u8; 32],
        doc: IdentityDoc,
        source: CopySource,
    ) -> Result<Option<(IdentityDoc, Option<u64>)>, AppError> {
        let reader = self.reader();
        let held = identity::held_copy(&reader, pubky).await?;
        let now = self.now();
        let mut tx = self.tx()?;
        let mut observed = SourceReads::default();
        match source {
            CopySource::Homeserver(at) => observed.homeserver_ms = Some(at.min(now)),
            CopySource::Dispatch(at) => observed.dispatch_ms = Some(at.min(now)),
            CopySource::Directory => {}
        }
        let taken = identity::take_peer_read(&reader, &mut tx, doc, held, observed, now).await?;
        self.commit(tx).await?;
        match taken {
            Ok((doc, reads)) => Ok(Some((doc, reads.latest()))),
            Err(equivocation) => {
                self.events.push(AppEvent::PeerEquivocation {
                    identity: *pubky,
                    version: equivocation.version,
                });
                Ok(None)
            }
        }
    }

    // ---------------------------------------------------------------------------------
    // Directories

    pub(crate) async fn cached_directory(
        &self,
        pubky: &[u8; 32],
    ) -> Result<Option<CachedDirectory>, AppError> {
        self.reader().get(&dir_key(pubky)).await
    }

    /// A client for `pubky`'s account at the Dispatch its `identity.json` names, presenting
    /// the app's certificate (Dispatch wire 7.2).
    pub(crate) fn peer_client(
        &self,
        pubky: &[u8; 32],
        doc: &IdentityDoc,
    ) -> Result<DispatchClient, AppError> {
        Ok(DispatchClient::new(
            &doc.inbox().url,
            *pubky,
            Credentials::App {
                identity: self.state.meta.identity,
                keys: self.state.keys.clone(),
                cert: self.state.cert.clone(),
            },
            Some(doc.inbox().service_key),
            std::sync::Arc::clone(&self.env.transport),
            std::sync::Arc::clone(&self.env.clock),
        )?)
    }

    /// `pubky`'s directory: the cached one while it still holds (module docs), otherwise
    /// read again. `invite_code` admits a read at a Dispatch that doesn't admit the app yet
    /// (Dispatch wire 7.4.10).
    ///
    /// # Errors
    ///
    /// As [`App::peer_identity`]; a failed read or commit.
    pub(crate) fn directory_of<'a>(
        &'a mut self,
        pubky: &'a [u8; 32],
        invite_code: Option<&'a str>,
    ) -> crate::transport::BoxFuture<'a, Result<CachedDirectory, AppError>> {
        // Boxed where it is made, as `App::try_item` says.
        Box::pin(self.directory_of_inner(pubky, invite_code))
    }

    async fn directory_of_inner(
        &mut self,
        pubky: &[u8; 32],
        invite_code: Option<&str>,
    ) -> Result<CachedDirectory, AppError> {
        let doc = self.peer_identity(pubky, false).await?;
        let cached = self.cached_directory(pubky).await?;
        if let Some(cached) = &cached
            && !cached.stale
            && cached.origin == doc.inbox().url
            && cached.generation == doc.generation()
            && cached.identity_version >= doc.version()
        {
            return Ok(cached.clone());
        }
        self.read_directory(pubky, &doc, cached, invite_code).await
    }

    fn read_directory<'a>(
        &'a mut self,
        pubky: &'a [u8; 32],
        doc: &'a IdentityDoc,
        previous: Option<CachedDirectory>,
        invite_code: Option<&'a str>,
    ) -> crate::transport::BoxFuture<'a, Result<CachedDirectory, AppError>> {
        // Boxed where it is made, as `App::try_item` says.
        Box::pin(self.read_directory_inner(pubky, doc, previous, invite_code))
    }

    async fn read_directory_inner(
        &mut self,
        pubky: &[u8; 32],
        doc: &IdentityDoc,
        previous: Option<CachedDirectory>,
        invite_code: Option<&str>,
    ) -> Result<CachedDirectory, AppError> {
        let own = *pubky == self.state.meta.identity;
        let started = self.now();
        let directory: Directory = if own {
            let result = self.client.directory(None).await;
            self.take(result).await?
        } else {
            let client = self.peer_client(pubky, doc)?;
            client.directory(invite_code).await?
        };
        // Apps whose entry didn't verify are left out of the directory, and the others used
        // (Dispatch spec 8.1).
        for app_id in &directory.skipped {
            self.unreachable(pubky, *app_id);
        }
        let mut newest = doc.clone();
        if own {
            // The directory's copy is newer than the one held: taken (Dispatch spec 4.3).
            if doc.compare(&directory.identity) == VersionOrder::Newer {
                self.take_own_copy(directory.identity.clone()).await?;
                newest = self.state.own_doc.clone();
            }
        } else {
            let taken = self
                .take_peer_copy(pubky, directory.identity.clone(), CopySource::Directory)
                .await?;
            if taken.version() > newest.version() {
                newest = taken;
            }
            self.note_known_version(pubky, directory.known_version)
                .await?;
        }
        let cached = CachedDirectory {
            origin: doc.inbox().url.clone(),
            service_key: doc.inbox().service_key,
            generation: doc.generation(),
            identity_version: newest.version(),
            directory_version: directory.directory_version,
            apps_version: directory.apps_version,
            apps: directory
                .apps
                .iter()
                .map(|app| CachedApp {
                    app_id: app.app_id,
                    record: app.record.signed().clone(),
                    receive_key: app.receive_key.as_ref().map(|k| k.signed().clone()),
                })
                .collect(),
            stale: false,
            read_ms: started.min(self.now()),
        };
        let mut tx = self.tx()?;
        keep_directory(&mut tx, pubky, &cached)?;
        match self.commit(tx).await {
            // A store that refuses it as too large keeps only its stub: this send uses it.
            Err(AppError::Store(StoreError::TooLarge { .. })) => {
                self.reload_now().await?;
                let mut tx = self.tx()?;
                tx.put(&dir_key(pubky), &cached.stub())?;
                self.commit(tx).await?;
            }
            committed => committed?,
        }
        // A provider loss since the copy held: the old Dispatch's accepted messages since the
        // previous check are sent again to the new one (Dispatch spec 8.1).
        if let Some(previous) = previous
            && !own
            && (previous.origin != cached.origin || previous.generation != cached.generation)
            && newest
                .body()
                .recovery_from
                .is_some_and(|lost| lost >= previous.generation)
        {
            self.resend_since(pubky, previous.read_ms).await?;
        }
        Ok(cached)
    }

    /// Drop `pubky`'s cached directory, so the next send reads it again.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn forget_directory(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let mut tx = self.tx()?;
            tx.delete(&dir_key(pubky))?;
            self.commit(tx).await
        })
        .await
    }

    pub(crate) async fn mark_directory_stale(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        if let Some(mut cached) = self.cached_directory(pubky).await? {
            cached.stale = true;
            let mut tx = self.tx()?;
            keep_directory(&mut tx, pubky, &cached)?;
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// The apps of `pubky` a message of `kind` would go to now (Dispatch spec 8.1), reading
    /// its `identity.json` and directory as a send would.
    ///
    /// # Errors
    ///
    /// As a send's directory read.
    pub async fn recipients_for(
        &mut self,
        pubky: &[u8; 32],
        message: &Message,
    ) -> Result<Vec<[u8; 16]>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let (routes, _) = self.routes(pubky, message, None).await?;
            Ok(routes.into_iter().map(|r| r.app_id).collect())
        })
        .await
    }

    /// The recipients of `message` and the `apps_version` they were chosen for. A cached
    /// directory that leaves no app is read again once before the counterparty counts as
    /// unreachable (Dispatch spec 8.1).
    pub(crate) fn routes<'a>(
        &'a mut self,
        pubky: &'a [u8; 32],
        message: &'a Message,
        invite_code: Option<&'a str>,
    ) -> crate::transport::BoxFuture<'a, Result<(Vec<Route>, u64), AppError>> {
        // Boxed where it is made, as `App::try_item` says.
        Box::pin(self.routes_inner(pubky, message, invite_code))
    }

    async fn routes_inner(
        &mut self,
        pubky: &[u8; 32],
        message: &Message,
        invite_code: Option<&str>,
    ) -> Result<(Vec<Route>, u64), AppError> {
        let directory = self.directory_of(pubky, invite_code).await?;
        let routes = self.choose(pubky, &directory, message).await?;
        if !routes.is_empty() {
            return Ok((routes, directory.apps_version));
        }
        let doc = self.peer_identity(pubky, false).await?;
        let directory = self
            .read_directory(pubky, &doc, Some(directory), invite_code)
            .await?;
        let routes = self.choose(pubky, &directory, message).await?;
        if routes.is_empty() {
            return Err(Refusal::NotNow(
                "Dispatch spec 8.1: no reachable app of the counterparty takes the kind".into(),
            )
            .into());
        }
        Ok((routes, directory.apps_version))
    }

    /// The apps of a directory a message goes to, each with a checked receive key.
    fn choose<'a>(
        &'a mut self,
        pubky: &'a [u8; 32],
        directory: &'a CachedDirectory,
        message: &'a Message,
    ) -> crate::transport::BoxFuture<'a, Result<Vec<Route>, AppError>> {
        // Boxed where it is made, as `App::try_item` says.
        Box::pin(self.choose_inner(pubky, directory, message))
    }

    async fn choose_inner(
        &mut self,
        pubky: &[u8; 32],
        directory: &CachedDirectory,
        message: &Message,
    ) -> Result<Vec<Route>, AppError> {
        let doc = self.peer_identity(pubky, false).await?;
        let now = self.now();
        let own = *pubky == self.state.meta.identity;
        let mut routes = Vec::new();
        let mut tx = self.tx()?;
        let mut floors = HashMap::new();
        // Each app is listed once (Dispatch wire 7.4.10): one listed twice can't be judged,
        // and goes unreachable.
        let mut listed: HashMap<[u8; 16], usize> = HashMap::new();
        for app in &directory.apps {
            let count = listed.entry(app.app_id).or_insert(0);
            *count = count.saturating_add(1);
        }
        for app in &directory.apps {
            if own && app.app_id == self.state.meta.app_id {
                continue;
            }
            match listed.get_mut(&app.app_id) {
                Some(count) if *count > 1 => {
                    // Reported once, every copy skipped.
                    if *count != usize::MAX {
                        *count = usize::MAX;
                        self.unreachable(pubky, app.app_id);
                    }
                    continue;
                }
                _ => {}
            }
            let Ok(record) = AppRecord::verify(&app.record, pubky) else {
                self.unreachable(pubky, app.app_id);
                continue;
            };
            let cert = record.cert();
            // Dispatch wire 3.8 checks 1 to 6 for a sender: the certificate the record carries,
            // unexpired now, current with it in the newest identity.json held.
            if cert.app_id() != app.app_id
                || cert.expired_at(now)
                || record.is_ahead(now)
                || !doc.current_now(&app.app_id, &cert.hash())
            {
                continue;
            }
            // Dispatch spec 3.4: the certificate allows the kind and `accepts` lists it, and
            // the protocol's narrower rule holds.
            if !self.protocols.receives(&message.kind, cert) || !record.accepts(&message.kind) {
                continue;
            }
            // The kind's protocol has `receives` above; its narrower rule reads its own state.
            let Some(owner) = self.protocols.of_kind(&message.kind).cloned() else {
                continue;
            };
            let store = std::sync::Arc::clone(self.env.store.store());
            let view = LocalView::new(
                self.state.meta.identity,
                self.state.meta.app_id,
                store.as_ref(),
                &self.ns,
                &owner.name,
            );
            if !owner.protocol.sends_to(message, &record, &view) {
                continue;
            }
            let checked = match &app.receive_key {
                Some(signed) => {
                    self.check_receive_key(pubky, &record, signed, &mut floors, &mut tx)
                        .await?
                }
                None => None,
            };
            match checked {
                Some(key) => routes.push(Route {
                    app_id: app.app_id,
                    recipient: Recipient::new(key.x25519()),
                }),
                None => self.unreachable(pubky, app.app_id),
            }
        }
        self.commit(tx).await?;
        Ok(routes)
    }

    fn unreachable(&mut self, pubky: &[u8; 32], app_id: [u8; 16]) {
        self.events.push(AppEvent::UnreachableApp {
            identity: *pubky,
            app_id,
        });
    }

    /// The checks of Dispatch spec 8.1 on one receive key record: its signature with the
    /// record's key, its identity and App ID, its kid derived from a key not of low order
    /// (the core's [`ReceiveKeyRecord::verify`]), and an `n` not below the highest seen for
    /// the app, which then moves up.
    ///
    /// `floors` holds the highest `n` taken so far in this answer, ahead of `tx`'s commit,
    /// so a second record of the same app in one answer is checked against the first: the
    /// floor only goes up (Dispatch spec 4.4).
    async fn check_receive_key(
        &mut self,
        pubky: &[u8; 32],
        record: &AppRecord,
        signed: &SignedDoc,
        floors: &mut HashMap<String, u64>,
        tx: &mut super::state::Tx,
    ) -> Result<Option<ReceiveKeyRecord>, AppError> {
        let Ok(key) = ReceiveKeyRecord::verify(signed, record.cert()) else {
            return Ok(None);
        };
        if key.body().identity != *pubky {
            return Ok(None);
        }
        let slot = highest_n_key(pubky, &record.cert().app_id());
        let highest: u64 = match floors.get(&slot) {
            Some(highest) => *highest,
            None => self.reader().get(&slot).await?.unwrap_or(0),
        };
        if key.n() < highest {
            floors.insert(slot, highest);
            return Ok(None);
        }
        if key.n() > highest {
            tx.put(&slot, &key.n())?;
        }
        floors.insert(slot, key.n());
        Ok(Some(key))
    }

    /// The records of a `409 stale_key` answer (Dispatch wire 7.6): each current record is
    /// checked as a directory's and replaces the cached one; apps no longer current leave
    /// the cache; apps added since are checked, against an `identity.json` read again if the
    /// one held doesn't list them, and join it; the `apps_version` moves on. A `current`
    /// whose `receive_keys`, `not_current` and `added_apps` together name an App ID twice is
    /// refused: nothing is taken from it, and the directory is read again. So is one missing
    /// any member the wire lists as required, or holding one as `null`: `receive_keys`,
    /// `not_current`, `unknown_kids`, `added_apps` and `apps_version`. A sender then never
    /// seals again for a set of apps that part of an answer left out.
    pub(crate) fn take_stale_key<'a>(
        &'a mut self,
        pubky: &'a [u8; 32],
        current: &'a Value,
    ) -> crate::transport::BoxFuture<'a, Result<(), AppError>> {
        // Boxed where it is made, as `App::try_item` says.
        Box::pin(self.take_stale_key_inner(pubky, current))
    }

    async fn take_stale_key_inner(
        &mut self,
        pubky: &[u8; 32],
        current: &Value,
    ) -> Result<(), AppError> {
        if !stale_key_reads(current) || names_an_app_twice(current) {
            return self.mark_directory_stale(pubky).await;
        }
        let Some(mut cached) = self.cached_directory(pubky).await? else {
            return Ok(());
        };
        if cached.stale && cached.apps.is_empty() {
            // A stub, or a copy without apps read again before the next seal anyway: the
            // answer has nothing to update.
            return Ok(());
        }
        let mut tx = self.tx()?;
        let mut floors = HashMap::new();
        for entry in array(current, "receive_keys") {
            let (Some(app_id), Some(signed)) =
                (app_id_of(entry, "app_id"), doc_of(entry, "record"))
            else {
                continue;
            };
            let Some(index) = cached.apps.iter().position(|a| a.app_id == app_id) else {
                continue;
            };
            let Some(app) = cached.apps.get(index) else {
                continue;
            };
            let Ok(record) = AppRecord::verify(&app.record, pubky) else {
                continue;
            };
            if self
                .check_receive_key(pubky, &record, &signed, &mut floors, &mut tx)
                .await?
                .is_some()
                && let Some(app) = cached.apps.get_mut(index)
            {
                app.receive_key = Some(signed);
            }
        }
        let gone: Vec<[u8; 16]> = current
            .get("not_current")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
            .filter_map(|text| pubky_dispatch_core::enc::app_id_decode(text).ok())
            .collect();
        cached.apps.retain(|app| !gone.contains(&app.app_id));
        let added: Vec<([u8; 16], SignedDoc, SignedDoc)> = array(current, "added_apps")
            .filter_map(|entry| {
                Some((
                    app_id_of(entry, "app_id")?,
                    doc_of(entry, "app_record")?,
                    doc_of(entry, "record")?,
                ))
            })
            .collect();
        if !added.is_empty() {
            let mut doc = self.peer_identity(pubky, false).await?;
            let unlisted = added.iter().any(|(app_id, record, _)| {
                AppRecord::verify(record, pubky)
                    .map_or(true, |r| !doc.current_now(app_id, &r.cert().hash()))
            });
            if unlisted {
                doc = self.peer_identity(pubky, true).await?;
            }
            for (app_id, signed_record, receive_key) in added {
                let Ok(record) = AppRecord::verify(&signed_record, pubky) else {
                    continue;
                };
                if record.cert().app_id() != app_id
                    || !doc.current_now(&app_id, &record.cert().hash())
                {
                    continue;
                }
                if self
                    .check_receive_key(pubky, &record, &receive_key, &mut floors, &mut tx)
                    .await?
                    .is_some()
                {
                    cached.apps.retain(|a| a.app_id != app_id);
                    cached.apps.push(CachedApp {
                        app_id,
                        record: signed_record,
                        receive_key: Some(receive_key),
                    });
                }
            }
        }
        if let Some(version) = current.get("apps_version").and_then(Value::as_u64) {
            cached.apps_version = version;
        }
        if !gone.is_empty() {
            cached.stale = true;
        }
        keep_directory(&mut tx, pubky, &cached)?;
        self.commit(tx).await
    }

    // ---------------------------------------------------------------------------------
    // The own identity.json at counterparties' Dispatches (Dispatch spec 6.1, 12.2 step 5)

    pub(crate) async fn peer_dispatch(&self, pubky: &[u8; 32]) -> Result<PeerDispatch, AppError> {
        Ok(self
            .reader()
            .get(&peer_key(pubky))
            .await?
            .unwrap_or_default())
    }

    /// The version of the own `identity.json` a counterparty's Dispatch named in a signed
    /// answer: its word, which may be lower than what the app delivered (a rollback, a
    /// provider change).
    pub(crate) async fn note_known_version(
        &mut self,
        pubky: &[u8; 32],
        known: Option<u64>,
    ) -> Result<(), AppError> {
        let mut peer = self.peer_dispatch(pubky).await?;
        if peer.known_version == known {
            return Ok(());
        }
        peer.known_version = known;
        let mut tx = self.tx()?;
        tx.put(&peer_key(pubky), &peer)?;
        self.commit(tx).await
    }

    /// Deliver the own `identity.json` to `pubky`'s Dispatch (`PUT /peers`, Dispatch wire
    /// 7.4.5) unless its last answer named this version or a later one; `force` delivers
    /// whatever it named, after `409 identity_needed`.
    ///
    /// # Errors
    ///
    /// The equivocation alarm when the Dispatch holds another body of the own document at
    /// this version (Dispatch wire 7.4.5); a failed call.
    pub(crate) fn deliver_own_identity<'a>(
        &'a mut self,
        pubky: &'a [u8; 32],
        invite_code: Option<&'a str>,
        force: bool,
    ) -> crate::transport::BoxFuture<'a, Result<(), AppError>> {
        // Boxed where it is made, as `App::try_item` says.
        Box::pin(self.deliver_own_identity_inner(pubky, invite_code, force))
    }

    async fn deliver_own_identity_inner(
        &mut self,
        pubky: &[u8; 32],
        invite_code: Option<&str>,
        force: bool,
    ) -> Result<(), AppError> {
        let own = self.state.own_doc.clone();
        let peer = self.peer_dispatch(pubky).await?;
        if !force && peer.known_version.is_some_and(|v| v >= own.version()) {
            return Ok(());
        }
        let doc = self.peer_identity(pubky, false).await?;
        let client = self.peer_client(pubky, &doc)?;
        match client.put_peers(own.signed(), invite_code).await {
            Ok(answer) => {
                self.note_known_version(pubky, Some(answer.known_version.unwrap_or(answer.version)))
                    .await
            }
            Err(ClientError::Dispatch {
                code: ErrorCode::StaleIdentity,
                current,
                ..
            }) => self.held_elsewhere(pubky, &own, &current).await,
            Err(error) => Err(error.into()),
        }
    }

    /// `409 stale_identity` at `PUT /peers`: the Dispatch holds another body of the own
    /// document at this version, which is equivocation (an alarm), or a newer version,
    /// which the app reads from its Homeserver.
    async fn held_elsewhere(
        &mut self,
        pubky: &[u8; 32],
        own: &IdentityDoc,
        current: &Value,
    ) -> Result<(), AppError> {
        if let Some(held) = doc_of(current, "identity")
            && let Ok(held) = IdentityDoc::verify(&held, &self.state.meta.identity)
            && held.version() == own.version()
            && held.body_hash() != own.body_hash()
        {
            return Err(self
                .raise(Alarm::Equivocation {
                    version: own.version(),
                })
                .await);
        }
        let version = current.get("version").and_then(Value::as_u64);
        if version.is_some_and(|v| v > own.version()) {
            self.refresh_identity().await?;
        }
        self.note_known_version(pubky, version).await
    }

    /// Whether a pass of the deliveries of [`App::deliver_to_recent_peers`] is under way.
    pub(crate) async fn peers_pass_open(&self) -> Result<bool, AppError> {
        let judged: PeersDoc = self.reader().get(PEERS_DOC).await?.unwrap_or_default();
        Ok(judged.untried > 0)
    }

    /// After an own `identity.json` that removes an app or closes a renewal, deliver it to
    /// the Dispatches the app wrote to in the last 30 days whose copy is older, by the
    /// `known_version` they last answered (Dispatch spec 12.2 step 5, 3.2). The ones that fail
    /// stay owed, each on its own, and are tried again by a later call.
    ///
    /// The deliveries go in passes, each trying every owed Dispatch once. Past the call's
    /// `budget`, once a unit of the call went (`units`, counted with the call's other
    /// units), the rest of the pass is left to the next call, and it returns `true`; the next
    /// call tries only those. A Dispatch whose delivery failed goes behind them, so one slow
    /// failing Dispatch holds up no other. The call that ends a pass returns `false`, failed
    /// Dispatches still owed, and the call after starts a new pass.
    ///
    /// # Errors
    ///
    /// An alarm or a store failure; a Dispatch's failure only keeps it owed.
    pub(crate) async fn deliver_to_recent_peers(
        &mut self,
        budget: &super::CallBudget,
        units: &mut usize,
    ) -> Result<bool, AppError> {
        let own = self.state.own_doc.clone();
        let mut judged: PeersDoc = self.reader().get(PEERS_DOC).await?.unwrap_or_default();
        let now = self.now();
        let recent = |peer: &PeerDispatch| {
            peer.last_sent_ms
                .is_some_and(|at| now.saturating_sub(at) < PEER_DELIVERY_MS)
        };
        if own.version() > judged.version {
            let removed: Vec<String> = own
                .body()
                .removed
                .iter()
                .map(|r| zbase32_encode(&r.app_id))
                .collect();
            let closed: Vec<String> = own
                .body()
                .renewed
                .iter()
                .filter(|r| r.until.is_some())
                .map(|r| b64(&r.cert))
                .collect();
            // Without an earlier judgement, any removal or closed renewal counts as new.
            let owed_now = removed.iter().any(|r| !judged.removed.contains(r))
                || closed.iter().any(|c| !judged.closed.contains(c));
            let mut owed = std::mem::take(&mut judged.owed);
            if owed_now {
                for (rest, peer) in self.reader().scan::<PeerDispatch>(PEER_PREFIX).await? {
                    if recent(&peer)
                        && peer.known_version.is_none_or(|v| v < own.version())
                        && !owed.contains(&rest)
                    {
                        owed.push(rest);
                    }
                }
            }
            judged = PeersDoc {
                version: own.version(),
                removed,
                closed,
                owed,
                // Newly owed Dispatches come after the pass under way.
                untried: judged.untried,
            };
        } else if judged.owed.is_empty() {
            return Ok(false);
        }
        // A pass tries each owed Dispatch once. A Dispatch whose delivery failed goes behind
        // those the budget left untried, so one slow failing Dispatch holds up no other.
        let mut owed = std::mem::take(&mut judged.owed);
        let pass = match judged.untried {
            0 => owed.len(),
            untried => untried.min(owed.len()),
        };
        let tried_before = owed.split_off(pass);
        let mut skipped = Vec::new();
        let mut failed = Vec::new();
        for rest in owed {
            // Past the call's time budget, once a unit of the call went, the rest are owed to
            // a later call.
            if *units > 0 && self.spent(budget) {
                skipped.push(rest);
                continue;
            }
            let Ok(pubky) = pubky_dispatch_core::enc::pubky_key(&rest) else {
                continue;
            };
            let peer = self.peer_dispatch(&pubky).await?;
            if !recent(&peer) {
                continue;
            }
            *units += 1;
            match self.deliver_own_identity(&pubky, None, false).await {
                Ok(()) => {}
                Err(error @ (AppError::Alarm(_) | AppError::Store(_))) => return Err(error),
                // A Dispatch that can't be reached now gets it at a later call.
                Err(_) => failed.push(rest),
            }
        }
        let left = !skipped.is_empty();
        judged.untried = skipped.len();
        judged.owed = skipped;
        judged.owed.extend(tried_before);
        judged.owed.extend(failed);
        let mut tx = self.tx()?;
        tx.put(PEERS_DOC, &judged)?;
        self.commit(tx).await?;
        Ok(left)
    }
}

/// Cache `cached` as `pubky`'s directory, or, when it is over the store's value size, its
/// stub ([`CachedDirectory::stub`]): a directory may take up to 104 MiB at an app limit of
/// 255 (Dispatch wire 9), and one too large to keep is read again at each send instead, which
/// then still goes, and still finds a provider loss since the read before (Dispatch spec 8.1).
fn keep_directory(tx: &mut Tx, pubky: &[u8; 32], cached: &CachedDirectory) -> Result<(), AppError> {
    let key = dir_key(pubky);
    let size = super::state::encode(cached)?
        .len()
        .saturating_add(key.len());
    if u64::try_from(size).unwrap_or(u64::MAX) <= crate::store::MAX_VALUE_BYTES {
        tx.put(&key, cached)
    } else {
        tx.put(&key, &cached.stub())
    }
}

fn array<'a>(value: &'a Value, name: &str) -> impl Iterator<Item = &'a Value> {
    value
        .get(name)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn app_id_of(value: &Value, name: &str) -> Option<[u8; 16]> {
    pubky_dispatch_core::enc::app_id_decode(value.get(name)?.as_str()?).ok()
}

fn doc_of(value: &Value, name: &str) -> Option<SignedDoc> {
    SignedDoc::from_strict_value(value.get(name)?).ok()
}

/// Whether a `409 stale_key`'s `current` holds every member Dispatch wire 7.6 lists, none
/// marked optional there: the four lists, present and arrays, and `apps_version`.
fn stale_key_reads(current: &Value) -> bool {
    let Ok(current) = Obj::of(current, "Dispatch wire 7.6: a stale_key's current") else {
        return false;
    };
    ["receive_keys", "not_current", "unknown_kids", "added_apps"]
        .iter()
        .all(|name| current.required_list(name).is_ok())
        && current.u64("apps_version").is_ok()
}

/// Whether a `409 stale_key`'s `current` names an App ID more than once across its
/// `receive_keys`, `not_current` and `added_apps` (Dispatch wire 7.6).
fn names_an_app_twice(current: &Value) -> bool {
    let not_current = array(current, "not_current")
        .filter_map(Value::as_str)
        .filter_map(|text| pubky_dispatch_core::enc::app_id_decode(text).ok());
    let mut seen = HashSet::new();
    array(current, "receive_keys")
        .chain(array(current, "added_apps"))
        .filter_map(|entry| app_id_of(entry, "app_id"))
        .chain(not_current)
        .any(|app_id| !seen.insert(app_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A counterparty's lookups at the service, stored under the current format's keys.
    #[test]
    fn test_directory_lookup_keys_spell_the_current_names() {
        let id = "y".repeat(52);
        assert_eq!(
            dispatch_read_key(&[0; 32]),
            format!("ident/{id}/dispatch_read")
        );
        assert_eq!(
            dispatch_lookups_key(&[0; 32]),
            format!("ident/{id}/dispatch_lookups")
        );
    }

    #[test]
    fn test_directory_stale_key_members_read_leniently() {
        let current = json!({ "receive_keys": [ { "app_id": "x", "record": 1 } ],
                              "not_current": ["not-an-id"], "apps_version": 5 });
        assert_eq!(array(&current, "receive_keys").count(), 1);
        let entry = array(&current, "receive_keys").next().unwrap();
        assert!(app_id_of(entry, "app_id").is_none());
        assert!(doc_of(entry, "record").is_none());
        assert_eq!(array(&current, "added_apps").count(), 0);
    }

    fn directory_of(apps: usize, record_bytes: usize) -> CachedDirectory {
        CachedDirectory {
            origin: "https://bob-dispatch.example".into(),
            service_key: [3; 32],
            generation: 4,
            identity_version: 7,
            directory_version: 9,
            apps_version: 2,
            apps: (0..apps)
                .map(|n| CachedApp {
                    app_id: [u8::try_from(n).unwrap(); 16],
                    record: SignedDoc {
                        body: "A".repeat(record_bytes),
                        sig: "A".repeat(86),
                    },
                    receive_key: None,
                })
                .collect(),
            stale: false,
            read_ms: 11,
        }
    }

    /// The value `tx` puts at `pubky`'s directory key.
    fn kept(tx: &Tx, pubky: &[u8; 32]) -> CachedDirectory {
        let key = dir_key(pubky);
        let value = tx
            .pending_writes()
            .iter()
            .find_map(|write| match write {
                crate::store::Write::Put { key: k, value, .. } if k == key.as_bytes() => {
                    Some(value.clone())
                }
                _ => None,
            })
            .unwrap();
        super::super::state::decode(&value).unwrap()
    }

    #[test]
    fn test_directory_over_the_value_size_is_kept_as_its_stub() {
        // 38 apps of 450 KB each: over the 16 MiB value size, as a directory at an app limit
        // of 255 may be (Dispatch wire 9).
        let big = directory_of(38, 450_000);
        let mut tx = Tx::new("ns");
        keep_directory(&mut tx, &[1; 32], &big).unwrap();
        let stub = kept(&tx, &[1; 32]);
        assert!(stub.apps.is_empty() && stub.stale);
        assert_eq!(
            (stub.origin.as_str(), stub.generation, stub.read_ms),
            (big.origin.as_str(), big.generation, big.read_ms)
        );
        assert_eq!(
            (
                stub.identity_version,
                stub.directory_version,
                stub.apps_version
            ),
            (7, 9, 2)
        );
        // One that fits is kept whole.
        let small = directory_of(2, 1_000);
        let mut tx = Tx::new("ns");
        keep_directory(&mut tx, &[1; 32], &small).unwrap();
        assert_eq!(kept(&tx, &[1; 32]), small);
    }

    #[test]
    fn test_directory_keys_sort_by_identity_and_app() {
        let a = highest_n_key(&[1; 32], &[2; 16]);
        assert!(a.starts_with("rkn/"));
        assert!(dir_key(&[1; 32]).starts_with(DIR_PREFIX));
        assert!(peer_key(&[1; 32]).starts_with(PEER_PREFIX));
    }
}
