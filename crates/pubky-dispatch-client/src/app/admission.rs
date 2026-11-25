//! Admission at the own Dispatch, the app's side (Dispatch spec 7; Dispatch wire 6.2, 7.4.6,
//! 7.4.7).
//!
//! - **Kept peers and the deny list** (`allow.put`, `allow.delete`, `deny.put`,
//!   `deny.delete`), with `lists.manage`.
//! - **Reply grants**: an invite is a reply grant before any message
//!   (`reply.add`); a first message adds one itself ([`super::send`]).
//! - **Invite codes**: the app makes a code of 32 random bytes, registers its hash with an
//!   expiry and a maximum number of uses (`invite_code.put`), shows it as
//!   `pubky://<id>?dispatch=invite&code=<code>`, and may withdraw it.
//! - **Connect requests**: asking a stranger's Dispatch to be invited, and listing, allowing
//!   (an invite) and declining the requests at the own Dispatch.
//!
//! The app keeps what it knows of the lists from its own writes and, with `lists.read`,
//! from the feed, in the copy of the lists under `lc/` (`lc/kept/`, `lc/r/`,
//! `lc/deny/`, `lc/code/`), and the codes themselves
//! it registered, `invite/<code_hash>`. A send consults them to skip a reply grant
//! the identity already holds. The flagged senders (`lc/flag/`), which no feed item
//! carries, come only from `GET /allow` ([`App::allow_list`]), which also keeps when the
//! copy was last replaced (`lc/lists_at`); a protocol's receive step reads both, with the
//! deny list, as a [`SenderDisposition`].

use pubky_dispatch_core::admission::PeerReason;
use pubky_dispatch_core::enc::{b64, pubky_id, random_bytes, serde_b64};
use pubky_dispatch_core::http::ErrorCode;
use pubky_dispatch_core::ident::{invite_code_hash, invite_code_uri};
use pubky_dispatch_core::ops::{InviteCodePut, OpKind};
use pubky_dispatch_core::scopes::Permission;
use serde::{Deserialize, Serialize};

use super::batch::OpBatch;
use super::error::Refusal;
use super::feed::DENY_GAP;
use super::state::Tx;
use super::{App, AppError};
use crate::client::answers::{AllowList, ConnectList, ObservedAllowList};
use crate::error::{ClientError, StoreError};

/// The random bytes in an invite code the app makes (Dispatch spec 7: at least 16).
pub const INVITE_CODE_BYTES: usize = 32;

const INVITE_PREFIX: &str = "invite/";

/// Remove bearer invite codes when the app destroys its keys.
pub(super) fn clear_on_leave(tx: &mut Tx) -> Result<(), AppError> {
    tx.delete_prefix(INVITE_PREFIX)
}

pub(super) mod observations;

pub(crate) fn allow_key(reason: PeerReason, pubky: &[u8; 32]) -> String {
    match reason {
        PeerReason::Kept => format!("lc/kept/{}", pubky_id(pubky)),
        PeerReason::Reply => observations::reply_key(pubky),
    }
}

pub(crate) fn deny_key(pubky: &[u8; 32]) -> String {
    format!("lc/deny/{}", pubky_id(pubky))
}

/// A flagged sender in the copy of the lists, from `GET /allow` only (Dispatch wire 7.4.6).
/// The flagged senders are kept whole, bounded by the transport and batch caps as the
/// other lists are, and never cut: a cut list would read a flagged sender as not flagged.
pub(crate) fn flag_key(pubky: &[u8; 32]) -> String {
    format!("lc/flag/{}", pubky_id(pubky))
}

/// When [`App::allow_list`] last replaced the copy of the lists: the service time of its
/// answer, Unix milliseconds. Absent until the first.
pub(crate) const LISTS_AT: &str = "lc/lists_at";

/// Signed head of the last complete list applied to the account copy.
pub(super) const LIST_POSITION: &str = "lc/list_position";

/// `lc/too_large`: the service time of the last `GET /allow` answer whose lists didn't fit
/// one commit. While it is less than [`LISTS_TOO_LARGE_RETRY_MS`] old, a read doesn't
/// refresh the copy it owes; [`App::allow_list`] still does. A refresh that fits, a
/// provider change and a restore remove it.
pub(crate) const LISTS_TOO_LARGE: &str = "lc/too_large";

/// How long a read waits, in service time, before it tries again a refresh of the lists
/// whose answer didn't fit one commit: a day. The answer of such lists is 16 MB or more, so
/// a read that retried it at every long poll would download and parse it every time.
pub const LISTS_TOO_LARGE_RETRY_MS: u64 = pubky_dispatch_core::records::DAY_MS;

/// What the app knows of a sender's standing in the own identity's lists, for a protocol's
/// receive step ([`super::ReceiveContext::sender_disposition`]), such as to keep only a
/// count of messages from a sender the user blocked or the service flagged (Dispatch spec 7
/// "Spam").
///
/// Both values are as fresh as the app's copy of the lists. `blocked` follows the app's own
/// deny and undeny, the deny list changes the feed shows an app with `lists.read`, and the
/// last [`App::allow_list`]. `flagged` follows only the last [`App::allow_list`]: no feed
/// item carries the flags, so it is `false` for every sender until the app first refreshes
/// its lists. [`SenderDisposition::lists_as_of_ms`] is `None` while the copy isn't known to
/// be complete, and both values then say nothing.
///
/// It has no `Default`: a disposition that defaulted to neither blocked nor flagged would
/// be the unsafe answer to a failed read.
///
/// The service refuses a denied sender at the inbox (Dispatch spec 7), so `blocked` reaches a
/// protocol only for a message accepted before the block, or after a deny that another app
/// made and this one hasn't seen yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SenderDisposition {
    /// The sender is on the app's copy of the deny list.
    pub blocked: bool,
    /// The sender was among the flagged senders of the last [`App::allow_list`] (Dispatch
    /// wire 7.4.6): it hit the rate limits at least 3 times.
    pub flagged: bool,
    /// The service time, Unix milliseconds, of the `GET /allow` answer the copy of the
    /// lists was last replaced from, to compare with
    /// [`super::ReceiveContext::highest_service_time`] when deciding to refresh.
    ///
    /// `None` when the copy isn't known to be complete: the app never refreshed its lists
    /// (as an app without `lists.read`), was restored from a backup, which requires a new signed read,
    /// or followed a provider loss since. `blocked` and `flagged` then say nothing of the
    /// sender: a `false` may be a deny or a flag the app never saw, such as another app's deny
    /// made after the backup. A protocol must not read `None` as neither blocked nor flagged,
    /// unless the protocol states its own rule for an unknown sender. An
    /// app with `lists.read` refreshes a copy in that state at its next
    /// [`App::receive`](super::App::receive), before it hands any entry over, when it can.
    pub lists_as_of_ms: Option<u64>,
}

/// An invite code this app registered, in the copy of the lists.
pub(crate) fn code_key(code_hash: &[u8; 32]) -> String {
    format!("lc/code/{}", b64(code_hash))
}

/// The code itself, which only this app holds, to show it again.
pub(crate) fn invite_key(code_hash: &[u8; 32]) -> String {
    format!("{INVITE_PREFIX}{}", b64(code_hash))
}

/// An invite code the app registered. Its `Debug` shows only the hash: the code is a
/// bearer secret (Dispatch spec 7).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCode {
    /// The code, base64url.
    pub code: String,
    /// `hash(code bytes)`.
    #[serde(with = "serde_b64")]
    pub code_hash: [u8; 32],
    /// When it expires, Unix milliseconds.
    pub expires_at: u64,
    /// How many appends it admits.
    pub max_uses: u64,
}

impl std::fmt::Debug for InviteCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InviteCode({})", b64(&self.code_hash))
    }
}

/// Keep a registered code once the Dispatch took it.
pub(crate) fn keep_invite(tx: &mut Tx, put: &InviteCodePut, code: &str) -> Result<(), AppError> {
    tx.put(&code_key(&put.code_hash), &())?;
    tx.put(
        &invite_key(&put.code_hash),
        &InviteCode {
            code: code.to_owned(),
            code_hash: put.code_hash,
            expires_at: put.expires_at,
            max_uses: put.max_uses,
        },
    )
}

impl InviteCode {
    /// The link that shows it: `pubky://<identity>?dispatch=invite&code=<code>` (Dispatch spec
    /// 7).
    pub fn uri(&self, identity: &[u8; 32]) -> String {
        invite_code_uri(identity, &self.code)
    }
}

impl App {
    async fn need(&mut self, permission: Permission) -> Result<(), AppError> {
        self.reload_if_needed().await?;
        if self.state.cert.has_permission(permission) {
            Ok(())
        } else {
            Err(Refusal::Usage(format!(
                "Dispatch spec 3.2: the certificate lacks {}",
                permission.as_str()
            ))
            .into())
        }
    }

    // ---------------------------------------------------------------------------------
    // Kept peers, reply grants and the deny list

    /// Keep `pubky` explicitly (`allow.put` with reason `kept`, `lists.manage`).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] without the permission; as [`App::submit_batch`].
    pub async fn keep_peer(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ListsManage).await?;
            self.list_op(OpKind::AllowPut {
                pubky: *pubky,
                reason: PeerReason::Kept,
            })
            .await
        })
        .await
    }

    /// Remove the kept reason of `pubky` (`allow.delete` with reason `kept`, `lists.manage`).
    /// A reply grant the peer holds stays. While a provider loss's list upload still carries
    /// the peer as kept in a page no answer has confirmed, it is first left out of that upload,
    /// so the upload doesn't keep the peer again (Dispatch wire 7.4.14 "Lists"). That is done in
    /// the commit that settles the removal at the service, so a removal refused changes
    /// nothing, and the upload waits while a removal is not yet answered.
    ///
    /// # Errors
    ///
    /// As [`App::keep_peer`].
    pub async fn remove_kept_peer(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ListsManage).await?;
            self.own_write_checks().await?;
            self.list_op(OpKind::AllowDelete {
                pubky: *pubky,
                reason: PeerReason::Kept,
            })
            .await
        })
        .await
    }

    /// Invite `pubky`: a reply grant before any message, so it can write first
    /// (`allow.put` with reason `reply`, `reply.add`). It also allows a pending connect
    /// request from it (Dispatch wire 6.2).
    ///
    /// # Errors
    ///
    /// As [`App::keep_peer`], with `reply.add`.
    pub async fn invite(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ReplyAdd).await?;
            self.list_op(OpKind::AllowPut {
                pubky: *pubky,
                reason: PeerReason::Reply,
            })
            .await
        })
        .await
    }

    /// Remove the reply grant of `pubky` (`allow.delete` with reason `reply`, `lists.manage`),
    /// as when pruning idle grants (Dispatch spec 7). A kept reason the peer holds stays.
    ///
    /// # Errors
    ///
    /// As [`App::keep_peer`].
    pub async fn remove_reply(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ListsManage).await?;
            self.list_op(OpKind::AllowDelete {
                pubky: *pubky,
                reason: PeerReason::Reply,
            })
            .await
        })
        .await
    }

    /// Block `pubky`: the deny list overrides every entry, and removes a pending connect
    /// request from it (`deny.put`, `lists.manage`).
    ///
    /// # Errors
    ///
    /// As [`App::keep_peer`].
    pub async fn deny(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ListsManage).await?;
            self.list_op(OpKind::DenyPut { pubky: *pubky }).await
        })
        .await
    }

    /// Unblock `pubky` (`deny.delete`, `lists.manage`).
    ///
    /// While a provider loss's list upload still carries `pubky` as a deny entry in a page no
    /// answer has confirmed ([`App::recovery_deny_entries`]), it is left out of that upload,
    /// so the upload doesn't deny it again; a kept entry for the same peer stays. This is the
    /// user's way to make room when the upload doesn't fit ([`Refusal::DenyListFull`]). With
    /// `lists.manage`, the entry is left out in the commit that settles the removal at the
    /// service, so a removal refused or not yet answered leaves the upload denying the peer,
    /// which only narrows admission. An app with `lists.read` alone may do only the leaving
    /// out, which sends nothing (Dispatch wire 7.4.14 "Lists").
    ///
    /// # Errors
    ///
    /// As [`App::keep_peer`].
    pub async fn undeny(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if self.state.cert.has_permission(Permission::ListsManage) {
                self.own_write_checks().await?;
                return self.list_op(OpKind::DenyDelete { pubky: *pubky }).await;
            }
            self.need(Permission::ListsRead).await?;
            if !self
                .leave_out_of_upload(super::recovery::lists::List::Deny, pubky)
                .await?
            {
                // Nothing to leave out, and no permission to remove it at the service.
                self.need(Permission::ListsManage).await?;
            }
            Ok(())
        })
        .await
    }

    /// Leave `pubky` out of `list` in the owed list upload when a page not yet confirmed
    /// carries it, for an app that may only leave entries out (`lists.read` alone): there is
    /// no removal at the service to settle (Dispatch wire 7.4.14).
    async fn leave_out_of_upload(
        &mut self,
        list: super::recovery::lists::List,
        pubky: &[u8; 32],
    ) -> Result<bool, AppError> {
        if !self.upload_still_carries(list, pubky).await? {
            return Ok(false);
        }
        let mut tx = self.tx()?;
        self.leave_out(&mut tx, list, pubky, false).await?;
        self.commit(tx).await?;
        Ok(true)
    }

    /// The local checks an own write passes before it is sent, run before anything of it is
    /// written: the store read again after a failed commit, a stopped app, a write the
    /// account's state doesn't allow now, and a write before the loss's evidence upload.
    async fn own_write_checks(&mut self) -> Result<(), AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        self.may_write_own()?;
        self.refuse_before_upload().await
    }

    async fn list_op(&mut self, kind: OpKind) -> Result<(), AppError> {
        self.submit_batch(OpBatch::new().op(kind)).await?;
        Ok(())
    }

    /// Whether the app knows `pubky` to be kept or to hold a reply grant.
    ///
    /// A kept or reply row a restore brought back admits only once something verifies it: a
    /// complete list read, or a change to that peer's row in the feed or by this app. Until
    /// then it may be one the user removed after the backup, and for an app without
    /// `lists.read` only its own write on the peer verifies it (Dispatch spec 7, 12.4).
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn admits(&self, pubky: &[u8; 32]) -> Result<bool, AppError> {
        let reader = self.reader();
        // A provider loss's own deny entries deny until a list read after their upload.
        if reader.exists(&deny_key(pubky)).await?
            || self.owed_contributed_denies().await?.contains(pubky)
        {
            return Ok(false);
        }
        Ok(observations::verified_row(&reader, true, pubky).await?
            || observations::verified_row(&reader, false, pubky).await?)
    }

    /// The signed `GET /allow` lists (`lists.read`, Dispatch wire 7.4.6). Each peer has a
    /// kept flag and an optional reply grant with its original writer and times. The other
    /// lists hold denied senders, flagged senders and live invitation codes. One commit
    /// replaces local membership, denials, flags and the app's invitation-code hashes
    /// along with the signed service position and time ([`SenderDisposition::lists_as_of_ms`]).
    ///
    /// The copy is taken whole, so the protocol is given the same list (Dispatch spec 8.3):
    /// once the answer is read, a deny list gap at the cursor is committed first, on its own,
    /// and the copy replaced after it. The next read tells that gap after the owed calls,
    /// with the lists read for it, and takes the copy again from the same answer
    /// ([`super::Protocol::deny_list_gap`]): a crash between the two commits, or lists too large
    /// for one, leaves the gap owed, and the copy and the protocol end set from one list.
    /// The gap is told by a read, not by this call, so it comes after what the protocol is
    /// owed, in feed order.
    ///
    /// Each list is kept whole, as the answer holds it, the flagged senders included. The
    /// copy is bounded as the other lists are: by the transport's cap on an answer's size
    /// and the store's batch size. At the default limits the flagged senders are at most
    /// `max_flags`, 1,000 (Dispatch wire 9.2). The list isn't cut to a count of its own: a
    /// cut list would read a flagged sender as not flagged.
    ///
    /// The whole copy is replaced in one commit, which must fit the store's batch size,
    /// [`crate::store::MAX_BATCH_BYTES`]. Lists that don't fit, as they may at raised
    /// limits, fail this call with [`StoreError::TooLarge`], the gap committed: the copy's
    /// lists stay as they were, not known complete, so
    /// [`SenderDisposition::lists_as_of_ms`] is `None`, and such an app can't refresh its
    /// copy today. The refusal is kept with the answer's service time. The gap's read still
    /// tells the protocol the list and tries the copy once more; after that, the reads go
    /// on and don't fetch the lists again for the refresh they owe until
    /// [`LISTS_TOO_LARGE_RETRY_MS`] later, a provider change, a restore or a renewal that
    /// adds `lists.read`. This call always fetches them.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] without `lists.read`; a failed call or commit;
    /// [`StoreError::TooLarge`] for lists too large for one commit.
    pub async fn allow_list(&mut self) -> Result<AllowList, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.need(Permission::ListsRead).await?;
            let result = self.client.observed_allow().await;
            let list = self.take(result).await?;
            // The gap before the copy, each in its own commit: whatever stops between them,
            // the protocol is owed the list the copy is then taken from (Dispatch spec 8.3).
            // The gap deletes `lc/lists_at`, which the copy's commit writes again.
            let cursor = self.state.cursor;
            let mut tx = self.tx()?;
            self.note_deny_gap(cursor.generation, cursor.seq, &mut tx)
                .await?;
            self.commit(tx).await?;
            self.take_lists(&list).await.map(|()| list.list)
        })
        .await
    }

    /// The refresh a read owes when the copy of the lists isn't known to be complete
    /// (`lc/lists_at` absent: never refreshed, as after a join, restored, after a provider
    /// loss, after a renewal that added `lists.read`, or after a gap told without the list)
    /// and the app holds `lists.read`.
    /// The protocol then has no baseline either, so the refresh is a deny list gap at the
    /// cursor (Dispatch spec 8.3): the read tells it after the owed calls, with the lists read
    /// for it, and takes the copy from the same answer (`App::tell_deny_gap_if_owed`), so
    /// the copy and the protocol are set from one list. Not while a gap is owed already,
    /// nor while a move or a provider loss is in progress, whose steps read and upload the
    /// copy as the app kept it. After lists too large for one commit (`lc/too_large`), not
    /// before [`LISTS_TOO_LARGE_RETRY_MS`] of service time has passed.
    pub(crate) async fn refresh_lists_if_owed(&mut self) -> Result<(), AppError> {
        if !self.state.cert.has_permission(Permission::ListsRead) {
            return Ok(());
        }
        let reader = self.reader();
        if reader.exists(LISTS_AT).await?
            || reader.exists(DENY_GAP).await?
            || reader.exists(super::provider::keys::MOVE).await?
            || self.loss_record().await?.is_some_and(|loss| !loss.done())
        {
            return Ok(());
        }
        // Lists too large for one commit are tried again a day later, not at every read.
        // The day is judged on the highest service time verified, which every read's page
        // moves on: at most one read later than a fresh time would, and no request of its
        // own.
        if let Some(at) = reader.get::<u64>(LISTS_TOO_LARGE).await?
            && self
                .highest_service_time()
                .is_none_or(|now| now < at.saturating_add(LISTS_TOO_LARGE_RETRY_MS))
        {
            return Ok(());
        }
        let cursor = self.state.cursor;
        let mut tx = self.tx()?;
        self.note_deny_gap(cursor.generation, cursor.seq, &mut tx)
            .await?;
        self.commit(tx).await
    }

    /// The copy of the lists replaced from `list`, the answer just read, in one commit: too
    /// large for one, `lc/too_large` is kept instead, in a commit of its own, so the reads
    /// don't fetch the same lists again before [`LISTS_TOO_LARGE_RETRY_MS`].
    pub(crate) async fn take_lists(&mut self, list: &ObservedAllowList) -> Result<(), AppError> {
        match self.replace_lists(list).await {
            Err(error @ AppError::Store(StoreError::TooLarge { .. })) => {
                let mut tx = self.tx()?;
                tx.put(LISTS_TOO_LARGE, &list.at_ms)?;
                self.commit(tx).await?;
                Err(error)
            }
            replaced => replaced,
        }
    }

    /// Replace the lists and their service position from the same signed answer in one commit.
    async fn replace_lists(&mut self, observed: &ObservedAllowList) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        stage_lists(observed, self.state.meta.app_id, &mut tx)?;
        // While a provider loss's list upload is owed, the new service's lists lack this app's
        // own deny entries: the copy keeps them denied, as the upload will, each row marked
        // as held for the upload (Dispatch spec 12.6 step 2).
        tx.delete_prefix(super::recovery::lists::HELD)?;
        let read: std::collections::BTreeSet<_> = observed.list.deny.iter().collect();
        for pubky in self.owed_contributed_denies().await? {
            if !read.contains(&pubky) {
                let row = deny_key(&pubky);
                tx.put(&format!("{}{row}", super::recovery::lists::HELD), &())?;
                tx.put_raw(&row, Vec::new())?;
            }
        }
        self.list_read_after_upload(&mut tx).await?;
        self.commit(tx).await
    }

    // ---------------------------------------------------------------------------------
    // Invite codes

    /// Make and register an invite code (`invite_code.put`, `reply.add`): 32 random
    /// bytes, its hash, `expires_at` and `max_uses` (Dispatch spec 7). The app keeps the
    /// code to show it again ([`InviteCode::uri`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] without the permission or for `max_uses` 0; a failing random
    /// generator; as [`App::submit_batch`].
    pub async fn register_invite_code(
        &mut self,
        expires_at: u64,
        max_uses: u64,
    ) -> Result<InviteCode, AppError> {
        Box::pin(async move {
            self.need(Permission::ReplyAdd).await?;
            if max_uses == 0 {
                return Err(
                    Refusal::Usage("Dispatch wire 6.2: max_uses is at least 1".into()).into(),
                );
            }
            let code = b64(&random_bytes::<INVITE_CODE_BYTES>()?);
            let code_hash = invite_code_hash(&code)?;
            let put = InviteCodePut {
                code_hash,
                expires_at,
                max_uses,
            };
            self.submit_batch(
                OpBatch::new()
                    .op(OpKind::InviteCodePut(put))
                    .invite(&code_hash, &code),
            )
            .await?;
            Ok(InviteCode {
                code,
                code_hash,
                expires_at,
                max_uses,
            })
        })
        .await
    }

    /// Withdraw an invite code (`invite_code.delete`, `reply.add`). A code that
    /// expired or ran out is deleted by the Dispatch's own sweep at a later request (Dispatch
    /// wire 9.1): withdrawing it then is `404`, and the next refresh of the lists
    /// ([`App::allow_list`]) drops it from what the app holds.
    ///
    /// # Errors
    ///
    /// As [`App::register_invite_code`]; `404` for a code the Dispatch doesn't hold, a swept
    /// one included.
    pub async fn withdraw_invite_code(&mut self, code_hash: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ReplyAdd).await?;
            self.list_op(OpKind::InviteCodeDelete {
                code_hash: *code_hash,
            })
            .await
        })
        .await
    }

    /// The invite codes the app registered and hasn't withdrawn.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn invite_codes(&self) -> Result<Vec<InviteCode>, AppError> {
        Ok(self
            .reader()
            .scan::<InviteCode>(INVITE_PREFIX)
            .await?
            .into_iter()
            .map(|(_, code)| code)
            .collect())
    }

    // ---------------------------------------------------------------------------------
    // Connect requests

    /// Ask `pubky`'s Dispatch to be invited (`POST /connect`, Dispatch wire 7.4.7), delivering the
    /// own `identity.json` there first when its Dispatch doesn't hold it. Returns whether the
    /// request is pending.
    ///
    /// # Errors
    ///
    /// `403 not_admitted` where the identity takes no connect requests; `429` when its list
    /// is full; a failed call.
    pub async fn ask_to_connect(&mut self, pubky: &[u8; 32]) -> Result<bool, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let mut delivered = false;
            loop {
                let doc = self.peer_identity(pubky, false).await?;
                let client = self.peer_client(pubky, &doc)?;
                match client.connect().await {
                    Ok(answer) => {
                        self.note_known_version(pubky, answer.known_version).await?;
                        return Ok(answer.pending);
                    }
                    Err(ClientError::Dispatch {
                        code: ErrorCode::IdentityNeeded,
                        ..
                    }) if !delivered => {
                        delivered = true;
                        self.deliver_own_identity(pubky, None, true).await?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await
    }

    /// The connect requests pending at the own Dispatch (`GET /connect`, `lists.read`).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] without the permission; a failed call.
    pub async fn connect_requests(&mut self) -> Result<ConnectList, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.need(Permission::ListsRead).await?;
            let result = self.client.connect_requests().await;
            self.take(result).await
        })
        .await
    }

    /// Allow a connect request: an invite, which removes it (Dispatch spec 7).
    ///
    /// # Errors
    ///
    /// As [`App::invite`].
    pub async fn allow_connect(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move { self.invite(pubky).await }).await
    }

    /// Decline a connect request (`DELETE /connect/{pubky}`, `reply.add`).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] without the permission; `404` when none is pending from it.
    pub async fn decline_connect(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.may_write_own()?;
            self.need(Permission::ReplyAdd).await?;
            let result = self.client.decline_connect(pubky).await;
            self.take(result).await?;
            Ok(())
        })
        .await
    }
}

/// Stage the membership rows and the signed position of their complete read.
fn stage_lists(observed: &ObservedAllowList, me: [u8; 16], tx: &mut Tx) -> Result<(), AppError> {
    let list = &observed.list;
    for prefix in ["lc/kept/", "lc/r/", "lc/deny/", "lc/flag/", "lc/code/"] {
        tx.delete_prefix(prefix)?;
    }
    tx.delete(LISTS_TOO_LARGE)?;
    for peer in &list.peers {
        if peer.kept {
            tx.put_raw(&allow_key(PeerReason::Kept, &peer.pubky), Vec::new())?;
        }
        if let Some(grant) = peer.reply {
            let observed = observations::ReplyObservation::Observed {
                grant,
                as_of_ms: observed.at_ms,
            };
            tx.put_raw(&observations::reply_key(&peer.pubky), observed.bytes())?;
        }
    }
    for pubky in &list.deny {
        tx.put_raw(&deny_key(pubky), Vec::new())?;
    }
    for flagged in &list.flagged {
        tx.put(&flag_key(&flagged.pubky), &())?;
    }
    tx.put(LISTS_AT, &observed.at_ms)?;
    let position = observed.position.map(|head| super::FeedPosition {
        generation: head.generation,
        seq: head.seq,
    });
    tx.put(LIST_POSITION, &position)?;
    for code in list.invite_codes.iter().filter(|c| c.written_by == me) {
        tx.put(&code_key(&code.code_hash), &())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admission_keys_name_the_list() {
        assert!(allow_key(PeerReason::Kept, &[1; 32]).starts_with("lc/kept/"));
        assert!(allow_key(PeerReason::Reply, &[1; 32]).starts_with("lc/r/"));
        assert!(deny_key(&[1; 32]).starts_with("lc/deny/"));
        assert!(flag_key(&[1; 32]).starts_with("lc/flag/"));
        assert!(code_key(&[1; 32]).starts_with("lc/code/"));
    }

    #[test]
    fn test_default_peer_list_fits_the_wire_and_one_complete_store_replacement() {
        use crate::client::answers::{Flagged, InviteCodeStatus};
        use crate::store::{MAX_BATCH_BYTES, client_namespace};
        use pubky_dispatch_core::admission::{PeerEntry, ReplyGrant, ReplyOrigin};
        use pubky_dispatch_core::ops::{Limits, Position};
        use pubky_dispatch_core::time::{MAX_TIME_MS, rfc3339};

        let limits = Limits::default();
        let me = [1; 16];
        let key = |n: u64| {
            let mut id = [1; 32];
            id[..8].copy_from_slice(&n.to_be_bytes());
            id
        };
        let kept = PeerEntry {
            pubky: key(0),
            kept: true,
            reply: None,
        };
        let grant = ReplyGrant {
            origin: ReplyOrigin::Invite([2; 32]),
            at: MAX_TIME_MS - 1,
            last_used: Some(MAX_TIME_MS),
        };
        let reply = PeerEntry {
            pubky: key(1),
            kept: false,
            reply: Some(grant),
        };
        let peers = (0..limits.max_kept_peers)
            .map(|n| PeerEntry {
                pubky: key(n),
                ..kept
            })
            .chain((0..limits.max_reply_peers).map(|n| PeerEntry {
                pubky: key(n + limits.max_kept_peers),
                ..reply
            }))
            .collect();
        let list = AllowList {
            peers,
            deny: (0..pubky_dispatch_core::ops::MAX_DENY).map(key).collect(),
            flagged: (0..1000)
                .map(|n| Flagged {
                    pubky: key(n),
                    hits: u64::MAX,
                })
                .collect(),
            invite_codes: (0..limits.max_invite_codes)
                .map(|n| InviteCodeStatus {
                    code_hash: key(n),
                    expires_at: MAX_TIME_MS,
                    max_uses: limits.max_invite_uses,
                    uses: limits.max_invite_uses - 1,
                    written_by: me,
                })
                .collect(),
        };
        let flag = serde_json::json!({"pubky":pubky_id(&key(0)), "hits":u64::MAX});
        let code = serde_json::json!({"code_hash":b64(&key(0)), "expires_at":rfc3339(MAX_TIME_MS),
            "max_uses":limits.max_invite_uses,"uses":limits.max_invite_uses-1,"written_by":pubky_dispatch_core::enc::zbase32_encode(&me)});
        let wire = br#"{"peers":[],"deny":[],"flagged":[],"invite_codes":[]}"#.len()
            + (kept.to_json().unwrap().len() + 1) * limits.max_kept_peers as usize
            + (reply.to_json().unwrap().len() + 1) * limits.max_reply_peers as usize
            + (serde_json::to_vec(&pubky_id(&key(0))).unwrap().len() + 1) * list.deny.len()
            + (serde_json::to_vec(&flag).unwrap().len() + 1) * list.flagged.len()
            + (serde_json::to_vec(&code).unwrap().len() + 1) * list.invite_codes.len()
            - 4;
        let ns = client_namespace(&me);
        let mut tx = Tx::new(&ns);
        let observed = ObservedAllowList {
            list,
            position: Some(Position {
                generation: u64::MAX,
                seq: u64::MAX,
            }),
            at_ms: MAX_TIME_MS,
        };
        stage_lists(&observed, me, &mut tx).unwrap();
        let owned = tx.size() + ns.len() as u64 + 32;
        assert!(wire > 32 << 20 && wire <= 33 << 20, "{wire} response bytes");
        assert!(owned <= MAX_BATCH_BYTES, "{owned} owned replacement bytes");
    }

    #[test]
    fn test_admission_invite_code_debug_hides_the_code() {
        let code = InviteCode {
            code: "secret-code".into(),
            code_hash: [1; 32],
            expires_at: 1,
            max_uses: 1,
        };
        assert!(!format!("{code:?}").contains("secret"));
        assert!(
            code.uri(&[2; 32])
                .contains("dispatch=invite&code=secret-code")
        );
    }
}
