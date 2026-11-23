//! A signed display read the host can finish after its extension exits (Switch spec 9, 12.6).

use serde::{Deserialize, Serialize};

use super::error::{AppError, Refusal};
use super::state::{Meta, Reader};
use super::{App, AppState, PeekReport};
use crate::client::answers::FeedQuery;
use crate::client::own::{Decision, OwnReads};
use crate::client::{CheckedResponse, OwnAnswer, SentRequest, SwitchClient, check_response};
use crate::error::ClientError;
use crate::transport::{Header, Request, Response, TimeoutClass};
use pubky_switch_core::ops::Position;

pub(super) const PENDING: &str = "display_read";

/// The one signed feed GET reserved for a host that owns its transport across process exit.
/// The host matches its durable result to [`Self::id`]. Reopening a pending read never
/// authorizes sending it again while its original outcome is unknown.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayRead {
    id: [u8; 16],
    meta: Meta,
    after: u64,
    limit: u32,
    path: String,
    headers: Vec<Header>,
}

impl std::fmt::Debug for DisplayRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisplayRead")
            .field("id", &self.id)
            .field("generation", &self.meta.generation)
            .field("after", &self.after)
            .finish_non_exhaustive()
    }
}

/// A portable terminal transport receipt. The original response is checked against the
/// owner's retained request, pinned key and account. A timeout or an unreadable answer is
/// unavailability. A transfer whose outcome remains unknown has no receipt yet.
#[derive(Clone, Serialize, Deserialize)]
pub struct DisplayReceipt {
    id: [u8; 16],
    received_at_ms: u64,
    response: Option<Response>,
}

impl DisplayRead {
    /// Opaque identifier for the host's durable request and reply.
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// The exact already-signed GET for the host transport. Send it at most once.
    pub fn request(&self) -> Request {
        Request {
            method: "GET".into(),
            origin: self.meta.origin.clone(),
            path_and_query: self.path.clone(),
            headers: self.headers.clone(),
            body: Vec::new(),
            timeout: TimeoutClass::Bulk,
        }
    }

    fn checked(&self, response: &Response) -> Result<CheckedResponse, ClientError> {
        check_response(
            &self.meta.service_key,
            &self.meta.identity,
            &SentRequest::of(&self.request()),
            response,
        )
    }

    /// Retain a terminal transport result before delivering it. `received_at_ms` is the
    /// trusted device clock at receipt. `None` denotes a conclusive transport failure.
    pub fn receipt(&self, response: Option<Response>, received_at_ms: u64) -> DisplayReceipt {
        DisplayReceipt {
            id: self.id,
            received_at_ms,
            response,
        }
    }
}

pub(super) async fn load(
    reader: &Reader,
    meta: &Meta,
    id: Option<[u8; 16]>,
) -> Result<Option<DisplayRead>, AppError> {
    let read: Option<DisplayRead> = reader.get(PENDING).await?;
    if read.as_ref().map(|r| r.id) != id || read.as_ref().is_some_and(|r| r.meta != *meta) {
        return Err(super::corrupt());
    }
    Ok(read)
}

/// Resume only the exact signed own-account feed GET previously handed to the host.
pub(super) fn restore(client: &SwitchClient, state: &AppState) -> Result<(), AppError> {
    if let Some(read) = &state.display_read {
        let saved = read.request();
        let timestamp = saved
            .header(pubky_switch_core::http::header::TIMESTAMP)
            .and_then(|s| pubky_switch_core::time::parse_rfc3339(s).ok())
            .ok_or_else(super::corrupt)?;
        let query = FeedQuery {
            after: Some(Position {
                generation: read.meta.generation,
                seq: read.after,
            }),
            limit: Some(read.limit),
            wait: None,
        };
        if read.limit == 0 || client.display_feed_request(&query, Some(timestamp))? != saved {
            return Err(super::corrupt());
        }
    }
    if let Some(reads) = &client.own_reads {
        reads.stored_display(state.display_read.is_some(), state.health.notice);
    }
    Ok(())
}

impl App {
    /// The original issued display read still awaiting its outcome. When present, the
    /// foreground checks the host transport's durable result before further own requests
    /// or attempts. Its presence alone says nothing about the service's health.
    pub fn pending_display_read(&self) -> Option<&DisplayRead> {
        self.state.display_read.as_ref()
    }

    /// Reserve one signed, single-page display GET before it is handed to a transport
    /// that survives extension exit. The owner serializes this handoff with its other
    /// own requests. A display process may render the reply with [`Self::display_preview`].
    ///
    /// # Errors
    /// A store failure, an unregistered or departed app, or another own read in flight.
    pub async fn begin_display_read(&mut self) -> Result<DisplayRead, AppError> {
        self.ready_local().await?;
        if self.state.leave.is_some() {
            return Err(Refusal::Left.into());
        }
        if self.state.gone.is_some() {
            return Err(Refusal::Gone.into());
        }
        if self.state.chain.is_none() {
            return Err(Refusal::NotNow("the app isn't registered".into()).into());
        }
        let after = self.cursor();
        let query = FeedQuery {
            after: Some(after),
            limit: Some(self.config.page()),
            wait: None,
        };
        let request = self.client.display_feed_request(&query, None)?;
        let mut id = [0; 16];
        getrandom::fill(&mut id)
            .map_err(|_| Refusal::NotNow("display read randomness unavailable".into()))?;
        let read = DisplayRead {
            id,
            meta: self.state.meta.clone(),
            after: after.seq,
            limit: self.config.page(),
            path: request.path_and_query,
            headers: request.headers,
        };
        let mut next = self.state.health;
        next.display_id = Some(id);
        let mut tx = self.tx()?;
        next.write(&mut tx)?;
        tx.put(PENDING, &read)?;
        if !self
            .client
            .own_reads
            .as_ref()
            .is_some_and(|reads| reads.reserve_display())
        {
            return Err(Refusal::NotNow("an own request is still in flight".into()).into());
        }
        self.commit(tx).await?;
        self.state.health = next;
        self.state.display_read = Some(read.clone());
        Ok(read)
    }

    /// Check a returned page for display without changing the app. The host can show a
    /// generic notification on a failed read or for the unread remainder of this page.
    ///
    /// # Errors
    /// A stale handoff, a failed or unverifiable response, or an unavailable local record.
    /// Returns [`Refusal::NotNow`] while a save's outcome is unknown: a call that changes
    /// state, such as [`App::receive`], reloads it, and this call succeeds after that.
    pub async fn display_preview(&self, receipt: &DisplayReceipt) -> Result<PeekReport, AppError> {
        self.require_loaded()?;
        let read = self
            .pending_display_read()
            .filter(|r| r.id == receipt.id)
            .ok_or_else(|| Refusal::NotNow("the display read is no longer pending".into()))?;
        let response = receipt.response.as_ref().ok_or_else(|| {
            Refusal::NotNow("the display read could not reach the service".into())
        })?;
        let checked = read.checked(response)?;
        let page = self.client.feed_page(&checked)?;
        let mut chain = self.state.chain.clone().ok_or_else(super::corrupt)?;
        let mut report = PeekReport {
            items: Vec::new(),
            chain_verified: chain
                .feed_page(&page, self.now(), self.state.device.multi_device)
                .is_ok(),
            more: page.more,
        };
        self.display_entries(&page, read.after, &mut report).await?;
        Ok(report)
    }

    /// Commit a host transport's terminal display outcome and release its request. Only
    /// after this succeeds may the host discard its retained response. An already released
    /// identifier returns `false`, including after acknowledgement loss and reopen.
    ///
    /// # Errors
    /// A storage failure, a provider identity that must be followed, or a rollback alarm.
    pub async fn finish_display_read(
        &mut self,
        receipt: &DisplayReceipt,
    ) -> Result<bool, AppError> {
        Box::pin(self.finish_display(receipt)).await
    }

    async fn finish_display(&mut self, receipt: &DisplayReceipt) -> Result<bool, AppError> {
        self.ready_local().await?;
        let Some(read) = self.pending_display_read().filter(|r| r.id == receipt.id) else {
            return Ok(false);
        };
        let generation = read.meta.generation;
        let answer = receipt
            .response
            .as_ref()
            .and_then(|response| {
                OwnAnswer::from_response(read.checked(response).as_ref(), response)
            })
            .unwrap_or(OwnAnswer::Unavailable);
        let mut next = self.health_after(answer, receipt.received_at_ms).await?;
        let reads = OwnReads::new(generation, next.notice);
        reads.observe(1, answer, receipt.received_at_ms);
        let mut alarm = None;
        if !self.provider_superseded() {
            match reads.first() {
                Some(Decision::Notice(notice)) => next.notice = notice,
                Some(Decision::Rollback) => alarm = Some(self.recovery_rollback().await),
                None => {}
            }
        }
        next.display_id = None;
        self.pending_health = Some(next);
        self.keep_health().await?;
        if let Some(error) = alarm {
            return Err(error);
        }
        Ok(true)
    }
}
