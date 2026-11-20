//! The admission state kept for one peer (Switch spec 7).

use crate::ops::AllowKind;

/// Who first granted the current reply reason (Switch wire 7.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyOrigin {
    /// The App ID that granted reply access.
    App([u8; 16]),
    /// The code hash of the invitation the service redeemed to grant reply access.
    Invite([u8; 32]),
}

/// One continuous grant of reply access to a peer (Switch wire 7.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyGrant {
    /// The grant's original writer.
    pub origin: ReplyOrigin,
    /// When the grant was created, in Unix milliseconds.
    pub at: u64,
    /// When an append last used the grant, in Unix milliseconds, at or after its creation.
    pub last_used: Option<u64>,
}

/// The reasons a single peer has admission (Switch wire 7.4.6, 10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerEntry {
    /// The peer's Pubky ID.
    pub pubky: [u8; 32],
    /// Whether a managing app explicitly kept the peer.
    pub kept: bool,
    /// The current reply grant, when one exists.
    pub reply: Option<ReplyGrant>,
}

impl PeerEntry {
    /// Whether the peer holds this particular admission reason.
    pub fn has_reason(&self, reason: AllowKind) -> bool {
        match reason {
            AllowKind::Contact => self.kept,
            AllowKind::Conversation => self.reply.is_some(),
        }
    }
}
