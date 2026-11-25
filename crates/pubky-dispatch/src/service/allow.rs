//! Signed peer admission, deny, flag and invitation inventories (Dispatch wire 7.4.6).

use pubky_dispatch_core::{
    admission::PeerEntry,
    enc::{b64, pubky_id, zbase32_encode},
    records::AppCert,
    scopes::Permission,
    time::rfc3339,
};

use super::{AccountOutcome, PageRead, Service, store_error};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::ServiceSigner,
    store::{AccountTxn, AllowInvite, SnapshotRead},
};

/// A JSON string: the encodings this answer writes (a Pubky ID, an App ID, b64, a time)
/// are ASCII with nothing to escape.
fn string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    out.extend_from_slice(text.as_bytes());
    out.push(b'"');
}

/// `[ "pubky", ... ]`.
fn pubkys(out: &mut Vec<u8>, entries: &[[u8; 32]]) {
    out.push(b'[');
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        string(out, &pubky_id(entry));
    }
    out.push(b']');
}

/// A live invite code: `code_hash`, `expires_at`, `max_uses`, `uses`,
/// `written_by`.
fn invite(out: &mut Vec<u8>, invite: &AllowInvite) {
    out.extend_from_slice(b"{\"code_hash\":");
    string(out, &b64(&invite.code_hash));
    out.extend_from_slice(b",\"expires_at\":");
    string(out, &rfc3339(invite.expires_at_ms));
    out.extend_from_slice(format!(",\"max_uses\":{}", invite.max_uses).as_bytes());
    out.extend_from_slice(format!(",\"uses\":{}", invite.uses).as_bytes());
    out.extend_from_slice(b",\"written_by\":");
    string(out, &zbase32_encode(&invite.writer));
    out.push(b'}');
}

/// The four lists in the order of the signed answer (Dispatch wire 7.4.6).
fn answer_body(
    peers: &[PeerEntry],
    deny: &[[u8; 32]],
    flagged: &[([u8; 32], u64)],
    invites: &[AllowInvite],
) -> Result<Vec<u8>, ApiError> {
    let mut out = b"{\"peers\":[".to_vec();
    for (i, peer) in peers.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(
            &peer
                .to_json()
                .map_err(|_| ApiError::unavailable("7.4.6: stored peer admission"))?,
        );
    }
    out.extend_from_slice(b"],\"deny\":");
    pubkys(&mut out, deny);
    out.extend_from_slice(b",\"flagged\":[");
    for (i, (pubky, hits)) in flagged.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"pubky\":");
        string(&mut out, &pubky_id(pubky));
        out.extend_from_slice(format!(",\"hits\":{hits}}}").as_bytes());
    }
    out.extend_from_slice(b"],\"invite_codes\":[");
    for (i, code) in invites.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        invite(&mut out, code);
    }
    out.extend_from_slice(b"]}");
    Ok(out)
}

/// A `GET /allow` answer's lists, read once the lock is gone from the snapshot of the state
/// under it, so a long read holds no lock other requests wait for.
#[derive(Debug)]
pub(super) struct AllowRead {
    snapshot: SnapshotRead,
    time_ms: u64,
    flag_after: u64,
}

impl Service {
    /// `GET /v1/{id}/allow` (Dispatch wire 7.4.6) under the lock, for the own app `reader`,
    /// which needs `lists.read` (`403 permission_missing`). The lists are read after the
    /// lock ([`Service::allow_body`]) from the snapshot this transaction exports under it:
    /// every write to them takes the account's lock, so they are the state at its stamped
    /// service time `time_ms`, the `Dispatch-Server-Time` the answer is signed at, which the
    /// client keeps as the time its copy of the lists is as of.
    pub(super) async fn get_allow(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        reader: Option<&AppCert>,
        time_ms: u64,
    ) -> Result<AccountOutcome, ApiError> {
        if !reader.is_some_and(|cert| cert.has_permission(Permission::ListsRead)) {
            return Err(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.6: reading the lists needs lists.read",
            ));
        }
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        let snapshot = txn.snapshot_read().map_err(|e| store_error(&e))?;
        Ok(AccountOutcome::page(
            PageRead::Allow(AllowRead {
                snapshot,
                time_ms,
                flag_after: u64::from(self.limits.flag_after),
            }),
            head,
        ))
    }

    /// The lists of `read`, whole (Dispatch wire 7.4.6): `flagged` holds every sender with at
    /// least `flag_after` hits, bounded by `max_flags` (9.4), and `invite_codes` every code
    /// with uses left and unexpired at the request's service time.
    pub(super) async fn allow_body(read: AllowRead) -> Result<Vec<u8>, ApiError> {
        let AllowRead {
            mut snapshot,
            time_ms,
            flag_after,
        } = read;
        snapshot.start().await;
        let fail = |e: &crate::store::StoreError| store_error(e);
        let peers = snapshot.admission_rows().await.map_err(|e| fail(&e))?;
        let deny = snapshot.deny_rows().await.map_err(|e| fail(&e))?;
        let flagged = snapshot
            .flagged_senders(flag_after)
            .await
            .map_err(|e| fail(&e))?;
        let invites = snapshot
            .live_invite_codes(time_ms)
            .await
            .map_err(|e| fail(&e))?;
        snapshot.finish().await.map_err(|e| fail(&e))?;
        answer_body(&peers, &deny, &flagged, &invites)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_answer_has_every_list_in_table_order() {
        use pubky_dispatch_core::admission::{ReplyGrant, ReplyOrigin};
        let empty =
            String::from_utf8(answer_body(&[], &[], &[], &[]).expect("answer")).expect("utf-8");
        assert_eq!(
            empty,
            "{\"peers\":[],\"deny\":[],\"flagged\":[],\"invite_codes\":[]}"
        );
        let service = PeerEntry {
            pubky: [1; 32],
            kept: true,
            reply: Some(ReplyGrant {
                origin: ReplyOrigin::Invite([2; 32]),
                at: 0,
                last_used: Some(1_000),
            }),
        };
        let app = PeerEntry {
            pubky: [3; 32],
            kept: false,
            reply: Some(ReplyGrant {
                origin: ReplyOrigin::App([4; 16]),
                at: 0,
                last_used: None,
            }),
        };
        let body = answer_body(&[service, app], &[], &[([5; 32], 3)], &[]).expect("answer");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let rows = value["peers"].as_array().expect("peers");
        assert_eq!(rows[0]["kept"], true);
        assert_eq!(rows[0]["reply"]["written_by"], "service");
        assert_eq!(rows[0]["reply"]["code_hash"], b64(&[2; 32]));
        assert!(rows[1]["reply"].get("code_hash").is_none());
        assert!(rows[1]["reply"].get("last_used").is_none());
        assert_eq!(value["flagged"][0]["hits"], 3);
    }
}
