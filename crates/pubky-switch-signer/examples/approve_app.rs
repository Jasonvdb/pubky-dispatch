//! Approve an app with an open signer and the host's device-bound store (Switch spec 12.1).

use std::error::Error;

use pubky_switch_core::records::{AppRequest, AuthRequest};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_signer::{AppReview, Signer};

/// A signer, relay, grant or durable-storage result returned to the host.
pub type HostResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// One device-bound record per request hash. Never log the original auth request.
#[derive(Clone)]
pub enum SavedApproval {
    /// The user chose these capabilities. Grant delivery is still pending.
    Confirmed {
        /// The original signed app request.
        request: SignedDoc,
        /// The matching Pubky auth request, including its secret.
        auth: AuthRequest,
        /// The paths declined in this confirmed review.
        declined: Vec<String>,
    },
    /// The relay accepted the claim and the Homeserver confirmed the grant.
    GrantComplete,
}

/// Each write atomically replaces the record, and returns after it is durable.
/// The host handles one approval at a time for each request.
pub trait ApprovalStore {
    /// Read the device-bound record for this request, if present.
    fn read(&self, hash: &[u8; 32]) -> HostResult<Option<SavedApproval>>;
    /// Persist a confirmed review or replace it with its completed grant.
    fn save(&self, hash: &[u8; 32], approval: SavedApproval) -> HostResult<()>;
    /// Delete this record once the signer has acknowledged delivery.
    fn remove(&self, hash: &[u8; 32]) -> HostResult<()>;
}

/// Show the review, applying the user's selected paths with `AppReview::decline`.
/// Returning false cancels a new request before anything is signed.
///
/// # Errors
///
/// Returns the signer's or the host adapter's error.
pub async fn approve_app(
    signer: &mut Signer,
    store: &impl ApprovalStore,
    request: &SignedDoc,
    auth: &AuthRequest,
    confirm: impl AsyncFnOnce(&mut AppReview) -> HostResult<bool>,
    send_companion_claim: impl AsyncFnOnce(&AuthRequest, &[u8]) -> HostResult<()>,
    approve_auth_with_capabilities: impl AsyncFnOnce(&AuthRequest, &str) -> HostResult<()>,
) -> HostResult<Option<[u8; 32]>> {
    let hash = AppRequest::verify(request)?.hash();
    if store.read(&hash)?.is_none() {
        let mut review = signer.review(request, auth)?;
        if !confirm(&mut review).await? {
            return Ok(None);
        }
        store.save(
            &hash,
            SavedApproval::Confirmed {
                request: request.clone(),
                auth: auth.clone(),
                declined: review.declined().to_vec(),
            },
        )?;
    }
    resume_approval(
        signer,
        store,
        &hash,
        send_companion_claim,
        approve_auth_with_capabilities,
    )
    .await?;
    Ok(Some(hash))
}

/// On restart, call this for each saved request. The relay callback encrypts the claim.
/// The grant callback confirms the grant for exactly the signer's selected capabilities.
/// Both adapters must recognize an already completed delivery if its response was lost.
///
/// # Errors
///
/// Returns the signer's or the host adapter's error. Keep the record and retry.
pub async fn resume_approval(
    signer: &mut Signer,
    store: &impl ApprovalStore,
    hash: &[u8; 32],
    send_companion_claim: impl AsyncFnOnce(&AuthRequest, &[u8]) -> HostResult<()>,
    approve_auth_with_capabilities: impl AsyncFnOnce(&AuthRequest, &str) -> HostResult<()>,
) -> HostResult<()> {
    match store.read(hash)? {
        None => return Ok(()),
        Some(SavedApproval::GrantComplete) => {}
        Some(SavedApproval::Confirmed {
            request,
            auth,
            declined,
        }) => {
            if AppRequest::verify(&request)?.hash() != *hash {
                return Err("saved approval does not match its request hash".into());
            }
            signer.resume().await?;
            let approved = match signer.approved(hash)? {
                Some(approved) => approved,
                None => {
                    let mut review = signer.review(&request, &auth)?;
                    review.decline(&declined.iter().map(String::as_str).collect::<Vec<_>>())?;
                    signer.approve(review).await?
                }
            };
            send_companion_claim(&auth, &approved.claim).await?;
            approve_auth_with_capabilities(&auth, &approved.caps).await?;
            store.save(hash, SavedApproval::GrantComplete)?;
        }
    }
    signer.claim_delivered(hash).await?;
    store.remove(hash)
}
