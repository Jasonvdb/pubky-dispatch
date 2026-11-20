//! Approve a new app request on an open signer (Switch spec 12.1).
//! The host supplies its confirmation screen, device-bound storage, relay and Pubky grant.

use std::error::Error;

use pubky_switch_core::records::AuthRequest;
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_signer::{AppReview, Signer};

type HostResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Show the checked selection for this request. If the user confirms, keep the original
/// requests, review hash and declined paths in device-bound storage before returning true.
/// A cancellation or storage error stops before the signer can approve.
///
/// The relay callback encrypts the companion claim for this auth request. After the relay
/// accepts it, the grant callback approves exactly the capabilities returned by the signer.
/// Keep the saved decision through any error. Follow the signer host guide's approval
/// checklist to resume it after restart. On success, remove the saved decision for the
/// returned request hash. A user cancellation returns `None`.
///
/// # Errors
///
/// Returns a declined-path, signer, storage, relay or grant error to the host.
pub async fn approve_app(
    signer: &mut Signer,
    request: &SignedDoc,
    auth: &AuthRequest,
    declined_paths: &[&str],
    confirm_and_save: impl AsyncFnOnce(&SignedDoc, &AuthRequest, &AppReview) -> HostResult<bool>,
    send_companion_claim: impl AsyncFnOnce(&AuthRequest, &[u8]) -> HostResult<()>,
    approve_auth_with_capabilities: impl AsyncFnOnce(&AuthRequest, &str) -> HostResult<()>,
) -> HostResult<Option<[u8; 32]>> {
    let mut review = signer.review(request, auth)?;
    review.decline(declined_paths)?;
    if !confirm_and_save(request, auth, &review).await? {
        return Ok(None);
    }
    let approved = signer.approve(review).await?;
    send_companion_claim(auth, &approved.claim).await?;
    approve_auth_with_capabilities(auth, &approved.caps).await?;
    signer.claim_delivered(&approved.request).await?;
    Ok(Some(approved.request))
}
