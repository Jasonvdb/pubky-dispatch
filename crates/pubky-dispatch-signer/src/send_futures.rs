//! The futures of the signer's entry points a host may spawn are `Send`: a host runs them on
//! a multi-threaded runtime, and a future that holds a non-`Send` value, such as a borrowed
//! iterator, across an await can't be spawned. Building the library checks every public async
//! function of the signer. The function below is never called.

use std::sync::Arc;

use pubky_dispatch_core::keys::AppKeys;
use pubky_dispatch_core::records::ConnectRequests;

use crate::{
    Alert, AppReview, CertChange, FirstEnrollmentRestore, IdentityKeyring, KeyRecoveryConfirmed,
    ReceivingApp, RecordsDiscarded, SecretVault, Signer, SignerEnv, UserConfirmed,
};

fn is_send<T: Send>(_: T) {}

/// Every call below is a future the host may spawn; none is awaited.
#[allow(dead_code, clippy::too_many_arguments)]
fn signer_futures_are_send(
    signer: &mut Signer,
    env: SignerEnv,
    keyring: fn() -> IdentityKeyring,
    first: &FirstEnrollmentRestore,
    recovery: KeyRecoveryConfirmed,
    review: AppReview,
    request: &[u8; 32],
    change: CertChange,
    settings: ConnectRequests,
    alert: &Alert,
    receiving: &ReceivingApp,
    keys: &AppKeys,
    vault: Arc<dyn SecretVault>,
) {
    let confirmed = UserConfirmed::shown_and_confirmed;
    let origin = "https://switch.example";
    // Calls that don't require an open signer.
    is_send(Signer::create(env.clone(), keyring(), origin));
    is_send(Signer::open(env.clone(), keyring()));
    is_send(Signer::restore_new(env.clone(), keyring(), confirmed()));
    is_send(Signer::restore_over_unusable(
        env.clone(),
        keyring(),
        RecordsDiscarded::shown_and_confirmed(),
    ));
    is_send(Signer::survey_key_recovery_new(env.clone(), keyring()));
    is_send(Signer::survey_key_recovery_new_at(
        env.clone(),
        keyring(),
        origin,
    ));
    is_send(Signer::survey_provider_loss_with_key(
        env.clone(),
        keyring(),
        origin,
    ));
    is_send(Signer::declare_provider_loss_with_key(
        env.clone(),
        keyring(),
        recovery,
    ));
    is_send(Signer::receive_hand_over(
        env.clone(),
        receiving,
        vault.clone(),
    ));
    is_send(Signer::resume_take_over(env, [0; 32], keys, vault));
    // Calls on a signer, one at a time, as `&mut self` allows.
    is_send(signer.resume());
    is_send(signer.restart_first_enrollment(origin, confirmed()));
    is_send(signer.survey_first_enrollment_restore(origin));
    is_send(signer.restore_first_enrollment(first, &[], confirmed()));
    is_send(signer.clear_alert(alert));
    is_send(signer.set_record_max_age(None));
    is_send(signer.set_connect_requests(settings));
    is_send(signer.renew([0; 16], change));
    is_send(signer.complete_renewals());
    is_send(signer.run_due());
    is_send(signer.renew_expiring());
    is_send(signer.declare_provider_loss(origin, confirmed()));
    is_send(signer.declare_provider_loss_confirming_records(origin, confirmed()));
    is_send(signer.end_staged_admission());
    is_send(signer.survey_key_recovery());
    is_send(signer.cancel_key_recovery(confirmed()));
    is_send(signer.restore(confirmed()));
    is_send(signer.approve(review));
    is_send(signer.claim_delivered(request));
    is_send(signer.hand_over_to([0; 16], confirmed()));
    is_send(signer.abort_hand_over(confirmed()));
    is_send(signer.take_back(confirmed()));
    is_send(signer.close_account(confirmed()));
    is_send(signer.abort_erasure());
    is_send(signer.revoke([0; 16], None, confirmed()));
    is_send(signer.complete_removals());
    is_send(signer.open_attempts([0; 16]));
    is_send(signer.purge_removed([0; 16]));
    is_send(signer.serve_full_bundles());
}
