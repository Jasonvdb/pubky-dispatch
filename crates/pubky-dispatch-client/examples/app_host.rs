//! Startup and foreground reads in a host with one registered protocol.
//! Build with `cargo build -p pubky-dispatch-client --example app_host`.
//! The embedding app supplies its encrypted durable store, clock, transport,
//! Homeserver access and protocol through the same public APIs it uses on device.

use std::sync::Arc;

use pubky_dispatch_client::app::{
    App, AppConfig, AppEnv, AppError, AppEvent, JoinRequest, LocalWrite, Protocol,
};

/// Join once after the host verifies the signer's companion claim (Dispatch wire 3.10).
/// Save the App ID before joining so an interrupted registration can be loaded.
///
/// # Errors
///
/// Returns the host's storage error or the client's approval, storage or registration error.
pub async fn join_approved(
    env: AppEnv,
    protocol: Arc<dyn Protocol>,
    config: AppConfig,
    approval: JoinRequest,
    save_app_id: impl FnOnce([u8; 16]) -> Result<(), AppError>,
) -> Result<App, AppError> {
    save_app_id(approval.keys.app_id_bytes())?;
    App::join(env, protocol, config, approval).await
}

/// Reopen the same installation and display its current recovery state before a network call.
///
/// # Errors
///
/// Returns the load error if the stored installation or its protocol cannot be opened.
pub async fn reopen(
    env: AppEnv,
    protocol: Arc<dyn Protocol>,
    config: AppConfig,
    app_id: [u8; 16],
    show_health: impl FnOnce(pubky_dispatch_client::app::ProviderHealth),
) -> Result<App, AppError> {
    let app = App::load(env, protocol, config, app_id).await?;
    show_health(app.provider_health());
    Ok(app)
}

/// What the embedding app should schedule after one bounded receive.
#[derive(Debug, PartialEq, Eq)]
pub enum NextRead {
    /// Another bounded read can make progress now.
    ReadAgain,
    /// Resolve the reported stop or finish an outstanding host duty.
    AttendToHostWork,
    /// Schedule the next foreground wake or use the client's paced feed wait.
    Wait,
}

/// Receive once on startup or wake (Dispatch spec 8.2).
///
/// `show` presents events. `writes_for_duty` returns the protocol-local changes that
/// finish a duty, or `None` until the host is ready. Presentation alone leaves a duty owed.
/// On an uncertain acknowledgement, reopen and inspect the durable handling state before
/// performing any external action again.
///
/// # Errors
///
/// Returns a receive or store error to the host for its normal error handling.
pub async fn on_wake(
    app: &mut App,
    owner: &str,
    mut show: impl FnMut(&AppEvent),
    mut writes_for_duty: impl FnMut(&AppEvent) -> Option<Vec<LocalWrite>>,
) -> Result<NextRead, AppError> {
    let mut next = match app.receive(None).await {
        Ok(report) => {
            for event in &report.events {
                if !event.is_duty() {
                    show(event);
                }
            }
            Ok(if report.stopped {
                NextRead::AttendToHostWork
            } else if report.more {
                NextRead::ReadAgain
            } else {
                NextRead::Wait
            })
        }
        Err(error) => {
            for event in app.take_events() {
                if !event.is_duty() {
                    show(&event);
                }
            }
            Err(error)
        }
    };

    for event in app.unacknowledged_events_for(owner).await? {
        show(&event);
        if let Some(id) = event.id()
            && let Some(writes) = writes_for_duty(&event)
        {
            app.ack_event_with(owner, id, &writes).await?;
        } else if matches!(next, Ok(NextRead::Wait)) {
            next = Ok(NextRead::AttendToHostWork);
        }
    }
    next
}
