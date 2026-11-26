//! The app's public futures are `Send`, so a host can run them on a multi-threaded runtime.
//! A future that holds a value that isn't `Send` across an await stops this file compiling,
//! as one that loses `Sync` does where it had it.

use pubky_dispatch_core::message::MessagePlaintext;
use serde_json::Map;

use super::*;
use crate::app::{AppBackup, LeaveMode, OutgoingMessage};

fn assert_send<T: Send>(_: &T) {}

/// Each future is made and dropped, never polled: the check is the compiler's.
fn futures_are_send(
    app: &mut App,
    env: AppEnv,
    protocol: Arc<dyn Protocol>,
    backup: &AppBackup,
    request: JoinRequest,
    plaintext: &MessagePlaintext,
) {
    assert_send(&app.receive(None));
    assert_send(&app.check_for_move());
    assert_send(&app.follow_provider());
    assert_send(&app.fetch_key_bundle());
    assert_send(&app.list_collections());
    assert_send(&app.flush_cursor());
    assert_send(&app.finish_leave());
    assert_send(&app.backup_layered());
    assert_send(&app.set_protocol_member("sample", Some(Map::new()), None));
    assert_send(&app.renew_record("sample", None));
    assert_send(&app.update_accepts());
    assert_send(&app.publish_record());
    assert_send(&app.forget_processed("sample", [0; 32], "", &[]));
    assert_send(&app.flush_outbox());
    assert_send(&app.listing_owed());
    assert_send(&app.send(OutgoingMessage::new([0; 32], "sample.note", Map::new())));
    assert_send(&app.queue_stored(plaintext));
    assert_send(&app.hold_queued(&[0; 32]));
    assert_send(&app.release_queued(&[0; 32]));
    assert_send(&app.held_counterparties());
    assert_send(&app.withdraw_queued(&[0; 32]));
    assert_send(&app.leave(LeaveMode::TwoStep));
    assert_send(&App::load(
        env.clone(),
        Arc::clone(&protocol),
        AppConfig::default(),
        [0; 16],
    ));
    assert_send(&App::join(
        env.clone(),
        Arc::clone(&protocol),
        AppConfig::default(),
        request,
    ));
    assert_send(&App::restore(env, protocol, AppConfig::default(), backup));
}

fn assert_sync<T: Sync>(_: &T) {}

/// The futures that are `Sync` as well, made and dropped, never polled: one boxed on the
/// way as `dyn Future` would lose it, so a host whose bound asks `Sync` keeps it.
fn futures_are_sync(
    app: &mut App,
    env: AppEnv,
    protocol: Arc<dyn Protocol>,
    backup: &AppBackup,
    plaintext: &MessagePlaintext,
) {
    assert_sync(&app.withdraw_queued(&[0; 32]));
    assert_sync(&app.withdraw_message("sample", ""));
    assert_sync(&app.backup_layered());
    assert_sync(&app.forget_processed("sample", [0; 32], "", &[]));
    assert_sync(&app.listing_owed());
    assert_sync(&app.queue_stored(plaintext));
    assert_sync(&app.hold_queued(&[0; 32]));
    assert_sync(&app.release_queued(&[0; 32]));
    assert_sync(&app.held_counterparties());
    assert_sync(&App::load(
        env.clone(),
        Arc::clone(&protocol),
        AppConfig::default(),
        [0; 16],
    ));
    assert_sync(&App::restore(env, protocol, AppConfig::default(), backup));
}

#[test]
fn test_send_futures_of_the_app_that_are_sync_stay_sync() {
    let _ =
        futures_are_sync as fn(&mut App, AppEnv, Arc<dyn Protocol>, &AppBackup, &MessagePlaintext);
}

#[test]
fn test_send_futures_of_the_app_are_send() {
    let _ = futures_are_send
        as fn(&mut App, AppEnv, Arc<dyn Protocol>, &AppBackup, JoinRequest, &MessagePlaintext);
}
