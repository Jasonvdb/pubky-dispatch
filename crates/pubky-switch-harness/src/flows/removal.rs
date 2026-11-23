//! Removing an app: a revocation by the signer, and a departure by the app itself, each
//! with the rotation that follows (Switch spec 12.2, 12.3, 3.5, Switch wire 7.4.11, 7.4.12).

use pubky_switch_client::app::{App, AppError, Delivery, LeaveMode, OutgoingMessage};
use pubky_switch_signer::UserConfirmed;
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::parties::NOTE_KIND;
use crate::{FlowResult, World};

/// The signer revokes one of two apps: at the switch, then with the rotation and the version
/// that removes it. The app that stays follows its feed and fetches the new epoch's keys;
/// the revoked app is refused. An app approved after the rotation joins at the new epoch,
/// with every key it needs in its approval.
///
/// Calls, beyond the join's: `POST /v1/{id}/apps/{app_id}/revoke`, the signer's `POST
/// /v1/{id}/ops` (`key_bundle.put` for the rotation), `PUT /v1/{id}/identity` (the removing
/// version), `GET /v1/{id}/apps/{app_id}/keys` with parts, and a revoked app's refused `GET
/// /v1/{id}/feed` and `GET /v1/{id}/apps/{app_id}/keys`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn revocation(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    let removing = signer
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "revoked",
        &json!({
            "version": removing.version(),
            "data_epoch": removing.body().data_epoch,
            "removed": removing.body().removed.len(),
            "signer": status(&signer)?,
        }),
    );
    world.advance_ms(STEP_MS);

    follow(world, &mut wallet, "the wallet after the revocation").await?;
    let refused = phone.receive(None).await;
    world.outcome("the revoked phone reads its feed", &result(&refused));
    world.advance_ms(STEP_MS);

    // An app approved now joins at the new epoch.
    let (mut tablet, _) = joined(world, &alice, &mut signer, "tablet").await?;
    follow(world, &mut tablet, "the tablet").await?;
    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    world.advance_ms(STEP_MS);
    follow(world, &mut wallet, "the wallet at the end").await?;
    Ok(())
}

/// One of two apps leaves in two steps: `leave` at the switch, then, once the signer's
/// routine run rotated and published it as removed, the wait and the deletion of its keys.
/// The app that stays follows its feed and fetches the new epoch's keys.
///
/// Calls, beyond the join's: `POST /v1/{id}/apps/{app_id}/leave`, the signer's `GET
/// /v1/{id}/apps` showing the departure, its `POST /v1/{id}/ops` (`key_bundle.put`) and `PUT
/// /v1/{id}/identity` (the removing version).
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn departure(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    let left = phone.leave(LeaveMode::TwoStep).await?;
    world.outcome("the phone left", &json!({ "report": format!("{left:?}") }));
    world.advance_ms(STEP_MS);

    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    world.advance_ms(STEP_MS);

    let waiting = phone.finish_leave().await?;
    world.outcome(
        "the phone sees its removal",
        &json!({ "report": format!("{waiting:?}").split(' ').next() }),
    );
    world.advance_ms(pubky_switch_client::app::LEAVE_CACHE_MS + STEP_MS);
    let done = phone.finish_leave().await?;
    world.outcome(
        "the phone deleted its keys",
        &json!({ "report": format!("{done:?}") }),
    );

    follow(world, &mut wallet, "the wallet after the departure").await?;
    Ok(())
}

/// A revocation while a counterparty's messages are held. alice's wallet has written to
/// bob, so it knows his switch's copy of her `identity.json`. The host then holds the
/// wallet's messages to bob ([`App::hold_queued`]) and the wallet queues one more. alice's
/// signer revokes her phone. The wallet reads the removing version in its feed, and its
/// flush delivers that version to bob's switch (Switch spec 12.2 step 5), which the hold
/// doesn't hold back: it tells bob's switch that the phone's signature no longer counts.
/// The held message makes no request meanwhile. Released, it goes, and bob reads both
/// messages.
///
/// Calls: `PUT /v1/{id}/peers` with a version that removes an app, sent while a message to
/// that counterparty is held, and `POST /v1/{id}/inbox` once it is released.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the held message is sent
/// while held, or the removing version doesn't reach bob's switch.
pub async fn revocation_held(world: &World) -> FlowResult {
    const APPEND: &str = "{alice/wallet} POST /v1/{bob}/inbox";
    const DELIVERY: &str = "{alice/wallet} PUT /v1/{bob}/peers";
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (phone, _) = joined(world, &alice, &mut alice_signer, "phone").await?;
    let (mut shop, shop_protocol) = joined(world, &bob, &mut bob_signer, "shop").await?;
    shop.keep_peer(&alice.public()).await?;
    world.advance_ms(STEP_MS);

    let note = |text: &str| {
        let mut body = serde_json::Map::new();
        body.insert("text".into(), json!(text));
        OutgoingMessage::new(bob.public(), NOTE_KIND, body)
    };
    let (_, first) = wallet.send(note("first")).await?;
    world.outcome(
        "the wallet wrote to bob",
        &json!({ "delivery": shown(&first), "app": app_status(&mut wallet) }),
    );
    world.advance_ms(STEP_MS);

    // The host holds bob's messages; the next one stays queued, untried.
    wallet.hold_queued(&bob.public()).await?;
    let from = world.trace().lines.len();
    let (held, queued) = wallet.send(note("held")).await?;
    world.outcome(
        "the wallet queued a message to bob, held",
        &json!({
            "delivery": shown(&queued),
            "held": wallet.held_counterparties().await?.len(),
        }),
    );
    world.advance_ms(STEP_MS);

    // The delivery may come in the wallet's read or its flush, and once or more (Switch spec
    // 12.2 step 5): what counts is that one arrives.
    let delivered_from = world.trace().lines.len();
    let removing = alice_signer
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer revoked the phone",
        &json!({ "version": removing.version(), "signer": status(&alice_signer)? }),
    );
    world.advance_ms(STEP_MS);
    let report = wallet.receive(None).await?;
    world.outcome(
        "the wallet read the removing version",
        &json!({ "events": events(&report.events), "app": app_status(&mut wallet) }),
    );
    world.advance_ms(STEP_MS);
    let flushed = wallet.flush_outbox().await?;
    let still = wallet.delivery(&held).await?;
    world.outcome(
        "the wallet's flush, bob held",
        &json!({
            "done": flushed.done.len(),
            "queued": flushed.queued.len(),
            "delivery": still.as_ref().map(shown),
        }),
    );
    world.advance_ms(STEP_MS);

    // The removing version reached bob's switch (Switch wire 7.4.5): it holds it now.
    let delivered = world.trace().lines[delivered_from..]
        .iter()
        .filter(|line| line.label == DELIVERY)
        .map(|line| {
            (
                line.facts.get("status").cloned(),
                line.facts.get("body.version").cloned(),
            )
        })
        .collect::<Vec<_>>();
    let expected = (
        Some("200".to_owned()),
        Some(format!("number {}", removing.version())),
    );
    if !delivered.contains(&expected) {
        return Err(format!(
            "the wallet's deliveries to bob's switch were {delivered:?}, none {expected:?}"
        )
        .into());
    }
    // The held message made no request, and is still owed.
    let appended = world.trace().lines[from..]
        .iter()
        .filter(|line| line.label == APPEND)
        .count();
    if appended != 0 || !flushed.queued.contains(&held) {
        return Err(format!("the held message was sent {appended} times while held").into());
    }

    wallet.release_queued(&bob.public()).await?;
    let flushed = wallet.flush_outbox().await?;
    let released = wallet.delivery(&held).await?;
    world.outcome(
        "the wallet released bob",
        &json!({ "done": flushed.done.len(), "delivery": released.as_ref().map(shown) }),
    );
    world.advance_ms(STEP_MS);
    if !matches!(released, Some(Delivery::Accepted { .. })) {
        return Err(format!("the released message is {}", shown_opt(released.as_ref())).into());
    }
    let report = shop.receive(None).await?;
    shop.flush_cursor().await?;
    world.outcome(
        "bob's shop read alice's messages",
        &json!({
            "events": events(&report.events),
            "messages": shop_protocol.received().len(),
        }),
    );
    if shop_protocol.received().len() != 2 {
        return Err("bob didn't read both of alice's messages".into());
    }
    Ok(())
}

/// A delivery's state, for the trace: its variant's name.
fn shown(delivery: &Delivery) -> String {
    format!("{delivery:?}")
        .split(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// As [`shown`], for a delivery the app may not know.
fn shown_opt(delivery: Option<&Delivery>) -> String {
    delivery.map_or_else(|| "unknown".to_owned(), shown)
}

/// `app` follows its feed and fetches its key bundle, with what it shows after each.
pub(crate) async fn follow(world: &World, app: &mut App, name: &str) -> FlowResult {
    let report = app.receive(None).await?;
    world.outcome(
        &format!("{name}: received"),
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    app.fetch_key_bundle().await?;
    world.outcome(&format!("{name}: keys fetched"), &app_status(app));
    world.advance_ms(STEP_MS);
    Ok(())
}

/// How a call ended, for the trace: the error's kind and its code at the switch, never its
/// text.
pub(crate) fn result<T>(result: &Result<T, AppError>) -> Value {
    match result {
        Ok(_) => json!({ "ok": true }),
        Err(error) => {
            let shown = format!("{error:?}");
            let kind = shown.split(|c: char| !c.is_ascii_alphanumeric()).next();
            json!({
                "ok": false,
                "error": kind,
                "code": error.code().map(|code| code.as_str().to_owned()),
            })
        }
    }
}
