//! The account's erasure, when the user stops using the Dispatch (Dispatch spec 12.7, Dispatch
//! wire 7.4.16).

use std::sync::Arc;

use pubky_dispatch_client::app::{App, AppEvent};
use pubky_dispatch_client::store::MemoryStore;
use pubky_dispatch_signer::{Signer, SignerStatus, UserConfirmed};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::recovery::{expect_staged, expect_upload, follow_recovery};
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// Where the signer stands in an erasure in doubt, for the trace: how its run ended, its
/// state, since when it holds the account as erased but unconfirmed, as far into the flow
/// as the world's clock was then, and whether its `identity.json` is on the Homeserver.
fn in_doubt<T, E: std::fmt::Debug>(
    world: &World,
    started_ms: u64,
    signer: &Signer,
    run: &Result<T, E>,
    identity: &[u8; 32],
) -> Result<Value, Box<dyn std::error::Error>> {
    let unconfirmed_since = match signer.status() {
        SignerStatus::ErasedUnconfirmed { since_ms } => Some(since_ms.saturating_sub(started_ms)),
        _ => None,
    };
    Ok(json!({
        "ended": ended(run),
        "signer": status(signer)?,
        "unconfirmed_since_ms_into_the_flow": unconfirmed_since,
        "published": world.files().identity_doc(identity).is_some(),
    }))
}

/// Fail the flow when the signer doesn't stand where the step says: the steps of the wait
/// are named for what the signer holds at each, on either Dispatch.
fn standing(signer: &Signer, expected: &str, holds: bool) -> FlowResult {
    if holds {
        Ok(())
    } else {
        Err(format!("the signer is {:?}, not {expected}", signer.status()).into())
    }
}

/// How a call ended, for the trace: nothing of an error but its kinds.
fn ended<T, E: std::fmt::Debug>(result: &Result<T, E>) -> Value {
    match result {
        Ok(_) => json!({ "ok": true }),
        Err(error) => {
            let shown = super::recovery::shown_without_messages(error);
            let kinds: Vec<&str> = shown
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| word.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
                .take(4)
                .collect();
            json!({ "ok": false, "error": kinds.join(" ") })
        }
    }
}

/// One read of an app whose account was erased, for the trace: how it ended, the events it
/// raised, where the app stands with its service, and whether the identity's
/// `identity.json` is on the Homeserver. Returns whether the read raised `AccountGone`.
async fn read_once_erased(
    world: &World,
    name: &str,
    app: &mut App,
    identity: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error>> {
    let read = app.receive(None).await;
    let (stopped, raised) = match &read {
        Ok(report) => (Some(report.stopped), report.events.clone()),
        Err(_) => (None, app.take_events()),
    };
    // Where the app stands with its service, asked apart from the read, with the events
    // the asking itself raised.
    let provider = app.follow_provider().await;
    let provider_events = app.take_events();
    world.outcome(
        name,
        &json!({
            "ended": ended(&read),
            "stopped": stopped,
            "events": events(&raised),
            "provider": match &provider {
                Ok(status) => ended_word(&format!("{status:?}")),
                Err(error) => ended_word(&format!("{error:?}")),
            },
            "provider_events": events(&provider_events),
            "app": app_status(app),
            "published": world.files().identity_doc(identity).is_some(),
        }),
    );
    Ok(raised
        .iter()
        .any(|event| matches!(event, AppEvent::AccountGone { .. })))
}

/// The first word of a `Debug` text: a status's or an error's name.
fn ended_word(shown: &str) -> String {
    shown
        .split(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Fail the flow when a read of the app's wait raised `AccountGone` or not, against what
/// the step says.
fn gone(raised: bool, expected: bool, step: &str) -> FlowResult {
    if raised == expected {
        Ok(())
    } else if expected {
        Err(format!("{step}: the app didn't take its account as gone").into())
    } else {
        Err(format!("{step}: the app took its account as gone already").into())
    }
}

/// What the world shows of the identity once its signer closed the account: the signer's
/// own state, whether its `identity.json` is still on the Homeserver, what anyone reading
/// the public `identity.json` from the Dispatch gets, an app's next reads, and the signer's
/// next run.
///
/// The app's next read meets the service's `404` saying that it doesn't host the identity,
/// signed with the service key the app pinned and bound to its own request, and a missing
/// `identity.json`: "Both together are an erasure, at once" (Dispatch spec 12.7 step 5,
/// Dispatch wire 7.4.16 Afterwards), so that read raises `AccountGone`. The flow deletes
/// nothing itself: the file is missing because the signer's erasure took it off the
/// Homeserver. A read after that asks the Dispatch nothing.
async fn afterwards(
    world: &World,
    name: &str,
    signer: &mut Signer,
    app: &mut App,
    public_path: &str,
    identity: &[u8; 32],
) -> FlowResult {
    world.outcome(
        &format!("{name}: the signer"),
        &json!({
            "signer": status(signer)?,
            "published": world.files().identity_doc(identity).is_some(),
        }),
    );
    let public = world.request("GET", ORIGIN, public_path).await?;
    world.outcome(
        &format!("{name}: the public read"),
        &json!({ "status": public.status }),
    );

    let step = format!("{name}: an app's next read, the account is gone");
    let raised = read_once_erased(world, &step, app, identity).await?;
    gone(raised, true, &step)?;
    world.advance_ms(STEP_MS);
    let step = format!("{name}: the app's read once the account is gone");
    read_once_erased(world, &step, app, identity).await?;

    world.advance_ms(STEP_MS);
    let again = signer.resume().await;
    world.outcome(
        &format!("{name}: the signer's next run"),
        &json!({ "ended": ended(&again), "signer": status(signer)? }),
    );
    Ok(())
}

/// The signer closes the identity's account: `identity.json` leaves the Homeserver, the
/// Dispatch erases the account, and every later call is answered by the not-hosted `404`,
/// signed with the service key.
///
/// An app of the identity takes the account as gone at its next read (Dispatch spec 12.7
/// step 5).
///
/// Calls: `POST /v1/{id}/erase` (`200`), then the public `GET /v1/{id}/identity` and an
/// own app's `GET /v1/{id}/feed`, each answered `404` with the service key. The signer,
/// holding the account as erased, sends nothing at its next run, nor does the app once it
/// took the account as gone.
///
/// # Errors
///
/// When a step that should succeed against any Dispatch fails.
pub async fn erasure(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let public_path = format!("/v1/{}/identity", alice.key().id());

    let closed = signer
        .close_account(UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome("the account was closed", &ended(&closed));
    world.advance_ms(STEP_MS);
    afterwards(
        world,
        "after the erasure",
        &mut signer,
        &mut wallet,
        &public_path,
        &alice.public(),
    )
    .await
}

/// The erasure's answer is lost: the signer's call fails with the erasure in doubt. Its
/// next run meets the not-hosted `404` its pinned key signed, which "confirms the erasure at
/// once" (Dispatch wire 7.4.16 "The signer's `404`", Dispatch spec 12.7 step 5): the account is
/// erased, and the erasure is never sent again. An app of the identity then takes the
/// account as gone, as in [`erasure`].
///
/// Calls: `POST /v1/{id}/erase` with its answer lost; then the signer's read at its next
/// run, answered `404` with the service key; then the calls of [`erasure`] after its
/// `200`.
///
/// # Errors
///
/// When a step that should succeed against any Dispatch fails.
pub async fn erasure_answer_lost(world: &World) -> FlowResult {
    let started_ms = world.now_ms();
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let public_path = format!("/v1/{}/identity", alice.key().id());

    world.lose_answer("POST", "/erase");
    let lost = signer
        .close_account(UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the erasure's answer was lost",
        &in_doubt(world, started_ms, &signer, &lost, &alice.public())?,
    );
    standing(
        &signer,
        "erasing",
        matches!(signer.status(), SignerStatus::Erasing),
    )?;
    world.advance_ms(STEP_MS);
    let first = signer.resume().await;
    world.outcome(
        "the signer's next run meets the signed 404: erased",
        &in_doubt(world, started_ms, &signer, &first, &alice.public())?,
    );
    standing(
        &signer,
        "erased",
        matches!(signer.status(), SignerStatus::Erased),
    )?;
    world.advance_ms(STEP_MS);
    afterwards(
        world,
        "after the erasure",
        &mut signer,
        &mut wallet,
        &public_path,
        &alice.public(),
    )
    .await?;
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// An erased account enrolled again at the same origin (Dispatch spec 12.7 step 4, Dispatch
/// wire 7.4.16, 7.4.1). alice's signer closes her account, and the service deletes
/// everything it held for her, her account's mark too. Her signer then declares the loss at
/// the same origin. The service knows no account for her, so the enrollment makes a new one
/// with a new (0, 0) mark, under the service's one key, the erased account's too. The
/// account starts as after a provider loss: its first document is the next generation's,
/// at a higher version, naming the erased one as lost. Her wallet follows the recovery
/// there, and the signer signs on.
///
/// Calls: `POST /v1/enroll` and `PUT /v1/{id}/identity` at an origin whose account was
/// erased, and what follows a recovery there.
///
/// # Errors
///
/// When a step that should succeed against any Dispatch fails, the new account answers
/// under another key than the Dispatch's one key, or doesn't start at the next generation.
pub async fn erasure_enrolled_again(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let before = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;
    let first_key = world.last_answer("{alice} GET /v1/{alice}/apps");

    let closed = signer
        .close_account(UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome("the account was closed", &ended(&closed));
    if closed.is_err() || signer.status() != SignerStatus::Erased {
        return Err(format!(
            "the account wasn't erased: the signer is {:?}",
            signer.status()
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    let doc = signer
        .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer enrolled again at the same origin",
        &json!({
            "generation": doc.generation(),
            "recovery_from": doc.body().recovery_from,
            "version_steps": doc.version() - before.version(),
            "signer": status(&signer)?,
        }),
    );
    // The Dispatch's one key signs for the new account, as it did for the erased one
    // (Dispatch wire 7.1).
    // An answer the trace names no key for counts as none.
    let named =
        |answer: Option<[String; 3]>| answer.map(|[_, _, key]| key).filter(|key| !key.is_empty());
    let key_of = |label: &str| named(world.last_answer(label));
    let enrolled_under = key_of("{alice} POST /v1/enroll");
    let delivered_under = key_of("{alice} PUT /v1/{alice}/identity");
    let erased_key = named(first_key);
    if doc.generation() != before.generation() + 1
        || doc.body().recovery_from != Some(before.generation())
        || doc.version() <= before.version()
        || delivered_under.as_deref() != Some("service key number 1")
        || enrolled_under.is_none()
        || enrolled_under != erased_key
    {
        return Err(format!(
            "the new account starts at generation {} from {:?}, its enrollment answered \
             under {enrolled_under:?} and its document under {delivered_under:?}; the erased \
             account signed with {erased_key:?}",
            doc.generation(),
            doc.body().recovery_from
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    // The wallet follows the recovery there; its upload, with no kept peer to bring, ends
    // the staged admission.
    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_upload(world, "wallet", false)?;
    signer.run_due().await?;
    world.outcome("the signer ran what is due", &status(&signer)?);
    expect_staged(world, false)?;
    world.advance_ms(STEP_MS);
    let next = signer.set_record_max_age(Some(60)).await?;
    world.outcome(
        "the signer signed on",
        &json!({ "version_steps": next.version() - doc.version(), "signer": status(&signer)? }),
    );
    Ok(())
}

/// A signed unavailable answer preserves the erasure in progress. Reads expose only
/// established outcomes; an unknown attempt is resolved by the signer's exact retry.
///
/// # Errors
///
/// When a retained outcome is misreported or the authorized retry cannot finish.
pub async fn erasure_outcome(
    world: &World,
    outcome: pubky_dispatch_client::testing::ErasureOutcome,
) -> FlowResult {
    Box::pin(erasure_outcome_after_reply(world, outcome, false)).await
}

/// An unavailable erasure answer is lost, then the signer restarts and retries.
///
/// # Errors
///
/// When the unresolved outcome or its exact retry is misreported.
pub async fn erasure_outcome_answer_lost(
    world: &World,
    outcome: pubky_dispatch_client::testing::ErasureOutcome,
) -> FlowResult {
    Box::pin(erasure_outcome_after_reply(world, outcome, true)).await
}

async fn erasure_outcome_after_reply(
    world: &World,
    outcome: pubky_dispatch_client::testing::ErasureOutcome,
    lose_reply: bool,
) -> FlowResult {
    use pubky_dispatch_client::testing::ErasureOutcome;
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, store.clone())?;
    let mut signer = Box::pin(Signer::create(env, world.keyring(&alice)?, ORIGIN)).await?;
    Box::pin(signer.resume()).await?;
    world.advance_ms(STEP_MS);
    let (_wallet, _) = Box::pin(joined(world, &alice, &mut signer, "wallet")).await?;
    world.fail_next_erasure(ORIGIN, &alice, outcome).await?;
    if lose_reply {
        world.lose_answer("POST", "/erase");
    }
    let first = Box::pin(signer.close_account(UserConfirmed::shown_and_confirmed())).await;
    if first.is_ok() {
        return Err("an unfinished erasure answered success".into());
    }
    world.outcome("the erasure is unavailable", &ended(&first));
    let read = world
        .request("GET", ORIGIN, &format!("/v1/{}/identity", alice.key().id()))
        .await?;
    let expected = match outcome {
        ErasureOutcome::Unresolved | ErasureOutcome::UnresolvedAbsent => 503,
        ErasureOutcome::Committed => 404,
        ErasureOutcome::Rejected => 200,
    };
    if read.status != expected {
        return Err(format!(
            "pending erasure read: {} instead of {expected}",
            read.status
        )
        .into());
    }
    if expected != 200
        && read
            .header(pubky_dispatch_core::http::header::HEAD)
            .is_some()
    {
        return Err("an unresolved or erased account carried a head".into());
    }
    world.outcome(
        "the retained outcome was read",
        &json!({"status": read.status}),
    );
    // The pending operation must survive reopening the same durable signer state.
    drop(signer);
    let mut signer = Signer::open(world.signer_env(&alice, store)?, world.keyring(&alice)?).await?;
    world.advance_ms(STEP_MS);
    let resumed = Box::pin(signer.resume()).await;
    world.outcome("the signer resumed the erasure", &ended(&resumed));
    resumed?;
    standing(
        &signer,
        "erased",
        matches!(signer.status(), SignerStatus::Erased),
    )?;
    Ok(())
}

/// An unrelated unavailable read grants no authority to unpublish or erase.
///
/// # Errors
///
/// When the signer deletes state without first establishing ownership.
pub async fn erasure_unavailable_before_authorization(world: &World) -> FlowResult {
    use pubky_dispatch_client::{Credentials, DispatchClient};
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let created = world.now_ms();
    let mut signer = Box::pin(enroll(world, &alice, ORIGIN)).await?;
    let (_wallet, _) = Box::pin(joined(world, &alice, &mut signer, "wallet")).await?;
    let published = world.files().identity_doc(&alice.public());
    let doc = signer
        .identity_doc()?
        .ok_or("the signer holds its document")?;
    let client = DispatchClient::new(
        ORIGIN,
        alice.public(),
        Credentials::Signer {
            identity: alice.public(),
            key: Arc::new(pubky_dispatch_core::keys::IdentityKey::from_secret(
                alice.key().secret_bytes(),
            )),
        },
        Some(doc.inbox().service_key),
        world.transport(),
        world.clock().clone(),
    )?;
    // A request outside this signer's flow left uncertainty. It does not authorize
    // this signer to delete Homeserver records or acquire an erasure intent from a 503.
    world
        .fail_next_erasure(
            ORIGIN,
            &alice,
            pubky_dispatch_client::testing::ErasureOutcome::Unresolved,
        )
        .await?;
    let client = client.with_account_created(created)?;
    let first = client.erase(Some(created), Some(doc.hash())).await;
    if !matches!(
        first,
        Err(pubky_dispatch_client::ClientError::Dispatch {
            status: 503,
            code: pubky_dispatch_core::http::ErrorCode::Unavailable,
            ..
        })
    ) {
        return Err(
            format!("the external attempt did not leave an unresolved erasure: {first:?}").into(),
        );
    }
    let result = Box::pin(signer.close_account(UserConfirmed::shown_and_confirmed())).await;
    world.outcome("unavailable before authorization", &ended(&result));
    if result.is_ok()
        || !matches!(signer.status(), SignerStatus::Signing)
        || published != world.files().identity_doc(&alice.public())
    {
        return Err("an unavailable ownership read authorized erasure".into());
    }
    // The authorizing caller can repeat its exact request; the local signer still
    // holds no unanswered erasure and takes the resulting 404 only as not hosted.
    client.erase(Some(created), Some(doc.hash())).await?;
    let result = Box::pin(signer.close_account(UserConfirmed::shown_and_confirmed())).await;
    if result.is_ok()
        || !matches!(signer.status(), SignerStatus::Signing)
        || published != world.files().identity_doc(&alice.public())
    {
        return Err("another caller's completed erasure authorized local deletion".into());
    }
    Ok(())
}
