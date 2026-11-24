//! A batch an app kept to send again, its answer lost, when the recovery notice comes
//! (Dispatch spec 6.4 "Held for the next generation", 12.6 "The recovery notice"): the app
//! neither sends it again nor drops it while it holds the notice. A notice that clears at
//! the same generation sends it again unchanged, as after `503 unavailable`; a recovery to a
//! later generation carries it as Dispatch spec 12.5 "Kept batches" and 12.6 step 5 "Kept
//! attempts" say.

use pubky_dispatch_client::app::{
    App, AppError, AppEvent, ClaimAttempt, ClaimOp, KeptBatchDrop, KeptBatchStatus,
    ObligationDeadline, ProviderStatus, Refusal,
};
use serde_json::{Value, json};

use crate::trace::Line;

use super::super::enrollment::enroll;
use super::super::join::{app_status, events};
use super::super::messaging::joined;
use super::super::recovery::{RECOVERY_ORIGIN, ended, expect_upload, follow_recovery, upload_of};
use super::super::upload::lose_and_recover;
use super::{Notice, ORIGIN, STEP_MS, expect_notices, serving};
use crate::{FlowResult, World};

/// The notice a withheld account and one restored behind its mark answer with: `behind`,
/// at generation 1, not permanent (Dispatch wire 7.3, Table 1).
const BEHIND: Notice = Notice {
    generation: 1,
    reason: "behind",
    permanent: false,
};

/// How many requests labelled `label` the run sent from line `from` of the trace on.
fn sent_since(world: &World, from: usize, label: &str) -> usize {
    world
        .trace()
        .lines
        .iter()
        .skip(from)
        .filter(|line| line.label == label)
        .count()
}

/// The line just after the first one, from line `from` of the trace on, at which alice's
/// app `name` was answered with the notice: the app holds it from there (Dispatch spec 6.4
/// "Held for the next generation"). `None` when no call of the app met it.
fn after_first_notice(world: &World, from: usize, name: &str) -> Option<usize> {
    let caller = format!("{{alice/{name}}} ");
    world
        .trace()
        .lines
        .iter()
        .enumerate()
        .skip(from)
        .find(|(_, line)| {
            line.label.starts_with(&caller)
                && line.facts.get("status").map(String::as_str) == Some("503")
                && line.facts.get("body.code").map(String::as_str) == Some("text recovery_required")
        })
        .map(|(at, _)| at + 1)
}

/// The facts of `line` under `prefix`: a request's body, or the proofs of its answer. A
/// long string shows by its number among the run's strings, so the same facts are the
/// same bytes.
fn facts_under<'a>(line: &'a Line, prefix: &str) -> Vec<(&'a String, &'a String)> {
    line.facts
        .iter()
        .filter(|(at, _)| at.starts_with(prefix))
        .collect()
}

/// The requests labelled `label` from line `from` of the trace on, with their lines.
fn requests_since(world: &World, from: usize, label: &str) -> Vec<(usize, Line)> {
    world
        .trace()
        .lines
        .into_iter()
        .enumerate()
        .skip(from)
        .filter(|(_, line)| line.label == label)
        .collect()
}

/// The operations a batch request carries, by their `op`.
fn ops_of(line: &Line) -> Vec<&str> {
    line.facts
        .iter()
        .filter(|(at, _)| at.starts_with("request body.ops[") && at.ends_with("].body~.op"))
        .filter_map(|(_, op)| op.strip_prefix("text "))
        .collect()
}

/// What became of a kept batch, for the trace: the variant's name and, for a drop, why.
fn kept_status(status: Option<&KeptBatchStatus>) -> Value {
    match status {
        None => json!(null),
        Some(KeptBatchStatus::Kept { sent_at_ms, .. }) => {
            json!({ "kept": true, "sent": sent_at_ms.is_some() })
        }
        Some(KeptBatchStatus::Applied { .. }) => json!({ "applied": true }),
        Some(KeptBatchStatus::Dropped { reason, .. }) => {
            json!({ "dropped": format!("{reason:?}") })
        }
        Some(other) => json!(format!("{other:?}").split(' ').next()),
    }
}

/// The ID `kept`'s call kept its batch under, or the flow's error.
fn kept_id<T>(kept: &Result<T, AppError>, what: &str) -> Result<[u8; 16], String> {
    kept.as_ref()
        .err()
        .and_then(AppError::kept_batch)
        .ok_or_else(|| format!("{what} ended {}, its batch not kept", ended(kept)))
}

/// `app`, named `name`, reads its feed while the account answers the notice: the read
/// stops, the app holds the notice, and the batch `kept` stays kept. A write the caller asks
/// for meanwhile is refused locally.
async fn read_held(
    world: &World,
    app: &mut App,
    name: &str,
    kept: [u8; 16],
    step: &str,
) -> FlowResult {
    let read = app.receive(None).await;
    let status = app.kept_batch(kept).await?;
    let carol = world.identity("carol")?;
    let calls = world.requests_sent();
    let added = app.keep_peer(&carol.public()).await;
    world.outcome(
        &format!("the {name} read its feed, {step}"),
        &json!({
            "read": ended(&read),
            "stopped": read.as_ref().ok().map(|report| report.stopped),
            "events": read.as_ref().map(|report| events(&report.events)).unwrap_or_default(),
            "notice": app.recovery_required().map(|notice| notice.generation),
            "kept": kept_status(status.as_ref()),
            "added": ended(&added),
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    if !read.as_ref().is_ok_and(|report| report.stopped) {
        return Err(format!("the {name}'s read {step} didn't stop at the notice").into());
    }
    if app.recovery_required().map(|notice| notice.generation) != Some(BEHIND.generation) {
        return Err(format!("the {name} holds no notice {step}").into());
    }
    if !matches!(status, Some(KeptBatchStatus::Kept { .. })) {
        return Err(format!("the {name}'s kept batch is {status:?} {step}").into());
    }
    // No write while the notice holds (Dispatch spec 12.6): refused locally, nothing sent.
    if !matches!(
        added,
        Err(AppError::Refused(Refusal::RecoveryRequired { .. }))
    ) || world.requests_sent() != calls
    {
        return Err(format!("the {name}'s write {step} wasn't refused locally").into());
    }
    Ok(())
}

/// A batch kept, its answer lost, when the account answers the notice; the notice clears
/// at the same generation. alice's wallet keeps bob as a peer, and the Dispatch takes the
/// batch but its answer is lost: the wallet keeps it. The account is then withheld (Dispatch
/// wire 7.3, Table 1, row "None"): the wallet's next read meets the notice at its feed.
/// While it holds the notice the wallet neither sends the batch again nor drops it (Dispatch
/// spec 6.4 "Held for the next generation"; 12.6 "Nothing follows automatically": no notice
/// drops kept bytes): two reads send no write once the first call met the notice, a write
/// the user asks for is refused locally, and the batch stays kept. The account is put back
/// at the same generation. The wallet's next verified success with a head clears the
/// notice (Dispatch spec 12.6), and it sends the kept batch again unchanged, the same body
/// as the try whose answer was lost, as after `503 unavailable`: the Dispatch answers with
/// the original proofs (Dispatch wire 6.4 step 5), the batch is applied, and bob is admitted.
///
/// Calls: `GET /v1/{id}/feed` answered with the notice while a batch is kept; the kept
/// batch again once the notice cleared, answered with its original proofs.
///
/// # Errors
///
/// When a step that should succeed against any Dispatch fails, or the kept batch is sent
/// again or dropped while the notice holds, or doesn't end applied once it clears.
pub async fn notice_kept_batch(world: &World) -> FlowResult {
    const OPS: &str = "{alice/wallet} POST /v1/{alice}/ops";
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    let (_signer, mut wallet) = serving(world).await?;

    world.lose_answer("POST", "/ops");
    let lost = wallet.keep_peer(&bob.public()).await;
    let kept = kept_id(&lost, "the kept peer's write")?;
    world.outcome(
        "the kept peer's batch was answered and the answer lost",
        &json!({
            "ended": ended(&lost),
            "kept": kept_status(wallet.kept_batch(kept).await?.as_ref()),
        }),
    );
    world.advance_ms(STEP_MS);

    world.set_account_missing(ORIGIN, &alice, true).await?;
    let from = world.trace().lines.len();
    for step in ["the account withheld", "the notice held"] {
        read_held(world, &mut wallet, "wallet", kept, step).await?;
    }
    let held = after_first_notice(world, from, "wallet").ok_or("no call met the notice")?;
    if sent_since(world, held, OPS) != 0 {
        return Err("the wallet sent its kept batch again while it held the notice".into());
    }
    expect_notices(world, from, BEHIND, 2)?;

    world.set_account_missing(ORIGIN, &alice, false).await?;
    let from = world.trace().lines.len();
    let followed = wallet.follow_provider().await?;
    let cleared = wallet.take_events();
    world.outcome(
        "the wallet asked its service again, the account back",
        &json!({
            "followed": format!("{followed:?}"),
            "events": events(&cleared),
            "notice": wallet.recovery_required().map(|notice| notice.generation),
            "kept": kept_status(wallet.kept_batch(kept).await?.as_ref()),
        }),
    );
    world.advance_ms(STEP_MS);
    let told = cleared.iter().any(|event| {
        matches!(event, AppEvent::RecoveryNoticeCleared { generation, .. } if *generation == 1)
    });
    if followed != ProviderStatus::Current || wallet.recovery_required().is_some() || !told {
        return Err("the notice didn't clear once the account was back".into());
    }
    let report = wallet.receive(None).await?;
    let status = wallet.kept_batch(kept).await?;
    let admits = wallet.admits(&bob.public()).await?;
    world.outcome(
        "the wallet read its feed, the notice cleared",
        &json!({
            "events": events(&report.events),
            "kept": kept_status(status.as_ref()),
            "admits": admits,
            "app": app_status(&mut wallet),
        }),
    );
    world.advance_ms(STEP_MS);
    // Sent again once, unchanged, and answered with the original proofs: the body and the
    // proofs are those of the try whose answer was lost.
    let resent = requests_since(world, from, OPS);
    let first = requests_since(world, 0, OPS)
        .into_iter()
        .rev()
        .find(|(_, line)| line.facts.contains_key("fault"))
        .ok_or("the lost try isn't in the trace")?;
    let [(_, again)] = resent.as_slice() else {
        return Err(format!("the kept batch went {} times once cleared", resent.len()).into());
    };
    if again.facts.get("status").map(String::as_str) != Some("200") {
        return Err(format!(
            "the kept batch was answered {:?}",
            again.facts.get("status")
        )
        .into());
    }
    for prefix in ["request body", "body.proofs"] {
        if facts_under(again, prefix) != facts_under(&first.1, prefix) {
            return Err(format!("the kept batch's {prefix} differs from its first try").into());
        }
    }
    if !matches!(status, Some(KeptBatchStatus::Applied { .. })) || !admits {
        return Err(format!("the kept batch ended {status:?}, bob admitted {admits}").into());
    }
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// The claim alice's wallet attempts before the loss.
const LOST_CLAIM: [u8; 32] = [0x4d; 32];
/// The attempt on it.
const LOST_ATTEMPT: [u8; 16] = [0x4e; 16];

/// Batches kept when the account answers the notice, and a provider loss declared then.
/// alice's wallet attempts a claim and her phone keeps bob as a peer; the Dispatch takes
/// both batches and both answers are lost, so each app keeps its batch. The account is
/// restored behind its mark (Dispatch wire 7.3, Table 1: `behind`): each app's next read
/// meets the notice, and while it holds it the app neither sends its kept batch nor drops
/// it (Dispatch spec 6.4 "Held for the next generation"). The user declares the loss,
/// and the signer recovers at another service (Dispatch spec 12.6 step 1). Each app follows
/// the recovery, which clears its notice (Dispatch spec 12.6), and carries its kept batch to
/// the new generation:
///
/// - **The attempt** is dropped, never signed again: whether the lost service applied it
///   can't be known (Dispatch spec 12.6 step 5 "Kept attempts"). The wallet raises
///   `KeptBatchDropped` and `AttemptDropped` for its protocol, the batch ends dropped as
///   uncertain, and the wallet's only batch at the new service is its registration.
/// - **The kept peer** is signed again for the new generation under a new batch ID: a resend
///   unchanged decides nothing after a loss (Dispatch spec 12.5 "Kept batches"). The phone
///   raises `KeptBatchSignedAgain`, sends it at the new service once it has uploaded what
///   it holds (Dispatch spec 12.6 step 3), and the batch ends applied there.
///
/// Calls: each app's `GET /v1/{id}/feed` answered with the notice while a batch is kept;
/// the phone's re-signed batch at the new service.
///
/// # Errors
///
/// When a step that should succeed against any Dispatch fails, or a kept batch is sent
/// again or dropped while the notice holds, or isn't carried to the new generation as
/// Dispatch spec 12.6 says.
pub async fn notice_kept_batches_recovered(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;
    wallet.receive(None).await?;

    world.lose_answer("POST", "/ops");
    let lost = wallet
        .write_claim(
            ClaimOp::attempt(LOST_CLAIM, 0, LOST_ATTEMPT, 3_600, None),
            Vec::new(),
            ObligationDeadline::NotKnown,
        )
        .await;
    let attempt = kept_id(&lost, "the wallet's attempt")?;
    world.outcome(
        "the wallet's attempt was answered and the answer lost",
        &json!({ "ended": ended(&lost), "events": events(&wallet.take_events()) }),
    );
    world.advance_ms(STEP_MS);
    world.lose_answer("POST", "/ops");
    let lost = phone.keep_peer(&bob.public()).await;
    let kept_peer = kept_id(&lost, "the phone's kept peer")?;
    world.outcome(
        "the phone's kept peer was answered and the answer lost",
        &json!({ "ended": ended(&lost), "events": events(&phone.take_events()) }),
    );
    world.advance_ms(STEP_MS);

    world.restore_behind_mark(ORIGIN, &alice).await?;
    for (app, name, kept) in [
        (&mut wallet, "wallet", attempt),
        (&mut phone, "phone", kept_peer),
    ] {
        let ops = format!("{{alice/{name}}} POST /v1/{{alice}}/ops");
        let from = world.trace().lines.len();
        for step in ["behind its mark", "the notice held"] {
            read_held(world, app, name, kept, step).await?;
        }
        let held = after_first_notice(world, from, name).ok_or("no call met the notice")?;
        if sent_since(world, held, &ops) != 0 {
            return Err(format!("the {name} sent its kept batch while it held the notice").into());
        }
        expect_notices(world, from, BEHIND, 2)?;
    }

    let lost_try = requests_since(world, 0, "{alice/phone} POST /v1/{alice}/ops")
        .into_iter()
        .rev()
        .find(|(_, line)| line.facts.contains_key("fault"))
        .ok_or("the phone's lost try isn't in the trace")?
        .1;
    let recovered = world.trace().lines.len();
    lose_and_recover(world, &alice, &mut signer).await?;
    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    follow_recovery(world, &mut phone, "phone", 1).await?;
    let raised = |name: &str| {
        let label = format!("outcome the {name} followed the recovery");
        world.trace().lines[recovered..]
            .iter()
            .filter(|line| line.label == label)
            .any(|line| {
                line.facts
                    .values()
                    .any(|v| v == "text KeptBatchSignedAgain")
            })
    };
    if raised("wallet") || !raised("phone") {
        return Err("KeptBatchSignedAgain wasn't raised by the phone alone".into());
    }

    // The wallet: the attempt dropped, and its protocol told.
    let duties = wallet.pending_duty_events().await?;
    let dropped = duties.iter().any(|duty| {
        matches!(
            duty.event,
            AppEvent::KeptBatchDropped { batch_id, .. } if batch_id == attempt
        )
    });
    let attempt_dropped = duties.iter().any(|duty| {
        matches!(
            duty.event,
            AppEvent::AttemptDropped { claim_key, attempt_id, .. }
                if claim_key == LOST_CLAIM && attempt_id == LOST_ATTEMPT
        )
    });
    let notice_cleared = duties.iter().any(|duty| {
        matches!(duty.event, AppEvent::RecoveryNoticeCleared { generation, .. } if generation == 1)
    });
    let status = wallet.kept_batch(attempt).await?;
    let by_attempt = wallet
        .kept_attempt(ClaimAttempt {
            claim_key: LOST_CLAIM,
            attempt_id: LOST_ATTEMPT,
        })
        .await?;
    world.outcome(
        "the wallet carried its kept attempt to the new generation",
        &json!({
            "duties": events(&duties.iter().map(|duty| duty.event.clone()).collect::<Vec<_>>()),
            "kept": kept_status(status.as_ref()),
            "by_attempt": kept_status(by_attempt.as_ref().map(|kept| &kept.status)),
            "notice": wallet.recovery_required().map(|notice| notice.generation),
        }),
    );
    if !dropped || !attempt_dropped || !notice_cleared {
        return Err(format!(
            "the wallet raised batch dropped {dropped}, attempt dropped {attempt_dropped}, \
             notice cleared {notice_cleared}"
        )
        .into());
    }
    if !matches!(
        status,
        Some(KeptBatchStatus::Dropped {
            reason: KeptBatchDrop::Uncertain,
            ..
        })
    ) || wallet.recovery_required().is_some()
    {
        return Err(format!("the wallet's kept attempt ended {status:?}").into());
    }
    // Never signed again for the new generation: the wallet's only batch there is its
    // registration, also after a read.
    let read = wallet.receive(None).await?;
    world.outcome(
        "the wallet read its feed at the new service",
        &json!({ "events": events(&read.events), "app": app_status(&mut wallet) }),
    );
    world.advance_ms(STEP_MS);
    for (_, line) in requests_since(world, recovered, "{alice/wallet} POST /v1/{alice}/ops") {
        if ops_of(&line)
            .iter()
            .any(|op| !matches!(*op, "app.put" | "receive_key.put"))
        {
            return Err(format!("the wallet wrote {:?} at the new service", ops_of(&line)).into());
        }
    }

    // The phone: the kept peer signed again, then sent at the new service.
    let status = phone.kept_batch(kept_peer).await?;
    let report = phone.receive(None).await?;
    let carol = world.identity("carol")?;
    phone.keep_peer(&carol.public()).await?;
    let ended_as = phone.kept_batch(kept_peer).await?;
    let admits = phone.admits(&bob.public()).await?;
    world.outcome(
        "the phone sent its kept peer again at the new service",
        &json!({
            "signed_again": kept_status(status.as_ref()),
            "events": events(&report.events),
            "kept": kept_status(ended_as.as_ref()),
            "admits": admits,
            "notice": phone.recovery_required().map(|notice| notice.generation),
            "app": app_status(&mut phone),
        }),
    );
    let signed_again = matches!(
        status,
        Some(KeptBatchStatus::Kept {
            wire_batch_id,
            sent_at_ms: None,
        }) if wire_batch_id != kept_peer
    );
    // The resend is the batch that keeps bob, at the new generation, under a batch ID
    // other than the lost try's, and after the phone's upload (Dispatch spec 12.6 step 3).
    let batch_id = "request body.ops[0].body~.batch.id";
    let resends: Vec<usize> =
        requests_since(world, recovered, "{alice/phone} POST /v1/{alice}/ops")
            .into_iter()
            .filter(|(_, line)| {
                let fact = |at: &str| line.facts.get(at).map(String::as_str);
                ops_of(line) == ["allow.put"]
                    && fact("request body.ops[0].body~.pubky") == Some("id {bob}")
                    && fact("request body.ops[0].body~.generation") == Some("number 2")
                    && fact("status") == Some("200")
                    && line.facts.get(batch_id) != lost_try.facts.get(batch_id)
            })
            .map(|(at, _)| at)
            .collect();
    let uploaded = requests_since(world, recovered, &upload_of("phone"))
        .iter()
        .filter(|(_, line)| line.facts.get("status").map(String::as_str) == Some("200"))
        .map(|(at, _)| *at)
        .max();
    expect_upload(world, "phone", false)?;
    let at_new = resends.len();
    if !signed_again
        || at_new != 1
        || !uploaded.is_some_and(|upload| resends.iter().all(|at| upload < *at))
        || !matches!(ended_as, Some(KeptBatchStatus::Applied { .. }))
        || !admits
        || phone.recovery_required().is_some()
    {
        return Err(format!(
            "the phone's kept peer was {status:?}, sent {at_new} times at {RECOVERY_ORIGIN}, \
             ended {ended_as:?}, bob admitted {admits}"
        )
        .into());
    }
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}
