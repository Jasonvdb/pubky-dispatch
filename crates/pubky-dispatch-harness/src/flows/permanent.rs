//! Permanent records (Dispatch spec 10.3.1, Dispatch wire 6.2 "Permanent policies"): records of
//! `tasks` under a permanent policy, which no app deletes and no create at version 0
//! replaces, and one whose policy names a generation, deleted once the account is past it.

use pubky_dispatch_client::app::{App, AppError, OpBatch, RecordRead, RecordTarget, Refusal};
use pubky_dispatch_client::testing::TestIdentity;
use pubky_dispatch_signer::Signer;
use serde_json::json;

use super::enrollment::enroll;
use super::join::events;
use super::messaging::joined_as;
use super::records::{look, shown};
use super::recovery::{RECOVERY_ORIGIN, ended, expect_answer, follow_recovery};
use super::upload::{client_of, lose_and_recover};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, TASKS, share_counts, task_closures, tasks_protocol_with_permanent};
use crate::{FlowResult, World};

/// The label of the wallet's batches in the trace.
const WALLET_OPS: &str = "{alice/wallet} POST /v1/{alice}/ops";

/// alice's wallet and phone run `tasks` with two permanent collections. The wallet closes a
/// task: it creates the task's record and changes it. It can't delete it: it refuses the
/// delete itself, and the Dispatch refuses the same delete signed and sent as no app would,
/// `400 bad_request`. The create it made first, sent again over the live record, is `409
/// conflict`. It creates generation 1's share count, which it can't delete in generation 1.
///
/// The service is lost and alice recovers at another: generation 2, `recovery_from` 1. Both
/// apps upload what they hold, and the wallet reads both records there. The task's record still can't be deleted, by the app or by a
/// delete sent as no app would. The share count, of a generation the account is past, is
/// deleted; a create of another share count of generation 1 is refused, locally and by the
/// Dispatch. The phone reads the task's record at the new Dispatch, which then loses it: the
/// phone's next read meets a `404` for a record it saw live in this generation, and raises
/// the rollback alarm.
///
/// Calls: `POST /v1/{id}/ops` with `record.put` at permanent policies (a create, an update,
/// a delete and a create in another generation refused, `400`, a create over a live record,
/// `409`, a delete in a later generation taken); `POST /v1/{id}/recovery/upload` with
/// permanent records; `GET /v1/{id}/records/{key}` of a permanent record, live and lost.
///
/// # Errors
///
/// When a step that should succeed against any Dispatch fails, a refusal the rule gives
/// doesn't come, or the phone doesn't raise the alarm.
pub async fn permanent_records(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let asking = |name: &str| -> Result<Asking, crate::HarnessError> {
        Asking::for_scope(world.app_keys(&alice, name)?, TASKS)
    };
    let (mut wallet, _) = joined_as(
        world,
        &alice,
        &mut signer,
        asking("wallet")?,
        tasks_protocol_with_permanent(),
    )
    .await?;
    let (mut phone, _) = joined_as(
        world,
        &alice,
        &mut signer,
        asking("phone")?,
        tasks_protocol_with_permanent(),
    )
    .await?;

    let closure = RecordTarget::new(task_closures(), b"task 1");
    let count = RecordTarget::new(share_counts(), b"generation 1");
    let closed = br#"{"closed_by":"wallet"}"#;
    // The create, kept to be sent again once the record is live.
    let create = wallet.record_op(&closure, Some(closed), Vec::new()).await?;
    let written = wallet.put_record(&closure, closed, Vec::new()).await?;
    world.outcome("the wallet closed a task", &shown(Some(&written)));
    world.advance_ms(STEP_MS);
    let changed = wallet
        .put_record(
            &closure,
            br#"{"closed_by":"wallet","note":"done"}"#,
            Vec::new(),
        )
        .await?;
    world.outcome("the wallet changed the closed task", &shown(Some(&changed)));
    world.advance_ms(STEP_MS);
    refused_here(world, &mut wallet, &closure, None, "the closed task").await?;
    refused_there(
        world,
        &alice,
        &signer,
        &mut wallet,
        &closure,
        None,
        "a delete of it",
    )
    .await?;
    let again = wallet.submit_batch(OpBatch::new().entry(create)).await;
    world.outcome(
        "the wallet's first create, sent again over the live record",
        &ended(&again),
    );
    world.advance_ms(STEP_MS);
    expect_answer(world, WALLET_OPS, 409, "conflict")?;

    let counted = wallet
        .put_record(&count, br#"{"shares":1}"#, Vec::new())
        .await?;
    world.outcome(
        "the wallet counted generation 1's shares",
        &shown(Some(&counted)),
    );
    world.advance_ms(STEP_MS);
    refused_here(
        world,
        &mut wallet,
        &count,
        None,
        "generation 1's count, in it",
    )
    .await?;
    look(world, &mut phone, "the phone followed both records").await?;

    lose_and_recover(world, &alice, &mut signer).await?;
    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    follow_recovery(world, &mut phone, "phone", 1).await?;
    // A write over a record taken from a recovery upload names that upload with
    // `record_current` (Dispatch spec 10.3): the wallet reads both records at the new Dispatch,
    // so its writes there name the uploads and reach the permanent rule.
    for (target, what) in [
        (&closure, "the closed task"),
        (&count, "generation 1's count"),
    ] {
        let read = wallet.read_record_fresh(target).await?;
        let RecordRead::Fresh(record) = &read else {
            return Err(format!("the wallet doesn't read {what} fresh: {read:?}").into());
        };
        world.outcome(
            &format!("the wallet read {what} at the new Dispatch"),
            &shown(Some(record)),
        );
        world.advance_ms(STEP_MS);
    }

    refused_here(
        world,
        &mut wallet,
        &closure,
        None,
        "the closed task, after the loss",
    )
    .await?;
    refused_there(
        world,
        &alice,
        &signer,
        &mut wallet,
        &closure,
        None,
        "a delete of it after the loss",
    )
    .await?;
    let deleted = wallet.delete_record(&count, Vec::new()).await?;
    world.outcome(
        "the wallet deleted generation 1's count in generation 2",
        &shown(Some(&deleted)),
    );
    world.advance_ms(STEP_MS);
    let other = RecordTarget::new(share_counts(), b"generation 1, again");
    let value: &[u8] = br#"{"shares":2}"#;
    refused_here(
        world,
        &mut wallet,
        &other,
        Some(value),
        "a generation 1 count",
    )
    .await?;
    refused_there(
        world,
        &alice,
        &signer,
        &mut wallet,
        &other,
        Some(value),
        "a create of it in generation 2",
    )
    .await?;

    // The phone sees the task's record live in generation 2; the new Dispatch then loses it.
    let fresh = phone.read_record_fresh(&closure).await?;
    let RecordRead::Fresh(record) = &fresh else {
        return Err(format!("the phone doesn't read the closed task fresh: {fresh:?}").into());
    };
    world.outcome(
        "the phone read the closed task at the new Dispatch",
        &shown(Some(record)),
    );
    world.advance_ms(STEP_MS);
    let key = phone.record_key(&closure)?;
    world.drop_record(RECOVERY_ORIGIN, &alice, &key).await?;
    let read = phone.read_record_fresh(&closure).await;
    let alarm = phone.alarm().map(ToString::to_string);
    world.outcome(
        "the phone read the closed task the Dispatch lost",
        &json!({
            "read": ended(&read),
            "alarm": alarm,
            "events": events(&phone.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    if alarm.is_none() {
        return Err("the phone raised no alarm for a permanent record gone".into());
    }
    Ok(())
}

/// `app` refuses to write `value` at `target`, a delete for `None`, itself: the rule of the
/// permanent policy forbids it in the generation it follows. Fails the flow unless it does.
async fn refused_here(
    world: &World,
    app: &mut App,
    target: &RecordTarget,
    value: Option<&[u8]>,
    what: &str,
) -> FlowResult {
    let written = match value {
        Some(value) => app.put_record(target, value, Vec::new()).await,
        None => app.delete_record(target, Vec::new()).await,
    };
    world.outcome(
        &format!("the wallet refused {what} itself"),
        &ended(&written),
    );
    world.advance_ms(STEP_MS);
    // Refused by the app itself, so nothing reached the Dispatch.
    if !matches!(written, Err(AppError::Refused(Refusal::Usage(_)))) {
        return Err(format!("the wallet didn't refuse {what} itself: {written:?}").into());
    }
    Ok(())
}

/// The wallet's write of `value` at `target`, a delete for `None`, built as its own write
/// would be, then signed for the generation alice's newest document names and sent as no
/// app would: `record_op` builds the write without the refusal the app makes when a batch
/// is submitted. The Dispatch must answer `400 bad_request`.
async fn refused_there(
    world: &World,
    alice: &TestIdentity,
    signer: &Signer,
    wallet: &mut App,
    target: &RecordTarget,
    value: Option<&[u8]>,
    what: &str,
) -> FlowResult {
    let entry = wallet.record_op(target, value, Vec::new()).await?;
    let doc = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;
    let client = client_of(
        world,
        alice,
        "wallet",
        wallet,
        &doc.inbox().url,
        doc.inbox().service_key,
    )?;
    let batch = client.sign_batch(doc.generation(), vec![entry], None)?;
    let answered = client.submit(&batch).await;
    world.outcome(
        &format!("the Dispatch's answer to {what}"),
        &ended(&answered),
    );
    world.advance_ms(STEP_MS);
    expect_answer(world, WALLET_OPS, 400, "bad_request")
}
