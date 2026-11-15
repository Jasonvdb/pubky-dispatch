//! Two protocols on one app (Switch spec 3.2, Switch wire 3.1 "Several protocols"): each
//! message goes to the protocol its kind names, each protocol keeps its own state, and a
//! backup carries one layer per protocol, which a restore puts back apart (Switch spec
//! 12.4).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use pubky_switch_client::app::{App, AppConfig, OutgoingMessage, ProtocolSet};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::{TestIdentity, TestProtocol};
use pubky_switch_signer::Signer;
use serde_json::{Value, json};

use super::enrollment::enroll;
use super::join::{app_status, events};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, CHAT, TASKS, sample_protocol};
use crate::{FlowResult, World};

struct OrderedProtocol {
    inner: Arc<TestProtocol>,
    held: AtomicBool,
    hold_receive: bool,
    deny_changes: AtomicUsize,
}

impl pubky_switch_client::app::Protocol for OrderedProtocol {
    fn name(&self) -> String {
        self.inner.name()
    }
    fn has_keys(&self, scope: &str) -> bool {
        self.inner.has_keys(scope)
    }
    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.inner.sent_between_own_apps(kind)
    }
    fn check_scopes(
        &self,
        message: &pubky_switch_core::message::Message,
        sender: &pubky_switch_core::records::AppCert,
        own: &pubky_switch_core::records::AppCert,
    ) -> Result<(), String> {
        self.inner.check_scopes(message, sender, own)
    }
    fn accepts(&self, cert: &pubky_switch_core::records::AppCert) -> Vec<String> {
        self.inner.accepts(cert)
    }
    fn check_body(
        &self,
        message: &pubky_switch_client::app::ReceivedMessage,
    ) -> Result<(), String> {
        self.inner.check_body(message)
    }
    fn receive(
        &self,
        message: &pubky_switch_client::app::ReceivedMessage,
        cx: &mut pubky_switch_client::app::ReceiveContext<'_>,
    ) -> pubky_switch_client::app::Outcome {
        use pubky_switch_client::app::{Effect, LocalWrite, Outcome, StoreFailure};
        if self.hold_receive && self.held.load(Ordering::Relaxed) {
            return Outcome::Retry(StoreFailure::unavailable(
                pubky_switch_client::error::StoreError::Unavailable,
            ));
        }
        match cx.sender_disposition(&message.sender) {
            Ok(standing) => Outcome::Apply(Effect {
                ops: Vec::new(),
                local: vec![LocalWrite::Put {
                    key: b"blocked".to_vec(),
                    value: vec![u8::from(standing.blocked)],
                }],
            }),
            Err(error) => Outcome::Drop {
                reason: error.to_string(),
            },
        }
    }
    fn resend_needed(
        &self,
        needed: &pubky_switch_client::app::ResendNeeded,
    ) -> Result<Vec<pubky_switch_client::app::LocalWrite>, pubky_switch_client::app::StoreFailure>
    {
        self.inner.resend_needed(needed)
    }
    fn missed(
        &self,
        missed: &pubky_switch_client::app::MissedEntries,
    ) -> Result<Vec<pubky_switch_client::app::LocalWrite>, pubky_switch_client::app::StoreFailure>
    {
        if !self.hold_receive && self.held.load(Ordering::Relaxed) {
            return Err(pubky_switch_client::app::StoreFailure::unavailable(
                pubky_switch_client::error::StoreError::Unavailable,
            ));
        }
        self.inner.missed(missed)
    }

    fn deny_list_changed(
        &self,
        _: &pubky_switch_client::app::DenyListChange,
    ) -> Result<Vec<pubky_switch_client::app::LocalWrite>, pubky_switch_client::app::StoreFailure>
    {
        self.deny_changes.fetch_add(1, Ordering::Relaxed);
        Ok(Vec::new())
    }
}

/// `tasks` and `chat`, in that order.
fn both() -> (Arc<TestProtocol>, Arc<TestProtocol>) {
    (sample_protocol(TASKS), sample_protocol(CHAT))
}

fn set_of(tasks: &Arc<TestProtocol>, chat: &Arc<TestProtocol>) -> Result<ProtocolSet, String> {
    ProtocolSet::new(vec![
        Arc::clone(tasks) as Arc<dyn pubky_switch_client::app::Protocol>,
        Arc::clone(chat) as Arc<dyn pubky_switch_client::app::Protocol>,
    ])
    .map_err(|error| error.to_string())
}

/// `identity`'s app `name`, approved by `signer` for the scopes of `tasks` and `chat` and
/// joined with both.
async fn joined_with_both(
    world: &World,
    identity: &TestIdentity,
    signer: &mut Signer,
    name: &str,
    protocols: ProtocolSet,
) -> Result<App, Box<dyn std::error::Error>> {
    let asking = Asking::for_scopes(world.app_keys(identity, name)?, &[TASKS, CHAT])?;
    let review = signer.review(asking.request.signed(), &asking.auth)?;
    let approved = signer.approve(review).await?;
    signer.claim_delivered(&approved.request).await?;
    world.advance_ms(STEP_MS);
    let mut app = App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        protocols,
        AppConfig::default(),
        asking.join_request(identity.public(), &approved)?,
    )
    .await?;
    app.receive(None).await?;
    world.outcome("joined", &app_status(&mut app));
    world.advance_ms(STEP_MS);
    Ok(app)
}

/// What each protocol of `app` keeps: the kinds under its own key space, in key order.
async fn kept(app: &App) -> Result<Value, Box<dyn std::error::Error>> {
    let mut of = serde_json::Map::new();
    for name in [TASKS, CHAT] {
        let state = app.protocol_scan(name, b"").await?;
        let kinds: Vec<String> = state
            .into_iter()
            .map(|(_, kind)| String::from_utf8_lossy(&kind).into_owned())
            .collect();
        of.insert(name.to_owned(), json!(kinds));
    }
    Ok(Value::Object(of))
}

/// alice's wallet and bob's shop each run `tasks` and `chat` on one app. alice admits bob,
/// whose shop sends her messages of both protocols, interleaved; the wallet reads them in
/// one read, each handed to the protocol its kind names, which keeps it under its own key
/// space. A layered backup carries one layer per protocol; the wallet restored from it on
/// a new device puts each layer back under its own protocol, and reads on.
///
/// Calls, beyond the join's and the messaging flow's: none of their own; `POST
/// /v1/{id}/inbox` of two protocols' kinds to one app, and `GET /v1/{id}/feed` with them.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn two_protocols(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let (tasks, chat) = both();
    let mut wallet = joined_with_both(
        world,
        &alice,
        &mut alice_signer,
        "wallet",
        set_of(&tasks, &chat)?,
    )
    .await?;
    let (shop_tasks, shop_chat) = both();
    let mut shop = joined_with_both(
        world,
        &bob,
        &mut bob_signer,
        "shop",
        set_of(&shop_tasks, &shop_chat)?,
    )
    .await?;
    let record = pubky_switch_core::records::AppRecord::verify(wallet.record(), &alice.public())?;
    world.outcome("the wallet's record accepts", &json!(record.body().accepts));

    wallet.add_contact(&bob.public()).await?;
    world.outcome("contact saved", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);

    // Interleaved: each protocol's messages between the other's.
    for (n, kind) in [TASKS, CHAT, TASKS, CHAT].iter().enumerate() {
        let mut body = serde_json::Map::new();
        body.insert("n".into(), json!(n));
        let (_, delivery) = shop
            .send(OutgoingMessage::new(
                alice.public(),
                &format!("{kind}.item"),
                body,
            ))
            .await?;
        world.outcome(
            &format!("sent {kind}.item"),
            &json!({ "delivery": format!("{delivery:?}").split(' ').next() }),
        );
        world.advance_ms(STEP_MS);
    }

    let report = wallet.receive(None).await?;
    wallet.flush_cursor().await?;
    let before = kept(&wallet).await?;
    let kinds = |protocol: &TestProtocol| -> Vec<String> {
        protocol
            .received()
            .iter()
            .map(|message| message.message.kind.clone())
            .collect()
    };
    world.outcome(
        "received",
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "tasks": kinds(&tasks),
            "chat": kinds(&chat),
            "kept": before,
            "app": app_status(&mut wallet),
        }),
    );
    world.advance_ms(STEP_MS);
    // Each message went to its own protocol, which keeps it under its own key space.
    let items = |kind: &str| vec![format!("{kind}.item"); 2];
    if kinds(&tasks) != items(TASKS)
        || kinds(&chat) != items(CHAT)
        || before != json!({ TASKS: items(TASKS), CHAT: items(CHAT) })
    {
        return Err("each protocol takes and keeps its own messages alone".into());
    }

    let backup = wallet.backup_layered().await?;
    let layers: Vec<String> = backup
        .layers()?
        .iter()
        .map(|layer| layer.protocol.clone())
        .collect();
    world.outcome("backed up", &json!({ "layers": layers }));
    world.advance_ms(STEP_MS);
    // The device is lost.
    drop(wallet);

    let (tasks, chat) = both();
    let mut restored = App::restore(
        world.app_env(Arc::new(MemoryStore::new())),
        set_of(&tasks, &chat)?,
        AppConfig::default(),
        &backup,
    )
    .await?;
    let after = kept(&restored).await?;
    world.outcome(
        "restored",
        &json!({
            "kept": after,
            "app": app_status(&mut restored),
        }),
    );
    if after != before {
        return Err("the restore puts each layer back under its own protocol".into());
    }
    world.advance_ms(STEP_MS);

    // A message of each protocol after the restore goes to its own protocol, once.
    for kind in [CHAT, TASKS] {
        shop.send(OutgoingMessage::new(
            alice.public(),
            &format!("{kind}.item"),
            serde_json::Map::new(),
        ))
        .await?;
        world.advance_ms(STEP_MS);
    }
    let report = restored.receive(None).await?;
    world.outcome(
        "the restored wallet read on",
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "tasks": kinds(&tasks),
            "chat": kinds(&chat),
            "kept": kept(&restored).await?,
        }),
    );
    if kinds(&tasks) != [format!("{TASKS}.item")] || kinds(&chat) != [format!("{CHAT}.item")] {
        return Err("each protocol takes its own message after the restore, once".into());
    }
    Ok(())
}

/// A deny change waits while either protocol still holds an earlier message. Both
/// messages observe the sender's standing before the change (Switch spec 8.3).
///
/// # Errors
///
/// When an earlier message sees the later deny, or an ordinary operation fails.
pub async fn protocol_deny_barrier(world: &World) -> FlowResult {
    ordered_deny(world, false).await
}

/// An entry already handed to a protocol may be retried after a later deny change,
/// observing the current deny copy on that retry (Switch spec 8.2, 8.3).
///
/// # Errors
///
/// When a retry observes the earlier copy, or an ordinary operation fails.
pub async fn protocol_retry_after_deny(world: &World) -> FlowResult {
    ordered_deny(world, true).await
}

async fn ordered_deny(world: &World, retry: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    let limits = pubky_switch::limits::Limits {
        quota_bytes: if retry { 64 * 1024 * 1024 } else { 8 * 1024 },
        sender_share_percent: 100,
        ..pubky_switch::limits::Limits::default()
    };
    world
        .add_switch_with(ORIGIN, &[&alice, &bob], limits)
        .await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let tasks = Arc::new(OrderedProtocol {
        inner: sample_protocol(TASKS),
        held: AtomicBool::new(true),
        hold_receive: retry,
        deny_changes: AtomicUsize::new(0),
    });
    let chat = Arc::new(OrderedProtocol {
        inner: sample_protocol(CHAT),
        held: AtomicBool::new(false),
        hold_receive: retry,
        deny_changes: AtomicUsize::new(0),
    });
    let protocols = ProtocolSet::new(vec![tasks.clone(), chat.clone()])?;
    let mut wallet =
        joined_with_both(world, &alice, &mut alice_signer, "wallet", protocols).await?;
    let (manager_tasks, manager_chat) = both();
    let mut manager = joined_with_both(
        world,
        &alice,
        &mut alice_signer,
        "manager",
        set_of(&manager_tasks, &manager_chat)?,
    )
    .await?;
    let (shop_tasks, shop_chat) = both();
    let mut shop = joined_with_both(
        world,
        &bob,
        &mut bob_signer,
        "shop",
        set_of(&shop_tasks, &shop_chat)?,
    )
    .await?;
    wallet.add_contact(&bob.public()).await?;
    wallet.receive(None).await?;
    if !retry {
        for _ in 0..8 {
            let mut body = serde_json::Map::new();
            body.insert("text".into(), json!("x".repeat(1000)));
            shop.send(OutgoingMessage::new(
                alice.public(),
                &format!("{CHAT}.item"),
                body,
            ))
            .await?;
            manager.receive(None).await?;
            manager.flush_cursor().await?;
            world.advance_ms(STEP_MS);
        }
        wallet.receive(None).await?;
        if wallet.owed_protocol_calls().await? == 0 {
            return Err("inbox pressure did not leave the missed callback owed".into());
        }
    }
    for name in [TASKS, CHAT] {
        shop.send(OutgoingMessage::new(
            alice.public(),
            &format!("{name}.item"),
            serde_json::Map::new(),
        ))
        .await?;
        world.advance_ms(STEP_MS);
    }
    manager.deny(&bob.public()).await?;
    wallet.receive(None).await?;
    if chat.deny_changes.load(Ordering::Relaxed) != usize::from(retry) {
        return Err("a deny callback crossed the first-delivery barrier".into());
    }
    if wallet.protocol_get(TASKS, b"blocked").await?.is_some()
        || wallet.protocol_get(CHAT, b"blocked").await? != Some(vec![0])
    {
        return Err("the ready protocol did not take its earlier message".into());
    }
    tasks.held.store(false, Ordering::Relaxed);
    wallet.receive(None).await?;
    if tasks.deny_changes.load(Ordering::Relaxed) != 1
        || chat.deny_changes.load(Ordering::Relaxed) != 1
    {
        return Err("the deny change was not handed once to each protocol".into());
    }
    for name in [TASKS, CHAT] {
        let expected = u8::from(retry && name == TASKS);
        if wallet.protocol_get(name, b"blocked").await? != Some(vec![expected]) {
            return Err("a protocol observed the wrong deny copy".into());
        }
    }
    world.outcome(
        "the protocols observed the deny copy",
        &json!({"tasks_blocked": retry, "chat_blocked": false}),
    );
    Ok(())
}
