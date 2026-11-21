//! The order each protocol is told things in (Switch spec 8.3), checked against a model.
//!
//! A seeded generator shows two or three protocols every kind of feed item, in any order,
//! with pages of any size, reads that stop on their pages, each protocol failing and
//! taking again each kind of call at any point, and the app dropped and loaded again from
//! its store at any point. The check is the rule itself: what a protocol took is, at every
//! moment, the first items the feed holds for it, in feed order, each once; a call it
//! fails is the next of them; and once every protocol takes its calls and the reads are
//! quiet, it is all of them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use pubky_switch_core::envelope::Recipient;
use pubky_switch_core::ident::Policy;
use pubky_switch_core::keys::ReceiveKey;
use pubky_switch_core::message::{Message, Sender};
use pubky_switch_core::ops::{KeyBundlePut, OpKind};
use pubky_switch_core::records::{AppCert, seal_bundle_parts};
use pubky_switch_core::scopes::Permission;
use serde_json::{Map, json};

use super::*;
use crate::app::{
    AppError, AppEvent, Collection, DenyListChange, DenyListGap, ProtocolSet, ReceiveContext,
    RecordTarget, Refusal, StoreFailure,
};
use crate::error::StoreError;

#[test]
fn test_order_model_deny_waits_for_every_earlier_message() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        let missed = b.missed();
        let tasks = b.entry("tasks", "item");
        let chat = b.entry("chat", "item");
        b.tick();
        b.manager.deny(&b.w.bob.public()).await.unwrap();
        let deny = b.w.switch.seq();
        let names = b.names.clone();
        b.holds(&names, deny, "deny sender");
        b.last_barrier = deny;
        b.deny_positions.insert(deny);
        b.quiet(false).await;
        assert_eq!(b.taken("tasks"), (vec![], Some(missed)));
        assert_eq!(b.taken("chat").0, [missed, chat]);
        b.model("tasks").failing.lock().unwrap().clear();
        b.quiet(true).await;
        assert_eq!(b.taken("tasks").0, [missed, tasks, deny]);
        assert_eq!(b.taken("chat").0, [missed, chat, deny]);
        assert_eq!(*b.model("chat").blocked.lock().unwrap(), [(chat, false)]);
        assert_eq!(*b.model("tasks").blocked.lock().unwrap(), [(tasks, false)]);
        b.finish().await;
    });
}

#[test]
fn test_order_model_sender_verified_after_a_deny_uses_the_current_copy() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        let sender = b.w.bob.public();
        let path = pubky_switch_core::records::IDENTITY_PATH;
        let document = b.w.homeserver.file(sender, path).unwrap();
        b.w.homeserver.remove(sender, path);
        b.tick();
        let (entry, _) =
            b.w.switch
                .send(
                    &b.w.bob,
                    &b.w.bob_keys,
                    &b.w.bob_cert,
                    "tasks.guarded",
                    json!({ "text": "held" }),
                    &[b.app.app_id()],
                )
                .unwrap();
        b.app.receive(None).await.unwrap();
        assert!(b.model("tasks").blocked.lock().unwrap().is_empty());
        b.tick();
        b.manager.deny(&sender).await.unwrap();
        let deny = b.w.switch.seq();
        b.app.receive(None).await.unwrap();
        assert!(b.app.lists_copy().await.unwrap().deny.contains(&sender));
        assert_eq!(b.taken("tasks").0, [deny]);
        assert_eq!(b.taken("chat").0, [deny]);
        assert!(b.model("tasks").blocked.lock().unwrap().is_empty());
        b.w.homeserver.put(sender, path, document);
        b.tick();
        b.reopen().await;
        b.app.receive(None).await.unwrap();
        assert_eq!(*b.model("tasks").blocked.lock().unwrap(), [(entry, true)]);
        assert!(
            b.app
                .protocol_get("tasks", format!("took/{entry}").as_bytes())
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn test_order_model_deny_copy_waits_for_the_last_callback() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        let sender = b.w.bob.public();
        for added in [true, false] {
            b.model("tasks").failing.lock().unwrap().push(Call::Deny);
            b.tick();
            if added {
                b.manager.deny(&sender).await.unwrap();
            } else {
                b.manager.undeny(&sender).await.unwrap();
            }
            let change = b.w.switch.seq();
            let names = b.names.clone();
            b.holds(&names, change, "deny sender change");
            b.last_barrier = change;
            b.deny_positions.insert(change);
            b.quiet(true).await;
            assert_eq!(
                b.app.lists_copy().await.unwrap().deny.contains(&sender),
                !added
            );
            b.model("tasks").failing.lock().unwrap().clear();
            b.quiet(true).await;
            assert_eq!(
                b.app.lists_copy().await.unwrap().deny.contains(&sender),
                added
            );
        }
        b.finish().await;
    });
}

#[test]
fn test_order_model_failed_call_wakes_a_read_without_a_new_item() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        let missed = b.missed();
        let tasks = b.entry("tasks", "item");
        b.entry("chat", "item");
        b.quiet(false).await;
        b.model("tasks").failing.lock().unwrap().clear();
        let woken = b.app.feed_wait(1).wait().await;
        assert_ne!(woken, crate::app::Woken::Quiet);
        b.read().await;
        assert_eq!(b.taken("tasks").0, [missed, tasks]);
        b.finish().await;
    });
}

#[test]
fn test_order_model_reload_bounds_positions_after_a_trailing_unreadable_item() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        b.missed();
        b.entry("tasks", "item");
        let now = b.tick();
        let tail = b.w.switch.push_unreadable(b.w.bob.public(), now);
        b.quiet(false).await;
        assert_eq!(b.app.told("chat").1, tail);
        assert!(b.app.cursor().seq < tail);
        assert!(b.app.state.chain.as_ref().unwrap().verified_seq() < tail);
        assert!(!b.app.state.seen.contains(&tail));
        assert!(!b.app.state.asked.contains(&tail));
        assert!(!b.app.reader().exists("feed_at").await.unwrap());
        b.reopen().await;
        b.app.ready_local().await.unwrap();
        assert_eq!(b.app.told("chat").1, tail);
        let mut tx = b.app.tx().unwrap();
        tx.put(
            "told/chat",
            &crate::app::order::Told {
                generation: b.app.cursor().generation,
                seq: tail + 1,
            },
        )
        .unwrap();
        b.app.commit(tx).await.unwrap();
        b.reopen().await;
        assert!(matches!(
            b.app.ready_local().await,
            Err(AppError::Store(StoreError::Corrupt))
        ));
    });
}

#[test]
fn test_order_model_scan_bound_cannot_name_an_unknown_generation() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.entry("chat", "item");
        b.quiet(false).await;
        let mut tx = b.app.tx().unwrap();
        let generation = b.app.state.own_doc.generation();
        let chain = b.app.state.chain.as_mut().unwrap();
        chain.read_through.0 = generation + 1;
        chain.write(&mut tx).unwrap();
        b.app.commit(tx).await.unwrap();
        b.reopen().await;
        assert!(matches!(
            b.app.ready_local().await,
            Err(AppError::Store(StoreError::Corrupt))
        ));
    });
}

#[test]
fn test_order_model_processed_pairs_can_be_forgotten_only_by_their_protocol() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.entry("tasks", "item");
        b.quiet(false).await;
        b.reopen().await;
        let pairs = b
            .app
            .reader()
            .scan::<crate::app::state::Processed>("proc/")
            .await
            .unwrap();
        let (key, processed) = pairs
            .iter()
            .find(|(_, pair)| pair.kind == "tasks.item")
            .unwrap();
        let (_, msg_id) = key.split_once('/').unwrap();
        let sender = b.w.bob.public();
        let local = [LocalWrite::Put {
            key: b"forgot".to_vec(),
            value: b"1".to_vec(),
        }];
        assert!(matches!(
            b.app.forget_processed("chat", sender, msg_id, &local).await,
            Err(AppError::Refused(Refusal::Usage(_)))
        ));
        assert!(
            b.app
                .protocol_get("chat", b"forgot")
                .await
                .unwrap()
                .is_none()
        );
        for (name, allowed) in [("chat", false), ("tasks", true)] {
            let mut cx = ReceiveContext::new(
                &b.app.state,
                &b.app.protocols,
                name,
                b.store.as_ref(),
                &b.app.ns,
                true,
                &[],
                &[],
                &[],
            );
            let result = cx.forget_processed(sender, msg_id);
            if allowed {
                assert!(result.unwrap());
                assert_eq!(cx.into_writes().forget.len(), 2);
            } else {
                assert!(matches!(result, Err(AppError::Refused(Refusal::Usage(_)))));
                assert!(cx.into_writes().forget.is_empty());
            }
        }
        assert_eq!(processed.kind, "tasks.item");
        assert!(
            b.app
                .forget_processed("tasks", sender, msg_id, &local)
                .await
                .unwrap()
        );
        assert!(
            b.app
                .protocol_get("tasks", b"forgot")
                .await
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn test_order_model_other_protocol_record_is_a_current_view() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        b.missed();
        let entry = b.entry("tasks", "item");
        b.phone_writes("chat").await;
        let target = RecordTarget::new(list_of("chat"), b"w1");
        let key = b.phone.record_key(&target).unwrap();
        let version = b.phone.shared_record(&key).await.unwrap().unwrap().version;
        assert!(version.version > entry);
        b.quiet(true).await;
        b.model("tasks").failing.lock().unwrap().clear();
        b.quiet(true).await;
        let views = b.model("tasks").views.lock().unwrap().clone();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].seq, entry);
        assert_eq!(views[0].other_record, Some(version));
        b.finish().await;
    });
}

#[test]
fn test_order_model_claim_is_current_while_a_protocol_is_behind() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        b.missed();
        let entry = b.entry("tasks", "item");
        b.tick();
        b.phone
            .write_claim(
                crate::app::ClaimOp::attempt(SHARED_CLAIM, 0, [74; 16], 3600, None),
                vec![],
                crate::app::ObligationDeadline::NoDeadline,
            )
            .await
            .unwrap();
        b.quiet(true).await;
        b.model("tasks").failing.lock().unwrap().clear();
        b.quiet(true).await;
        let views = b.model("tasks").views.lock().unwrap().clone();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].seq, entry);
        assert_eq!(views[0].claim_step, Some(1));
        b.finish().await;
    });
}

#[test]
fn test_order_model_certificate_and_keys_are_current_while_a_protocol_is_behind() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        let before = b.app.cert().hash();
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        b.missed();
        let entry = b.entry("tasks", "item");
        b.renew();
        b.quiet(true).await;
        let current = b.app.cert().hash();
        assert_ne!(before, current);
        b.model("tasks").failing.lock().unwrap().clear();
        b.quiet(true).await;
        let views = b.model("tasks").views.lock().unwrap().clone();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].seq, entry);
        assert_eq!(views[0].cert, current);
        assert_eq!(views[0].epoch, b.app.state.own_doc.data_epoch());
        assert!(views[0].has_key);
        assert!(!views[0].flagged);
        b.finish().await;
    });
}

#[test]
fn test_order_model_explicit_list_refresh_supplies_current_admission_and_flags() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        b.missed();
        let entry = b.entry("tasks", "item");
        b.quiet(false).await;
        let sender = b.w.bob.public();
        b.w.switch.lock().shared.flagged.insert(sender, 3);
        b.manager.keep_peer(&sender).await.unwrap();
        let list = b.app.allow_list().await.unwrap();
        assert!(list.kept_peers().any(|id| id == sender));
        assert!(list.flagged.iter().any(|flag| flag.pubky == sender));
        b.model("tasks").failing.lock().unwrap().clear();
        b.quiet(true).await;
        let views = b.model("tasks").views.lock().unwrap().clone();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].seq, entry);
        assert!(views[0].flagged);
        assert!(!b.model("tasks").blocked.lock().unwrap()[0].1);
        b.finish().await;
    });
}

#[test]
fn test_order_model_restore_restricts_every_protocol_before_owed_calls_recover() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        b.missed();
        b.entry("tasks", "item");
        b.quiet(false).await;
        let read_through = b.app.state.chain.as_ref().unwrap().read_through;
        let backup = b.app.backup().await.unwrap();
        b.app = App::restore(
            b.w.env_on(b.store.clone()),
            set_of(&b.models),
            b.config.clone(),
            &backup,
        )
        .await
        .unwrap();
        b.app.ready_local().await.unwrap();
        assert_eq!(
            b.app.state.chain.as_ref().unwrap().read_through,
            read_through
        );
        assert!(b.app.reconcile_mode());
        assert!(b.app.may_attempt(false).is_err());
        for name in &b.names {
            let mut cx = ReceiveContext::new(
                &b.app.state,
                &b.app.protocols,
                name,
                b.store.as_ref(),
                &b.app.ns,
                b.app.may_attempt(false).is_ok(),
                &[],
                &[],
                &[],
            );
            let attempt = crate::app::ClaimOp::attempt(SHARED_CLAIM, 0, [74; 16], 3600, None);
            assert!(matches!(
                cx.claim(attempt, vec![], crate::app::ObligationDeadline::NoDeadline),
                Err(AppError::Refused(Refusal::NotNow(_)))
            ));
        }
    });
}

#[test]
fn test_order_model_provider_loss_reaches_every_protocol_before_owed_calls_recover() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        b.missed();
        b.entry("tasks", "item");
        b.quiet(false).await;
        let router = super::moves::Router::of(&b.w);
        let key = super::moves::next_key();
        let next = ScriptedSwitch::recovering(&b.w.alice, key.to_bytes(), b.w.clock.clone(), 2, 1)
            .unwrap();
        router.add(super::moves::NEXT, &next);
        super::moves::publish_at(
            &b.w,
            &next,
            pubky_switch_core::records::Inbox::new(
                super::moves::NEXT,
                key.verifying_key().to_bytes(),
            ),
            2,
            Some(1),
        );
        b.app = App::load(
            router.env(&b.w, b.store.clone()),
            set_of(&b.models),
            b.config.clone(),
            b.app.app_id(),
        )
        .await
        .unwrap();
        b.app.refresh_identity().await.unwrap();
        b.app.follow_provider().await.unwrap();
        assert_eq!(b.app.state.chain.as_ref().unwrap().read_through, (2, 1));
        b.app.receive(None).await.unwrap();
        for model in &b.models {
            assert_eq!(*model.losses.lock().unwrap(), [2]);
        }
        assert_eq!(b.app.cursor().generation, 2);
        assert_eq!(b.app.state.chain.as_ref().unwrap().read_through.0, 2);
        assert!(b.app.reconcile_mode());
        assert!(b.app.may_attempt(false).is_err());
    });
}

#[test]
fn test_order_model_sender_standing_follows_deny_and_undeny_in_feed_order() {
    for seed in 1..41 {
        on_a_thread(async move {
            let mut rng = Rng(seed);
            let mut b = Bench::new(2, if seed % 2 == 0 { 1 } else { 100 }).await;
            let sender = b.w.bob.public();
            let mut denied = false;
            let mut expected = BTreeMap::new();
            for _ in 0..50 {
                let name = if rng.chance(2) { "tasks" } else { "chat" };
                match rng.below(8) {
                    0 => {
                        b.tick();
                        denied = !denied;
                        if denied {
                            b.manager.deny(&sender).await.unwrap();
                        } else {
                            b.manager.undeny(&sender).await.unwrap();
                        }
                        let seq = b.w.switch.seq();
                        let names = b.names.clone();
                        b.holds(&names, seq, "sender standing change");
                        b.last_barrier = seq;
                        b.deny_positions.insert(seq);
                    }
                    1 => {
                        *b.model(name).failing.lock().unwrap() = vec![Call::Missed];
                        b.missed();
                    }
                    2 => b.model(name).failing.lock().unwrap().clear(),
                    3 => b.reopen().await,
                    4 => {
                        b.read().await;
                    }
                    _ => {
                        expected.insert(b.entry(name, "item"), denied);
                    }
                }
            }
            b.finish().await;
            for model in &b.models {
                for (seq, blocked) in model.blocked.lock().unwrap().iter() {
                    assert_eq!(Some(blocked), expected.get(seq), "seed {seed}, entry {seq}");
                }
            }
        });
    }
}

/// A kind of call a protocol may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Missed,
    Resend,
    Deny,
    Gap,
}

const CALLS: [Call; 4] = [Call::Missed, Call::Resend, Call::Deny, Call::Gap];

/// What a protocol was told, as it saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Told {
    /// It took the feed item at this `seq`: a message, or a call about the item.
    Took(u64),
    /// It failed the call about the feed item at this `seq`.
    Failed(u64),
    /// It took, or failed, a deny list gap at this position.
    Gap(u64),
}

/// A protocol named `name` with one collection, `<name>.list`: it takes `<name>.item`,
/// `<name>.write`, whose step writes a record of its own, and `<name>.poach`, whose step
/// tries to write a record of another protocol; it notes everything it is told.
struct Model {
    name: String,
    list: Collection,
    /// A collection of another protocol, which a `.poach` step tries to write.
    other: Collection,
    told: Mutex<Vec<Told>>,
    timeline: Arc<Mutex<Vec<(String, Told)>>>,
    /// The kinds of call it fails now.
    failing: Mutex<Vec<Call>>,
    /// The `seq` of the unopenable entry accepted at each time: a re-send call names only
    /// the time.
    resends: Arc<Mutex<BTreeMap<u64, u64>>>,
    /// How many writes of another protocol's record its steps had refused.
    refused_poaches: Mutex<u32>,
    /// Whether it notes what it is told: off for the apps beside the one under test.
    notes: bool,
    /// The sender's deny standing each message step observed.
    blocked: Mutex<Vec<(u64, bool)>>,
    /// The committed protocol state checked by the crash cases.
    committed_store: Mutex<Option<(Arc<dyn StateStore>, String)>>,
    repeated_committed: Mutex<Vec<u64>>,
    views: Mutex<Vec<StepView>>,
    losses: Mutex<Vec<u64>>,
}

/// Shared observations made by a message step, apart from its ordered deny copy.
#[derive(Clone, Debug)]
struct StepView {
    seq: u64,
    cert: [u8; 32],
    epoch: u64,
    has_key: bool,
    other_record: Option<pubky_switch_core::ops::RecordVersion>,
    claim_step: Option<u64>,
    flagged: bool,
}

const SHARED_CLAIM: [u8; 32] = [73; 32];

struct CountOwedScans {
    store: Arc<MemoryStore>,
    scans: std::sync::atomic::AtomicUsize,
}

impl StateStore for CountOwedScans {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.store.get(ns, key)
    }
    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<crate::store::KeyValue>, StoreError> {
        if prefix == b"owed/" {
            self.scans
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.store.scan(ns, prefix, after, limit)
    }
    fn commit(&self, batch: crate::store::WriteBatch) -> Result<(), StoreError> {
        self.store.commit(batch)
    }
    fn acquire(
        &self,
        ns: &str,
        owner: crate::store::StoreOwner,
    ) -> Result<crate::store::AcquireOutcome, StoreError> {
        self.store.acquire(ns, owner)
    }

    fn commit_if(
        &self,
        ns: &str,
        owner: crate::store::StoreOwner,
        batch: crate::store::WriteBatch,
    ) -> Result<crate::store::CommitOutcome, StoreError> {
        self.store.commit_if(ns, owner, batch)
    }
}

#[test]
fn test_order_model_replaying_many_calls_does_not_rescan_each_call() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Resend);
        for _ in 0..40 {
            b.unopenable();
        }
        b.quiet(false).await;
        assert_eq!(b.app.owed_protocol_calls().await.unwrap(), 40);
        let counting = Arc::new(CountOwedScans {
            store: b.store.clone(),
            scans: std::sync::atomic::AtomicUsize::new(0),
        });
        b.app = App::load(
            b.w.env_on(counting.clone()),
            set_of(&b.models),
            b.config.clone(),
            b.app.app_id(),
        )
        .await
        .unwrap();
        b.model("tasks").failing.lock().unwrap().clear();
        b.app.receive(None).await.unwrap();
        let scans = counting.scans.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            scans <= 8,
            "one read rescanned the kept calls {scans} times"
        );
        assert_eq!(b.app.owed_protocol_calls().await.unwrap(), 0);
        b.finish().await;
    });
}

/// The scope of protocol `name`, which has keys: its name, or one under its root.
fn scope_of(name: &str) -> String {
    if name == "sample" {
        "sample-a".into()
    } else {
        name.into()
    }
}

fn list_of(name: &str) -> Collection {
    let scope = scope_of(name);
    Collection::new(&format!("{name}.list"), Policy::new(&scope, &[&scope]))
}

impl Model {
    fn check_committed(&self, seq: u64) {
        let held = self.committed_store.lock().unwrap();
        let Some((store, ns)) = held.as_ref() else {
            return;
        };
        let key = [
            crate::app::state::PROTOCOL_PREFIX,
            &crate::app::protocols::qualified_key(&self.name, format!("took/{seq}").as_bytes()),
        ]
        .concat();
        if store.get(ns, &key).unwrap().is_some() {
            self.repeated_committed.lock().unwrap().push(seq);
        }
    }

    fn fails(&self, call: Call) -> bool {
        self.failing.lock().unwrap().contains(&call)
    }

    fn note(&self, told: Told) {
        if self.notes {
            self.told.lock().unwrap().push(told);
            self.timeline
                .lock()
                .unwrap()
                .push((self.name.clone(), told));
        }
    }

    fn call(&self, call: Call, seq: u64) -> Result<Vec<LocalWrite>, StoreFailure> {
        if self.fails(call) {
            self.note(Told::Failed(seq));
            return Err(StoreError::Unavailable.into());
        }
        self.note(Told::Took(seq));
        self.check_committed(seq);
        Ok(vec![LocalWrite::Put {
            key: format!("took/{seq}").into_bytes(),
            value: b"1".to_vec(),
        }])
    }
}

impl Protocol for Model {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn provider_lost(
        &self,
        loss: &crate::app::ProviderLoss,
        _: &crate::app::LocalView<'_>,
    ) -> Result<crate::app::LossActions, StoreFailure> {
        self.losses.lock().unwrap().push(loss.generation);
        Ok(crate::app::LossActions::default())
    }

    fn collections(&self) -> Vec<Collection> {
        // The first protocol has a second collection, whose read scope a renewal adds.
        let mut collections = vec![self.list.clone()];
        if self.name == NAMES[0] {
            collections.push(Collection::new(
                "tasks.wide",
                Policy::new("tasks_wide", &["tasks"]),
            ));
        }
        collections
    }

    fn has_keys(&self, scope: &str) -> bool {
        scope == scope_of(&self.name)
    }

    fn sent_between_own_apps(&self, _kind: &str) -> bool {
        false
    }

    fn check_scopes(&self, _: &Message, _: &AppCert, _: &AppCert) -> Result<(), String> {
        Ok(())
    }

    fn accepts(&self, _cert: &AppCert) -> Vec<String> {
        ["item", "write", "poach", "guarded"]
            .iter()
            .map(|kind| format!("{}.{kind}", self.name))
            .collect()
    }

    fn check_body(&self, _message: &ReceivedMessage) -> Result<(), String> {
        Ok(())
    }

    fn receive(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        let kind = message.message.kind.as_str();
        self.check_committed(message.seq);
        if self.notes {
            let other = cx
                .record_key(&RecordTarget::new(self.other.clone(), b"w1"))
                .unwrap();
            self.views.lock().unwrap().push(StepView {
                seq: message.seq,
                cert: cx.cert().hash(),
                epoch: cx.data_epoch(),
                has_key: cx.holds_scope_key(&scope_of(&self.name), cx.data_epoch()),
                other_record: cx.record_at(&other).unwrap().map(|record| record.version),
                claim_step: cx.claim_view(&SHARED_CLAIM).unwrap().map(|view| view.step),
                flagged: cx.sender_disposition(&message.sender).unwrap().flagged,
            });
            self.blocked.lock().unwrap().push((
                message.seq,
                cx.sender_disposition(&message.sender).unwrap().blocked,
            ));
        }
        if kind.ends_with(".guarded") && cx.sender_disposition(&message.sender).unwrap().blocked {
            return Outcome::Pass;
        }
        if kind.ends_with(".write") {
            let target = RecordTarget::new(self.list.clone(), b"own");
            let value = json!({ "seq": message.seq }).to_string();
            if cx.put_record(&target, value.as_bytes(), vec![]).is_err() {
                return Outcome::Retry(StoreFailure::unavailable(StoreError::Unavailable));
            }
        }
        if kind.ends_with(".poach") {
            let target = RecordTarget::new(self.other.clone(), b"poached");
            match cx.put_record(&target, b"{}", vec![]) {
                Err(AppError::Refused(Refusal::Usage(_))) => {
                    *self.refused_poaches.lock().unwrap() += 1;
                }
                other => panic!("a write of another protocol's record: {other:?}"),
            }
        }
        // A step run again for one entry, as after a conflict, tells it the same entry.
        if self.told.lock().unwrap().last() != Some(&Told::Took(message.seq)) {
            self.note(Told::Took(message.seq));
        }
        Outcome::Apply(Effect {
            ops: Vec::new(),
            local: vec![LocalWrite::Put {
                key: format!("took/{}", message.seq).into_bytes(),
                value: b"1".to_vec(),
            }],
        })
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        let seq = self
            .resends
            .lock()
            .unwrap()
            .get(&needed.accepted_from_ms)
            .copied()
            .unwrap_or(0);
        self.call(Call::Resend, seq)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.call(Call::Missed, missed.seq)
    }

    fn deny_list_changed(&self, change: &DenyListChange) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.call(Call::Deny, change.seq)
    }

    fn deny_list_gap(&self, gap: &DenyListGap) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.note(Told::Gap(gap.seq));
        if self.fails(Call::Gap) {
            return Err(StoreError::Unavailable.into());
        }
        Ok(Vec::new())
    }
}

/// A small generator of numbers from a seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, of: u64) -> bool {
        self.below(of) == 0
    }
}

/// An app under test with its protocols, another own app that writes records, and one that
/// manages the deny list; and what the feed holds for each protocol.
struct Bench {
    w: World,
    names: Vec<String>,
    models: Vec<Arc<Model>>,
    store: Arc<MemoryStore>,
    config: AppConfig,
    app: App,
    phone: App,
    manager: App,
    resends: Arc<Mutex<BTreeMap<u64, u64>>>,
    /// The `seq` of each item the feed holds for each protocol, in feed order.
    feed: BTreeMap<String, Vec<u64>>,
    /// The record of each protocol the app wrote itself, for uploads to make divergent.
    own: BTreeMap<String, [u8; 32]>,
    /// The `seq` of the last deny list change, and the position of the last gap asked for.
    last_barrier: u64,
    deny_positions: BTreeSet<u64>,
    /// The `seq` of each `missed` item shown.
    missed_at: Vec<u64>,
    /// What each item the feed holds for a protocol is, for a failure's message.
    shown: BTreeMap<u64, String>,
    written: u64,
    denied: u8,
    /// A record each protocol's collection held when it began to fail a call another
    /// protocol went past: the `seq` of the call, and the records as held then.
    frozen: BTreeMap<String, (u64, String)>,
    /// Whether a renewal was shown: its listing is owed outside the feed when the app
    /// takes it from its own record, so the records of a protocol behind may change.
    renewed: bool,
}

const NAMES: [&str; 3] = ["tasks", "chat", "sample"];

fn spec(names: &[String], permissions: &[Permission], extra: &[&str]) -> AppSpec {
    let own: Vec<String> = names.iter().map(|name| scope_of(name)).collect();
    let mut scopes: Vec<&str> = own.iter().map(String::as_str).collect();
    scopes.extend_from_slice(extra);
    // In the fixed order (Switch wire 3.1).
    let all: Vec<Permission> = Permission::ALL
        .iter()
        .copied()
        .filter(|p| *p == Permission::ReplyAdd || permissions.contains(p))
        .collect();
    AppSpec::new(&scopes).with_permissions(&all)
}

fn models(
    names: &[String],
    resends: &Arc<Mutex<BTreeMap<u64, u64>>>,
    notes: bool,
) -> Vec<Arc<Model>> {
    let timeline = Arc::new(Mutex::new(Vec::new()));
    names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let other = &names[(index + 1) % names.len()];
            Arc::new(Model {
                name: name.clone(),
                list: list_of(name),
                other: list_of(other),
                told: Mutex::new(Vec::new()),
                timeline: timeline.clone(),
                failing: Mutex::new(Vec::new()),
                resends: Arc::clone(resends),
                refused_poaches: Mutex::new(0),
                notes,
                blocked: Mutex::new(Vec::new()),
                committed_store: Mutex::new(None),
                repeated_committed: Mutex::new(Vec::new()),
                views: Mutex::new(Vec::new()),
                losses: Mutex::new(Vec::new()),
            })
        })
        .collect()
}

fn set_of(models: &[Arc<Model>]) -> ProtocolSet {
    ProtocolSet::new(
        models
            .iter()
            .map(|model| Arc::clone(model) as Arc<dyn Protocol>)
            .collect(),
    )
    .unwrap()
}

impl Bench {
    async fn new(protocols: usize, page_size: u32) -> Self {
        let w = World::new();
        let names: Vec<String> = NAMES[..protocols].iter().map(|n| (*n).to_owned()).collect();
        let resends = Arc::new(Mutex::new(BTreeMap::new()));
        let own_models = models(&names, &resends, true);
        let store = Arc::new(MemoryStore::new());
        let mut config = World::config();
        config.page_size = page_size;
        let join = |name: &str, permissions: &[Permission]| {
            w.signer
                .approve(&app_keys(name), &spec(&names, permissions, &[]))
                .unwrap()
        };
        let mut app = App::join(
            w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
            set_of(&own_models),
            config.clone(),
            join(
                "wallet",
                &[
                    Permission::ListsRead,
                    Permission::ClaimsRead,
                    Permission::ClaimsWrite,
                ],
            ),
        )
        .await
        .unwrap();
        let mut phone = App::join(
            w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
            set_of(&models(&names, &resends, false)),
            World::config(),
            join("phone", &[Permission::ClaimsRead, Permission::ClaimsWrite]),
        )
        .await
        .unwrap();
        let mut manager = App::join(
            w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
            set_of(&models(&names, &resends, false)),
            World::config(),
            join("manager", &[Permission::ListsManage]),
        )
        .await
        .unwrap();
        for other in [&mut phone, &mut manager] {
            for _ in 0..3 {
                other.receive(None).await.unwrap();
            }
        }
        let mut own = BTreeMap::new();
        for name in &names {
            let target = RecordTarget::new(list_of(name), b"held");
            app.put_record(&target, b"{}", vec![]).await.unwrap();
            own.insert(name.clone(), app.record_key(&target).unwrap());
        }
        let feed = names
            .iter()
            .map(|name| (name.clone(), Vec::new()))
            .collect();
        let mut bench = Self {
            w,
            names,
            models: own_models,
            store,
            config,
            app,
            phone,
            manager,
            resends,
            feed,
            own,
            last_barrier: 0,
            deny_positions: BTreeSet::new(),
            missed_at: Vec::new(),
            shown: BTreeMap::new(),
            written: 0,
            denied: 0,
            frozen: BTreeMap::new(),
            renewed: false,
        };
        bench.settle().await;
        for model in &bench.models {
            model.told.lock().unwrap().clear();
            model.timeline.lock().unwrap().clear();
        }
        bench
    }

    fn model(&self, name: &str) -> &Arc<Model> {
        self.models.iter().find(|model| model.name == name).unwrap()
    }

    /// Each item is accepted at a time of its own.
    fn tick(&self) -> u64 {
        let now = self.w.clock.now_ms() + 1;
        self.w.clock.set_ms(now);
        now
    }

    fn holds(&mut self, names: &[String], seq: u64, what: &str) {
        self.shown.insert(seq, what.to_owned());
        for name in names {
            self.feed.get_mut(name).unwrap().push(seq);
        }
    }

    /// A message of `kind` of protocol `name`.
    fn entry(&mut self, name: &str, kind: &str) -> u64 {
        self.tick();
        let me = self.app.app_id();
        let kind = format!("{name}.{kind}");
        let seq = self
            .w
            .switch
            .send(
                &self.w.bob,
                &self.w.bob_keys,
                &self.w.bob_cert,
                &kind,
                json!({ "text": kind }),
                &[me],
            )
            .unwrap()
            .0;
        self.holds(&[name.to_owned()], seq, &kind);
        seq
    }

    /// An entry sealed to a key the app doesn't hold: a re-send call to every protocol.
    fn unopenable(&mut self) -> u64 {
        let now = self.tick();
        let me = self.app.app_id();
        let stranger = ReceiveKey::from_secret(9, [45; 32]);
        let message = Message::new(
            "tasks.item",
            Sender::of_app(self.w.bob.public(), &self.w.bob_keys),
            self.w.alice.public(),
            now,
            vec![],
            Map::new(),
        )
        .unwrap();
        let sealed = message
            .sign(&self.w.bob_keys)
            .unwrap()
            .seal(
                &self.w.alice.public(),
                &[Recipient::new(stranger.public)],
                false,
            )
            .unwrap();
        let seq = self
            .w
            .switch
            .send_envelope(self.w.bob.public(), &self.w.bob_cert, sealed, &[me]);
        self.resends.lock().unwrap().insert(now, seq);
        let names = self.names.clone();
        self.holds(&names, seq, "unopenable");
        seq
    }

    /// A `missed` item: a call to every protocol, and a listing.
    fn missed(&mut self) -> u64 {
        let now = self.tick();
        let seq = self.w.switch.push_missed(1, now, now);
        let names = self.names.clone();
        self.holds(&names, seq, "missed");
        self.missed_at.push(seq);
        seq
    }

    /// A deny list change by the manager: a call to every protocol.
    async fn deny(&mut self) -> u64 {
        self.tick();
        self.denied = self.denied.wrapping_add(1);
        self.manager.deny(&[self.denied; 32]).await.unwrap();
        let seq = self.w.switch.seq();
        let names = self.names.clone();
        self.holds(&names, seq, "deny list change");
        self.last_barrier = seq;
        self.deny_positions.insert(seq);
        seq
    }

    /// Another own app's write of a record of protocol `name`.
    async fn phone_writes(&mut self, name: &str) {
        self.tick();
        self.written += 1;
        let natural = format!("w{}", self.written % 3);
        let target = RecordTarget::new(list_of(name), natural.as_bytes());
        let value = json!({ "n": self.written }).to_string();
        // The phone builds on what it holds: it reads its own writes first.
        self.phone.receive(None).await.unwrap();
        self.phone
            .put_record(&target, value.as_bytes(), vec![])
            .await
            .unwrap();
    }

    /// An upload making the record of protocol `name` the app holds divergent.
    fn upload(&mut self, name: &str) {
        self.tick();
        self.written += 1;
        let by = app_keys("phone").app_id_bytes();
        let hash = [u8::try_from(self.written % 250).unwrap(); 32];
        self.w
            .switch
            .make_divergent(by, self.own[name], hash)
            .unwrap();
    }

    /// An upload of more records than the app keeps marks for: a listing.
    fn upload_past_the_marks(&mut self) {
        self.tick();
        let records = (0..=crate::app::MAX_RECORD_MARKS)
            .map(|i| {
                let mut key = [0xee; 32];
                key[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
                key
            })
            .collect();
        let changes = pubky_switch_core::recovery::UploadChanges {
            records,
            ..Default::default()
        };
        self.w
            .switch
            .chain_upload(app_keys("phone").app_id_bytes(), changes.to_value())
            .unwrap();
    }

    /// A renewal of the app's certificate that adds the read scope of a collection: the
    /// certificate is taken, the app's record changes, and a listing is owed.
    fn renew(&mut self) {
        let now = self.tick();
        self.renewed = true;
        let me = self.app.app_id();
        let renewed = issue_cert(
            &self.w.alice,
            &app_keys("wallet"),
            &spec(&self.names, &[Permission::ListsRead], &["tasks_wide"]),
            now + 1000,
        )
        .unwrap();
        let old = self.app.cert().clone();
        self.w
            .switch
            .signer_op(OpKind::CertPut {
                target_app_id: me,
                cert: renewed.signed().clone(),
            })
            .unwrap();
        self.w.next_doc(|body| {
            body.apps.retain(|a| a.app_id != me);
            body.apps.push(pubky_switch_core::records::ListedApp {
                app_id: me,
                cert: renewed.hash(),
            });
            body.renewed.retain(|r| r.app_id != me);
            body.renewed.push(pubky_switch_core::records::RenewedCert {
                app_id: me,
                cert: old.hash(),
                until: None,
            });
        });
    }

    /// Drop the app and load it again from its store.
    async fn reopen(&mut self) {
        let me = self.app.app_id();
        self.app = App::load(
            self.w
                .env_on(Arc::clone(&self.store) as Arc<dyn StateStore>),
            set_of(&self.models),
            self.config.clone(),
            me,
        )
        .await
        .unwrap();
    }

    async fn read(&mut self) -> crate::app::ReceiveReport {
        let report = self.app.receive(None).await.unwrap();
        self.check().await;
        report
    }

    /// Read until the reads tell no protocol anything new: twice in a row from a read
    /// that has more to do now to the one that has not, with nothing taken between (a
    /// read behind a held item starts at the cursor again once it reached the feed's end),
    /// `reopening` the app before each read when asked.
    async fn quiet(&mut self, reopening: bool) {
        let mut still = 0;
        let mut before = self.told_count();
        for _ in 0..600 {
            if reopening {
                self.reopen().await;
            }
            let report = self.read().await;
            if report.more {
                continue;
            }
            if self.told_count() == before {
                still += 1;
                if still == 2 {
                    return;
                }
            } else {
                still = 0;
                before = self.told_count();
            }
        }
        panic!(
            "the reads never come to rest: {:?}",
            self.models
                .iter()
                .map(|model| (model.name.clone(), model.told.lock().unwrap().clone()))
                .collect::<Vec<_>>()
        );
    }

    async fn settle(&mut self) {
        self.quiet(false).await;
    }

    /// How many things the protocols took so far, the calls they failed aside.
    fn told_count(&self) -> usize {
        self.models
            .iter()
            .map(|model| {
                let told = model.told.lock().unwrap();
                told.iter()
                    .filter(|told| matches!(told, Told::Took(_)))
                    .count()
            })
            .sum()
    }

    /// What protocol `name` took so far, and the call it fails now, if it fails one.
    fn taken(&self, name: &str) -> (Vec<u64>, Option<u64>) {
        let mut took = Vec::new();
        let mut failing = None;
        let all = self.model(name).told.lock().unwrap().clone();
        for told in &all {
            match told {
                Told::Took(seq) => {
                    took.push(*seq);
                    failing = None;
                }
                Told::Failed(seq) => failing = Some(*seq),
                Told::Gap(_) => {}
            }
        }
        (took, failing)
    }

    /// The rule: what each protocol took is the first items the feed holds for it, in
    /// order, each once; a call it failed was the next of them then; and a gap came after
    /// everything at or before its position.
    async fn check(&mut self) {
        let mut delivered: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        for (name, notice) in self.models[0].timeline.lock().unwrap().iter() {
            if let Told::Took(seq) = notice {
                if self.deny_positions.contains(seq) {
                    for (owner, items) in &self.feed {
                        for earlier in items.iter().filter(|item| **item < *seq) {
                            assert!(
                                delivered
                                    .get(owner)
                                    .is_some_and(|seen| seen.contains(earlier)),
                                "`{name}` took deny {seq} before `{owner}` took {earlier}"
                            );
                        }
                    }
                }
                delivered.entry(name.clone()).or_default().insert(*seq);
            }
        }
        for name in self.names.clone() {
            let feed = &self.feed[&name];
            let mut next = 0;
            let all = self.model(&name).told.lock().unwrap().clone();
            for told in &all {
                match *told {
                    Told::Took(seq) => {
                        assert_eq!(
                            feed.get(next),
                            Some(&seq),
                            "`{name}` took {seq}, not the next the feed holds for it: {all:?} of {feed:?}; {:?}",
                            self.shown
                        );
                        next += 1;
                    }
                    Told::Failed(seq) => assert_eq!(
                        feed.get(next),
                        Some(&seq),
                        "`{name}` was handed {seq} before what comes before it"
                    ),
                    // A gap carries the list as it stands when it is told: it comes after
                    // everything at or before its position.
                    Told::Gap(at) => assert!(
                        feed.get(next).is_none_or(|seq| *seq > at),
                        "`{name}` was told a gap at {at} before what comes before it: {next} of {feed:?}"
                    ),
                }
            }
        }
        self.check_records().await;
    }

    /// While a protocol fails a re-send or deny list call another protocol went past, the
    /// app's copy of its records stays as it was: nothing of them is judged, marked or
    /// read for it.
    async fn check_records(&mut self) {
        if self.renewed {
            return;
        }
        let missed = self.missed_at.clone();
        for name in self.names.clone() {
            let (_, failing) = self.taken(&name);
            let passed = failing.filter(|seq| {
                !missed.contains(seq)
                    && self
                        .names
                        .iter()
                        .any(|other| *other != name && self.taken(other).0.last() > Some(seq))
            });
            let Some(seq) = passed else {
                self.frozen.remove(&name);
                continue;
            };
            let held = format!(
                "{:?}",
                self.app.records_of(&format!("{name}.list")).await.unwrap()
            );
            match self.frozen.get(&name) {
                Some((at, before)) if *at == seq => assert_eq!(
                    *before, held,
                    "the records of `{name}` changed while it fails the call at {seq}"
                ),
                _ => {
                    self.frozen.insert(name, (seq, held));
                }
            }
        }
    }

    /// Every protocol takes its calls again; then, the reads quiet, each took everything
    /// the feed holds for it, the app owes nothing, and its records are the switch's.
    async fn finish(&mut self) {
        for model in &self.models {
            model.failing.lock().unwrap().clear();
        }
        self.quiet(false).await;
        for name in &self.names {
            assert_eq!(
                self.taken(name).0,
                self.feed[name],
                "`{name}` took everything the feed holds for it"
            );
        }
        assert_eq!(self.app.owed_protocol_calls().await.unwrap(), 0);
        assert!(!self.app.listing_owed().await.unwrap());
        self.phone.receive(None).await.unwrap();
        for name in &self.names {
            let collection = format!("{name}.list");
            for theirs in self.phone.records_of(&collection).await.unwrap() {
                let ours = self.app.shared_record(&theirs.key).await.unwrap();
                assert_eq!(
                    ours.map(|record| record.version),
                    Some(theirs.version),
                    "the app holds the newest write of each record of `{name}`"
                );
            }
        }
    }
}

/// One step of a generated run.
#[derive(Clone, Copy, Debug)]
enum Step {
    Entry,
    WritingEntry,
    PoachingEntry,
    Unopenable,
    Missed,
    MissedUnparsable,
    Deny,
    Gap,
    PhoneWrite,
    Upload,
    UploadPastTheMarks,
    Renew,
    Read,
    Fail,
    Recover,
    Reopen,
    Settle,
}

/// The steps, each as often as its weight.
const STEPS: [(Step, u64); 17] = [
    (Step::Entry, 26),
    (Step::WritingEntry, 5),
    (Step::PoachingEntry, 3),
    (Step::Unopenable, 8),
    (Step::Missed, 8),
    (Step::MissedUnparsable, 2),
    (Step::Deny, 4),
    (Step::Gap, 2),
    (Step::PhoneWrite, 8),
    (Step::Upload, 5),
    (Step::UploadPastTheMarks, 1),
    (Step::Renew, 1),
    (Step::Read, 30),
    (Step::Fail, 8),
    (Step::Recover, 8),
    (Step::Reopen, 6),
    (Step::Settle, 3),
];

fn pick(rng: &mut Rng) -> Step {
    let total: u64 = STEPS.iter().map(|(_, weight)| weight).sum();
    let mut at = rng.below(total);
    for (step, weight) in STEPS {
        if at < weight {
            return step;
        }
        at -= weight;
    }
    Step::Read
}

impl Bench {
    async fn step(&mut self, step: Step, rng: &mut Rng) {
        let name = self.names[usize::try_from(rng.below(self.names.len() as u64)).unwrap()].clone();
        match step {
            Step::Entry => {
                self.entry(&name, "item");
            }
            Step::WritingEntry => {
                self.entry(&name, "write");
            }
            Step::PoachingEntry => {
                self.entry(&name, "poach");
            }
            Step::Unopenable => {
                self.unopenable();
            }
            Step::Missed => {
                self.missed();
            }
            Step::MissedUnparsable => {
                self.tick();
                self.w.switch.push_missed_unparsable(1);
            }
            Step::Deny => {
                self.deny().await;
            }
            Step::Gap => {
                self.app.allow_list().await.unwrap();
                self.last_barrier = self.last_barrier.max(self.app.cursor().seq);
            }
            Step::PhoneWrite => self.phone_writes(&name).await,
            Step::Upload => self.upload(&name),
            Step::UploadPastTheMarks => self.upload_past_the_marks(),
            Step::Renew => {
                if !self.renewed {
                    self.renew();
                }
            }
            Step::Read => {
                self.read().await;
            }
            Step::Fail => {
                let call = CALLS[usize::try_from(rng.below(4)).unwrap()];
                let mut failing = self.model(&name).failing.lock().unwrap();
                if !failing.contains(&call) {
                    failing.push(call);
                }
            }
            Step::Recover => self.model(&name).failing.lock().unwrap().clear(),
            Step::Reopen => self.reopen().await,
            Step::Settle => {
                let reopening = rng.chance(2);
                self.quiet(reopening).await;
                self.check_progress();
            }
        }
    }

    /// Once the reads are quiet, a protocol that fails no call took everything the feed
    /// holds for it, whatever another protocol fails: unless a deny list change or gap,
    /// which every protocol takes before any is handed anything later, came after the
    /// first call a protocol fails.
    fn check_progress(&self) {
        let stuck: Vec<u64> = self
            .names
            .iter()
            .filter_map(|name| self.taken(name).1)
            .collect();
        let barrier = stuck.iter().any(|seq| self.last_barrier >= *seq);
        let gap_fails = self
            .models
            .iter()
            .any(|model| model.fails(Call::Gap) || model.fails(Call::Deny));
        if barrier || gap_fails {
            return;
        }
        for name in &self.names {
            if self.taken(name).1.is_none() && self.model(name).failing.lock().unwrap().is_empty() {
                assert_eq!(
                    self.taken(name).0,
                    self.feed[name],
                    "`{name}` fails nothing, and took everything the feed holds for it"
                );
            }
        }
    }
}

/// One generated run: `steps` steps from `seed`, then every protocol takes its calls.
async fn run(seed: u64, protocols: usize, page_size: u32, steps: usize) {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut bench = Bench::new(protocols, page_size).await;
    for _ in 0..steps {
        let step = pick(&mut rng);
        bench.step(step, &mut rng).await;
    }
    bench.finish().await;
}

/// The seeds of one test, each run on a thread of its own stack, and named when it fails.
fn run_seeds(seeds: impl IntoIterator<Item = u64>, protocols: usize, steps: usize) {
    for seed in seeds {
        // Pages of one item for a third of the seeds, of a few for another, of many else.
        let page_size = match seed % 3 {
            0 => 1,
            1 => 2 + u32::try_from(seed % 4).unwrap(),
            _ => 100,
        };
        let outcome = std::thread::Builder::new()
            .stack_size(test_stack())
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run(seed, protocols, page_size, steps));
            })
            .unwrap()
            .join();
        assert!(
            outcome.is_ok(),
            "seed {seed} with {protocols} protocols and pages of {page_size} failed"
        );
    }
}

#[test]
fn test_order_model_two_protocols_take_the_feed_in_order_in_any_run() {
    run_seeds(1..41, 2, 70);
}

#[test]
fn test_order_model_three_protocols_take_the_feed_in_order_in_any_run() {
    run_seeds(100..130, 3, 70);
}

#[test]
fn test_order_model_kept_calls_and_repeated_listings_preserve_order() {
    // A deny list change kept for one protocol while the read went on for the others; a
    // listing owed again by an item the read met a second time; a call kept past the
    // cursor reached on a page that ended for a listing.
    run_seeds([6, 18, 148, 263, 411], 2, 90);
    run_seeds([104, 1104, 1337], 3, 90);
}

fn test_stack() -> usize {
    std::env::var("RUST_MIN_STACK")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8 << 20)
}

/// Run `test` on a thread with room for the read's deepest futures.
fn on_a_thread(test: impl std::future::Future<Output = ()> + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(test_stack())
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(test);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_order_model_protocol_behind_a_read_that_stopped_on_its_pages_catches_up_in_order() {
    // `tasks` fails a missed call; an entry of its own follows, then enough of `chat`'s
    // for a read of one-item pages to stop on its pages past the held entry, then another
    // of `tasks`. Once `tasks` takes the call, it gets the held entry before the later
    // one, though the read before went on past both.
    on_a_thread(async {
        let mut b = Bench::new(2, 1).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        let missed = b.missed();
        b.quiet(false).await;
        assert_eq!(b.taken("tasks"), (vec![], Some(missed)));
        let held = b.entry("tasks", "item");
        for _ in 0..6 {
            b.entry("chat", "item");
        }
        let later = b.entry("tasks", "item");
        let report = b.read().await;
        assert!(report.more, "the read stopped on its pages: {report:?}");
        b.model("tasks").failing.lock().unwrap().clear();
        b.quiet(false).await;
        assert_eq!(b.taken("tasks").0, [missed, held, later]);
        b.finish().await;
    });
}

#[test]
fn test_order_model_step_writing_another_protocols_record_is_refused() {
    // A step of `chat` that writes a record of `tasks` is refused where it names the
    // target; a batch of `chat` carrying such a write is refused too. Nothing of `tasks`
    // changes, also while `tasks` fails a call.
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        b.missed();
        b.quiet(false).await;
        let before = format!("{:?}", b.app.records_of("tasks.list").await.unwrap());
        // `tasks` is the collection after `chat`'s in the bench: `chat`'s step tries it.
        b.entry("chat", "poach");
        b.quiet(false).await;
        assert_eq!(*b.model("chat").refused_poaches.lock().unwrap(), 1);
        assert_eq!(
            format!("{:?}", b.app.records_of("tasks.list").await.unwrap()),
            before
        );
        let target = RecordTarget::new(list_of("tasks"), b"batched");
        let (_, write) = b.app.record_op(&target, Some(b"{}"), vec![]).await.unwrap();
        let batch = crate::app::OpBatch::for_protocol("chat").op(write);
        match b.app.submit_batch(batch).await {
            Err(AppError::Refused(Refusal::Usage(why))) => {
                assert!(why.contains("`tasks`"), "{why}");
            }
            other => panic!("a batch of `chat` writing a record of `tasks`: {other:?}"),
        }
        assert_eq!(
            format!("{:?}", b.app.records_of("tasks.list").await.unwrap()),
            before
        );
        b.finish().await;
    });
}

#[test]
fn test_protocol_batch_collection_owner_survives_a_different_policy() {
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        let mut collection = list_of("tasks");
        collection.policy = list_of("chat").policy;
        let target = RecordTarget::new(collection, b"different-policy");
        let (_, write) = b.app.record_op(&target, Some(b"{}"), vec![]).await.unwrap();
        let result = b
            .app
            .submit_batch(crate::app::OpBatch::for_protocol("chat").op(write))
            .await;
        assert!(
            matches!(result, Err(AppError::Refused(Refusal::Usage(_)))),
            "a collection remains owned regardless of its supplied policy: {result:?}"
        );
    });
}

#[test]
fn test_order_model_app_loaded_before_every_read_goes_on_past_a_protocol_that_is_behind() {
    // `tasks` fails a missed call and has an entry held behind it, so the cursor stays;
    // `chat` has more entries than one read of one-item pages takes. With the app loaded
    // again from its store before every read, `chat` still gets them all in a few reads:
    // the positions are in the store, and no read starts over at the cursor.
    on_a_thread(async {
        let mut b = Bench::new(2, 1).await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        b.missed();
        b.quiet(false).await;
        b.entry("tasks", "item");
        let chat: Vec<u64> = (0..12).map(|_| b.entry("chat", "item")).collect();
        for _ in 0..6 {
            b.reopen().await;
            b.read().await;
        }
        let took = b.taken("chat").0;
        assert!(
            took.ends_with(&chat),
            "`chat` took its twelve entries: {took:?}"
        );
        b.finish().await;
    });
}

#[test]
fn test_order_model_listing_an_item_owes_is_not_held_by_that_items_own_call() {
    // `tasks` fails the call of a `missed` item: the listing the item owes is made for
    // `tasks` too, before it takes the call, as with one protocol; `chat` goes on.
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.phone_writes("tasks").await;
        b.model("tasks").failing.lock().unwrap().push(Call::Missed);
        let missed = b.missed();
        let after = b.entry("chat", "item");
        b.quiet(false).await;
        assert_eq!(b.taken("tasks"), (vec![], Some(missed)));
        assert!(b.taken("chat").0.ends_with(&[missed, after]));
        assert!(
            !b.app.listing_owed().await.unwrap(),
            "the listing was made for both protocols"
        );
        b.finish().await;
    });
}

#[test]
fn test_order_model_listing_waiting_for_one_protocols_key_lets_the_other_go_on() {
    // The app lacks the key of `tasks`'s scope when a `missed` item owes a listing: the
    // listing of `tasks` waits for it, the full key bundle is asked for again, and the
    // read says so; `chat` is listed and goes on. Once the key is back, `tasks` is listed
    // and gets its later entry.
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        let held = b.app.state.scope_keys.keys.clone();
        b.app
            .state
            .scope_keys
            .keys
            .retain(|key| key.scope != "tasks");
        let mut tx = b.app.tx().unwrap();
        for key in held.iter().filter(|key| key.scope == "tasks") {
            tx.delete(&crate::app::state::key::scope(key.data_epoch, &key.scope))
                .unwrap();
        }
        b.app.commit(tx).await.unwrap();
        let missed = b.missed();
        let tasks_later = b.entry("tasks", "item");
        let chat_later = b.entry("chat", "item");
        let mut events = Vec::new();
        for _ in 0..3 {
            events.extend(b.read().await.events);
        }
        assert!(
            events
                .iter()
                .any(|event| matches!(event, AppEvent::ListingWaitsForKey)),
            "{events:?}"
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, AppEvent::FullBundleRequested)),
            "{events:?}"
        );
        assert!(b.app.listing_owed().await.unwrap());
        assert_eq!(b.taken("tasks").0, [missed]);
        assert!(b.taken("chat").0.ends_with(&[missed, chat_later]));
        // The key comes back.
        let mut tx = b.app.tx().unwrap();
        for key in &held {
            tx.put(
                &crate::app::state::key::scope(key.data_epoch, &key.scope),
                key,
            )
            .unwrap();
        }
        b.app.commit(tx).await.unwrap();
        b.app.state.scope_keys.keys = held;
        b.quiet(false).await;
        assert!(!b.app.listing_owed().await.unwrap());
        assert_eq!(b.taken("tasks").0, [missed, tasks_later]);
        b.finish().await;
    });
}

#[test]
fn test_order_model_listing_owed_outside_the_feed_waiting_for_a_key_holds_its_protocol() {
    // A listing owed outside the feed to both protocols, with the key of `tasks`'s scope
    // missing: `chat` is listed and goes on; `tasks` is handed nothing, not the entry
    // right after its position either, until its listing is made.
    on_a_thread(async {
        let mut b = Bench::new(2, 1).await;
        let held = b.app.state.scope_keys.keys.clone();
        b.app
            .state
            .scope_keys
            .keys
            .retain(|key| key.scope != "tasks");
        let mut tx = b.app.tx().unwrap();
        for key in held.iter().filter(|key| key.scope == "tasks") {
            tx.delete(&crate::app::state::key::scope(key.data_epoch, &key.scope))
                .unwrap();
        }
        let due = crate::app::records::ListDue {
            to: vec![("tasks".into(), None), ("chat".into(), None)],
            upload: None,
        };
        tx.put(crate::app::records::LIST_DUE, &due).unwrap();
        b.app.commit(tx).await.unwrap();
        let first = b.entry("tasks", "item");
        let chat: Vec<u64> = (0..8).map(|_| b.entry("chat", "item")).collect();
        let later = b.entry("tasks", "item");
        for _ in 0..4 {
            b.read().await;
            assert!(
                b.taken("tasks").0.is_empty(),
                "`tasks` was handed {:?} while its listing is still owed",
                b.taken("tasks").0
            );
        }
        assert!(b.taken("chat").0.ends_with(&chat));
        assert!(b.app.listing_owed().await.unwrap());
        // The key comes back.
        let mut tx = b.app.tx().unwrap();
        for key in &held {
            tx.put(
                &crate::app::state::key::scope(key.data_epoch, &key.scope),
                key,
            )
            .unwrap();
        }
        b.app.commit(tx).await.unwrap();
        b.app.state.scope_keys.keys = held;
        b.quiet(false).await;
        assert_eq!(b.taken("tasks").0, [first, later]);
        b.finish().await;
    });
}

#[test]
fn test_order_model_one_protocol_reads_its_marks_in_a_read_that_ends_for_a_second_listing() {
    // One protocol: an upload, a `missed` item, an entry and another `missed` item in one
    // page. The read lists once, and ends at the second item for the next read's listing,
    // not stopped: the record the upload marked is read again at its end.
    on_a_thread(async {
        let mut b = Bench::new(1, 100).await;
        b.upload("tasks");
        b.missed();
        b.entry("tasks", "item");
        b.missed();
        b.w.switch.lock().shared.record_reads.clear();
        let report = b.read().await;
        assert_eq!(
            b.w.switch.lock().shared.record_reads,
            [b.own["tasks"]],
            "the ready protocol reads its upload once"
        );
        assert!(!report.stopped && report.more, "{report:?}");
        let marks = b.app.reader().scan_raw("rcread/").await.unwrap();
        assert!(marks.is_empty(), "the upload's mark was read");
        b.finish().await;
    });
}

#[test]
fn test_order_model_one_protocol_failing_a_call_holds_the_read() {
    // One protocol: an upload marks its record, and a re-send call after it fails. As
    // long as it fails the call, no read goes on: the record marked is not read again,
    // though the feed has nothing after the call. Once it takes the call, it is.
    on_a_thread(async {
        let mut b = Bench::new(1, 100).await;
        b.upload("tasks");
        b.model("tasks").failing.lock().unwrap().push(Call::Resend);
        let resend = b.unopenable();
        for _ in 0..3 {
            let report = b.read().await;
            assert!(report.stopped, "{report:?}");
        }
        assert_eq!(b.taken("tasks"), (vec![], Some(resend)));
        let marks = b.app.reader().scan_raw("rcread/").await.unwrap();
        assert!(
            !marks.is_empty(),
            "the upload's mark is read while the call fails"
        );
        b.model("tasks").failing.lock().unwrap().clear();
        b.quiet(false).await;
        let marks = b.app.reader().scan_raw("rcread/").await.unwrap();
        assert!(marks.is_empty(), "the upload's mark was read");
        b.finish().await;
    });
}

/// Key bundle parts for the app of `cert`, through the current data epoch, stored at the
/// switch as the signer stores them.
fn store_parts_for(b: &Bench, cert: &AppCert) {
    let names = b.names.clone();
    let has_keys = move |scope: &str| names.iter().any(|name| scope_of(name) == scope);
    let epoch = b.w.switch.identity_doc().unwrap().data_epoch();
    for part in seal_bundle_parts(&b.w.alice, cert, 1, epoch, &has_keys).unwrap() {
        b.w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: cert.app_id(),
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
}

/// Whether the app holds the record at `key` with its value open.
async fn opened(b: &Bench, key: &[u8; 32]) -> bool {
    let held = b.app.shared_record(key).await.unwrap().unwrap();
    held.content.value().is_some()
}

#[test]
fn test_order_model_record_a_key_opens_waits_for_its_protocol_behind_the_read() {
    // The app holds a record of `tasks` it can't open yet: the data epoch rose, and only
    // the phone has the new keys. `tasks` then fails a re-send call `chat` goes past, and
    // the app's key comes while `tasks` is behind: the record stays unopened until `tasks`
    // takes the call and is with the read again.
    on_a_thread(async {
        let mut b = Bench::new(2, 100).await;
        b.w.next_doc(|body| body.data_epoch = 2);
        let phone_cert = b.phone.cert().clone();
        store_parts_for(&b, &phone_cert);
        b.phone.receive(None).await.unwrap();
        b.phone_writes("tasks").await;
        b.quiet(false).await;
        let w1 = b
            .app
            .record_key(&RecordTarget::new(list_of("tasks"), b"w1"))
            .unwrap();
        assert!(!opened(&b, &w1).await, "the app lacks the key");
        b.model("tasks").failing.lock().unwrap().push(Call::Resend);
        let resend = b.unopenable();
        b.quiet(false).await;
        assert_eq!(b.taken("tasks"), (vec![], Some(resend)));
        let app_cert = b.app.cert().clone();
        store_parts_for(&b, &app_cert);
        b.entry("chat", "item");
        b.quiet(false).await;
        assert!(b.app.scope_key(2, "tasks").is_some(), "the key was taken");
        assert!(
            !opened(&b, &w1).await,
            "the record of `tasks` opened while `tasks` fails its call"
        );
        b.model("tasks").failing.lock().unwrap().clear();
        b.quiet(false).await;
        assert!(opened(&b, &w1).await);
        assert_eq!(b.taken("tasks").0, [resend]);
        b.finish().await;
    });
}

#[test]
fn test_order_model_protocol_stuck_past_a_held_entry_lets_the_other_go_on() {
    // An entry of `chat` from carol, who has no `identity.json` on the Homeserver, is held
    // for its sender's check, so the cursor stays before it. `tasks` fails a re-send call
    // after it: `tasks` can't move until a read's start tells it the call, so no read
    // walks again from its position, and `chat` gets its thirty entries in reads of
    // one-item pages that each go on from where the one before got.
    on_a_thread(async {
        let mut b = Bench::new(2, 1).await;
        let carol = identity("carol");
        let carol_key = IdentityKey::from_secret(carol.key().secret_bytes());
        let carol_keys = carol.app_keys("x");
        let now = b.w.clock.now_ms();
        let carol_cert = cert_for(carol.key(), &carol_keys, now - 1000, &["chat"]);
        let me = b.app.app_id();
        b.tick();
        b.w.switch
            .send(
                &carol_key,
                &carol_keys,
                &carol_cert,
                "chat.item",
                json!({ "text": "carol" }),
                &[me],
            )
            .unwrap();
        b.model("tasks").failing.lock().unwrap().push(Call::Resend);
        let resend = b.unopenable();
        let chat: Vec<u64> = (0..30).map(|_| b.entry("chat", "item")).collect();
        let mut reads = 0;
        while b.read().await.more {
            reads += 1;
            assert!(reads < 20, "the reads never get to the feed's end");
        }
        assert_eq!(b.taken("tasks"), (vec![], Some(resend)));
        let took = b.taken("chat").0;
        assert!(
            took.ends_with(&chat),
            "`chat` took its thirty entries: {took:?}"
        );
    });
}

async fn committed_items(b: &Bench, name: &str) -> Vec<u64> {
    let mut seqs: Vec<u64> = b
        .app
        .protocol_scan(name, b"took/")
        .await
        .unwrap()
        .into_iter()
        .map(|kv| {
            let key = String::from_utf8(kv.0.clone()).unwrap();
            key.trim_start_matches("took/").parse::<u64>().unwrap()
        })
        .collect();
    seqs.sort_unstable();
    seqs
}

async fn check_committed_prefix(b: &Bench, n: u64, at: &str) {
    for name in &b.names {
        let got = committed_items(b, name).await;
        let feed = &b.feed[name];
        assert!(
            got.len() <= feed.len() && feed[..got.len()] == got[..],
            "crash {n} {at}: `{name}` committed {got:?}, not a prefix of {feed:?}"
        );
    }
}

async fn crash_run(n: u64, recover_before: bool) -> bool {
    let mut b = Bench::new(2, 2).await;
    for model in &b.models {
        *model.committed_store.lock().unwrap() = Some((
            Arc::clone(&b.store) as Arc<dyn StateStore>,
            b.app.ns.clone(),
        ));
    }
    b.model("tasks").failing.lock().unwrap().push(Call::Missed);
    b.missed();
    b.entry("tasks", "item");
    for _ in 0..5 {
        b.entry("chat", "item");
    }
    b.phone_writes("tasks").await;
    b.unopenable();
    b.entry("tasks", "item");
    b.deny().await;
    b.entry("chat", "item");
    b.entry("tasks", "write");
    b.missed();
    b.entry("chat", "item");
    b.app.receive(None).await.unwrap();
    check_committed_prefix(&b, n, "first read").await;
    if recover_before {
        b.model("tasks").failing.lock().unwrap().clear();
    }
    let fault = Arc::new(crate::store::FaultStore::new(
        Arc::clone(&b.store) as Arc<dyn StateStore>,
        crate::store::Fault::StopAfter(n),
    ));
    let me = b.app.app_id();
    let loaded = App::load(
        b.w.env_on(Arc::clone(&fault) as Arc<dyn StateStore>),
        set_of(&b.models),
        b.config.clone(),
        me,
    )
    .await;
    if let Ok(app) = loaded {
        b.app = app;
        for _ in 0..30 {
            if b.app.receive(None).await.is_err() {
                break;
            }
            if !recover_before {
                b.model("tasks").failing.lock().unwrap().clear();
            }
        }
    }
    let stopped = fault.stopped();
    b.reopen().await;
    check_committed_prefix(&b, n, "after the restart").await;
    b.model("tasks").failing.lock().unwrap().clear();
    for _ in 0..40 {
        b.app.receive(None).await.unwrap();
        check_committed_prefix(&b, n, "after a read").await;
    }
    for name in b.names.clone() {
        assert_eq!(
            committed_items(&b, &name).await,
            b.feed[&name],
            "crash {n}: `{name}` took everything once"
        );
        let dups = b.model(&name).repeated_committed.lock().unwrap().clone();
        assert!(
            dups.is_empty(),
            "crash {n}: `{name}` handed again after its commit: {dups:?}"
        );
    }
    assert_eq!(b.app.owed_protocol_calls().await.unwrap(), 0);
    stopped
}

#[test]
fn test_order_model_crashes_preserve_every_protocols_committed_prefix() {
    on_a_thread(async {
        for recover_before in [true, false] {
            let mut reached_end = false;
            for n in 1..=400 {
                if !Box::pin(crash_run(n, recover_before)).await {
                    reached_end = true;
                    break;
                }
            }
            assert!(reached_end, "the sweep covers every commit");
        }
    });
}
