//! Moves, provider loss, revocation and erasure against scripted Dispatches: the old service,
//! and the next one, reached by origin through one transport.

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use pubky_dispatch_core::admission::PeerReason;
use pubky_dispatch_core::chain::ItemType;
use pubky_dispatch_core::http::ErrorCode;
use pubky_dispatch_core::ops::OpKind;
use pubky_dispatch_core::records::{
    CLOCK_TOLERANCE_MS, DAY_MS, Freeze, FreezeBody, IDENTITY_PATH, RemovedApp,
};
use pubky_dispatch_core::scopes::Permission;
use pubky_dispatch_core::sig::SignedDoc;

use super::*;
use crate::app::{
    AppBackup, AppError, AppEvent, ClaimOp, Collection, Evidence, LocalWrite, LossActions,
    MAX_STEP_LOCAL_BYTES, ObligationDeadline, ParkReason, ProviderLoss, ProviderStatus, PushRelay,
    Refusal, RefusedCall, UserConfirmed, Woken,
};
use crate::error::TransportError;
use crate::error::{ClientError, StoreError};
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::{self, DISPATCH_ORIGIN as ORIGIN, Fault, Item};

/// The next service's origin.
pub(crate) const NEXT: &str = "https://next.example";

pub(crate) fn has(events: &[AppEvent], pred: impl Fn(&AppEvent) -> bool) -> bool {
    events.iter().any(pred)
}

fn received(events: &[AppEvent], seq: u64) -> bool {
    has(
        events,
        |e| matches!(e, AppEvent::MessageReceived { seq: s, .. } if *s == seq),
    )
}

/// The public router, with the Dispatches of this account by origin.
#[derive(Clone)]
pub(crate) struct Router(Arc<testing::Router>);

impl Router {
    pub(crate) fn of(w: &World) -> Self {
        let router = testing::Router::new();
        router.add_dispatch(ORIGIN, &w.dispatch);
        Self(Arc::new(router))
    }

    /// Route `origin` to `dispatch`, in place of any Dispatch routed there.
    pub(crate) fn add(&self, origin: &str, dispatch: &Arc<ScriptedDispatch>) {
        self.0.add_dispatch(origin, dispatch);
    }

    /// Route `origin` to `transport`, in place of any Dispatch routed there.
    pub(crate) fn add_transport(
        &self,
        origin: &str,
        transport: Arc<dyn crate::transport::Transport>,
    ) {
        self.0.add(origin, transport);
    }

    /// Route nothing to `origin` any more: its service is unreachable.
    pub(crate) fn remove(&self, origin: &str) {
        self.0.remove(origin);
    }

    /// Fail every feed read after the next `reads`, so a read that never ends fails.
    pub(crate) fn limit_feeds(&self, reads: u64) {
        self.0.limit_feeds(reads);
    }

    /// Every request sent, as `"METHOD origin path"`, in order.
    pub(crate) fn log(&self) -> Vec<String> {
        self.0.log()
    }

    pub(crate) fn env(&self, w: &World, store: Arc<dyn StateStore>) -> AppEnv {
        w.signer.env_with(
            store,
            Arc::clone(&self.0) as Arc<dyn crate::transport::Transport>,
        )
    }
}

/// The sample protocol, also recording provider losses and naming bob for a reply grant
/// entry after one.
#[derive(Default)]
pub(crate) struct LossProtocol {
    /// Its name; `sample` when `None`.
    pub(crate) name: Option<&'static str>,
    pub(crate) sample: SampleProtocol,
    pub(crate) losses: Mutex<Vec<ProviderLoss>>,
    /// Current coverage and divergence for the record reads a test follows.
    pub(crate) observed_records: Mutex<Option<Vec<(bool, bool)>>>,
    pub(crate) counterparties: Vec<[u8; 32]>,
    /// How many of the next loss calls fail, as when the protocol can't read its state.
    pub(crate) failing: Mutex<u32>,
    /// The size of the value the loss call writes; one byte when zero.
    pub(crate) local_bytes: Mutex<usize>,
    /// The protocol's collections; none unless a test sets them.
    pub(crate) collections: Mutex<Vec<Collection>>,
}

impl Protocol for LossProtocol {
    fn observe_record(
        &self,
        observed: &crate::app::RecordObservation<'_>,
        _: &crate::app::ReceiveContext<'_>,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        if let Some(reads) = self.observed_records.lock().unwrap().as_mut() {
            reads.push((observed.current, observed.record.divergent));
        }
        Ok(Vec::new())
    }

    fn name(&self) -> String {
        self.name.unwrap_or("sample").into()
    }

    fn collections(&self) -> Vec<Collection> {
        self.collections.lock().unwrap().clone()
    }

    fn has_keys(&self, scope: &str) -> bool {
        // A protocol of another name has keys for the scope of its name.
        match self.name {
            Some(name) => scope == name,
            None => self.sample.has_keys(scope),
        }
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.sample.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.sample.accepts(cert)
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }

    fn receive(
        &self,
        message: &ReceivedMessage,
        cx: &mut crate::app::ReceiveContext<'_>,
    ) -> Outcome {
        self.sample.receive(message, cx)
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.missed(missed)
    }

    fn provider_lost(
        &self,
        loss: &ProviderLoss,
        _: &crate::app::LocalView<'_>,
    ) -> Result<LossActions, crate::app::StoreFailure> {
        {
            let mut failing = self.failing.lock().unwrap();
            if *failing > 0 {
                *failing -= 1;
                return Err(StoreError::Unavailable.into());
            }
        }
        self.losses.lock().unwrap().push(*loss);
        let bytes = (*self.local_bytes.lock().unwrap()).max(1);
        Ok(LossActions {
            reply_peers: self.counterparties.clone(),
            local: vec![LocalWrite::Put {
                key: format!("lost/{}", loss.lost_generation).into_bytes(),
                value: vec![b'1'; bytes],
            }],
        })
    }
}

/// The signer approves the wallet's keys for `sample-a` with `permissions`.
pub(crate) fn approve_with(w: &World, permissions: &[Permission]) -> JoinRequest {
    let app = AppSpec::new(&["sample-a"]).with_permissions(permissions);
    w.signer.approve(&app_keys("wallet"), &app).unwrap()
}

pub(crate) async fn join_on(
    w: &World,
    router: &Router,
    store: Arc<dyn StateStore>,
    protocol: Arc<dyn Protocol>,
    permissions: &[Permission],
) -> App {
    App::join(
        router.env(w, store),
        protocol,
        World::config(),
        approve_with(w, permissions),
    )
    .await
    .unwrap()
}

pub(crate) async fn join(w: &World, router: &Router) -> App {
    join_on(
        w,
        router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ReplyAdd],
    )
    .await
}

pub(crate) fn next_key() -> SigningKey {
    SigningKey::from_bytes(&seed("service/alice/next"))
}

/// The signer's freeze naming the next service at `NEXT`.
pub(crate) fn freeze_for(w: &World, next: &SigningKey, next_generation: u64) -> Freeze {
    Freeze::sign(
        &w.alice,
        FreezeBody {
            identity: w.alice.public(),
            inbox: Inbox::new(NEXT, next.verifying_key().to_bytes()),
            next_generation,
            issued_at: w.clock.now_ms(),
            nonce: [next_generation as u8; 16],
        },
    )
    .unwrap()
}

/// The signer delivers alice's next version naming `inbox` at `generation` to `to`, and
/// publishes it.
pub(crate) fn publish_at(
    w: &World,
    to: &ScriptedDispatch,
    inbox: Inbox,
    generation: u64,
    recovery_from: Option<u64>,
) -> IdentityDoc {
    let doc = w
        .signer
        .sign_next(|body| {
            body.generation = generation;
            body.inbox = inbox;
            body.recovery_from = recovery_from;
        })
        .unwrap();
    to.deliver_identity(&doc).unwrap();
    doc
}

/// The transition proof of the first chain item the app wrote at `dispatch`.
fn first_proof(dispatch: &ScriptedDispatch) -> SignedDoc {
    dispatch
        .lock()
        .items
        .iter()
        .find_map(|item| match item {
            Item::Chain {
                item_type: ItemType::Op,
                proof: Some(proof),
                ..
            } => Some(proof.clone()),
            _ => None,
        })
        .unwrap()
}

pub(crate) fn note_at(w: &World, dispatch: &ScriptedDispatch, to: [u8; 16], text: &str) -> u64 {
    dispatch
        .send(
            &w.bob,
            &w.bob_keys,
            &w.bob_cert,
            "sample.note",
            json!({ "text": text }),
            &[to],
        )
        .unwrap()
        .0
}

pub(crate) fn reply_grants_at(dispatch: &ScriptedDispatch) -> usize {
    dispatch
        .applied()
        .iter()
        .filter(|op| {
            matches!(
                op.body().kind,
                OpKind::AllowPut {
                    reason: PeerReason::Reply,
                    ..
                }
            )
        })
        .count()
}

// -------------------------------------------------------------------------------------
// Cooperative move (Dispatch spec 12.5)

#[tokio::test]
async fn test_move_followed_from_a_frozen_feed() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let seq = w.note(me, "before").0;
    assert!(received(&app.receive(None).await.unwrap().events, seq));
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    // The signer freezes the old service; the next one imports the account, staged.
    let n_key = next_key();
    let freeze = freeze_for(&w, &n_key, 2);
    w.dispatch.freeze(&freeze).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Moved)));
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::EvidenceUploaded {
            heads: 1,
            proofs: 1
        }
    )));
    // The staged upload carried the newest head and the old service's proof, with the
    // app's certificate.
    let uploads = next.uploads();
    assert_eq!(uploads.len(), 1);
    assert!(uploads[0].1);
    let head = &uploads[0].0["heads"][0];
    assert_eq!(head["seq"].as_u64(), Some(w.dispatch.tip_seq()));
    assert_eq!(app.cursor().generation, 1);
    // Waiting changes nothing until the move is published.
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert_eq!(next.uploads().len(), 1);
    // The signer publishes generation 2 naming the next service.
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(!report.stopped, "{:?}", report.events);
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    assert_eq!(app.cursor().generation, 2);
    assert_eq!(app.own_identity().generation(), 2);
    // The record and the current key went to the next service at generation 2: the bytes
    // it imported, so the batch chains nothing (Dispatch wire 6.4 "No-ops").
    assert_eq!(next.app(&me).receive_key, w.dispatch.app(&me).receive_key);
    let ops_at_next = format!("POST {NEXT} /v1/{}/ops", w.alice.id());
    assert!(
        router.0.log().contains(&ops_at_next),
        "{:?}",
        router.0.log()
    );
    // The old service's proofs went again once the move was published, without the cert.
    let uploads = next.uploads();
    assert_eq!(uploads.len(), 2);
    assert!(!uploads[1].1);
    // A note at the next service is received; the chain view carried across.
    let seq = note_at(&w, &next, me, "after");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(reply_grants_at(&next), 1);
    assert!(app.alarm().is_none());
    // Without list permissions the app doesn't compare the lists.
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::ListsDiffer { .. }
    )));
}

#[tokio::test]
async fn test_move_followed_from_a_410_answer() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // A note waits in the feed. The page is read before the account is frozen, and the
    // freeze lands before the note's effect is written, so the app learns of it from the
    // effect's `410 moved`.
    w.note(me, "before");
    let n_key = next_key();
    let freeze = freeze_for(&w, &n_key, 2);
    let imported = Arc::new(Mutex::new(None));
    let (dispatch, held, routes) = (w.dispatch.clone(), Arc::clone(&imported), router.clone());
    let secret = n_key.to_bytes();
    router.add_transport(
        ORIGIN,
        Arc::new(crate::transport::MockTransport::with_handler(
            move |request| {
                let mut held = held.lock().unwrap();
                if request.path_and_query.contains("/ops") && held.is_none() {
                    dispatch.freeze(&freeze).unwrap();
                    let next = dispatch.import_into(secret);
                    routes.add(NEXT, &next);
                    *held = Some(next);
                }
                drop(held);
                dispatch.handle(request)
            },
        )),
    );
    let report = app.receive(None).await.unwrap();
    let next = imported.lock().unwrap().clone().unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Moved)));
    assert_eq!(next.uploads().len(), 1);
    // Nothing was applied at the frozen service.
    assert_eq!(w.effects(), 0);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    // The note is processed at the next service, which imported it.
    assert_eq!(reply_grants_at(&next), 1);
}

#[tokio::test]
async fn test_move_check_uses_the_signed_feed_when_public_time_is_stale() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    w.dispatch.lock().clock =
        Arc::new(crate::clock::TestClock::new(w.clock.now_ms() + 20 * 60_000));
    assert_eq!(app.check_for_move().await.unwrap(), ProviderStatus::Current);
    w.dispatch.fail_next(Fault::Unanswered {
        path: "/feed".into(),
        after: 0,
    });
    assert!(app.check_for_move().await.is_err());
}

#[tokio::test]
async fn test_move_found_through_the_public_read() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let n_key = next_key();
    let freeze = freeze_for(&w, &n_key, 2);
    w.dispatch.freeze(&freeze).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    assert_eq!(
        app.check_for_move().await.unwrap(),
        ProviderStatus::AwaitingMove { next_generation: 2 }
    );
    assert_eq!(next.uploads().len(), 1);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Followed { generation: 2 }
    );
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
}

#[tokio::test]
async fn test_move_refuses_a_forged_freeze() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let next = w.dispatch.import_into(next_key().to_bytes());
    router.add(NEXT, &next);
    // A freeze bob's key signed, for bob's identity: not alice's.
    let forged = Freeze::sign(
        &w.bob,
        FreezeBody {
            identity: w.bob.public(),
            inbox: Inbox::new(NEXT, next_key().verifying_key().to_bytes()),
            next_generation: 2,
            issued_at: START,
            nonce: [9; 16],
        },
    )
    .unwrap();
    w.note(me, "hello");
    w.dispatch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Moved,
        current: json!({ "freeze": forged.signed() }),
    });
    let error = app.receive(None).await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // Nothing was followed: no upload, and the app reads on at its service.
    assert!(next.uploads().is_empty());
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
    app.receive(None).await.unwrap();
    assert_eq!(w.effects(), 1);
    // A freeze that skips a generation is refused too, though alice signed it.
    let skipping = freeze_for(&w, &next_key(), 3);
    w.dispatch.freeze(&skipping).unwrap();
    let error = app.check_for_move().await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    assert!(next.uploads().is_empty());
}

#[tokio::test]
async fn test_move_cancelled_by_an_unfreeze_stays() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let n_key = next_key();
    let freeze = freeze_for(&w, &n_key, 2);
    w.dispatch.freeze(&freeze).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    // The signer aborts: the old service resumes.
    w.dispatch.unfreeze(&freeze).unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::MoveCancelled
    )));
    let seq = w.note(me, "still here").0;
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(app.cursor().generation, 1);
}

/// The Dispatch's answer to the public read now (Dispatch wire 7.4.15), as an on-path party
/// keeps it.
fn public_read_now(w: &World) -> crate::transport::Response {
    w.dispatch
        .handle(&crate::transport::Request {
            method: "GET".into(),
            origin: ORIGIN.into(),
            path_and_query: format!(
                "/v1/{}/identity",
                pubky_dispatch_core::enc::pubky_id(&w.alice.public())
            ),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: crate::transport::TimeoutClass::Bulk,
        })
        .unwrap()
}

/// Route [`ORIGIN`] through an on-path party that answers every public read with `kept`, an
/// earlier answer sent again, and passes every other request on to the Dispatch. The public
/// read binds no header and no timestamp, so `kept` verifies for each of them (Dispatch wire
/// 7.1 "Identical requests").
fn replay_public_read(w: &World, router: &Router, kept: crate::transport::Response) {
    let dispatch = w.dispatch.clone();
    router.add_transport(
        ORIGIN,
        Arc::new(crate::transport::MockTransport::with_handler(
            move |request| {
                if pubky_dispatch_core::http::is_public_read(
                    &request.method,
                    &request.path_and_query,
                ) {
                    Ok(kept.clone())
                } else {
                    dispatch.handle(request)
                }
            },
        )),
    );
}

/// The app frozen at its service with a move to [`NEXT`] under way, waiting for it to be
/// published (`MoveStep::Uploaded`); with the freeze, and the public read's answers from
/// before the freeze and while frozen.
async fn waiting_for_the_move(
    w: &World,
    router: &Router,
) -> (
    App,
    Freeze,
    crate::transport::Response,
    crate::transport::Response,
) {
    let mut app = join(w, router).await;
    let before = public_read_now(w);
    let n_key = next_key();
    let freeze = freeze_for(w, &n_key, 2);
    w.dispatch.freeze(&freeze).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::AwaitingMove { next_generation: 2 }
    );
    let during = public_read_now(w);
    (app, freeze, before, during)
}

async fn holds_a_move(app: &App) -> bool {
    app.reader()
        .exists(crate::app::provider::keys::MOVE)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_public_read_replayed_without_freeze_cancels_no_move() {
    // An answer from before the freeze, sent again, carries no freeze: it shows nothing about
    // the account now, so the move stays (Dispatch wire 7.1 "Identical requests").
    let w = World::new();
    let router = Router::of(&w);
    let (mut app, _, before, _) = waiting_for_the_move(&w, &router).await;
    replay_public_read(&w, &router, before);
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::AwaitingMove { next_generation: 2 }
    );
    assert!(holds_a_move(&app).await);
}

#[tokio::test]
async fn test_public_read_replayed_with_freeze_hides_no_cancellation() {
    // The signer aborts while the public read still answers as when frozen: the own feed's
    // signed word, which carries no freeze any more, is the one taken (Dispatch wire 7.3 step 8).
    let w = World::new();
    let router = Router::of(&w);
    let (mut app, freeze, _, during) = waiting_for_the_move(&w, &router).await;
    w.dispatch.unfreeze(&freeze).unwrap();
    replay_public_read(&w, &router, during);
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::MoveCancelled
    );
    assert!(!holds_a_move(&app).await);
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
}

#[tokio::test]
async fn test_public_read_replayed_from_an_aborted_move_starts_none() {
    // An app that never saw the freeze meets the aborted move's answer sent again: the own
    // feed carries no freeze, so no move starts and nothing goes to the next service.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let n_key = next_key();
    let freeze = freeze_for(&w, &n_key, 2);
    w.dispatch.freeze(&freeze).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    let during = public_read_now(&w);
    w.dispatch.unfreeze(&freeze).unwrap();
    replay_public_read(&w, &router, during);
    assert_eq!(app.check_for_move().await.unwrap(), ProviderStatus::Current);
    assert!(!holds_a_move(&app).await);
    assert!(next.uploads().is_empty());
    assert_eq!(app.cursor().generation, 1);
}

/// Each way the own feed's signed page with no items can fail: no answer, an answer the
/// pinned key didn't sign, a `503` and a `429`.
fn failed_signed_reads() -> Vec<Fault> {
    let path = || "limit=0".to_owned();
    vec![
        Fault::Unanswered {
            path: path(),
            after: 0,
        },
        Fault::SignWith {
            path: path(),
            secret: [42; 32],
        },
        Fault::Error {
            path: path(),
            code: ErrorCode::Unavailable,
            current: serde_json::Value::Null,
        },
        Fault::Error {
            path: path(),
            code: ErrorCode::RateLimited,
            current: serde_json::Value::Null,
        },
    ]
}

#[tokio::test]
async fn test_public_read_failed_signed_read_decides_nothing() {
    // A signed read that fails shows neither a freeze nor its absence: a move waiting to be
    // published, though since cancelled, isn't given up, and one the public read shows isn't
    // started; the next check asks again and decides (Dispatch spec 12.5).
    for fault in failed_signed_reads() {
        let w = World::new();
        let router = Router::of(&w);
        let (mut app, freeze, _, _) = waiting_for_the_move(&w, &router).await;
        w.dispatch.unfreeze(&freeze).unwrap();
        w.dispatch.fail_next(fault.clone());
        assert_eq!(
            app.follow_provider().await.unwrap(),
            ProviderStatus::AwaitingMove { next_generation: 2 },
            "{fault:?}"
        );
        assert!(holds_a_move(&app).await, "{fault:?}");
        assert_eq!(
            app.follow_provider().await.unwrap(),
            ProviderStatus::MoveCancelled,
            "{fault:?}"
        );

        let w = World::new();
        let router = Router::of(&w);
        let mut app = join(&w, &router).await;
        let n_key = next_key();
        w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
        router.add(NEXT, &w.dispatch.import_into(n_key.to_bytes()));
        w.dispatch.fail_next(fault.clone());
        let checked = app.check_for_move().await;
        assert!(checked.is_err(), "{fault:?}: {checked:?}");
        assert!(!holds_a_move(&app).await, "{fault:?}");
        assert_eq!(
            app.check_for_move().await.unwrap(),
            ProviderStatus::AwaitingMove { next_generation: 2 },
            "{fault:?}"
        );
    }
}

#[tokio::test]
async fn test_move_import_conflict_is_reported_and_the_move_goes_on() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    next.fail_next(Fault::Error {
        path: "recovery/upload".into(),
        code: ErrorCode::Conflict,
        current: json!({ "conflicts": ["a head the import doesn't extend"] }),
    });
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::EvidenceRefused { code } if code == "conflict"
    )));
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Followed { generation: 2 }
    );
}

#[tokio::test]
async fn test_move_compares_the_admission_lists() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[
            Permission::ListsRead,
            Permission::ListsManage,
            Permission::ReplyAdd,
        ],
    )
    .await;
    let me = app.app_id();
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let erin = IdentityKey::from_secret(seed("erin/identity")).public();
    let phone = w.other_app("phone", &[Permission::ListsManage]);
    w.dispatch
        .app_op(
            &phone,
            OpKind::AllowPut {
                pubky: carol,
                reason: PeerReason::Kept,
            },
        )
        .unwrap();
    app.receive(None).await.unwrap();
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    // A faulty export: carol is gone, erin was never added, and an invite code in this
    // app's name that it never registered.
    let planted = [1u8; 32];
    next.lock().shared.plant_invite(planted, 1, me);
    next.lock().allow = Some(json!({
        "peers": [{"pubky": pubky_dispatch_core::enc::pubky_id(&erin), "kept": true, "reply": null}], "deny": [], "flagged": [],
        "invite_codes": [{ "code_hash": pubky_dispatch_core::enc::b64(&planted),
                           "expires_at": "2026-02-01T00:00:00.000Z", "max_uses": 1, "uses": 0,
                           "written_by": pubky_dispatch_core::enc::zbase32_encode(&me) }],
    }));
    app.receive(None).await.unwrap();
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::ListsDiffer {
                added: 1,
                unverified_kept_peers: 1,
                withdrawn_codes: 1
            }
        )),
        "{:?}",
        report.events
    );
    let applied = next.applied();
    assert!(applied.iter().any(|op| matches!(
        op.body().kind,
        OpKind::AllowPut { pubky, reason: PeerReason::Kept } if pubky == carol
    )));
    assert!(applied.iter().any(|op| matches!(
        op.body().kind,
        OpKind::InviteCodeDelete { code_hash } if code_hash == planted
    )));
    // Erin is shown, not removed.
    assert!(
        !applied
            .iter()
            .any(|op| matches!(op.body().kind, OpKind::AllowDelete { .. }))
    );
}

#[tokio::test]
async fn test_sender_disposition_move_keeps_the_flags_and_the_refresh_time() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsRead, Permission::ReplyAdd],
    )
    .await;
    w.dispatch.lock().shared.flagged.insert(FLAGGED, 3);
    app.receive(None).await.unwrap();
    let before = lists_copy_in(&w.store);
    assert!(before.0 && before.1.is_some());
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    w.clock.advance_ms(60_000);
    app.receive(None).await.unwrap();
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    // The export carried the flags: the copy stays as it was, refreshed no sooner.
    assert_eq!(lists_copy_in(&w.store), before);
}

#[tokio::test]
async fn test_move_registers_again_a_key_the_next_service_rolled_back() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let first = w.dispatch.app(&me).receive_key.clone();
    w.note(me, "one");
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    assert_eq!(w.dispatch.app(&me).receive_n, Some(1));
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    // The export shows the app's older key as current, and its kid index holds that key's
    // kid alone.
    let first_kid = first.as_ref().map(|record| {
        let value: serde_json::Value = record.peek().unwrap();
        pubky_dispatch_core::enc::unb64_array::<8>(value["kid"].as_str().unwrap()).unwrap()
    });
    {
        let mut inner = next.lock();
        let held = inner.apps.get_mut(&me).unwrap();
        held.receive_key = first;
        held.receive_n = Some(0);
        inner.kids.retain(|kid, _| Some(*kid) == first_kid);
    }
    app.receive(None).await.unwrap();
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::ReceiveKeyRolledBack {
                shown: 0,
                current: 1
            }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(next.app(&me).receive_n, Some(1));
}

#[tokio::test]
async fn test_move_next_service_showing_a_foreign_key_is_a_compromise() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let registered_at = w.clock.now_ms();
    // The freeze, an hour later, is the newest chain item the app verifies at the old
    // service.
    w.clock.advance_ms(3_600_000);
    let frozen_at = w.clock.now_ms();
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    // A key signed with the app's signing key that no device of the app made.
    let thief = pubky_dispatch_core::keys::ReceiveKey::generate(1).unwrap();
    let record = pubky_dispatch_core::records::ReceiveKeyRecord::sign(
        &app_keys("wallet"),
        app.cert(),
        pubky_dispatch_core::records::ReceiveKeyBody::new(app.cert(), &thief),
    )
    .unwrap();
    {
        let mut inner = next.lock();
        let held = inner.apps.get_mut(&me).unwrap();
        held.receive_key = Some(record.signed().clone());
        held.receive_n = Some(1);
    }
    app.receive(None).await.unwrap();
    w.clock.advance_ms(3_600_000);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Alarm(crate::app::Alarm::Compromise { n: 1, .. })
        ),
        "{error:?}"
    );
    // Without the registration's chain item, it distrusts from the later of the newest
    // chain item it verified, the freeze, and its own last registration (Dispatch spec 3.6).
    assert!(registered_at < frozen_at);
    assert_eq!(app.compromise_distrust_from(), Some(frozen_at));
    // It left at once, at the service it follows.
    assert!(next.app(&me).departed);
}

#[tokio::test]
async fn test_key_change_in_place_is_followed_without_a_freeze() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // The same origin under a new key at generation 2: nothing exported, the chain goes on.
    let pending = SigningKey::from_bytes(&seed("service/alice/pending"));
    let changed = w.dispatch.import_into(pending.to_bytes());
    router.add(ORIGIN, &changed);
    publish_at(
        &w,
        &changed,
        Inbox::new(ORIGIN, pending.verifying_key().to_bytes()),
        2,
        None,
    );
    let seq = note_at(&w, &changed, me, "after the change");
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(app.cursor().generation, 2);
}

#[tokio::test]
async fn test_move_with_kept_batches_at_the_cap_completes() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsManage, Permission::ReplyAdd],
    )
    .await;
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    // While frozen every batch is kept: each with 3.5 MiB of local writes, 4.7 MiB kept,
    // 33 MiB for seven, more than the switch's one commit takes. Two fit the cap; the
    // others are refused, not kept.
    let mut results = Vec::new();
    for n in 0..7u8 {
        let batch = crate::app::OpBatch::for_protocol("sample")
            .op(OpKind::AllowPut {
                pubky: [n + 40; 32],
                reason: PeerReason::Kept,
            })
            .local(LocalWrite::Put {
                key: format!("big/{n}").into_bytes(),
                value: vec![123u8; (7 << 20) / 2],
            });
        results.push(app.submit_batch(batch).await.unwrap_err());
    }
    assert_eq!(results[0].code(), Some(ErrorCode::Moved));
    assert_eq!(results[1].code(), Some(ErrorCode::Moved));
    for refused in &results[2..] {
        assert!(
            matches!(refused, AppError::Refused(Refusal::NotNow(why)) if why.contains("not kept")),
            "{refused:?}"
        );
    }
    assert_eq!(app.kept_batches().await.unwrap().len(), 2);
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    app.receive(None).await.unwrap();
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    // The switch's one commit carries both kept batches; the move completes.
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    app.receive(None).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    for n in 0..2u8 {
        assert!(next.applied().iter().any(|op| matches!(
            op.body().kind,
            OpKind::AllowPut { pubky, .. } if pubky == [n + 40; 32]
        )));
    }
}

#[tokio::test]
async fn test_lists_too_large_refresh_is_tried_again_after_a_provider_loss() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // The copy was refused as too large just before the loss.
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    let mut batch = crate::store::WriteBatch::new();
    batch
        .put(
            &ns,
            b"lc/too_large".to_vec(),
            crate::app::state::encode(&lost.w.clock.now_ms()).unwrap(),
        )
        .unwrap();
    store.commit(batch).unwrap();
    let (mut app, _) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert_eq!(app.cursor().generation, 2);
    app.receive(None).await.unwrap();
    // The loss let the refresh go: the copy is read from the new service.
    assert!(store.get(&ns, b"lc/too_large").unwrap().is_none());
    assert!(store.get(&ns, b"lc/lists_at").unwrap().is_some());
}

#[tokio::test]
async fn test_lists_too_large_refresh_is_tried_again_after_a_provider_change() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsRead, Permission::ReplyAdd],
    )
    .await;
    let ns = crate::store::client_namespace(&app.app_id());
    let held = |key: &[u8]| w.store.get(&ns, key).unwrap().is_some();
    {
        let mut dispatch = w.dispatch.lock();
        for n in 0..310_000u32 {
            let mut pubky = [9u8; 32];
            pubky[..4].copy_from_slice(&n.to_be_bytes());
            dispatch.shared.flagged.insert(pubky, 3);
        }
    }
    app.receive(None).await.unwrap();
    assert!(held(b"lc/too_large") && !held(b"lc/lists_at"));
    // A key change in place; the lists fit at the new service.
    let pending = SigningKey::from_bytes(&seed("service/alice/pending"));
    let changed = w.dispatch.import_into(pending.to_bytes());
    changed.lock().shared.flagged.clear();
    router.add(ORIGIN, &changed);
    publish_at(
        &w,
        &changed,
        Inbox::new(ORIGIN, pending.verifying_key().to_bytes()),
        2,
        None,
    );
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    assert!(!held(b"lc/too_large"));
    assert!(held(b"lc/lists_at"));
}

/// Join and read at the old service, freeze it and import the account at the next one,
/// publish the move, and queue a note there: everything the follow then reads.
async fn moved_world(store: Arc<dyn StateStore>) -> (World, Router, Arc<ScriptedDispatch>, u64) {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        store,
        w.protocol.clone(),
        &[Permission::ReplyAdd],
    )
    .await;
    let me = app.app_id();
    w.note(me, "before");
    app.receive(None).await.unwrap();
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let seq = note_at(&w, &next, me, "after");
    (w, router, next, seq)
}

/// The follow: reads until the note at the next service is processed.
async fn follow_move(
    w: &World,
    router: &Router,
    store: Arc<dyn StateStore>,
) -> Result<(), AppError> {
    let mut app = App::load(
        router.env(w, store),
        w.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await?;
    app.receive(None).await?;
    app.receive(None).await?;
    Ok(())
}

#[tokio::test]
async fn test_move_keeps_an_owed_call_and_makes_it_at_the_next_service() {
    let store = Arc::new(MemoryStore::new());
    let (w, router, _next, _) = moved_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // A re-send call the protocol couldn't answer at generation 1.
    let mut app = App::load(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    let call = crate::app::feed::OwedCall::Resend {
        sender: w.bob.public(),
        accepted_from_ms: 5,
        accepted_until_ms: 6,
        unreadable: false,
    };
    let mut tx = app.tx().unwrap();
    tx.put(
        &crate::app::state::key::owed(1, 7),
        &(crate::app::feed::Owed {
            to: vec!["sample".into()],
            call,
        }),
    )
    .unwrap();
    app.commit(tx).await.unwrap();
    drop(app);
    follow_move(&w, &router, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let resends = w.protocol.resends.lock().unwrap().clone();
    assert!(
        resends.iter().any(|r| r.sender == w.bob.public()
            && r.accepted_from_ms == 5
            && r.accepted_until_ms == 6),
        "{resends:?}"
    );
    let app = App::load(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(app.cursor().generation, 2);
    assert!(app.reader().scan_raw("owed/").await.unwrap().is_empty());
}

#[tokio::test]
async fn test_move_crash_at_each_commit_point_resumes() {
    let counting_inner = Arc::new(MemoryStore::new());
    let (w, router, _, _) = moved_world(Arc::clone(&counting_inner) as Arc<dyn StateStore>).await;
    let counting = Arc::new(FaultStore::new(
        counting_inner as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    follow_move(&w, &router, Arc::clone(&counting) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let commits = counting.commits();
    assert!(commits > 5, "the follow commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let inner = Arc::new(MemoryStore::new());
            let (w, router, next, seq) =
                moved_world(Arc::clone(&inner) as Arc<dyn StateStore>).await;
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let first = follow_move(&w, &router, Arc::clone(&fault) as Arc<dyn StateStore>).await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            follow_move(&w, &router, Arc::clone(&inner) as Arc<dyn StateStore>)
                .await
                .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let app = App::load(
                router.env(&w, Arc::clone(&inner) as Arc<dyn StateStore>),
                w.protocol.clone(),
                World::config(),
                app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            assert_eq!(app.cursor().generation, 2, "commit {n} ({stop_after})");
            assert!(app.cursor().seq >= seq, "commit {n} ({stop_after})");
            // The note at the next service was applied once.
            assert_eq!(reply_grants_at(&next), 1, "commit {n} ({stop_after})");
            // Nothing was applied at the frozen service after the freeze.
            assert_eq!(w.effects(), 1, "commit {n} ({stop_after})");
            assert!(app.alarm().is_none());
        }
    }
}

// -------------------------------------------------------------------------------------
// Provider loss (Dispatch spec 12.6)

pub(crate) struct Lost {
    pub(crate) w: World,
    pub(crate) router: Router,
    pub(crate) protocol: Arc<LossProtocol>,
    /// The protocols registered beside [`Lost::protocol`], each holding the scope of its
    /// name.
    pub(crate) others: Vec<Arc<LossProtocol>>,
    pub(crate) next: Arc<ScriptedDispatch>,
    carol: [u8; 32],
    dave: [u8; 32],
    note_at_ms: u64,
}

/// A sender the old service flags in [`lost_world`] and the move tests.
const FLAGGED: [u8; 32] = [44; 32];

/// The app's copy of the lists in `store`: whether it holds [`FLAGGED`], and its refresh
/// time.
fn lists_copy_in(store: &MemoryStore) -> (bool, Option<u64>) {
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    let flag = format!("lc/flag/{}", pubky_dispatch_core::enc::pubky_id(&FLAGGED));
    let flagged = store.get(&ns, flag.as_bytes()).unwrap().is_some();
    let at = store
        .get(&ns, b"lc/lists_at")
        .unwrap()
        .map(|bytes| crate::app::state::decode::<u64>(&bytes).unwrap());
    (flagged, at)
}

/// An app with the list permissions, a kept peer and a deny entry in its copy, a note
/// processed, and kept evidence; then the signer declares generation 1 lost at a new
/// service, and the old one is gone.
pub(crate) async fn lost_world(store: Arc<dyn StateStore>) -> Lost {
    let permissions = [
        Permission::ListsRead,
        Permission::ListsManage,
        Permission::ReplyAdd,
    ];
    lost_world_with(store, &permissions, false, true).await
}

/// [`lost_world`], the app holding `permissions`, with `record` a shared record it wrote
/// before the loss, and without `lists` nothing in its lists.
pub(crate) async fn lost_world_with(
    store: Arc<dyn StateStore>,
    permissions: &[Permission],
    record: bool,
    lists: bool,
) -> Lost {
    lost_world_beside(store, permissions, record, lists, Vec::new()).await
}

/// [`lost_world_with`], with `others` registered beside the sample protocol, the app's
/// certificate holding the scope of each one's name.
pub(crate) async fn lost_world_beside(
    store: Arc<dyn StateStore>,
    permissions: &[Permission],
    record: bool,
    lists: bool,
    others: Vec<Arc<LossProtocol>>,
) -> Lost {
    let w = World::new();
    let router = Router::of(&w);
    let protocol = Arc::new(LossProtocol {
        counterparties: vec![w.bob.public()],
        ..LossProtocol::default()
    });
    let names: Vec<String> = others.iter().map(|other| other.name()).collect();
    let scopes: Vec<&str> = std::iter::once("sample-a")
        .chain(names.iter().map(String::as_str))
        .collect();
    let request = w
        .signer
        .approve(
            &app_keys("wallet"),
            &AppSpec::new(&scopes).with_permissions(permissions),
        )
        .unwrap();
    let mut app = App::join(
        router.env(&w, store),
        loss_set(&protocol, &others),
        World::config(),
        request,
    )
    .await
    .unwrap();
    if record {
        let target = crate::app::RecordTarget::new(super::shared_flows::items(), b"key");
        let value = super::shared_flows::value(&["a"]);
        app.put_record(&target, &value, vec![]).await.unwrap();
    }
    let me = app.app_id();
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    let phone = w.other_app("phone", &[Permission::ListsManage]);
    if lists {
        w.dispatch
            .app_op(
                &phone,
                OpKind::AllowPut {
                    pubky: carol,
                    reason: PeerReason::Kept,
                },
            )
            .unwrap();
        w.dispatch
            .app_op(&phone, OpKind::DenyPut { pubky: dave })
            .unwrap();
    }
    w.clock.advance_ms(1000);
    let note_at_ms = w.clock.now_ms();
    w.note(me, "before the loss");
    // The old service flags a sender; the read refreshes the copy of the lists with it.
    w.dispatch.lock().shared.flagged.insert(FLAGGED, 3);
    app.receive(None).await.unwrap();
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    w.clock.advance_ms(60_000);
    let n_key = next_key();
    let next = ScriptedDispatch::recovering(&w.alice, n_key.to_bytes(), Arc::clone(&w.clock), 2, 1)
        .unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    // The old service is unreachable.
    w.dispatch.lock().not_hosted_unpinned = true;
    Lost {
        w,
        router,
        protocol,
        others,
        next,
        carol,
        dave,
        note_at_ms,
    }
}

/// `protocol` and `others`, in that order.
fn loss_set(protocol: &Arc<LossProtocol>, others: &[Arc<LossProtocol>]) -> crate::app::ProtocolSet {
    crate::app::ProtocolSet::new(
        std::iter::once(protocol)
            .chain(others)
            .map(|one| Arc::clone(one) as Arc<dyn Protocol>)
            .collect(),
    )
    .unwrap()
}

/// The follow: the own identity.json from the Homeserver, then a read. Returns the app and
/// the read's events.
pub(crate) async fn load_loss(lost: &Lost, store: Arc<dyn StateStore>) -> Result<App, AppError> {
    App::load(
        lost.router.env(&lost.w, store),
        loss_set(&lost.protocol, &lost.others),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
}

pub(crate) async fn follow_loss(
    lost: &Lost,
    store: Arc<dyn StateStore>,
) -> Result<(App, Vec<AppEvent>), AppError> {
    let mut app = load_loss(lost, store).await?;
    app.refresh_identity().await?;
    let report = app.receive(None).await?;
    Ok((app, report.events))
}

#[tokio::test]
async fn test_loss_local_writes_over_the_bound_are_refused_with_the_loss_as_called() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    *lost.protocol.local_bytes.lock().unwrap() = MAX_STEP_LOCAL_BYTES;
    let (app, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    // Asked once, with a view of nothing zero.
    let losses = lost.protocol.losses.lock().unwrap().clone();
    assert_eq!(losses.len(), 1);
    let loss = losses[0];
    assert_eq!(loss.accepted_from_ms, lost.note_at_ms);
    assert!(loss.lost_generation > 0 && loss.generation > loss.lost_generation);
    assert!(loss.declared_at_ms > 0 && loss.uncertain_until_ms > loss.declared_at_ms);
    // Its writes, over the bound with their overhead, weren't committed; the protocol is
    // told, durably, of the very loss it was called with; and the recovery went on.
    assert_eq!(app.protocol_get("sample", b"lost/1").await.unwrap(), None);
    let refused = |events: &[AppEvent]| {
        has(events, |e| {
            matches!(
                e,
                AppEvent::LocalWritesRefused { call: RefusedCall::ProviderLost(called), .. }
                    if *called == loss
            )
        })
    };
    assert!(refused(&events), "{events:?}");
    assert!(refused(&app.kept_duties().await.unwrap()));
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::ProviderRecovered { generation: 2 }
    )));
    assert_eq!(lost.protocol.losses.lock().unwrap().len(), 1);
    let backup = app.backup().await.unwrap();
    drop(app);
    let mut restored = App::restore(
        lost.router.env(&lost.w, Arc::new(MemoryStore::new())),
        loss_set(&lost.protocol, &lost.others),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.follow_provider().await.unwrap();
    assert!(refused(&restored.kept_duties().await.unwrap()));
    assert_eq!(lost.protocol.losses.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_loss_roster_selects_the_new_opening_after_a_second_loss() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let (mut app, _) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    let first = app.recovery_roster().await.unwrap().unwrap();
    let third = third_recovering(&lost.w, &lost.router, 3, 2);
    let next = third.identity_doc().unwrap();
    app.refresh_identity().await.unwrap();
    assert_ne!(
        app.recovery_roster()
            .await
            .unwrap()
            .as_ref()
            .map(IdentityDoc::hash),
        Some(first.hash())
    );
    app.follow_provider().await.unwrap();
    let second = app.recovery_roster().await.unwrap().unwrap();
    assert_eq!(second.hash(), next.hash());
    assert_eq!(second.body().recovery_from, Some(2));
}

#[tokio::test]
async fn test_loss_roster_keeps_the_opening_document_after_a_later_version_and_reload() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let opening = lost.next.identity_doc().unwrap();
    let later = lost.w.signer.sign_next(|_| {}).unwrap();
    lost.next.deliver_identity(&later).unwrap();
    let (mut app, _) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert_eq!(app.own_identity().hash(), later.hash());
    assert_eq!(
        app.recovery_roster().await.unwrap().unwrap().hash(),
        opening.hash()
    );

    // A loss followed before its roster was kept can still read the original pair.
    let mut tx = app.tx().unwrap();
    tx.delete("loss/opening").unwrap();
    app.commit(tx).await.unwrap();
    assert_eq!(
        app.recovery_roster().await.unwrap().unwrap().hash(),
        opening.hash()
    );

    let app_id = app.app_id();
    drop(app);
    let mut reloaded = App::load(
        lost.router.env(&lost.w, store as Arc<dyn StateStore>),
        loss_set(&lost.protocol, &lost.others),
        World::config(),
        app_id,
    )
    .await
    .unwrap();
    lost.next.lock().not_hosted_unpinned = true;
    let kept = reloaded.recovery_roster().await.unwrap().unwrap();
    assert_eq!(kept.hash(), opening.hash());
    assert_eq!(kept.body().recovery_from, Some(1));
}

#[tokio::test]
async fn test_loss_roster_indexes_the_original_removal_after_an_interrupted_commit() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let store = Arc::new(FaultStore::new(
        store as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    let mut app = load_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let opening = lost.next.identity_doc().unwrap();
    let phone = app_keys("phone").app_id_bytes();
    assert!(opening.listed_cert(&phone).is_some());
    let removed = lost
        .w
        .signer
        .sign_next(|body| {
            body.apps.retain(|app| app.app_id != phone);
            body.removed.push(RemovedApp {
                app_id: phone,
                distrust_from: START,
            });
        })
        .unwrap();
    lost.next.deliver_identity(&removed).unwrap();
    app.refresh_identity().await.unwrap();
    let purged = lost
        .w
        .signer
        .sign_next(|body| body.removed.clear())
        .unwrap();
    lost.next.deliver_identity(&purged).unwrap();
    app.refresh_identity().await.unwrap();
    assert_eq!(app.own_identity().hash(), purged.hash());

    store.fail_put_once(b"loss/opening");
    assert!(app.follow_provider().await.is_err());
    drop(app);

    // Reuse the signed copy kept on observation. The store can commit the opening
    // and version indexes even when it cannot accept another copy of the document.
    store.refuse_puts_as_too_large(Some(b"loss/removal/"));
    let (mut app, _) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert_eq!(
        app.recovery_roster().await.unwrap().unwrap().hash(),
        opening.hash()
    );
    assert_eq!(
        app.recovery_removal(&phone).await.unwrap().unwrap().hash(),
        removed.hash()
    );
    drop(app);
    let mut app = load_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert_eq!(
        app.recovery_removal(&phone).await.unwrap().unwrap().hash(),
        removed.hash()
    );
}

#[tokio::test]
async fn test_loss_upload_inputs_and_application_survive_an_unanswered_request() {
    use crate::app::LossUploadOutcome;
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world_with(Arc::clone(&store) as Arc<dyn StateStore>, &[], true, false).await;
    let load = || load_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut app = load().await.unwrap();
    app.retain_loss_uploads_for("sample", b"cutoff")
        .await
        .unwrap();
    app.protocol_commit(
        "sample",
        &[crate::app::LocalWrite::Put {
            key: b"cutoff".to_vec(),
            value: b"first".to_vec(),
        }],
    )
    .await
    .unwrap();

    lost.next.fail_next(Fault::LoseAnswer {
        path: "recovery/upload".into(),
    });
    app.refresh_identity().await.unwrap();
    assert!(app.receive(None).await.is_err());
    drop(app);
    let mut app = load().await.unwrap();
    let pending = app.loss_uploads(2).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].outcome, LossUploadOutcome::Pending);
    let (inputs, local) = app.loss_upload_inputs(&pending[0]).await.unwrap();
    assert_eq!(inputs.records.len(), 1);
    assert_eq!(local.records.len(), 1);
    assert!(local.omitted.is_empty());
    assert_eq!(local.checkpoints.len(), 1);
    let cutoff = Some(pubky_dispatch_core::enc::hash(b"first"));
    assert_eq!(local.checkpoints[0].before, cutoff);
    assert_eq!(local.checkpoints[0].after, cutoff);
    app.receive(None).await.unwrap();
    drop(app);
    let mut app = load().await.unwrap();
    let seen = app.loss_uploads(2).await.unwrap();
    assert_eq!(seen.len(), 1);
    let kept = &seen[0];
    assert_eq!(kept.body_hash, pending[0].body_hash);
    assert_eq!(
        kept.opening_hash,
        Some(app.recovery_roster().await.unwrap().unwrap().hash())
    );
    assert_eq!(kept.recovery_from, 1);
    assert_eq!(
        app.loss_upload_inputs(kept).await.unwrap(),
        (inputs.clone(), local)
    );
    let LossUploadOutcome::Answered { proof, .. } = &kept.outcome else {
        panic!("the checked retry is missing");
    };
    let pubky_dispatch_core::chain::ServiceTransition::Upload { by, changes, .. } =
        pubky_dispatch_core::chain::ServiceTransition::from_value(&proof.body().state).unwrap()
    else {
        panic!("expected an upload");
    };
    assert_eq!(by, app.app_id());
    assert!(changes["records"].as_array().unwrap().is_empty());
    let target = crate::app::RecordTarget::new(super::shared_flows::items(), b"key");
    let current = app.read_record_application(&target).await.unwrap().unwrap();
    assert_eq!(current.evidence.op, inputs.records[0].op);
    assert_eq!(current.record.key, app.record_key(&target).unwrap());
    assert_eq!(current.application.generation, 2);
    assert_eq!(current.installed_version, current.record.version);
    app.forget_loss_uploads(2).await.unwrap();
    assert!(app.loss_uploads(2).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_record_application_reports_the_installed_version_after_a_later_loss() {
    use crate::app::RecordTarget;
    use pubky_dispatch_core::ops::RecordVersion;

    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(&w, &router, w.store.clone(), w.protocol.clone(), &[]).await;
    let target = RecordTarget::new(super::shared_flows::items(), b"key");
    assert!(
        app.read_record_application(&target)
            .await
            .unwrap()
            .is_none()
    );
    let held = app
        .put_record(&target, &super::shared_flows::value(&["a"]), vec![])
        .await
        .unwrap();
    let original = app.read_record_application(&target).await.unwrap().unwrap();
    assert_eq!(original.record, held);
    assert!(held.authenticated && original.evidence.proof.is_some());
    assert_eq!(original.installed_version, held.version);
    assert_eq!(original.application.generation, held.version.generation);
    assert_eq!(original.application.seq, held.version.version);
    assert!(held.version.version > 1);

    change_key(&w, &router);
    app.refresh_identity().await.unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    let replacement = third_recovering(&w, &router, 3, 2);
    app.refresh_identity().await.unwrap();
    app.receive(None).await.unwrap();
    drop(app);
    let mut app = App::load(
        router.env(&w, w.store.clone()),
        w.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    let installed = replacement.record(&held.key).unwrap();
    assert_eq!(installed.op, original.evidence.op);
    assert_eq!(installed.state.version, RecordVersion::new(1, 1));
    assert_eq!(installed.revision.generation, 3);
    let current = app.read_record_application(&target).await.unwrap().unwrap();
    assert_eq!(current.installed_version, installed.state.version);
    assert_eq!(current.application, installed.revision);
    assert_eq!(current.record.version, held.version);
    assert_eq!(current.record.content, held.content);
    assert!(current.record.authenticated);
    assert_eq!(current.evidence, original.evidence);
}

#[tokio::test]
async fn test_loss_upload_empty_evidence_records_the_pass_without_posting() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world_with(Arc::clone(&store) as Arc<dyn StateStore>, &[], false, false).await;
    let mut app = load_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    app.forget_evidence(&[Evidence::Proof(first_proof(&lost.w.dispatch))])
        .await
        .unwrap();
    // No verified old head can be uploaded across a gap (Dispatch spec 12.6 step 3).
    app.state.chain.as_mut().unwrap().gap = Some((1, 2));
    app.retain_loss_uploads_for("sample", b"cutoff")
        .await
        .unwrap();
    app.refresh_identity().await.unwrap();
    app.receive(None).await.unwrap();
    let observations = app.loss_uploads(2).await.unwrap();
    assert_eq!(observations.len(), 1);
    let seen = &observations[0];
    assert_eq!(seen.outcome, crate::app::LossUploadOutcome::NoRequest);
    let (inputs, details) = app.loss_upload_inputs(seen).await.unwrap();
    assert!(
        inputs.records.is_empty()
            && inputs.claims.is_empty()
            && inputs.proofs.is_empty()
            && inputs.heads.is_empty()
    );
    assert!(details.records.is_empty() && details.omitted.is_empty());
    assert_eq!(details.checkpoints[0].before, None);
    assert_eq!(details.checkpoints[0].after, None);
    assert!(lost.next.uploads().is_empty());
}

#[tokio::test]
async fn test_loss_upload_retains_the_unanswered_inputs_after_the_next_scan_changes() {
    use crate::app::LossUploadOutcome;
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let mut app = load_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    app.retain_loss_uploads().await.unwrap();
    lost.next.fail_next(Fault::LoseAnswer {
        path: "recovery/upload".into(),
    });
    app.refresh_identity().await.unwrap();
    assert!(app.receive(None).await.is_err());
    let old = app.loss_uploads(2).await.unwrap().pop().unwrap();
    app.forget_evidence(&[Evidence::Proof(first_proof(&lost.w.dispatch))])
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    let observations = app.loss_uploads(2).await.unwrap();
    assert_eq!(observations.len(), 2);
    assert!(observations.contains(&old));
    assert_eq!(old.outcome, LossUploadOutcome::Pending);
    assert_eq!(
        app.loss_upload_inputs(&old).await.unwrap().0.proofs.len(),
        1
    );
    let new = observations
        .iter()
        .find(|v| v.body_hash != old.body_hash)
        .unwrap();
    assert!(matches!(new.outcome, LossUploadOutcome::Answered { .. }));
    assert!(
        app.loss_upload_inputs(new)
            .await
            .unwrap()
            .0
            .proofs
            .is_empty()
    );
}

#[tokio::test]
async fn test_loss_recovers_at_the_new_generation() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let (mut app, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    let me = app.app_id();
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::ProviderLost {
            lost_generation: 1,
            generation: 2
        }
    )));
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::ProviderRecovered { generation: 2 }
    )));
    // Registered at the new service with an `n` above every one registered before.
    assert_eq!(lost.next.app(&me).receive_n, Some(1));
    assert!(lost.next.app(&me).record.is_some());
    // Evidence first, with the lost generation's identity.json, the old head and proofs;
    // then the lists from the app's copy.
    let uploads = lost.next.uploads();
    assert_eq!(uploads.len(), 2, "{uploads:?}");
    let evidence = &uploads[0].0;
    assert_eq!(evidence["heads"].as_array().unwrap().len(), 1);
    assert_eq!(evidence["proofs"].as_array().unwrap().len(), 1);
    let lost_doc = SignedDoc::from_strict_value(&evidence["lost_identity"]).unwrap();
    assert_eq!(
        IdentityDoc::verify(&lost_doc, &lost.w.alice.public())
            .unwrap()
            .generation(),
        1
    );
    let lists = &uploads[1].0["lists"];
    assert_eq!(
        lists["kept"],
        json!([pubky_dispatch_core::enc::pubky_id(&lost.carol)])
    );
    assert_eq!(
        lists["deny"],
        json!([pubky_dispatch_core::enc::pubky_id(&lost.dave)])
    );
    // The protocol was asked for re-sends once, from the cursor's time at the old service.
    let losses = lost.protocol.losses.lock().unwrap().clone();
    assert_eq!(losses.len(), 1);
    assert_eq!(losses[0].lost_generation, 1);
    assert_eq!(losses[0].accepted_from_ms, lost.note_at_ms);
    assert!(losses[0].uncertain_until_ms > losses[0].declared_at_ms);
    assert_eq!(
        app.protocol_get("sample", b"lost/1").await.unwrap(),
        Some(b"1".to_vec())
    );
    // Bob's reply grant was added back.
    assert_eq!(reply_grants_at(&lost.next), 1);
    // Reconcile mode until the protocol's reconciliation ends it.
    assert!(app.reconcile_mode());
    assert!(app.may_attempt(false).is_err());
    let info = app.recovery_info().await.unwrap().unwrap();
    assert!(info.steps_done);
    assert_eq!(info.loss.generation, 2);
    assert_eq!(info.reply_peers_left_out, 0);
    assert_eq!(app.cursor().generation, 2);
    // The new service's feed is followed from its start; a note there is received.
    let seq = note_at(&lost.w, &lost.next, me, "after the loss");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    app.end_reconcile(UserConfirmed::new()).await.unwrap();
    assert!(!app.reconcile_mode());
    // Nothing is asked again.
    app.receive(None).await.unwrap();
    assert_eq!(lost.protocol.losses.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_peer_recovery_with_only_reply_add_retains_its_answer_on_reopen() {
    use crate::app::admission::observations::{ReplyObservation, reply_key};
    let store = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        StoreFault::None,
    ));
    let lost = lost_world_with(store.clone(), &[Permission::ReplyAdd], false, false).await;
    let peer = lost.w.bob.public();
    store.fail_put_once(b"lc/r/");
    let interrupted = follow_loss(&lost, store.clone()).await;
    assert!(matches!(
        interrupted,
        Err(AppError::Store(crate::error::StoreError::Unavailable))
    ));
    assert_eq!(reply_grants_at(&lost.next), 1);
    let mut app = load_loss(&lost, store.clone()).await.unwrap();
    assert!(!app.recovery_info().await.unwrap().unwrap().steps_done);
    app.receive(None).await.unwrap();
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
    drop(app);
    let mut app = load_loss(&lost, store).await.unwrap();
    assert!(matches!(
        app.allow_list().await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    assert!(app.admits(&peer).await.unwrap());
    let held = app
        .reader()
        .get_raw(reply_key(&peer).as_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ReplyObservation::read(&held).unwrap(),
        ReplyObservation::Present
    );
    assert_eq!(reply_grants_at(&lost.next), 1);
}

#[tokio::test]
async fn test_sender_disposition_loss_clears_the_refresh_time_and_keeps_the_flags() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let (flagged, at) = lists_copy_in(&store);
    assert!(flagged && at.is_some());
    // The new service's lists don't read for now, so the owed refresh fails.
    lost.next.lock().allow = Some(json!({}));
    let (mut app, _) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert_eq!(app.cursor().generation, 2);
    assert_eq!(lists_copy_in(&store), (true, None));
    // Once they read, the next read refreshes the copy from the new service.
    lost.next.lock().allow = None;
    app.receive(None).await.unwrap();
    let (flagged, at) = lists_copy_in(&store);
    assert!(!flagged);
    assert!(at.is_some());
}

#[tokio::test]
async fn test_loss_call_the_protocol_fails_is_made_again() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // The protocol can't read its state: the recovery stops at the step, and the call
    // fails with the protocol's error, which isn't the app's store failing.
    *lost.protocol.failing.lock().unwrap() = 1;
    let first = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>).await;
    assert!(
        matches!(&first, Err(AppError::Protocol(failure))
            if *failure.error() == StoreError::Unavailable),
        "{:?}",
        first.map(|_| ())
    );
    assert!(lost.protocol.losses.lock().unwrap().is_empty());
    // The next call asks again, and the recovery goes on.
    let (app, events) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(
        has(&events, |e| matches!(
            e,
            AppEvent::ProviderRecovered { generation: 2 }
        )),
        "{events:?}"
    );
    let losses = lost.protocol.losses.lock().unwrap().clone();
    assert_eq!(losses.len(), 1);
    assert_eq!(losses[0].lost_generation, 1);
    assert_eq!(losses[0].accepted_from_ms, lost.note_at_ms);
    assert_eq!(
        app.protocol_get("sample", b"lost/1").await.unwrap(),
        Some(b"1".to_vec())
    );
    assert_eq!(reply_grants_at(&lost.next), 1);
}

#[tokio::test]
async fn test_loss_keeps_an_owed_call_from_the_lost_generation_and_makes_it() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // A missed-entries call the protocol couldn't answer at generation 1.
    let mut app = load_lost(&lost, Arc::clone(&store) as Arc<dyn StateStore>).await;
    let call = crate::app::feed::OwedCall::from(crate::app::MissedEntries {
        read_at_ms: lost.note_at_ms + 1,
        seq: 9,
        entries: 2,
        accepted_from_ms: lost.note_at_ms,
        accepted_until_ms: lost.note_at_ms + 1,
    });
    let mut tx = app.tx().unwrap();
    tx.put(
        &crate::app::state::key::owed(1, 9),
        &(crate::app::feed::Owed {
            to: vec!["sample".into()],
            call,
        }),
    )
    .unwrap();
    app.commit(tx).await.unwrap();
    drop(app);
    // Recovered at generation 2, the call is still made, with what it named then: the
    // re-sends it asks for are the counterparties' to answer, wherever the app reads.
    let (app, _) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert_eq!(app.cursor().generation, 2);
    let missed = lost.protocol.sample.missed.lock().unwrap().clone();
    assert!(
        missed.iter().any(|m| m.seq == 9
            && m.entries == 2
            && m.accepted_from_ms == lost.note_at_ms
            && m.accepted_until_ms == lost.note_at_ms + 1),
        "{missed:?}"
    );
    assert!(app.reader().scan_raw("owed/").await.unwrap().is_empty());
}

/// `entries` entries stored for good, with plaintexts of `bytes`, written into `store` as
/// reads would have stored them, in commits that each fit; returns them by local ID.
async fn store_entries(
    lost: &Lost,
    store: &Arc<MemoryStore>,
    entries: u64,
    bytes: usize,
) -> std::collections::BTreeMap<u64, crate::app::state::ParkedEntry> {
    let mut app = App::load(
        lost.router
            .env(&lost.w, Arc::clone(store) as Arc<dyn StateStore>),
        Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    let mut kept = std::collections::BTreeMap::new();
    for chunk in (0..entries).collect::<Vec<_>>().chunks(64) {
        let mut tx = app.tx().unwrap();
        for n in chunk {
            let id = n + 1;
            let stored = crate::app::state::ParkedEntry {
                receipt: crate::app::EntryReceipt {
                    entry_id: [1; 16],
                    invite_code_hash: None,
                    service_key: [2; 32],
                    read_at_ms: lost.w.clock.now_ms(),
                },
                seq: 3 + n,
                generation: 1,
                sender: lost.w.bob.public(),
                cert: lost.w.bob_cert.signed().clone(),
                accepted_at_ms: lost.w.clock.now_ms(),
                plaintext: vec![0xff; bytes],
                reason: ParkReason::Refused,
                round: 0,
                released: false,
                keys_at: None,
            };
            tx.put(&crate::app::state::key::parked(id), &stored)
                .unwrap();
            kept.insert(id, stored);
        }
        tx.put(crate::app::state::key::STORED_NEXT, &(entries + 1))
            .unwrap();
        app.commit(tx).await.unwrap();
    }
    kept
}

#[tokio::test]
async fn test_stored_entries_keep_their_ids_across_two_losses_in_order() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let kept = store_entries(&lost, &store, 3, 16).await;
    let load = || async {
        App::load(
            lost.router
                .env(&lost.w, Arc::clone(&store) as Arc<dyn StateStore>),
            Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
            World::config(),
            app_keys("wallet").app_id_bytes(),
        )
        .await
        .unwrap()
    };
    // Two losses: neither writes the stored entries again, so each keeps its ID, its
    // `seq` and generation, and their order.
    let (app, _) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert_eq!(app.cursor().generation, 2);
    assert_eq!(load().await.state.parked, kept);
    let _third = third_recovering(&lost.w, &lost.router, 3, 2);
    let _ = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>).await;
    let app = load().await;
    assert_eq!(app.cursor().generation, 3);
    assert_eq!(app.state.parked, kept);
    // An entry stored after them takes the next ID.
    assert_eq!(app.state.next_stored_id, 4);
}

#[tokio::test]
async fn test_loss_starts_with_more_entries_stored_than_one_commit_takes() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // 420 entries of the largest plaintext, 64 KiB, 87 KiB each as stored, about 36 MiB
    // in all: writing them again in the loss's first commit would take it past the 32 MiB
    // batch size.
    let kept = store_entries(&lost, &store, 420, 64 * 1024).await;
    let (app, events) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::ProviderRecovered { generation: 2 }
    )));
    assert_eq!(app.cursor().generation, 2);
    assert_eq!(app.state.parked.len(), kept.len());
}

#[tokio::test]
async fn test_new_feed_entry_at_a_stored_entrys_seq_meets_none_of_it() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let (mut app, _) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let me = app.app_id();
    // A note at the new service, at a `seq` a stored entry of the lost generation was read
    // at too.
    let seq = note_at(&lost.w, &lost.next, me, "after the loss");
    let mut tx = app.tx().unwrap();
    let stored = crate::app::state::ParkedEntry {
        receipt: crate::app::EntryReceipt {
            entry_id: [1; 16],
            invite_code_hash: None,
            service_key: [2; 32],
            read_at_ms: lost.note_at_ms,
        },
        seq,
        generation: 1,
        sender: lost.w.bob.public(),
        cert: lost.w.bob_cert.signed().clone(),
        accepted_at_ms: lost.note_at_ms,
        plaintext: b"kept".to_vec(),
        reason: ParkReason::Refused,
        round: 0,
        released: false,
        keys_at: None,
    };
    let id = app.state.next_stored_id;
    tx.put(&crate::app::state::key::parked(id), &stored)
        .unwrap();
    tx.put(crate::app::state::key::STORED_NEXT, &(id + 1))
        .unwrap();
    app.commit(tx).await.unwrap();
    app.state.parked.insert(id, stored.clone());
    app.state.next_stored_id = id + 1;
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    // The stored entry is as it was, under its ID.
    assert_eq!(app.state.parked.get(&id), Some(&stored));
}

#[tokio::test]
async fn test_proved_kept_peer_add_and_removal_contribute_to_the_recovery_upload() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let old = w.bob.public();
    let added = IdentityKey::from_secret(seed("carol/identity")).public();
    let formerly_denied = IdentityKey::from_secret(seed("previous/identity")).public();
    let denied = IdentityKey::from_secret(seed("restricted/identity")).public();
    app.keep_peer(&old).await.unwrap();
    app.deny(&formerly_denied).await.unwrap();
    let changes = crate::app::OpBatch::new()
        .op(OpKind::AllowDelete {
            pubky: old,
            reason: PeerReason::Kept,
        })
        .op(OpKind::AllowPut {
            pubky: added,
            reason: PeerReason::Kept,
        })
        .op(OpKind::DenyDelete {
            pubky: formerly_denied,
        })
        .op(OpKind::DenyPut { pubky: denied });
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let kept = app
        .submit_batch(changes)
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    app.receive(None).await.unwrap();
    assert!(matches!(
        app.kept_batch(kept).await.unwrap(),
        Some(crate::app::KeptBatchStatus::Kept { .. })
    ));
    assert!(app.admits(&old).await.unwrap());
    assert!(!app.admits(&added).await.unwrap());

    let key = next_key();
    let next =
        ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    router.remove(ORIGIN);
    app.refresh_identity().await.unwrap();
    app.follow_provider().await.unwrap();
    assert!(matches!(
        app.kept_batch(kept).await.unwrap(),
        Some(crate::app::KeptBatchStatus::Applied { .. })
    ));
    let lists = next
        .uploads()
        .into_iter()
        .find_map(|(body, _)| body.get("lists").cloned())
        .expect("the loss list upload");
    assert_eq!(
        lists["kept"],
        json!([pubky_dispatch_core::enc::pubky_id(&added)])
    );
    assert_eq!(
        lists["deny"],
        json!([pubky_dispatch_core::enc::pubky_id(&denied)])
    );
}

#[tokio::test]
async fn test_signed_list_before_upload_preserves_the_kept_peer_contribution() {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let lost = lost_world_with(
        store.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
        false,
        true,
    )
    .await;
    let mut app = load_loss(&lost, store.clone()).await.unwrap();
    lost.next.fail_next(Fault::Error {
        path: "recovery/upload".into(),
        code: ErrorCode::Unavailable,
        current: json!({}),
    });
    app.refresh_identity().await.unwrap();
    assert_eq!(
        app.follow_provider().await.unwrap_err().code(),
        Some(ErrorCode::Unavailable)
    );
    let progress = app.recovery_info().await.unwrap().unwrap();
    assert!(matches!(
        progress.step,
        crate::app::RecoveryStep::Upload | crate::app::RecoveryStep::Lists
    ));
    let before = app.allow_list().await.unwrap();
    assert!(before.kept_peers().next().is_none() && before.deny.is_empty());
    assert!(!app.admits(&lost.carol).await.unwrap());
    drop(app);
    let mut app = load_loss(&lost, store).await.unwrap();
    app.follow_provider().await.unwrap();
    let lists = app.allow_list().await.unwrap();
    assert_eq!(
        lists.kept_peers().collect::<Vec<_>>(),
        [lost.carol],
        "the new service still needed the original kept peer contribution"
    );
    assert_eq!(lists.deny, [lost.dave]);
}

/// `count` distinct peers no test identity uses.
fn many_peers(domain: u8, count: u64) -> Vec<[u8; 32]> {
    (0..count)
        .map(|n| {
            let mut key = [domain; 32];
            key[24..].copy_from_slice(&n.to_be_bytes());
            key
        })
        .collect()
}

#[tokio::test]
async fn test_loss_deny_entries_past_the_limit_are_left_out_by_the_user() {
    // A full deny list, a loss whose list upload is never answered, one more deny entry at the
    // replacement, and a second loss: the owed upload now carries one entry more than any
    // list holds. The client refuses it without sending it, shows exactly what it would send,
    // and the step completes once the user unblocks one peer. A list reader, which can't
    // delete at the service, does it by leaving the peer out alone (Dispatch wire 7.4.14).
    use pubky_dispatch_core::ops::MAX_DENY;
    for manage in [true, false] {
        let w = World::new();
        let router = Router::of(&w);
        let permissions: &[Permission] = if manage {
            &[Permission::ListsRead, Permission::ListsManage]
        } else {
            &[Permission::ListsRead]
        };
        let mut app = join_on(
            &w,
            &router,
            Arc::clone(&w.store) as Arc<dyn StateStore>,
            w.protocol.clone(),
            permissions,
        )
        .await;
        let full = many_peers(7, MAX_DENY);
        w.dispatch.lock().shared.deny.extend(full.iter().copied());
        assert_eq!(app.allow_list().await.unwrap().deny.len(), full.len());
        app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
            .await
            .unwrap();
        let key = next_key();
        let next =
            ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1)
                .unwrap();
        router.add(NEXT, &next);
        publish_at(
            &w,
            &next,
            Inbox::new(NEXT, key.verifying_key().to_bytes()),
            2,
            Some(1),
        );
        router.remove(ORIGIN);
        next.fail_next(Fault::Unanswered {
            path: "recovery/upload".into(),
            after: 1,
        });
        app.refresh_identity().await.unwrap();
        assert!(app.follow_provider().await.is_err());
        assert_eq!(
            app.recovery_info().await.unwrap().unwrap().step,
            crate::app::RecoveryStep::Lists
        );
        // One more deny entry at the replacement, from this app or another one's.
        let extra = IdentityKey::from_secret(seed("erin/identity")).public();
        if manage {
            app.deny(&extra).await.unwrap();
        } else {
            next.lock().shared.deny.insert(extra);
            app.allow_list().await.unwrap();
        }
        let third = third_recovering(&w, &router, 3, 2);
        app.refresh_identity().await.unwrap();
        app.take_events();
        assert_eq!(
            app.follow_provider().await.unwrap_err(),
            AppError::Refused(Refusal::DenyListFull { over: 1 })
        );
        assert!(app.take_events().contains(&AppEvent::RecoveryDenyListFull {
            generation: 3,
            over: 1
        }));
        let lists_sent = || {
            third
                .uploads()
                .iter()
                .filter(|(body, _)| body.get("lists").is_some())
                .count()
        };
        assert_eq!(lists_sent(), 0, "refused before sending");
        let owed = app.recovery_deny_entries().await.unwrap();
        let mut expected: Vec<_> = full.iter().copied().chain([extra]).collect();
        expected.sort();
        assert_eq!(owed.iter().map(|e| e.pubky).collect::<Vec<_>>(), expected);
        assert!(owed.iter().all(|entry| !entry.also_kept));
        let batches = third.lock().batches.len();
        app.undeny(&extra).await.unwrap();
        if !manage {
            assert_eq!(
                third.lock().batches.len(),
                batches,
                "a list reader sends nothing"
            );
        }
        let owed: Vec<_> = app
            .recovery_deny_entries()
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.pubky)
            .collect();
        assert_eq!(owed, full);
        app.follow_provider().await.unwrap();
        let held = third.lock().shared.deny.clone();
        assert_eq!(held, full.iter().copied().collect());
        let sent: std::collections::BTreeSet<[u8; 32]> = third
            .uploads()
            .iter()
            .filter_map(|(body, _)| body.get("lists"))
            .flat_map(|lists| lists["deny"].as_array().cloned().unwrap_or_default())
            .map(|id| pubky_dispatch_core::enc::pubky_key(id.as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(sent, held, "the upload sent what the list showed");
        assert!(app.recovery_deny_entries().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn test_loss_list_removals_are_never_undone_by_the_upload() {
    // The user removes a kept peer and unblocks a peer while the list upload is owed, once
    // when the upload never reached the new service and once when it landed with its answer
    // lost; a restore comes in between. The upload sent after leaves both out, a peer kept and
    // blocked is shown as kept, and the new service's lists end as the user left them
    // (Dispatch wire 7.4.14 "Lists").
    for (fault, landed) in [
        (
            Fault::Unanswered {
                path: "recovery/upload".into(),
                after: 1,
            },
            false,
        ),
        (
            Fault::LoseAnswerAfter {
                path: "recovery/upload".into(),
                after: 1,
            },
            true,
        ),
    ] {
        let w = World::new();
        let router = Router::of(&w);
        let mut app = join_on(
            &w,
            &router,
            Arc::clone(&w.store) as Arc<dyn StateStore>,
            w.protocol.clone(),
            &[Permission::ListsRead, Permission::ListsManage],
        )
        .await;
        let [carol, dave, frank] = ["carol", "dave", "frank"]
            .map(|n| IdentityKey::from_secret(seed(&format!("{n}/identity"))).public());
        app.keep_peer(&carol).await.unwrap();
        app.keep_peer(&frank).await.unwrap();
        app.deny(&dave).await.unwrap();
        app.deny(&frank).await.unwrap();
        app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
            .await
            .unwrap();
        let key = next_key();
        let next =
            ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1)
                .unwrap();
        router.add(NEXT, &next);
        publish_at(
            &w,
            &next,
            Inbox::new(NEXT, key.verifying_key().to_bytes()),
            2,
            Some(1),
        );
        router.remove(ORIGIN);
        next.fail_next(fault);
        app.refresh_identity().await.unwrap();
        assert!(app.follow_provider().await.is_err());
        assert_eq!(next.lock().shared.kept.contains(&carol), landed);
        let owed = app.recovery_deny_entries().await.unwrap();
        assert_eq!(owed.len(), 2);
        assert!(owed.iter().all(|e| e.also_kept == (e.pubky == frank)));
        app.remove_kept_peer(&carol).await.unwrap();
        app.undeny(&dave).await.unwrap();
        let owed = app.recovery_deny_entries().await.unwrap();
        assert_eq!(owed.iter().map(|e| e.pubky).collect::<Vec<_>>(), [frank]);
        let backup = app.backup().await.unwrap();
        drop(app);
        let mut restored = App::restore(
            router.env(&w, Arc::new(MemoryStore::new())),
            w.protocol.clone(),
            World::config(),
            &backup,
        )
        .await
        .unwrap();
        restored.follow_provider().await.unwrap();
        {
            let held = next.lock();
            assert!(
                !held.shared.kept.contains(&carol),
                "the kept removal stands"
            );
            assert!(!held.shared.deny.contains(&dave), "the unblock stands");
            assert!(held.shared.kept.contains(&frank) && held.shared.deny.contains(&frank));
        }
        // Once the upload is confirmed, a removal is an ordinary one at the service.
        assert!(restored.recovery_deny_entries().await.unwrap().is_empty());
        restored.undeny(&frank).await.unwrap();
        assert!(!next.lock().shared.deny.contains(&frank));
    }
}

/// An app whose list upload after a loss is owed and not yet sent, carrying carol kept and
/// dave denied.
async fn owed_list_upload() -> (
    World,
    Router,
    Arc<ScriptedDispatch>,
    App,
    [u8; 32],
    [u8; 32],
) {
    let [carol, dave] = ["carol", "dave"]
        .map(|n| IdentityKey::from_secret(seed(&format!("{n}/identity"))).public());
    let (w, router, next, app) = owed_upload_of(
        &[Permission::ListsRead, Permission::ListsManage],
        &[carol],
        &[dave],
    )
    .await;
    (w, router, next, app, carol, dave)
}

/// An app with `permissions` whose list upload after a loss is owed and not yet sent,
/// carrying `kept` as kept and `denied` as denied: written by the app itself when it holds
/// `lists.manage`, or else put at the old service by another own app and read into the
/// app's copy of the lists.
async fn owed_upload_of(
    permissions: &[Permission],
    kept: &[[u8; 32]],
    denied: &[[u8; 32]],
) -> (World, Router, Arc<ScriptedDispatch>, App) {
    let w = World::new();
    let protocol = w.protocol.clone();
    owed_upload_in(w, protocol, World::config(), permissions, kept, denied).await
}

/// [`owed_upload_of`] in `w`, the app running `protocol` with `config`.
async fn owed_upload_in(
    w: World,
    protocol: Arc<dyn Protocol>,
    config: AppConfig,
    permissions: &[Permission],
    kept: &[[u8; 32]],
    denied: &[[u8; 32]],
) -> (World, Router, Arc<ScriptedDispatch>, App) {
    let router = Router::of(&w);
    let mut app = App::join(
        router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>),
        protocol,
        config,
        approve_with(&w, permissions),
    )
    .await
    .unwrap();
    if permissions.contains(&Permission::ListsManage) {
        for pubky in kept {
            app.keep_peer(pubky).await.unwrap();
        }
        for pubky in denied {
            app.deny(pubky).await.unwrap();
        }
    } else {
        {
            let mut state = w.dispatch.lock();
            state.shared.kept.extend(kept.iter().copied());
            state.shared.deny.extend(denied.iter().copied());
        }
        assert_eq!(app.allow_list().await.unwrap().deny.len(), denied.len());
    }
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    let key = next_key();
    let next =
        ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    router.remove(ORIGIN);
    next.fail_next(Fault::Unanswered {
        path: "recovery/upload".into(),
        after: 1,
    });
    app.refresh_identity().await.unwrap();
    assert!(app.follow_provider().await.is_err());
    assert!(kept.iter().all(|p| !next.lock().shared.kept.contains(p)));
    assert_eq!(
        app.recovery_deny_entries().await.unwrap().len(),
        denied.len()
    );
    // A call that reads the store again, after the commit the unanswered upload failed.
    app.protocol_commit("sample", &[]).await.unwrap();
    (w, router, next, app)
}

/// How many list uploads `dispatch` was sent, answered or not.
fn list_uploads(dispatch: &ScriptedDispatch) -> usize {
    dispatch
        .uploads()
        .iter()
        .filter(|(body, _)| body.get("lists").is_some())
        .count()
}

/// How many requests to the upload route the app sent.
fn upload_requests(router: &Router) -> usize {
    router
        .log()
        .iter()
        .filter(|line| line.contains("recovery/upload"))
        .count()
}

/// Another own app, `name`, with `permissions`, as another device of the account at the
/// new service `at`: listed in the next `identity.json`, delivered there, and its record
/// put there, for operations a test injects with [`ScriptedDispatch::app_op`].
fn other_app_at(
    w: &World,
    at: &ScriptedDispatch,
    name: &str,
    permissions: &[Permission],
) -> pubky_dispatch_core::keys::AppKeys {
    let keys = app_keys(name);
    let now = w.clock.now_ms();
    let cert = issue_cert(
        &w.alice,
        &keys,
        &AppSpec::new(&["sample-a"]).with_permissions(permissions),
        now,
    )
    .unwrap();
    let doc = w
        .signer
        .sign_next(|body| {
            body.apps.push(ListedApp {
                app_id: cert.app_id(),
                cert: cert.hash(),
            })
        })
        .unwrap();
    at.deliver_identity(&doc).unwrap();
    let record = pubky_dispatch_core::records::AppRecord::sign(
        &keys,
        pubky_dispatch_core::records::AppRecordBody::new(&cert, Vec::new(), now),
    )
    .unwrap();
    at.app_op(
        &keys,
        OpKind::AppPut {
            record: record.signed().clone(),
        },
    )
    .unwrap();
    keys
}

/// An app with `lists.manage` whose list upload, keeping carol and denying dave, landed at the
/// new service with its answer lost, so it is owed again; and the phone, another own app
/// there with `lists.manage`.
async fn owed_after_a_landed_upload() -> (
    World,
    Router,
    Arc<ScriptedDispatch>,
    App,
    pubky_dispatch_core::keys::AppKeys,
    [u8; 32],
    [u8; 32],
) {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
    )
    .await;
    let [carol, dave] = ["carol", "dave"]
        .map(|n| IdentityKey::from_secret(seed(&format!("{n}/identity"))).public());
    app.keep_peer(&carol).await.unwrap();
    app.deny(&dave).await.unwrap();
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    let key = next_key();
    let next =
        ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    router.remove(ORIGIN);
    next.fail_next(Fault::LoseAnswerAfter {
        path: "recovery/upload".into(),
        after: 1,
    });
    app.refresh_identity().await.unwrap();
    assert!(app.follow_provider().await.is_err());
    assert!(next.lock().shared.kept.contains(&carol));
    assert!(next.lock().shared.deny.contains(&dave));
    app.protocol_commit("sample", &[]).await.unwrap();
    let phone = other_app_at(&w, &next, "phone", &[Permission::ListsManage]);
    (w, router, next, app, phone, carol, dave)
}

#[tokio::test]
async fn test_loss_list_step_waits_past_a_deny_change_not_checked_yet() {
    // The phone unblocks dave and then removes carol; this app no longer holds the phone's
    // certificate, and the directory it would fetch it from can't answer for now. The read
    // stops at the unblock, unchecked, and sends no upload: a later read checks it, reads on
    // to the removal, and leaves both out of the upload it sends (Dispatch spec 12.6 step 3).
    let (w, _router, next, mut app, phone, carol, dave) = owed_after_a_landed_upload().await;
    // A read that takes the phone's registration, its upload refused for now.
    next.fail_next(Fault::Error {
        path: "recovery/upload".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    app.receive(None).await.unwrap();
    assert_eq!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    let mut tx = app.tx().unwrap();
    tx.delete_prefix(&format!(
        "ocert/{}/",
        pubky_dispatch_core::enc::zbase32_encode(&phone.app_id_bytes())
    ))
    .unwrap();
    app.commit(tx).await.unwrap();
    next.app_op(&phone, OpKind::DenyDelete { pubky: dave })
        .unwrap();
    next.app_op(
        &phone,
        OpKind::AllowDelete {
            pubky: carol,
            reason: PeerReason::Kept,
        },
    )
    .unwrap();
    // Past the refused upload's wait.
    w.clock.advance_ms(120_000);
    for _ in 0..3 {
        next.fail_next(Fault::Error {
            path: "directory".into(),
            code: ErrorCode::Unavailable,
            current: serde_json::Value::Null,
        });
    }
    let uploads = list_uploads(&next);
    let report = app.receive(None).await.unwrap();
    let faults = next.lock().faults.len();
    assert!(report.stopped, "{:?} faults left {faults}", report.events);
    assert_eq!(
        list_uploads(&next),
        uploads,
        "no upload before the feed is read"
    );
    next.lock().faults.clear();
    for _ in 0..3 {
        app.receive(None).await.unwrap();
    }
    assert_ne!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    let held = next.lock();
    assert!(!held.shared.kept.contains(&carol), "kept again");
    assert!(!held.shared.deny.contains(&dave), "denied again");
}

#[tokio::test]
async fn test_loss_list_removal_seen_in_the_feed_is_left_out_of_the_upload() {
    // The list upload lands and its answer is lost, so it is owed again. Another app then
    // removes carol and unblocks dave at the new service. This app's next read sees both in
    // its feed, though its complete read of the lists already covers them, and the upload it
    // sends again leaves both out (Dispatch spec 12.6 step 3).
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
    )
    .await;
    let [carol, dave] = ["carol", "dave"]
        .map(|n| IdentityKey::from_secret(seed(&format!("{n}/identity"))).public());
    app.keep_peer(&carol).await.unwrap();
    app.deny(&dave).await.unwrap();
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    let key = next_key();
    let next =
        ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    router.remove(ORIGIN);
    next.fail_next(Fault::LoseAnswerAfter {
        path: "recovery/upload".into(),
        after: 1,
    });
    app.refresh_identity().await.unwrap();
    assert!(app.follow_provider().await.is_err());
    assert!(next.lock().shared.kept.contains(&carol));
    assert!(next.lock().shared.deny.contains(&dave));
    app.protocol_commit("sample", &[]).await.unwrap();
    let phone = other_app_at(&w, &next, "phone", &[Permission::ListsManage]);
    next.app_op(
        &phone,
        OpKind::AllowDelete {
            pubky: carol,
            reason: PeerReason::Kept,
        },
    )
    .unwrap();
    next.app_op(&phone, OpKind::DenyDelete { pubky: dave })
        .unwrap();
    app.receive(None).await.unwrap();
    let held = next.lock();
    assert!(!held.shared.kept.contains(&carol), "kept again");
    assert!(!held.shared.deny.contains(&dave), "denied again");
}

/// An app with `lists.manage` denying bob, and carol kept and denied, after a loss to
/// a new service whose deny list has room for one more entry only, its admission staged:
/// the list upload doesn't fit until one entry is removed. Returns the app, the new
/// service, and a peer its deny list holds that the app's copy lacks.
async fn deny_room_short() -> (World, Router, Arc<ScriptedDispatch>, App, [u8; 32]) {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let first = w.bob.public();
    let second = IdentityKey::from_secret(seed("carol/identity")).public();
    app.deny(&first).await.unwrap();
    app.keep_peer(&second).await.unwrap();
    app.deny(&second).await.unwrap();
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    let key = next_key();
    let next =
        ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    let fillers = many_peers(9, pubky_dispatch_core::ops::MAX_DENY - 1);
    {
        let mut state = next.lock();
        state.shared.deny.extend(fillers.iter().copied());
        state.admission_staged = true;
    }
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    router.remove(ORIGIN);
    app.refresh_identity().await.unwrap();
    (w, router, next, app, fillers[0])
}

/// How many times `events` tell that the deny list has no room for the upload.
fn deny_list_full_told(events: &[AppEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, AppEvent::RecoveryDenyListFull { .. }))
        .count()
}

/// After the step finished: the new service holds both of the app's deny entries, carol
/// kept, and admission no longer staged.
fn deny_room_made(next: &ScriptedDispatch, app_denies: [[u8; 32]; 2]) {
    let held = next.lock();
    assert!(app_denies.iter().all(|p| held.shared.deny.contains(p)));
    assert_eq!(
        u64::try_from(held.shared.deny.len()).unwrap(),
        pubky_dispatch_core::ops::MAX_DENY
    );
    assert_eq!(held.shared.kept, [app_denies[1]].into_iter().collect());
    assert!(!held.admission_staged);
}

#[tokio::test]
async fn test_loss_list_step_waiting_for_deny_room_lets_reads_go_on() {
    // A deny list without room for the upload doesn't fail the read: it is told once by its
    // event, a later read doesn't send the upload again, and messages are received
    // meanwhile. Once the user unblocks a peer, the next read sends the upload and the step
    // finishes (Dispatch spec 12.6 step 2, Dispatch wire 7.4.14 "Lists").
    let (w, router, next, mut app, room) = deny_room_short().await;
    let me = app.app_id();
    let first = w.bob.public();
    let second = IdentityKey::from_secret(seed("carol/identity")).public();
    app.take_events();
    let mut events = app.receive(None).await.unwrap().events;
    events.extend(app.take_events());
    assert_eq!(deny_list_full_told(&events), 1, "{events:?}");
    assert!(events.contains(&AppEvent::RecoveryDenyListFull {
        generation: 2,
        over: 1
    }));
    assert_eq!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    let requests = upload_requests(&router);
    let lists_sent = list_uploads(&next);
    let seq = note_at(&w, &next, me, "while the lists wait");
    let mut events = app.receive(None).await.unwrap().events;
    events.extend(app.take_events());
    assert!(received(&events, seq), "{events:?}");
    assert_eq!(deny_list_full_told(&events), 0, "{events:?}");
    assert_eq!(upload_requests(&router), requests, "not sent again");
    assert_eq!(list_uploads(&next), lists_sent);
    assert!(!next.lock().shared.deny.contains(&first), "nothing merged");
    app.undeny(&room).await.unwrap();
    app.receive(None).await.unwrap();
    assert_ne!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    deny_room_made(&next, [first, second]);
    assert!(!app.admits(&first).await.unwrap());
    assert!(!app.admits(&second).await.unwrap());
}

#[tokio::test]
async fn test_loss_list_step_waiting_for_deny_room_adopts_a_renewal() {
    // The signer renews the app's certificate while the list step waits for deny room: a
    // read adopts the renewal as ever, and once the user makes room, under the renewed
    // certificate, the step finishes (Dispatch spec 3.2, 12.6 step 2, Dispatch wire 7.4.14).
    let (w, _router, next, mut app, room) = deny_room_short().await;
    let first = w.bob.public();
    let second = IdentityKey::from_secret(seed("carol/identity")).public();
    app.receive(None).await.unwrap();
    assert_eq!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    let me = app.app_id();
    let old = app.cert().clone();
    w.clock.advance_ms(1_000);
    let renewed = issue_cert(
        &w.alice,
        &app_keys("wallet"),
        &AppSpec::new(&["sample-a"])
            .with_permissions(&[Permission::ListsManage, Permission::ReplyAdd]),
        w.clock.now_ms(),
    )
    .unwrap();
    assert_ne!(renewed.hash(), old.hash());
    let has_keys = |s: &str| SampleProtocol::default().has_keys(s);
    let epoch = next.identity_doc().unwrap().data_epoch();
    let mut batch = vec![OpKind::CertPut {
        target_app_id: me,
        cert: renewed.signed().clone(),
    }];
    for part in
        pubky_dispatch_core::records::seal_bundle_parts(&w.alice, &renewed, 1, epoch, &has_keys)
            .unwrap()
    {
        batch.push(OpKind::KeyBundlePut(
            pubky_dispatch_core::ops::KeyBundlePut {
                target_app_id: me,
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            },
        ));
    }
    next.signer_batch(batch).unwrap();
    let doc = w
        .signer
        .sign_next(|body| {
            body.apps.retain(|a| a.app_id != me);
            body.apps.push(ListedApp {
                app_id: me,
                cert: renewed.hash(),
            });
            body.renewed
                .push(pubky_dispatch_core::records::RenewedCert {
                    app_id: me,
                    cert: old.hash(),
                    until: None,
                });
        })
        .unwrap();
    next.deliver_identity(&doc).unwrap();
    // A renewal ends the wait, as it may give what the upload was refused for: the read
    // that adopts it tries the step again, which waits from then. The wait is dated a moment
    // earlier, still within its hour.
    let now = waits_since(&app).await.unwrap();
    let mut tx = app.tx().unwrap();
    tx.put(crate::app::recovery::lists::WAITS, &(now - 1))
        .unwrap();
    app.commit(tx).await.unwrap();
    for _ in 0..2 {
        app.receive(None).await.unwrap();
    }
    assert_eq!(app.cert().hash(), renewed.hash(), "the renewal is adopted");
    let since = waits_since(&app).await;
    assert!(since.is_some_and(|since| since != now - 1), "tried again");
    assert_eq!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists,
        "the step still waits"
    );
    app.undeny(&room).await.unwrap();
    app.receive(None).await.unwrap();
    assert_ne!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    deny_room_made(&next, [first, second]);
}

#[tokio::test]
async fn test_loss_refused_undeny_leaves_the_upload_denying() {
    // An unblock refused by a local check, here the app stopped by an alarm, writes nothing:
    // the owed upload still carries frank, kept and denied, and once the alarm clears the
    // new service ends both keeping and denying him (Dispatch wire 7.4.14 "Lists").
    let frank = IdentityKey::from_secret(seed("frank/identity")).public();
    let (_w, _router, next, mut app) = owed_upload_of(
        &[Permission::ListsRead, Permission::ListsManage],
        &[frank],
        &[frank],
    )
    .await;
    let owed = app.recovery_deny_entries().await.unwrap();
    assert_eq!(
        owed,
        [crate::app::RecoveryDenyEntry {
            pubky: frank,
            also_kept: true
        }]
    );
    let batches = next.lock().batches.len();
    app.state.alarm = Some(crate::app::Alarm::Rollback {
        reason: "test".into(),
    });
    assert_eq!(
        app.undeny(&frank).await.unwrap_err(),
        AppError::Refused(Refusal::Stopped)
    );
    assert_eq!(next.lock().batches.len(), batches, "nothing sent");
    assert_eq!(app.recovery_deny_entries().await.unwrap(), owed);
    app.state.alarm = None;
    assert_eq!(app.recovery_deny_entries().await.unwrap(), owed);
    app.follow_provider().await.unwrap();
    let held = next.lock();
    assert!(held.shared.deny.contains(&frank), "the upload denied him");
    assert!(held.shared.kept.contains(&frank), "and kept him");
}

#[tokio::test]
async fn test_loss_contributed_deny_goes_with_its_upload() {
    // A loss's own deny entry denies in the copy of the lists only while its upload is owed:
    // once the list step is done, an unblock is not undone by it (Dispatch spec 12.6 step 2).
    let frank = IdentityKey::from_secret(seed("frank/identity")).public();
    let (_w, _router, _next, mut app) = owed_upload_of(
        &[Permission::ListsRead, Permission::ListsManage],
        &[],
        &[frank],
    )
    .await;
    assert!(app.lists_copy().await.unwrap().deny.contains(&frank));
    app.follow_provider().await.unwrap();
    app.undeny(&frank).await.unwrap();
    assert!(
        !app.lists_copy().await.unwrap().deny.contains(&frank),
        "the unblock is undone"
    );
}

#[tokio::test]
async fn test_loss_own_deny_left_out_leaves_the_copy_where_no_read_holds_it() {
    // A list reader's copy holds the loss's own deny entries while the upload waits for
    // room: dave, whom the new service's list lacks, and erin, whom it holds. The user
    // unblocks both, which leaves both out of the upload. Dave's row stays until the lists
    // are read again, which the unblock asks for: then dave is denied in the copy no longer,
    // and erin still is, as the new service denies her (Dispatch spec 8.3, 12.6 step 2 and 3).
    let [dave, erin] =
        ["dave", "erin"].map(|n| IdentityKey::from_secret(seed(&format!("{n}/identity"))).public());
    let (_w, _router, next, mut app) =
        owed_upload_of(&[Permission::ListsRead], &[], &[dave, erin]).await;
    {
        let mut state = next.lock();
        state.shared.deny.insert(erin);
        state
            .shared
            .deny
            .extend(many_peers(9, pubky_dispatch_core::ops::MAX_DENY - 1));
    }
    app.receive(None).await.unwrap();
    assert_eq!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    assert!(list_upload_waits(&app).await);
    let copy = app.lists_copy().await.unwrap();
    assert!(copy.deny.contains(&dave) && copy.deny.contains(&erin));
    app.undeny(&dave).await.unwrap();
    app.undeny(&erin).await.unwrap();
    assert!(app.recovery_deny_entries().await.unwrap().is_empty());
    assert!(app.lists_copy().await.unwrap().deny.contains(&dave));
    app.receive(None).await.unwrap();
    let copy = app.lists_copy().await.unwrap();
    assert!(!copy.deny.contains(&dave), "held for the upload alone");
    assert!(copy.deny.contains(&erin), "the new service denies her");
}

#[tokio::test]
async fn test_loss_own_deny_left_out_keeps_the_copy_after_a_page_unanswered() {
    // A list reader's copy holds dave for the owed upload alone, and its page lands at the
    // new service with the answer lost. Left out before the page is answered, dave stays
    // denied in the copy: the new service may hold him, and does (Dispatch spec 12.6 step 2).
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    let (_w, _router, next, mut app) = owed_upload_of(&[Permission::ListsRead], &[], &[dave]).await;
    next.fail_next(Fault::LoseAnswer {
        path: "recovery/upload".into(),
    });
    app.receive(None).await.unwrap();
    assert_eq!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    assert!(next.lock().shared.deny.contains(&dave), "the page landed");
    app.undeny(&dave).await.unwrap();
    assert!(app.recovery_deny_entries().await.unwrap().is_empty());
    assert!(app.lists_copy().await.unwrap().deny.contains(&dave));
    assert!(!app.admits(&dave).await.unwrap());
}

#[tokio::test]
async fn test_loss_own_deny_left_out_keeps_the_copy_after_a_refused_resend() {
    // As above, and the host's call sends the page again at once, which the service refuses:
    // that send merged nothing, but the first landed, so dave still stays denied in the copy
    // when he is left out (Dispatch spec 12.6 step 2).
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    let (_w, _router, next, mut app) = owed_upload_of(&[Permission::ListsRead], &[], &[dave]).await;
    next.fail_next(Fault::LoseAnswer {
        path: "recovery/upload".into(),
    });
    app.receive(None).await.unwrap();
    assert!(next.lock().shared.deny.contains(&dave), "the page landed");
    next.fail_next(Fault::Error {
        path: "recovery/upload".into(),
        code: ErrorCode::PermissionMissing,
        current: serde_json::Value::Null,
    });
    assert!(app.follow_provider().await.is_err());
    app.undeny(&dave).await.unwrap();
    assert!(app.lists_copy().await.unwrap().deny.contains(&dave));
}

#[tokio::test]
async fn test_loss_own_deny_left_out_stays_denied_after_an_upload_not_read_yet() {
    // A list reader's copy holds dave for the owed upload alone, which waits for room.
    // Another app's upload then merges dave at the new service, which the feed shows only as
    // an upload, and the user unblocks dave before this app reads it. Dave stays denied in
    // the copy, through the next read, which meets the upload and takes the lists again
    // (Dispatch spec 8.3, 12.6 step 2, Dispatch wire 7.4.14).
    let [dave, frank] = ["dave", "frank"]
        .map(|n| IdentityKey::from_secret(seed(&format!("{n}/identity"))).public());
    let (_w, _router, next, mut app) =
        owed_upload_of(&[Permission::ListsRead], &[], &[dave, frank]).await;
    next.lock()
        .shared
        .deny
        .extend(many_peers(9, pubky_dispatch_core::ops::MAX_DENY - 1));
    app.receive(None).await.unwrap();
    assert!(list_upload_waits(&app).await);
    next.lock().shared.deny.insert(dave);
    let changes = pubky_dispatch_core::recovery::UploadChanges {
        lists: true,
        ..Default::default()
    };
    next.chain_upload(app_keys("phone").app_id_bytes(), changes.to_value())
        .unwrap();
    app.undeny(&dave).await.unwrap();
    assert!(app.lists_copy().await.unwrap().deny.contains(&dave));
    for _ in 0..2 {
        app.receive(None).await.unwrap();
    }
    assert!(app.lists_copy().await.unwrap().deny.contains(&dave));
    assert!(!app.admits(&dave).await.unwrap());
}

#[tokio::test]
async fn test_upload_that_added_to_the_lists_takes_the_lists_again() {
    // Another app's upload merges erin into the deny list, which the feed shows only as an
    // upload: the read that meets it takes the lists again, so the copy denies her (Dispatch
    // spec 8.3, Dispatch wire 7.4.14).
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsRead],
    )
    .await;
    app.receive(None).await.unwrap();
    let erin = IdentityKey::from_secret(seed("erin/identity")).public();
    w.dispatch.lock().shared.deny.insert(erin);
    let changes = pubky_dispatch_core::recovery::UploadChanges {
        lists: true,
        ..Default::default()
    };
    w.dispatch
        .chain_upload(app_keys("phone").app_id_bytes(), changes.to_value())
        .unwrap();
    for _ in 0..2 {
        app.receive(None).await.unwrap();
    }
    assert!(app.lists_copy().await.unwrap().deny.contains(&erin));
}

#[tokio::test]
async fn test_loss_list_step_waiting_is_left_by_a_check_for_a_move() {
    // While the list upload waits for deny room, a check for a move doesn't send it again;
    // the host's call does (Dispatch wire 7.4.14 "Lists").
    let (_w, router, _next, mut app, _room) = deny_room_short().await;
    app.receive(None).await.unwrap();
    assert!(list_upload_waits(&app).await);
    let requests = upload_requests(&router);
    let _ = app.check_for_move().await;
    assert_eq!(upload_requests(&router), requests, "not sent by the check");
    let _ = app.follow_provider().await;
    assert!(
        upload_requests(&router) > requests,
        "sent by the host's call"
    );
}

#[tokio::test]
async fn test_loss_refused_kept_removal_leaves_the_upload_keeping() {
    // A removal of a kept peer refused by a local check writes nothing: the owed upload
    // still keeps carol (Dispatch wire 7.4.14 "Lists").
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let (_w, _router, next, mut app) = owed_upload_of(
        &[Permission::ListsRead, Permission::ListsManage],
        &[carol],
        &[],
    )
    .await;
    let batches = next.lock().batches.len();
    app.state.alarm = Some(crate::app::Alarm::Rollback {
        reason: "test".into(),
    });
    assert_eq!(
        app.remove_kept_peer(&carol).await.unwrap_err(),
        AppError::Refused(Refusal::Stopped)
    );
    assert_eq!(next.lock().batches.len(), batches, "nothing sent");
    app.state.alarm = None;
    app.follow_provider().await.unwrap();
    assert!(
        next.lock().shared.kept.contains(&carol),
        "the upload kept her"
    );
}

#[tokio::test]
async fn test_loss_list_upload_waits_for_an_unanswered_kept_removal() {
    // A removal of a kept peer whose answer is lost is answered before the owed upload goes:
    // the host's call waits, and the read sends the kept removal again, which settles and
    // leaves carol out, and then the upload (Dispatch spec 12.6 step 3).
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let (_w, _router, next, mut app) = owed_upload_of(
        &[Permission::ListsRead, Permission::ListsManage],
        &[carol],
        &[],
    )
    .await;
    next.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.remove_kept_peer(&carol).await.is_err());
    let uploads = next.uploads().len();
    assert!(matches!(
        app.follow_provider().await.unwrap_err(),
        AppError::Refused(Refusal::NotNow(_))
    ));
    assert_eq!(
        next.uploads().len(),
        uploads,
        "no upload before the removal settles"
    );
    app.receive(None).await.unwrap();
    let held = next.lock();
    assert!(!held.shared.kept.contains(&carol), "kept again");
}

/// The sample protocol, also noting for each message it is handed whether `watched` reads as
/// blocked, carrying `effect_ops` in the effect of the next message alone, and failing the
/// next `failing_gaps` deny list gaps.
#[derive(Default)]
struct WatchingProtocol {
    sample: SampleProtocol,
    watched: Mutex<Option<[u8; 32]>>,
    blocked: Mutex<Vec<bool>>,
    effect_ops: Mutex<Vec<OpKind>>,
    failing_gaps: Mutex<u32>,
}

impl Protocol for WatchingProtocol {
    fn name(&self) -> String {
        self.sample.name()
    }

    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.sample.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.sample.accepts(cert)
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }

    fn receive(
        &self,
        message: &ReceivedMessage,
        cx: &mut crate::app::ReceiveContext<'_>,
    ) -> Outcome {
        if let Some(watched) = *self.watched.lock().unwrap() {
            let blocked = cx.sender_disposition(&watched).unwrap().blocked;
            self.blocked.lock().unwrap().push(blocked);
        }
        let ops = std::mem::take(&mut *self.effect_ops.lock().unwrap());
        if ops.is_empty() {
            return self.sample.receive(message, cx);
        }
        Outcome::Apply(Effect {
            ops: ops.into_iter().map(|op| (Vec::new(), op)).collect(),
            local: Vec::new(),
        })
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.missed(missed)
    }

    fn deny_list_changed(
        &self,
        change: &crate::app::DenyListChange,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.deny_list_changed(change)
    }

    fn deny_list_gap(
        &self,
        gap: &crate::app::DenyListGap,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        {
            let mut failing = self.failing_gaps.lock().unwrap();
            if *failing > 0 {
                *failing -= 1;
                return Err(StoreError::Unavailable.into());
            }
        }
        self.sample.deny_list_gap(gap)
    }
}

/// An app with the list permissions and `reply.add`, running `protocol`, that keeps and
/// denies dave, after a loss to a new service another own app's list upload reached first:
/// it keeps dave there without denying him, and the service's deny list holds `fillers`.
/// The loss is seen, not yet followed. Returns dave too.
async fn loss_after_another_apps_lists(
    protocol: Arc<dyn Protocol>,
    fillers: &[[u8; 32]],
) -> (World, Router, Arc<ScriptedDispatch>, App, [u8; 32]) {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        protocol,
        &[
            Permission::ListsRead,
            Permission::ListsManage,
            Permission::ReplyAdd,
        ],
    )
    .await;
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    app.keep_peer(&dave).await.unwrap();
    app.deny(&dave).await.unwrap();
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    let key = next_key();
    let next =
        ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    {
        let mut state = next.lock();
        state.shared.kept.insert(dave);
        state.shared.deny.extend(fillers.iter().copied());
    }
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    router.remove(ORIGIN);
    app.refresh_identity().await.unwrap();
    (w, router, next, app, dave)
}

/// The step the app's provider recovery stands at.
async fn recovery_step(app: &App) -> crate::app::RecoveryStep {
    app.recovery_info().await.unwrap().unwrap().step
}

#[tokio::test]
async fn test_loss_own_deny_stays_in_the_copy_another_apps_lists_replace() {
    // Another own app's list upload reached the new service first, keeping dave without
    // denying him. This app keeps and denies him: its read starts the loss, takes the new
    // service's lists into its copy for the loss's deny gap, and sends its list upload. The
    // copy keeps dave denied through it, so he is never admitted (Dispatch spec 12.6 step 2).
    let (_w, _router, next, mut app, dave) =
        loss_after_another_apps_lists(Arc::new(WatchingProtocol::default()), &[]).await;
    app.receive(None).await.unwrap();
    assert_ne!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    assert!(
        next.lock().shared.deny.contains(&dave),
        "the upload denied him"
    );
    let copy = app.lists_copy().await.unwrap();
    assert!(copy.kept.contains(&dave), "the new service's lists read");
    assert!(copy.deny.contains(&dave), "{:?}", copy.deny);
    assert!(!app.admits(&dave).await.unwrap());
}

#[tokio::test]
async fn test_loss_own_deny_blocks_the_sender_while_the_list_step_waits_for_room() {
    // As above, with no deny room at the new service for this app's entry: while the list
    // step waits, a protocol reads dave as blocked and the app doesn't admit him; once the
    // user makes room, the upload goes and he stays blocked (Dispatch spec 12.6 step 2).
    let protocol = Arc::new(WatchingProtocol::default());
    let fillers = many_peers(9, pubky_dispatch_core::ops::MAX_DENY);
    let (w, _router, next, mut app, dave) =
        loss_after_another_apps_lists(protocol.clone(), &fillers).await;
    *protocol.watched.lock().unwrap() = Some(dave);
    app.receive(None).await.unwrap();
    assert_eq!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    assert!(!next.lock().shared.deny.contains(&dave), "nothing merged");
    let me = app.app_id();
    note_at(&w, &next, me, "while the lists wait");
    app.receive(None).await.unwrap();
    assert_eq!(*protocol.blocked.lock().unwrap(), [true]);
    assert!(!app.admits(&dave).await.unwrap());
    assert!(app.lists_copy().await.unwrap().deny.contains(&dave));
    app.undeny(&fillers[0]).await.unwrap();
    note_at(&w, &next, me, "as the upload goes");
    app.receive(None).await.unwrap();
    assert_ne!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    assert!(
        next.lock().shared.deny.contains(&dave),
        "the upload denied him"
    );
    assert_eq!(*protocol.blocked.lock().unwrap(), [true, true]);
    assert!(!app.admits(&dave).await.unwrap());
    assert!(app.lists_copy().await.unwrap().deny.contains(&dave));
}

#[tokio::test]
async fn test_loss_list_upload_waits_for_an_unanswered_removal_in_an_effect() {
    // A message's effect removes carol, kept, or unblocks dave; the new service applies it and
    // its answer is lost. The host's call waits and sends no upload; the next read settles the
    // effect, and the upload leaves the peer out (Dispatch spec 12.6 step 3).
    let [carol, dave] = ["carol", "dave"]
        .map(|n| IdentityKey::from_secret(seed(&format!("{n}/identity"))).public());
    for removal in [
        OpKind::AllowDelete {
            pubky: carol,
            reason: PeerReason::Kept,
        },
        OpKind::DenyDelete { pubky: dave },
    ] {
        let unblock = matches!(removal, OpKind::DenyDelete { .. });
        let w = World::new();
        let protocol = Arc::new(WatchingProtocol::default());
        let (w, _router, next, mut app) = owed_upload_in(
            w,
            protocol.clone(),
            World::config(),
            &[
                Permission::ListsRead,
                Permission::ListsManage,
                Permission::ReplyAdd,
            ],
            &[carol],
            &[dave],
        )
        .await;
        *protocol.effect_ops.lock().unwrap() = vec![removal];
        let me = app.app_id();
        note_at(&w, &next, me, "with a removal");
        next.fail_next(Fault::LoseAnswer { path: "ops".into() });
        assert!(app.receive(None).await.is_err());
        assert!(app.state.pending_effect.is_some(), "{unblock}");
        let uploads = list_uploads(&next);
        assert!(
            matches!(
                app.follow_provider().await.unwrap_err(),
                AppError::Refused(Refusal::NotNow(_))
            ),
            "{unblock}"
        );
        assert_eq!(
            list_uploads(&next),
            uploads,
            "no upload before the effect settles"
        );
        app.receive(None).await.unwrap();
        assert!(app.state.pending_effect.is_none(), "{unblock}");
        assert_ne!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
        let held = next.lock();
        assert_eq!(held.shared.kept.contains(&carol), unblock, "{unblock}");
        assert_eq!(held.shared.deny.contains(&dave), !unblock, "{unblock}");
    }
}

#[tokio::test]
async fn test_loss_list_upload_waits_for_the_whole_feed() {
    // Past the pages one read takes, another own app removes carol at the new service. The
    // read that stops with more of the feed to read sends no list upload; the host reads
    // again while there is more, and the upload, once the feed is read, leaves her out
    // (Dispatch spec 12.6 step 3).
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let w = World::new();
    let protocol = w.protocol.clone();
    let config = AppConfig {
        page_size: 1,
        ..World::config()
    };
    let (w, _router, next, mut app) = owed_upload_in(
        w,
        protocol,
        config,
        &[Permission::ListsRead, Permission::ListsManage],
        &[carol],
        &[],
    )
    .await;
    let phone = other_app_at(&w, &next, "phone", &[Permission::ListsManage]);
    let fillers = many_peers(7, u64::from(crate::app::feed::FEED_PAGES_PER_READ));
    for pubky in &fillers {
        next.app_op(
            &phone,
            OpKind::AllowPut {
                pubky: *pubky,
                reason: PeerReason::Kept,
            },
        )
        .unwrap();
    }
    next.app_op(
        &phone,
        OpKind::AllowDelete {
            pubky: carol,
            reason: PeerReason::Kept,
        },
    )
    .unwrap();
    let uploads = list_uploads(&next);
    let mut report = app.receive(None).await.unwrap();
    assert!(report.more);
    assert_eq!(
        list_uploads(&next),
        uploads,
        "not with more of the feed to read"
    );
    let mut reads = 1;
    while report.more {
        assert_eq!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
        reads += 1;
        assert!(reads < 20, "the feed never ends");
        report = app.receive(None).await.unwrap();
    }
    assert_eq!(list_uploads(&next), uploads + 1);
    assert_ne!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    let held = next.lock();
    assert!(!held.shared.kept.contains(&carol), "kept again");
    assert!(fillers.iter().all(|p| held.shared.kept.contains(p)));
}

#[tokio::test]
async fn test_loss_list_step_runs_after_a_read_a_deny_gap_holds() {
    // A protocol that fails the loss's deny gap holds the read before the feed; only its
    // answer ends that, so the read still runs the list step (Dispatch spec 8.3, 12.6 step 3).
    let w = World::new();
    let protocol = Arc::new(WatchingProtocol::default());
    *protocol.failing_gaps.lock().unwrap() = u32::MAX;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let (_w, _router, next, mut app) = owed_upload_in(
        w,
        protocol.clone(),
        World::config(),
        &[Permission::ListsRead, Permission::ListsManage],
        &[carol],
        &[],
    )
    .await;
    let uploads = list_uploads(&next);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped && !report.more, "{report:?}");
    assert!(
        app.reader()
            .exists(crate::app::feed::DENY_GAP)
            .await
            .unwrap()
    );
    assert_eq!(list_uploads(&next), uploads + 1);
    assert_ne!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    assert!(next.lock().shared.kept.contains(&carol));
}

/// Whether the owed list upload waits, refused for a reason that stands.
#[tokio::test]
async fn test_loss_list_upload_refused_for_good_waits_for_reads() {
    // A list page the service refuses for a permission or a size keeps the upload waiting,
    // as a deny list without room does: reads don't send it again for a while (Dispatch wire
    // 7.4.14).
    for code in [ErrorCode::PermissionMissing, ErrorCode::TooLarge] {
        let carol = IdentityKey::from_secret(seed("carol/identity")).public();
        let (_w, _router, next, mut app) = owed_upload_of(
            &[Permission::ListsRead, Permission::ListsManage],
            &[carol],
            &[],
        )
        .await;
        next.fail_next(Fault::Error {
            path: "recovery/upload".into(),
            code,
            current: serde_json::Value::Null,
        });
        assert!(app.follow_provider().await.is_err(), "{code:?}");
        assert!(list_upload_waits(&app).await, "{code:?}");
    }
}

/// When the owed list upload began to wait, by the device clock.
async fn waits_since(app: &App) -> Option<u64> {
    app.reader()
        .get(crate::app::recovery::lists::WAITS)
        .await
        .unwrap()
}

async fn list_upload_waits(app: &App) -> bool {
    app.reader()
        .exists(crate::app::recovery::lists::WAITS)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_loss_list_step_waiting_tries_again_after_the_clock_stepped_back() {
    // The device clock stands behind when the upload began to wait, as after it stepped
    // back: the wait isn't judged on it, and the next read sends the upload again, which
    // room another device made lets pass (Dispatch wire 7.4.14 "Lists").
    let (w, router, next, mut app, room) = deny_room_short().await;
    let first = w.bob.public();
    let second = IdentityKey::from_secret(seed("carol/identity")).public();
    app.receive(None).await.unwrap();
    assert!(list_upload_waits(&app).await);
    let since: u64 = app
        .reader()
        .get(crate::app::recovery::lists::WAITS)
        .await
        .unwrap()
        .unwrap();
    next.lock().shared.deny.remove(&room);
    // The app runs again on a device clock ten seconds behind when the wait began, the
    // service's clock unchanged.
    let me = app.app_id();
    drop(app);
    let mut env = router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>);
    env.clock = Arc::new(TestClock::new(since - 10_000));
    let mut app = App::load(env, w.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    let requests = upload_requests(&router);
    app.receive(None).await.unwrap();
    assert!(upload_requests(&router) > requests, "sent again");
    assert_ne!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    assert!(!list_upload_waits(&app).await);
    let held = next.lock();
    assert!(held.shared.deny.contains(&first) && held.shared.deny.contains(&second));
}

#[tokio::test]
async fn test_loss_list_step_refused_for_room_at_the_hosts_call_waits_for_reads_too() {
    // The host's own call meets the deny list without room: the upload waits, so the next
    // read doesn't send it again (Dispatch wire 7.4.14 "Lists").
    let (_w, router, next, mut app, _room) = deny_room_short().await;
    assert_eq!(
        app.follow_provider().await.unwrap_err(),
        AppError::Refused(Refusal::DenyListFull { over: 1 })
    );
    assert!(list_upload_waits(&app).await);
    let requests = upload_requests(&router);
    let lists_sent = list_uploads(&next);
    app.receive(None).await.unwrap();
    assert_eq!(upload_requests(&router), requests, "not sent again");
    assert_eq!(list_uploads(&next), lists_sent);
    assert_eq!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
}

#[tokio::test]
async fn test_loss_list_step_waiting_for_deny_room_isnt_ended_by_a_kept_peer_left_out() {
    // A kept peer the user leaves out of the upload frees no deny room: the upload still
    // waits, and the next read doesn't send it again (Dispatch wire 7.4.14 "Lists").
    let (_w, router, _next, mut app, _room) = deny_room_short().await;
    let second = IdentityKey::from_secret(seed("carol/identity")).public();
    app.receive(None).await.unwrap();
    assert!(list_upload_waits(&app).await);
    app.remove_kept_peer(&second).await.unwrap();
    assert!(list_upload_waits(&app).await);
    let requests = upload_requests(&router);
    app.receive(None).await.unwrap();
    assert_eq!(upload_requests(&router), requests, "not sent again");
    assert_eq!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
}

#[tokio::test]
async fn test_loss_accepted_list_page_ends_the_wait() {
    // A list upload of two pages that waits, as a refusal that stands leaves it. The host's
    // call sends the first page, which the service accepts, and the second can't connect: the
    // accepted page ends the wait, so the next read sends the second page and the step ends
    // (Dispatch wire 7.4.14 "Lists").
    let (w, _router, third, mut app) = two_page_upload().await;
    let mut tx = app.tx().unwrap();
    tx.put(crate::app::recovery::lists::WAITS, &w.clock.now_ms())
        .unwrap();
    app.commit(tx).await.unwrap();
    third.fail_next(Fault::Unreachable {
        path: "recovery/upload".into(),
        after: 1,
    });
    assert!(app.follow_provider().await.is_err());
    assert_eq!(list_uploads(&third), 1, "the first page accepted");
    assert!(!list_upload_waits(&app).await);
    app.receive(None).await.unwrap();
    assert_eq!(list_uploads(&third), 2, "the second page sent by the read");
    assert_ne!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
}

#[tokio::test]
async fn test_loss_deny_removed_after_its_page_is_accepted_stays_removed_in_the_copy() {
    // A list upload of two pages: the first, with the deny entries, is accepted, and the
    // second can't connect. The user then unblocks one of those entries. The removal stands
    // at the service, and while the second page is owed the copy doesn't deny the peer again
    // for the upload's sake (Dispatch spec 12.6 step 2 and 3).
    let (_w, _router, third, mut app) = two_page_upload().await;
    third.fail_next(Fault::Unreachable {
        path: "recovery/upload".into(),
        after: 1,
    });
    assert!(app.follow_provider().await.is_err());
    assert_eq!(list_uploads(&third), 1, "the first page accepted");
    let mut peer = [4; 32];
    peer[28..].copy_from_slice(&0u32.to_be_bytes());
    assert!(third.lock().shared.deny.contains(&peer));
    assert!(app.lists_copy().await.unwrap().deny.contains(&peer));
    app.undeny(&peer).await.unwrap();
    assert!(!third.lock().shared.deny.contains(&peer));
    assert_eq!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    assert!(!app.lists_copy().await.unwrap().deny.contains(&peer));
}

/// An app whose list upload after a second loss, at the third service, is two pages long and
/// owed, its first try unanswered.
async fn two_page_upload() -> (World, Router, Arc<ScriptedDispatch>, App) {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
    )
    .await;
    // Two signed list reads at services whose operators raised the kept limit: the second
    // loss's contribution carries both, two pages.
    const KEPT: u32 = 160_000;
    const DENY: u32 = 5_000;
    let fill = |service: &ScriptedDispatch, kept_domain, deny_domain| {
        let peers = |domain, count| {
            (0u32..count).map(move |n| {
                let mut id = [domain; 32];
                id[28..].copy_from_slice(&n.to_be_bytes());
                id
            })
        };
        let mut state = service.lock();
        state.shared.kept.extend(peers(kept_domain, KEPT));
        state.shared.deny.extend(peers(deny_domain, DENY));
    };
    fill(&w.dispatch, 1, 2);
    drop(app.allow_list().await.unwrap());
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    let key = next_key();
    let next =
        ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    router.remove(ORIGIN);
    next.fail_next(Fault::Unanswered {
        path: "recovery/upload".into(),
        after: 1,
    });
    app.refresh_identity().await.unwrap();
    assert!(app.follow_provider().await.is_err());
    fill(&next, 3, 4);
    drop(app.allow_list().await.unwrap());
    let third = third_recovering(&w, &router, 3, 2);
    third.lock().max_kept_peers = 1;
    third.fail_next(Fault::Unanswered {
        path: "recovery/upload".into(),
        after: 1,
    });
    app.refresh_identity().await.unwrap();
    assert!(app.follow_provider().await.is_err());
    assert_eq!(recovery_step(&app).await, crate::app::RecoveryStep::Lists);
    (w, router, third, app)
}

#[tokio::test]
async fn test_loss_undeny_by_a_stopped_list_reader_is_refused() {
    // An app with `lists.read` alone may only leave a peer out of the owed upload; stopped,
    // it gets an error and leaves nothing out; once the alarm clears, it leaves the peer
    // out. An app without the list permissions is refused (Dispatch spec 3.2, Dispatch wire
    // 7.4.14 "Lists").
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    let (w, router, _next, mut app) = owed_upload_of(&[Permission::ListsRead], &[], &[dave]).await;
    app.state.alarm = Some(crate::app::Alarm::Rollback {
        reason: "test".into(),
    });
    assert_eq!(
        app.undeny(&dave).await.unwrap_err(),
        AppError::Refused(Refusal::Stopped)
    );
    let owed: Vec<_> = app
        .recovery_deny_entries()
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.pubky)
        .collect();
    assert_eq!(owed, [dave], "nothing left out");
    app.state.alarm = None;
    app.undeny(&dave).await.unwrap();
    assert!(app.recovery_deny_entries().await.unwrap().is_empty());
    drop((w, router, app));
    // An app without the list permissions.
    let w = World::new();
    let mut plain = w.join("wallet").await;
    let batches = w.dispatch.lock().batches.len();
    assert!(
        matches!(
            plain.undeny(&dave).await.unwrap_err(),
            AppError::Refused(Refusal::Usage(_))
        ),
        "no list permission"
    );
    assert_eq!(w.dispatch.lock().batches.len(), batches, "nothing sent");
}

#[tokio::test]
async fn test_loss_list_removal_stands_through_a_restore_in_place() {
    // A backup taken before the user removed carol: in place, the store's list recovery is
    // past it, so the restore is refused and the removal stands. Onto a store that never held
    // the removal, the resumed upload keeps her again, as the backup alone says, and tells
    // the host once it has, as of a loss's contribution (Dispatch spec 12.4, 12.6 step 3).
    for in_place in [true, false] {
        let (w, router, next, mut app, carol, _dave) = owed_list_upload().await;
        let backup = app.backup().await.unwrap();
        app.remove_kept_peer(&carol).await.unwrap();
        drop(app);
        let store: Arc<dyn StateStore> = if in_place {
            Arc::clone(&w.store) as Arc<dyn StateStore>
        } else {
            Arc::new(MemoryStore::new())
        };
        let restored = App::restore(
            router.env(&w, store),
            w.protocol.clone(),
            World::config(),
            &backup,
        )
        .await;
        if in_place {
            assert!(
                matches!(&restored, Err(AppError::Refused(Refusal::NotNow(_)))),
                "{:?}",
                restored.map(|_| ())
            );
            continue;
        }
        let mut restored = restored.unwrap();
        restored.follow_provider().await.unwrap();
        assert!(next.lock().shared.kept.contains(&carol));
        // Told once, when the resumed upload carried her.
        let told = restored
            .take_events()
            .into_iter()
            .filter(|e| {
                matches!(
                    e,
                    AppEvent::ListsUnverified {
                        kept: 1,
                        contributed: true,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(told, 1);
    }
}

#[tokio::test]
async fn test_capped_kept_peer_upload_retries_the_original_set_after_an_unknown_answer() {
    let w = World::new();
    let router = Router::of(&w);
    let mut manager = lists_app(&w, &router).await;
    let first = w.bob.public();
    let second = IdentityKey::from_secret(seed("carol/identity")).public();
    manager.keep_peer(&first).await.unwrap();
    manager.keep_peer(&second).await.unwrap();
    manager
        .keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    let key = next_key();
    let next =
        ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    next.lock().max_kept_peers = 1;
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    router.remove(ORIGIN);
    next.fail_next(Fault::LoseAnswerAfter {
        path: "recovery/upload".into(),
        after: 1,
    });
    manager.refresh_identity().await.unwrap();
    assert!(manager.follow_provider().await.is_err());
    assert_eq!(
        manager.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    assert_eq!(next.lock().shared.kept.len(), 1);
    drop(manager);
    let mut manager = App::load(
        router.env(&w, w.store.clone()),
        w.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    manager.follow_provider().await.unwrap();
    let bodies: Vec<_> = next
        .uploads()
        .into_iter()
        .filter(|(body, _)| body.get("lists").is_some())
        .map(|(body, _)| body)
        .collect();
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0], bodies[1]);
    let mut kept = [
        pubky_dispatch_core::enc::pubky_id(&first),
        pubky_dispatch_core::enc::pubky_id(&second),
    ];
    kept.sort();
    assert_eq!(bodies[0]["lists"]["kept"], json!(kept));
    assert_eq!(next.lock().shared.kept.len(), 1);
    assert!(!manager.admits(&first).await.unwrap());
    assert!(!manager.admits(&second).await.unwrap());
}

#[tokio::test]
async fn test_loss_deny_entries_past_the_limit_hold_the_list_step() {
    // No deny entry is dropped: when the new service's deny list holds entries the app's
    // copy lacks and the app's would pass the limit, the whole list upload is refused with how
    // many don't fit, the kept peer the app also denies isn't restored without its deny
    // entry, and the step runs again once the user has removed enough entries with `undeny`
    // (Dispatch wire 7.4.14 "Lists").
    let w = World::new();
    let router = Router::of(&w);
    let mut manager = lists_app(&w, &router).await;
    let first = w.bob.public();
    let second = IdentityKey::from_secret(seed("carol/identity")).public();
    manager.deny(&first).await.unwrap();
    manager.keep_peer(&second).await.unwrap();
    manager.deny(&second).await.unwrap();
    manager
        .keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    let key = next_key();
    let next =
        ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    let filler = |n: u64| {
        let mut key = [9u8; 32];
        key[24..].copy_from_slice(&n.to_be_bytes());
        key
    };
    {
        let mut state = next.lock();
        state
            .shared
            .deny
            .extend((0..pubky_dispatch_core::ops::MAX_DENY - 1).map(filler));
        state.admission_staged = true;
    }
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    router.remove(ORIGIN);
    manager.refresh_identity().await.unwrap();
    assert_eq!(
        manager.follow_provider().await.unwrap_err(),
        AppError::Refused(Refusal::DenyListFull { over: 1 })
    );
    assert!(
        manager
            .take_events()
            .contains(&AppEvent::RecoveryDenyListFull {
                generation: 2,
                over: 1
            })
    );
    assert_eq!(
        manager.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    {
        let held = next.lock();
        assert!(!held.shared.deny.contains(&first), "nothing merged");
        assert!(!held.shared.deny.contains(&second), "nothing merged");
        assert!(
            held.shared.kept.is_empty(),
            "the kept peer waits for its deny entry"
        );
        assert!(held.admission_staged);
    }
    manager.undeny(&filler(0)).await.unwrap();
    manager.follow_provider().await.unwrap();
    {
        let held = next.lock();
        assert!(held.shared.deny.contains(&first) && held.shared.deny.contains(&second));
        assert_eq!(
            u64::try_from(held.shared.deny.len()).unwrap(),
            pubky_dispatch_core::ops::MAX_DENY
        );
        assert_eq!(held.shared.kept, [second].into_iter().collect());
        assert!(!held.admission_staged);
    }
    assert!(!manager.admits(&first).await.unwrap());
    assert!(!manager.admits(&second).await.unwrap());
}

/// The replacement's list can change twice while the original contribution is
/// still owed. Reopen and fresh restore must send the same contributed IDs on
/// the next loss after the replacement removed its own entries.
async fn replacement_observation_before_second_loss(fresh: bool) {
    let original = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let lost = lost_world_with(
        original.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
        true,
        true,
    )
    .await;
    let mut app = load_loss(&lost, original.clone()).await.unwrap();
    lost.next.fail_next(Fault::Unanswered {
        path: "recovery/upload".into(),
        after: 1,
    });
    app.refresh_identity().await.unwrap();
    assert!(app.follow_provider().await.is_err());
    let peer = lost.w.bob.public();
    let denied = IdentityKey::from_secret(seed("replacement-only/identity")).public();
    app.keep_peer(&peer).await.unwrap();
    app.deny(&denied).await.unwrap();
    let snapshot = app.allow_list().await.unwrap();
    assert!(snapshot.kept_peers().any(|id| id == peer) && snapshot.deny.contains(&denied));
    let backup = app.backup().await.unwrap();
    // The app changes the hosted lists after the backup. The fresh restore
    // sees those removals only through its subsequent complete signed read.
    app.remove_kept_peer(&peer).await.unwrap();
    app.undeny(&denied).await.unwrap();
    drop(app);
    let mut app = if fresh {
        App::restore(
            lost.router.env(&lost.w, Arc::new(MemoryStore::new())),
            loss_set(&lost.protocol, &lost.others),
            World::config(),
            &backup,
        )
        .await
        .unwrap()
    } else {
        load_loss(&lost, original).await.unwrap()
    };
    let snapshot = app.allow_list().await.unwrap();
    assert!(!snapshot.kept_peers().any(|id| id == peer) && !snapshot.deny.contains(&denied));
    let third = third_recovering(&lost.w, &lost.router, 3, 2);
    app.refresh_identity().await.unwrap();
    app.follow_provider().await.unwrap();
    let posted = third
        .uploads()
        .into_iter()
        .find_map(|(body, _)| body.get("lists").cloned())
        .unwrap();
    assert_eq!(
        posted["kept"],
        json!([pubky_dispatch_core::enc::pubky_id(&lost.carol)])
    );
    assert_eq!(
        posted["deny"],
        json!([pubky_dispatch_core::enc::pubky_id(&lost.dave)])
    );
}

#[tokio::test]
async fn test_replacement_observation_after_restore_excludes_removed_members() {
    replacement_observation_before_second_loss(true).await;
}

#[tokio::test]
async fn test_replacement_observation_after_reopen_excludes_removed_members() {
    replacement_observation_before_second_loss(false).await;
}

#[tokio::test]
async fn test_a_later_loss_keeps_kept_peers_and_denies_not_yet_sent() {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let lost = lost_world_with(
        store.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
        true,
        true,
    )
    .await;
    let mut app = load_loss(&lost, store.clone()).await.unwrap();
    lost.next.fail_next(Fault::Unanswered {
        path: "recovery/upload".into(),
        after: 1,
    });
    app.refresh_identity().await.unwrap();
    assert!(app.follow_provider().await.is_err());
    assert_eq!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    let observed = app.allow_list().await.unwrap();
    assert!(observed.kept_peers().next().is_none() && observed.deny.is_empty());
    drop(app);
    let third = third_recovering(&lost.w, &lost.router, 3, 2);
    let mut app = load_loss(&lost, store).await.unwrap();
    app.refresh_identity().await.unwrap();
    app.follow_provider().await.unwrap();
    assert!(
        lost.next
            .uploads()
            .iter()
            .all(|(body, _)| body.get("lists").is_none())
    );
    let observed = app.allow_list().await.unwrap();
    assert_eq!(observed.kept_peers().collect::<Vec<_>>(), [lost.carol]);
    assert_eq!(observed.deny, [lost.dave]);
    assert_eq!(
        third
            .uploads()
            .iter()
            .filter(|(body, _)| body.get("lists").is_some())
            .count(),
        1
    );
}

#[tokio::test]
async fn test_large_signed_lists_resume_only_the_unanswered_page_after_restore() {
    let w = World::new();
    let router = Router::of(&w);
    let store = Arc::new(FaultStore::new(w.store.clone(), StoreFault::None));
    let mut app = join_on(
        &w,
        &router,
        store.clone(),
        w.protocol.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
    )
    .await;
    // Two real signed list reads at services whose operators raised the kept limit, with
    // deny lists that together fill the fixed deny limit, so the owed contribution takes
    // two pages. The replacement's rows are disjoint from those still owed to it.
    const KEPT: u32 = 160_000;
    const DENY: u32 = 5_000;
    let fill = |service: &ScriptedDispatch, kept_domain, deny_domain| {
        let peers = |domain, count| {
            (0u32..count).map(move |n| {
                let mut id = [domain; 32];
                id[28..].copy_from_slice(&n.to_be_bytes());
                id
            })
        };
        let mut state = service.lock();
        state.shared.kept.extend(peers(kept_domain, KEPT));
        state.shared.deny.extend(peers(deny_domain, DENY));
    };
    fill(&w.dispatch, 1, 2);
    let first = app.allow_list().await.unwrap();
    assert_eq!(
        (first.kept_peers().count(), first.deny.len()),
        (KEPT as usize, DENY as usize)
    );
    drop(first);
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.dispatch))])
        .await
        .unwrap();
    let key = next_key();
    let next =
        ScriptedDispatch::recovering(&w.alice, key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    router.remove(ORIGIN);
    next.fail_next(Fault::Unanswered {
        path: "recovery/upload".into(),
        after: 1,
    });
    app.refresh_identity().await.unwrap();
    assert!(app.follow_provider().await.is_err());
    assert_eq!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    fill(&next, 3, 4);
    let replacement = app.allow_list().await.unwrap();
    assert_eq!(
        (replacement.kept_peers().count(), replacement.deny.len()),
        (KEPT as usize, DENY as usize)
    );
    drop(replacement);
    let third = third_recovering(&w, &router, 3, 2);
    {
        let mut service = third.lock();
        service.max_kept_peers = 1;
    }
    // One raw page reaches the inactive bank, but the next page cannot be
    // stored. The last committed generation and its original duty survive.
    store.fail_put_once(b"loss-list-parts/0/loss/list-input/0/1");
    app.refresh_identity().await.unwrap();
    assert!(matches!(
        app.follow_provider().await,
        Err(AppError::Store(StoreError::Unavailable))
    ));
    assert!(third.uploads().is_empty());
    drop(app);
    let reopen = || {
        App::load(
            router.env(&w, store.clone()),
            w.protocol.clone(),
            World::config(),
            app_keys("wallet").app_id_bytes(),
        )
    };
    let mut app = reopen().await.unwrap();
    let prior = app.recovery_info().await.unwrap().unwrap();
    assert_eq!(
        (prior.loss.generation, prior.step),
        (2, crate::app::RecoveryStep::Lists)
    );
    // Rewriting the already stored first page would now fail. An unchanged
    // contribution resumes staging from its checked bytes.
    store.fail_put_once(b"loss-list-parts/0/loss/list-input/0/0");
    // Capture a backup before any list page is accepted. Then accept the
    // first page and lose the second page's answer after it is committed.
    third.fail_next(Fault::Unanswered {
        path: "recovery/upload".into(),
        after: 1,
    });
    assert!(app.follow_provider().await.is_err());
    drop(app);
    let mut app = reopen().await.unwrap();
    let before_page = app.backup().await.unwrap();
    third.fail_next(Fault::LoseAnswerAfter {
        path: "recovery/upload".into(),
        after: 1,
    });
    assert!(app.follow_provider().await.is_err());
    assert_eq!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    assert!(!third.lock().admission_staged);
    drop(app);
    let app = reopen().await.unwrap();
    let backup = app.backup().await.unwrap();
    drop(app);
    let stale = App::restore(
        router.env(&w, store),
        w.protocol.clone(),
        World::config(),
        &before_page,
    )
    .await;
    assert!(matches!(stale, Err(AppError::Refused(Refusal::NotNow(_)))));
    let mut restored = App::restore(
        router.env(&w, Arc::new(MemoryStore::new())),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.follow_provider().await.unwrap();
    assert!(restored.recovery_info().await.unwrap().unwrap().steps_done);
    let uploads = third.uploads();
    let pages: Vec<_> = uploads
        .iter()
        .filter_map(|(body, _)| body.get("lists"))
        .collect();
    assert_eq!(pages.len(), 3);
    let first_count = pages[0]["kept"].as_array().unwrap().len();
    assert!(first_count > 0 && first_count < 2 * KEPT as usize);
    assert_eq!(
        pages[0]["deny"].as_array().unwrap().len(),
        2 * DENY as usize
    );
    assert_eq!(
        pages[1]["kept"].as_array().unwrap().len(),
        2 * KEPT as usize - first_count
    );
    assert!(pages[1]["deny"].as_array().unwrap().is_empty());
    assert!(pages[1] == pages[2], "the same final page was retried");
    assert_eq!(third.lock().shared.kept.len(), 1);
    assert_eq!(third.lock().shared.deny.len(), 2 * DENY as usize);
}

#[tokio::test]
async fn test_refused_list_upload_remains_owed_after_reopen() {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let lost = lost_world_with(
        store.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
        true,
        true,
    )
    .await;
    let mut app = load_loss(&lost, store.clone()).await.unwrap();
    lost.next.fail_next(Fault::Unanswered {
        path: "recovery/upload".into(),
        after: 1,
    });
    app.refresh_identity().await.unwrap();
    assert!(app.follow_provider().await.is_err());
    lost.next.fail_next(Fault::Error {
        path: "recovery/upload".into(),
        code: ErrorCode::PermissionMissing,
        current: json!({}),
    });
    assert!(matches!(
        app.follow_provider().await,
        Err(AppError::Refused(Refusal::NotNow(_)))
    ));
    assert_eq!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    assert!(
        lost.next
            .uploads()
            .iter()
            .all(|(body, _)| body.get("lists").is_none())
    );
    drop(app);
    let app = load_loss(&lost, store.clone()).await.unwrap();
    let backup = app.backup().await.unwrap();
    drop(app);
    let mut app = App::restore(
        lost.router.env(&lost.w, store),
        loss_set(&lost.protocol, &lost.others),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    app.follow_provider().await.unwrap();
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
    let lists = app.allow_list().await.unwrap();
    assert_eq!(lists.kept_peers().collect::<Vec<_>>(), [lost.carol]);
    assert_eq!(lists.deny, [lost.dave]);
}

#[tokio::test]
async fn test_read_only_recovery_without_denies_keeps_an_earlier_backup_restorable() {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let lost = lost_world_with(store.clone(), &[Permission::ListsRead], false, false).await;
    let mut app = load_loss(&lost, store.clone()).await.unwrap();
    let backup = app.backup().await.unwrap();
    app.refresh_identity().await.unwrap();
    app.follow_provider().await.unwrap();
    assert!(
        lost.next
            .uploads()
            .iter()
            .all(|(body, _)| body.get("lists").is_none())
    );
    drop(app);
    App::restore(
        lost.router.env(&lost.w, store),
        loss_set(&lost.protocol, &lost.others),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
}

/// Resume the original list upload from a real backup taken after registration and
/// the evidence upload. The replacement's signed empty list was already observed.
async fn restore_owed_lists(layered: bool) {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let lost = lost_world_with(
        store.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
        true,
        true,
    )
    .await;
    let mut app = load_loss(&lost, store.clone()).await.unwrap();
    let earlier = app.backup().await.unwrap();
    lost.next.fail_next(Fault::Unanswered {
        path: "recovery/upload".into(),
        after: 1,
    });
    app.refresh_identity().await.unwrap();
    assert!(app.follow_provider().await.is_err());
    assert_eq!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    assert!(
        app.allow_list()
            .await
            .unwrap()
            .kept_peers()
            .next()
            .is_none()
    );
    let stale = App::restore(
        lost.router.env(&lost.w, store.clone()),
        loss_set(&lost.protocol, &lost.others),
        World::config(),
        &earlier,
    )
    .await;
    assert!(matches!(stale, Err(AppError::Refused(Refusal::NotNow(_)))));
    drop(app);
    let mut app = load_loss(&lost, store).await.unwrap();
    assert_eq!(
        app.recovery_info().await.unwrap().unwrap().step,
        crate::app::RecoveryStep::Lists
    );
    let backup = if layered {
        app.backup_layered().await.unwrap()
    } else {
        app.backup().await.unwrap()
    };
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    drop(app);
    let fresh = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let mut restored = App::restore(
        lost.router.env(&lost.w, fresh.clone()),
        loss_set(&lost.protocol, &lost.others),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.follow_provider().await.unwrap();
    let observed = restored.allow_list().await.unwrap();
    assert_eq!(observed.kept_peers().collect::<Vec<_>>(), [lost.carol]);
    assert_eq!(observed.deny, [lost.dave]);
    let count = || {
        lost.next
            .uploads()
            .into_iter()
            .filter(|(body, _)| body.get("lists").is_some())
            .count()
    };
    assert_eq!(count(), 1);
    restored.follow_provider().await.unwrap();
    assert_eq!(count(), 1);
    drop(restored);
    let stale = App::restore(
        lost.router.env(&lost.w, fresh.clone()),
        loss_set(&lost.protocol, &lost.others),
        World::config(),
        &backup,
    )
    .await;
    assert!(matches!(stale, Err(AppError::Refused(Refusal::NotNow(_)))));
    let mut current = load_loss(&lost, fresh).await.unwrap();
    assert!(current.recovery_info().await.unwrap().unwrap().steps_done);
    current.follow_provider().await.unwrap();
    assert_eq!(count(), 1);
}

#[tokio::test]
async fn test_plain_backup_before_list_upload_resumes_the_original_contribution() {
    restore_owed_lists(false).await;
}

#[tokio::test]
async fn test_layered_backup_before_list_upload_resumes_the_original_contribution() {
    restore_owed_lists(true).await;
}

#[tokio::test]
async fn test_loss_upload_merges_the_lists_and_ends_staged_admission() {
    // The next Dispatch merges the app's record and lists, and its kept peers, from an app
    // holding `lists.manage`, end staged admission (Dispatch spec 12.6 step 2, wire 7.4.14).
    let store = Arc::new(MemoryStore::new());
    let permissions = [Permission::ListsRead, Permission::ListsManage];
    let lost = lost_world_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        &permissions,
        true,
        true,
    )
    .await;
    let written = lost.w.dispatch.lock().shared.records.clone();
    lost.next.lock().admission_staged = true;
    let (_, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(!has(&events, |e| matches!(
        e,
        AppEvent::EvidenceRefused { .. }
    )));
    let next = lost.next.lock();
    assert!(!next.admission_staged);
    // The record written before the loss is taken at the version the lost Dispatch's proof
    // gave it, with no proof of its own.
    let (key, before) = written.iter().next().expect("the record");
    let taken = next.shared.records.get(key).expect("taken");
    assert_eq!(taken.state, before.state);
    assert_eq!((taken.uploaded, taken.proof.as_ref()), (Some(true), None));
    assert!(next.shared.kept.contains(&lost.carol));
    assert!(next.shared.deny.contains(&lost.dave));
    // A fork of that write, built on the same version in another batch, is kept divergent:
    // the record stays, its view `divergent` (Dispatch wire 7.4.14).
    let op = pubky_dispatch_core::ops::SignedOp::peek(&taken.op).unwrap();
    let fork = pubky_dispatch_core::ops::sign_batch(
        &app_keys("wallet"),
        &lost.w.alice.public(),
        Some(app_keys("wallet").app_id_bytes()),
        op.body().generation,
        [99; 16],
        vec![(Vec::new(), op.body().kind.clone())],
    )
    .unwrap();
    let cert = taken.cert.clone().unwrap();
    let state = taken.state.clone();
    drop(next);
    let body = json!({ "records": [{ "op": fork[0].signed(), "cert": cert }] });
    let (status, answer) = upload_at_next(&lost, &body.to_string());
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        answer["result"]["divergent"],
        json!([pubky_dispatch_core::enc::b64(key)])
    );
    let next = lost.next.lock();
    assert_eq!(next.shared.records[key].state, state);
    assert_eq!(next.shared.divergent[key].len(), 1);
}

/// A kept peer and a deny entry, backed up and restored onto a new device before the loss
/// is followed: with the old service gone the copy is the only evidence, so the restored
/// kept peer is contributed though nothing verified it, beside the deny entry, and the host
/// is told how many (Dispatch spec 12.4, 12.6 step 2).
async fn restored_loss_contributes_the_kept_peers(permissions: &[Permission]) {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        permissions,
        false,
        false,
    )
    .await;
    let erin = IdentityKey::from_secret(seed("erin/identity")).public();
    let frank = IdentityKey::from_secret(seed("frank/identity")).public();
    lost.w.dispatch.lock().not_hosted_unpinned = false;
    let mut app = load_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    app.keep_peer(&erin).await.unwrap();
    app.deny(&frank).await.unwrap();
    let backup = app.backup().await.unwrap();
    drop(app);
    lost.w.dispatch.lock().not_hosted_unpinned = true;
    let device = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        lost.router
            .env(&lost.w, Arc::clone(&device) as Arc<dyn StateStore>),
        loss_set(&lost.protocol, &lost.others),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(
        has(&restored.take_events(), |e| matches!(
            e,
            AppEvent::ListsUnverified {
                kept: 1,
                replies: 0,
                contributed: false,
                left_out: crate::app::ListsLeftOut::Nothing,
                ..
            }
        )),
        "{permissions:?}"
    );
    assert!(!restored.admits(&erin).await.unwrap(), "{permissions:?}");
    drop(restored);
    let contributed = |events: &[AppEvent]| {
        has(events, |e| {
            matches!(
                e,
                AppEvent::ListsUnverified {
                    kept: 1,
                    replies: 0,
                    contributed: true,
                    ..
                }
            )
        })
    };
    let (_, events) = follow_loss(&lost, Arc::clone(&device) as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(contributed(&events), "{permissions:?}: {events:?}");
    // The restore's event is kept too: the reload told it again.
    assert!(
        has(&events, |e| matches!(
            e,
            AppEvent::ListsUnverified {
                contributed: false,
                ..
            }
        )),
        "{permissions:?}"
    );
    // Kept until the host acknowledges it: an app that stops before is told again.
    let mut reopened = load_loss(&lost, device as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(contributed(&reopened.take_events()), "{permissions:?}");
    let lists = lost
        .next
        .uploads()
        .into_iter()
        .find_map(|(body, _)| body.get("lists").cloned())
        .expect("the lists' upload");
    assert_eq!(
        lists["kept"],
        json!([pubky_dispatch_core::enc::pubky_id(&erin)]),
        "{permissions:?}"
    );
    assert_eq!(
        lists["deny"],
        json!([pubky_dispatch_core::enc::pubky_id(&frank)]),
        "{permissions:?}"
    );
    // The deny entry wins at the new service.
    let next = lost.next.lock();
    assert!(next.shared.deny.contains(&frank), "{permissions:?}");
    assert!(!next.shared.kept.contains(&frank), "{permissions:?}");
}

#[tokio::test]
async fn test_loss_with_a_kept_row_that_doesnt_read_still_follows() {
    // A kept row whose value is neither empty nor the restore's mark reads as unverified: it
    // doesn't admit, and the loss goes on, contributing it (Dispatch spec 12.6 step 2).
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        &[Permission::ListsRead, Permission::ListsManage],
        false,
        false,
    )
    .await;
    let erin = IdentityKey::from_secret(seed("erin/identity")).public();
    let mut app = load_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let mut tx = app.tx().unwrap();
    tx.put_raw(
        &crate::app::admission::allow_key(PeerReason::Kept, &erin),
        vec![7, 7],
    )
    .unwrap();
    app.commit(tx).await.unwrap();
    assert!(!app.admits(&erin).await.unwrap());
    drop(app);
    let (_, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::ListsUnverified {
            kept: 1,
            contributed: true,
            ..
        }
    )));
    let lists = lost
        .next
        .uploads()
        .into_iter()
        .find_map(|(body, _)| body.get("lists").cloned())
        .expect("the lists' upload");
    assert_eq!(
        lists["kept"],
        json!([pubky_dispatch_core::enc::pubky_id(&erin)])
    );
}

#[tokio::test]
async fn test_loss_count_skips_a_kept_row_the_loss_commit_verifies() {
    // A marked kept row the loss's own commit writes, as a kept write it settles, is
    // verified there: it isn't counted. One the commit leaves alone is, and a peer the
    // upload also denies isn't (Dispatch spec 12.6 step 2).
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        &[Permission::ListsRead, Permission::ListsManage],
        false,
        false,
    )
    .await;
    let mut app = load_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let peer = |name: &str| IdentityKey::from_secret(seed(name)).public();
    let (erin, frank, gina) = (
        peer("erin/identity"),
        peer("frank/identity"),
        peer("gina/identity"),
    );
    let hank = peer("hank/identity");
    let mut tx = app.tx().unwrap();
    for who in [erin, frank, gina] {
        tx.put_raw(
            &crate::app::admission::allow_key(PeerReason::Kept, &who),
            crate::app::admission::observations::RESTORED_KEPT.to_vec(),
        )
        .unwrap();
    }
    app.commit(tx).await.unwrap();
    let mut tx = app.tx().unwrap();
    tx.put_raw(
        &crate::app::admission::allow_key(PeerReason::Kept, &erin),
        Vec::new(),
    )
    .unwrap();
    let denied = std::collections::BTreeSet::from([gina]);
    let counted = app
        .unverified_contributed([erin, frank, gina, hank].into_iter(), &denied, &tx)
        .await
        .unwrap();
    assert_eq!(counted, 1, "only frank is contributed unverified");
    // hank has no row: from an earlier loss's own copy he isn't counted, from a restored
    // one he is.
    let mut marked = app.tx().unwrap();
    marked
        .put(crate::app::recovery::lists::RESTORED_INPUT, &())
        .unwrap();
    app.commit(marked).await.unwrap();
    let counted = app
        .unverified_contributed([frank, hank].into_iter(), &denied, &tx)
        .await
        .unwrap();
    assert_eq!(counted, 2);
}

#[tokio::test]
async fn test_move_adds_back_deny_entries_before_kept_peers() {
    // The next service lacks a kept peer and a deny entry of the app's copy: the move sends
    // the deny entry first, so no moment admits a peer the copy denies (Dispatch spec 12.5
    // step 4).
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
    )
    .await;
    let [carol, dave] = ["carol", "dave"]
        .map(|n| IdentityKey::from_secret(seed(&format!("{n}/identity"))).public());
    app.keep_peer(&carol).await.unwrap();
    app.deny(&dave).await.unwrap();
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    {
        let mut held = next.lock();
        held.shared.kept.remove(&carol);
        held.shared.deny.remove(&dave);
    }
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    app.refresh_identity().await.unwrap();
    let _ = app.receive(None).await;
    app.receive(None).await.unwrap();
    let applied = next.applied();
    let at = |wanted: &dyn Fn(&OpKind) -> bool| {
        applied
            .iter()
            .position(|op| wanted(&op.body().kind))
            .expect("added back")
    };
    let denied = at(&|kind| matches!(kind, OpKind::DenyPut { pubky } if *pubky == dave));
    let kept = at(
        &|kind| matches!(kind, OpKind::AllowPut { pubky, reason: PeerReason::Kept } if *pubky == carol),
    );
    assert!(denied < kept, "kept before the deny");
}

#[tokio::test]
async fn test_move_without_lists_read_compares_nothing_and_completes() {
    // An app with `lists.manage` alone can't read the next service's lists: it asks for
    // none, adds nothing back, and follows the move (Dispatch spec 12.5 step 4).
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsManage],
    )
    .await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    app.keep_peer(&carol).await.unwrap();
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    // The next service lacks carol: an app that compared the lists would add her back.
    next.lock().shared.kept.remove(&carol);
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    app.refresh_identity().await.unwrap();
    let _ = app.receive(None).await;
    app.receive(None).await.unwrap();
    assert_eq!(app.state.meta.generation, 2);
    assert!(!next.lock().shared.kept.contains(&carol), "kept again");
    let asked = router
        .log()
        .into_iter()
        .filter(|line| line.starts_with(&format!("GET {NEXT}")) && line.contains("/allow"))
        .count();
    assert_eq!(asked, 0, "the lists were asked for");
}

#[tokio::test]
async fn test_restore_then_loss_contributes_the_restored_kept_peers() {
    for permissions in [
        &[Permission::ListsRead, Permission::ListsManage][..],
        &[Permission::ListsManage][..],
    ] {
        restored_loss_contributes_the_kept_peers(permissions).await;
    }
}

#[tokio::test]
async fn test_loss_upload_from_manage_holding_no_kept_peers_sends_them_empty() {
    // An app with `lists.manage` whose lists hold nothing still sends `kept: []`: that
    // upload ends staged admission (Dispatch spec 12.6 step 2).
    let store = Arc::new(MemoryStore::new());
    let permissions = [Permission::ListsRead, Permission::ListsManage];
    let lost = lost_world_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        &permissions,
        false,
        false,
    )
    .await;
    lost.next.lock().admission_staged = true;
    follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    let lists = lost
        .next
        .uploads()
        .into_iter()
        .find_map(|(body, _)| body.get("lists").cloned())
        .expect("the lists' upload");
    assert_eq!(lists["kept"], json!([]), "{lists}");
    assert!(!lost.next.lock().admission_staged);
}

#[tokio::test]
async fn test_loss_upload_without_manage_sends_no_kept_peers() {
    // An app with `lists.read` alone uploads its deny list and no kept peers, which it may not
    // send (`403` for the whole upload): staged admission stays for the signer to end.
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        &[Permission::ListsRead],
        false,
        true,
    )
    .await;
    lost.next.lock().admission_staged = true;
    let (_, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(!has(&events, |e| matches!(
        e,
        AppEvent::EvidenceRefused { .. }
    )));
    let lists = lost
        .next
        .uploads()
        .into_iter()
        .find_map(|(body, _)| body.get("lists").cloned())
        .expect("the lists' upload");
    assert!(lists.get("kept").is_none(), "{lists}");
    let next = lost.next.lock();
    assert!(next.admission_staged);
    assert!(next.shared.kept.is_empty());
    assert!(next.shared.deny.contains(&lost.dave));
}

/// The wallet's `POST /recovery/upload` of `body`, as a request to the lost world's next
/// Dispatch.
fn upload_request(lost: &Lost, body: &str) -> crate::transport::Request {
    crate::transport::Request {
        method: "POST".into(),
        origin: NEXT.into(),
        path_and_query: format!("/v1/{}/recovery/upload", lost.w.alice.id()),
        headers: vec![crate::transport::Header::new(
            "switch-app",
            &pubky_dispatch_core::enc::zbase32_encode(&app_keys("wallet").app_id_bytes()),
        )],
        body: body.as_bytes().to_vec(),
        timeout: crate::transport::TimeoutClass::Bulk,
    }
}

/// The wallet's `POST /recovery/upload` of `body` at the lost world's next Dispatch.
pub(crate) fn upload_at_next(lost: &Lost, body: &str) -> (u16, serde_json::Value) {
    let answer = lost.next.handle(&upload_request(lost, body)).unwrap();
    (answer.status, serde_json::from_slice(&answer.body).unwrap())
}

#[tokio::test]
async fn test_loss_upload_refusals_come_in_the_services_order() {
    // As at the service (Dispatch wire 7.2, 7.4.14): the caller's own checks before the body,
    // so an app not current at the next Dispatch yet gets `403 not_current` for a body that
    // doesn't read; once it is current, `400`.
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let (status, body) = upload_at_next(&lost, "not json");
    assert_eq!((status, body["code"].as_str()), (403, Some("not_current")));
    follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    let (status, body) = upload_at_next(&lost, "not json");
    assert_eq!((status, body["code"].as_str()), (400, Some("bad_request")));
}

#[tokio::test]
async fn test_loss_upload_is_limited_per_hour_and_the_kept_list_is_capped() {
    // As at the service (Dispatch wire 7.4.14, 9.4): past `uploads_per_app_per_hour` an upload
    // is `429 rate_limited` until the next hour of the Dispatch's clock, and kept peers past
    // `max_kept_peers` are dropped.
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    {
        let mut next = lost.next.lock();
        next.uploads_per_app_per_hour = 2;
        next.max_kept_peers = 0;
    }
    let (_, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    // The evidence and the lists both went, the two the hour takes.
    assert!(!has(&events, |e| matches!(
        e,
        AppEvent::EvidenceRefused { .. }
    )));
    {
        let next = lost.next.lock();
        assert!(next.shared.kept.is_empty(), "past max_kept_peers");
        assert!(next.shared.deny.contains(&lost.dave));
    }
    let (status, body) = upload_at_next(&lost, "{}");
    assert_eq!((status, body["code"].as_str()), (429, Some("rate_limited")));
    let wait = body["retry_after"].as_u64().unwrap();
    assert!((1..=3600).contains(&wait), "{wait}");
    lost.w.clock.advance_ms(wait * 1000);
    assert_eq!(upload_at_next(&lost, "{}").0, 200);
}

#[tokio::test]
async fn test_loss_upload_refused_takes_a_slot_of_the_hour() {
    // As at the service (Dispatch wire 7.4.14, 9.4): every upload of an own app counts
    // against `uploads_per_app_per_hour`, one refused for its body included, and past the
    // limit the refusals keep the wire's order. The `429` repeats its `retry_after` in
    // `Retry-After` (Dispatch wire 7.1).
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    lost.next.lock().uploads_per_app_per_hour = 3;
    // The evidence and the lists: two of the three.
    follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    let (status, body) = upload_at_next(&lost, "not json");
    assert_eq!((status, body["code"].as_str()), (400, Some("bad_request")));
    // The refused one took the third: an upload the Dispatch would take is limited.
    let (status, body) = upload_at_next(&lost, "{}");
    assert_eq!((status, body["code"].as_str()), (429, Some("rate_limited")));
    let wait = body["retry_after"].as_u64().unwrap();
    let limited = lost.next.handle(&upload_request(&lost, "{}")).unwrap();
    assert_eq!(limited.status, 429);
    assert_eq!(
        limited.header(pubky_dispatch_core::http::header::RETRY_AFTER),
        Some(wait.to_string().as_str())
    );
    // Past the limit a body that doesn't read is still `400`, and takes no slot.
    let (status, body) = upload_at_next(&lost, "not json");
    assert_eq!((status, body["code"].as_str()), (400, Some("bad_request")));
    lost.w.clock.advance_ms(wait * 1000);
    assert_eq!(upload_at_next(&lost, "{}").0, 200);
}

#[tokio::test]
async fn test_loss_upload_before_the_loss_takes_a_slot_of_the_hour() {
    // As at the service (Dispatch wire 7.4.14, 9.4): an upload takes its slot once the
    // caller is an app the Dispatch holds a record for, before the stage is looked at, so
    // one answered `404` at an account in neither stage counts too. The `404` itself comes
    // before the `429` in the answer order.
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    {
        // The next Dispatch as an account that lost no provider, the wallet registered there,
        // in an hour of its own.
        let mut next = lost.next.lock();
        next.recovery_from = None;
        next.uploads_per_app_per_hour = 2;
    }
    lost.w.clock.advance_ms(3_600_000);
    for _ in 0..3 {
        let (status, body) = upload_at_next(&lost, "{}");
        assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    }
    // After a loss in the same hour, the slots are used up.
    lost.next.lock().recovery_from = Some(1);
    let (status, body) = upload_at_next(&lost, "{}");
    assert_eq!((status, body["code"].as_str()), (429, Some("rate_limited")));
    // An app the Dispatch holds no record for takes none.
    let unknown = crate::transport::Request {
        headers: vec![crate::transport::Header::new(
            "switch-app",
            &pubky_dispatch_core::enc::zbase32_encode(&app_keys("unknown").app_id_bytes()),
        )],
        ..upload_request(&lost, "{}")
    };
    let refused = lost.next.handle(&unknown).unwrap();
    assert_eq!(refused.status, 403);
    assert!(
        !lost
            .next
            .lock()
            .upload_counts_of(&app_keys("unknown").app_id_bytes()),
        "no slot for an app without a record"
    );
}

#[tokio::test]
async fn test_loss_upload_answered_503_is_sent_again_and_staging_ends() {
    // A `503` the service may lift fails the step, which the next read sends again: the
    // lists' upload that ends staged admission isn't given up (Dispatch wire 7.6, 7.4.14).
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    lost.next.lock().admission_staged = true;
    lost.next.fail_next(Fault::Error {
        path: "recovery/upload".into(),
        code: ErrorCode::Unavailable,
        current: json!({}),
    });
    let error = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Unavailable), "{error:?}");
    assert!(lost.next.lock().admission_staged);
    let (_, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(!has(&events, |e| matches!(
        e,
        AppEvent::EvidenceRefused { .. }
    )));
    assert!(
        !lost.next.lock().admission_staged,
        "the lists went, and ended it"
    );
}

#[tokio::test]
async fn test_loss_upload_answered_429_waits_its_retry_after() {
    // The lists' upload answered `429 rate_limited` is sent again only once its
    // `retry_after` has passed by the device clock (Dispatch wire 7.6). A read goes on
    // meanwhile; the host sees the wait from `follow_provider`.
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    {
        let mut next = lost.next.lock();
        next.admission_staged = true;
        next.uploads_per_app_per_hour = 1;
    }
    let mut app = App::load(
        lost.router
            .env(&lost.w, Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    app.refresh_identity().await.unwrap();
    app.receive(None).await.unwrap();
    assert!(lost.next.lock().admission_staged, "the lists went");
    let sent = lost.next.uploads().len();
    app.receive(None).await.unwrap();
    let error = app.follow_provider().await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(crate::app::Refusal::NotNow(_))),
        "{error:?}"
    );
    assert_eq!(
        lost.next.uploads().len(),
        sent,
        "nothing sent while it waits"
    );
    lost.w.clock.advance_ms(3_600_000);
    app.receive(None).await.unwrap();
    assert!(!lost.next.lock().admission_staged);
}

#[tokio::test]
async fn test_loss_reports_unverified_evidence_to_protocol_and_advances() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let mut app = load_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let mut bad = first_proof(&lost.w.dispatch);
    bad.sig = pubky_dispatch_core::enc::b64(&[0; 64]);
    app.keep_evidence(vec![Evidence::Proof(bad)]).await.unwrap();
    drop(app);
    let (app, _) = follow_loss(&lost, store).await.unwrap();
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
    let calls = lost.protocol.losses.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].unverified, 1);
}

#[tokio::test]
async fn test_loss_refused_upload_is_reported_and_recovery_goes_on() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let mut app = load_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    app.retain_loss_uploads().await.unwrap();
    drop(app);
    lost.next.fail_next(Fault::Error {
        path: "recovery/upload".into(),
        code: ErrorCode::Conflict,
        current: json!({}),
    });
    let (app, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::EvidenceRefused { code } if code == "conflict"
    )));
    let info = app.recovery_info().await.unwrap().unwrap();
    assert!(info.steps_done);
    let observations = app.loss_uploads(2).await.unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].outcome,
        crate::app::LossUploadOutcome::Refused(ErrorCode::Conflict)
    );
    // The refused evidence isn't sent again; the lists went.
    assert_eq!(lost.next.uploads().len(), 1);
    assert_eq!(lost.protocol.losses.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_loss_registration_naming_another_key_stops_the_recovery() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    lost.next.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!({ "receive_key": null }),
    });
    let error = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap_err();
    // The conflict names no key, so the app looks for its own in the directory; the new
    // service holds no record of it yet, its registration refused, and refuses the read as
    // a first call, with no head (Dispatch wire 7.2). That isn't a removal.
    assert_eq!(error.code(), Some(ErrorCode::NotCurrent), "{error:?}");
    // Nothing past the registration ran; the next read resumes it.
    assert!(lost.next.uploads().is_empty());
    assert!(lost.protocol.losses.lock().unwrap().is_empty());
    let (app, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(
        !has(&events, |e| matches!(e, AppEvent::Removed)),
        "{events:?}"
    );
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
}

#[tokio::test]
async fn test_loss_crash_at_each_commit_point_resumes() {
    let counting_inner = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&counting_inner) as Arc<dyn StateStore>).await;
    let counting = Arc::new(FaultStore::new(
        counting_inner as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    follow_loss(&lost, Arc::clone(&counting) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let commits = counting.commits();
    assert!(commits > 5, "the recovery commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let inner = Arc::new(MemoryStore::new());
            let lost = lost_world(Arc::clone(&inner) as Arc<dyn StateStore>).await;
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let first = follow_loss(&lost, Arc::clone(&fault) as Arc<dyn StateStore>).await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            let (app, _) = follow_loss(&lost, Arc::clone(&inner) as Arc<dyn StateStore>)
                .await
                .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let me = app.app_id();
            let info = app.recovery_info().await.unwrap().unwrap();
            assert!(info.steps_done, "commit {n} ({stop_after})");
            assert!(app.reconcile_mode());
            // One registration at the new service; the re-sends' writes committed, the
            // protocol asked again only when the commit that carries them didn't happen.
            assert_eq!(lost.next.app(&me).receive_n, Some(1), "commit {n}");
            assert_eq!(
                app.protocol_get("sample", b"lost/1").await.unwrap(),
                Some(b"1".to_vec()),
                "commit {n} ({stop_after})"
            );
            assert!(lost.protocol.losses.lock().unwrap().len() <= 2);
            assert!(reply_grants_at(&lost.next) >= 1);
            assert!(app.alarm().is_none(), "commit {n} ({stop_after})");
        }
    }
}

// -------------------------------------------------------------------------------------
// Revocation and erasure (Dispatch spec 12.2, 12.7)

#[derive(Default)]
pub(crate) struct NoRelay;

impl PushRelay for NoRelay {
    fn register(
        &self,
        _relay_url: String,
        device_token: String,
        _push_key: [u8; 32],
    ) -> crate::transport::BoxFuture<'_, Result<String, TransportError>> {
        Box::pin(async move { Ok(format!("handle-{}", device_token.len())) })
    }
}

#[tokio::test]
async fn test_revoked_app_stops_and_drops_its_push_setting() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    app.register_push(&NoRelay, "https://push.example/v1/hook", "token")
        .await
        .unwrap();
    // The signer revokes the app at the service: every call is `403 not_current`. The
    // newest identity.json still lists the app with the certificate it holds, so the answer
    // is final: it is revoked (Dispatch wire 7.2, Dispatch spec 12.2).
    w.dispatch.revoke(me).unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Removed)));
    assert!(has(&report.events, |e| matches!(e, AppEvent::PushRemoved)));
    assert!(app.push_registration().await.unwrap().is_none());
    // It stays stopped, also once loaded again, and asks the service nothing.
    let mut app = w_load(&w, &router).await;
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

async fn w_load(w: &World, router: &Router) -> App {
    App::load(
        router.env(w, Arc::clone(&w.store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_removed_in_identity_json_stops_for_good() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Removed)));
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

/// A read that meets an erased account and doesn't conclude: the read fails as the wait's
/// own outcome, naming its first try (Dispatch spec 12.7).
async fn unreachable_read(app: &mut App) {
    let result = app.receive(None).await;
    let since = app.state.erasing.map(|e| e.since_ms);
    assert!(
        matches!(
            result,
            Err(AppError::NotAnsweringAsAccount { since_ms }) if Some(since_ms) == since
        ),
        "{result:?}"
    );
}

/// Tries spaced as the erasure wait counts them, up to the last one before it concludes.
async fn erasure_tries_but_the_last(w: &World, app: &mut App) {
    unreachable_read(app).await;
    for _ in 2..crate::app::provider::ERASURE_TRIES {
        w.clock
            .advance_ms(crate::app::provider::ERASURE_TRY_SPACING_MS);
        unreachable_read(app).await;
    }
}

#[tokio::test]
async fn test_erased_account_is_gone_once_the_identity_is_unpublished() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.register_push(&NoRelay, "https://push.example/v1/hook", "token")
        .await
        .unwrap();
    w.dispatch.lock().not_hosted_unpinned = true;
    // While the identity still publishes its identity.json, the unsigned 404 explains
    // nothing: the error stands, an answer that doesn't verify, and the app isn't stopped.
    let result = app.receive(None).await;
    assert!(
        matches!(
            result,
            Err(AppError::Dispatch(ClientError::BadServiceSignature {
                status: 404
            }))
        ),
        "{result:?}"
    );
    assert!(app.state.erasing.is_none());
    // The signer erased the account and deleted identity.json from the Homeserver. Until
    // both have held at tries spread over 24 hours, the service counts as unreachable.
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    erasure_tries_but_the_last(&w, &mut app).await;
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
    w.clock
        .advance_ms(crate::app::provider::ERASURE_TRY_SPACING_MS);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    let gone = |events: &[AppEvent]| {
        events
            .iter()
            .filter_map(|e| match e {
                AppEvent::AccountGone { id } => Some(*id),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let ids = gone(&report.events);
    assert_eq!(ids.len(), 1, "{:?}", report.events);
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
    // A duty event: kept in the store, and delivered again until it is acknowledged.
    assert_eq!(gone(&app.unacknowledged_events().await.unwrap()), ids);
    app.ack_events(ids[0]).await.unwrap();
    assert!(gone(&app.unacknowledged_events().await.unwrap()).is_empty());
    // The push setting is kept, only no longer set, for when the account shows again.
    assert!(app.push_registration().await.unwrap().is_none());
    assert!(app.push_record().await.unwrap().is_some());
}

/// The signer erases alice's account at the Dispatch (Dispatch wire 7.4.16): from then on the
/// Dispatch answers every call for her with the `404` of an identity it doesn't host, signed
/// with its service key.
async fn signer_erases(w: &World) {
    let signer = crate::client::DispatchClient::new(
        ORIGIN,
        w.alice.public(),
        crate::client::Credentials::Signer {
            identity: w.alice.public(),
            key: Arc::new(IdentityKey::from_secret(w.alice.secret_bytes())),
        },
        Some(w.dispatch.service_key()),
        w.dispatch.transport(),
        w.clock.clone(),
    )
    .unwrap()
    .with_account_created(w.dispatch.created())
    .unwrap();
    let held = w.dispatch.identity_doc().map(|doc| doc.hash());
    signer
        .erase(Some(w.dispatch.created()), held)
        .await
        .unwrap();
    assert!(w.dispatch.erased());
}

#[tokio::test]
async fn test_public_read_not_hosted_is_asked_again_with_a_signed_read() {
    // The public read binds no timestamp, so its `404` with `current: { "hosted": false }`
    // verifies at any time, a replayed one included: the app takes the service's word only
    // from a request it signed (Dispatch wire 7.1 "Identical requests"). While the account is
    // served, a missing identity.json ends nothing; once it is erased, it does.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    w.dispatch.fail_next(Fault::Error {
        path: "/identity".into(),
        code: ErrorCode::NotFound,
        current: pubky_dispatch_core::http::not_hosted_current(),
    });
    // The signed read finds the account hosted: the public read's `404` shows nothing.
    assert_eq!(app.check_for_move().await.unwrap(), ProviderStatus::Current);
    assert!(
        app.state.gone.is_none(),
        "not gone on the public read alone"
    );
    signer_erases(&w).await;
    assert_eq!(app.check_for_move().await.unwrap(), ProviderStatus::Gone);
}

#[tokio::test]
async fn test_erased_account_signed_404_and_no_identity_is_gone_at_once() {
    // The signed `404` of an identity the Dispatch doesn't host and a missing identity.json
    // together are an erasure, at once: the first read stops with `AccountGone` (Dispatch spec
    // 12.7 step 5, wire 7.4.16 "Afterwards").
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    signer_erases(&w).await;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::AccountGone { .. })),
        "{:?}",
        report.events
    );
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

#[tokio::test]
async fn test_erased_account_signed_404_with_identity_published_ends_nothing() {
    // A signed `404` while identity.json still names the service ends nothing: the service
    // counts as unreachable, the call fails as it came, and no wait starts (Dispatch spec 12.7
    // step 5).
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    signer_erases(&w).await;
    for _ in 0..2 {
        let result = app.receive(None).await;
        assert!(
            matches!(&result, Err(AppError::Dispatch(error)) if error.is_not_hosted()),
            "{result:?}"
        );
        assert!(app.state.gone.is_none());
        assert!(app.state.erasing.is_none());
    }
    let checked = app.check_for_move().await;
    assert!(
        matches!(&checked, Err(AppError::Dispatch(error)) if error.is_not_hosted()),
        "{checked:?}"
    );
    assert!(app.state.gone.is_none());
}

#[tokio::test]
async fn test_erasure_wait_counts_the_tries_of_check_for_move() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    // The public read meets the same unsigned 404: each spaced try counts in the wait's
    // record, and fails as the wait's outcome.
    for tries in 1..crate::app::provider::ERASURE_TRIES {
        let error = app.check_for_move().await.unwrap_err();
        let since = app.state.erasing.map(|e| e.since_ms);
        assert!(
            matches!(error, AppError::NotAnsweringAsAccount { since_ms } if Some(since_ms) == since),
            "{error:?}"
        );
        assert_eq!(app.state.erasing.map(|e| e.tries), Some(tries));
        w.clock
            .advance_ms(crate::app::provider::ERASURE_TRY_SPACING_MS);
    }
    // A read makes the last try: the account is gone.
    assert!(app.receive(None).await.unwrap().stopped);
    assert_eq!(app.check_for_move().await.unwrap(), ProviderStatus::Gone);
}

#[tokio::test]
async fn test_erasure_wait_goes_on_past_a_replayed_public_read() {
    // An answer to the public read verifies at any time, an earlier one sent again included,
    // so it shows no account alive now: the wait goes on until a signed read answers (Dispatch
    // spec 12.7, wire 7.1 "Identical requests").
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let before = public_read_now(&w);
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    let error = app.check_for_move().await.unwrap_err();
    assert!(
        matches!(error, AppError::NotAnsweringAsAccount { .. }),
        "{error:?}"
    );
    let erasing = app.state.erasing;
    assert!(erasing.is_some());
    w.clock
        .advance_ms(crate::app::provider::ERASURE_TRY_SPACING_MS);
    // A public read with no answer counts no try and starts nothing over.
    w.dispatch.fail_next(Fault::Unanswered {
        path: "/identity".into(),
        after: 0,
    });
    assert!(app.check_for_move().await.is_err());
    assert_eq!(app.state.erasing, erasing);
    // A replayed answer starts nothing over: the signed read it prompts counts the next try.
    replay_public_read(&w, &router, before);
    let _ = app.check_for_move().await;
    let held = |app: &App| app.state.erasing.map(|e| (e.since_ms, e.tries));
    let first = erasing.map(|e| (e.since_ms, e.tries + 1));
    assert_eq!(held(&app), first);
    // The account answers again: the public read, replayed still, makes the app ask the own
    // feed, whose signed answer ends the wait.
    w.dispatch.lock().not_hosted_unpinned = false;
    let _ = app.check_for_move().await;
    assert_eq!(app.state.erasing, None);
}

#[tokio::test]
async fn test_erasure_wait_survives_an_unanswered_signed_read() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    unreachable_read(&mut app).await;
    let waiting = app.state.erasing;
    assert!(waiting.is_some());
    w.dispatch.lock().not_hosted_unpinned = false;
    w.dispatch.fail_next(Fault::Unanswered {
        path: "/feed".into(),
        after: 0,
    });
    assert!(app.check_for_move().await.is_err());
    assert_eq!(app.state.erasing, waiting);
}

#[tokio::test]
async fn test_erasure_wait_ends_on_a_signed_read_a_public_refusal_prompts() {
    // A refusal the pinned key signed for the public read may be an earlier one sent again,
    // so it only prompts the signed read, whose answer ends the wait (Dispatch spec 12.7).
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    assert!(app.check_for_move().await.is_err());
    assert!(app.state.erasing.is_some());
    w.dispatch.lock().not_hosted_unpinned = false;
    w.dispatch.fail_next(Fault::Error {
        path: "/identity".into(),
        code: ErrorCode::RateLimited,
        current: serde_json::Value::Null,
    });
    let _ = app.check_for_move().await;
    assert_eq!(app.state.erasing, None);
}

#[tokio::test]
async fn test_erasure_wait_starts_over_on_any_answer_the_account_key_signs() {
    for clear in 0..3 {
        let w = World::new();
        let router = Router::of(&w);
        let mut app = lists_app(&w, &router).await;
        let published = w.homeserver.file(w.alice.public(), IDENTITY_PATH).unwrap();
        // One coincident blip starts the wait.
        w.dispatch.lock().not_hosted_unpinned = true;
        w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
        unreachable_read(&mut app).await;
        assert!(app.state.erasing.is_some());
        w.dispatch.lock().not_hosted_unpinned = false;
        match clear {
            // identity.json shows again.
            0 => {
                w.homeserver
                    .put(w.alice.public(), IDENTITY_PATH, published.clone());
                app.refresh_identity().await.unwrap();
            }
            // A batch answer verifies with the account's key.
            1 => {
                let dave = IdentityKey::from_secret(seed("dave/identity")).public();
                app.submit_batch(kept_peer_batch(dave)).await.unwrap();
            }
            // A signed refusal.
            _ => {
                w.dispatch.fail_next(Fault::Error {
                    path: "feed".into(),
                    code: ErrorCode::RateLimited,
                    current: json!({}),
                });
                assert!(app.receive(None).await.is_err());
            }
        }
        assert!(app.state.erasing.is_none(), "case {clear}");
        // A second blip a day later starts the wait again, and concludes nothing.
        w.clock.advance_ms(crate::app::provider::ERASURE_WAIT_MS);
        w.dispatch.lock().not_hosted_unpinned = true;
        w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
        unreachable_read(&mut app).await;
        assert_eq!(app.state.erasing.map(|e| e.tries), Some(1), "case {clear}");
        assert_ne!(
            app.follow_provider().await.unwrap(),
            ProviderStatus::Gone,
            "case {clear}"
        );
    }
}

#[tokio::test]
async fn test_erasure_wait_starts_over_on_a_signed_503() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let published = w.homeserver.file(w.alice.public(), IDENTITY_PATH).unwrap();
    // Hour 0: an unsigned 404 and no identity.json.
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    unreachable_read(&mut app).await;
    assert!(app.state.erasing.is_some());
    // Hour 12: a `503` signed with the account's key, an error the pinned key verifies.
    w.clock.advance_ms(12 * 3_600_000);
    w.dispatch.lock().not_hosted_unpinned = false;
    w.homeserver.put(w.alice.public(), IDENTITY_PATH, published);
    w.dispatch.fail_next(Fault::Error {
        path: "feed".into(),
        code: ErrorCode::Unavailable,
        current: json!({}),
    });
    let error = app.receive(None).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Unavailable));
    assert!(app.state.erasing.is_none());
    // Hour 24: another unsigned 404 starts the wait afresh.
    w.clock.advance_ms(12 * 3_600_000);
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    unreachable_read(&mut app).await;
    let now = w.clock.now_ms();
    assert_eq!(
        app.state.erasing.map(|e| (e.since_ms, e.tries)),
        Some((now, 1))
    );
    assert_ne!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

#[tokio::test]
async fn test_erasure_wait_isnt_concluded_by_a_clock_jump() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    unreachable_read(&mut app).await;
    // The clock jumps a week ahead: that counts one try, and the tries right after it add
    // nothing.
    w.clock.advance_ms(7 * DAY_MS);
    for _ in 0..10 {
        unreachable_read(&mut app).await;
        w.clock.advance_ms(60_000);
    }
    assert_eq!(app.state.erasing.map(|e| e.tries), Some(2));
    assert_ne!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
    // A clock gone back starts the wait over.
    w.clock.set_ms(w.clock.now_ms() - 8 * DAY_MS);
    unreachable_read(&mut app).await;
    assert_eq!(app.state.erasing.map(|e| e.tries), Some(1));
}

/// An app whose account was taken as erased, holding alice's version 2; the Homeserver
/// serves nothing. Returns the bytes of her version 1.
async fn erased_holding_v2(w: &World, router: &Router) -> (App, Vec<u8>) {
    let mut app = join(w, router).await;
    let first = w.homeserver.file(w.alice.public(), IDENTITY_PATH).unwrap();
    w.next_doc(|_| {});
    app.refresh_identity().await.unwrap();
    assert_eq!(app.state.own_doc.version(), 2);
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    erasure_tries_but_the_last(w, &mut app).await;
    w.clock
        .advance_ms(crate::app::provider::ERASURE_TRY_SPACING_MS);
    assert!(app.receive(None).await.unwrap().stopped);
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
    (app, first)
}

#[tokio::test]
async fn test_erased_account_isnt_revived_by_an_older_document() {
    let w = World::new();
    let router = Router::of(&w);
    let (mut app, first) = erased_holding_v2(&w, &router).await;
    // A stale version 1 shows again: nothing newer than what the app holds.
    w.homeserver.put(w.alice.public(), IDENTITY_PATH, first);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(
        !has(&report.events, |e| matches!(e, AppEvent::AccountBack)),
        "{:?}",
        report.events
    );
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

#[tokio::test]
async fn test_erased_account_stays_gone_when_the_copy_fails() {
    let w = World::new();
    let router = Router::of(&w);
    let (mut app, _) = erased_holding_v2(&w, &router).await;
    // Another body at the version held: equivocation, so the copy fails.
    let mut body = w.signer.body();
    body.record_max_age = Some(3600);
    let other = IdentityDoc::sign(&w.alice, body).unwrap();
    assert_eq!(other.version(), 2);
    w.homeserver.publish(&other).unwrap();
    assert!(app.receive(None).await.is_err());
    // `gone` stays, in the store too.
    assert!(app.state.gone.is_some());
    assert!(
        app.reader()
            .exists(crate::app::provider::keys::GONE)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_erased_account_seen_alive_again_comes_back() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let published = w.homeserver.file(w.alice.public(), IDENTITY_PATH).unwrap();
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    erasure_tries_but_the_last(&w, &mut app).await;
    w.clock
        .advance_ms(crate::app::provider::ERASURE_TRY_SPACING_MS);
    assert!(app.receive(None).await.unwrap().stopped);
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
    // It was a fault: the account and its identity.json are there again.
    w.dispatch.lock().not_hosted_unpinned = false;
    w.homeserver.put(w.alice.public(), IDENTITY_PATH, published);
    let seq = w.note(me, "after the fault").0;
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(e, AppEvent::AccountBack)),
        "{:?}",
        report.events
    );
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_ne!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

/// An `AccountGone` the host took but didn't acknowledge, and the account seen alive again
/// (`AccountBack`): the event no longer holds, so it goes in the commit that brings the
/// account back, and no later load delivers it for a live account.
#[tokio::test]
async fn test_erased_account_back_drops_its_unacknowledged_account_gone() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let published = w.homeserver.file(w.alice.public(), IDENTITY_PATH).unwrap();
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    erasure_tries_but_the_last(&w, &mut app).await;
    w.clock
        .advance_ms(crate::app::provider::ERASURE_TRY_SPACING_MS);
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::AccountGone { .. }
    )));
    w.dispatch.lock().not_hosted_unpinned = false;
    w.homeserver.put(w.alice.public(), IDENTITY_PATH, published);
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(e, AppEvent::AccountBack)));
    let kept = app.unacknowledged_events().await.unwrap();
    assert!(
        !has(&kept, |e| matches!(e, AppEvent::AccountGone { .. })),
        "{kept:?}"
    );
    drop(app);
    let mut app = w_load(&w, &router).await;
    let events = app.take_events();
    assert!(
        !has(&events, |e| matches!(e, AppEvent::AccountGone { .. })),
        "{events:?}"
    );
    assert_ne!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

#[test]
fn test_residual_window_is_a_minute_and_the_tolerance() {
    assert_eq!(crate::app::RESIDUAL_WINDOW_MS, 60_000 + CLOCK_TOLERANCE_MS);
}

#[tokio::test]
async fn test_evidence_takes_only_record_and_claim_operations() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let usage = |error: AppError| matches!(error, AppError::Refused(crate::app::Refusal::Usage(_)));
    // The join's app.put is no evidence.
    let op = w.dispatch.applied()[0].signed().clone();
    let cert = app.cert().signed().clone();
    let error = app
        .keep_evidence(vec![Evidence::Op {
            op,
            cert,
            proof: None,
        }])
        .await
        .unwrap_err();
    assert!(usage(error));
    // Nor is a proof that doesn't read.
    let error = app
        .keep_evidence(vec![Evidence::Proof(SignedDoc::from_parts(
            b"{}", &[0; 64],
        ))])
        .await
        .unwrap_err();
    assert!(usage(error));
    // A proof is kept, and forgotten; its Debug shows nothing of it.
    let proof = Evidence::Proof(first_proof(&w.dispatch));
    assert_eq!(format!("{proof:?}"), "Evidence::Proof");
    app.keep_evidence(vec![proof.clone()]).await.unwrap();
    app.forget_evidence(&[proof]).await.unwrap();
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    app.receive(None).await.unwrap();
    assert_eq!(next.uploads()[0].0["proofs"], json!([]));
}

#[tokio::test]
async fn test_not_current_while_listed_with_another_certificate_is_no_removal() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // The newest identity.json lists the app with a renewed certificate it hasn't taken.
    let mut body = w.signer.body();
    body.version += 1;
    for listed in body.apps.iter_mut().filter(|a| a.app_id == me) {
        listed.cert = [9; 32];
    }
    w.homeserver
        .publish(&IdentityDoc::sign(&w.alice, body).unwrap())
        .unwrap();
    w.dispatch.fail_next(Fault::Error {
        path: "feed".into(),
        code: ErrorCode::NotCurrent,
        current: json!({}),
    });
    let error = app.receive(None).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotCurrent));
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
}

// -------------------------------------------------------------------------------------
// Earlier generations' evidence, and writes before the upload

pub(crate) const CLAIM: [u8; 32] = [5; 32];
pub(crate) const ATTEMPT: [u8; 16] = [6; 16];

/// The same origin under a new key at generation 2, published (a key change in place).
pub(crate) fn change_key(w: &World, router: &Router) -> Arc<ScriptedDispatch> {
    let pending = SigningKey::from_bytes(&seed("service/alice/pending"));
    let changed = w.dispatch.change_key_into(pending.to_bytes());
    router.add(ORIGIN, &changed);
    publish_at(
        w,
        &changed,
        Inbox::new(ORIGIN, pending.verifying_key().to_bytes()),
        2,
        None,
    );
    changed
}

#[tokio::test]
async fn test_claim_read_after_a_key_change_checks_earlier_proofs_with_their_key() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    app.write_claim(
        ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
        vec![],
        ObligationDeadline::NoDeadline,
    )
    .await
    .unwrap();
    change_key(&w, &router);
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    // The entry carries generation 1's proof: checked with that generation's key, no alarm.
    let read = app.read_claim(&CLAIM).await.unwrap().unwrap();
    assert_eq!(read.entries.len(), 1);
    assert!(app.alarm().is_none(), "{:?}", app.alarm());
}

/// The own attempt asked again after a key change: the proof the app holds for it is of
/// generation 1, not the generation its `identity.json` names now, so it doesn't pass the
/// checks of an own attempt (Dispatch wire 6.5 "Binding"), and the conflict stands.
#[tokio::test]
async fn test_claim_attempt_made_again_after_a_key_change_gets_the_conflict() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    app.write_claim(attempt, vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    change_key(&w, &router);
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    let error = app
        .write_claim(attempt, vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict), "{error:?}");
    // The conflict shows the app's own attempt open, current and not orphaned: only the
    // proof's generation keeps it from being returned as held.
    let view = crate::app::claim_conflict(&error).unwrap();
    assert_eq!(view.attempt_id, Some(ATTEMPT));
    assert_eq!(view.owner, Some(app.app_id()));
    assert!(!view.attempt(&ATTEMPT).unwrap().orphaned);
}

#[tokio::test]
async fn test_claim_entry_of_an_earlier_generation_in_the_feed_is_kept() {
    let w = World::new();
    let router = Router::of(&w);
    let phone_store = Arc::new(MemoryStore::new());
    let mut phone = App::join(
        router.env(&w, Arc::clone(&phone_store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        // `claims.read`, to read the claim entry in full (Dispatch wire 7.5).
        w.signer
            .approve(
                &app_keys("phone"),
                &AppSpec::new(&["sample-a"]).with_permissions(&[Permission::ClaimsRead]),
            )
            .unwrap(),
    )
    .await
    .unwrap();
    phone.receive(None).await.unwrap();
    let mut wallet = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    wallet
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap();
    change_key(&w, &router);
    // The phone learns of the change first, then reads generation 1's items at the new key.
    phone.refresh_identity().await.unwrap();
    phone.receive(None).await.unwrap();
    assert_eq!(phone.cursor().generation, 2);
    assert!(phone.alarm().is_none(), "{:?}", phone.alarm());
    let evidence = phone.claim_evidence(&CLAIM).await.unwrap();
    assert!(evidence.is_some(), "the entry's evidence is kept");
}

#[tokio::test]
async fn test_loss_writes_wait_for_the_upload() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    lost.next.fail_next(Fault::LoseAnswer {
        path: "recovery/upload".into(),
    });
    assert!(
        follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
            .await
            .is_err()
    );
    let mut app = App::load(
        lost.router
            .env(&lost.w, Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    let applied = lost.next.applied().len();
    let error = app
        .submit_batch(crate::app::OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(crate::app::Refusal::NotNow(_))),
        "{error:?}"
    );
    let error = app.end_reconcile(UserConfirmed::new()).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(crate::app::Refusal::NotNow(_))),
        "{error:?}"
    );
    // Nor does a rotation go, whose key is kept for later (Dispatch spec 12.6 step 3).
    let error = app.rotate().await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(crate::app::Refusal::NotNow(_))),
        "{error:?}"
    );
    assert_eq!(lost.next.applied().len(), applied);
    // Once the upload went, the app writes.
    app.receive(None).await.unwrap();
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
    app.submit_batch(crate::app::OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap();
}

// -------------------------------------------------------------------------------------
// Provider changes that go wrong on the way (Dispatch spec 12.5 "Abort", 12.6, 13.5)

/// A third service's origin.
pub(crate) const THIRD: &str = "https://third.example";

/// A service recovering alice's account at `generation` after the loss of `from`, at
/// `THIRD`, with the signer's document naming it delivered and published.
pub(crate) fn third_recovering(
    w: &World,
    router: &Router,
    generation: u64,
    from: u64,
) -> Arc<ScriptedDispatch> {
    let key = SigningKey::from_bytes(&seed("service/alice/third"));
    let third = ScriptedDispatch::recovering(
        &w.alice,
        key.to_bytes(),
        Arc::clone(&w.clock),
        generation,
        from,
    )
    .unwrap();
    router.add(THIRD, &third);
    publish_at(
        w,
        &third,
        Inbox::new(THIRD, key.verifying_key().to_bytes()),
        generation,
        Some(from),
    );
    third
}

fn transport(error: &AppError) -> bool {
    matches!(error, AppError::Transport(_))
}

pub(crate) fn allow_ops_for(ops: &[pubky_dispatch_core::ops::SignedOp], who: [u8; 32]) -> usize {
    ops.iter()
        .filter(|op| matches!(op.body().kind, OpKind::AllowPut { pubky, .. } if pubky == who))
        .count()
}

#[tokio::test]
async fn test_move_reads_the_old_feed_past_pages_of_entries_alone() {
    let w = World::new();
    let router = Router::of(&w);
    let config = AppConfig {
        page_size: 2,
        ..World::config()
    };
    let mut app = App::join(
        router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        config,
        approve_with(&w, &[Permission::ReplyAdd]),
    )
    .await
    .unwrap();
    let me = app.app_id();
    // More than a page of inbox entries after the last chain item, then the freeze.
    for i in 0..5 {
        w.note(me, &format!("note {i}"));
    }
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    // A read of the old feed that never ends fails here instead of running on.
    router.limit_feeds(50);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert_eq!(next.uploads().len(), 1, "{:?}", report.events);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    // Every entry is processed once, at the next service.
    assert_eq!(reply_grants_at(&next), 5);
    assert_eq!(w.effects(), 0);
}

#[tokio::test]
async fn test_move_stuck_at_a_gone_next_service_follows_a_newer_loss() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    // The next service is gone before the app re-registers there: the move is stuck.
    router.remove(NEXT);
    let error = app.receive(None).await.unwrap_err();
    assert!(transport(&error), "{error:?}");
    assert!(transport(&app.receive(None).await.unwrap_err()));
    // The signer declares generation 2 lost, at a third service.
    let third = third_recovering(&w, &router, 3, 2);
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::ProviderChangeSuperseded {
                generation: 2,
                newer: 3
            }
        )),
        "{:?}",
        report.events
    );
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderLost {
            lost_generation: 2,
            generation: 3
        }
    )));
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderRecovered { generation: 3 }
    )));
    assert_eq!(app.cursor().generation, 3);
    assert!(third.app(&me).receive_n.is_some());
    assert!(app.alarm().is_none());
}

#[tokio::test]
async fn test_loss_stuck_at_a_gone_service_follows_a_newer_loss() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // The new service is gone too before the app registers there.
    lost.router.remove(NEXT);
    let error = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap_err();
    assert!(transport(&error), "{error:?}");
    // The signer declares generation 2 lost, at a third service.
    let third = third_recovering(&lost.w, &lost.router, 3, 2);
    let (app, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(
        has(&events, |e| matches!(
            e,
            AppEvent::ProviderChangeSuperseded {
                generation: 2,
                newer: 3
            }
        )),
        "{events:?}"
    );
    let info = app.recovery_info().await.unwrap().unwrap();
    assert!(info.steps_done);
    assert_eq!(info.loss.lost_generation, 2);
    assert_eq!(info.loss.generation, 3);
    assert!(third.app(&app.app_id()).receive_n.is_some());
    // The re-sends are asked once, from the cursor's time at the first service.
    let losses = lost.protocol.losses.lock().unwrap().clone();
    assert_eq!(losses.len(), 1);
    assert_eq!(losses[0].accepted_from_ms, lost.note_at_ms);
}

#[tokio::test]
async fn test_move_carries_kept_batches_to_the_next_service() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsManage, Permission::ReplyAdd],
    )
    .await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let erin = IdentityKey::from_secret(seed("erin/identity")).public();
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    let kept_peer = |pubky| {
        crate::app::OpBatch::new().op(OpKind::AllowPut {
            pubky,
            reason: PeerReason::Kept,
        })
    };
    // A batch the old service applied, its answer lost.
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let applied_id = app
        .submit_batch(kept_peer(carol))
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    // A batch queued while the account is frozen (Dispatch spec 12.5 step 2).
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let error = app.submit_batch(kept_peer(erin)).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Moved));
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchApplied { .. }
        )),
        "{:?}",
        report.events
    );
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::KeptBatchSignedAgain { .. }
    )));
    // Its end says so, at the commit that settled it from the old chain.
    assert_eq!(
        app.kept_batch(applied_id).await.unwrap(),
        Some(crate::app::KeptBatchStatus::Applied {
            applied_at_ms: w.clock.now_ms()
        })
    );
    assert!(app.admits(&carol).await.unwrap());
    // The batch the old service never applied goes to the next one at generation 2, with
    // the next write.
    app.submit_batch(kept_peer(dave)).await.unwrap();
    let applied = next.applied();
    assert!(applied.iter().any(|op| op.body().generation == 2
        && matches!(op.body().kind, OpKind::AllowPut { pubky, .. } if pubky == erin)));
    // The one it applied isn't applied again.
    assert_eq!(allow_ops_for(&applied, carol), 0);
    assert_eq!(allow_ops_for(&w.dispatch.applied(), carol), 1);
    assert_eq!(allow_ops_for(&applied, erin), 1);
}

/// An app with kept peers to write, joined at the first service.
async fn lists_app(w: &World, router: &Router) -> App {
    join_on(
        w,
        router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsManage, Permission::ReplyAdd],
    )
    .await
}

pub(crate) fn kept_peer_batch(pubky: [u8; 32]) -> crate::app::OpBatch {
    crate::app::OpBatch::new().op(OpKind::AllowPut {
        pubky,
        reason: PeerReason::Kept,
    })
}

#[tokio::test]
async fn test_key_change_sends_a_kept_batch_again_and_its_original_proofs_show_it_applied() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    // Applied at generation 1, its answer lost; the app never reads it there.
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let id = app
        .submit_batch(kept_peer_batch(carol))
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    let changed = change_key(&w, &router);
    // Sent again unchanged, it gets its original proofs, which a key change in place keeps,
    // checked with generation 1's key: applied, and never signed again (Dispatch spec 12.5
    // "Kept batches", Dispatch wire 6.4 step 6).
    let report = app.receive(None).await.unwrap();
    assert!(app.alarm().is_none(), "{:?}", app.alarm());
    assert_eq!(
        changed
            .lock()
            .batches
            .values()
            .filter(|record| record.proofs.is_some())
            .count(),
        w.dispatch.lock().batches.len(),
        "the original proofs are kept"
    );
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchApplied { .. }
        )),
        "{:?}",
        report.events
    );
    assert!(
        !has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchSignedAgain { .. }
        )),
        "{:?}",
        report.events
    );
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(
        app.kept_batch(id).await.unwrap(),
        Some(crate::app::KeptBatchStatus::Applied {
            applied_at_ms: w.clock.now_ms()
        })
    );
    assert_eq!(allow_ops_for(&changed.applied(), carol), 0);
    assert_eq!(allow_ops_for(&w.dispatch.applied(), carol), 1);
    assert!(app.admits(&carol).await.unwrap());
}

#[tokio::test]
async fn test_unseen_move_sends_a_kept_batch_again_and_its_conflict_shows_it_applied() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.submit_batch(kept_peer_batch(carol)).await.is_err());
    // A move the app never saw frozen: the import carries the batch's ID without its
    // proofs, so the resend is answered `409 conflict`, which shows it applied.
    let n_key = next_key();
    let next = w.dispatch.import_into_at(n_key.to_bytes(), NEXT);
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    // The app learns of the move from its identity.json, before reading the old feed.
    app.refresh_identity().await.unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchApplied { .. }
        )),
        "{:?}",
        report.events
    );
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(allow_ops_for(&next.applied(), carol), 0);
    assert!(app.admits(&carol).await.unwrap());
}

#[tokio::test]
async fn test_unseen_move_after_a_lost_reply_grant_answer_keeps_receiving() {
    // A reply grant applied at the old service, its answer lost, then a move the app never
    // saw frozen: the conflict on resend shows it applied but at no position the app can
    // order against its earlier full read. The app drops its local reply row rather than
    // refusing, so receiving and sending go on, and its next send repeats the grant, which
    // the service takes as a repeat (Dispatch spec 7, 12.5).
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsRead, Permission::ReplyAdd],
    )
    .await;
    app.allow_list().await.unwrap();
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.invite(&carol).await.is_err());
    let n_key = next_key();
    let next = w.dispatch.import_into_at(n_key.to_bytes(), NEXT);
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    app.refresh_identity().await.unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchApplied { .. }
        )),
        "{:?}",
        report.events
    );
    assert!(app.kept_batches().await.unwrap().is_empty());
    app.receive(None).await.unwrap();
    app.flush_outbox().await.unwrap();
}

#[tokio::test]
async fn test_move_after_a_lost_reply_removal_answer_forgets_the_grant() {
    // A removal of a reply grant applied at the old service, its answer lost, then a
    // cooperative move: the kept batch settles as applied, and the app no longer believes
    // the peer may reply, so its next send writes the grant again (Dispatch spec 7, 12.5).
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsManage, Permission::ReplyAdd],
    )
    .await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    app.invite(&carol).await.unwrap();
    assert!(app.admits(&carol).await.unwrap());
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.remove_reply(&carol).await.is_err());
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchApplied { .. }
        )),
        "{:?}",
        report.events
    );
    assert!(!app.admits(&carol).await.unwrap());
}

#[tokio::test]
async fn test_move_after_a_lost_reply_grant_answer_grants_again_at_the_next_send() {
    // A reply grant applied at the old service, its answer lost, then a cooperative move: the
    // move's reply writes have no position the app can order, so the row is dropped rather
    // than placed. The app holds a narrower view, and its next send writes the grant again,
    // which the next service, holding the imported grant, takes as a repeat (Dispatch spec 7).
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsManage, Permission::ReplyAdd],
    )
    .await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.invite(&carol).await.is_err());
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::KeptBatchApplied { .. }
    )));
    assert!(!app.admits(&carol).await.unwrap());
    assert!(app.reply_grant_owed(&carol).await.unwrap());
}

#[tokio::test]
async fn test_restore_in_place_of_an_older_backup_never_widens_admission() {
    // A backup from before the app removed a reply grant and denied a peer, restored in place:
    // the deny written since stays, and the restored grant neither admits nor counts as held,
    // so a send writes it again, until something verifies it. For a list reader a list read
    // does; for an app without one only its own write on the peer (Dispatch spec 7, 12.4).
    for read in [false, true] {
        let w = World::new();
        let router = Router::of(&w);
        let permissions: &[Permission] = if read {
            &[
                Permission::ListsRead,
                Permission::ListsManage,
                Permission::ReplyAdd,
            ]
        } else {
            &[Permission::ListsManage, Permission::ReplyAdd]
        };
        let mut app = join_on(
            &w,
            &router,
            Arc::clone(&w.store) as Arc<dyn StateStore>,
            w.protocol.clone(),
            permissions,
        )
        .await;
        let carol = IdentityKey::from_secret(seed("carol/identity")).public();
        let dave = IdentityKey::from_secret(seed("dave/identity")).public();
        let erin = IdentityKey::from_secret(seed("erin/identity")).public();
        app.invite(&carol).await.unwrap();
        app.invite(&dave).await.unwrap();
        assert!(!app.reply_grant_owed(&carol).await.unwrap());
        let backup = app.backup().await.unwrap();
        app.remove_reply(&carol).await.unwrap();
        app.deny(&dave).await.unwrap();
        // A peer the backup has no row of, denied since.
        app.deny(&erin).await.unwrap();
        drop(app);
        let mut restored = App::restore(
            router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>),
            w.protocol.clone(),
            World::config(),
            &backup,
        )
        .await
        .unwrap();
        for app in [&restored] {
            assert!(
                !app.admits(&dave).await.unwrap(),
                "the deny written since stays"
            );
            assert!(
                !app.admits(&carol).await.unwrap(),
                "{read}: the removed grant admits"
            );
            assert!(app.reply_grant_owed(&carol).await.unwrap());
            assert!(
                app.reader()
                    .exists(&crate::app::admission::deny_key(&erin))
                    .await
                    .unwrap(),
                "{read}: the deny written since is lost"
            );
        }
        restored.receive(None).await.unwrap();
        assert!(!restored.admits(&carol).await.unwrap());
        assert!(!restored.admits(&dave).await.unwrap());
        // The app's own grant verifies the row again.
        restored.invite(&carol).await.unwrap();
        assert!(restored.admits(&carol).await.unwrap());
        assert!(!restored.reply_grant_owed(&carol).await.unwrap());
    }
}

#[tokio::test]
async fn test_restore_then_move_keeps_no_peer_the_backup_alone_keeps() {
    // A kept peer the user removed after the backup: restored, then followed through a
    // cooperative move, the app doesn't keep it again at the next service, which imported
    // the old one's lists (Dispatch spec 12.4, 12.5). The move compares the lists only for an
    // app that may read them.
    {
        let w = World::new();
        let router = Router::of(&w);
        let mut app = join_on(
            &w,
            &router,
            Arc::clone(&w.store) as Arc<dyn StateStore>,
            w.protocol.clone(),
            &[
                Permission::ListsRead,
                Permission::ListsManage,
                Permission::ReplyAdd,
            ],
        )
        .await;
        let carol = IdentityKey::from_secret(seed("carol/identity")).public();
        app.keep_peer(&carol).await.unwrap();
        let backup = app.backup().await.unwrap();
        app.remove_kept_peer(&carol).await.unwrap();
        let n_key = next_key();
        w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
        let next = w.dispatch.import_into(n_key.to_bytes());
        router.add(NEXT, &next);
        assert!(app.receive(None).await.unwrap().stopped);
        drop(app);
        let mut restored = App::restore(
            router.env(&w, Arc::new(MemoryStore::new())),
            w.protocol.clone(),
            World::config(),
            &backup,
        )
        .await
        .unwrap();
        publish_at(
            &w,
            &next,
            Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
            2,
            None,
        );
        restored.refresh_identity().await.unwrap();
        let _ = restored.receive(None).await;
        restored.receive(None).await.unwrap();
        let held = next.lock();
        assert!(!held.shared.kept.contains(&carol), "kept again");
    }
}

#[tokio::test]
async fn test_list_position_cleanup_runs_in_bounded_commits_across_a_restart() {
    // More kept positions than one commit removes, all behind the cursor: each commit that
    // advances the cursor removes at most the bound, the next one goes on, and a restart in
    // between loses nothing (Dispatch spec 8.3).
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    app.receive(None).await.unwrap();
    let cursor = app
        .reader()
        .get::<crate::app::state::Cursor>(crate::app::state::key::CURSOR)
        .await
        .unwrap()
        .unwrap();
    let mut tx = app.tx().unwrap();
    for n in 0u32..20_005 {
        let mut who = [5u8; 32];
        who[28..].copy_from_slice(&n.to_be_bytes());
        tx.put(
            &format!(
                "{}kept/{}",
                crate::app::list_settlement::EFFECT_CUTOFF,
                pubky_dispatch_core::enc::b64(&who)
            ),
            &crate::app::FeedPosition {
                generation: cursor.generation,
                seq: cursor.seq,
            },
        )
        .unwrap();
    }
    app.commit(tx).await.unwrap();
    // Written directly, as a restore installs them: a reopened app knows nothing of them yet.
    drop(app);
    let reopen = || {
        App::load(
            router.env(&w, w.store.clone()),
            w.protocol.clone(),
            World::config(),
            app_keys("wallet").app_id_bytes(),
        )
    };
    let mut app = reopen().await.unwrap();
    let left = |app: &App| {
        let reader = app.reader();
        async move {
            reader
                .scan_raw(crate::app::list_settlement::EFFECT_CUTOFF)
                .await
                .unwrap()
                .len()
        }
    };
    assert_eq!(left(&app).await, 20_005);
    let advance = |app: &mut App| {
        let mut tx = app.tx().unwrap();
        tx.advanced_list_cursor = true;
        tx
    };
    let tx = advance(&mut app);
    app.commit(tx).await.unwrap();
    assert_eq!(left(&app).await, 10_005);
    let tx = advance(&mut app);
    app.commit(tx).await.unwrap();
    assert_eq!(left(&app).await, 5);
    drop(app);
    let mut app = reopen().await.unwrap();
    let tx = advance(&mut app);
    app.commit(tx).await.unwrap();
    assert_eq!(left(&app).await, 0);
}

#[tokio::test]
async fn test_key_change_signs_a_kept_batch_again_only_on_stale_generation() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    // Never applied at generation 1.
    w.dispatch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    assert!(app.submit_batch(kept_peer_batch(carol)).await.is_err());
    let changed = change_key(&w, &router);
    // `409 stale_generation`: signed again for generation 2 under a new batch ID, and sent.
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchSignedAgain { .. }
        )),
        "{:?}",
        report.events
    );
    let applied = changed.applied();
    assert!(applied.iter().any(|op| op.body().generation == 2
        && matches!(op.body().kind, OpKind::AllowPut { pubky, .. } if pubky == carol)));
    assert_eq!(allow_ops_for(&applied, carol), 1);
    assert!(app.kept_batches().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_key_change_resend_past_the_window_drops_instead_of_signing_again() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    // Applied at generation 1, its answer lost.
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.submit_batch(kept_peer_batch(carol)).await.is_err());
    // On day 29 the key changes: the batch is kept to be sent again, but the first resend
    // can't connect.
    w.clock.advance_ms(29 * DAY_MS);
    let changed = change_key(&w, &router);
    changed.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    assert!(app.receive(None).await.is_err());
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    // On day 31 the service has forgotten the batch ID: `409 stale_generation` no longer
    // shows the batch was never applied (Dispatch spec 12.5 "Kept batches").
    w.clock.advance_ms(2 * DAY_MS);
    changed.lock().batches.clear();
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchDropped { .. }
        )),
        "{:?}",
        report.events
    );
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::KeptBatchSignedAgain { .. }
    )));
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(allow_ops_for(&changed.applied(), carol), 0);
    assert_eq!(allow_ops_for(&w.dispatch.applied(), carol), 1);
}

#[tokio::test]
async fn test_key_change_kept_peer_past_the_window_doesnt_undo_a_deletion() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let phone = w.other_app("phone", &[Permission::ListsManage]);
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    // A kept `allow.put`: applied at generation 1, its answer lost.
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.submit_batch(kept_peer_batch(carol)).await.is_err());
    // The provider changes on day 29, inside the window; the first resend can't connect.
    w.clock.advance_ms(29 * DAY_MS);
    let changed = change_key(&w, &router);
    changed.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    assert!(app.receive(None).await.is_err());
    // Another device deletes the kept peer.
    changed
        .app_op(
            &phone,
            OpKind::AllowDelete {
                pubky: carol,
                reason: PeerReason::Kept,
            },
        )
        .unwrap();
    // Later retries fall past the window, the batch ID forgotten: the batch is dropped,
    // and the deletion stands (Dispatch spec 12.5 "Kept batches").
    w.clock.advance_ms(2 * DAY_MS);
    changed.lock().batches.clear();
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchDropped { .. }
        )),
        "{:?}",
        report.events
    );
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(allow_ops_for(&changed.applied(), carol), 0);
    assert!(!app.admits(&carol).await.unwrap());
}

#[tokio::test]
async fn test_key_change_effect_resend_past_the_window_parks_its_entry() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let (seq, message) = w.note(me, "before");
    // The effect is applied at generation 1, and its answer lost.
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert_eq!(w.effects(), 1);
    w.clock.advance_ms(29 * DAY_MS);
    let changed = change_key(&w, &router);
    changed.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    assert!(app.receive(None).await.is_err());
    w.clock.advance_ms(2 * DAY_MS);
    changed.lock().batches.clear();
    // The entry is stored and passed, never applied again, and the protocol told.
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::Parked { id: Some(_), seq: s, reason: ParkReason::Uncertain, .. } if *s == seq
        )),
        "{:?}",
        report.events
    );
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::EffectUncertain { seq: s, .. } if *s == seq
    )));
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::EffectRefused { .. }
    )));
    assert!(!received(&report.events, seq), "{:?}", report.events);
    assert_eq!(reply_grants_at(&changed), 0);
    assert!(app.cursor().seq >= seq);
    // Not tried again.
    let report = app.receive(None).await.unwrap();
    assert!(!received(&report.events, seq));
    assert_eq!(reply_grants_at(&changed), 0);
    resend_is_a_duplicate(&w, &mut app, &changed, &message).await;
}

#[tokio::test]
async fn test_kept_effect_without_its_entry_is_corrupt_state() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    w.note(me, "before");
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    // A kept effect without the entry it keeps: no build writes one.
    app.ready_local().await.unwrap();
    let pending = app.state.pending_effect.clone().unwrap();
    let mut value = serde_json::to_value(&pending).unwrap();
    value.as_object_mut().unwrap().remove("entry");
    let mut tx = app.tx().unwrap();
    tx.put(crate::app::state::key::PENDING_EFFECT, &value)
        .unwrap();
    app.commit(tx).await.unwrap();
    drop(app);
    let loaded = App::load(
        router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        me,
    )
    .await;
    assert!(
        matches!(loaded, Err(AppError::Store(StoreError::Corrupt))),
        "{:?}",
        loaded.map(|_| ())
    );
}

#[tokio::test]
async fn test_key_change_drops_a_kept_batch_older_than_the_batch_window() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    w.dispatch.fail_next(Fault::Unanswered {
        path: "ops".into(),
        after: 0,
    });
    let attempt = crate::app::ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    assert!(
        app.submit_batch(kept_peer_batch(carol).op(attempt.kind()))
            .await
            .is_err()
    );
    w.clock
        .advance_ms(crate::app::provider::KEPT_BATCH_ANSWER_MS);
    let changed = change_key(&w, &router);
    let report = app.receive(None).await.unwrap();
    // The answer can't tell any more: dropped, and the protocol told of its attempt.
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchDropped { .. }
        )),
        "{:?}",
        report.events
    );
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::AttemptDropped { claim_key, attempt_id, .. }
                if *claim_key == CLAIM && *attempt_id == ATTEMPT
        )),
        "{:?}",
        report.events
    );
    assert_eq!(allow_ops_for(&changed.applied(), carol), 0);
    // Both are duty events: a load delivers them again until acknowledged.
    let mut loaded = App::load(
        router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        app.app_id(),
    )
    .await
    .unwrap();
    let events = loaded.take_events();
    let duties: Vec<AppEvent> = report
        .events
        .iter()
        .filter(|e| e.is_duty())
        .cloned()
        .collect();
    assert_eq!(duties.len(), 2, "{:?}", report.events);
    assert_eq!(events, duties);
}

#[tokio::test]
async fn test_move_settling_an_applied_effect_clears_its_retry_count() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let (seq, _) = w.note(me, "before");
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    // The entry's receive step had been retried for the store before.
    app.ready_local().await.unwrap();
    let retry = crate::app::state::RetryEntry {
        reads: 1,
        since_ms: w.clock.now_ms(),
    };
    let mut tx = app.tx().unwrap();
    tx.put(&crate::app::state::key::retry(seq), &retry).unwrap();
    app.commit(tx).await.unwrap();
    app.state.retries.insert(seq, retry);
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    // Settled at the Dispatch: processed, its count gone, in memory and in the store.
    assert!(app.no_retries());
    let loaded = App::load(
        router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    assert!(loaded.no_retries());
}

#[tokio::test]
async fn test_move_settles_an_effect_the_old_service_applied() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let (seq, message) = w.note(me, "before");
    // The effect is applied at the old service, and its answer lost.
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert_eq!(w.effects(), 1);
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::ProviderFollowed { generation: 2 }
        )),
        "{:?}",
        report.events
    );
    assert!(received(&report.events, seq));
    // Applied once, at the old service: the entry isn't processed again at the next one.
    assert_eq!(reply_grants_at(&next), 0);
    assert_eq!(w.effects(), 1);
    assert!(app.cursor().seq >= seq);
    assert_eq!(
        app.protocol_get("sample", format!("notes/{}", message.msg_id).as_bytes())
            .await
            .unwrap(),
        Some(b"before".to_vec())
    );
}

#[tokio::test]
async fn test_key_change_sends_a_kept_effect_again_and_settles_it_once() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let (seq, message) = w.note(me, "before");
    // The effect is applied at generation 1, and its answer lost.
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert_eq!(w.effects(), 1);
    let changed = change_key(&w, &router);
    // Sent again unchanged at generation 2, its answer shows it applied: its outcome
    // commits, and the entry isn't processed again (Dispatch spec 12.5 "Kept batches").
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(reply_grants_at(&changed), 0);
    assert_eq!(w.effects(), 1);
    assert!(app.cursor().seq >= seq);
    assert_eq!(
        app.protocol_get("sample", format!("notes/{}", message.msg_id).as_bytes())
            .await
            .unwrap(),
        Some(b"before".to_vec())
    );
}

#[tokio::test]
async fn test_key_change_keeps_an_owed_call_and_makes_it_at_the_new_generation() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    w.note(app.app_id(), "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    let seq = w.dispatch.push_missed(3, now - 3_600_000, now);
    // The protocol can't answer at generation 1: the call is kept.
    *w.protocol.failing.lock().unwrap() = 1;
    app.receive(None).await.unwrap();
    assert!(w.protocol.missed.lock().unwrap().is_empty());
    // After the key change the next read makes it, with the item's `seq` at generation 1.
    let _changed = change_key(&w, &router);
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    let missed = w.protocol.missed.lock().unwrap().clone();
    assert_eq!(missed.len(), 1, "{missed:?}");
    assert_eq!(missed[0].seq, seq);
    assert_eq!(missed[0].entries, 3);
    assert!(app.reader().scan_raw("owed/").await.unwrap().is_empty());
}

/// After an uncertain park of `message`'s entry: the same signed message again, as a
/// re-send at `dispatch`, is a duplicate, not applied (Dispatch spec 11).
async fn resend_is_a_duplicate(
    w: &World,
    app: &mut App,
    dispatch: &Arc<ScriptedDispatch>,
    message: &pubky_dispatch_core::message::Message,
) {
    let plaintext = message.sign(&w.bob_keys).unwrap();
    let again = dispatch
        .send_plaintext(w.bob.public(), &w.bob_cert, &plaintext, &[app.app_id()])
        .unwrap();
    let before = reply_grants_at(dispatch);
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::Duplicate { seq, conflicting: false } if *seq == again
        )),
        "{:?}",
        report.events
    );
    assert!(
        !has(&report.events, |e| matches!(
            e,
            AppEvent::MessageReceived { .. }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(reply_grants_at(dispatch), before);
    assert!(app.cursor().seq >= again);
}

#[tokio::test]
async fn test_key_change_parks_a_kept_effect_older_than_the_batch_window() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let (seq, message) = w.note(me, "before");
    // The effect is applied at generation 1, and its answer lost.
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert_eq!(w.effects(), 1);
    w.clock
        .advance_ms(crate::app::provider::KEPT_BATCH_ANSWER_MS);
    // The key changes past the window, and the service has forgotten the batch ID.
    let changed = change_key(&w, &router);
    changed.lock().batches.clear();
    // Sent again at the Dispatch, `409 stale_generation` can't tell any more whether it was
    // applied: the entry is stored and passed, its effect not built again, and the
    // protocol told (Dispatch spec 12.5 "Kept batches").
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::Parked { seq: s, reason: ParkReason::Uncertain, .. } if *s == seq
        )),
        "{:?}",
        report.events
    );
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::EffectUncertain { seq: s, msg_id, .. }
                if *s == seq && *msg_id == message.msg_id
        )),
        "{:?}",
        report.events
    );
    assert!(!received(&report.events, seq), "{:?}", report.events);
    assert_eq!(reply_grants_at(&changed), 0);
    assert_eq!(w.effects(), 1);
    assert!(app.cursor().seq >= seq);
    assert_eq!(
        app.stored_at(seq).map(|p| p.reason),
        Some(ParkReason::Uncertain)
    );
    assert_eq!(
        app.protocol_get("sample", format!("notes/{}", message.msg_id).as_bytes())
            .await
            .unwrap(),
        None
    );
    // Later reads don't try it again, nor apply a re-send.
    let report = app.receive(None).await.unwrap();
    assert!(!received(&report.events, seq), "{:?}", report.events);
    assert_eq!(reply_grants_at(&changed), 0);
    resend_is_a_duplicate(&w, &mut app, &changed, &message).await;
    // The protocol is told durably: a load delivers it again until it is acknowledged.
    let loaded = App::load(
        router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        me,
    )
    .await
    .unwrap()
    .take_events();
    assert!(
        has(&loaded, |e| matches!(
            e,
            AppEvent::EffectUncertain { id, seq: s, .. } if *s == seq && e.id() == Some(*id)
        )),
        "{loaded:?}"
    );
    assert!(loaded.iter().all(AppEvent::is_duty), "{loaded:?}");
}

#[tokio::test]
async fn test_kept_effect_resend_refused_before_the_lookup_stays_kept() {
    for code in [ErrorCode::CertExpired, ErrorCode::BadSignature] {
        let w = World::new();
        let router = Router::of(&w);
        let mut app = join(&w, &router).await;
        let me = app.app_id();
        let (seq, _) = w.note(me, "before");
        // Applied, its answer lost.
        w.dispatch
            .fail_next(Fault::LoseAnswer { path: "ops".into() });
        assert!(app.receive(None).await.is_err());
        assert_eq!(w.effects(), 1);
        // Sent again, refused before the service looks at its batch ID: that tells
        // nothing, so the effect stays kept (Dispatch wire 6.4 steps 1 to 5).
        w.dispatch.fail_next(Fault::Error {
            path: "ops".into(),
            code,
            current: json!(null),
        });
        let built = w.protocol.received.lock().unwrap().len();
        assert!(app.receive(None).await.is_err(), "{code:?}");
        assert!(app.state.pending_effect.is_some(), "{code:?}");
        assert_eq!(w.protocol.received.lock().unwrap().len(), built, "{code:?}");
        // The cause gone, the same bytes show it applied: once in all.
        let report = app.receive(None).await.unwrap();
        assert!(
            received(&report.events, seq),
            "{code:?}: {:?}",
            report.events
        );
        assert_eq!(w.effects(), 1, "{code:?}");
        assert!(app.state.pending_effect.is_none());
    }
}

/// A key change followed to its end, with an effect applied at generation 1, its answer
/// lost, still kept: its resend at generation 2 couldn't connect. `None` when the
/// unreachable send at `after` doesn't leave that state.
async fn key_change_with_a_kept_effect(
    after: usize,
) -> Option<(World, App, Arc<ScriptedDispatch>, u64)> {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let (seq, _) = w.note(me, "before");
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    let changed = change_key(&w, &router);
    changed.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after,
    });
    let failed = app.receive(None).await.is_err();
    changed.lock().faults.clear();
    let done = failed
        && app.cursor().generation == 2
        && !app.reader().exists("mv").await.unwrap()
        && app.state.pending_effect.is_some();
    done.then_some((w, app, changed, seq))
}

#[tokio::test]
async fn test_key_change_kept_effect_resend_refused_before_the_lookup_stays_kept() {
    for code in [ErrorCode::CertExpired, ErrorCode::BadSignature] {
        let mut found = false;
        for after in 0..6 {
            let Some((w, mut app, changed, seq)) = key_change_with_a_kept_effect(after).await
            else {
                continue;
            };
            found = true;
            let kept = app.state.pending_effect.as_ref().unwrap().body.clone();
            let built = w.protocol.received.lock().unwrap().len();
            // Its resend is refused before the batch ID lookup: kept, the same bytes, and
            // the effect not built again (Dispatch wire 6.4 steps 1 to 5).
            changed.fail_next(Fault::Error {
                path: "ops".into(),
                code,
                current: json!(null),
            });
            assert!(app.receive(None).await.is_err(), "{code:?}");
            assert_eq!(
                app.state.pending_effect.as_ref().map(|p| p.body.clone()),
                Some(kept),
                "{code:?}"
            );
            assert_eq!(w.protocol.received.lock().unwrap().len(), built, "{code:?}");
            // Then its answer shows it applied: never built again.
            let report = app.receive(None).await.unwrap();
            assert!(
                received(&report.events, seq),
                "{code:?}: {:?}",
                report.events
            );
            assert_eq!(w.protocol.received.lock().unwrap().len(), built, "{code:?}");
            assert_eq!(reply_grants_at(&changed), 0, "{code:?}");
            break;
        }
        assert!(found, "a resend at generation 2 is reached");
    }
}

#[tokio::test]
async fn test_kept_effect_past_the_window_isnt_sent_again_at_the_same_generation() {
    for forgotten in [false, true] {
        let w = World::new();
        let router = Router::of(&w);
        let mut app = join(&w, &router).await;
        let me = app.app_id();
        let (seq, message) = w.note(me, "before");
        // Applied, its answer lost.
        w.dispatch
            .fail_next(Fault::LoseAnswer { path: "ops".into() });
        assert!(app.receive(None).await.is_err());
        assert_eq!(w.effects(), 1);
        let built = w.protocol.received.lock().unwrap().len();
        // 31 days on, the service dropped the batch's proofs, or forgot its ID: a resend
        // would get `409 conflict`, read as a failed condition, or be applied again.
        w.clock.advance_ms(31 * DAY_MS);
        if forgotten {
            w.dispatch.lock().batches.clear();
        } else {
            w.dispatch.fail_next(Fault::Error {
                path: "ops".into(),
                code: ErrorCode::Conflict,
                current: json!(null),
            });
        }
        let report = app.receive(None).await.unwrap();
        // Not sent again: its entry is stored as uncertain, and the effect not built again.
        assert!(
            has(&report.events, |e| matches!(
                e,
                AppEvent::EffectUncertain { seq: s, .. } if *s == seq
            )),
            "{forgotten}: {:?}",
            report.events
        );
        assert_eq!(w.effects(), 1, "{forgotten}");
        assert_eq!(
            w.protocol.received.lock().unwrap().len(),
            built,
            "{forgotten}"
        );
        assert_eq!(
            app.stored_at(seq).map(|p| p.reason),
            Some(ParkReason::Uncertain)
        );
        w.dispatch.lock().faults.clear();
        resend_is_a_duplicate(&w, &mut app, &w.dispatch.clone(), &message).await;
    }
}

#[tokio::test]
async fn test_kept_effect_window_is_measured_against_the_verified_service_time() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let (seq, _) = w.note(me, "before");
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    // The device clock reads as when the effect was kept, but the app has verified a
    // service time past the window: the window is closed.
    app.ready_local().await.unwrap();
    let kept = Some(app.state.pending_effect.as_ref().unwrap().kept_ms);
    assert_eq!(app.state.pending_effect.as_ref().map(|p| p.seq), Some(seq));
    assert!(app.answer_decides(kept));
    let past = w.clock.now_ms() + crate::app::provider::KEPT_BATCH_ANSWER_MS;
    let time = app.state.service_time.as_mut().unwrap();
    time.highest_ms = past;
    assert_eq!(app.kept_window_now(), past);
    assert!(!app.answer_decides(kept));
}

#[tokio::test]
async fn test_kept_batch_past_the_window_isnt_sent_again_at_the_same_generation() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.submit_batch(kept_peer_batch(carol)).await.is_err());
    w.clock.advance_ms(31 * DAY_MS);
    w.dispatch.lock().batches.clear();
    // The next write: the kept batch isn't sent again, but dropped and reported.
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    app.submit_batch(kept_peer_batch(dave)).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert!(has(&app.take_events(), |e| matches!(
        e,
        AppEvent::KeptBatchDropped { .. }
    )));
    assert_eq!(allow_ops_for(&w.dispatch.applied(), carol), 1);
}

#[tokio::test]
async fn test_kept_batch_resend_refused_before_the_lookup_stays_kept() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.submit_batch(kept_peer_batch(carol)).await.is_err());
    // The next write sends it again first; refused before the batch ID lookup, it stays.
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    w.dispatch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::CertExpired,
        current: json!(null),
    });
    assert!(app.submit_batch(kept_peer_batch(dave)).await.is_err());
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    assert!(!has(&app.take_events(), |e| matches!(
        e,
        AppEvent::BatchRefused { .. }
    )));
    // Then its answer shows it applied: once in all.
    app.submit_batch(kept_peer_batch(dave)).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(allow_ops_for(&w.dispatch.applied(), carol), 1);
}

/// The sample protocol, whose effect for a note also writes an own `attempt`.
struct AttemptingProtocol(SampleProtocol);

impl Protocol for AttemptingProtocol {
    fn name(&self) -> String {
        "sample".into()
    }

    fn has_keys(&self, scope: &str) -> bool {
        self.0.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.0.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.0.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.0.accepts(cert)
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.0.check_body(message)
    }

    fn receive(
        &self,
        message: &ReceivedMessage,
        cx: &mut crate::app::ReceiveContext<'_>,
    ) -> Outcome {
        match self.0.receive(message, cx) {
            Outcome::Apply(mut effect) => {
                effect.ops.push((
                    Vec::new(),
                    ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None).kind(),
                ));
                Outcome::Apply(effect)
            }
            other => other,
        }
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.0.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.0.missed(missed)
    }
}

#[tokio::test]
async fn test_kept_effect_parked_uncertain_reports_its_attempts() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        Arc::new(AttemptingProtocol(SampleProtocol::default())),
        &Permission::ALL,
    )
    .await;
    let me = app.app_id();
    let (seq, _) = w.note(me, "before");
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    w.clock
        .advance_ms(crate::app::provider::KEPT_BATCH_ANSWER_MS);
    let changed = change_key(&w, &router);
    changed.lock().batches.clear();
    let report = app.receive(None).await.unwrap();
    let attempt = crate::app::ClaimAttempt {
        claim_key: CLAIM,
        attempt_id: ATTEMPT,
    };
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::EffectUncertain { seq: s, attempts, .. }
                if *s == seq && *attempts == vec![attempt]
        )),
        "{:?}",
        report.events
    );
    // Kept with them.
    assert!(has(
        &app.unacknowledged_events().await.unwrap(),
        |e| matches!(
            e,
            AppEvent::EffectUncertain { attempts, .. } if *attempts == vec![attempt]
        )
    ));
}

#[tokio::test]
async fn test_loss_reports_the_attempts_of_a_kept_effect_it_drops() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // A kept effect from before the loss, carrying an `attempt`.
    let mut app = load_lost(&lost, Arc::clone(&store) as Arc<dyn StateStore>).await;
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    let batch = app
        .sign_ops(vec![(Vec::new(), attempt.kind())], None)
        .unwrap();
    let pending = crate::app::state::PendingEffect {
        body: batch.body().to_vec(),
        seq: 99,
        sender: lost.w.bob.public(),
        msg_id: "kept".into(),
        hash: [1; 32],
        accepted_at_ms: lost.note_at_ms,
        kind: "sample.note".into(),
        local: Vec::new(),
        cursor_to: None,
        past_held: false,
        generation: 1,
        stored: None,
        deadlines: Vec::new(),
        kept_ms: lost.note_at_ms,
        forget: Vec::new(),
        entry: crate::app::state::KeptEntry {
            receipt: crate::app::EntryReceipt {
                entry_id: [1; 16],
                invite_code_hash: None,
                service_key: [2; 32],
                read_at_ms: lost.w.clock.now_ms(),
            },
            cert: app.cert().signed().clone(),
            plaintext: Vec::new(),
        },
    };
    let mut tx = app.tx().unwrap();
    tx.put(crate::app::state::key::PENDING_EFFECT, &pending)
        .unwrap();
    app.commit(tx).await.unwrap();
    drop(app);
    let (mut app, events) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let dropped = |e: &AppEvent| {
        matches!(
            e,
            AppEvent::AttemptDropped { claim_key, attempt_id, .. }
                if *claim_key == CLAIM && *attempt_id == ATTEMPT
        )
    };
    assert!(has(&events, dropped), "{events:?}");
    assert!(app.state.pending_effect.is_none());
    assert!(has(&app.unacknowledged_events().await.unwrap(), dropped));
}

/// A kept effect at generation 1 for an entry at `seq`, written into `app`'s store as if a
/// read had kept it, with `parked` and `past_held` set as given.
async fn keep_an_effect(
    w: &World,
    app: &mut App,
    seq: u64,
    parked: bool,
    past_held: bool,
) -> crate::app::state::PendingEffect {
    let batch = app
        .sign_ops(
            vec![(
                Vec::new(),
                OpKind::AllowPut {
                    pubky: w.bob.public(),
                    reason: PeerReason::Reply,
                },
            )],
            None,
        )
        .unwrap();
    let entry = crate::app::state::KeptEntry {
        receipt: crate::app::EntryReceipt {
            entry_id: [1; 16],
            invite_code_hash: None,
            service_key: [2; 32],
            read_at_ms: w.clock.now_ms(),
        },
        cert: w.bob_cert.signed().clone(),
        plaintext: b"kept".to_vec(),
    };
    let pending = crate::app::state::PendingEffect {
        body: batch.body().to_vec(),
        seq,
        sender: w.bob.public(),
        msg_id: format!("kept-{seq}"),
        hash: [2; 32],
        accepted_at_ms: w.clock.now_ms(),
        kind: "sample.note".into(),
        local: Vec::new(),
        cursor_to: None,
        past_held,
        generation: 1,
        stored: parked.then_some(seq),
        deadlines: Vec::new(),
        kept_ms: w.clock.now_ms(),
        forget: Vec::new(),
        entry: entry.clone(),
    };
    let mut tx = app.tx().unwrap();
    tx.put(crate::app::state::key::PENDING_EFFECT, &pending)
        .unwrap();
    if parked {
        let stored = crate::app::state::ParkedEntry {
            receipt: entry.receipt,
            seq,
            generation: 1,
            sender: w.bob.public(),
            cert: entry.cert,
            accepted_at_ms: pending.accepted_at_ms,
            plaintext: entry.plaintext,
            reason: ParkReason::Quota,
            round: 0,
            released: false,
            keys_at: None,
        };
        tx.put(&crate::app::state::key::parked(seq), &stored)
            .unwrap();
        app.state.parked.insert(seq, stored);
    }
    app.commit(tx).await.unwrap();
    app.state.pending_effect = Some(pending.clone());
    pending
}

#[tokio::test]
async fn test_uncertain_park_of_an_entry_stored_before_changes_its_reason() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let cursor = app.cursor().seq;
    let seq = cursor + 40;
    let pending = keep_an_effect(&w, &mut app, seq, true, false).await;
    w.clock
        .advance_ms(crate::app::provider::KEPT_BATCH_ANSWER_MS);
    change_key(&w, &router);
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::EffectUncertain { seq: s, .. } if *s == seq
        )),
        "{:?}",
        report.events
    );
    // The entry stored before keeps its plaintext; only its reason changes, and it is
    // processed.
    let stored = app.stored_at(seq).unwrap();
    assert_eq!(stored.reason, ParkReason::Uncertain);
    assert_eq!(stored.plaintext, pending.entry.plaintext);
    assert!(
        app.reader()
            .exists(&crate::app::state::key::processed(
                &pending.sender,
                &pending.msg_id
            ))
            .await
            .unwrap()
    );
    assert!(app.state.pending_effect.is_none());
}

#[tokio::test]
async fn test_uncertain_park_of_an_entry_past_a_held_one_keeps_the_cursor() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let seq = app.cursor().seq + 40;
    keep_an_effect(&w, &mut app, seq, false, true).await;
    w.clock
        .advance_ms(crate::app::provider::KEPT_BATCH_ANSWER_MS);
    change_key(&w, &router);
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::EffectUncertain { seq: s, .. } if *s == seq
        )),
        "{:?}",
        report.events
    );
    // Past a held entry, it is marked seen; the cursor doesn't pass the held one for it.
    assert_eq!(
        app.stored_at(seq).map(|p| p.reason),
        Some(ParkReason::Uncertain)
    );
    assert!(app.state.seen.contains(&seq));
    assert!(app.cursor().seq < seq);
}

#[tokio::test]
async fn test_kept_effect_refused_for_its_bytes_is_parked_at_once() {
    for code in [ErrorCode::BadRequest, ErrorCode::TooLarge] {
        let w = World::new();
        let router = Router::of(&w);
        let mut app = join(&w, &router).await;
        let me = app.app_id();
        let (seq, message) = w.note(me, "before");
        w.dispatch
            .fail_next(Fault::LoseAnswer { path: "ops".into() });
        assert!(app.receive(None).await.is_err());
        let (later, _) = w.note(me, "later");
        // Sent again, refused for its own shape: the same bytes would be again, so the
        // entry is stored as uncertain at once, and the read goes on to the feed.
        w.dispatch.fail_next(Fault::Error {
            path: "ops".into(),
            code,
            current: json!(null),
        });
        let report = app.receive(None).await.unwrap();
        assert!(
            has(&report.events, |e| matches!(
                e,
                AppEvent::EffectUncertain { seq: s, .. } if *s == seq
            )),
            "{code:?}: {:?}",
            report.events
        );
        assert!(
            received(&report.events, later),
            "{code:?}: {:?}",
            report.events
        );
        assert_eq!(
            app.stored_at(seq).map(|p| p.reason),
            Some(ParkReason::Uncertain)
        );
        assert!(app.state.pending_effect.is_none());
        // Never applied twice, and a re-send is a duplicate: one effect for each note.
        assert_eq!(w.effects(), 2, "{code:?}");
        resend_is_a_duplicate(&w, &mut app, &w.dispatch.clone(), &message).await;
    }
}

#[tokio::test]
async fn test_kept_batch_refused_for_its_bytes_is_dropped_at_once() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    w.dispatch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.submit_batch(kept_peer_batch(carol)).await.is_err());
    // The next write sends it again first; refused for its shape, it is dropped and
    // reported at once, and the write goes on.
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    w.dispatch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::BadRequest,
        current: json!(null),
    });
    app.submit_batch(kept_peer_batch(dave)).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    let events = app.take_events();
    assert!(
        has(&events, |e| matches!(e, AppEvent::KeptBatchDropped { .. })),
        "{events:?}"
    );
    assert!(has(
        &app.unacknowledged_events().await.unwrap(),
        |e| matches!(e, AppEvent::KeptBatchDropped { .. })
    ));
    assert_eq!(allow_ops_for(&w.dispatch.applied(), dave), 1);
    assert_eq!(allow_ops_for(&w.dispatch.applied(), carol), 1);
}

#[tokio::test]
async fn test_kept_batch_signed_again_then_refused_for_good_is_reported() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    // The claim is at step 1 already.
    app.write_claim(
        ClaimOp::attempt(CLAIM, 0, [9; 16], 3600, None),
        vec![],
        ObligationDeadline::NoDeadline,
    )
    .await
    .unwrap();
    // A batch with an attempt built on step 0, never sent.
    w.dispatch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    assert!(
        app.submit_batch(kept_peer_batch(carol).op(attempt.kind()))
            .await
            .is_err()
    );
    app.take_events();
    let changed = change_key(&w, &router);
    // `409 stale_generation`: signed again and sent, then refused for good with `409
    // conflict`; dropped with what it carried, and the protocol told in that commit.
    let mut events = Vec::new();
    for _ in 0..3 {
        match app.receive(None).await {
            Ok(report) => events.extend(report.events),
            Err(_) => events.extend(app.take_events()),
        }
    }
    assert!(
        has(&events, |e| matches!(
            e,
            AppEvent::KeptBatchSignedAgain { .. }
        )),
        "{events:?}"
    );
    let refused = |e: &AppEvent| {
        matches!(e, AppEvent::BatchRefused { code, .. } if code == "conflict") && e.is_duty()
    };
    assert!(has(&events, refused), "{events:?}");
    assert!(has(&app.unacknowledged_events().await.unwrap(), refused));
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(allow_ops_for(&changed.applied(), carol), 0);
}

/// The kept batch of `app`, with its attempt, never sent.
async fn kept_attempt_batch(
    w: &World,
    app: &mut App,
) -> (
    [u8; 16],
    crate::app::batch::PendingBatch,
    crate::client::Batch,
) {
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    w.dispatch.fail_next(Fault::Unanswered {
        path: "ops".into(),
        after: 0,
    });
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    assert!(
        app.submit_batch(kept_peer_batch(carol).op(attempt.kind()))
            .await
            .is_err()
    );
    let (id, pending) = app.kept_batches().await.unwrap().pop().unwrap();
    let batch = crate::client::Batch::from_body(pending.body.clone()).unwrap();
    (id, pending, batch)
}

fn refused(code: ErrorCode) -> AppError {
    AppError::Dispatch(ClientError::Dispatch {
        status: 403,
        code,
        message: "scripted".into(),
        current: json!(null),
        known_version: None,
        retry_after: None,
    })
}

/// Dropped and reported, with its attempt, in one commit.
async fn dropped_with_its_attempt(app: &mut App) {
    assert!(app.kept_batches().await.unwrap().is_empty());
    let kept = app.unacknowledged_events().await.unwrap();
    assert!(
        has(&kept, |e| matches!(e, AppEvent::KeptBatchDropped { .. })),
        "{kept:?}"
    );
    assert!(
        has(&kept, |e| matches!(
            e,
            AppEvent::AttemptDropped { claim_key, attempt_id, .. }
                if *claim_key == CLAIM && *attempt_id == ATTEMPT
        )),
        "{kept:?}"
    );
}

#[tokio::test]
async fn test_kept_batch_refused_about_the_caller_past_the_window_is_dropped() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    let (id, pending, batch) = kept_attempt_batch(&w, &mut app).await;
    // Within the window a refusal about the caller keeps it.
    let kept = app
        .kept_refused_before_lookup(&id, &pending, &batch, refused(ErrorCode::CertExpired))
        .await;
    assert!(kept.is_err());
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    // Past it, the same refusal drops it.
    w.clock
        .advance_ms(crate::app::provider::KEPT_BATCH_ANSWER_MS);
    app.kept_refused_before_lookup(&id, &pending, &batch, refused(ErrorCode::CertExpired))
        .await
        .unwrap();
    dropped_with_its_attempt(&mut app).await;
}

#[tokio::test]
async fn test_kept_batch_of_an_earlier_generation_past_the_window_is_dropped_at_its_resend() {
    for code in [Some(ErrorCode::CertExpired), None] {
        let w = World::new();
        let router = Router::of(&w);
        let mut app = join_on(
            &w,
            &router,
            Arc::clone(&w.store) as Arc<dyn StateStore>,
            w.protocol.clone(),
            &Permission::ALL,
        )
        .await;
        let (id, pending, batch) = kept_attempt_batch(&w, &mut app).await;
        let changed = change_key(&w, &router);
        // Followed to generation 2 with the batch still kept for generation 1.
        let mut followed = false;
        for after in 0..6 {
            changed.fail_next(Fault::Unreachable {
                path: "ops".into(),
                after,
            });
            let _ = app.receive(None).await;
            changed.lock().faults.clear();
            if app.cursor().generation == 2 && app.kept_batches().await.unwrap().len() == 1 {
                followed = true;
                break;
            }
        }
        assert!(followed);
        // Past the window, its resend is refused about the caller, or answered `409
        // stale_generation`: either way it is dropped, not kept or signed again.
        w.clock
            .advance_ms(crate::app::provider::KEPT_BATCH_ANSWER_MS);
        if let Some(code) = code {
            changed.fail_next(Fault::Error {
                path: "ops".into(),
                code,
                current: json!(null),
            });
        }
        app.ready_local().await.unwrap();
        app.resend_earlier(&id, &pending, &batch).await.unwrap();
        dropped_with_its_attempt(&mut app).await;
        assert!(!has(&app.take_events(), |e| matches!(
            e,
            AppEvent::KeptBatchSignedAgain { .. }
        )));
    }
}

#[tokio::test]
async fn test_key_change_signs_a_batch_never_sent_again_without_resending_it() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    // Written while the service can't be reached: kept, never sent.
    w.dispatch.fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 0,
    });
    w.dispatch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    assert!(app.submit_batch(kept_peer_batch(carol)).await.is_err());
    w.dispatch.lock().faults.clear();
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].1.kept_ms, None);
    let old_id = kept[0].0;
    // The key changes before its first send: it is signed again for the new generation,
    // its old bytes never sent, then sent once.
    let changed = change_key(&w, &router);
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchSignedAgain { batch_id, .. } if *batch_id == old_id
        )),
        "{:?}",
        report.events
    );
    assert_eq!(allow_ops_for(&w.dispatch.applied(), carol), 0);
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    app.submit_batch(kept_peer_batch(dave)).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(allow_ops_for(&changed.applied(), carol), 1);
    assert!(
        changed
            .applied()
            .iter()
            .all(|op| op.body().batch.id != old_id)
    );
}

/// The app at `store`, loaded through the loss's router.
async fn load_lost(lost: &Lost, store: Arc<dyn StateStore>) -> App {
    App::load(
        lost.router.env(&lost.w, store),
        Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap()
}

/// A receive key record of the wallet's signing key for `key`.
fn wallet_key_record(
    app: &App,
    key: &pubky_dispatch_core::keys::ReceiveKey,
) -> pubky_dispatch_core::records::ReceiveKeyRecord {
    pubky_dispatch_core::records::ReceiveKeyRecord::sign(
        &app_keys("wallet"),
        app.cert(),
        pubky_dispatch_core::records::ReceiveKeyBody::new(app.cert(), key),
    )
    .unwrap()
}

/// A copy of the wallet's signing key registers `record` first at the new service, after
/// delivering the wallet's app record there, as an own app's first call must.
fn register_first(lost: &Lost, app: &App, record: &pubky_dispatch_core::records::ReceiveKeyRecord) {
    let keys = app_keys("wallet");
    let app_record = app.record().clone();
    lost.next
        .app_op(&keys, OpKind::AppPut { record: app_record })
        .unwrap();
    lost.next
        .app_op(
            &keys,
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
}

#[tokio::test]
async fn test_loss_registration_taken_by_another_device_is_adopted() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // The first follow can't reach the new service: the loss starts, its batch kept.
    lost.router.remove(NEXT);
    assert!(
        follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
            .await
            .is_err()
    );
    // Another device of the app registers its key first, and shares its kid.
    let mut app = load_lost(&lost, Arc::clone(&store) as Arc<dyn StateStore>).await;
    let other = pubky_dispatch_core::keys::ReceiveKey::generate(1).unwrap();
    register_first(&lost, &app, &wallet_key_record(&app, &other));
    app.take_device_keys(crate::app::DeviceKeys {
        receive_keys: Vec::new(),
        known: vec![(pubky_dispatch_core::enc::b64(&other.kid), 1)],
        rotation_ms: 0,
    })
    .await
    .unwrap();
    drop(app);
    lost.router.add(NEXT, &lost.next);
    let (app, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(
        has(&events, |e| matches!(e, AppEvent::RotationLost { n: 1 })),
        "{events:?}"
    );
    // This device's own key went; its record went alone.
    assert_eq!(app.receive_key_numbers(), vec![0]);
    assert!(lost.next.app(&app.app_id()).record.is_some());
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
    assert!(app.alarm().is_none());
}

#[tokio::test]
async fn test_loss_registration_taken_by_a_foreign_key_is_a_compromise() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // A copy of the signing key registers a key of its own first at the new service.
    let app = load_lost(&lost, Arc::clone(&store) as Arc<dyn StateStore>).await;
    let me = app.app_id();
    let thief = pubky_dispatch_core::keys::ReceiveKey::generate(1).unwrap();
    register_first(&lost, &app, &wallet_key_record(&app, &thief));
    drop(app);
    let error = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Alarm(crate::app::Alarm::Compromise { n: 1, .. })
        ),
        "{error:?}"
    );
    // It left at once, at the new service.
    assert!(lost.next.app(&me).departed);
}

#[tokio::test]
async fn test_not_current_while_listed_with_its_own_certificate_is_final() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    // The newest identity.json lists the app with the certificate it presents: the answer
    // is final (Dispatch wire 7.2).
    w.dispatch.fail_next(Fault::Error {
        path: "feed".into(),
        code: ErrorCode::NotCurrent,
        current: json!({}),
    });
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Removed)));
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

#[tokio::test]
async fn test_not_current_from_a_service_the_identity_left_follows_the_move() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // The identity publishes generation 2 at another service, still listing the app with
    // the certificate it holds.
    let n_key = next_key();
    let next = w.dispatch.import_into_at(n_key.to_bytes(), NEXT);
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    // The old service answers `403 not_current`, which says nothing once the identity left
    // it (Dispatch wire 7.2).
    w.dispatch.fail_next(Fault::Error {
        path: "feed".into(),
        code: ErrorCode::NotCurrent,
        current: json!({}),
    });
    let seq = note_at(&w, &next, me, "at the next service");
    let report = app.receive(None).await.unwrap();
    assert!(
        !has(&report.events, |e| matches!(e, AppEvent::Removed)),
        "{:?}",
        report.events
    );
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(app.cursor().generation, 2);
    assert_ne!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

#[tokio::test]
async fn test_not_current_without_the_homeserver_isnt_final() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // Without a read of the newest identity.json, the answer stands for now.
    w.homeserver.set_down(true);
    w.dispatch.fail_next(Fault::Error {
        path: "feed".into(),
        code: ErrorCode::NotCurrent,
        current: json!({}),
    });
    let error = app.receive(None).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotCurrent));
    w.homeserver.set_down(false);
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
    let seq = w.note(me, "after").0;
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
}

#[tokio::test]
async fn test_gone_app_refuses_every_read() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    assert!(app.receive(None).await.unwrap().stopped);
    let gone = |error: AppError| matches!(error, AppError::Refused(crate::app::Refusal::Gone));
    let target = crate::app::RecordTarget::new(super::shared_flows::items(), b"key");
    for _ in 0..2 {
        assert!(gone(
            app.register_push(&NoRelay, "https://push.example/v1/hook", "token")
                .await
                .unwrap_err()
        ));
        assert!(gone(app.read_claim(&[1; 32]).await.unwrap_err()));
        assert!(gone(app.read_record(&target).await.unwrap_err()));
        assert!(gone(app.peek().await.unwrap_err()));
        // The read itself reports the app stopped, asking the service nothing.
        assert!(app.receive(None).await.unwrap().stopped);
        app = w_load(&w, &router).await;
    }
}

#[tokio::test]
async fn test_registration_sent_again_never_takes_the_service_cursor_back() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let phone = w.other_app("phone", &[Permission::ListsManage]);
    w.note(me, "one");
    app.receive(None).await.unwrap();
    // A chain item the cursor passes with its move deferred, then the rotation, whose
    // registration doesn't reach the service.
    w.dispatch
        .app_op(&phone, OpKind::DenyPut { pubky: [9; 32] })
        .unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    w.dispatch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    assert!(app.receive(None).await.is_err());
    // A later effect moves the service's cursor further, then the registration goes again.
    let seq = w.note(me, "two").0;
    app.receive(None).await.unwrap();
    assert_eq!(w.dispatch.app(&me).receive_n, Some(1));
    assert!(
        w.dispatch.app(&me).cursor >= seq,
        "{}",
        w.dispatch.app(&me).cursor
    );
}

#[tokio::test]
async fn test_device_sync_doesnt_bring_back_a_deleted_key() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let shared = app.device_keys();
    w.note(me, "one");
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    // Key 0 went once the cursor passed key 1's registration.
    assert_eq!(app.receive_key_numbers(), vec![1]);
    // Another device still shares key 0: it doesn't come back.
    app.take_device_keys(shared).await.unwrap();
    assert_eq!(app.receive_key_numbers(), vec![1]);
}

#[tokio::test]
async fn test_move_lists_batch_is_kept_and_sent_again_unchanged() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[
            Permission::ListsRead,
            Permission::ListsManage,
            Permission::ReplyAdd,
        ],
    )
    .await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let phone = w.other_app("phone", &[Permission::ListsManage]);
    w.dispatch
        .app_op(
            &phone,
            OpKind::AllowPut {
                pubky: carol,
                reason: PeerReason::Kept,
            },
        )
        .unwrap();
    app.receive(None).await.unwrap();
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    // The export lacks carol.
    next.lock().allow = Some(json!({
        "peers": [], "deny": [], "flagged": [], "invite_codes": [],
    }));
    app.receive(None).await.unwrap();
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    // The re-registration goes through; the batch adding carol back doesn't.
    next.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    assert!(app.receive(None).await.is_err());
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    // The batch went again, the bytes signed before it was first sent, and once.
    let unreached = next.lock().unreached.clone();
    let request = pubky_dispatch_core::ops::OpsRequest::parse(&unreached[0]).unwrap();
    let sent_id = request
        .signed()
        .map(|signed| pubky_dispatch_core::ops::SignedOp::peek(signed).unwrap())
        .next()
        .unwrap()
        .body()
        .batch
        .id;
    let applied = next.applied();
    assert_eq!(allow_ops_for(&applied, carol), 1);
    assert!(applied.iter().any(|op| op.body().batch.id == sent_id
        && matches!(op.body().kind, OpKind::AllowPut { pubky, .. } if pubky == carol)));
}

#[tokio::test]
async fn test_unsigned_404_with_a_newer_own_document_is_followed_not_erased() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    // The app holds the verified document naming the next service; then the old service
    // drops the account and the Homeserver serves no identity.json.
    assert!(matches!(
        app.refresh_identity().await.unwrap(),
        crate::app::IdentityRefresh::Newer { .. }
    ));
    w.dispatch.lock().not_hosted_unpinned = true;
    w.homeserver.remove(w.alice.public(), IDENTITY_PATH);
    let over = app
        .take_over(Err(AppError::Dispatch(ClientError::BadServiceSignature {
            status: 404,
        })))
        .await;
    assert!(matches!(over, crate::app::provider::TakeOver::ReadAgain));
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Followed { generation: 2 }
    );
}

#[tokio::test]
async fn test_chain_hashes_behind_the_cursor_stay_bounded() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let ns = crate::store::client_namespace(&me);
    let rows = |w: &World| {
        w.store
            .scan(&ns, b"chain/at/", None, u32::MAX)
            .unwrap()
            .len()
    };
    let phone = w.other_app("phone", &[Permission::ListsManage]);
    for round in 0..3u8 {
        for i in 0..100u8 {
            w.dispatch
                .app_op(
                    &phone,
                    OpKind::DenyPut {
                        pubky: [round.wrapping_mul(100).wrapping_add(i); 32],
                    },
                )
                .unwrap();
        }
        app.receive(None).await.unwrap();
        assert!(
            rows(&w) <= crate::app::chain::HASHES_BEHIND + 2,
            "{} rows",
            rows(&w)
        );
    }
    // The view still checks what it reads, and reloads.
    let seq = w.note(me, "after").0;
    let mut app = w_load(&w, &router).await;
    assert!(received(&app.receive(None).await.unwrap().events, seq));
    assert!(app.alarm().is_none());
}

// -------------------------------------------------------------------------------------
// The signer's view of kept proofs (Dispatch wire 3.3 "Service keys", 7.4.12)

/// A signer's call bound to the account held at `dispatch`.
fn signer_call(
    w: &World,
    dispatch: &ScriptedDispatch,
    method: &str,
    route: &str,
    body: Vec<u8>,
) -> (u16, serde_json::Value) {
    use crate::transport::Header;
    use pubky_dispatch_core::http::{self, RequestHeaders, RequestTarget, header};

    let origin = dispatch.lock().origin.clone();
    let path = format!("/v1/{}/{route}", w.alice.id());
    let created = pubky_dispatch_core::time::rfc3339(dispatch.created());
    let fields = RequestHeaders {
        identity: w.alice.id(),
        timestamp: pubky_dispatch_core::time::rfc3339_seconds(w.clock.now_ms()),
        created: Some(created.clone()),
        ..RequestHeaders::default()
    };
    let signature = http::sign_request(
        &w.alice,
        &RequestTarget {
            method,
            path_and_query: &path,
            body: &body,
            origin: &origin,
        },
        &fields,
    );
    let response = dispatch
        .handle(&crate::transport::Request {
            method: method.into(),
            origin,
            path_and_query: path,
            headers: vec![
                Header::new(header::IDENTITY, &fields.identity),
                Header::new(header::TIMESTAMP, &fields.timestamp),
                Header::new(header::CREATED, &created),
                Header::new(
                    header::SIGNATURE,
                    &pubky_dispatch_core::enc::b64(&signature),
                ),
            ],
            body,
            timeout: crate::transport::TimeoutClass::Bulk,
        })
        .unwrap();
    (
        response.status,
        serde_json::from_slice(&response.body).unwrap(),
    )
}

/// The signer delivers `doc`, built on `prev`, to `dispatch` (Dispatch wire 7.4.2).
fn deliver(
    w: &World,
    dispatch: &ScriptedDispatch,
    doc: &IdentityDoc,
    prev: &IdentityDoc,
) -> (u16, serde_json::Value) {
    let delivery = pubky_dispatch_core::http::IdentityDelivery {
        identity: doc.signed().clone(),
        prev: Some(prev.hash()),
    };
    signer_call(w, dispatch, "PUT", "identity", delivery.to_json())
}

#[tokio::test]
async fn test_move_kept_proofs_keep_their_generation_key() {
    let w = World::new();
    let router = Router::of(&w);
    let _app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ClaimsWrite, Permission::ReplyAdd],
    )
    .await;
    // A live claim at generation 1: its entry's proof is checked with generation 1's key.
    w.dispatch
        .app_op(
            &app_keys("wallet"),
            OpKind::Claim(pubky_dispatch_core::claims::ClaimFields {
                claim_key: vec![7; 32],
                kind: pubky_dispatch_core::claims::ClaimType::Attempt,
                expected_step: 0,
                attempt_id: vec![8; 16],
                orphan_after: Some(86_400),
                deadline: None,
                basis: None,
                evidence_ref: None,
            }),
        )
        .unwrap();
    assert_eq!(
        signer_call(&w, &w.dispatch, "GET", "apps", Vec::new()).1["proof_generations"],
        serde_json::json!([1])
    );
    let old_key = w.dispatch.service_key();
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    let held = next.identity_doc().unwrap();
    // The document naming the next service keeps generation 1's key.
    let named = w
        .signer
        .sign_next(|body| {
            body.generation = 2;
            body.inbox = Inbox::new(NEXT, n_key.verifying_key().to_bytes());
            body.service_keys = vec![pubky_dispatch_core::records::ServiceKeyEntry {
                generation: 1,
                key: old_key,
            }];
        })
        .unwrap();
    assert_eq!(deliver(&w, &next, &named, &held).0, 200);
    let (status, apps) = signer_call(&w, &next, "GET", "apps", Vec::new());
    assert_eq!(status, 200);
    assert_eq!(apps["proof_generations"], serde_json::json!([1]));
    // A later version that drops it is refused, naming the generation.
    let dropped = w
        .signer
        .sign_next(|body| body.service_keys.clear())
        .unwrap();
    let (status, answer) = deliver(&w, &next, &dropped, &named);
    assert_eq!(status, 409, "{answer}");
    assert_eq!(answer["code"], "conflict");
    assert_eq!(
        answer["current"]["proof_generations"],
        serde_json::json!([1])
    );
    // So is one that lists another key for it.
    let wrong = w
        .signer
        .sign_next(|body| {
            body.service_keys = vec![pubky_dispatch_core::records::ServiceKeyEntry {
                generation: 1,
                key: [9; 32],
            }];
        })
        .unwrap();
    assert_eq!(deliver(&w, &next, &wrong, &named).0, 409);
    assert_eq!(next.identity_doc().unwrap().hash(), named.hash());
}

#[tokio::test]
async fn test_apps_answer_reports_what_the_dispatch_holds() {
    let w = World::new();
    let app = w.join("wallet").await;
    let (_, apps) = signer_call(&w, &w.dispatch, "GET", "apps", Vec::new());
    assert_eq!(apps["recovery"], serde_json::Value::Null);
    assert!(apps["identity"].is_object());
    let wallet = apps["apps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["app_id"] == pubky_dispatch_core::enc::zbase32_encode(&app.app_id()))
        .unwrap()
        .clone();
    assert_eq!(
        wallet["cert_expires_at"],
        pubky_dispatch_core::time::rfc3339(app.cert().expires_at())
    );
    // No document held: `identity` is null, not left out.
    let empty = ScriptedDispatch::new(&w.alice, [5; 32], Arc::clone(&w.clock));
    let (_, apps) = signer_call(&w, &empty, "GET", "apps", Vec::new());
    assert_eq!(apps.get("identity"), Some(&serde_json::Value::Null));
    // A recovery reports when it was declared.
    w.clock.advance_ms(5_000);
    let declared = w.clock.now_ms();
    let recovering =
        ScriptedDispatch::recovering(&w.alice, [6; 32], Arc::clone(&w.clock), 2, 1).unwrap();
    w.clock.advance_ms(5_000);
    let (_, apps) = signer_call(&w, &recovering, "GET", "apps", Vec::new());
    assert_eq!(
        apps["recovery"]["declared_at"],
        pubky_dispatch_core::time::rfc3339(declared)
    );
}

#[tokio::test]
async fn test_loss_claim_changed_by_an_upload_after_an_entry_here_is_read() {
    // After the loss the app writes an attempt at the new Dispatch (an entry at step 0).
    // Another app's recovery upload then changes the claim as the core merge does (an
    // attempt beside it: divergent, step 2, no entry). The Dispatch lists the one entry, and
    // the app reads the gapped claim without an alarm (Dispatch wire 7.4.8).
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        &Permission::ALL,
        false,
        true,
    )
    .await;
    let (mut app, _) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    if app.reconcile_mode() {
        app.end_reconcile(UserConfirmed::new()).await.unwrap();
    }
    app.write_claim(
        ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
        vec![],
        ObligationDeadline::NoDeadline,
    )
    .await
    .unwrap();
    upload_beside(&lost.next);
    let read = app.read_claim(&CLAIM).await;
    assert!(read.is_ok(), "the gapped claim is read: {read:?}");
    assert!(app.alarm().is_none(), "{:?}", app.alarm());
}

#[tokio::test]
async fn test_loss_claim_step_before_its_last_entry_is_a_rollback() {
    // Even after a provider loss, a claim's step is never before its last entry's: a Dispatch
    // that shows one contradicts its answer (Dispatch wire 7.4.8).
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        &Permission::ALL,
        false,
        true,
    )
    .await;
    let (mut app, _) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    if app.reconcile_mode() {
        app.end_reconcile(UserConfirmed::new()).await.unwrap();
    }
    app.write_claim(
        ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
        vec![],
        ObligationDeadline::NoDeadline,
    )
    .await
    .unwrap();
    if let Some(claim) = lost.next.lock().shared.claims.get_mut(&CLAIM) {
        claim.step = 0;
    }
    assert!(app.read_claim(&CLAIM).await.is_err());
    assert!(
        matches!(app.alarm(), Some(crate::app::Alarm::Rollback { .. })),
        "{:?}",
        app.alarm()
    );
}

/// Another app's uploaded attempt beside the one `dispatch` holds at [`CLAIM`], merged as the
/// core merges an upload: divergent, one step on, no entry.
pub(crate) fn upload_beside(dispatch: &ScriptedDispatch) {
    let mut next = dispatch.lock();
    let held = next.shared.claims.get(&CLAIM).cloned();
    let entry = pubky_dispatch_core::recovery::UploadedEntry {
        entry: pubky_dispatch_core::claims::ClaimEntry {
            claim_key: CLAIM,
            attempt_id: [77; 16],
            expected_step: 0,
            kind: pubky_dispatch_core::claims::EntryKind::Attempt {
                orphan_after: 60,
                deadline: None,
            },
        },
        writer: [9; 16],
        proof: None,
    };
    let merge =
        pubky_dispatch_core::recovery::merge_upload_claim(held.as_ref(), None, &[entry], START, 64);
    assert!(merge.changed && merge.divergent, "{merge:?}");
    next.shared.claims.insert(CLAIM, merge.claim.unwrap());
}

#[tokio::test]
async fn test_claim_step_past_its_last_entry_outside_a_loss_is_a_rollback() {
    // Outside a generation that began with a provider loss, a claim whose step is past its
    // last entry's contradicts the answer: the read alarms.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    app.write_claim(
        ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
        vec![],
        ObligationDeadline::NoDeadline,
    )
    .await
    .unwrap();
    upload_beside(&w.dispatch);
    assert!(app.read_claim(&CLAIM).await.is_err());
    assert!(
        matches!(app.alarm(), Some(crate::app::Alarm::Rollback { .. })),
        "{:?}",
        app.alarm()
    );
}

/// The lost world followed by an app holding every permission, which wrote an attempt at
/// [`CLAIM`] at the new Dispatch; then another app's upload changed the claim beside it.
async fn gapped_after_a_loss() -> (Lost, App) {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        &Permission::ALL,
        false,
        true,
    )
    .await;
    let (mut app, _) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    if app.reconcile_mode() {
        app.end_reconcile(UserConfirmed::new()).await.unwrap();
    }
    app.write_claim(
        ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
        vec![],
        ObligationDeadline::NoDeadline,
    )
    .await
    .unwrap();
    upload_beside(&lost.next);
    (lost, app)
}

#[tokio::test]
async fn test_gapped_claim_read_by_an_app_without_a_loss_record() {
    // An app that holds no loss record, as one that joined at the new Dispatch after the
    // loss: the identity's identity.json carries `recovery_from`, so the rebuilt claim's gap
    // is read without an alarm (Dispatch wire 7.4.8).
    let (_lost, mut app) = gapped_after_a_loss().await;
    let mut tx = app.tx().unwrap();
    tx.delete(crate::app::recovery::keys::LOSS).unwrap();
    app.commit(tx).await.unwrap();
    assert!(app.state.own_doc.body().recovery_from.is_some());
    let read = app.read_claim(&CLAIM).await;
    assert!(read.is_ok(), "the gapped claim is read: {read:?}");
    assert!(app.alarm().is_none(), "{:?}", app.alarm());
}

#[tokio::test]
async fn test_gapped_claim_read_at_a_generation_after_the_loss() {
    // An app whose loss record names an earlier generation than the one it serves now, as
    // after a later move or key change: the claim's gap is still read (Dispatch wire 7.4.8,
    // 10.5).
    let (_lost, mut app) = gapped_after_a_loss().await;
    let mut loss = app.loss_record().await.unwrap().unwrap();
    loss.generation -= 1;
    let mut tx = app.tx().unwrap();
    tx.put(crate::app::recovery::keys::LOSS, &loss).unwrap();
    app.commit(tx).await.unwrap();
    let read = app.read_claim(&CLAIM).await;
    assert!(read.is_ok(), "the gapped claim is read: {read:?}");
    assert!(app.alarm().is_none(), "{:?}", app.alarm());
}

#[tokio::test]
async fn test_gapped_claim_that_isnt_rebuilt_is_a_rollback_after_a_loss() {
    // Even at an identity that had a provider loss, a claim whose view isn't `rebuilt` and
    // whose step is past its last entry's contradicts the answer: a service that dropped its
    // newest entries (Dispatch wire 7.4.8).
    let (lost, mut app) = gapped_after_a_loss().await;
    if let Some(claim) = lost.next.lock().shared.claims.get_mut(&CLAIM) {
        claim.rebuilt = false;
    }
    assert!(app.read_claim(&CLAIM).await.is_err());
    assert!(
        matches!(app.alarm(), Some(crate::app::Alarm::Rollback { .. })),
        "{:?}",
        app.alarm()
    );
}

// -------------------------------------------------------------------------------------
// A restore meeting a provider change: registrations since the backup (Dispatch spec 12.4)

/// Alice's wallet, joined at `router`, and its backup taken before the device rotated to
/// key 1: the restored app never made that key.
async fn backed_up_then_rotated(w: &World, router: &Router) -> AppBackup {
    let mut app = join(w, router).await;
    let backup = app.backup().await.unwrap();
    w.note(app.app_id(), "before the rotation");
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    assert_eq!(app.receive_key_numbers().last(), Some(&1));
    backup
}

/// `backup` restored at `router` onto `store`.
async fn restored_at(
    w: &World,
    router: &Router,
    store: Arc<dyn StateStore>,
    backup: &AppBackup,
) -> App {
    App::restore(
        router.env(w, store),
        w.protocol.clone(),
        World::config(),
        backup,
    )
    .await
    .unwrap()
}

fn asked(events: &[AppEvent]) -> bool {
    has(events, |e| matches!(e, AppEvent::RestoreQuestion { .. }))
}

#[tokio::test]
async fn test_restore_meeting_a_key_change_asks_about_a_later_registration() {
    let w = World::new();
    let router = Router::of(&w);
    let backup = backed_up_then_rotated(&w, &router).await;
    let changed = change_key(&w, &router);
    let mut restored = restored_at(&w, &router, Arc::new(MemoryStore::new()), &backup).await;
    let report = restored.receive(None).await.unwrap();
    assert!(asked(&report.events), "{:?}", report.events);
    assert_eq!(restored.restore_question(), vec![1]);
    assert!(restored.alarm().is_none());
    assert_eq!(restored.cursor().generation, 2);
    // It registered a key above the one it can't account for, at the service it follows.
    assert_eq!(restored.receive_key_numbers().last(), Some(&2));
    assert_eq!(changed.app(&restored.app_id()).receive_n, Some(2));
}

#[tokio::test]
async fn test_restore_meeting_a_move_asks_about_a_later_registration() {
    let w = World::new();
    let router = Router::of(&w);
    let backup = backed_up_then_rotated(&w, &router).await;
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let mut restored = restored_at(&w, &router, Arc::new(MemoryStore::new()), &backup).await;
    let mut events = Vec::new();
    for _ in 0..2 {
        events.extend(restored.receive(None).await.unwrap().events);
    }
    assert!(asked(&events), "{events:?}");
    assert_eq!(restored.restore_question(), vec![1]);
    assert!(restored.alarm().is_none());
    assert_eq!(restored.cursor().generation, 2);
}

#[tokio::test]
async fn test_restore_meeting_a_key_change_then_denied_is_a_compromise() {
    let w = World::new();
    let router = Router::of(&w);
    let backup = backed_up_then_rotated(&w, &router).await;
    change_key(&w, &router);
    let mut restored = restored_at(&w, &router, Arc::new(MemoryStore::new()), &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(restored.restore_question(), vec![1]);
    let error = restored.refuse_restored_registrations().await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Alarm(crate::app::Alarm::Compromise { n: 1, .. })
        ),
        "{error:?}"
    );
}

/// The device sync of an app that shares its keys: a registration since the backup that no
/// device made is asked about while the restore is held, not taken for a compromise.
#[tokio::test]
async fn test_restore_device_sync_asks_about_a_registration_no_device_made() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.set_multi_device(true).await.unwrap();
    let backup = app.backup().await.unwrap();
    w.note(app.app_id(), "before the rotation");
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    assert_eq!(app.receive_key_numbers().last(), Some(&1));
    drop(app);
    let mut restored = restored_at(&w, &router, Arc::new(MemoryStore::new()), &backup).await;
    restored.receive(None).await.unwrap();
    assert!(
        restored.restore_question().is_empty(),
        "the device sync decides"
    );
    // A device sync that brings no key 1: no device made it.
    let keys = restored.device_keys();
    restored.take_device_keys(keys).await.unwrap();
    assert_eq!(restored.restore_question(), vec![1]);
    assert!(restored.alarm().is_none());
}

/// A provider loss the device the backup came from followed first, registering its own
/// key at the new service: the restored app's registration there meets it, and asks.
#[tokio::test]
async fn test_restore_meeting_a_loss_asks_about_a_later_registration() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let backup = app.backup().await.unwrap();
    w.clock.advance_ms(60_000);
    let n_key = next_key();
    let next = ScriptedDispatch::recovering(&w.alice, n_key.to_bytes(), Arc::clone(&w.clock), 2, 1)
        .unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    w.dispatch.lock().not_hosted_unpinned = true;
    // The device follows the loss, registering a fresh key there.
    app.refresh_identity().await.unwrap();
    app.receive(None).await.unwrap();
    let theirs = next.app(&app.app_id()).receive_n.unwrap();
    assert!(theirs >= 1);
    drop(app);
    let mut restored = restored_at(&w, &router, Arc::new(MemoryStore::new()), &backup).await;
    restored.refresh_identity().await.unwrap();
    let mut events = Vec::new();
    for _ in 0..2 {
        events.extend(restored.receive(None).await.unwrap().events);
    }
    assert!(asked(&events), "{events:?}");
    assert!(
        restored.restore_question().contains(&theirs),
        "{:?}",
        restored.restore_question()
    );
    assert!(restored.alarm().is_none());
}

/// The restore's key check owed across a crash: the read that follows the key change stops
/// before the check, and the app loaded again asks, as the first read would have.
#[tokio::test]
async fn test_restore_check_owed_across_a_crash_after_a_key_change_still_asks() {
    let w = World::new();
    let router = Router::of(&w);
    let backup = backed_up_then_rotated(&w, &router).await;
    let changed = change_key(&w, &router);
    let store = Arc::new(MemoryStore::new());
    let mut restored = restored_at(
        &w,
        &router,
        Arc::clone(&store) as Arc<dyn StateStore>,
        &backup,
    )
    .await;
    // The follow reads the directory once; the restore's check, which reads it again, can't.
    changed.fail_next(Fault::Unreachable {
        path: "directory".into(),
        after: 1,
    });
    assert!(restored.receive(None).await.is_err());
    assert!(restored.alarm().is_none());
    drop(restored);
    let mut loaded = App::load(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    assert!(loaded.reconcile_mode());
    loaded.receive(None).await.unwrap();
    assert_eq!(loaded.restore_question(), vec![1]);
    assert!(loaded.alarm().is_none());
    assert_eq!(loaded.receive_key_numbers().last(), Some(&2));
}

/// A record signed before the old service was lost goes with the new registration and
/// is published after it.
#[tokio::test]
async fn test_loss_record_changed_before_it_is_published_after_the_re_registration() {
    loss_record_published(false).await;
}

/// As above, the Homeserver failing at the read that follows the loss: the record stays
/// owed in the store, and a later load publishes it.
#[tokio::test]
async fn test_loss_record_changed_before_stays_owed_across_a_load() {
    loss_record_published(true).await;
}

async fn loss_record_published(homeserver_fails: bool) {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let publishing = AppConfig {
        publishes_record: true,
        ..World::config()
    };
    let path = pubky_dispatch_core::records::app_record_path(&app_keys("wallet").app_id_bytes());
    let mut app = App::load(
        lost.router
            .env(&lost.w, Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
        publishing.clone(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    // The old service answers the time read but cannot take the signed record.
    lost.w.dispatch.lock().not_hosted_unpinned = false;
    lost.w.dispatch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    let member = serde_json::Map::from_iter([("a".to_owned(), json!(1))]);
    app.set_protocol_member("sample", Some(member), None)
        .await
        .unwrap_err();
    lost.w.dispatch.lock().not_hosted_unpinned = true;
    assert!(app.state.pending_record.is_some());
    let changed = app.record().clone();
    assert!(
        lost.w
            .homeserver
            .file(lost.w.alice.public(), &path)
            .is_none()
    );
    drop(app);
    let mut app = App::load(
        lost.router
            .env(&lost.w, Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
        publishing,
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    app.refresh_identity().await.unwrap();
    if homeserver_fails {
        lost.w.homeserver.fail_writes(1, false);
    }
    app.receive(None).await.unwrap();
    let me = app.app_id();
    assert_eq!(lost.next.app(&me).record, Some(changed.clone()));
    if homeserver_fails {
        assert!(
            lost.w
                .homeserver
                .file(lost.w.alice.public(), &path)
                .is_none()
        );
        drop(app);
        let mut app = App::load(
            lost.router
                .env(&lost.w, Arc::clone(&store) as Arc<dyn StateStore>),
            Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
            AppConfig {
                publishes_record: true,
                ..World::config()
            },
            me,
        )
        .await
        .unwrap();
        app.receive(None).await.unwrap();
    }
    assert_eq!(
        lost.w.homeserver.file(lost.w.alice.public(), &path),
        Some(serde_json::to_vec(&changed).unwrap())
    );
}

/// A record changed while the old service was frozen goes with the re-registration at the
/// next one, and is published after it (Dispatch spec 4.2, 12.5).
#[tokio::test]
async fn test_move_record_changed_before_it_is_published_after_the_re_registration() {
    move_record_published(false).await;
}

/// As above, the Homeserver failing at the read that follows the move: the record stays
/// owed in the store, and a later load publishes it.
#[tokio::test]
async fn test_move_record_changed_before_stays_owed_across_a_load() {
    move_record_published(true).await;
}

async fn move_record_published(homeserver_fails: bool) {
    let store = Arc::new(MemoryStore::new());
    let (w, router, next, _) = moved_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let publishing = AppConfig {
        publishes_record: true,
        ..World::config()
    };
    let me = app_keys("wallet").app_id_bytes();
    let path = pubky_dispatch_core::records::app_record_path(&me);
    let load = || {
        App::load(
            router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
            w.protocol.clone(),
            publishing.clone(),
            me,
        )
    };
    let mut app = load().await.unwrap();
    w.clock.advance_ms(1);
    let member = serde_json::Map::from_iter([("a".to_owned(), json!(1))]);
    app.set_protocol_member("sample", Some(member), None)
        .await
        .unwrap_err();
    assert!(app.state.pending_record.is_some());
    let changed = app.record().clone();
    drop(app);
    if homeserver_fails {
        // Both reads of the follow meet it.
        w.homeserver.fail_writes(2, false);
    }
    let mut app = load().await.unwrap();
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    assert_eq!(next.app(&me).record, Some(changed.clone()));
    if homeserver_fails {
        assert!(w.homeserver.file(w.alice.public(), &path).is_none());
        drop(app);
        load().await.unwrap().receive(None).await.unwrap();
    }
    assert_eq!(
        w.homeserver.file(w.alice.public(), &path),
        Some(serde_json::to_vec(&changed).unwrap())
    );
}

/// Dispatch spec 4.2: a record the new service refuses at the re-registration, holding a later
/// one of the app's from another device, is never published.
#[tokio::test]
async fn test_loss_record_the_new_service_refuses_is_never_published() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    lost.router.remove(NEXT);
    assert!(
        follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
            .await
            .is_err()
    );
    // Another device of the app registers its key first, with a later record of the app.
    let mut app = load_lost(&lost, Arc::clone(&store) as Arc<dyn StateStore>).await;
    let other = pubky_dispatch_core::keys::ReceiveKey::generate(1).unwrap();
    let mut later =
        pubky_dispatch_core::records::AppRecord::verify(app.record(), &lost.w.alice.public())
            .unwrap()
            .body()
            .clone();
    later.updated_at += 60_000;
    later
        .protocols
        .insert("calendar".into(), Default::default());
    let later = pubky_dispatch_core::records::AppRecord::sign(&app_keys("wallet"), later).unwrap();
    let keys = app_keys("wallet");
    lost.next
        .app_op(
            &keys,
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    lost.next
        .app_op(
            &keys,
            OpKind::ReceiveKeyPut {
                record: wallet_key_record(&app, &other).signed().clone(),
            },
        )
        .unwrap();
    app.take_device_keys(crate::app::DeviceKeys {
        receive_keys: Vec::new(),
        known: vec![(pubky_dispatch_core::enc::b64(&other.kid), 1)],
        rotation_ms: 0,
    })
    .await
    .unwrap();
    drop(app);
    lost.router.add(NEXT, &lost.next);
    let mut app = App::load(
        lost.router
            .env(&lost.w, Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
        AppConfig {
            publishes_record: true,
            ..World::config()
        },
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    app.refresh_identity().await.unwrap();
    app.receive(None).await.unwrap();
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
    // The new service holds the later record; the app's own was refused, so nothing of it
    // was noted as accepted or published.
    let me = app.app_id();
    assert_eq!(lost.next.app(&me).record, Some(later.signed().clone()));
    let path = pubky_dispatch_core::records::app_record_path(&me);
    assert!(
        lost.w
            .homeserver
            .file(lost.w.alice.public(), &path)
            .is_none()
    );
}

#[tokio::test]
async fn test_feed_wait_across_a_move_followed_outside_a_read() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    for _ in 0..10 {
        w.note(me, "hello");
    }
    app.receive(None).await.unwrap();
    let read_to = app.cursor();
    let n_key = next_key();
    let freeze = freeze_for(&w, &n_key, 2);
    w.dispatch.freeze(&freeze).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    assert_eq!(
        app.check_for_move().await.unwrap(),
        ProviderStatus::AwaitingMove { next_generation: 2 }
    );
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    // The document naming the next generation, taken outside a read: no wait at this
    // service can tell anything, and none is sent.
    app.refresh_identity().await.unwrap();
    assert!(app.not_current_here().is_some());
    assert_eq!(format!("{:?}", app.feed_wait(25)), "FeedWait(ReadLater)");
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadLater);
    // Followed outside a read: the wait goes from the cursor at the next service, not from
    // the position the last read reached at the earlier one.
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Followed { generation: 2 }
    );
    let cursor = app.cursor();
    assert_eq!(cursor.generation, 2);
    let shown = format!("{:?}", app.feed_wait(25));
    assert!(shown.contains(&format!("\"{cursor}\"")), "{shown}");
    // Whatever `seq` the earlier service's position has.
    assert_eq!(read_to.generation, 1);
    app.next_wait = crate::app::wait::NextWait::From(crate::app::wait::WaitFrom {
        position: pubky_dispatch_core::ops::Position {
            seq: cursor.seq + 50,
            ..read_to
        },
        again: false,
    });
    let shown = format!("{:?}", app.feed_wait(25));
    assert!(shown.contains(&format!("\"{cursor}\"")), "{shown}");
}

#[tokio::test]
async fn test_move_sends_writes_kept_during_the_freeze_once_in_order() {
    writes_kept_during_a_freeze_reach_the_next_service().await;
}

/// Five writes while the account is frozen: the first is sent and answered `410 moved`, the
/// next four are kept unsent behind it. At the next service each goes once, in the order the
/// calls kept them, and nothing more goes to the old one. Also run on a small stack
/// (`protocol_api.rs`): the read that follows the move sends them.
pub(super) async fn writes_kept_during_a_freeze_reach_the_next_service() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = lists_app(&w, &router).await;
    let pubkys: Vec<[u8; 32]> = ["carol", "erin", "dave", "frank", "grace"]
        .iter()
        .map(|name| IdentityKey::from_secret(seed(&format!("{name}/identity"))).public())
        .collect();
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let mut kept = Vec::new();
    for pubky in &pubkys {
        w.clock.advance_ms(1_000);
        let error = app.submit_batch(kept_peer_batch(*pubky)).await.unwrap_err();
        assert_eq!(error.code(), Some(ErrorCode::Moved), "{error:?}");
        kept.push(error.kept_batch().expect("kept"));
    }
    let old_ops = w.dispatch.applied().len();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    for _ in 0..6 {
        if !app.receive(None).await.unwrap().more {
            break;
        }
    }
    assert!(app.kept_batches().await.unwrap().is_empty());
    for id in &kept {
        assert!(
            matches!(
                app.kept_batch(*id).await.unwrap(),
                Some(crate::app::KeptBatchStatus::Applied { .. })
            ),
            "{:?}",
            app.kept_batch(*id).await.unwrap()
        );
    }
    let order: Vec<[u8; 32]> = next
        .applied()
        .iter()
        .filter_map(|op| match op.body().kind {
            OpKind::AllowPut { pubky, .. } if pubkys.contains(&pubky) => Some(pubky),
            _ => None,
        })
        .collect();
    assert_eq!(order, pubkys, "each once, in the order kept");
    assert_eq!(w.dispatch.applied().len(), old_ops);
}

#[tokio::test]
async fn test_loss_upload_over_cap_reports_refusal_after_reload() {
    Box::pin(loss_upload_with_records(40)).await;
}

#[tokio::test]
async fn test_loss_upload_within_cap_completes_after_reload() {
    Box::pin(loss_upload_with_records(1)).await;
}

async fn loss_upload_with_records(count: usize) {
    use crate::client::answers::{RecoveryUpload, UploadedOp};

    const CAP: usize = 16 * 1024 * 1024;
    let store = Arc::new(MemoryStore::new());
    let w = World::new();
    let router = Router::of(&w);
    let protocol = Arc::new(LossProtocol::default());
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&protocol) as Arc<dyn Protocol>,
        &[],
    )
    .await;
    let value = json!({"items": [], "pad": "x".repeat(200_000)})
        .to_string()
        .into_bytes();
    for n in 0..count {
        let target = crate::app::RecordTarget::new(
            super::shared_flows::items(),
            format!("record-{n}").as_bytes(),
        );
        app.put_record(&target, &value, vec![]).await.unwrap();
    }
    let kept = app.shared_evidence().await.unwrap();
    let records: Vec<UploadedOp> = kept
        .ops
        .iter()
        .map(|op| UploadedOp {
            op: op.op.clone(),
            cert: op.cert.clone(),
            proof: op.proof.clone(),
        })
        .collect();
    assert_eq!(records.len(), count);
    for record in &records {
        let cert = AppCert::verify(&record.cert, &w.alice.public()).unwrap();
        pubky_dispatch_core::ops::SignedOp::verify_with_cert(&record.op, &cert, &w.alice.public())
            .unwrap();
        assert!(record.proof.is_some());
    }
    let bytes = RecoveryUpload {
        records,
        ..RecoveryUpload::default()
    }
    .to_json()
    .len();
    let too_large = count == 40;
    assert_eq!(
        bytes > CAP,
        too_large,
        "the aggregate, not one operation, exceeds the cap"
    );
    w.clock.advance_ms(60_000);
    let n_key = next_key();
    let next = ScriptedDispatch::recovering(&w.alice, n_key.to_bytes(), Arc::clone(&w.clock), 2, 1)
        .unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    w.dispatch.lock().not_hosted_unpinned = true;
    drop(app);
    let load = || {
        App::load(
            router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
            Arc::clone(&protocol) as Arc<dyn Protocol>,
            World::config(),
            app_keys("wallet").app_id_bytes(),
        )
    };
    let mut app = load().await.unwrap();
    app.refresh_identity().await.unwrap();
    let first = app.receive(None).await;
    let first_done = app.recovery_info().await.unwrap().unwrap().steps_done;
    assert_eq!(
        app.shared_evidence().await.unwrap(),
        kept,
        "retained signed evidence survives"
    );
    drop(app);
    let mut app = load().await.unwrap();
    let second = app.receive(None).await;
    assert_eq!(
        app.shared_evidence().await.unwrap(),
        kept,
        "reload preserves retained evidence"
    );
    let sent = router
        .log()
        .iter()
        .filter(|line| line.contains("/recovery/upload"))
        .count();
    assert_eq!(
        sent,
        usize::from(!too_large),
        "a local cap refusal sends nothing"
    );
    assert_eq!(
        next.lock().shared.records.len(),
        if too_large { 0 } else { count }
    );
    assert!(
        first_done,
        "an upload refused for good must let recovery continue: {first:?}; retry: {second:?}"
    );
    let first = first.unwrap();
    assert_eq!(
        has(&first.events, |event| matches!(event,
            AppEvent::EvidenceRefused { code } if code == "too_large"
        )),
        too_large
    );
    second.unwrap();
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
    assert_eq!(protocol.losses.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_upload_refusal_keeps_unread_answers_retryable() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    for code in [
        ErrorCode::TooLarge,
        ErrorCode::RateLimited,
        ErrorCode::NotFound,
    ] {
        let error = ClientError::BodyUnread {
            status: code.status(),
            code,
            retry_after: None,
        };
        app.events.clear();
        assert_eq!(
            app.uploaded(Err(error.clone())),
            Err(AppError::Dispatch(error))
        );
        assert!(app.events.is_empty());
    }
}

/// The signer renews the app at the current service to the same scopes, stores the
/// renewal there and lists it; returns it.
fn renew_listed(w: &World, me: [u8; 16], old: &AppCert) -> AppCert {
    use pubky_dispatch_core::records::{ListedApp, RenewedCert};
    w.clock.advance_ms(1_000);
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["sample-a"],
    );
    w.dispatch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: me,
            cert: renewed.signed().clone(),
        }])
        .unwrap();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.apps.push(ListedApp {
            app_id: me,
            cert: renewed.hash(),
        });
        body.renewed.push(RenewedCert {
            app_id: me,
            cert: old.hash(),
            until: None,
        });
    });
    renewed
}

#[tokio::test]
async fn test_move_after_a_restore_takes_the_renewal_listed_since_the_backup() {
    // The backup predates a renewal the app took at the old service. Restored after the
    // move, the app reads its entry at the next service and takes the listed certificate
    // before it registers there (Dispatch spec 12.4 "Certificate"); without a renewal since
    // the backup the move goes as before.
    for renewed_since in [false, true] {
        let w = World::new();
        let router = Router::of(&w);
        let mut app = join_on(
            &w,
            &router,
            Arc::new(MemoryStore::new()),
            w.protocol.clone(),
            &[Permission::ReplyAdd],
        )
        .await;
        let me = app.app_id();
        app.receive(None).await.unwrap();
        let backup = app.backup().await.unwrap();
        let old = app.cert().clone();
        let mut presented = old.hash();
        if renewed_since {
            let renewed = renew_listed(&w, me, &old);
            for _ in 0..2 {
                w.clock.advance_ms(1_000);
                app.receive(None).await.unwrap();
            }
            assert_eq!(app.cert().hash(), renewed.hash());
            presented = renewed.hash();
        }
        drop(app);
        w.clock.advance_ms(1_000);
        let n_key = next_key();
        w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
        let next = w.dispatch.import_into(n_key.to_bytes());
        router.add(NEXT, &next);
        publish_at(
            &w,
            &next,
            Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
            2,
            None,
        );
        let mut restored = App::restore(
            router.env(&w, Arc::new(MemoryStore::new())),
            w.protocol.clone(),
            World::config(),
            &backup,
        )
        .await
        .unwrap();
        for _ in 0..3 {
            w.clock.advance_ms(1_000);
            restored.receive(None).await.unwrap();
        }
        assert_eq!(restored.cursor().generation, 2, "renewed: {renewed_since}");
        assert_eq!(
            restored.cert().hash(),
            presented,
            "renewed: {renewed_since}"
        );
        let held = next.app(&me).record.unwrap();
        assert_eq!(
            pubky_dispatch_core::records::AppRecord::verify(&held, &w.alice.public())
                .unwrap()
                .cert()
                .hash(),
            presented
        );
    }
}

#[tokio::test]
async fn test_loss_after_a_restore_takes_the_listed_certificate_before_registering() {
    // The backup predates a renewal the app took. The service is then lost, and another
    // device of the app registered at the next service under the renewal. The restored
    // app reads its entry there and takes the listed certificate before it registers
    // (Dispatch spec 12.4 "Certificate"); its record under the earlier one would be refused.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::new(MemoryStore::new()),
        w.protocol.clone(),
        &[Permission::ReplyAdd],
    )
    .await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let backup = app.backup().await.unwrap();
    let old = app.cert().clone();
    let renewed = renew_listed(&w, me, &old);
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        app.receive(None).await.unwrap();
    }
    assert_eq!(app.cert().hash(), renewed.hash());
    let theirs = app.record().clone();
    drop(app);
    w.clock.advance_ms(60_000);
    let n_key = next_key();
    let next = ScriptedDispatch::recovering(&w.alice, n_key.to_bytes(), Arc::clone(&w.clock), 2, 1)
        .unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    w.dispatch.lock().not_hosted_unpinned = true;
    next.app_op(&app_keys("wallet"), OpKind::AppPut { record: theirs })
        .unwrap();
    let mut restored = App::restore(
        router.env(&w, Arc::new(MemoryStore::new())),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.refresh_identity().await.unwrap();
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(restored.cursor().generation, 2);
    assert_eq!(restored.cert().hash(), renewed.hash());
    assert!(next.app(&me).receive_n.is_some());
}

#[tokio::test]
async fn test_loss_after_a_restore_waits_on_an_entry_that_does_not_verify() {
    // At the next service the app's entry doesn't verify: the restored app registers
    // nothing there on the record it holds, and says why, until the user goes on from it.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::new(MemoryStore::new()),
        w.protocol.clone(),
        &[Permission::ReplyAdd],
    )
    .await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let backup = app.backup().await.unwrap();
    let record = app.record().clone();
    drop(app);
    w.clock.advance_ms(60_000);
    let n_key = next_key();
    let next = ScriptedDispatch::recovering(&w.alice, n_key.to_bytes(), Arc::clone(&w.clock), 2, 1)
        .unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    w.dispatch.lock().not_hosted_unpinned = true;
    next.app_op(
        &app_keys("wallet"),
        OpKind::AppPut {
            record: record.clone(),
        },
    )
    .unwrap();
    next.lock().apps.get_mut(&me).unwrap().receive_key = Some(record);
    let store = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.refresh_identity().await.unwrap();
    let waits = restored.receive(None).await;
    assert!(
        matches!(&waits, Err(AppError::Refused(Refusal::NotNow(how))) if how.contains("build_on_held_record")),
        "{waits:?}"
    );
    assert_eq!(next.app(&me).receive_n, None);
    // The user goes on, and the app stops before the registration goes: the go-ahead isn't
    // kept, so the read after the restart waits again, its event still pending.
    let unread = |events: Vec<AppEvent>| {
        events
            .into_iter()
            .filter(|e| matches!(e, AppEvent::RecordBaseUnread { .. }))
            .count()
    };
    assert_eq!(unread(restored.unacknowledged_events().await.unwrap()), 1);
    restored.build_on_held_record().await.unwrap();
    drop(restored);
    let mut restored = App::load(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    let waits = restored.receive(None).await;
    assert!(
        matches!(&waits, Err(AppError::Refused(Refusal::NotNow(how))) if how.contains("build_on_held_record")),
        "{waits:?}"
    );
    assert_eq!(unread(restored.unacknowledged_events().await.unwrap()), 1);
    // The same call goes on from there: the next read sends the registration. The scripted
    // service itself can't apply it over the entry this test broke; what is shown is that
    // the request goes.
    restored.build_on_held_record().await.unwrap();
    w.clock.advance_ms(1_000);
    let ops = |router: &Router| {
        router
            .log()
            .iter()
            .filter(|line| line.contains(NEXT) && line.contains("/ops"))
            .count()
    };
    let before = ops(&router);
    let _ = restored.receive(None).await;
    assert!(
        ops(&router) > before,
        "the registration went to the next service"
    );
}

#[tokio::test]
async fn test_move_after_a_restore_and_a_document_read_takes_the_listed_certificate() {
    // As above, but the restored app reads its newest identity.json first, so it follows
    // the move without reading the old service: it takes the listed certificate from its
    // entry at the next service before it registers there.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::new(MemoryStore::new()),
        w.protocol.clone(),
        &[Permission::ReplyAdd],
    )
    .await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let backup = app.backup().await.unwrap();
    let old = app.cert().clone();
    let renewed = renew_listed(&w, me, &old);
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        app.receive(None).await.unwrap();
    }
    assert_eq!(app.cert().hash(), renewed.hash());
    drop(app);
    w.clock.advance_ms(1_000);
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let mut restored = App::restore(
        router.env(&w, Arc::new(MemoryStore::new())),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.refresh_identity().await.unwrap();
    for _ in 0..3 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(restored.cursor().generation, 2);
    assert_eq!(restored.cert().hash(), renewed.hash());
}

/// A restore whose first read left the base unread, then a provider loss to a service
/// that holds no record of the app: there is no entry there, the held record is the base,
/// and the registration goes.
#[tokio::test]
async fn test_loss_to_an_empty_service_settles_a_base_left_unread() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::new(MemoryStore::new()),
        w.protocol.clone(),
        &[Permission::ReplyAdd],
    )
    .await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let backup = app.backup().await.unwrap();
    drop(app);
    let unlisted = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms() + 1_000,
        &["sample-a"],
    );
    let body = pubky_dispatch_core::records::AppRecordBody::new(
        &unlisted,
        vec![],
        w.clock.now_ms() + 1_000,
    );
    let shown = pubky_dispatch_core::records::AppRecord::sign(&app_keys("wallet"), body).unwrap();
    w.dispatch.lock().apps.get_mut(&me).unwrap().record = Some(shown.signed().clone());
    let mut restored = App::restore(
        router.env(&w, Arc::new(MemoryStore::new())),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    w.clock.advance_ms(2_000);
    restored.receive(None).await.unwrap();
    assert_eq!(
        restored.state.base_unread,
        Some(crate::app::RecordBaseCause::OtherCertificate)
    );
    w.clock.advance_ms(60_000);
    let n_key = next_key();
    let next = ScriptedDispatch::recovering(&w.alice, n_key.to_bytes(), Arc::clone(&w.clock), 2, 1)
        .unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    w.dispatch.lock().not_hosted_unpinned = true;
    restored.refresh_identity().await.unwrap();
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(restored.cursor().generation, 2);
    assert!(next.app(&me).receive_n.is_some());
    assert_eq!(restored.state.base_unread, None);
}

/// After a restore, at a loss, the app takes the listed certificate from its entry at the
/// next service; the commit that keeps the registration signed again then fails. The next
/// read sends the registration under the certificate taken, not the bytes kept before.
#[tokio::test]
async fn test_loss_after_a_restore_sends_the_registration_for_the_record_taken() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::new(MemoryStore::new()),
        w.protocol.clone(),
        &[Permission::ReplyAdd],
    )
    .await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let backup = app.backup().await.unwrap();
    let old = app.cert().clone();
    let renewed = renew_listed(&w, me, &old);
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        app.receive(None).await.unwrap();
    }
    let theirs = app.record().clone();
    drop(app);
    w.clock.advance_ms(60_000);
    let n_key = next_key();
    let next = ScriptedDispatch::recovering(&w.alice, n_key.to_bytes(), Arc::clone(&w.clock), 2, 1)
        .unwrap();
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    w.dispatch.lock().not_hosted_unpinned = true;
    next.app_op(&app_keys("wallet"), OpKind::AppPut { record: theirs })
        .unwrap();
    let store = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        StoreFault::None,
    ));
    let mut restored = App::restore(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.refresh_identity().await.unwrap();
    // The loss starts; its read at the next service fails once.
    next.fail_next(Fault::Unreachable {
        path: "/directory".into(),
        after: 0,
    });
    restored.receive(None).await.unwrap_err();
    // The read takes the renewal; keeping the registration signed again fails.
    store.fail_put_once(crate::app::recovery::keys::LOSS.as_bytes());
    restored.receive(None).await.unwrap_err();
    // Signed again and kept, its send fails: the next try sends those bytes, not new ones.
    next.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    restored.receive(None).await.unwrap_err();
    let kept = restored.loss_record().await.unwrap().unwrap().batch;
    let mut again = kept.clone();
    assert!(!restored.read_before_registering(&mut again).await.unwrap());
    assert_eq!(again, kept);
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(restored.cert().hash(), renewed.hash());
    assert!(next.app(&me).receive_n.is_some());
}

/// After a restore, the move's read at the next service takes the listed certificate; the
/// commit that keeps the registration signed again fails. The next read sends the
/// registration for the record taken.
#[tokio::test]
async fn test_move_after_a_restore_sends_the_registration_for_the_record_taken() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::new(MemoryStore::new()),
        w.protocol.clone(),
        &[Permission::ReplyAdd],
    )
    .await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let backup = app.backup().await.unwrap();
    let old = app.cert().clone();
    let renewed = renew_listed(&w, me, &old);
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        app.receive(None).await.unwrap();
    }
    drop(app);
    w.clock.advance_ms(1_000);
    let n_key = next_key();
    w.dispatch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.dispatch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let store = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        StoreFault::None,
    ));
    let mut restored = App::restore(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.refresh_identity().await.unwrap();
    next.fail_next(Fault::Unreachable {
        path: "/directory".into(),
        after: 0,
    });
    restored.receive(None).await.unwrap_err();
    store.fail_put_once(crate::app::provider::keys::MOVE.as_bytes());
    restored.receive(None).await.unwrap_err();
    assert_eq!(restored.cert().hash(), renewed.hash());
    // The kept registration still carries the record from before the renewal: the read
    // before registering signs it again for the record held.
    let mut kept = restored
        .reader()
        .get::<crate::app::provider::MoveRecord>(crate::app::provider::keys::MOVE)
        .await
        .unwrap()
        .unwrap()
        .batch;
    assert!(restored.read_before_registering(&mut kept).await.unwrap());
    for _ in 0..3 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(restored.cursor().generation, 2);
    assert_eq!(restored.cert().hash(), renewed.hash());
}
