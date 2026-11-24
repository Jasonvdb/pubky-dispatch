//! An app's push registration, and its end with the app (Dispatch spec 9, Dispatch wire 8.1).

use pubky_dispatch::store::PUSH_PER_HOST;
use pubky_dispatch_client::TransportError;
use pubky_dispatch_client::app::{
    AppError, LeaveMode, MAX_HANDLES, PushHandles, PushRegistration, PushRelay,
};
use pubky_dispatch_client::transport::BoxFuture;
use pubky_dispatch_core::http::ErrorCode;
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::app_status;
use super::messaging::joined;
use super::removal::result;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

// The flow fills one relay host to the service's per-host limit from one registration, so
// the client's per-registration limit must be the same number (Dispatch wire 8.1).
const _: () = assert!(MAX_HANDLES == PUSH_PER_HOST);

/// The relay every app of the flow registers at: one relay host.
const RELAY_URL: &str = "https://push.example/v1/hook";

/// A relay that binds each device token to a handle of its own, the same for the same
/// token, whatever push key it is bound to (Dispatch spec 9 step 2, Dispatch wire 8.3).
struct Relay;

impl PushRelay for Relay {
    fn register(
        &self,
        _relay_url: String,
        device_token: String,
        _push_key: [u8; 32],
    ) -> BoxFuture<'_, Result<String, TransportError>> {
        Box::pin(async move { Ok(format!("{device_token} at the relay")) })
    }
}

/// What a registration call ended with, for the trace: the handles the Dispatch keeps, or the
/// error.
fn registered(registration: &Result<PushRegistration, AppError>) -> Value {
    match registration {
        Ok(registration) => json!({ "ok": true, "handles": registration.handles }),
        Err(_) => result(registration),
    }
}

/// An app registers for pushes, and the registration goes when the app leaves (Dispatch wire
/// 8.1: "removed when the app stops being current"). alice's phone registers its handle at
/// a relay. Her wallet registers its own there, then sets the handles of its seven other
/// devices too: eight of its own and the phone's one would be more than an entry sends
/// toward one relay host (Dispatch wire 8.2), so the Dispatch refuses the list. The phone
/// leaves, and its registration with it: the wallet's eight are then taken.
///
/// Calls: `PUT /v1/{id}/push`, a start that mints a push key, a start the Dispatch answers
/// with the registration it holds, the handles set, and a list refused with `400`.
///
/// # Errors
///
/// When a step that should succeed against any Dispatch fails, the wallet's list is taken
/// while the phone's registration holds, or refused once the phone left.
pub async fn push_registration(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    let phone_registered = phone.register_push(&Relay, RELAY_URL, "phone").await;
    world.outcome("the phone registered", &registered(&phone_registered));
    if phone_registered?.handles != 1 {
        return Err("the Dispatch keeps another number of the phone's handles".into());
    }
    world.advance_ms(STEP_MS);

    let first = wallet.register_push(&Relay, RELAY_URL, "wallet").await;
    world.outcome("the wallet registered", &registered(&first));
    let first = first?;
    world.advance_ms(STEP_MS);

    // The wallet's other devices, from its host's device sync, bound to the same push key.
    let others = (1..PUSH_PER_HOST)
        .map(|device| format!("wallet device {device} at the relay"))
        .collect();
    wallet
        .take_device_push_handles(PushHandles {
            push_key: first.push_key,
            handles: others,
        })
        .await?;
    let refused = wallet.register_push(&Relay, RELAY_URL, "wallet").await;
    world.outcome(
        "the wallet set eight handles beside the phone's",
        &registered(&refused),
    );
    match &refused {
        Err(error) if error.code() == Some(ErrorCode::BadRequest) => {}
        _ => return Err("nine handles at one relay host weren't refused".into()),
    }
    world.advance_ms(STEP_MS);

    let left = phone.leave(LeaveMode::TwoStep).await?;
    world.outcome("the phone left", &json!({ "report": format!("{left:?}") }));
    world.advance_ms(STEP_MS);

    let taken = wallet.register_push(&Relay, RELAY_URL, "wallet").await;
    world.outcome(
        "the wallet set eight handles after the phone left",
        &json!({
            "registration": registered(&taken),
            "same_push_key": taken.as_ref().is_ok_and(|now| now.push_key == first.push_key),
            "wallet": app_status(&mut wallet),
        }),
    );
    let taken = taken?;
    if usize::try_from(taken.handles) != Ok(PUSH_PER_HOST) || taken.push_key != first.push_key {
        return Err("the wallet's eight handles weren't taken under its push key".into());
    }
    world.advance_ms(STEP_MS);

    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Bytes, http::HeaderMap, routing::post};
    use pubky_dispatch_core::{
        enc::unb64_array,
        http::{header, verify_webhook},
        records::ConnectRequests,
    };
    use tokio::{net::TcpListener, sync::mpsc};

    use super::*;
    use crate::{Backend, run};

    async fn connect_wake(world: &World) -> FlowResult {
        let alice = world.identity("alice")?;
        let bob = world.identity("bob")?;
        world.add_dispatch(ORIGIN, &[&alice, &bob]).await?;
        let mut owner = enroll(world, &alice, ORIGIN).await?;
        let mut sender = enroll(world, &bob, ORIGIN).await?;
        let (mut wallet, _) = joined(world, &alice, &mut owner, "wallet").await?;
        let (mut shop, _) = joined(world, &bob, &mut sender, "shop").await?;
        owner
            .set_connect_requests(ConnectRequests {
                enabled: true,
                push: true,
                ..Default::default()
            })
            .await?;
        let registration = wallet.register_push(&Relay, RELAY_URL, "phone").await?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let delivery = world.push_service(ORIGIN, listener.local_addr()?)?;
        let (wakes, mut received) = mpsc::unbounded_channel();
        let relay = Router::new().route(
            "/v1/hook",
            post(move |headers: HeaderMap, body: Bytes| {
                let wakes = wakes.clone();
                async move {
                    let _ = wakes.send((headers, body));
                }
            }),
        );
        let serving = tokio::spawn(async move { axum::serve(listener, relay).await });

        assert!(shop.ask_to_connect(&alice.public()).await?);
        let sent = delivery.deliver_pushes().await;
        serving.abort();
        assert_eq!(sent.delivered, 1);
        let (headers, body) = received.try_recv()?;
        let signature = unb64_array(headers[header::SIGNATURE].to_str()?)?;
        verify_webhook(&registration.push_key, RELAY_URL, &body, &signature)?;
        let hook: Value = serde_json::from_slice(&body)?;
        assert_eq!(hook.as_object().map(|v| v.len()), Some(4));
        assert_eq!(hook["v"], 1);
        assert_eq!(hook["handle"], "phone at the relay");
        assert_eq!(
            hook["ts"],
            pubky_dispatch_core::time::rfc3339(world.now_ms())
        );
        unb64_array::<16>(hook["nonce"].as_str().ok_or("nonce")?)?;
        let list = wallet.connect_requests().await?;
        assert_eq!(list.requests.len(), 1);
        assert_eq!(list.requests[0].pubky, bob.public());
        Ok(())
    }

    #[tokio::test]
    async fn test_connect_push_wakes_registered_app() -> FlowResult {
        Box::pin(run(Backend::Service, connect_wake)).await?;
        Ok(())
    }
}
