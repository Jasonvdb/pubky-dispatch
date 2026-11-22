//! Join a wallet on a retained store so it can be reopened after provider loss.

use super::*;
use crate::parties::{Asking, notes_protocol};
use pubky_switch_client::app::{AppConfig, AppEnv};
use pubky_switch_client::testing::TestIdentity;

pub(in crate::flows) fn app_env(world: &World, store: Arc<MemoryStore>) -> AppEnv {
    world.app_env(store)
}

pub(in crate::flows) async fn join_member(
    world: &World,
    owner: &TestIdentity,
    signer: &mut Signer,
    name: &str,
    store: Arc<MemoryStore>,
) -> Result<App, Box<dyn std::error::Error>> {
    let asking = Asking::new(world.app_keys(owner, name)?)?;
    let review = signer.review(asking.request.signed(), &asking.auth)?;
    let approved = Box::pin(signer.approve(review)).await?;
    signer.claim_delivered(&approved.request).await?;
    world.advance_ms(STEP_MS);
    let app = Box::pin(App::join(
        app_env(world, store),
        notes_protocol(),
        AppConfig::default(),
        asking.join_request(owner.public(), &approved)?,
    ))
    .await?;
    Ok(app)
}
