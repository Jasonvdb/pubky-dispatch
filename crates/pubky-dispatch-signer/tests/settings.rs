//! The signer's settings: the record age limit and the connect request settings (Dispatch spec 4.3).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use pubky_dispatch_core::json::MAX_INT;
use pubky_dispatch_core::records::ConnectRequests;
use pubky_dispatch_signer::{Signer, SignerError};

/// What a refused setting must leave: the same newest version here and at the Dispatch, and
/// nothing sent.
fn unchanged(world: &World, signer: &Signer, version: u64, sent: usize) {
    let newest = signer.identity_doc().unwrap().unwrap();
    assert_eq!(newest.version(), version);
    assert_eq!(world.dispatch.identity_doc().unwrap().version(), version);
    assert_eq!(world.sent_docs().len(), sent);
}

#[tokio::test]
async fn test_settings_record_age_above_the_json_integers_signs_nothing() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let sent = world.sent_docs().len();
    for refused in [MAX_INT + 1, u64::MAX] {
        let error = signer.set_record_max_age(Some(refused)).await.unwrap_err();
        assert!(matches!(error, SignerError::InvalidData(_)), "{error:?}");
        unchanged(&world, &signer, 1, sent);
    }
    for (version, seconds) in [(2, 1), (3, MAX_INT)] {
        let doc = signer.set_record_max_age(Some(seconds)).await.unwrap();
        assert_eq!(
            (doc.version(), doc.body().record_max_age),
            (version, Some(seconds))
        );
    }
}

#[tokio::test]
async fn test_settings_max_pending_above_the_json_integers_signs_nothing() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let sent = world.sent_docs().len();
    let settings = |max_pending| ConnectRequests {
        enabled: true,
        max_pending,
        push: false,
    };
    for refused in [MAX_INT + 1, u64::MAX] {
        let error = signer
            .set_connect_requests(settings(refused))
            .await
            .unwrap_err();
        assert!(matches!(error, SignerError::InvalidData(_)), "{error:?}");
        unchanged(&world, &signer, 1, sent);
    }
    for (version, max_pending) in [(2, 0), (3, MAX_INT)] {
        let doc = signer
            .set_connect_requests(settings(max_pending))
            .await
            .unwrap();
        assert_eq!(doc.version(), version);
        assert_eq!(doc.body().policy.connect_requests.max_pending, max_pending);
    }
}
