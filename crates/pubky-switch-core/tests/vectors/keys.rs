//! The identities, apps and service keys of keys.json (Switch wire 1.3, 1.5, 3).

use pubky_switch_core::enc::{self, app_id, app_id_bytes, b64, kid, lp, pubky_id};
use pubky_switch_core::{ident, keys as k, labels, sig};
use serde_json::json;

use crate::common::*;

/// Rebuild every key from its seed and check the relationships between the keys.
#[test]
pub(super) fn test_vectors_keys() {
    let v = load("keys.json");
    let keys = keys();
    let emit = |base: &str, members: &[(&str, serde_json::Value)]| {
        generated_members("keys.json", base, members)
    };
    for (index, i) in arr(&v, "identities").iter().enumerate() {
        let secret = seed(st(i, "seed_label"));
        let identity = k::IdentityKey::from_secret(secret);
        let public = keys.identity(st(i, "name"));
        assert_eq!(identity.public(), public);
        let root = ident::switch_root(&secret);
        assert_eq!(identity.switch_root(), root);
        let backup = identity.backup_secret();
        assert_eq!(
            backup,
            clamp(enc::derive(labels::derive::BACKUP_KEY, &[&secret]))
        );
        assert_ne!(backup, root);
        emit(
            &format!("/identities/{index}"),
            &[
                ("secret_hex", json!(hex::encode(secret))),
                ("public_hex", json!(hex::encode(public))),
                ("pubky_id", json!(pubky_id(&public))),
                ("switch_root_hex", json!(hex::encode(root))),
                ("naming_key", json!(b64(&identity.naming_key().to_bytes()))),
                ("backup_secret_hex", json!(hex::encode(backup))),
                ("backup_public", json!(b64(&identity.backup_public()))),
                ("backup_kid", json!(b64(&kid(&identity.backup_public())))),
            ],
        );
    }
    let mut scoped = Vec::new();
    for (index, c) in arr(&v, "scope_keys").iter().enumerate() {
        let owner = st(c, "identity");
        let public = keys.identity(owner);
        let identity = k::IdentityKey::from_secret(keys.identity_secrets[&public]);
        let root = identity.switch_root();
        let (epoch, scope) = (int(c, "data_epoch"), st(c, "scope"));
        let key = ident::scope_key(&root, epoch, scope);
        assert_eq!(identity.scope_key(epoch, scope), key);
        emit(
            &format!("/scope_keys/{index}"),
            &[
                (
                    "key_material_hex",
                    json!(hex::encode(lp(&[
                        &root,
                        &epoch.to_be_bytes(),
                        scope.as_bytes()
                    ]))),
                ),
                ("key", json!(b64(&key))),
            ],
        );
        scoped.push(((owner, epoch, scope), key));
    }
    for (i, (a, key)) in scoped.iter().enumerate() {
        for (b, other) in &scoped[i + 1..] {
            if a != b {
                assert_ne!(key, other, "{a:?} and {b:?} share a key");
            }
        }
    }
    let subs = arr(&v["sub_scope_keys"], "keys");
    assert_eq!(subs.len(), 2);
    for (index, c) in subs.iter().enumerate() {
        let public = keys.identity(st(c, "identity"));
        let identity = k::IdentityKey::from_secret(keys.identity_secrets[&public]);
        let root = identity.switch_root();
        let (epoch, parent, sub) = (int(c, "data_epoch"), st(c, "parent"), st(c, "sub"));
        let scope = format!("{parent}:{sub}");
        let parent_key = ident::scope_key(&root, epoch, parent);
        let key = ident::sub_scope_key(&parent_key, sub);
        emit(
            &format!("/sub_scope_keys/keys/{index}"),
            &[
                ("scope", json!(scope)),
                ("parent_key", json!(b64(&parent_key))),
                (
                    "key_material_hex",
                    json!(hex::encode(lp(&[&parent_key, sub.as_bytes()]))),
                ),
                ("key", json!(b64(&key))),
            ],
        );
        assert_eq!(ident::key_of_scope(&root, epoch, &scope), key);
        assert_eq!(identity.scope_key(epoch, &scope), key);
        let held = k::ScopeKeys::derive_range(&identity, &[parent.to_owned()], epoch, epoch);
        assert_eq!(held.get(epoch, &scope), Some(key));
        let only_sub = k::ScopeKeys::derive_range(&identity, &[scope], epoch, epoch);
        assert_eq!(only_sub.get(epoch, parent), None);
        assert_ne!(key, parent_key);
        assert_ne!(key, ident::sub_scope_key(&parent_key, "another-sub"));
    }
    let service_key = |base: &str, s: &serde_json::Value| {
        let secret = seed(st(s, "seed_label"));
        let public = sig::public_of(&secret);
        emit(
            base,
            &[
                ("account", json!(pubky_id(&keys.identity(service_owner(s))))),
                ("secret_hex", json!(hex::encode(secret))),
                ("public", json!(b64(&public))),
            ],
        );
        public
    };
    let next = service_key("/next_service_key", &v["next_service_key"]);
    for (index, s) in arr(&v, "service_keys").iter().enumerate() {
        assert_ne!(
            next,
            service_key(&format!("/service_keys/{index}"), s),
            "the next service's key is its own"
        );
    }
    for (index, a) in arr(&v, "apps").iter().enumerate() {
        let app = keys.app(st(a, "name"));
        let public = sig::public_of(&app.signing_secret);
        assert_eq!(app.signing_public, public);
        assert_eq!(app.app_id, app_id(&public));
        assert_eq!(app.bundle_secret, clamp(seed(st(a, "bundle_seed_label"))));
        assert!(!enc::x25519_low_order(&app.receive_public));
        emit(
            &format!("/apps/{index}"),
            &[
                ("identity", json!(pubky_id(&app.identity))),
                ("signing_secret_hex", json!(hex::encode(app.signing_secret))),
                ("signing_public", json!(b64(&public))),
                (
                    "app_id_bytes_hex",
                    json!(hex::encode(app_id_bytes(&public))),
                ),
                ("app_id", json!(app.app_id)),
                ("bundle_secret_hex", json!(hex::encode(app.bundle_secret))),
                ("bundle_public", json!(b64(&app.bundle_public))),
                ("bundle_kid", json!(b64(&kid(&app.bundle_public)))),
            ],
        );
        emit(
            &format!("/apps/{index}/receive_key"),
            &[
                ("secret_hex", json!(hex::encode(app.receive_secret))),
                ("public", json!(b64(&app.receive_public))),
                ("kid", json!(b64(&app.receive_kid))),
            ],
        );
    }
    let secret = seed(st(&v["removed_app"], "signing_seed_label"));
    let public = sig::public_of(&secret);
    emit("/removed_app", &[("app_id", json!(app_id(&public)))]);
}
