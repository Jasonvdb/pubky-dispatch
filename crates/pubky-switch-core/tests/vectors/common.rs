//! Helpers shared by the vector tests.

#![allow(dead_code)]

use std::collections::HashMap;

use pubky_switch_core::enc::{pubky_key, unb64, unb64_array};
use pubky_switch_core::{enc, ident, keys as k, labels, sig};
use serde_json::Value;

pub use super::generation::{Place, generated, generated_members, load};

/// The README's seed convention under the core's versioned label prefix.
pub fn seed_prefix() -> &'static str {
    static PREFIX: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| format!("{}test-vectors/", labels::PREFIX));
    &PREFIX
}

#[test]
fn test_vectors_readme_seed_prefix() {
    let readme = std::fs::read_to_string(pubky_switch_core::spec_vectors_dir().join("README.md"))
        .expect("vector README");
    let rule = readme
        .lines()
        .find(|line| line.starts_with("- **Seeds.** "))
        .expect("the README has a Seeds rule");
    let formula = format!("BLAKE3(\"{}\" + label)", seed_prefix());
    assert_eq!(rule.split('`').nth(1), Some(formula.as_str()), "{rule}");
}

/// A vector seed: `BLAKE3(prefix + label)` (README "Seeds").
pub fn seed(label: &str) -> [u8; 32] {
    *blake3::hash(format!("{}{label}", seed_prefix()).as_bytes()).as_bytes()
}

/// A UUID v4 from the first 16 bytes of a vector seed.
pub fn uuid_from_seed(label: &str) -> String {
    let mut bytes = seed(label);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(&bytes[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// RFC 7748 clamping, as the README applies to X25519 secrets.
pub fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

pub fn hx(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

pub fn hx32(text: &str) -> [u8; 32] {
    hx(text).try_into().expect("32 bytes")
}

pub fn b64(text: &str) -> Vec<u8> {
    unb64(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

pub fn b64n<const N: usize>(text: &str) -> [u8; N] {
    unb64_array::<N>(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

pub fn pubky(id: &str) -> [u8; 32] {
    pubky_key(id).unwrap_or_else(|e| panic!("{id}: {e}"))
}

pub fn st<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} isn't a string in {v}"))
}

pub fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array()
        .unwrap_or_else(|| panic!("{k} isn't an array in {v}"))
}

pub fn int(v: &Value, k: &str) -> u64 {
    v[k].as_u64()
        .unwrap_or_else(|| panic!("{k} isn't an integer in {v}"))
}

pub fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("an array")
        .iter()
        .map(|x| x.as_str().expect("a string").to_owned())
        .collect()
}

/// One app of `keys.json`.
#[derive(Clone, Debug)]
pub struct AppKeys {
    pub name: String,
    pub identity: [u8; 32],
    pub app_id: String,
    pub signing_public: [u8; 32],
    pub signing_secret: [u8; 32],
    pub bundle_public: [u8; 32],
    pub bundle_secret: [u8; 32],
    pub receive_public: [u8; 32],
    pub receive_secret: [u8; 32],
    pub receive_kid: [u8; 8],
    pub scopes: Vec<String>,
    pub permissions: Vec<String>,
}

/// The fixed keys of `keys.json`.
pub struct Keys {
    pub apps: Vec<AppKeys>,
    /// Ed25519 public key to its secret, for every identity, app and service key.
    pub secrets: HashMap<[u8; 32], [u8; 32]>,
    /// Account (Pubky ID) to its service key at the service its `identity.json` names.
    pub service: HashMap<String, [u8; 32]>,
    /// The next service's public key for Alice's move.
    pub next_service_key: [u8; 32],
    /// Identity name (`alice`, `bob`) to its public key.
    pub identities: HashMap<String, [u8; 32]>,
    /// Identity public key to its secret.
    pub identity_secrets: HashMap<[u8; 32], [u8; 32]>,
}

impl Keys {
    pub fn app(&self, name: &str) -> &AppKeys {
        self.apps
            .iter()
            .find(|a| a.name == name)
            .unwrap_or_else(|| panic!("no app {name}"))
    }

    pub fn app_by_id(&self, id: &str) -> &AppKeys {
        self.apps
            .iter()
            .find(|a| a.app_id == id)
            .unwrap_or_else(|| panic!("no app {id}"))
    }

    pub fn identity(&self, name: &str) -> [u8; 32] {
        self.identities[name]
    }

    pub fn secret(&self, public: &[u8; 32]) -> Option<[u8; 32]> {
        self.secrets.get(public).copied()
    }

    pub fn root(&self, identity: &[u8; 32]) -> [u8; 32] {
        ident::switch_root(&self.identity_secrets[identity])
    }

    pub fn naming(&self, identity: &[u8; 32]) -> ident::NamingKey {
        ident::NamingKey::from_root(&self.root(identity))
    }

    pub fn service_key(&self, account: &str) -> [u8; 32] {
        self.service[account]
    }
}

/// The named account in a service seed label of the form service/account[/next].
pub fn service_owner(case: &Value) -> &str {
    st(case, "seed_label")
        .split('/')
        .nth(1)
        .expect("service account")
}

/// Derive the shared keys from the fixture's seed labels.
pub fn keys() -> Keys {
    let k = load("keys.json");
    let mut secrets = HashMap::new();
    let mut identities = HashMap::new();
    let mut identity_secrets = HashMap::new();
    for i in arr(&k, "identities") {
        let secret = seed(st(i, "seed_label"));
        let public = sig::public_of(&secret);
        secrets.insert(public, secret);
        identity_secrets.insert(public, secret);
        identities.insert(st(i, "name").to_owned(), public);
    }
    let next = &k["next_service_key"];
    let next_secret = seed(st(next, "seed_label"));
    let next_service_key = sig::public_of(&next_secret);
    secrets.insert(next_service_key, next_secret);
    let mut service = HashMap::new();
    for s in arr(&k, "service_keys") {
        let secret = seed(st(s, "seed_label"));
        let public = sig::public_of(&secret);
        secrets.insert(public, secret);
        service.insert(enc::pubky_id(&identities[service_owner(s)]), public);
    }
    let apps = arr(&k, "apps")
        .iter()
        .map(|a| {
            let r = &a["receive_key"];
            let signing_secret = seed(st(a, "signing_seed_label"));
            let bundle_label = st(a, "bundle_seed_label");
            let (owner, _) = bundle_label.split_once('/').expect("account/app/bundle");
            let app = k::AppKeys::from_secrets(signing_secret, seed(bundle_label));
            let receive = k::ReceiveKey::from_secret(int(r, "n"), seed(st(r, "seed_label")));
            let app = AppKeys {
                name: st(a, "name").to_owned(),
                identity: identities[owner],
                app_id: app.app_id(),
                signing_public: app.signing_public(),
                signing_secret,
                bundle_public: app.bundle_public(),
                bundle_secret: app.bundle_secret(),
                receive_public: receive.public,
                receive_secret: receive.secret(),
                receive_kid: receive.kid,
                scopes: strings(&a["scopes"]),
                permissions: strings(&a["permissions"]),
            };
            secrets.insert(app.signing_public, app.signing_secret);
            app
        })
        .collect();
    Keys {
        apps,
        secrets,
        service,
        next_service_key,
        identities,
        identity_secrets,
    }
}

/// Sign again from the seed and compare: Ed25519 signing is deterministic.
pub fn reproduce(
    keys: &Keys,
    public: &[u8; 32],
    label: &str,
    fields: &[&[u8]],
    signature: &[u8; 64],
) -> bool {
    match keys.secret(public) {
        Some(secret) => {
            let key = ed25519_dalek::SigningKey::from_bytes(&secret);
            assert_eq!(
                &sig::sign(&key, label, fields),
                signature,
                "{label}: signature not reproduced from the seed"
            );
            true
        }
        None => false,
    }
}

/// The scopes the vectors give keys, which is a protocol's choice (Switch spec 3.5), read
/// from the vector files: the scopes of `keys.json`'s scope keys and sub-scope keys, of the
/// honest key bundles of `envelopes.json`, and the scope its reduction removes as one with
/// keys.
pub fn keyed_scopes() -> std::collections::BTreeSet<String> {
    let k = load("keys.json");
    let e = load("envelopes.json");
    let mut keyed = std::collections::BTreeSet::new();
    for entry in arr(&k, "scope_keys")
        .iter()
        .chain(arr(&k["sub_scope_keys"], "keys"))
    {
        keyed.insert(st(entry, "scope").to_owned());
    }
    for member in ["key_bundle", "reduction_key_bundle"] {
        let plaintext: Value = serde_json::from_str(st(&e[member], "plaintext_json")).unwrap();
        for key in arr(&plaintext, "keys") {
            keyed.insert(st(key, "scope").to_owned());
        }
    }
    keyed.insert(st(&e["reduction_key_bundle"], "removed_scope").to_owned());
    keyed
}

/// A document of `documents.json` by name, in its carrying form.
pub fn document(name: &str) -> sig::SignedDoc {
    let v = load("documents.json");
    let entry = arr(&v, "documents")
        .iter()
        .find(|d| st(d, "name") == name)
        .unwrap_or_else(|| panic!("no document {name}"));
    serde_json::from_value(entry["signed"].clone()).unwrap()
}

/// Fixed sealing randomness from its three values.
pub fn fixed(
    cek_hex: &str,
    nonce_hex: &str,
    ikm_e_hex: &str,
) -> pubky_switch_core::envelope::FixedRandomness {
    pubky_switch_core::envelope::FixedRandomness {
        content_key: hx32(cek_hex),
        nonce: hx(nonce_hex).try_into().expect("24 bytes"),
        ikm_e: hx32(ikm_e_hex),
    }
}

/// Fixed sealing randomness from the seeds `<label>/cek`, `<label>/nonce` (its first 24
/// bytes) and `<label>/ikm-e` (README "Seeds").
pub fn fixed_from_seeds(label: &str) -> pubky_switch_core::envelope::FixedRandomness {
    pubky_switch_core::envelope::FixedRandomness {
        content_key: seed(&format!("{label}/cek")),
        nonce: seed(&format!("{label}/nonce"))[..24].try_into().unwrap(),
        ikm_e: seed(&format!("{label}/ikm-e")),
    }
}

/// Keep the fixture author's explanation alongside each generated rejection.
pub fn with_published_rules(mut cases: Vec<Value>, published: &Value) -> Vec<Value> {
    if let Some(entries) = published.as_array() {
        for case in &mut cases {
            let original = entries.iter().find(|entry| entry["name"] == case["name"]);
            if let Some(rule) = original.and_then(|entry| entry.get("rule")) {
                case["rule"] = rule.as_str().expect("rule must be a string").into();
            }
        }
    }
    cases
}

/// A refusal's reason as the files quote it: without the section it starts with (README
/// "Rejections").
pub fn quoted(reason: &str) -> String {
    match reason.split_once(": ") {
        Some((section, rest)) if section.starts_with("Switch ") => rest.to_owned(),
        _ => reason.to_owned(),
    }
}
