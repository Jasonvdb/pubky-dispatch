//! Helpers shared by the vector tests.

#![allow(dead_code)]

use std::collections::HashMap;

use pubky_switch_core::enc::{pubky_key, unb64, unb64_array};
use pubky_switch_core::{enc, ident, keys as k, sig};
use serde_json::Value;

pub use super::generation::{Place, generated, generated_members, load};

/// The README's seed convention under the core's versioned label prefix.
pub fn seed_prefix() -> &'static str {
    static PREFIX: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let path = format!(
            "{}/../../spec/vectors/README.md",
            env!("CARGO_MANIFEST_DIR")
        );
        let readme = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let rule = readme
            .lines()
            .find(|line| line.starts_with("- **Seeds.** "))
            .expect("the README has a Seeds rule");
        let (_, formula) = rule
            .split_once("BLAKE3(\"")
            .expect("BLAKE3 in the Seeds rule");
        let (prefix, _) = formula.split_once('"').expect("the seed prefix");
        assert!(
            prefix.starts_with(pubky_switch_core::labels::PREFIX),
            "seed prefix {prefix}"
        );
        prefix.to_owned()
    });
    &PREFIX
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
    secrets.insert(sig::public_of(&next_secret), next_secret);
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
        identities,
        identity_secrets,
    }
}

/// A named app and its published key material in keys.json.
pub fn app_entry<'a>(keys: &'a Value, name: &str) -> &'a Value {
    arr(keys, "apps")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no app {name}"))
}

/// Read the key material carried by keys.json for a dependent fixture.
pub fn carried_keys() -> Keys {
    let file = load("keys.json");
    let mut keys = Keys {
        apps: Vec::new(),
        secrets: HashMap::new(),
        service: HashMap::new(),
        identities: HashMap::new(),
        identity_secrets: HashMap::new(),
    };
    for c in arr(&file, "identities") {
        let public = hx32(st(c, "public_hex"));
        let secret = hx32(st(c, "secret_hex"));
        keys.identities.insert(st(c, "name").into(), public);
        keys.identity_secrets.insert(public, secret);
        keys.secrets.insert(public, secret);
    }
    for c in arr(&file, "service_keys") {
        let public = b64n(st(c, "public"));
        keys.service.insert(st(c, "account").into(), public);
        keys.secrets.insert(public, hx32(st(c, "secret_hex")));
    }
    let next = &file["next_service_key"];
    keys.secrets
        .insert(b64n(st(next, "public")), hx32(st(next, "secret_hex")));
    for c in arr(&file, "apps") {
        let receive = &c["receive_key"];
        let app = AppKeys {
            name: st(c, "name").into(),
            identity: pubky(st(c, "identity")),
            app_id: st(c, "app_id").into(),
            signing_public: b64n(st(c, "signing_public")),
            signing_secret: hx32(st(c, "signing_secret_hex")),
            bundle_public: b64n(st(c, "bundle_public")),
            bundle_secret: hx32(st(c, "bundle_secret_hex")),
            receive_public: b64n(st(receive, "public")),
            receive_secret: hx32(st(receive, "secret_hex")),
            receive_kid: b64n(st(receive, "kid")),
            scopes: strings(&c["scopes"]),
            permissions: strings(&c["permissions"]),
        };
        keys.secrets.insert(app.signing_public, app.signing_secret);
        keys.apps.push(app);
    }
    keys
}

/// The first sixteen bytes of the named seed, for nonces and install IDs.
pub fn seed16(case: &Value, member: &str) -> [u8; 16] {
    seed(st(case, member))[..16].try_into().unwrap()
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

/// The scopes for which this fixture gives the app a key at each epoch.
pub fn keyed_scopes(input: &Value) -> std::collections::BTreeSet<String> {
    strings(&input["keyed_scopes"]).into_iter().collect()
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

/// Assemble a bundle with the naming key and published scope keys of its account.
/// Epochs and scopes without a key example use the account's Switch root.
pub fn bundle_contents(
    cert: &pubky_switch_core::records::AppCert,
    first: u64,
    last: u64,
    has_keys: &dyn Fn(&str) -> bool,
) -> pubky_switch_core::records::KeyBundleContents {
    use pubky_switch_core::records::{KeyBundleContents, keyed_scopes as certificate_scopes};
    let file = load("keys.json");
    let public = hex::encode(cert.identity());
    let account = arr(&file, "identities")
        .iter()
        .find(|c| c["public_hex"] == public)
        .unwrap();
    let root = hx32(st(account, "switch_root_hex"));
    let scopes = certificate_scopes(cert, has_keys);
    let mut keys = k::ScopeKeys::default();
    for data_epoch in first..=last {
        for &scope in &scopes {
            let key = arr(&file, "scope_keys")
                .iter()
                .chain(arr(&file["sub_scope_keys"], "keys"))
                .find(|r| {
                    r["identity"] == account["name"]
                        && r["scope"] == scope
                        && r["data_epoch"] == data_epoch
                })
                .map_or_else(
                    || ident::key_of_scope(&root, data_epoch, scope),
                    |r| b64n(st(r, "key")),
                );
            keys.keys.push(k::ScopeKey {
                data_epoch,
                scope: scope.into(),
                key,
            });
        }
    }
    KeyBundleContents {
        naming_key: ident::NamingKey::from_bytes(b64n(st(account, "naming_key"))),
        cert: cert.hash(),
        first_epoch: first,
        last_epoch: last,
        keys,
    }
}
