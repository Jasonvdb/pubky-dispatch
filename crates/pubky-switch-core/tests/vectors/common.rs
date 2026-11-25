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
    // The client's and the service's vector tests read the prefix from this rule.
    let rule_formula = format!("BLAKE3(\"{}\" + label)", seed_prefix());
    assert_eq!(
        rule.split('`').nth(1),
        Some(rule_formula.as_str()),
        "{rule}"
    );
    let keys = load("keys.json");
    let formula = format!("BLAKE3(\"{}\" + seed label)", seed_prefix());
    assert!(st(&keys, "description").contains(&formula), "{formula}");
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
    pub receive_n: u64,
    pub receive_kid: [u8; 8],
    pub scopes: Vec<String>,
    pub permissions: Vec<String>,
}

/// The fixed keys of `keys.json`.
pub struct Keys {
    pub claims: std::cell::LazyCell<ClaimKeys>,
    pub http_signers: std::cell::LazyCell<HttpSigners>,
    pub apps: Vec<AppKeys>,
    /// Ed25519 public key to its secret, for every identity, app and service key.
    pub secrets: HashMap<[u8; 32], [u8; 32]>,
    /// Account (Pubky ID) to its service key at the service its `identity.json` names.
    pub service: HashMap<String, [u8; 32]>,
    /// The next service's public key for Alice's move.
    pub next_service_key: [u8; 32],
    /// App ID derived from the removed app's signing seed.
    pub removed_app: [u8; 16],
    /// Identity name (`alice`, `bob`) to its public key.
    pub identities: HashMap<String, [u8; 32]>,
    /// Identity public key to its secret.
    pub identity_secrets: HashMap<[u8; 32], [u8; 32]>,
}

/// Keys of the separate account on which the two claim scripts run.
pub struct ClaimKeys {
    pub identity: k::IdentityKey,
    pub apps: HashMap<String, (k::AppKeys, k::ReceiveKey)>,
}

fn claim_keys() -> ClaimKeys {
    let file = load("claims.json");
    let apps = file["apps"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, input)| {
            let app = k::AppKeys::from_secrets(
                seed(st(input, "signing_seed_label")),
                seed(st(input, "bundle_seed_label")),
            );
            let receive = k::ReceiveKey::from_secret(
                int(input, "receive_n"),
                seed(st(input, "receive_seed_label")),
            );
            (name.clone(), (app, receive))
        })
        .collect();
    ClaimKeys {
        identity: k::IdentityKey::from_secret(seed(st(&file, "identity_seed_label"))),
        apps,
    }
}

/// Public keys for the pending service and the independently seeded peer-list example.
pub struct HttpSigners {
    pub services: HashMap<String, [u8; 32]>,
    pub peers: HashMap<String, [u8; 32]>,
}

fn http_signers() -> HttpSigners {
    let file = load("http.json");
    let mut services = HashMap::new();
    let mut peers = HashMap::new();
    for request in arr(&file, "requests") {
        if let Some(label) = request.get("service_seed_label") {
            let label = label.as_str().unwrap();
            services.insert(label.to_owned(), sig::public_of(&seed(label)));
        }
    }
    for case in arr(&file, "responses")
        .iter()
        .filter(|c| c["answer"] == "peers")
    {
        for peer in arr(case, "peers") {
            if let Some(label) = peer.get("identity_seed_label") {
                let label = label.as_str().unwrap();
                // The README's original peer uses the unversioned test namespace.
                let namespace = labels::PREFIX.split_once('/').unwrap().0;
                let secret = enc::hash(format!("{namespace}/test/{label}").as_bytes());
                peers.insert(label.to_owned(), sig::public_of(&secret));
            }
        }
    }
    HttpSigners { services, peers }
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

    pub fn identity_key(&self, public: &[u8; 32]) -> k::IdentityKey {
        k::IdentityKey::from_secret(self.identity_secrets[public])
    }

    pub fn root(&self, identity: &[u8; 32]) -> [u8; 32] {
        self.identity_key(identity).switch_root()
    }

    pub fn naming(&self, identity: &[u8; 32]) -> ident::NamingKey {
        self.identity_key(identity).naming_key()
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
                receive_n: receive.n,
                receive_kid: receive.kid,
                scopes: strings(&a["scopes"]),
                permissions: strings(&a["permissions"]),
            };
            secrets.insert(app.signing_public, app.signing_secret);
            app
        })
        .collect();
    Keys {
        claims: std::cell::LazyCell::new(claim_keys),
        http_signers: std::cell::LazyCell::new(http_signers),
        apps,
        secrets,
        service,
        next_service_key,
        removed_app: enc::app_id_bytes(&sig::public_of(&seed(st(
            &k["removed_app"],
            "signing_seed_label",
        )))),
        identities,
        identity_secrets,
    }
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

pub const SEAL_SEED_SUFFIXES: [&str; 3] = ["cek", "nonce", "ikm-e"];

pub fn seal_seed_labels(label: &str) -> [String; 3] {
    SEAL_SEED_SUFFIXES.map(|suffix| format!("{label}/{suffix}"))
}

/// Fixed sealing randomness from the seeds `<label>/cek`, `<label>/nonce` (its first 24
/// bytes) and `<label>/ikm-e` (README "Seeds").
pub fn fixed_from_seeds(label: &str) -> pubky_switch_core::envelope::FixedRandomness {
    let [cek, nonce, ikm_e] = seal_seed_labels(label);
    pubky_switch_core::envelope::FixedRandomness {
        content_key: seed(&cek),
        nonce: seed(&nonce)[..24].try_into().unwrap(),
        ikm_e: seed(&ikm_e),
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

/// The chosen service timestamp, in Unix milliseconds.
pub fn time_of(case: &Value, member: &str) -> u64 {
    pubky_switch_core::time::parse_rfc3339(st(case, member)).unwrap()
}

/// The service that signed this identity's chain and export.
pub fn service_signer(keys: &Keys, identity: &[u8; 32]) -> ed25519_dalek::SigningKey {
    let public = keys.service_key(&enc::pubky_id(identity));
    ed25519_dalek::SigningKey::from_bytes(&keys.secret(&public).unwrap())
}

/// The collection ID, record key and blinded inputs for a named record of identifiers.json.
pub fn record_address(
    keys: &Keys,
    identity: &[u8; 32],
    name: &str,
    natural_key: &[u8],
    policy: &ident::Policy,
) -> ([u8; 32], [u8; 32], pubky_switch_core::ops::IdInputs) {
    let file = load("identifiers.json");
    let c = arr(&file, "record_keys")
        .iter()
        .find(|c| c["name"] == name)
        .expect(name);
    let collection = st(c, "collection");
    let blinded_key = keys.naming(identity).blind(natural_key);
    (
        ident::collection_id(collection, identity),
        ident::record_key_from_blinded(collection, &blinded_key, &policy.hash().unwrap()),
        pubky_switch_core::ops::IdInputs {
            collection: collection.into(),
            blinded_key,
        },
    )
}
