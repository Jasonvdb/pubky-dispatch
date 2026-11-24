//! Verification and explicit regeneration of the core's vector cases.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use pubky_switch_core::spec_vectors_dir;
use serde_json::Value;

thread_local! {
    // A file as a test changed it in memory, read in place of the published one.
    static CHANGED: RefCell<BTreeMap<String, Value>> = const { RefCell::new(BTreeMap::new()) };
    static PLACES: RefCell<Option<BTreeSet<(String, String)>>> = const { RefCell::new(None) };
    // Only the generator sees pending changes. Other tests read the published files.
    static STAGED: RefCell<Option<BTreeMap<String, Value>>> = const { RefCell::new(None) };
}

/// A parsed vector file, including any cases already generated on this thread.
pub fn load(name: &str) -> Value {
    if let Some(value) = CHANGED.with_borrow(|files| files.get(name).cloned()) {
        return value;
    }
    if let Some(value) = staged(name) {
        return value;
    }
    let path = spec_vectors_dir().join(name);
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn staged(name: &str) -> Option<Value> {
    STAGED.with_borrow(|files| files.as_ref()?.get(name).cloned())
}

/// Where a case that `pubky-switch-core` generated lies in its vector file (README "How the
/// files were generated"), as a JSON pointer.
#[derive(Clone, Copy, Debug)]
pub enum Place<'a> {
    /// A generated object member.
    Member(&'a str),
    /// A case of an array, found by its `name`.
    Case(&'a str),
    /// An array element the core rewrote, at its index, for an array whose cases have no
    /// `name`.
    Element(&'a str),
}

/// Compare generated cases with the fixture, or stage them during regeneration.
pub fn generated(name: &str, cases: &[(Place<'_>, Value)]) {
    let mut file = staged(name).unwrap_or_else(|| load(name));
    let staging = STAGED.with_borrow(Option::is_some);
    for (place, value) in cases {
        let pointer = match *place {
            Place::Member(p) | Place::Element(p) => Cow::Borrowed(p),
            Place::Case(p) => {
                let list = file
                    .pointer_mut(p)
                    .and_then(Value::as_array_mut)
                    .unwrap_or_else(|| panic!("{name}: no array at {p}"));
                let index = list
                    .iter()
                    .position(|case| case["name"] == value["name"])
                    .unwrap_or(list.len());
                if staging && index == list.len() {
                    list.push(Value::Null);
                }
                Cow::Owned(format!("{p}/{index}"))
            }
        };
        PLACES.with_borrow_mut(|places| {
            if let Some(places) = places {
                places.insert((name.to_owned(), pointer.to_string()));
            }
        });
        if !staging {
            assert_eq!(
                file.pointer(&pointer),
                Some(value),
                "{name}: {pointer} isn't what the core generates; see spec/vectors/README.md to regenerate"
            );
        } else if let Some(held) = file.pointer_mut(&pointer) {
            *held = value.clone();
        } else if matches!(place, Place::Member(_)) {
            let mut member = &mut file;
            for token in pointer.strip_prefix('/').expect("a member path").split('/') {
                member = if member.is_array() {
                    &mut member[token.parse::<usize>().expect("array index")]
                } else {
                    &mut member[token.replace("~1", "/").replace("~0", "~")]
                };
            }
            *member = value.clone();
        } else {
            panic!("{name}: no element at {pointer}");
        }
    }
    if staging {
        STAGED.with_borrow_mut(|files| {
            files
                .as_mut()
                .expect("staged files")
                .insert(name.to_owned(), file)
        });
    }
}

/// Replace the listed members. A stray sibling outside the declared inputs, annotations
/// and generated values fails the coverage test.
pub fn generated_members(name: &str, base: &str, members: &[(&str, Value)]) {
    let paths: Vec<_> = members
        .iter()
        .map(|(key, _)| format!("{base}/{key}"))
        .collect();
    let cases: Vec<_> = paths
        .iter()
        .zip(members)
        .map(|(path, (_, v))| (Place::Member(path), v.clone()))
        .collect();
    generated(name, &cases);
}

/// Regenerate the core-owned cases. This is the only writer for the published fixtures.
#[test]
#[ignore = "set PUBKY_SWITCH_WRITE_VECTORS=1 to publish regenerated fixtures"]
fn regenerate_vectors() {
    let publish = std::env::var("PUBKY_SWITCH_WRITE_VECTORS").as_deref() == Ok("1");
    let dir = spec_vectors_dir();
    // Every writer for this checkout shares this lock, even across Cargo target dirs.
    let target = dir.join("../../target");
    fs::create_dir_all(&target).unwrap();
    let lock = fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(target.join("vector-regeneration.lock"))
        .unwrap();
    lock.try_lock()
        .unwrap_or_else(|e| panic!("could not lock the vector fixtures for regeneration: {e}"));
    STAGED.set(Some(BTreeMap::new()));

    super::keys::test_vectors_keys();
    super::encoding::test_vectors_encoding();
    super::sealed::test_vectors_sealed();
    let docs = super::documents::issue_documents();
    super::envelopes::test_vectors_envelopes();
    let keys = super::common::keys();
    super::identifiers::test_vectors_identifiers();
    super::operations::test_vectors_operations();
    let chain = super::chain::chain_cases(&keys, &docs);
    let (transfer, chunk) = super::export::export_cases(&keys, &docs, &chain);
    super::record_current::condition_case(&keys, &chain);
    super::http::http_cases(&keys, &chain, &transfer, &chunk);
    super::signatures::test_vectors_signatures();

    for (name, file) in STAGED.take().unwrap() {
        let path = dir.join(&name);
        let mut bytes = serde_json::to_vec_pretty(&file).unwrap();
        bytes.push(b'\n');
        if fs::read(&path).unwrap() == bytes {
            continue;
        }
        assert!(
            publish,
            "{name} changed; see spec/vectors/README.md to regenerate"
        );
        // The writer holds the lock through rename. Readers always see complete JSON.
        let temp = dir.join(".regenerating-vector.tmp");
        fs::write(&temp, bytes).unwrap();
        fs::rename(temp, path).unwrap();
    }
}

/// Match an exact JSON pointer, allowing '*' only where the document has an array index.
fn input_matches(root: &Value, pointer: &str, pattern: &str) -> bool {
    let mut value = root;
    let mut tokens = pointer.split('/').skip(1);
    for part in pattern.split('/').skip(1) {
        let Some(token) = tokens.next() else {
            return false;
        };
        if (part == "*" && !value.is_array()) || (part != "*" && part != token) {
            return false;
        }
        value = value.pointer(&format!("/{token}")).expect("visited member");
    }
    tokens.next().is_none()
}

/// Visit the leaves outside the skipped subtrees, including empty arrays and objects.
fn visit_leaves(
    value: &Value,
    pointer: &str,
    skip: &BTreeSet<String>,
    visit: &mut impl FnMut(&str, &Value),
) {
    if skip.contains(pointer) {
        return;
    }
    match value {
        Value::Object(members) if !members.is_empty() => {
            for (member, child) in members {
                let token = member.replace('~', "~0").replace('/', "~1");
                visit_leaves(child, &format!("{pointer}/{token}"), skip, visit);
            }
        }
        Value::Array(elements) if !elements.is_empty() => {
            for (index, child) in elements.iter().enumerate() {
                visit_leaves(child, &format!("{pointer}/{index}"), skip, visit);
            }
        }
        _ => visit(pointer, value),
    }
}

type Fixture = (&'static str, fn(), &'static [&'static str]);

fn chain_cases() {
    super::chain::chain_cases(&super::common::keys(), &super::documents::issue_documents());
}

fn export_cases() {
    let keys = super::common::keys();
    let docs = super::documents::issue_documents();
    let chain = super::chain::chain_cases(&keys, &docs);
    super::export::export_cases(&keys, &docs, &chain);
}

fn fixtures() -> &'static [Fixture] {
    &[
        (
            "keys.json",
            super::keys::test_vectors_keys,
            &[
                "/identities/*/name",
                "/identities/*/seed_label",
                "/apps/*/name",
                "/apps/*/signing_seed_label",
                "/apps/*/bundle_seed_label",
                "/apps/*/permissions/*",
                "/apps/*/scopes/*",
                "/apps/*/receive_key/n",
                "/apps/*/receive_key/seed_label",
                "/scope_keys/*/identity",
                "/scope_keys/*/data_epoch",
                "/scope_keys/*/scope",
                "/sub_scope_keys/keys/*/identity",
                "/sub_scope_keys/keys/*/data_epoch",
                "/sub_scope_keys/keys/*/parent",
                "/sub_scope_keys/keys/*/sub",
                "/service_keys/*/seed_label",
                "/next_service_key/seed_label",
                "/next_service_key/description",
                "/next_service_key/origin",
                "/removed_app/name",
                "/removed_app/signing_seed_label",
            ],
        ),
        (
            "encoding.json",
            super::encoding::test_vectors_encoding,
            &[
                "/description",
                "/base64url/valid/0/hex",
                "/base64url/valid/0/base64url",
                "/base64url/valid/1/hex",
                "/base64url/valid/1/base64url",
                "/base64url/valid/2/hex",
                "/base64url/valid/2/base64url",
                "/base64url/valid/3/hex",
                "/base64url/valid/3/base64url",
                "/base64url/valid/4/seed_label",
                "/base64url/valid/5/seed_label",
                "/base64url/invalid/*/base64url",
                "/base64url/invalid/*/why",
                "/lp/0/parts_hex",
                "/lp/1/parts_hex/*",
                "/lp/2/parts_hex/*",
                "/lp/3/parts_hex/*",
                "/lp/4/parts_hex/*",
                "/lp/0/output_hex",
                "/lp/1/output_hex",
                "/lp/2/output_hex",
                "/lp/3/output_hex",
                "/lp/4/output_hex",
                "/derive/0/parts_hex",
                "/derive/1/parts_hex/*",
                "/derive/2/parts_hex/*",
                "/derive/4/seed_labels/*",
                "/zbase32/invalid/*/why",
                "/u64_be/*/value",
                "/u64_be/*/hex",
                "/u64_be/6/note",
                "/json/0/json",
                "/json/1/json",
                "/json/2/json",
                "/json/3/json",
                "/json/4/json",
                "/json/5/json",
                "/json/6/json",
                "/json/7/json",
                "/json/8/json",
                "/json/9/json",
                "/json/10/json",
                "/json/11/json",
                "/json/12/json",
                "/json/13/json_hex",
                "/json/*/valid",
                "/json/13/why",
                "/json/10/read_as",
                "/json/11/read_as",
                "/json/12/read_as",
                "/rfc3339/parse/*/text",
                "/rfc3339/parse/*/unix_ms",
                "/rfc3339/format/*/unix_ms",
                "/rfc3339/format/*/text",
                "/rfc3339/invalid/*/text",
                "/rfc3339/lenient_reader_only/*/text",
                "/rfc3339/lenient_reader_only/*/unix_ms",
            ],
        ),
        (
            "sealed.json",
            super::sealed::test_vectors_sealed,
            &[
                "/cases/*/name",
                "/cases/*/scope",
                "/cases/*/data_epoch",
                "/cases/*/nonce_seed_label",
                "/cases/0/msg_id_seed_label",
                "/cases/1/msg_id_seed_label",
            ],
        ),
        (
            "signatures.json",
            super::signatures::test_vectors_signatures,
            &[
                "/description",
                "/signatures/*/signer",
                "/rejections/*/name",
                "/rejections/*/why",
                "/rejections/*/reason",
                "/rejections/*/lenient_accepts",
                "/rejections/3/seed_a",
                "/rejections/3/seed_r",
                "/rejections/3/torsion_index",
                "/rejections/4/seed_a",
                "/rejections/4/torsion_index",
                "/rejections/5/seed_a",
                "/rejections/5/torsion_index",
                "/rejections/6/seed_a",
                "/rejections/6/seed_r",
                "/rejections/7/seed_a",
                "/rejections/7/seed_r",
                "/rejections/7/torsion_index",
                "/accepted/0/name",
                "/accepted/0/why",
                "/accepted/0/reason",
                "/accepted/0/lenient_accepts",
                "/accepted/0/seed_a",
                "/accepted/0/seed_r",
                "/accepted/0/torsion_index",
            ],
        ),
        (
            "documents.json",
            export_cases,
            &[
                "/documents/*/name",
                "/documents/*/signer",
                "/documents/0/expires_at",
                "/documents/0/issued_at",
                "/documents/1/expires_at",
                "/documents/1/issued_at",
                "/documents/2/expires_at",
                "/documents/2/issued_at",
                "/documents/3/expires_at",
                "/documents/3/issued_at",
                "/documents/4/accepts/*",
                "/documents/4/expires_at",
                "/documents/4/protocols/tasks/features/board_kinds/*",
                "/documents/4/protocols/tasks/public_boards",
                "/documents/4/updated_at",
                "/documents/5/accepts/*",
                "/documents/5/expires_at",
                "/documents/5/protocols/tasks/features/board_kinds/*",
                "/documents/5/protocols/tasks/public_boards",
                "/documents/5/updated_at",
                "/documents/6/accepts/*",
                "/documents/6/expires_at",
                "/documents/6/protocols/tasks/features/board_kinds/*",
                "/documents/6/protocols/tasks/public_boards",
                "/documents/6/updated_at",
                "/documents/7/accepts/*",
                "/documents/7/expires_at",
                "/documents/7/protocols/tasks/features/board_kinds/*",
                "/documents/7/protocols/tasks/public_boards/home",
                "/documents/7/updated_at",
                "/documents/12/data_epoch",
                "/documents/12/distrust_from",
                "/documents/12/listed_apps/*",
                "/documents/12/origin",
                "/documents/12/policy/admission",
                "/documents/12/policy/connect_requests/enabled",
                "/documents/12/policy/connect_requests/max_pending",
                "/documents/12/policy/connect_requests/push",
                "/documents/12/signer_seed_label",
                "/documents/12/version",
                "/documents/13/data_epoch",
                "/documents/13/listed_apps/*",
                "/documents/13/origin",
                "/documents/13/policy/admission",
                "/documents/13/policy/connect_requests/enabled",
                "/documents/13/policy/connect_requests/max_pending",
                "/documents/13/policy/connect_requests/push",
                "/documents/13/signer_seed_label",
                "/documents/13/version",
                "/documents/14/nonce_seed_label",
                "/documents/14/observed_at",
                "/documents/14/store_id_seed_label",
                "/documents/15/expires_at",
                "/documents/15/issued_at",
                "/documents/15/permissions/*",
                "/documents/15/scopes/*",
                "/documents/16/data_epoch",
                "/documents/16/until",
                "/documents/16/version",
                "/documents/17/data_epoch",
                "/documents/17/until",
                "/documents/17/version",
                "/documents/18/issued_at",
                "/documents/18/next_generation",
                "/documents/18/nonce_seed_label",
                "/documents/19/data_epoch",
                "/documents/19/version",
                "/documents/20/record_max_age",
                "/documents/20/version",
                "/documents/22/nonce_seed_label",
                "/documents/22/observed_at",
                "/documents/22/store_id_seed_label",
                "/documents/23/expires_at",
                "/documents/23/issued_at",
                "/documents/24/accepts/*",
                "/documents/24/expires_at",
                "/documents/24/protocols/tasks/features/board_kinds/*",
                "/documents/24/protocols/tasks/public_boards",
                "/documents/24/updated_at",
                "/documents/25/issued_at",
                "/documents/26/generation",
                "/documents/26/version",
                "/documents/27/expires_at",
                "/documents/27/issued_at",
                "/documents/28/accepts/*",
                "/documents/28/expires_at",
                "/documents/28/protocols/tasks/features/board_kinds/*",
                "/documents/28/protocols/tasks/public_boards",
                "/documents/28/updated_at",
                "/documents/29/version",
                "/auth_request/client_id",
                "/auth_request/client_seed_label",
                "/auth_request/secret_seed_label",
                "/approval/keyed_scopes/*",
                "/approval/seal_seed_label",
                "/approval/rejections/*/step",
                "/approval/rejections/*/error",
                "/approval/rejections/*/last_epoch",
                "/approval/rejections/*/seal_seed_label",
                "/identity_rejections/cases/*/name",
                "/identity_rejections/cases/*/error",
                "/app_record_conflict/conflict",
                "/app_record_conflict/kept",
                "/app_record_conflict/updated_at",
                "/app_record_conflict/records/*/board_kind",
                "/permission_rejections/cases/*/name",
                "/permission_rejections/cases/*/reason",
                "/permission_rejections/cases/2/extra_permission",
                "/scope_rule/accepted/*/extra_scopes/*",
                "/scope_rule/refused/*/reason",
                "/scope_rule/refused/*/extra_scopes/*",
                "/app_record_protocols/accepted/0/protocol",
                "/app_record_protocols/accepted/0/member/items/0",
                "/app_record_protocols/accepted/0/member/items/1/deep",
                "/app_record_protocols/accepted/0/member/level",
                "/app_record_protocols/accepted/1/protocol",
                "/app_record_protocols/accepted/1/member",
                "/app_record_protocols/refused/*/reason",
                "/app_record_protocols/refused/0/protocol",
                "/app_record_protocols/refused/0/member",
                "/app_record_protocols/refused/1/protocol",
                "/app_record_protocols/refused/1/member",
                "/app_record_protocols/refused/2/protocol",
                "/app_record_protocols/refused/2/member",
                "/app_record_protocols/refused/3/protocol",
                "/app_record_protocols/refused/3/member",
                "/app_record_protocols/refused/4/protocol",
                "/app_record_protocols/refused/4/member",
                "/app_record_protocols/refused/5/protocol",
                "/app_record_protocols/refused/5/member",
                "/app_record_protocols/refused/6/protocol",
                "/app_record_protocols/refused/6/member",
                "/app_record_protocols/refused/7/name",
                "/app_record_protocols/refused/7/protocols",
            ],
        ),
        (
            "envelopes.json",
            super::envelopes::test_vectors_envelopes,
            &[
                "/account_created",
                "/keyed_scopes/*",
                "/messages/assignment/body/board",
                "/messages/assignment/body/every",
                "/messages/assignment/body/starts_at",
                "/messages/assignment/body/task",
                "/messages/assignment/created_at",
                "/messages/assignment/kind",
                "/messages/assignment/msg_id_seed_label",
                "/messages/cancellation/body/reason",
                "/messages/cancellation/created_at",
                "/messages/cancellation/kind",
                "/messages/cancellation/msg_id_seed_label",
                "/messages/resend/created_at",
                "/messages/resend/item_seed_prefix",
                "/messages/resend/kind",
                "/messages/resend/msg_id_seed_label",
                "/cases/*/name",
                "/cases/*/notify",
                "/cases/*/cek_seed_label",
                "/cases/*/nonce_seed_label",
                "/cases/*/recipients/*/app",
                "/cases/*/recipients/*/ikm_e_seed_label",
                "/cases/2/resend_count",
                "/cases/3/resend_count",
                "/cases/4/resend_count",
                "/cases/5/resend_count",
                "/cases/6/resend_count",
                "/cases/7/resend_count",
                "/bucket_fit/*/bucket",
                "/bucket_fit/*/plaintext_len",
                "/bucket_fit/*/recipients",
                "/rejections/0/case",
                "/rejections/0/change",
                "/rejections/0/result",
                "/rejections/1/case",
                "/rejections/1/change",
                "/rejections/1/result",
                "/rejections/2/name",
                "/rejections/2/opens_for/*",
                "/rejections/2/rejected_by/0/app",
                "/rejections/2/rejected_by/0/reason",
                "/rejections/2/cek_seed_label",
                "/rejections/2/nonce_seed_label",
                "/rejections/2/other_cek_seed_label",
                "/rejections/2/ikm_e_seed_labels/0",
                "/rejections/2/ikm_e_seed_labels/1",
                "/key_bundle/app",
                "/key_bundle/first_epoch",
                "/key_bundle/last_epoch",
                "/key_bundle/seal_seed_label",
                "/reduction_key_bundle/app",
                "/reduction_key_bundle/first_epoch",
                "/reduction_key_bundle/last_epoch",
                "/reduction_key_bundle/seal_seed_label",
                "/reduction_key_bundle/removed_scope",
                "/key_bundle_rejections/cases/*/name",
                "/key_bundle_rejections/cases/*/reason",
                "/key_bundle_rejections/cases/*/seal_seed_label",
                "/key_bundle_rejections/cases/0/scope",
                "/key_bundle_rejections/cases/1/key_seed_label",
                "/key_bundle_rejections/cases/2/scope",
                "/signer_handover/app",
                "/signer_handover/parts/*/seal_seed_label",
                "/signer_backup/seal_seed_label",
                "/signer_handover_rejections/cases/*/name",
                "/signer_handover_rejections/cases/*/reason",
            ],
        ),
        (
            "chain.json",
            chain_cases,
            &[
                "/generation",
                "/items/*/seq",
                "/items/*/source",
                "/items/*/server_time",
                "/items/2/batch_seed_label",
                "/items/2/batch_count",
                "/items/4/batch_seed_label",
                "/items/4/batch_count",
                "/items/5/batch_seed_label",
                "/items/5/batch_count",
                "/items/5/claim_key",
                "/items/5/expected_step",
                "/items/5/orphan_after",
                "/items/5/attempt_seed_label",
                "/items/4/record_name",
                "/items/4/record_version",
                "/items/4/data_epoch",
                "/items/4/scope",
                "/items/4/record_status",
                "/items/4/nonce_seed_label",
                "/items/4/message/created_at",
                "/items/4/message/accepted_at",
                "/items/4/message/kind",
                "/items/4/message/msg_id_seed_label",
                "/items/6/record_status",
                "/items/6/nonce_seed_label",
                "/items/6/message/created_at",
                "/items/6/message/accepted_at",
                "/items/6/message/kind",
                "/items/6/message/msg_id_seed_label",
                "/items/4/message/body/board",
                "/items/4/message/body/task",
                "/items/4/message/body/due",
                "/items/6/message/body",
                "/items/7/app",
                "/peer_admission/items/*/seq",
                "/peer_admission/items/*/server_time",
                "/peer_admission/items/*/action",
                "/peer_admission/items/2/peer",
                "/peer_admission/items/3/peer",
                "/peer_admission/items/4/peer",
                "/peer_admission/items/5/peer",
                "/peer_admission/items/6/peer",
                "/peer_admission/items/7/peer",
                "/peer_admission/items/0/code_seed_label",
                "/peer_admission/items/1/code_seed_label",
                "/peer_admission/items/0/expires_at",
                "/peer_admission/items/1/expires_at",
                "/peer_admission/items/0/max_uses",
                "/peer_admission/items/1/max_uses",
                "/peer_admission/items/0/batch_seed_label",
                "/peer_admission/items/1/batch_seed_label",
                "/peer_admission/items/3/batch_seed_label",
                "/peer_admission/items/4/batch_seed_label",
                "/peer_admission/items/5/batch_seed_label",
                "/peer_admission/items/6/batch_seed_label",
                "/peer_admission/items/7/batch_seed_label",
                "/peer_admission/items/3/reason",
                "/peer_admission/items/4/reason",
                "/peer_admission/items/5/reason",
                "/peer_admission/items/6/reason",
                "/peer_admission/items/7/reason",
                "/peer_admission/items/7/peer_seed_label",
                "/record_delete/batch_seed_label",
                "/record_delete/nonce_seed_label",
                "/record_delete/server_time",
                "/rejections/*/name",
                "/rejections/*/error",
                "/rejections/0/item_sources/*",
                "/rejections/1/item_sources/*",
                "/rejections/2/item_sources/*",
                "/rejections/2/gap_ms",
                "/rejections/3/stubs",
                "/rejections/4/after",
                "/rejections/4/at_seq",
                "/rejections/4/hash_seed_label",
                "/batch_id_window/*/name",
                "/batch_id_window/*/outcome",
                "/batch_id_window/*/error",
                "/batch_id_window/*/gap_ms",
                "/batch_id_window/*/item_sources/*",
                "/signed_heads/*/at_seq",
                "/transition_proofs/*/at_seq",
            ],
        ),
        (
            "export.json",
            export_cases,
            &[
                "/manifest/signer",
                "/manifest/freeze_at",
                "/manifest/directory_version",
                "/manifest/apps_version",
                "/manifest/keys_through",
                "/manifest/wallet_added_at",
                "/manifest/wallet_cursor",
                "/pending_entry/seq",
                "/pending_entry/accepted_at",
                "/pending_entry/notify",
                "/pending_entry/directory_version",
                "/pending_entry/body/task",
                "/pending_entry/kind",
                "/pending_entry/entry_seed_label",
                "/pending_entry/msg_id_seed_label",
                "/pending_entry/seal_seed_label",
                "/peer_admission/entry_seq",
                "/peer_admission/entry_seed_label",
                "/peer_admission/directory_version",
                "/peer_admission/last_used",
                "/claim_rejections/*/name",
                "/claim_rejections/*/error",
                "/claim_rejections/0/creator_app",
                "/claim_rejections/1/earlier_ms",
                "/claim_rejections/3/batch_seed_label",
                "/claim_rejections/4/batch_seed_label",
                "/claim_rejections/*/status",
                "/record_rejections/*/name",
                "/record_rejections/*/error",
                "/record_rejections/1/signing_account",
            ],
        ),
    ]
}

/// Authored explanations and captions that do not choose wire values or expected outcomes.
fn annotations(file: &str) -> &'static [&'static str] {
    match file {
        "chain.json" => &[
            "/description",
            "/record_delete/description",
            "/transition_proofs/*/name",
            "/peer_admission/description",
            "/rejections/*/rule",
        ],
        "export.json" => &[
            "/description",
            "/manifest/name",
            "/peer_admission/description",
            "/pending_entry/description",
            "/record_rejections/*/rule",
            "/claim_rejections/*/rule",
        ],
        "documents.json" => &[
            "/app_record_conflict/description",
            "/app_record_protocols/description",
            "/auth_request/description",
            "/identity_rejections/description",
            "/permission_rejections/description",
            "/scope_rule/description",
            "/approval/rejections/*/name",
            "/approval/rejections/*/rule",
            "/identity_rejections/cases/*/rule",
            "/scope_rule/accepted/*/name",
            "/scope_rule/refused/*/name",
            "/app_record_protocols/accepted/*/name",
            "/app_record_protocols/refused/0/name",
            "/app_record_protocols/refused/1/name",
            "/app_record_protocols/refused/2/name",
            "/app_record_protocols/refused/3/name",
            "/app_record_protocols/refused/4/name",
            "/app_record_protocols/refused/5/name",
            "/app_record_protocols/refused/6/name",
        ],
        "envelopes.json" => &[
            "/key_bundle/note",
            "/reduction_key_bundle/note",
            "/rejections/2/note",
            "/signer_handover_rejections/description",
            "/key_bundle_rejections/cases/*/change",
        ],
        _ => &[],
    }
}

/// Require the authored text on each case, including each element of a captioned array.
pub(super) fn check_annotations(name: &str, file: &Value) {
    for &pattern in annotations(name) {
        let (parent, member) = pattern.rsplit_once('/').unwrap();
        let check = |entry: &Value| {
            assert!(
                entry[member].as_str().is_some_and(|s| !s.trim().is_empty()),
                "{name}: missing text at {pattern}"
            );
        };
        if let Some(array) = parent.strip_suffix("/*") {
            for entry in file.pointer(array).and_then(Value::as_array).expect(array) {
                check(entry);
            }
        } else {
            check(file.pointer(parent).expect(parent));
        }
    }
}

fn fixture(name: &str) -> Fixture {
    fixtures()
        .iter()
        .copied()
        .find(|(file, _, _)| *file == name)
        .expect(name)
}

fn reported_places(name: &str, produce: fn()) -> BTreeSet<String> {
    PLACES.set(Some(BTreeSet::new()));
    produce();
    PLACES
        .take()
        .expect("recorded places")
        .into_iter()
        .filter_map(|(file, pointer)| (file == name).then_some(pointer))
        .collect()
}

/// Leaves outside the skipped subtrees that no input or annotation pattern claims.
fn unclaimed_leaves(
    name: &str,
    file: &Value,
    inputs: &[&str],
    skip: &BTreeSet<String>,
) -> BTreeSet<String> {
    let prose = annotations(name);
    let mut unmatched: BTreeSet<_> = inputs.iter().chain(prose).copied().collect();
    let mut unclaimed = BTreeSet::new();
    visit_leaves(file, "", skip, &mut |pointer, _| {
        let mut covered = false;
        for &pattern in inputs.iter().chain(prose) {
            if input_matches(file, pointer, pattern) {
                covered = true;
                unmatched.remove(pattern);
            }
        }
        if !covered {
            unclaimed.insert(pointer.to_owned());
        }
    });
    assert!(
        unmatched.is_empty(),
        "{name}: patterns matched no leaf: {unmatched:?}"
    );
    unclaimed
}

fn check_coverage((name, verify, inputs): Fixture) -> Result<(), BTreeSet<String>> {
    let places = reported_places(name, verify);
    let unclaimed = unclaimed_leaves(name, &load(name), inputs, &places);
    if unclaimed.is_empty() {
        Ok(())
    } else {
        Err(unclaimed)
    }
}

/// Every published leaf is covered and every declared pattern covers a leaf.
#[test]
fn test_vectors_every_member_is_an_input_or_generated() {
    for &fixture in fixtures() {
        check_coverage(fixture)
            .unwrap_or_else(|paths| panic!("{}: unclaimed leaves: {paths:?}", fixture.0));
    }
}

#[test]
fn test_vectors_coverage_rejects_stray_case_members() {
    for (name, case) in [
        ("documents.json", "/documents/0"),
        ("envelopes.json", "/cases/0"),
        ("chain.json", "/items/0"),
        ("export.json", "/record_rejections/0"),
    ] {
        let mut file = load(name);
        file.pointer_mut(case).expect("published case")["stray"] = true.into();
        CHANGED.set(BTreeMap::from([(name.to_owned(), file)]));
        let coverage = check_coverage(fixture(name));
        CHANGED.with_borrow_mut(BTreeMap::clear);
        assert_eq!(
            coverage,
            Err(BTreeSet::from([format!("{case}/stray")])),
            "{name}"
        );
    }
}

/// Identifiers and operations stay unblanked because their input schemas are not covered.
/// The reader tests still compare HTTP answers with the exported chunk and chain.
#[test]
fn test_vectors_documents_and_envelopes_derive_their_carriers() {
    let producers: [(&str, fn()); 5] = [
        ("export.json", export_cases),
        ("chain.json", chain_cases),
        ("documents.json", export_cases),
        ("envelopes.json", super::envelopes::test_vectors_envelopes),
        ("keys.json", super::keys::test_vectors_keys),
    ];
    let mut expected = BTreeMap::new();
    let mut files = BTreeMap::new();
    for (name, _) in producers {
        let mut file = load(name);
        let (_, _, inputs) = fixture(name);
        let leaves = unclaimed_leaves(name, &file, inputs, &BTreeSet::new());
        for path in &leaves {
            *file.pointer_mut(path).expect("published leaf") = Value::Null;
        }
        expected.insert(name, leaves);
        files.insert(name.to_owned(), file);
    }
    // A later producer still sees blank carriers when it calls load().
    CHANGED.set(files.clone());
    let peer_seed = load("claims.json")["identity_seed_label"].clone();
    CHANGED.with_borrow_mut(|files| {
        files.insert(
            "claims.json".into(),
            serde_json::json!({"identity_seed_label":peer_seed}),
        );
        for name in [
            "http.json",
            "signatures.json",
            "encoding.json",
            "sealed.json",
        ] {
            files.insert(name.into(), Value::Null);
        }
    });
    STAGED.set(Some(files));
    for (name, produce) in producers {
        let places = reported_places(name, produce);
        let file = staged(name).expect(name);
        let mut emitted = BTreeSet::new();
        // A producer can report a signed document's body and signature under one path.
        for path in places {
            let value = file.pointer(&path).expect("generated value");
            visit_leaves(value, &path, &BTreeSet::new(), &mut |leaf, _| {
                emitted.insert(leaf.to_owned());
            });
        }
        let leaves = &expected[name];
        assert!(
            &emitted == leaves,
            "{name}: generated leaves differ at {:?}",
            leaves.symmetric_difference(&emitted).collect::<Vec<_>>()
        );
    }
    let rebuilt = STAGED.take().unwrap();
    CHANGED.with_borrow_mut(BTreeMap::clear);
    for (name, _) in producers {
        assert!(
            rebuilt[name] == load(name),
            "{name} differs after regeneration"
        );
    }
}

/// Seed labels are scalar members or entries of a seed_labels array.
fn is_seed_label(pointer: &str) -> bool {
    let Some((parent, name)) = pointer.rsplit_once('/') else {
        return false;
    };
    name.ends_with("seed_label")
        || matches!(name, "seed_a" | "seed_r" | "item_seed_prefix")
        || parent
            .rsplit('/')
            .next()
            .is_some_and(|member| member.ends_with("seed_labels"))
}

/// Each seed label in the file decides at least one generated value.
#[test]
fn test_vectors_seed_labels_decide_their_values() {
    for &(name, verify, _) in fixtures() {
        verify();
        let file = load(name);
        visit_leaves(&file, "", &BTreeSet::new(), &mut |pointer, value| {
            let Some(label) = value.as_str().filter(|_| is_seed_label(pointer)) else {
                return;
            };
            let mut changed = file.clone();
            *changed.pointer_mut(pointer).expect("visited label") =
                Value::String(format!("{label}/changed"));
            CHANGED.set(BTreeMap::from([(name.to_owned(), changed)]));
            let outcome = std::panic::catch_unwind(verify);
            CHANGED.with_borrow_mut(BTreeMap::clear);
            let payload = outcome
                .err()
                .unwrap_or_else(|| panic!("{name}: {pointer} doesn't decide any value"));
            let why = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied());
            assert!(
                why.is_some_and(
                    |s| s.split_once(" isn't what the core generates").is_some_and(
                        |(location, _)| location.contains(&format!("{name}: /"))
                            && !location.ends_with("/description")
                            && !location.ends_with("/note")
                    )
                ),
                "{name}: {pointer}: {why:?}"
            );
        });
    }
}
