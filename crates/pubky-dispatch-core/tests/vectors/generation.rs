//! Verification and explicit regeneration of the core's vector cases.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use pubky_dispatch_core::{http::header, spec_vectors_dir};
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

/// Compare generated cases with the fixture, or stage them during regeneration.
pub fn generated(name: &str, cases: &[(&str, Value)]) {
    let mut file = staged(name).unwrap_or_else(|| load(name));
    let staging = STAGED.with_borrow(Option::is_some);
    for &(pointer, ref value) in cases {
        PLACES.with_borrow_mut(|places| {
            if let Some(places) = places {
                places.insert((name.to_owned(), pointer.to_string()));
            }
        });
        if !staging {
            assert_eq!(
                file.pointer(pointer),
                Some(value),
                "{name}: {pointer} isn't what the core generates; see spec/vectors/README.md to regenerate"
            );
        } else if let Some(held) = file.pointer_mut(pointer) {
            *held = value.clone();
        } else {
            let mut member = &mut file;
            for token in pointer.strip_prefix('/').expect("a member path").split('/') {
                member = if member.is_array() {
                    &mut member[token.parse::<usize>().expect("array index")]
                } else {
                    &mut member[token.replace("~1", "/").replace("~0", "~")]
                };
            }
            *member = value.clone();
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
        .map(|(path, (_, v))| (path.as_str(), v.clone()))
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
    regenerate(publish, BTreeMap::new()).unwrap_or_else(|error| panic!("{error}"));
}

type Files = BTreeMap<String, Value>;
type Places = BTreeSet<(String, String)>;

/// Stage the vector files together, using their rebuilt carriers throughout.
fn stage_covered(files: Files) -> (Files, Places) {
    STAGED.set(Some(files));
    PLACES.set(Some(BTreeSet::new()));
    super::keys::test_vectors_keys();
    let keys = super::common::keys();
    let ids = super::identifiers::identifier_cases(&keys);
    super::encoding::test_vectors_encoding();
    super::sealed::test_vectors_sealed();
    let docs = super::documents::issue_documents();
    let (handover, bundle) = super::envelopes::envelope_cases();
    let chain = super::chain::chain_cases(&keys, &docs);
    let export = super::export::export_cases(&keys, &docs, &chain);
    super::claims::test_vectors_claims();
    super::http::http_cases(&keys, &docs, &chain, &export, &handover);
    super::operations::operation_cases(&keys, &chain, &docs, &bundle, &ids);
    super::signatures::test_vectors_signatures();
    (STAGED.take().unwrap(), PLACES.take().unwrap())
}

fn regenerate(publish: bool, files: Files) -> Result<(), String> {
    let (files, places) = stage_covered(files);
    for &(name, _, inputs) in fixtures() {
        let unclaimed = unclaimed_leaves(name, &files[name], inputs, &file_places(name, &places));
        if !unclaimed.is_empty() {
            return Err(format!("{name}: unclaimed leaves: {unclaimed:?}"));
        }
    }
    compare_or_write(publish, &files)
}

/// A vector file's exact bytes: pretty JSON with a final newline.
fn rendered(file: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(file).unwrap();
    bytes.push(b'\n');
    bytes
}

/// Check mode's rule: the published bytes equal the regenerated ones, byte for byte, so a
/// file that differs only in member order, layout or its final newline is refused.
fn unchanged(published: &[u8], file: &Value) -> bool {
    published == rendered(file)
}

fn compare_or_write(publish: bool, files: &Files) -> Result<(), String> {
    let dir = spec_vectors_dir();
    for (name, file) in files {
        let path = dir.join(name);
        if unchanged(&fs::read(&path).unwrap(), file) {
            continue;
        }
        let bytes = rendered(file);
        if !publish {
            return Err(format!(
                "{name} changed; see spec/vectors/README.md to regenerate"
            ));
        }
        // The writer holds the lock through rename. Readers always see complete JSON.
        let temp = dir.join(".regenerating-vector.tmp");
        fs::write(&temp, bytes).unwrap();
        fs::rename(temp, path).unwrap();
    }
    Ok(())
}

/// Expand an input pattern to scalar or empty-container leaves in its selected cases.
fn match_pattern(value: &Value, path: &str, pattern: &str, matches: &mut BTreeSet<String>) {
    let Some(rest) = pattern.strip_prefix('/') else {
        if value.as_array().is_none_or(Vec::is_empty)
            && value.as_object().is_none_or(serde_json::Map::is_empty)
        {
            matches.insert(path.to_owned());
        }
        return;
    };
    let split = rest.find('/').unwrap_or(rest.len());
    let (token, tail) = rest.split_at(split);
    if token == "*" || token.contains('=') {
        if let Some(array) = value.as_array() {
            for (i, item) in array.iter().enumerate() {
                if token == "*" || token.split_once('=').is_some_and(|(k, v)| item[k] == v) {
                    match_pattern(item, &format!("{path}/{i}"), tail, matches);
                }
            }
        }
    } else if let Some(child) = value.pointer(&format!("/{token}")) {
        match_pattern(child, &format!("{path}/{token}"), tail, matches);
    }
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

type Pattern = (&'static str, usize);
type Fixture = (&'static str, fn(), &'static [Pattern]);

/// Literal paths select one leaf. Array selectors declare their published cardinality.
macro_rules! patterns {
    ($($path:literal $(=> $count:literal)?),* $(,)?) => {
        &[$(($path, patterns!(@count $($count)?))),*]
    };
    (@count) => { 1 };
    (@count $count:literal) => { $count };
}

fn chain_cases() {
    super::chain::chain_cases(&super::common::keys(), &super::documents::issue_documents());
}

fn export_cases() {
    let keys = super::common::keys();
    let docs = super::documents::issue_documents();
    let chain = super::chain::chain_cases(&keys, &docs);
    super::export::export_cases(&keys, &docs, &chain);
}

fn http_cases() {
    let keys = super::common::keys();
    let docs = super::documents::issue_documents();
    let chain = super::chain::chain_cases(&keys, &docs);
    let export = super::export::export_cases(&keys, &docs, &chain);
    let (handover, _) = super::envelopes::envelope_cases();
    super::http::http_cases(&keys, &docs, &chain, &export, &handover);
}

fn operation_cases() {
    let keys = super::common::keys();
    let ids = super::identifiers::identifier_cases(&keys);
    let docs = super::documents::issue_documents();
    let chain = super::chain::chain_cases(&keys, &docs);
    let (_, bundle) = super::envelopes::envelope_cases();
    super::operations::operation_cases(&keys, &chain, &docs, &bundle, &ids);
}

fn fixtures() -> &'static [Fixture] {
    &[
        (
            "keys.json",
            super::keys::test_vectors_keys,
            patterns![
                "/identities/*/name" => 2,
                "/identities/*/seed_label" => 2,
                "/apps/*/name" => 6,
                "/apps/*/signing_seed_label" => 6,
                "/apps/*/bundle_seed_label" => 6,
                "/apps/*/permissions/*" => 15,
                "/apps/*/scopes/*" => 13,
                "/apps/*/receive_key/n" => 6,
                "/apps/*/receive_key/seed_label" => 6,
                "/scope_keys/*/identity" => 5,
                "/scope_keys/*/data_epoch" => 5,
                "/scope_keys/*/scope" => 5,
                "/sub_scope_keys/keys/*/identity" => 2,
                "/sub_scope_keys/keys/*/data_epoch" => 2,
                "/sub_scope_keys/keys/*/parent" => 2,
                "/sub_scope_keys/keys/*/sub" => 2,
                "/service_keys/*/seed_label" => 2,
                "/next_service_key/seed_label",
                "/next_service_key/description",
                "/next_service_key/origin",
                "/removed_app/name",
                "/removed_app/signing_seed_label",
            ],
        ),
        (
            "identifiers.json",
            super::identifiers::test_vectors_identifiers,
            patterns![
                "/app_id/*/name" => 4,
                "/kid/*/name" => 8,
                "/blinded_inputs/*/name" => 4,
                "/blinded_inputs/*/account" => 4,
                "/collections/*/name" => 5,
                "/collections/*/account" => 5,
                "/policies/*/name" => 17,
                "/policies/*/read_scope" => 17,
                "/policies/*/write_scopes/*" => 18,
                "/policies/*/create_scope" => 4,
                "/policies/*/delete_scope" => 4,
                "/policies/*/permanent/generation" => 6,
                "/record_keys/*/name" => 12,
                "/record_keys/*/collection" => 12,
                "/record_keys/*/policy" => 12,
                "/record_keys/*/account" => 12,
                "/record_keys/*/natural_from" => 5,
                "/record_keys/name=task_items record of a round (February)/period_start",
                "/record_keys/name=task_items record of a task done without an assignment/attempt_seed_label",
                "/record_keys/name=task_assignments record of a task done without an assignment/board",
                "/record_keys/name=task_assignments record of a task done without an assignment/task",
                "/record_keys/name=shares record/share_seed_label",
                "/record_keys/name=task_assignments record of the assignment labelled team1/message/sender",
                "/record_keys/name=task_assignments record of the assignment labelled team1/message/recipient",
                "/record_keys/name=task_assignments record of the assignment labelled team1/message/msg_id_seed_label",
                "/record_keys/name=task_assignments record of the assignment labelled team1/message/created_at",
                "/record_keys/name=task_assignments record of the assignment labelled team1/message/kind",
                "/record_keys/name=task_assignments record of the assignment labelled team1/message/refs",
                "/record_keys/name=task_assignments record of the assignment labelled team1/message/body/due",
                "/record_keys/name=task_assignments record of the assignment labelled team1/message/body/label",
                "/record_keys/name=task_assignments record of the assignment labelled team1/message/body/task",
                "/invite_code/account",
                "/invite_code/code_seed_label",
            ],
        ),
        (
            "operations.json",
            operation_cases,
            patterns![
                "/operations/*/name" => 22,
                "/operations/*/writer" => 22,
                "/operations/*/batch_seed_label" => 15,
                "/operations/*/batch_from" => 2,
                "/operations/*/nonce_seed_label" => 3,
                "/operations/*/previous_version" => 2,
                "/operations/*/evidence" => 2,
                "/operations/name=record.put after done/message",
                "/operations/name=record.put after done/accepted_at",
                "/operations/name=record.put after done/record_status",
                "/operations/name=executor batch: attempt/attempt_seed_label",
                "/operations/name=executor batch: attempt/orphan_after",
                "/operations/name=executor batch: share_runs record.put/record_name",
                "/operations/name=executor batch: share_runs record.put/condition_record",
                "/operations/name=executor batch: share_runs record.put/condition_version",
                "/operations/name=executor batch: share_runs record.put/start",
                "/operations/name=executor batch: share_runs record.put/end",
                "/operations/name=executor batch: share_runs record.put/record_version",
                "/operations/name=executor batch: share_runs record.put/counterparty",
                "/operations/name=executor batch: share_runs record.put/outcome",
                "/operations/*/peer" => 5,
                "/operations/*/reason" => 3,
                "/operations/name=invite_code.put/expires_at",
                "/operations/name=invite_code.put/max_uses",
                "/operations/name=cert.put/certificate",
                "/messages/*/name" => 2,
                "/messages/*/sender" => 2,
                "/messages/*/recipient" => 2,
                "/messages/*/kind" => 2,
                "/messages/*/created_at" => 2,
                "/messages/*/msg_id_seed_label" => 2,
                "/messages/*/refs/*" => 3,
                "/messages/name=done/body_refs/assignment",
                "/messages/name=receipt/body_refs/done",
                "/ops_request/operations/*" => 2,
                "/ops_request/cursor",
                "/unknown_members/cases/*/value" => 9,
                "/unknown_members/batch_entries/cases/*/value" => 2,
                "/integer_bounds/cases/*/member" => 6,
                "/unknown_members/cases/*/based_on" => 9,
                "/unknown_members/cases/*/writer" => 9,
                "/unknown_members/cases/*/member" => 9,
                "/unknown_members/cases/*/expect/status" => 9,
                "/unknown_members/cases/*/expect/code" => 9,
                "/unknown_members/batch_entries/cases/*/based_on" => 2,
                "/unknown_members/batch_entries/cases/*/member" => 2,
                "/unknown_members/batch_entries/cases/*/expect/status" => 2,
                "/unknown_members/batch_entries/cases/*/expect/code" => 2,
                "/integer_bounds/cases/*/based_on" => 6,
                "/integer_bounds/cases/*/number" => 6,
                "/integer_bounds/cases/*/writer" => 6,
                "/integer_bounds/cases/*/expect/valid",
                "/integer_bounds/cases/*/expect/status" => 5,
                "/integer_bounds/cases/*/expect/code" => 5,
                "/attempt_deadlines/cases/*/d" => 5,
                "/record_current/writer",
                "/record_current/batch_byte",
                "/shape_rejections/cases/*/based_on" => 7,
                "/shape_rejections/cases/*/name" => 7,
                "/shape_rejections/cases/*/writer" => 7,
                "/shape_rejections/cases/*/rule" => 7,
                "/shape_rejections/cases/*/expect/status" => 7,
                "/shape_rejections/cases/*/expect/code" => 7,
                "/record_scopes/record_name",
                "/record_scopes/data_epoch",
                "/record_scopes/generation",
                "/record_scopes/cases/*/writer" => 8,
                "/record_scopes/cases/*/policy" => 8,
                "/record_scopes/cases/*/delete_scope",
                "/record_scopes/cases/*/previous_version" => 5,
                "/record_scopes/cases/*/plaintext" => 8,
                "/record_scopes/cases/*/nonce_seed_label" => 8,
                "/record_scopes/cases/*/batch_seed_label" => 8,
                "/record_scopes/cases/*/success_status" => 3,
                "/record_scopes/cases/*/expect/valid" => 3,
                "/record_scopes/cases/*/expect/status" => 5,
                "/record_scopes/cases/*/expect/code" => 5,
                "/permanent_policies/cases/*/based_on" => 2,
                "/permanent_policies/cases/*/name" => 2,
                "/permanent_policies/cases/*/writer" => 2,
                "/permanent_policies/cases/*/generation" => 2,
                "/permanent_policies/cases/*/batch_seed_label" => 2,
                "/permanent_policies/cases/*/nonce_seed_label" => 2,
                "/permanent_policies/cases/*/expect/valid" => 2,
                "/permanent_policies/rejections/*/based_on" => 11,
                "/permanent_policies/rejections/*/permanent" => 11,
                "/permanent_policies/rejections/*/writer" => 11,
                "/permanent_policies/rejections/*/expect/status" => 11,
                "/permanent_policies/rejections/*/expect/code" => 11,
                "/deny_room/cases/*/held_bytes/*" => 3,
                "/deny_room/cases/*/uploaded_bytes/*" => 10,
                "/deny_room/cases/*/free_slots" => 3,
                "/deny_room/cases/*/expect/status" => 3,
                "/deny_room/cases/*/expect/code" => 2,
                "/deny_room/cases/*/expect/current/limit" => 2,
                "/deny_room/cases/*/expect/current/over" => 2,
            ],
        ),
        (
            "encoding.json",
            super::encoding::test_vectors_encoding,
            patterns![
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
                "/base64url/invalid/*/base64url" => 6,
                "/base64url/invalid/*/why" => 6,
                "/lp/0/parts_hex",
                "/lp/1/parts_hex/*",
                "/lp/2/parts_hex/*" => 2,
                "/lp/3/parts_hex/*" => 2,
                "/lp/4/parts_hex/*" => 2,
                "/lp/0/output_hex",
                "/lp/1/output_hex",
                "/lp/2/output_hex",
                "/lp/3/output_hex",
                "/lp/4/output_hex",
                "/derive/0/parts_hex",
                "/derive/1/parts_hex/*" => 2,
                "/derive/2/parts_hex/*" => 2,
                "/derive/4/seed_labels/*",
                "/zbase32/invalid/*/why" => 4,
                "/u64_be/*/value" => 7,
                "/u64_be/*/hex" => 7,
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
                "/json/*/valid" => 14,
                "/json/13/why",
                "/json/10/read_as",
                "/json/11/read_as",
                "/json/12/read_as",
                "/rfc3339/parse/*/text" => 9,
                "/rfc3339/parse/*/unix_ms" => 9,
                "/rfc3339/format/*/unix_ms" => 3,
                "/rfc3339/format/*/text" => 3,
                "/rfc3339/invalid/*/text" => 7,
                "/rfc3339/lenient_reader_only/*/text" => 2,
                "/rfc3339/lenient_reader_only/*/unix_ms" => 2,
            ],
        ),
        (
            "sealed.json",
            super::sealed::test_vectors_sealed,
            patterns![
                "/cases/*/name" => 3,
                "/cases/*/scope" => 3,
                "/cases/*/data_epoch" => 3,
                "/cases/*/nonce_seed_label" => 3,
                "/cases/0/msg_id_seed_label",
                "/cases/1/msg_id_seed_label",
                "/cases/0/record_version",
                "/cases/0/record_status",
                "/cases/0/message/accepted_at",
                "/cases/0/message/body/board",
                "/cases/0/message/body/due",
                "/cases/0/message/body/task",
                "/cases/0/message/created_at",
                "/cases/0/message/kind",
                "/cases/0/message/refs",
                "/cases/1/record_version",
                "/cases/1/message/accepted_at",
                "/cases/1/message/body/expires_at",
                "/cases/1/message/body/tasks/0",
                "/cases/1/message/body/tasks/1",
                "/cases/1/message/body/version",
                "/cases/1/message/created_at",
                "/cases/1/message/kind",
                "/cases/1/message/refs",
            ],
        ),
        (
            "signatures.json",
            super::signatures::test_vectors_signatures,
            patterns![
                "/description",
                "/signatures/*/signer" => 23,
                "/rejections/*/name" => 8,
                "/rejections/*/why" => 8,
                "/rejections/*/reason" => 8,
                "/rejections/*/lenient_accepts" => 8,
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
            patterns![
                "/documents/*/name" => 30,
                "/documents/*/signer" => 30,
                "/documents/0/expires_at",
                "/documents/0/issued_at",
                "/documents/1/expires_at",
                "/documents/1/issued_at",
                "/documents/2/expires_at",
                "/documents/2/issued_at",
                "/documents/3/expires_at",
                "/documents/3/issued_at",
                "/documents/4/accepts/*" => 6,
                "/documents/4/expires_at",
                "/documents/4/protocols/tasks/features/board_kinds/*" => 2,
                "/documents/4/protocols/tasks/public_boards",
                "/documents/4/updated_at",
                "/documents/5/accepts/*" => 6,
                "/documents/5/expires_at",
                "/documents/5/protocols/tasks/features/board_kinds/*" => 2,
                "/documents/5/protocols/tasks/public_boards",
                "/documents/5/updated_at",
                "/documents/6/accepts/*" => 11,
                "/documents/6/expires_at",
                "/documents/6/protocols/tasks/features/board_kinds/*" => 2,
                "/documents/6/protocols/tasks/public_boards",
                "/documents/6/updated_at",
                "/documents/7/accepts/*" => 10,
                "/documents/7/expires_at",
                "/documents/7/protocols/tasks/features/board_kinds/*" => 2,
                "/documents/7/protocols/tasks/public_boards/home",
                "/documents/7/updated_at",
                "/documents/12/data_epoch",
                "/documents/12/distrust_from",
                "/documents/12/listed_apps/*" => 3,
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
                "/documents/15/permissions/*" => 4,
                "/documents/15/scopes/*" => 2,
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
                "/documents/24/accepts/*" => 7,
                "/documents/24/expires_at",
                "/documents/24/protocols/tasks/features/board_kinds/*" => 2,
                "/documents/24/protocols/tasks/public_boards",
                "/documents/24/updated_at",
                "/documents/25/issued_at",
                "/documents/26/generation",
                "/documents/26/version",
                "/documents/27/expires_at",
                "/documents/27/issued_at",
                "/documents/28/accepts/*" => 6,
                "/documents/28/expires_at",
                "/documents/28/protocols/tasks/features/board_kinds/*" => 2,
                "/documents/28/protocols/tasks/public_boards",
                "/documents/28/updated_at",
                "/documents/29/version",
                "/auth_request/client_id",
                "/auth_request/client_seed_label",
                "/auth_request/secret_seed_label",
                "/approval/keyed_scopes/*" => 3,
                "/approval/seal_seed_label",
                "/approval/rejections/*/step",
                "/approval/rejections/*/error",
                "/approval/rejections/*/last_epoch",
                "/approval/rejections/*/seal_seed_label",
                "/identity_rejections/cases/*/name" => 2,
                "/identity_rejections/cases/*/error" => 2,
                "/app_record_conflict/conflict",
                "/app_record_conflict/kept",
                "/app_record_conflict/updated_at",
                "/app_record_conflict/records/*/board_kind" => 2,
                "/permission_rejections/cases/*/name" => 3,
                "/permission_rejections/cases/*/reason" => 3,
                "/permission_rejections/cases/2/extra_permission",
                "/scope_rule/accepted/*/extra_scopes/*" => 30,
                "/scope_rule/refused/*/reason" => 5,
                "/scope_rule/refused/*/extra_scopes/*" => 34,
                "/app_record_protocols/accepted/0/protocol",
                "/app_record_protocols/accepted/0/member/items/0",
                "/app_record_protocols/accepted/0/member/items/1/deep",
                "/app_record_protocols/accepted/0/member/level",
                "/app_record_protocols/accepted/1/protocol",
                "/app_record_protocols/accepted/1/member",
                "/app_record_protocols/refused/*/reason" => 8,
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
            patterns![
                "/account_created",
                "/keyed_scopes/*" => 5,
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
                "/cases/*/name" => 8,
                "/cases/*/notify" => 8,
                "/cases/*/cek_seed_label" => 8,
                "/cases/*/nonce_seed_label" => 8,
                "/cases/*/recipients/*/app" => 16,
                "/cases/*/recipients/*/ikm_e_seed_label" => 16,
                "/cases/2/resend_count",
                "/cases/3/resend_count",
                "/cases/4/resend_count",
                "/cases/5/resend_count",
                "/cases/6/resend_count",
                "/cases/7/resend_count",
                "/bucket_fit/*/bucket" => 8,
                "/bucket_fit/*/plaintext_len" => 8,
                "/bucket_fit/*/recipients" => 8,
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
                "/key_bundle_rejections/cases/*/name" => 4,
                "/key_bundle_rejections/cases/*/reason" => 4,
                "/key_bundle_rejections/cases/*/seal_seed_label" => 4,
                "/key_bundle_rejections/cases/0/scope",
                "/key_bundle_rejections/cases/1/key_seed_label",
                "/key_bundle_rejections/cases/2/scope",
                "/signer_handover/app",
                "/signer_handover/parts/*/seal_seed_label" => 2,
                "/signer_backup/seal_seed_label",
                "/signer_handover_rejections/cases/*/name" => 3,
                "/signer_handover_rejections/cases/*/reason" => 3,
            ],
        ),
        (
            "chain.json",
            chain_cases,
            patterns![
                "/generation",
                "/items/*/seq" => 8,
                "/items/*/source" => 8,
                "/items/*/server_time" => 8,
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
                "/peer_admission/items/*/seq" => 8,
                "/peer_admission/items/*/server_time" => 8,
                "/peer_admission/items/*/action" => 8,
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
                "/rejections/*/name" => 5,
                "/rejections/name=gap/error",
                "/rejections/name=forked head/error",
                "/rejections/0/item_sources/*" => 3,
                "/rejections/1/item_sources/*" => 2,
                "/rejections/2/item_sources/*" => 4,
                "/rejections/2/gap_ms",
                "/rejections/3/stubs",
                "/rejections/4/after",
                "/rejections/4/at_seq",
                "/rejections/4/hash_seed_label",
                "/batch_id_window/*/name" => 3,
                "/batch_id_window/*/outcome" => 3,
                "/batch_id_window/outcome=accepted/error" => 2,
                "/batch_id_window/*/gap_ms" => 3,
                "/batch_id_window/*/item_sources/*" => 12,
                "/signed_heads/*/at_seq" => 2,
                "/transition_proofs/*/at_seq" => 8,
            ],
        ),
        (
            "http.json",
            http_cases,
            patterns![
                "/received_cases/*/code" => 4,
                "/received_cases/*/fault" => 4,
                "/received_cases/*/headers/switch-server-time" => 4,
                "/received_cases/*/message" => 4,
                "/received_cases/*/name" => 4,
                "/received_cases/*/request" => 4,
                "/received_cases/*/service_account" => 4,
                "/received_cases/*/status" => 4,
                "/received_cases/fault=duplicate header/header",
                "/received_cases/fault=empty header/header",
                "/requests/*/account" => 18,
                "/requests/*/caller" => 18,
                "/requests/*/headers/switch-timestamp" => 18,
                "/requests/*/method" => 18,
                "/requests/*/name" => 18,
                "/requests/*/origin" => 18,
                "/requests/*/resource" => 18,
                "/requests/resource=directory/certificate",
                "/requests/resource=enroll/document",
                "/requests/resource=erase/document" => 2,
                "/requests/resource=feed/after" => 2,
                "/requests/resource=feed/limit" => 2,
                "/requests/resource=feed/wait",
                "/requests/resource=identity/document" => 3,
                "/requests/resource=identity/generation",
                "/requests/resource=identity/previous_document" => 3,
                "/requests/resource=identity/service_seed_label",
                "/requests/resource=identity/signer_seed_label",
                "/requests/resource=identity/version" => 2,
                "/requests/resource=inbox/apps_version",
                "/requests/resource=inbox/certificate",
                "/requests/resource=inbox/invite_seed_label",
                "/requests/resource=inbox/message/body/board",
                "/requests/resource=inbox/message/body/due",
                "/requests/resource=inbox/message/body/task",
                "/requests/resource=inbox/message/created_at",
                "/requests/resource=inbox/message/kind",
                "/requests/resource=inbox/message/msg_id_seed_label",
                "/requests/resource=inbox/message/notify",
                "/requests/resource=inbox/message/recipient",
                "/requests/resource=inbox/message/refs",
                "/requests/resource=inbox/message/seal_seed_label",
                "/requests/resource=inbox/message/sender",
                "/requests/resource=ops/operations/*" => 2,
                "/requests/resource=peers/certificate" => 2,
                "/requests/resource=peers/document" => 2,
                "/requests/resource=peers/enable_connect_requests",
                "/responses/*/answer" => 23,
                "/responses/*/headers/switch-server-time" => 23,
                "/responses/*/name" => 23,
                "/responses/*/request" => 23,
                "/responses/*/service_account" => 23,
                "/responses/*/status" => 23,
                "/responses/answer=admission history/deny",
                "/responses/answer=admission history/flagged",
                "/responses/answer=admission history/head_source",
                "/responses/answer=admission history/invite_codes",
                "/responses/answer=directory/apps/*" => 3,
                "/responses/answer=directory/apps_version",
                "/responses/answer=directory/directory_version",
                "/responses/answer=directory/document",
                "/responses/answer=directory/known_version",
                "/responses/answer=enrollment/limits/app_limit",
                "/responses/answer=enrollment/limits/max_batch",
                "/responses/answer=enrollment/limits/max_envelope",
                "/responses/answer=enrollment/limits/max_import_bytes",
                "/responses/answer=enrollment/limits/max_sealed_value",
                "/responses/answer=enrollment/limits/quota_bytes",
                "/responses/answer=enrollment/limits/record_quota_bytes",
                "/responses/answer=feed/cursor" => 3,
                "/responses/answer=feed/head_source" => 3,
                "/responses/answer=feed/items",
                "/responses/answer=feed/items/*/source" => 8,
                "/responses/answer=feed/items/source=chain/operation" => 4,
                "/responses/answer=feed/items/source=message/accepted_at" => 2,
                "/responses/answer=feed/items/source=message/entry_seed_label" => 2,
                "/responses/answer=feed/items/source=message/invite_seed_label",
                "/responses/answer=feed/items/source=message/message/body/task" => 2,
                "/responses/answer=feed/items/source=message/message/created_at" => 2,
                "/responses/answer=feed/items/source=message/message/kind" => 2,
                "/responses/answer=feed/items/source=message/message/msg_id_seed_label" => 2,
                "/responses/answer=feed/items/source=message/message/notify" => 2,
                "/responses/answer=feed/items/source=message/message/recipient" => 2,
                "/responses/answer=feed/items/source=message/message/refs" => 2,
                "/responses/answer=feed/items/source=message/message/seal_seed_label" => 2,
                "/responses/answer=feed/items/source=message/message/sender" => 2,
                "/responses/answer=feed/items/source=message/seq" => 2,
                "/responses/answer=feed/items/source=request/accepted_at",
                "/responses/answer=feed/items/source=request/entry_seed_label",
                "/responses/answer=feed/items/source=request/request",
                "/responses/answer=feed/items/source=request/seq",
                "/responses/answer=feed/more" => 3,
                "/responses/answer=feed/scanned_through" => 3,
                "/responses/answer=handover/head_source",
                "/responses/answer=known version/document",
                "/responses/answer=missing service key/code",
                "/responses/answer=missing service key/head_source",
                "/responses/answer=missing service key/message",
                "/responses/answer=missing service key/proof_generations/*",
                "/responses/answer=not hosted/code",
                "/responses/answer=not hosted/message",
                "/responses/answer=not hosted/read_account",
                "/responses/answer=not hosted/read_origin",
                "/responses/answer=peers/deny",
                "/responses/answer=peers/flagged",
                "/responses/answer=peers/head_source",
                "/responses/answer=peers/invite_codes",
                "/responses/answer=peers/peers/*/account" => 2,
                "/responses/answer=peers/peers/*/identity_seed_label",
                "/responses/answer=peers/peers/*/kept" => 3,
                "/responses/answer=peers/peers/*/reply" => 3,
                "/responses/answer=peers/peers/reply=service/at",
                "/responses/answer=peers/peers/reply=service/invite_seed_label",
                "/responses/answer=peers/peers/reply=service/last_used",
                "/responses/answer=peers/peers/reply=wallet/at",
                "/responses/answer=proofs/head_source",
                "/responses/answer=public identity/document" => 2,
                "/responses/answer=public identity/freeze",
                "/responses/answer=public identity/headers/cache-control" => 2,
                "/responses/answer=public identity/read_account" => 2,
                "/responses/answer=public identity/read_origin" => 2,
                "/responses/answer=rate limit/code",
                "/responses/answer=rate limit/message",
                "/responses/answer=rate limit/retry_after",
                "/responses/answer=stale delivery/code",
                "/responses/answer=stale delivery/document",
                "/responses/answer=stale delivery/head_source",
                "/responses/answer=stale delivery/message",
                "/responses/answer=stale erasure/code",
                "/responses/answer=stale erasure/message",
                "/responses/answer=stale key/added_apps/*",
                "/responses/answer=stale key/apps_version",
                "/responses/answer=stale key/code",
                "/responses/answer=stale key/message",
                "/responses/answer=stale key/not_current_apps",
                "/responses/answer=stale key/receive_apps/*",
                "/responses/answer=stale key/unknown_kid_seed_labels",
                "/responses/answer=stale peer/code",
                "/responses/answer=stale peer/document",
                "/responses/answer=stale peer/message",
                "/responses/answer=stored handover/head_source",
                "/saved_head/hash_seed_label",
                "/saved_head/position",
                "/webhook/account",
                "/webhook/handle_seed_label",
                "/webhook/nonce_seed_label",
                "/webhook/relay_url",
                "/webhook/timestamp",
            ],
        ),
        (
            "claims.json",
            super::claims::test_vectors_claims,
            patterns![
                "/apps/A/accepts",
                "/apps/A/bundle_seed_label",
                "/apps/A/expires_at",
                "/apps/A/inbox_permissions/*" => 3,
                "/apps/A/issued_at",
                "/apps/A/protocols",
                "/apps/A/receive_n",
                "/apps/A/receive_seed_label",
                "/apps/A/record_expires_at",
                "/apps/A/scopes/*",
                "/apps/A/signing_seed_label",
                "/apps/A/updated_at",
                "/apps/B/accepts",
                "/apps/B/bundle_seed_label",
                "/apps/B/expires_at",
                "/apps/B/inbox_permissions/*" => 3,
                "/apps/B/issued_at",
                "/apps/B/protocols",
                "/apps/B/receive_n",
                "/apps/B/receive_seed_label",
                "/apps/B/record_expires_at",
                "/apps/B/scopes/*",
                "/apps/B/signing_seed_label",
                "/apps/B/updated_at",
                "/apps/C/accepts",
                "/apps/C/bundle_seed_label",
                "/apps/C/expires_at",
                "/apps/C/inbox_permissions/*" => 3,
                "/apps/C/issued_at",
                "/apps/C/protocols",
                "/apps/C/receive_n",
                "/apps/C/receive_seed_label",
                "/apps/C/record_expires_at",
                "/apps/C/scopes/*",
                "/apps/C/signing_seed_label",
                "/apps/C/updated_at",
                "/apps/D/accepts",
                "/apps/D/bundle_seed_label",
                "/apps/D/expires_at",
                "/apps/D/inbox_permissions/*" => 3,
                "/apps/D/issued_at",
                "/apps/D/protocols",
                "/apps/D/receive_n",
                "/apps/D/receive_seed_label",
                "/apps/D/record_expires_at",
                "/apps/D/scopes/*",
                "/apps/D/signing_seed_label",
                "/apps/D/updated_at",
                "/apps/E/accepts",
                "/apps/E/bundle_seed_label",
                "/apps/E/expires_at",
                "/apps/E/inbox_permissions/*",
                "/apps/E/issued_at",
                "/apps/E/protocols",
                "/apps/E/receive_n",
                "/apps/E/receive_seed_label",
                "/apps/E/record_expires_at",
                "/apps/E/scopes/*",
                "/apps/E/signing_seed_label",
                "/apps/E/updated_at",
                "/attempt_seed_labels/a1",
                "/attempt_seed_labels/b1",
                "/attempt_seed_labels/b2",
                "/attempt_seed_labels/c1",
                "/attempt_seed_labels/c2",
                "/attempt_seed_labels/c3",
                "/attempt_seed_labels/d1",
                "/attempt_seed_labels/e1",
                "/claim_keys/O1",
                "/claim_keys/O10",
                "/claim_keys/O11",
                "/claim_keys/O2",
                "/claim_keys/O3",
                "/claim_keys/O4",
                "/claim_keys/O5",
                "/claim_keys/O6",
                "/claim_keys/O7",
                "/claim_keys/O8",
                "/claim_keys/O9",
                "/evidence_seed_labels/r1",
                "/evidence_seed_labels/r2",
                "/generation",
                "/identity_seed_label",
                "/quota/attempt_seed_labels/b4",
                "/quota/attempt_seed_labels/q1",
                "/quota/attempt_seed_labels/q2",
                "/quota/attempt_seed_labels/q3",
                "/quota/attempt_seed_labels/q4",
                "/quota/claim_keys/Q1",
                "/quota/claim_keys/Q2",
                "/quota/claim_keys/Q3",
                "/quota/claim_keys/Q4",
                "/quota/limits/claim_share_percent",
                "/quota/limits/max_claims",
                "/quota/limits/open_attempts_per_app",
                "/quota/steps/*/action" => 8,
                "/quota/steps/*/expect_attempts/claim/*/attempt" => 6,
                "/quota/steps/*/expect_attempts/claim/*/owner_app" => 6,
                "/quota/steps/*/expect_attempts/claim/*/resolved_by_app" => 2,
                "/quota/steps/*/expect/claim/attempts/*/duplicate" => 6,
                "/quota/steps/*/expect/claim/attempts/*/opened_at" => 6,
                "/quota/steps/*/expect/claim/attempts/*/orphan_after" => 6,
                "/quota/steps/*/expect/claim/attempts/*/orphaned" => 6,
                "/quota/steps/*/expect/claim/attempts/*/outcome" => 6,
                "/quota/steps/*/expect/claim/attempts/*/possibly_duplicate" => 6,
                "/quota/steps/*/expect/claim/divergent" => 6,
                "/quota/steps/*/expect/claim/next_possibly_duplicate" => 6,
                "/quota/steps/*/expect/claim/state" => 6,
                "/quota/steps/*/expect/claim/step" => 6,
                "/quota/steps/*/expect/claim/tombstone" => 6,
                "/quota/steps/*/expect/code" => 2,
                "/quota/steps/*/expect/current/limit" => 2,
                "/quota/steps/*/expect/status" => 8,
                "/quota/steps/*/n" => 8,
                "/quota/steps/action=write/app" => 8,
                "/quota/steps/action=write/claim_key" => 8,
                "/quota/steps/action=write/entry/attempt" => 8,
                "/quota/steps/action=write/entry/basis" => 2,
                "/quota/steps/action=write/entry/expected_step" => 8,
                "/quota/steps/action=write/entry/orphan_after" => 6,
                "/quota/steps/action=write/entry/type" => 8,
                "/start_time",
                "/steps/*/action" => 69,
                "/steps/*/expect_attempts/claim/*/attempt" => 41,
                "/steps/*/expect_attempts/claim/*/owner_app" => 41,
                "/steps/*/expect_attempts/claim/*/resolved_by_app" => 26,
                "/steps/*/expect/claim/attempts/*/duplicate" => 41,
                "/steps/*/expect/claim/attempts/*/opened_at" => 41,
                "/steps/*/expect/claim/attempts/*/orphan_after" => 41,
                "/steps/*/expect/claim/attempts/*/orphaned" => 41,
                "/steps/*/expect/claim/attempts/*/outcome" => 41,
                "/steps/*/expect/claim/attempts/*/possibly_duplicate" => 41,
                "/steps/*/expect/claim/deadline" => 11,
                "/steps/*/expect/claim/divergent" => 33,
                "/steps/*/expect/claim/next_possibly_duplicate" => 33,
                "/steps/*/expect/claim/state" => 33,
                "/steps/*/expect/claim/step" => 33,
                "/steps/*/expect/claim/tombstone" => 33,
                "/steps/*/expect/code" => 26,
                "/steps/*/expect/current" => 10,
                "/steps/*/expect/current/claim",
                "/steps/*/expect_attempts/current/*/attempt" => 16,
                "/steps/*/expect_attempts/current/*/owner_app" => 16,
                "/steps/*/expect_attempts/current/*/resolved_by_app" => 10,
                "/steps/*/expect/current/claim/attempts/*/duplicate" => 16,
                "/steps/*/expect/current/claim/attempts/*/opened_at" => 16,
                "/steps/*/expect/current/claim/attempts/*/orphan_after" => 16,
                "/steps/*/expect/current/claim/attempts/*/orphaned" => 16,
                "/steps/*/expect/current/claim/attempts/*/outcome" => 16,
                "/steps/*/expect/current/claim/attempts/*/possibly_duplicate" => 16,
                "/steps/*/expect/current/claim/deadline" => 3,
                "/steps/*/expect/current/claim/divergent" => 14,
                "/steps/*/expect/current/claim/next_possibly_duplicate" => 14,
                "/steps/*/expect/current/claim/state" => 14,
                "/steps/*/expect/current/claim/step" => 14,
                "/steps/*/expect/current/claim/tombstone" => 14,
                "/steps/*/expect/current/claim_step/step",
                "/steps/*/expect/current/server_time",
                "/steps/*/expect/proofs" => 3,
                "/steps/*/expect/status" => 64,
                "/steps/*/n" => 69,
                "/steps/action=advance/seconds" => 5,
                "/steps/action=app_put/app" => 2,
                "/steps/action=app_put/batch_seed_label" => 2,
                "/steps/action=app_put/variant" => 2,
                "/steps/action=noop_batch/app" => 4,
                "/steps/action=noop_batch/batch_seed_label" => 4,
                "/steps/action=noop_batch/condition_step" => 4,
                "/steps/action=noop_batch/cursor" => 4,
                "/steps/action=noop_batch/cursor_position" => 3,
                "/steps/action=noop_batch/condition_claim" => 3,
                "/steps/action=read/app" => 8,
                "/steps/action=read/claim_key" => 8,
                "/steps/action=revoke/app" => 2,
                "/steps/action=write/app" => 48,
                "/steps/action=write/claim_key" => 48,
                "/steps/action=write/entry/attempt" => 48,
                "/steps/action=write/entry/basis" => 13,
                "/steps/action=write/entry/deadline_after_s" => 7,
                "/steps/action=write/entry/evidence" => 3,
                "/steps/action=write/entry/expected_step" => 48,
                "/steps/action=write/entry/orphan_after" => 20,
                "/steps/action=write/entry/type" => 48,
                "/steps/variant=equal_time/protocols/tasks/public_boards/home",
            ],
        ),
        (
            "export.json",
            export_cases,
            patterns![
                "/manifest/signer",
                "/manifest/freeze_at",
                "/manifest/directory_version",
                "/manifest/apps_version",
                "/manifest/keys_through",
                "/manifest/wallet_added_at",
                "/manifest/wallet_cursor",
                "/pending_entry/seq",
                "/pending_entry/invite_seq",
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
                "/claim_rejections/*/name" => 6,
                "/claim_rejections/*/code" => 6,
                "/claim_rejections/4/error",
                "/claim_rejections/5/error",
                "/claim_rejections/0/creator_app",
                "/claim_rejections/1/earlier_ms",
                "/claim_rejections/3/batch_seed_label",
                "/claim_rejections/4/batch_seed_label",
                "/claim_rejections/*/status" => 6,
                "/record_rejections/*/name" => 3,
                "/record_rejections/*/status" => 3,
                "/record_rejections/*/code" => 3,
                "/record_rejections/1/signing_account",
            ],
        ),
    ]
}

/// Authored explanations and captions that do not choose wire values or expected outcomes.
fn annotations(file: &str) -> &'static [Pattern] {
    match file {
        "identifiers.json" => patterns!["/description"],
        "operations.json" => patterns![
            "/ops_request/note",
            "/record_current/name",
            "/record_scopes/cases/*/name" => 8,
            "/attempt_deadlines/description",
            "/attempt_deadlines/cases/*/name" => 5,
            "/deny_room/cases/*/name" => 3,
            "/integer_bounds/description",
            "/integer_bounds/cases/*/name" => 6,
            "/permanent_policies/description",
            "/permanent_policies/rejections/*/name" => 11,
            "/shape_rejections/description",
            "/unknown_members/description",
            "/unknown_members/cases/*/name" => 9,
            "/unknown_members/batch_entries/description",
            "/unknown_members/batch_entries/cases/*/name" => 2,
        ],
        "http.json" => patterns![
            "/description",
            "/received_cases/*/signer" => 4,
            "/requests/*/signer" => 18,
            "/responses/*/signer" => 23,
        ],
        "claims.json" => patterns![
            "/description",
            "/quota/description",
            "/quota/steps/action=write/note" => 8,
            "/quota/steps/action=write/row" => 8,
            "/steps/action=app_put/note" => 2,
            "/steps/action=noop_batch/note" => 4,
            "/steps/action=read/note" => 8,
            "/steps/action=write/note" => 48,
            "/steps/action=write/row" => 48,
        ],
        "chain.json" => patterns![
            "/record_delete/description",
            "/transition_proofs/*/name" => 8,
            "/peer_admission/description",
            "/rejections/*/rule" => 5,
        ],
        "export.json" => patterns![
            "/manifest/name",
            "/peer_admission/description",
            "/pending_entry/description",
            "/record_rejections/*/rule" => 3,
            "/claim_rejections/*/rule" => 6,
        ],
        "documents.json" => patterns![
            "/app_record_conflict/description",
            "/app_record_protocols/description",
            "/auth_request/description",
            "/identity_rejections/description",
            "/permission_rejections/description",
            "/scope_rule/description",
            "/approval/rejections/*/name",
            "/approval/rejections/*/rule",
            "/identity_rejections/cases/*/rule" => 2,
            "/scope_rule/accepted/*/name" => 2,
            "/scope_rule/refused/*/name" => 5,
            "/app_record_protocols/accepted/*/name" => 2,
            "/app_record_protocols/refused/0/name",
            "/app_record_protocols/refused/1/name",
            "/app_record_protocols/refused/2/name",
            "/app_record_protocols/refused/3/name",
            "/app_record_protocols/refused/4/name",
            "/app_record_protocols/refused/5/name",
            "/app_record_protocols/refused/6/name",
        ],
        "envelopes.json" => patterns![
            "/key_bundle/note",
            "/reduction_key_bundle/note",
            "/rejections/2/note",
            "/signer_handover_rejections/description",
            "/key_bundle_rejections/cases/*/change" => 4,
        ],
        _ => &[],
    }
}

/// Require the authored text on each case, including each element of a captioned array.
pub(super) fn check_annotations(name: &str, file: &Value) {
    for &(pattern, _) in annotations(name) {
        let (parent, member) = pattern.rsplit_once('/').unwrap();
        let check = |entry: &Value| {
            assert!(
                entry[member].as_str().is_some_and(|s| !s.trim().is_empty()),
                "{name}: missing text at {pattern}"
            );
        };
        if let Some((array, selector)) = parent.rsplit_once('/')
            && let Some((field, choice)) = selector.split_once('=')
        {
            for entry in file
                .pointer(array)
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .filter(|entry| entry[field] == choice)
            {
                check(entry);
            }
        } else if let Some(array) = parent.strip_suffix("/*") {
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
    file_places(name, &PLACES.take().unwrap())
}

fn file_places(name: &str, places: &Places) -> BTreeSet<String> {
    places
        .iter()
        .filter(|(file, _)| file == name)
        .map(|(_, path)| path.clone())
        .collect()
}

/// Leaves outside generated subtrees and the explicitly declared fixture patterns.
fn unclaimed_leaves(
    name: &str,
    file: &Value,
    inputs: &[Pattern],
    skip: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut claimed = BTreeSet::new();
    let declared = inputs
        .iter()
        .map(|p| (p, "the input patterns in fixtures()"))
        .chain(annotations(name).iter().map(|p| (p, "annotations()")));
    for (&(pattern, count), list) in declared {
        let mut matches = BTreeSet::new();
        match_pattern(file, "", pattern, &mut matches);
        assert_eq!(
            matches.len(),
            count,
            "{name}: {pattern} in {list} of generation.rs declares {count} leaves and matched \
             {matches:?}"
        );
        claimed.extend(matches);
    }
    let mut unclaimed = BTreeSet::new();
    visit_leaves(file, "", skip, &mut |pointer, _| {
        if !claimed.contains(pointer) {
            unclaimed.insert(pointer.to_owned());
        }
    });
    unclaimed
}

fn check_coverage((name, verify, inputs): Fixture) -> BTreeSet<String> {
    unclaimed_leaves(name, &load(name), inputs, &reported_places(name, verify))
}

#[test]
fn test_vectors_every_member_is_an_input_or_generated() {
    for &fixture in fixtures() {
        let paths = check_coverage(fixture);
        assert!(
            paths.is_empty(),
            "{}: unclaimed leaves: {paths:?}",
            fixture.0
        );
    }
}

#[test]
fn test_vectors_coverage_rejects_stray_case_members() {
    for (name, sibling) in [
        ("keys.json", "/apps/name=wallet/receive_key/seed_label"),
        ("identifiers.json", "/invite_code/code_hash"),
        (
            "operations.json",
            "/permanent_policies/rejections/*/signed/sig",
        ),
        (
            "identifiers.json",
            "/policies/name=share_counts, create and delete scopes and permanent/policy_hash",
        ),
        ("operations.json", "/record_scopes/cases/*/signed/sig"),
        ("encoding.json", "/base64url/valid/*/seed_label"),
        ("sealed.json", "/cases/*/nonce_seed_label"),
        ("signatures.json", "/signatures/*/signer"),
        ("documents.json", "/documents/name=wallet certificate/name"),
        ("envelopes.json", "/cases/name=1 recipient(s), 1 KiB/name"),
        ("chain.json", "/items/source=record.put update/source"),
        ("export.json", "/record_rejections/name=no proof/record/key"),
        ("claims.json", "/steps/action=write/expect/claim/state"),
        (
            "http.json",
            &format!("/requests/resource=inbox/headers/{}", header::TIMESTAMP),
        ),
        (
            "http.json",
            &format!("/webhook/headers/{}", header::SIGNATURE),
        ),
    ] {
        let mut file = load(name);
        let mut matches = BTreeSet::new();
        match_pattern(&file, "", sibling, &mut matches);
        let first = matches.first().expect(sibling);
        let (parent, _) = first.rsplit_once('/').unwrap();
        file.pointer_mut(parent).unwrap()["stray"] = true.into();
        let changed = BTreeMap::from([(name.to_owned(), file)]);
        CHANGED.set(changed.clone());
        let stray = check_coverage(fixture(name));
        CHANGED.with_borrow_mut(BTreeMap::clear);
        let path = format!("{parent}/stray");
        assert_eq!(stray, BTreeSet::from([path]), "{name}");
        assert_eq!(
            regenerate(false, changed),
            Err(format!("{name}: unclaimed leaves: {stray:?}"))
        );
    }
}

#[test]
fn test_vectors_http_header_patterns() {
    let inputs = fixture("http.json").2;
    for (group, header) in [
        ("requests", header::TIMESTAMP),
        ("responses", header::SERVER_TIME),
        ("received_cases", header::SERVER_TIME),
    ] {
        let path = format!("/{group}/*/headers/{header}");
        assert!(inputs.iter().any(|(pattern, _)| *pattern == path), "{path}");
    }
}

#[test]
fn test_vectors_deny_room_requires_arrays() {
    // The writer emits each array whole: an object in its place is replaced by the array, so
    // a published file holding the object fails check mode's byte comparison.
    let name = "operations.json";
    let mut file = load(name);
    let held = &mut file["deny_room"]["cases"][0]["held"];
    *held = serde_json::json!({"0": held[0]});
    let changed = file.clone();
    let (staged, _) = stage_covered(Files::from([(name.to_owned(), file)]));
    let emitted = &staged[name]["deny_room"]["cases"][0]["held"];
    assert!(emitted.is_array(), "{emitted}");
    assert_eq!(staged[name], load(name));
    assert!(!unchanged(&rendered(&changed), &staged[name]));
}

#[test]
fn test_vectors_check_mode_compares_bytes() {
    let name = "keys.json";
    let file = load(name);
    let published = fs::read(spec_vectors_dir().join(name)).unwrap();
    assert!(unchanged(&published, &file));
    // The same JSON in another layout, or without its final newline, is refused.
    let mut compact = serde_json::to_vec(&file).unwrap();
    compact.push(b'\n');
    assert!(!unchanged(&compact, &file));
    assert!(!unchanged(&published[..published.len() - 1], &file));
}

#[test]
#[should_panic(expected = "base writer for")]
fn test_vectors_permanent_rejection_requires_base_writer() {
    let name = "operations.json";
    let mut file = load(name);
    file["permanent_policies"]["rejections"][0]["writer"] = "signer".into();
    stage_covered(Files::from([(name.to_owned(), file)]));
}

/// A valid input on an extra case must change the count of the pattern that admits it.
#[test]
#[should_panic(
    expected = "http.json: /requests/resource=feed/wait in the input patterns in fixtures()"
)]
fn test_vectors_coverage_rejects_misplaced_input() {
    let mut file = load("http.json");
    let feed = file["requests"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| r["resource"] == "feed" && r.get("wait").is_none())
        .unwrap();
    feed["wait"] = 1.into();
    unclaimed_leaves("http.json", &file, fixture("http.json").2, &BTreeSet::new());
}

/// Only the declared inputs and captions survive blanking the published outputs.
#[test]
fn test_vectors_generated_leaves_rebuild_from_inputs() {
    let mut expected = BTreeMap::new();
    let mut blanked = Files::new();
    for &(name, _, inputs) in fixtures() {
        let mut file = load(name);
        let leaves = unclaimed_leaves(name, &file, inputs, &BTreeSet::new());
        for path in &leaves {
            let value = file.pointer_mut(path).unwrap();
            assert_ne!(value, "unset", "{name}: {path}");
            *value = Value::String("unset".into());
        }
        expected.insert(name, leaves);
        blanked.insert(name.to_owned(), file);
    }
    let (files, places) = stage_covered(blanked);
    for &(name, _, _) in fixtures() {
        let rebuilt = &files[name];
        let published = load(name);
        let mut emitted = BTreeSet::new();
        for path in file_places(name, &places) {
            visit_leaves(
                rebuilt.pointer(&path).unwrap(),
                &path,
                &BTreeSet::new(),
                &mut |leaf, _| {
                    emitted.insert(leaf.to_owned());
                },
            );
        }
        assert_eq!(emitted, expected[name], "{name}: emitted leaves");
        for path in emitted {
            assert_eq!(
                rebuilt.pointer(&path),
                published.pointer(&path),
                "{name}: {path}"
            );
        }
        assert_eq!(rebuilt, &published, "{name}");
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
