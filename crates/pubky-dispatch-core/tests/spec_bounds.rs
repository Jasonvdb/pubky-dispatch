//! The size bounds the wire format states, rebuilt from the core's own types and limits, so a
//! change to a name, a kind, a scope rule or a permission can't leave a stated bound behind.
//! Each test builds the largest value a stated bound counts, or adds up what it is made
//! of, and compares the result with the number the wire format gives.

// The helpers read the fixed specification text, where a failure is a test failure: the
// workspace's no-panic lints don't apply to them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pubky_dispatch_core::export::MAX_CHUNK_OVERHEAD;
use pubky_dispatch_core::json::MAX_INT;
use pubky_dispatch_core::keys::{AppKeys, IdentityKey, ReceiveKey};
use pubky_dispatch_core::records::{
    AppCert, AppCertBody, MAX_CERT_BODY_BYTES, MAX_CERT_LIFETIME_MS, MAX_HANDOVER_ENVELOPES,
    MAX_RECEIVE_KEY_BODY_BYTES, ReceiveKeyBody, ReceiveKeyRecord, SuiteKey,
};
use pubky_dispatch_core::scopes::{MAX_SCOPE_PART, MAX_SCOPES, Permission};
use pubky_dispatch_core::sig::SignedDoc;
use pubky_dispatch_core::time::MAX_TIME_MS;

const WIRE: &str = include_str!("../../../spec/wire-format.md");
const CONFIGURATION: &str = include_str!("../../../docs/configuration.md");

/// The number `text` states right after `before`, digits with thousands commas.
fn stated_in(text: &str, before: &str) -> usize {
    let at = text
        .find(before)
        .unwrap_or_else(|| panic!("the text no longer says {before:?}"));
    let digits: String = text[at + before.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == ',')
        .filter(char::is_ascii_digit)
        .collect();
    digits.parse().unwrap()
}

/// The number the wire format states right after `before`.
fn stated(before: &str) -> usize {
    stated_in(WIRE, before)
}

/// The number in the first row of a table of the wire format that starts with `start` and
/// gives a number next.
fn table_row(start: &str) -> usize {
    WIRE.lines()
        .filter_map(|line| line.strip_prefix(start))
        .find(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        .map(|rest| {
            rest.chars()
                .take_while(|c| c.is_ascii_digit() || *c == ',')
                .filter(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .unwrap()
        })
        .unwrap_or_else(|| panic!("no table row starts with {start:?} and a number"))
}

/// `n` with thousands commas, as the specification writes numbers.
fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The body of a certificate for an app with `scopes`, every permission, the given times and
/// suite keys.
fn cert_body(
    app: &AppKeys,
    scopes: Vec<String>,
    times: (u64, u64),
    suite_keys: Option<Vec<SuiteKey>>,
) -> AppCertBody {
    let mut body = AppCertBody::new(
        IdentityKey::from_secret([1; 32]).public(),
        app.signing_public(),
        app.bundle_public(),
        scopes,
        &Permission::ALL,
        times.0,
        times.1,
    );
    body.suite_keys = suite_keys;
    body
}

/// An app and a certificate the identity issues it, with `scopes` and the given times.
fn cert(scopes: Vec<String>, times: (u64, u64)) -> (AppKeys, AppCert) {
    let app = AppKeys::from_secrets([2; 32], [3; 32]);
    let body = cert_body(&app, scopes, times, None);
    let cert = AppCert::issue(&IdentityKey::from_secret([1; 32]), body).unwrap();
    (app, cert)
}

/// The largest certificate body the rules count (Dispatch wire 3.1, 3.12, 10.3): the most
/// scopes, each of the longest form `name:<sub>`, every permission, the latest times, each
/// with three fraction digits, and the given suite keys.
fn largest_cert_body(suite_keys: Option<Vec<SuiteKey>>) -> Vec<u8> {
    let scopes = (0..MAX_SCOPES)
        .map(|i| {
            let letter = char::from(b'a' + u8::try_from(i % 26).unwrap());
            let second = char::from(b'a' + u8::try_from(i / 26).unwrap());
            let name = format!("{}{second}{letter}", "n".repeat(MAX_SCOPE_PART - 2));
            format!("{name}:{}", "s".repeat(MAX_SCOPE_PART))
        })
        .collect();
    let times = (MAX_TIME_MS - MAX_CERT_LIFETIME_MS, MAX_TIME_MS);
    let app = AppKeys::from_secrets([2; 32], [3; 32]);
    cert_body(&app, scopes, times, suite_keys)
        .to_json()
        .unwrap()
}

/// The carrying form's length (Dispatch wire 2.2) of the largest certificate the rules count,
/// as 3.12 and the rows of 10.3 count it. With suite keys of the largest size it is over its
/// size cap (3.1), so no writer issues it: it is built here unsigned, only to be measured, and
/// the rows that count it are loose upper bounds.
fn largest_cert(suite_keys: Option<Vec<SuiteKey>>) -> usize {
    let doc = SignedDoc::from_parts(&largest_cert_body(suite_keys), &[0; 64]);
    serde_json::to_vec(&doc).unwrap().len()
}

/// The largest receive key record the rules allow, in its carrying form (Dispatch wire 3.4):
/// the highest registration number and the given suite keys.
fn largest_receive_key(suite_keys: Option<Vec<SuiteKey>>) -> usize {
    let (app, cert) = cert(vec!["tasks".into()], (1, 2));
    let mut body = ReceiveKeyBody::new(&cert, &ReceiveKey::from_secret(MAX_INT, [4; 32]));
    body.suite_keys = suite_keys;
    let record = ReceiveKeyRecord::sign(&app, &cert, body).unwrap();
    serde_json::to_vec(record.signed()).unwrap().len()
}

/// The body of the largest receive key record, as [`largest_receive_key`] builds it.
fn largest_receive_key_body(suite_keys: Option<Vec<SuiteKey>>) -> usize {
    let (app, cert) = cert(vec!["tasks".into()], (1, 2));
    let mut body = ReceiveKeyBody::new(&cert, &ReceiveKey::from_secret(MAX_INT, [4; 32]));
    body.suite_keys = suite_keys;
    let record = ReceiveKeyRecord::sign(&app, &cert, body).unwrap();
    record.signed().body_bytes().unwrap().len()
}

/// Four suite keys of the largest size the rule of a suite key allows: the highest suites,
/// with keys of 4,096 bytes (Dispatch wire 3.1). A receive key record holds them within its
/// size cap (3.4); a certificate can't (3.1), so only the rows of 10.3 count them there.
fn largest_suite_keys() -> Vec<SuiteKey> {
    (252..=255)
        .map(|suite| SuiteKey {
            suite,
            key: vec![0xff; 4096],
        })
        .collect()
}

#[test]
fn test_spec_bounds_largest_certificate() {
    let cert = largest_cert(None);
    assert_eq!(
        cert,
        stated("A certificate is at most "),
        "Dispatch wire 3.12"
    );
    assert_eq!(
        cert,
        stated_in(CONFIGURATION, "the full certificate, up to "),
        "the operator guide's hand-over"
    );
}

#[test]
fn test_spec_bounds_largest_certificate_and_receive_key_with_suite_keys() {
    let cert = largest_cert(Some(largest_suite_keys()));
    let receive_key = largest_receive_key(Some(largest_suite_keys()));
    let before = "each certificate otherwise the largest of 3.12 (";
    assert_eq!(cert, stated(before), "Dispatch wire 10.3");
    assert_eq!(
        receive_key,
        stated(&format!("{before}{} and ", thousands(cert))),
        "Dispatch wire 10.3"
    );
}

/// The hand-over's bound (Dispatch wire 3.12): the certificates `identity_doc` can reference,
/// each the largest certificate, with the commas between them; the rest of the state as the
/// paragraph adds it up; and the parts that hold it.
#[test]
fn test_spec_bounds_handover_state() {
    let cert = largest_cert(None);
    let count = stated("That document references at most ");
    let certs = count * cert + (count - 1);
    assert_eq!(
        certs,
        stated("and no `suite_keys`, which writers of this version omit: "),
        "the certificates and the commas between them"
    );
    // What the paragraph adds to them: `identity_doc`, `revoked_apps`, `bundle_parts`, and
    // the hand-over's other members with their syntax, 477 bytes.
    let identity_doc = stated("body cap (7.1), so it is at most ");
    let revoked = stated("at most 6,766 App IDs, ");
    let bundle_parts = stated("at most 153 bytes, ");
    let json = stated(
        "including the 45 bytes of `,\"account_created\":\"2026-02-10T00:00:00.000Z\"`, the JSON is at most ",
    );
    assert_eq!(json, identity_doc + certs + revoked + bundle_parts + 477);
    let largest = json
        + stated("a backup's `prev` (3.13) adds ")
        + stated("for each of the 255 listed apps, ");
    assert_eq!(largest, stated("The state is therefore at most "));
    let part = stated("each part fitting one envelope: at most ");
    let parts = largest.div_ceil(part);
    assert_eq!(
        parts,
        stated(&format!(
            "The state is therefore at most {} bytes, ",
            thousands(largest)
        ))
    );
    assert!(parts <= MAX_HANDOVER_ENVELOPES);
    assert_eq!(
        MAX_HANDOVER_ENVELOPES * part - largest,
        stated(&format!(
            "{} bytes, with ",
            thousands(MAX_HANDOVER_ENVELOPES * part)
        ))
    );
}

/// The export part bounds that carry a certificate or receive key records (Dispatch wire
/// 10.3), and the record view that is one of them (7.1): each is the rest of its part, which
/// the table counts apart and the caps of 9.2 bound, plus the largest certificate and receive
/// key records with suite keys.
#[test]
fn test_spec_bounds_export_parts() {
    let cert = largest_cert(Some(largest_suite_keys()));
    let receive_key = largest_receive_key(Some(largest_suite_keys()));
    let row = |part: &str| table_row(&format!("| `{part}` | "));
    assert_eq!(
        row("entry"),
        95_250 + cert,
        "entry: the envelope, 255 targets and a code hash"
    );
    assert_eq!(
        row("app"),
        393_548 + 9 * receive_key + cert,
        "app: the app record its app.put bounds, nine receive key records, a certificate"
    );
    assert_eq!(
        row("claim_entry"),
        548_960 + cert,
        "claim_entry: the entry and its proof"
    );
    assert_eq!(stated("and the writer's certificate ("), cert);
    let record = row("record");
    assert_eq!(
        record,
        919_313 + cert,
        "record: its operation, scopes and proof budget"
    );
    assert_eq!(
        stated("The largest, a `record` part, is at most "),
        record + MAX_CHUNK_OVERHEAD
    );
    assert_eq!(
        stated("a record view is the largest, "),
        record - 970,
        "Dispatch wire 7.1: the record view, the part without its export members"
    );
}

/// The size caps of a certificate and a receive key record (Dispatch wire 3.1, 3.4): the body
/// of the largest certificate a writer of this version produces, without suite keys, and of the
/// largest receive key record with four suite keys, each equal to the number the text states
/// and the constant the verifiers check.
#[test]
fn test_spec_bounds_size_caps() {
    let cap = "body, its decoded JSON body bytes (2.2), is at most ";
    let cert = largest_cert_body(None).len();
    assert_eq!(
        cert,
        stated(&format!("A certificate's {cap}")),
        "Dispatch wire 3.1"
    );
    assert_eq!(cert, MAX_CERT_BODY_BYTES, "AppCert::verify");
    let record = largest_receive_key_body(Some(largest_suite_keys()));
    assert_eq!(
        record,
        stated(&format!("A record's {cap}")),
        "Dispatch wire 3.4"
    );
    assert_eq!(
        record, MAX_RECEIVE_KEY_BODY_BYTES,
        "ReceiveKeyRecord::verify"
    );
}
