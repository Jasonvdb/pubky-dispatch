//! `encoding.json`: `lp()`, `u64`, `derive()`, base64url, z-base-32, strict JSON and RFC 3339
//! times (Dispatch wire 1).

use std::collections::BTreeMap;

use pubky_dispatch_core::enc::{self, b64, lp, unb64, zbase32_decode, zbase32_encode};
use pubky_dispatch_core::json::{self, Doc, OpaqueMember};
use pubky_dispatch_core::time;
use serde_json::Value;

use crate::common::*;

/// The opaque members of the sample protocol's message bodies that the `read_as: message`
/// cases rely on: `metadata` in every body, and `proof` in the body of the kind whose case
/// holds a non-integer there. The kind is read from the vectors, not named here.
fn sample_message_rules(cases: &[Value]) -> (String, String) {
    let messages: Vec<Value> = cases
        .iter()
        .filter(|c| c.get("read_as").and_then(Value::as_str) == Some("message"))
        .map(|c| serde_json::from_str(st(c, "json")).expect("a JSON case"))
        .collect();
    let proof_kind = messages
        .iter()
        .find(|m| m["body"].get("proof").is_some() && m["body"].get("metadata").is_none())
        .map(|m| st(m, "kind").to_owned())
        .expect("a case with a proof");
    let other_kind = messages
        .iter()
        .map(|m| st(m, "kind").to_owned())
        .find(|k| *k != proof_kind)
        .expect("a case of another kind");
    (proof_kind, other_kind)
}

fn examples<'a>(group: &'a Value, name: &str) -> &'a [Value] {
    let cases = arr(group, name);
    assert!(!cases.is_empty(), "encoding.json has no {name} examples");
    cases
}

/// A missing field, one empty field and a trailing empty field have distinct encodings.
/// Different splits of the same nonempty bytes must also be represented (Dispatch wire 1.4).
fn check_lp(cases: &[Value]) {
    let mut no_parts = false;
    let mut empty_part = false;
    let mut trailing_empty = false;
    let mut splits = BTreeMap::new();
    let mut different_splits = false;
    for c in cases {
        let parts: Vec<Vec<u8>> = arr(c, "parts_hex")
            .iter()
            .map(|p| hx(p.as_str().unwrap()))
            .collect();
        match parts.as_slice() {
            [] => no_parts = true,
            [part] if part.is_empty() => empty_part = true,
            [first, last] if !first.is_empty() && last.is_empty() => trailing_empty = true,
            [first, last] if !first.is_empty() && !last.is_empty() => {
                let previous = splits.insert(parts.concat(), first.len());
                different_splits |= previous.is_some_and(|cut| cut != first.len());
            }
            _ => {}
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let bytes = lp(&refs);
        assert_eq!(hex::encode(&bytes), st(c, "output_hex"));
        assert_eq!(enc::split_lp(&bytes), Some(parts));
    }
    assert!(no_parts, "lp needs an example with no parts");
    assert!(empty_part, "lp needs an example with one empty part");
    assert!(
        trailing_empty,
        "lp needs an example ending in an empty part"
    );
    assert!(
        different_splits,
        "lp needs two different splits of the same bytes"
    );
}

#[test]
fn test_vectors_encoding() {
    let e = load("encoding.json");
    check_lp(examples(&e, "lp"));
    for c in examples(&e, "u64_be") {
        let value = match &c["value"] {
            Value::String(s) => s.parse::<u64>().unwrap(),
            n => n.as_u64().unwrap(),
        };
        assert_eq!(hex::encode(enc::u64be(value)), st(c, "hex"));
        // Values beyond the JSON integers are written as strings.
        assert_eq!(c["value"].is_number(), value <= json::MAX_INT, "{c}");
    }
    for c in examples(&e, "derive") {
        let parts: Vec<Vec<u8>> = arr(c, "parts_hex")
            .iter()
            .map(|p| hx(p.as_str().unwrap()))
            .collect();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        assert_eq!(hex::encode(lp(&refs)), st(c, "key_material_hex"));
        assert_eq!(
            hex::encode(enc::derive(st(c, "label"), &refs)),
            st(c, "output_hex")
        );
    }
    for c in examples(&e["base64url"], "valid") {
        assert_eq!(
            hex::encode(unb64(st(c, "base64url")).unwrap()),
            st(c, "hex")
        );
        assert_eq!(b64(&hx(st(c, "hex"))), st(c, "base64url"));
    }
    for c in examples(&e["base64url"], "invalid") {
        assert!(unb64(st(c, "base64url")).is_err(), "accepted {c}");
    }
    for c in examples(&e["zbase32"], "valid") {
        let bytes = hx(st(c, "hex"));
        assert_eq!(zbase32_encode(&bytes), st(c, "zbase32"));
        let decoded = match bytes.len() {
            16 => zbase32_decode::<16>(st(c, "zbase32")).unwrap().to_vec(),
            32 => zbase32_decode::<32>(st(c, "zbase32")).unwrap().to_vec(),
            n => panic!("no z-base-32 case of {n} bytes expected"),
        };
        assert_eq!(decoded, bytes);
    }
    for c in examples(&e["zbase32"], "invalid") {
        assert!(
            zbase32_decode::<32>(st(c, "zbase32")).is_err(),
            "accepted {c}"
        );
    }

    // Strict JSON. A case with `read_as` is read as that document, whose opaque members
    // are named by path; the others have none.
    let cases = examples(&e, "json");
    let (proof_kind, _) = sample_message_rules(cases);
    let rules = [
        OpaqueMember {
            kind: None,
            member: "metadata",
        },
        OpaqueMember {
            kind: Some(&proof_kind),
            member: "proof",
        },
    ];
    let mut read_as = 0;
    for c in cases {
        let bytes = match c.get("json_hex") {
            Some(h) => hx(h.as_str().unwrap()),
            None => st(c, "json").as_bytes().to_vec(),
        };
        let valid = c["valid"].as_bool().unwrap();
        let doc = match c.get("read_as").and_then(Value::as_str) {
            None => Doc::Plain,
            Some("message") => Doc::Message(&rules),
            Some(other) => panic!("read_as {other:?}"),
        };
        assert_eq!(
            json::check_json_as(&bytes, doc).is_ok(),
            valid,
            "JSON case {c}"
        );
        if doc == Doc::Plain {
            assert_eq!(
                json::check_json_as(&bytes, Doc::Message(&rules)).is_ok(),
                valid
            );
        } else {
            read_as += 1;
            assert!(json::check_json(&bytes).is_err(), "{c} as plain JSON");
        }
    }
    assert_eq!(read_as, 3);

    // The integer rule at every depth outside the opaque members.
    for (number, ok) in [
        ("0", true),
        ("9007199254740991", true),
        ("9007199254740992", false),
        ("18446744073709551616", false),
        ("1.0", false),
        ("1e2", false),
        ("1E2", false),
        ("-1", false),
        ("-0", false),
    ] {
        let flat = format!("{{\"v\":{number}}}");
        assert_eq!(json::check_json(flat.as_bytes()).is_ok(), ok, "{flat}");
        let nested = format!("{{\"a\":[{{\"b\":{{\"c\":{number}}}}}]}}");
        assert_eq!(json::check_json(nested.as_bytes()).is_ok(), ok, "{nested}");
        let opaque = format!("{{\"body\":{{\"metadata\":{{\"n\":{number}}}}}}}");
        json::check_json_as(opaque.as_bytes(), Doc::Message(&rules)).unwrap();
        assert_eq!(json::check_json(opaque.as_bytes()).is_ok(), ok);
        for checked in [
            format!("{{\"metadata\":{{\"rate\":{number}}}}}"),
            format!("{{\"kind\":\"x.y\",\"body\":{{\"proof\":{{\"n\":{number}}}}}}}"),
            format!("{{\"body\":{{\"x\":[{{\"metadata\":{number}}}]}}}}"),
        ] {
            assert_eq!(
                json::check_json_as(checked.as_bytes(), Doc::Message(&rules)).is_ok(),
                ok,
                "{checked}"
            );
        }
    }

    // Times.
    let r = &e["rfc3339"];
    for c in examples(r, "parse") {
        assert_eq!(
            time::parse_rfc3339(st(c, "text")).unwrap(),
            int(c, "unix_ms"),
            "{c}"
        );
    }
    for c in examples(r, "format") {
        let ms = int(c, "unix_ms");
        assert_eq!(time::rfc3339(ms), st(c, "text"));
        assert_eq!(time::parse_rfc3339(st(c, "text")).unwrap(), ms);
    }
    for c in examples(r, "invalid") {
        assert!(time::parse_rfc3339(st(c, "text")).is_err(), "accepted {c}");
    }
    // Forms outside the grammar that some readers allow; this reader refuses them, which
    // Dispatch wire 1.6 leaves to each reader.
    for c in examples(r, "lenient_reader_only") {
        assert!(time::parse_rfc3339(st(c, "text")).is_err(), "accepted {c}");
    }
}
