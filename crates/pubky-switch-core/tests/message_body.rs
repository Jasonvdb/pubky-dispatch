//! Message writing with caller-encoded bodies (Switch wire 1.1, 5.1).

use pubky_switch_core::json::OpaqueMember;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::message::{Message, MessageFields, MessagePlaintext, Sender, max_json_len};
use pubky_switch_core::time::MAX_TIME_MS;

fn app() -> AppKeys {
    AppKeys::from_secrets([1; 32], [2; 32])
}

fn fields() -> MessageFields<'static> {
    MessageFields {
        kind: "tasks.event",
        msg_id: "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
        created_at_ms: 1_767_225_600_123,
        from: Sender::of_app([3; 32], &app()),
        to: [4; 32],
        refs: &[[5; 32], [6; 32]],
    }
}

#[test]
fn test_message_body_preserves_exact_bytes_through_signing() {
    let fields = fields();
    let body = b" \n{\"z\": {\"last\": 2, \"first\": 1}, \"a\":\"\\u0061\"}\t ";
    let json = fields.to_json_with_body(body, &[]).unwrap();
    let suffix = [b",\"body\":".as_slice(), body, b"}"].concat();
    assert!(json.ends_with(&suffix));
    let message = Message::parse(&json, &[]).unwrap();
    assert_eq!(message.kind, fields.kind);
    assert_eq!(message.msg_id, fields.msg_id);
    assert_eq!(message.created_at_ms, fields.created_at_ms);
    assert_eq!(message.from, fields.from);
    assert_eq!(message.to, fields.to);
    assert_eq!(message.refs, fields.refs);
    assert_eq!(message.body["z"]["last"], 2);
    assert_eq!(message.body["a"], "a");

    let plaintext = MessagePlaintext::sign_json(&app(), json.clone(), &[]).unwrap();
    assert_eq!(plaintext.json(), json);
    plaintext
        .verify_signature(&app().signing_public(), &fields.to)
        .unwrap();
    assert_ne!(message.to_json().unwrap(), json);
}

#[test]
fn test_message_body_matches_typed_common_fields() {
    let fields = fields();
    let body = br#"{"note":"hello"}"#;
    let json = fields.to_json_with_body(body, &[]).unwrap();
    let message = Message {
        kind: fields.kind.to_owned(),
        msg_id: fields.msg_id.to_owned(),
        created_at_ms: fields.created_at_ms,
        from: fields.from,
        to: fields.to,
        refs: fields.refs.to_vec(),
        body: serde_json::from_slice(body).unwrap(),
    };
    assert_eq!(json, message.to_json().unwrap());
    assert_eq!(
        MessagePlaintext::sign_json(&app(), json, &[]).unwrap(),
        message.sign(&app()).unwrap()
    );
}

#[test]
fn test_message_body_requires_one_complete_value() {
    for body in [
        b"".as_slice(),
        b"{",
        b"{} {}",
        b"{},\"extra\":5",
        b"{}/* comment */",
        b"\xef\xbb\xbf{}",
        b"{\"text\":\"\xff\"}",
        br#"{"text":"\ud800"}"#,
    ] {
        assert!(fields().to_json_with_body(body, &[]).is_err(), "{body:?}");
    }
    fields().to_json_with_body(b" \r\n{}\t", &[]).unwrap();
}

#[test]
fn test_message_body_requires_an_object() {
    for body in [b"[]".as_slice(), b"null", b"true", b"42", br#""text""#] {
        assert!(fields().to_json_with_body(body, &[]).is_err(), "{body:?}");
    }
    fields().to_json_with_body(b"{}", &[]).unwrap();
}

#[test]
fn test_message_body_refuses_duplicate_members_at_every_depth() {
    let opaque = [OpaqueMember {
        kind: Some("tasks.event"),
        member: "data",
    }];
    for body in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":1,"\u0061":2}"#,
        br#"{"data":{"a":1,"a":2}}"#,
        br#"{"data":[{"a":1,"\u0061":2}]}"#,
    ] {
        assert!(fields().to_json_with_body(body, &opaque).is_err());
    }
    fields()
        .to_json_with_body(br#"{"a":1,"data":{"a":2}}"#, &opaque)
        .unwrap();
}

#[test]
fn test_message_body_applies_opaque_rules_by_kind_and_path() {
    let opaque = [OpaqueMember {
        kind: Some("tasks.event"),
        member: "data",
    }];
    let body = br#"{"data":{"values":[-1,1.5,1e3]},"count":9007199254740991}"#;
    let json = fields().to_json_with_body(body, &opaque).unwrap();
    assert!(json.ends_with(&[body.as_slice(), b"}"].concat()));
    MessagePlaintext::sign_json(&app(), json, &opaque).unwrap();
    assert!(fields().to_json_with_body(body, &[]).is_err());
    let other = MessageFields {
        kind: "tasks.other",
        ..fields()
    };
    assert!(other.to_json_with_body(body, &opaque).is_err());
    for body in [
        br#"{"count":-1}"#.as_slice(),
        br#"{"count":1.5}"#,
        br#"{"count":1e3}"#,
        br#"{"count":9007199254740992}"#,
        br#"{"nested":{"data":1.5}}"#,
    ] {
        assert!(fields().to_json_with_body(body, &opaque).is_err());
    }
    let all_kinds = [OpaqueMember {
        kind: None,
        member: "data",
    }];
    other.to_json_with_body(body, &all_kinds).unwrap();
}

#[test]
fn test_message_body_checks_common_fields_and_escapes_strings() {
    for kind in ["", "tasks", ".event", "tasks."] {
        let fields = MessageFields { kind, ..fields() };
        assert!(fields.to_json_with_body(b"{}", &[]).is_err());
    }
    for msg_id in [
        "",
        "1B4E28BA-2FA1-41D2-883F-0016D3CCA427",
        "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
    ] {
        let fields = MessageFields { msg_id, ..fields() };
        assert!(fields.to_json_with_body(b"{}", &[]).is_err());
    }
    let fields = MessageFields {
        kind: "tasks.\"event\"",
        created_at_ms: u64::MAX,
        refs: &[],
        ..fields()
    };
    let json = fields.to_json_with_body(b"{}", &[]).unwrap();
    let parsed = Message::parse(&json, &[]).unwrap();
    assert_eq!(parsed.kind, fields.kind);
    assert_eq!(parsed.created_at_ms, MAX_TIME_MS);
    assert!(parsed.refs.is_empty());
    assert_eq!(parsed.to_json().unwrap(), json);
}

#[test]
fn test_message_body_bounds_the_complete_frame() {
    let fields = fields();
    let max = max_json_len(1).unwrap();
    let overhead = fields
        .to_json_with_body(br#"{"text":""}"#, &[])
        .unwrap()
        .len();
    let body = format!(r#"{{"text":"{}"}}"#, "x".repeat(max - overhead));
    let json = fields.to_json_with_body(body.as_bytes(), &[]).unwrap();
    assert_eq!(json.len(), max);
    MessagePlaintext::sign_json(&app(), json, &[]).unwrap();

    let too_large = format!(" {body}");
    assert!(too_large.len() < max);
    assert!(fields.to_json_with_body(too_large.as_bytes(), &[]).is_err());
    let too_large = format!(r#"{{"text":"{}"}}"#, "x".repeat(max));
    assert!(fields.to_json_with_body(too_large.as_bytes(), &[]).is_err());
}
