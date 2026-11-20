//! Strict JSON (Switch wire 1.1).
//!
//! Every Switch document is one UTF-8 JSON value without a byte order mark, with no
//! duplicate member names at any depth (compared after unescaping), no lone surrogates, and
//! every number an integer from 0 to 2^53 - 1 written without sign, fraction or exponent.
//! The number rule runs on the whole document when it is parsed, before any field is read,
//! and skips only the opaque members the document names by path.

use std::collections::HashSet;

use serde::de::{self, DeserializeOwned, DeserializeSeed, Visitor};

use crate::error::{Error, Result, invalid};

/// The largest integer a Switch document may carry, 2^53 - 1, so every binding reads it
/// exactly (Switch wire 1.1).
pub const MAX_INT: u64 = (1 << 53) - 1;

/// A member of a message body that a protocol names as opaque (Switch wire 1.1).
///
/// An opaque member, and everything below it, may hold any JSON number; the switch and its
/// readers never read it as a number. The Switch names no opaque member of message bodies
/// itself: each protocol names its own (Switch spec 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpaqueMember<'a> {
    /// The message `kind` the rule applies to, or `None` for every kind.
    pub kind: Option<&'a str>,
    /// The member of the message's `body` that is opaque.
    pub member: &'a str,
}

/// The document a JSON text is read as, which names its opaque members (Switch wire 1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Doc<'a> {
    /// No opaque members: certificates, records, `identity.json`, key bundle plaintexts,
    /// shared record values, requests and most answers.
    Plain,
    /// A message (Switch wire 5.1), with the opaque members of its `body` that its protocol
    /// names.
    Message(&'a [OpaqueMember<'a>]),
}

/// Check `bytes` as a strict JSON document without opaque members, then decode it.
///
/// # Errors
///
/// [`Error::Invalid`] if the bytes break a rule of Switch wire 1.1 or don't decode as `T`.
pub fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    parse_json_as(bytes, Doc::Plain)
}

/// Check `bytes` as a strict JSON document read as `doc`, then decode it.
///
/// # Errors
///
/// [`Error::Invalid`] if the bytes break a rule of Switch wire 1.1 or don't decode as `T`.
pub fn parse_json_as<T: DeserializeOwned>(bytes: &[u8], doc: Doc<'_>) -> Result<T> {
    check_json_as(bytes, doc)?;
    Ok(serde_json::from_slice(bytes)?)
}

/// Check that `bytes` are a strict JSON document without opaque members (Switch wire 1.1).
///
/// # Errors
///
/// [`Error::Invalid`] naming the rule that failed.
pub fn check_json(bytes: &[u8]) -> Result<()> {
    check_json_as(bytes, Doc::Plain)
}

/// Check that `bytes` are a strict JSON document read as `doc` (Switch wire 1.1).
///
/// # Errors
///
/// [`Error::Invalid`] naming the rule that failed: a byte order mark, anything after the
/// value but whitespace, a duplicate member name, a lone surrogate, or a number outside the
/// opaque members that isn't an integer from 0 to 2^53 - 1.
pub fn check_json_as(bytes: &[u8], doc: Doc<'_>) -> Result<()> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return invalid("Switch wire 1.1: JSON with a byte order mark");
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let outcome = Strict {
        node: Node::Top(doc),
        capture: false,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()?;
    // Every condition is decided at the object that holds it; one left over can only come
    // from a malformed document.
    if let Some((_, why)) = outcome.pending.into_iter().next() {
        return Err(Error::Invalid(why));
    }
    Ok(())
}

/// Check that `text` is a lower-case UUID version 4: `8-4-4-4-12` hex, version nibble 4,
/// variant bits `10` (Switch wire 1.7).
///
/// # Errors
///
/// [`Error::Invalid`] for any other form, upper case and other versions included.
pub fn check_uuid_v4(text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    let hyphens = [8, 13, 18, 23];
    let shape = bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| {
            if hyphens.contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        });
    if !shape
        || bytes.get(14) != Some(&b'4')
        || !matches!(bytes.get(19), Some(b'8' | b'9' | b'a' | b'b'))
    {
        return invalid("Switch wire 1.7: not a lower-case UUID v4");
    }
    Ok(())
}

/// Refuse a JSON object with a member outside `allowed`, for the documents where an
/// unknown member must never be skipped silently (Switch wire 1.1).
///
/// # Errors
///
/// [`Error::Invalid`] if `value` isn't an object or holds a member `allowed` doesn't list.
pub fn reject_unknown_members(
    value: &serde_json::Value,
    allowed: &[&str],
    what: &str,
) -> Result<()> {
    let Some(object) = value.as_object() else {
        return invalid(format!("Switch wire 1.1: {what} isn't a JSON object"));
    };
    // The member's name is the refused document's text, so the reason doesn't repeat it.
    if object.keys().any(|k| !allowed.contains(&k.as_str())) {
        return invalid(format!("Switch wire 1.1: an unknown member in {what}"));
    }
    Ok(())
}

/// Where the strict check is within a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node<'a> {
    /// Checked, with no opaque member at or below it.
    Checked,
    /// Opaque: any number.
    Opaque,
    /// A body member whose opacity depends on the message kind. The kind may come later.
    KindSpecific(&'a str),
    /// The top level of a document.
    Top(Doc<'a>),
    /// A message's `body`, with its protocol's opaque members.
    MessageBody(&'a [OpaqueMember<'a>]),
}

impl<'a> Node<'a> {
    /// The node of member `key` of an object at this node.
    fn member(self, key: &str) -> Node<'a> {
        match (self, key) {
            (Node::Opaque, _) => Node::Opaque,
            (Node::KindSpecific(member), _) => Node::KindSpecific(member),
            (Node::Top(Doc::Message(rules)), "body") => Node::MessageBody(rules),
            (Node::MessageBody(rules), _) => {
                let mut node = Node::Checked;
                for rule in rules.iter().filter(|r| r.member == key) {
                    if rule.kind.is_none() {
                        return Node::Opaque;
                    }
                    node = Node::KindSpecific(rule.member);
                }
                node
            }
            _ => Node::Checked,
        }
    }

    /// The node of an element of an array at this node.
    fn element(self) -> Node<'a> {
        match self {
            Node::Opaque => Node::Opaque,
            Node::KindSpecific(member) => Node::KindSpecific(member),
            _ => Node::Checked,
        }
    }
}

/// What checking one value found: numbers under a condition not decided yet (the condition
/// and why the number isn't an integer), and the value's text when its object keeps it to
/// decide a condition.
#[derive(Default)]
struct Outcome<'a> {
    pending: Vec<(&'a str, String)>,
    text: Option<String>,
}

/// The strict checker: no duplicate names at any depth, and every number a wire integer
/// outside the opaque members.
struct Strict<'a> {
    node: Node<'a>,
    capture: bool,
}

impl<'a> Strict<'a> {
    /// A number that isn't a wire integer: refused where checked, noted under a condition,
    /// accepted where opaque.
    fn number<E: de::Error>(&self, why: &str) -> std::result::Result<Outcome<'a>, E> {
        match self.node {
            Node::Opaque => Ok(Outcome::default()),
            Node::KindSpecific(member) => Ok(Outcome {
                pending: vec![(member, why.to_owned())],
                text: None,
            }),
            _ => Err(E::custom(why)),
        }
    }
}

impl<'de, 'a> DeserializeSeed<'de> for Strict<'a> {
    type Value = Outcome<'a>;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Outcome<'a>, D::Error> {
        deserializer.deserialize_any(self)
    }
}

// The reasons below never repeat a value or a name: the document may be decrypted plaintext.
impl<'de, 'a> Visitor<'de> for Strict<'a> {
    type Value = Outcome<'a>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, _: bool) -> std::result::Result<Outcome<'a>, E> {
        Ok(Outcome::default())
    }
    // serde_json gives a negative integer as i64, a non-negative one as u64, and a number
    // with a fraction or an exponent, or one beyond u64, as f64.
    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Outcome<'a>, E> {
        if value < 0 {
            return self.number("Switch wire 1.1: a negative integer");
        }
        Ok(Outcome::default())
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Outcome<'a>, E> {
        if value > MAX_INT {
            return self.number("Switch wire 1.1: an integer above 2^53 - 1");
        }
        Ok(Outcome::default())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Outcome<'a>, E> {
        self.number("Switch wire 1.1: a number with a fraction or an exponent")
    }
    fn visit_str<E>(self, value: &str) -> std::result::Result<Outcome<'a>, E> {
        Ok(Outcome {
            pending: Vec::new(),
            text: self.capture.then(|| value.to_owned()),
        })
    }
    fn visit_unit<E>(self) -> std::result::Result<Outcome<'a>, E> {
        Ok(Outcome::default())
    }
    fn visit_seq<A: de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Outcome<'a>, A::Error> {
        let mut pending = Vec::new();
        let element = self.node.element();
        while let Some(outcome) = seq.next_element_seed(Strict {
            node: element,
            capture: false,
        })? {
            pending.extend(outcome.pending);
        }
        Ok(Outcome {
            pending,
            text: None,
        })
    }
    fn visit_map<A: de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Outcome<'a>, A::Error> {
        let mut keys = HashSet::new();
        let mut kind = None;
        let mut pending = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(
                    "Switch wire 1.1: a duplicate member name",
                ));
            }
            let capture = matches!(self.node, Node::Top(Doc::Message(_))) && key == "kind";
            let outcome = map.next_value_seed(Strict {
                node: self.node.member(&key),
                capture,
            })?;
            pending.extend(outcome.pending);
            if let Some(text) = outcome.text {
                kind = Some(text);
            }
        }
        if let Node::Top(Doc::Message(rules)) = self.node {
            for (member, why) in pending.drain(..) {
                if !rules.iter().any(|rule| {
                    rule.member == member && rule.kind.is_some() && rule.kind == kind.as_deref()
                }) {
                    return Err(de::Error::custom(why));
                }
            }
        }
        Ok(Outcome {
            pending,
            text: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &[OpaqueMember<'static>] = &[
        OpaqueMember {
            kind: None,
            member: "metadata",
        },
        OpaqueMember {
            kind: Some("sample.proof"),
            member: "proof",
        },
    ];

    #[test]
    fn test_strict_json_refuses_duplicates_and_trailing_values() {
        assert!(check_json(br#"{"a":1,"b":{"c":2}}"#).is_ok());
        assert!(check_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(check_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(check_json(br#"{"a":1} {"b":2}"#).is_err());
        assert!(check_json(b"{\"a\":1}\n").is_ok());
        assert!(check_json(&[0xEF, 0xBB, 0xBF, b'{', b'}']).is_err());
    }

    #[test]
    fn test_strict_json_refuses_numbers_outside_the_integer_range() {
        assert!(check_json(br#"{"n":9007199254740991}"#).is_ok());
        for bad in [
            r#"{"n":9007199254740992}"#,
            r#"{"n":-1}"#,
            r#"{"n":1.0}"#,
            r#"{"n":1e3}"#,
        ] {
            assert!(check_json(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_strict_json_opaque_members_take_any_number() {
        let any = br#"{"kind":"x.y","body":{"metadata":{"rate":1.5e2}}}"#;
        assert!(check_json_as(any, Doc::Message(RULES)).is_ok());
        assert!(check_json(any).is_err());
        let proof = br#"{"kind":"sample.proof","body":{"proof":{"n":1e30}}}"#;
        assert!(check_json_as(proof, Doc::Message(RULES)).is_ok());
        // The rule names `proof` for one kind only, wherever `kind` comes in the object.
        let other = br#"{"body":{"proof":{"n":1.5}},"kind":"x.y"}"#;
        assert!(check_json_as(other, Doc::Message(RULES)).is_err());
        let later = br#"{"body":{"proof":{"n":1.5}},"kind":"sample.proof"}"#;
        assert!(check_json_as(later, Doc::Message(RULES)).is_ok());
    }

    #[test]
    fn test_uuid_v4_form() {
        assert!(check_uuid_v4("1b4e28ba-2fa1-41d2-883f-0016d3cca427").is_ok());
        assert!(check_uuid_v4("1B4E28BA-2FA1-41D2-883F-0016D3CCA427").is_err());
        assert!(check_uuid_v4("1b4e28ba-2fa1-11d2-883f-0016d3cca427").is_err());
        assert!(check_uuid_v4("1b4e28ba-2fa1-41d2-c83f-0016d3cca427").is_err());
        assert!(check_uuid_v4("1b4e28ba2fa141d2883f0016d3cca427").is_err());
    }

    #[test]
    fn test_reject_unknown_members() {
        let value = serde_json::json!({"a": 1, "b": 2});
        assert!(reject_unknown_members(&value, &["a", "b"], "doc").is_ok());
        assert!(reject_unknown_members(&value, &["a"], "doc").is_err());
        assert!(reject_unknown_members(&serde_json::json!([1]), &["a"], "doc").is_err());
    }
}
