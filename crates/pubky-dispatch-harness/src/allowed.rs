//! The allowed differences: where the scripted Dispatch answers an honest flow differently
//! from the service, and why each is accepted.
//!
//! This list is the source of truth for honest-path differences between the scripted Dispatch
//! (`pubky-dispatch-client`'s `testing` module) and the service. A flow's test fails on a
//! difference this list doesn't hold, and on an entry of the flow that matched nothing, so
//! the list can neither miss a difference nor keep one that is gone.
//!
//! What the scripted Dispatch fakes or leaves out beyond honest flows (limits, rates,
//! retention, refusals) is in that module's `FAKES.md`.

use crate::compare::Difference;

/// One accepted difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allowed {
    /// The flow it shows in.
    pub flow: &'static str,
    /// The line's label, as [`crate::trace::Line::label`] gives it. `*` stands for any run
    /// of characters, here and in the next three.
    pub label: &'static str,
    /// The fact that differs.
    pub fact: &'static str,
    /// What the service shows; `(nothing)` when it shows nothing there.
    pub service: &'static str,
    /// What the scripted Dispatch shows; `(nothing)` when it shows nothing there.
    pub scripted: &'static str,
    /// Why the difference is accepted.
    pub reason: &'static str,
    /// The clause of the wire format or the line of `FAKES.md` it follows from.
    pub reference: &'static str,
}

/// What stands for a fact one run didn't show.
pub const NOTHING: &str = "(nothing)";

impl Allowed {
    /// Whether this entry allows `difference`.
    pub fn allows(&self, difference: &Difference) -> bool {
        let shown = |value: &Option<String>| value.clone().unwrap_or_else(|| NOTHING.to_owned());
        matches(self.label, &difference.label)
            && matches(self.fact, &difference.fact)
            && matches(self.service, &shown(&difference.service))
            && matches(self.scripted, &shown(&difference.scripted))
    }
}

/// Whether `text` matches `pattern`, where each `*` stands for any run of characters.
fn matches(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return text.is_empty();
    };
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let mut parts = parts.peekable();
    if parts.peek().is_none() {
        return rest.is_empty();
    }
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return rest.ends_with(part);
        }
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    true
}

/// Why the service's times after a restart lie a minute ahead of the scripted Dispatch's.
const AFTER_A_RESTART: &str = "The service runs again after the restore, the fork, the \
     retirement or the account's return, and its first stamp at the account is the mark's \
     time floor, a minute past the last time it raised it; every time stamped from then on \
     is that one until the clock passes it. The scripted dispatch has no time floor and no \
     restart: it stamps its clock's time. Both times go forward, and the app compares only \
     times of one dispatch.";

/// Every accepted difference, by flow.
pub static ALLOWED: &[Allowed] = &[
    Allowed {
        flow: "records, permanent",
        label: "{alice/phone} GET /v1/{alice}/records/*",
        fact: "header dispatch-server-time",
        service: "time 2026-01-01T00:25:30.000Z",
        scripted: "time 2026-01-01T00:24:30.000Z",
        reason: "The service restarts after the record is lost. Its first read stamps the \
                 reserved time floor. The scripted dispatch keeps running at the same clock time.",
        reference: "Dispatch wire 7.3, \"Time base\"; FAKES.md, \"Accounts and marks\"",
    },
    Allowed {
        flow: "recovery notice, a restore behind the mark",
        label: "*",
        fact: "*",
        service: "time 2026-01-01T00:06:06.250Z",
        scripted: "time 2026-01-01T00:05:06.250Z",
        reason: AFTER_A_RESTART,
        reference: "Dispatch wire 7.3, \"Time base\"; FAKES.md, \"Accounts and marks\"",
    },
    Allowed {
        flow: "recovery notice, a fork",
        label: "*",
        fact: "*",
        service: "time 2026-01-01T00:05:05.000Z",
        scripted: "time 2026-01-01T00:04:05.000Z",
        reason: AFTER_A_RESTART,
        reference: "Dispatch wire 7.3, \"Time base\"; FAKES.md, \"Accounts and marks\"",
    },
    Allowed {
        flow: "recovery notice, a kept batch",
        label: "*",
        fact: "*",
        service: "time 2026-01-01T00:07:07.500Z",
        scripted: "time 2026-01-01T00:06:07.500Z",
        reason: AFTER_A_RESTART,
        reference: "Dispatch wire 7.3, \"Time base\"; FAKES.md, \"Accounts and marks\"",
    },
    Allowed {
        flow: "recovery notice, the generation retired",
        label: "*",
        fact: "*",
        service: "time 2026-01-01T00:06:06.250Z",
        scripted: "time 2026-01-01T00:05:06.250Z",
        reason: AFTER_A_RESTART,
        reference: "Dispatch wire 7.3, \"Time base\"; FAKES.md, \"Accounts and marks\"",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_with_and_without_stars() {
        assert!(matches("status", "status"));
        assert!(!matches("status", "status code"));
        assert!(matches("body.apps*", "body.apps[0].current"));
        assert!(matches("*", ""));
        assert!(matches("body.*.seq", "body.head.seq"));
        assert!(!matches("body.*.seq", "body.head.seq.more"));
        assert!(matches("*seq", "body.head.seq"));
        assert!(!matches("body.*.seq", "body.seq"));
        assert!(matches("a*b*c", "a-b-b-c"));
        assert!(!matches("a*b*c", "a-c"));
    }

    #[test]
    fn test_allowed_entry_names_both_sides() {
        let entry = Allowed {
            flow: "example",
            label: "{alice} GET /v1/{alice}/apps",
            fact: "body.recovery",
            service: "null",
            scripted: "(nothing)",
            reason: "an example",
            reference: "nowhere",
        };
        let mut difference = Difference {
            line: 3,
            label: "{alice} GET /v1/{alice}/apps".into(),
            fact: "body.recovery".into(),
            service: Some("null".into()),
            scripted: None,
        };
        assert!(entry.allows(&difference));
        difference.scripted = Some("bool true".into());
        assert!(!entry.allows(&difference), "another value there");
        difference.scripted = None;
        difference.label = "{bob} GET /v1/{bob}/apps".into();
        assert!(!entry.allows(&difference), "another call");
    }
}
