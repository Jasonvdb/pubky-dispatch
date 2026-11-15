//! What the harness verifies itself of every answer, in both runs.
//!
//! The comparison ([`crate::compare`]) sets one run beside the other. It can't tell a hash,
//! a signature or a key that a switch makes itself, echoing nothing a party sent, from the
//! right one: if such a value is wrong from its first appearance and repeated consistently
//! wherever the right one would show, the two runs still read alike. The client and the
//! signer verify much of it, and a flow fails where they refuse. This module checks the
//! rest of what the harness holds the means to check, on every answer of either switch:
//!
//! - the answer's signature (Switch wire 7.1), with the account's service key of its
//!   generation, or the switch's one key for an answer it can't tie to an account the run
//!   knows. The
//!   key of a generation is the one its `identity.json` names (`inbox.service_key`, Switch
//!   wire 3.3), taken from the delivery the switch accepted, which must itself be answered
//!   under that key; the key of the generation before is held no longer from then on.
//!   Before its document is taken, a key is one the run brought: the one key of the switch
//!   a world adds the account at, or the one an enrollment's answer names and is signed
//!   with (Switch wire 7.4.1). The trace says which signed, a generation's key or a key
//!   not delivered yet by its number in the order the run brought them, so the two runs
//!   must agree on it;
//! - every signed head, in `Switch-Head` and in a body's `head` (Switch wire 6.7): its
//!   signature, with the key that signed the answer carrying it, its generation, and its
//!   chain hash against the stub of its `seq` where the run showed one;
//! - every chain stub (Switch wire 6.6): its chain hash follows from its envelope, the stub
//!   at one `seq` is always the same, and it links to the stubs the run showed at the `seq`
//!   before and after it. A sequence starts from 32 zero bytes at `seq` 0 (Switch wire
//!   6.6), so its first item follows nothing. A provider loss starts a sequence afresh,
//!   with the `recovery` transition as its first item (Switch wire 7.4.2, spec 12.6 step
//!   1): the checker forgets the lost chain when the recovery's document is taken. A key
//!   rotation and a cooperative move go on in the same sequence under the next generation
//!   (Switch wire 3.3), so there the links are kept across the generations;
//! - every feed item shown in full: its document hashes to its envelope's `item_hash`, and
//!   a service transition is signed with the key that signed the answer;
//! - every transition proof (Switch wire 6.5): its signature, with the key that signed the
//!   answer, and its stub as above.
//!
//! A check that fails is a `violation` fact on the answer's line, and the comparison
//! reports every violation as a difference, also one both runs show.
//!
//! No flow rotates a key or moves an account yet. When one does, a proof or a transition
//! of the generation before, shown under the next one, needs that generation's key kept
//! for it: here it would be a violation.
//!
//! Still unchecked, by the harness and so only as far as the client and the signer check
//! them: the signatures of documents a party signed and the switch only carries, sealed
//! values, and whether a proof's state is the right one for its operation, which the
//! comparison covers by setting the two runs' states side by side.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard, PoisonError};

use pubky_switch_client::client::SentRequest;
use pubky_switch_client::transport::{Request, Response};
use pubky_switch_core::chain::{
    ChainEnvelope, ItemType, ServiceTransition, SignedHead, Stub, TransitionProof, Verifier,
    ZERO_HASH,
};
use pubky_switch_core::enc::unb64_array;
use pubky_switch_core::http::{ErrorCode, ResponseParts, header, verify_response};
use pubky_switch_core::records::IdentityDoc;
use pubky_switch_core::sig::SignedDoc;
use serde_json::Value;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One stub the run showed: its chain hash, and the chain hash it follows.
#[derive(Clone, Copy)]
struct Link {
    chain_hash: [u8; 32],
    prev: Option<[u8; 32]>,
}

/// A sequence before its first item: 32 zero bytes at `seq` 0 (Switch wire 6.6).
fn start_of_a_sequence() -> BTreeMap<u64, Link> {
    BTreeMap::from([(
        0,
        Link {
            chain_hash: ZERO_HASH,
            prev: None,
        },
    )])
}

/// An account the checker knows.
struct Account {
    identity: [u8; 32],
    /// Keys in the order the run brought them, for stable names across generations.
    keys: Vec<[u8; 32]>,
    /// The keys brought whose document no switch took yet, each with its number.
    named: Vec<(usize, [u8; 32])>,
    /// The generation whose document a switch took last, and the service key it names.
    current: Option<(u64, [u8; 32])>,
    /// The stubs the run showed of the account's sequence, by `seq`.
    chain: BTreeMap<u64, Link>,
    /// The generation the sequence started in: a recovery's, or 0 for the first.
    chain_since: u64,
}

impl Account {
    fn new(identity: [u8; 32]) -> Self {
        Self {
            identity,
            keys: Vec::new(),
            named: Vec::new(),
            current: None,
            chain: start_of_a_sequence(),
            chain_since: 0,
        }
    }

    /// The run brought `key`: one more, unless it is held already.
    fn bring(&mut self, key: [u8; 32]) {
        let held = self.current.is_some_and(|(_, current)| current == key)
            || self.named.iter().any(|(_, named)| *named == key);
        if !held {
            let number = match self.keys.iter().position(|known| *known == key) {
                Some(index) => index + 1,
                None => {
                    self.keys.push(key);
                    self.keys.len()
                }
            };
            self.named.push((number, key));
        }
    }

    /// The key `with` verified with, even if another generation has since started.
    fn key_of(&self, with: SignedWith) -> Option<[u8; 32]> {
        let number = match with {
            SignedWith::Generation(_, number) | SignedWith::Brought(number) => number,
            SignedWith::SwitchKey => return None,
        };
        self.keys.get(number.checked_sub(1)?).copied()
    }

    fn key_number(&self, key: &[u8; 32]) -> Result<usize, String> {
        self.keys
            .iter()
            .position(|known| known == key)
            .map(|index| index + 1)
            .ok_or_else(|| "the signing key has no name".to_owned())
    }

    /// A switch took `doc`: its generation's key is the one it names.
    fn take(&mut self, doc: &IdentityDoc) -> Result<(), String> {
        let (generation, key) = (doc.generation(), doc.inbox().service_key);
        match self.current {
            Some((current, _)) if generation < current => Err(format!(
                "a document of generation {generation} was taken, where the account's is \
                 {current}"
            )),
            Some((current, held)) if generation == current => {
                if held == key {
                    Ok(())
                } else {
                    Err(format!(
                        "a document names another service key for generation {generation} than \
                         the one taken before it"
                    ))
                }
            }
            _ => {
                self.bring(key);
                self.current = Some((generation, key));
                self.named.retain(|(_, named)| *named != key);
                // A provider loss starts the sequence afresh (Switch wire 7.4.2); a rotation
                // and a move go on in it (Switch wire 3.3).
                if doc.body().recovery_from.is_some() {
                    self.chain = start_of_a_sequence();
                    self.chain_since = generation;
                }
                Ok(())
            }
        }
    }
}

/// Verifies what a run's answers carry.
#[derive(Default)]
pub struct Checker {
    /// The accounts, by Pubky ID.
    accounts: Mutex<HashMap<String, Account>>,
    /// The one key of each of the run's switches.
    switch_keys: Mutex<Vec<[u8; 32]>>,
}

impl std::fmt::Debug for Checker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Checker({} accounts)", lock(&self.accounts).len())
    }
}

/// Which key an answer's signature verified with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedWith {
    /// The account's service key of this generation: the one the generation's
    /// `identity.json` names, which a switch took; and its stable key number.
    Generation(u64, usize),
    /// A service key the run brought whose document no switch took yet: its number, from
    /// 1, in the order the run brought them for the account.
    Brought(usize),
    /// A switch's one key, for an answer about no account the run knows.
    SwitchKey,
}

impl std::fmt::Display for SignedWith {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignedWith::Generation(_, number) | SignedWith::Brought(number) => {
                write!(f, "service key number {number}")
            }
            SignedWith::SwitchKey => write!(f, "the switch's key"),
        }
    }
}

/// The Pubky ID of the account a request is for: the one its path names, or for an
/// enrollment the one it is signed for.
fn account_id(request: &Request) -> Option<&str> {
    match request.path_and_query.strip_prefix("/v1/")? {
        rest if rest == "enroll" || rest.starts_with("enroll?") => request.header(header::IDENTITY),
        rest => rest.split(['/', '?']).next(),
    }
}

/// The `identity.json` a delivery carries, when `request` is a `PUT /v1/{id}/identity`
/// the switch took and the document is `identity`'s.
fn taken_document(
    request: &Request,
    answer: &Response,
    identity: &[u8; 32],
) -> Option<IdentityDoc> {
    let path = request.path_and_query.strip_prefix("/v1/")?;
    let (_, route) = path.split_once('/')?;
    if request.method != "PUT" || answer.status != 200 || route != "identity" {
        return None;
    }
    let body: Value = serde_json::from_slice(&request.body).ok()?;
    let signed = serde_json::from_value::<SignedDoc>(body.get("identity")?.clone()).ok()?;
    IdentityDoc::verify(&signed, identity).ok()
}

impl Checker {
    /// The run brings `service_key` for the account `id` (a Pubky ID) of the identity
    /// `identity`: the key a service is set up to answer it with, before any document
    /// names it.
    pub fn account(&self, id: &str, identity: [u8; 32], service_key: [u8; 32]) {
        lock(&self.accounts)
            .entry(id.to_owned())
            .or_insert_with(|| Account::new(identity))
            .bring(service_key);
    }

    /// The service key an enrollment's answer names, which the answer is signed with
    /// (Switch wire 7.4.1): the key of a next generation, or of another service, that the
    /// run hadn't brought. It is taken only when the answer verifies with it.
    fn enrolled_key(
        &self,
        request: &Request,
        answer: &Response,
        verifies: &impl Fn(&[u8; 32]) -> bool,
    ) -> Option<()> {
        let path = request.path_and_query.strip_prefix("/v1/")?;
        if answer.status != 200 || !(path == "enroll" || path.starts_with("enroll?")) {
            return None;
        }
        let id = request.header(header::IDENTITY)?;
        let body: Value = serde_json::from_slice(&answer.body).ok()?;
        let key = unb64_array::<32>(body.get("service_key")?.as_str()?).ok()?;
        if !verifies(&key) {
            return None;
        }
        lock(&self.accounts).get_mut(id)?.bring(key);
        Some(())
    }

    /// A switch of the run signs with `key`, the answers it can't tie to an account too
    /// (Switch wire 7.1).
    pub fn switch_key(&self, key: [u8; 32]) {
        let mut keys = lock(&self.switch_keys);
        if !keys.contains(&key) {
            keys.push(key);
        }
    }

    /// Verify `answer`'s signature as the switch sent it, and take what it settles: the key
    /// an enrollment names, and the generation a delivered document starts.
    ///
    /// # Errors
    ///
    /// What is wrong with it.
    pub fn signature(&self, request: &Request, answer: &Response) -> Result<SignedWith, String> {
        // As a client checks it (Switch wire 7.1): each header the signature decides on at
        // most once, and a head that is there verifies as the account's with the key that
        // signed the answer.
        for name in [header::SERVICE_SIGNATURE, header::SERVER_TIME, header::HEAD] {
            let count = answer
                .headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case(name))
                .count();
            if count > 1 {
                return Err(format!("the answer carries {name} {count} times"));
            }
        }
        let with = self.signed_with(request, answer)?;
        if let Some(text) = answer.header(header::HEAD) {
            let account = account_id(request).and_then(|id| {
                lock(&self.accounts)
                    .get(id)
                    .map(|account| (account.identity, account.key_of(with)))
            });
            let verifies = SignedHead::from_header(text).ok().zip(account).is_some_and(
                |(head, (identity, key))| {
                    key.is_some_and(|key| head.verify(&key, &identity).is_ok())
                },
            );
            if !verifies {
                return Err("its Switch-Head doesn't verify as the account's head".into());
            }
        }
        Ok(with)
    }

    /// The key [`Checker::signature`] finds `answer`'s signature verifies with.
    fn signed_with(&self, request: &Request, answer: &Response) -> Result<SignedWith, String> {
        let signature = answer
            .header(header::SERVICE_SIGNATURE)
            .and_then(|text| unb64_array::<64>(text).ok())
            .ok_or("the answer carries no service signature")?;
        let server_time = answer
            .header(header::SERVER_TIME)
            .ok_or("the answer carries no service time")?;
        // The request as the switch received it; the empty body field only for the answers
        // a switch may give before it reads the body, without a head (Switch wire 7.1).
        let sent = SentRequest::of(request);
        let before_the_body = answer.header(header::HEAD).is_none()
            && serde_json::from_slice::<Value>(&answer.body)
                .ok()
                .and_then(|body| body["code"].as_str().and_then(ErrorCode::parse))
                .is_some_and(|code| {
                    matches!(
                        code,
                        ErrorCode::TooLarge | ErrorCode::RateLimited | ErrorCode::NotFound
                    ) && code.status() == answer.status
                });
        let verifies = |key: &[u8; 32]| {
            let with = |body_read: bool| {
                verify_response(
                    key,
                    &ResponseParts {
                        status: answer.status,
                        request: sent.received(body_read),
                        server_time,
                        head: answer.header(header::HEAD),
                        body: &answer.body,
                    },
                    &signature,
                )
                .is_ok()
            };
            with(true) || (before_the_body && with(false))
        };
        // An enrollment's answer brings its key with it.
        let _ = self.enrolled_key(request, answer, &verifies);
        if let Some(id) = account_id(request)
            && let Some(account) = lock(&self.accounts).get_mut(id)
        {
            // A delivery the switch took is answered under the key its document names, the
            // generation's key from then on (Switch wire 3.3, 7.3).
            if let Some(doc) = taken_document(request, answer, &account.identity) {
                if !verifies(&doc.inbox().service_key) {
                    return Err(
                        "the delivery isn't answered under the service key its document names"
                            .into(),
                    );
                }
                account.take(&doc)?;
                return Ok(SignedWith::Generation(
                    doc.generation(),
                    account.key_number(&doc.inbox().service_key)?,
                ));
            }
            if let Some((generation, key)) = account.current
                && verifies(&key)
            {
                return Ok(SignedWith::Generation(
                    generation,
                    account.key_number(&key)?,
                ));
            }
            if let Some((number, _)) = account.named.iter().find(|(_, key)| verifies(key)) {
                return Ok(SignedWith::Brought(*number));
            }
        }
        if lock(&self.switch_keys).iter().any(verifies) {
            return Ok(SignedWith::SwitchKey);
        }
        Err(
            "the answer's signature verifies with neither the account's service key nor a \
             switch's key"
                .into(),
        )
    }

    /// Verify what `answer` carries: its heads, stubs, items and proofs, with the key
    /// `signed` says its signature verified with. Returns what is wrong, nothing when all
    /// of it holds or the request is for no account the checker knows.
    pub fn contents(
        &self,
        request: &Request,
        answer: &Response,
        signed: Option<SignedWith>,
    ) -> Vec<String> {
        let Some(id) = account_id(request) else {
            return Vec::new();
        };
        let (identity, key) = {
            let accounts = lock(&self.accounts);
            let Some(account) = accounts.get(id) else {
                return Vec::new();
            };
            let key = signed.and_then(|with| account.key_of(with));
            (account.identity, key)
        };
        let mut found = Found {
            checker: self,
            id,
            identity,
            key,
            signed,
            violations: Vec::new(),
        };
        // The body first: a head is then set against the stubs of its own answer too.
        if let Ok(body) = serde_json::from_slice::<Value>(&answer.body) {
            found.value("body", &body);
        }
        if let Some(text) = answer.header(header::HEAD) {
            match SignedHead::from_header(text) {
                Ok(head) => found.head(&head, "Switch-Head"),
                Err(error) => found.violation(format!("Switch-Head doesn't read: {error}")),
            }
        }
        found.violations
    }
}

/// The checks of one answer.
struct Found<'a> {
    checker: &'a Checker,
    id: &'a str,
    identity: [u8; 32],
    /// The service key the answer's signature verified with, when it was one.
    key: Option<[u8; 32]>,
    signed: Option<SignedWith>,
    violations: Vec<String>,
}

impl Found<'_> {
    fn violation(&mut self, text: String) {
        self.violations.push(text);
    }

    /// The service key to verify `what` at `at` with: the one that signed the answer. An
    /// answer about no account the run knows carries no head or proof of an account; one
    /// whose own signature failed is reported for that already.
    fn key_for(&mut self, what: &str, at: &str) -> Option<[u8; 32]> {
        if self.key.is_none() && self.signed == Some(SignedWith::SwitchKey) {
            self.violation(format!("{at}: {what} in an answer about no account"));
        }
        self.key
    }

    /// Walk a JSON value, checking each head, stub, feed item and proof found in it.
    fn value(&mut self, at: &str, value: &Value) {
        match value {
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    self.value(&format!("{at}[{index}]"), item);
                }
            }
            Value::Object(members) => {
                let is = |names: &[&str]| {
                    members.len() == names.len() && names.iter().all(|n| members.contains_key(*n))
                };
                if is(&["envelope", "chain_hash"]) {
                    match Stub::from_value(value) {
                        Ok(stub) => {
                            self.stub(&stub, at);
                        }
                        Err(error) => self.violation(format!("{at}: a stub doesn't read: {error}")),
                    }
                    return;
                }
                if let (Some(stub), Some(item), Some(item_type)) = (
                    members.get("stub"),
                    members.get("item"),
                    members.get("item_type").and_then(Value::as_str),
                ) {
                    self.item(stub, item, item_type, at);
                }
                for (name, member) in members {
                    let at = format!("{at}.{name}");
                    match name.as_str() {
                        "head" if member.is_object() => match SignedHead::from_value(member) {
                            Ok(head) => self.head(&head, &at),
                            Err(error) => {
                                self.violation(format!("{at}: a head doesn't read: {error}"));
                            }
                        },
                        "proof" if member.is_object() => self.proof(member, &at),
                        "proofs" => {
                            for (index, proof) in
                                member.as_array().into_iter().flatten().enumerate()
                            {
                                self.proof(proof, &format!("{at}[{index}]"));
                            }
                        }
                        _ => self.value(&at, member),
                    }
                }
            }
            _ => {}
        }
    }

    /// A signed head: its signature, its generation, and its chain hash where the run
    /// showed its `seq`.
    fn head(&mut self, head: &SignedHead, at: &str) {
        if let Some(key) = self.key_for("a head", at)
            && head.verify(&key, &self.identity).is_err()
        {
            self.violation(format!(
                "{at}: the head's signature doesn't verify with the key that signed the answer"
            ));
        }
        if let Some(SignedWith::Generation(generation, _)) = self.signed
            && head.generation != generation
        {
            self.violation(format!(
                "{at}: a head of generation {}, where the account's is {generation}",
                head.generation
            ));
        }
        let shown = lock(&self.checker.accounts)
            .get(self.id)
            .and_then(|account| account.chain.get(&head.seq).copied());
        if shown.is_some_and(|link| link.chain_hash != head.chain_hash) {
            self.violation(format!(
                "{at}: the head's chain hash isn't that of the stub the run showed at seq {}",
                head.seq
            ));
        }
    }

    /// A chain stub: its chain hash follows from its envelope, and it links to what the run
    /// showed before. Returns its envelope when it reads.
    fn stub(&mut self, stub: &Stub, at: &str) -> Option<ChainEnvelope> {
        let envelope = match stub.open() {
            Ok(envelope) => envelope,
            Err(error) => {
                self.violation(format!("{at}: {error}"));
                return None;
            }
        };
        let link = Link {
            chain_hash: stub.chain_hash,
            prev: Some(envelope.prev_chain_hash),
        };
        let (same_seq, before, after, since, current) = {
            let mut accounts = lock(&self.checker.accounts);
            let account = accounts.get_mut(self.id)?;
            let same_seq = account.chain.insert(envelope.seq, link);
            let before = envelope
                .seq
                .checked_sub(1)
                .and_then(|seq| account.chain.get(&seq).copied());
            let after = envelope
                .seq
                .checked_add(1)
                .and_then(|seq| account.chain.get(&seq).copied());
            let current = account.current.map(|(generation, _)| generation);
            (same_seq, before, after, account.chain_since, current)
        };
        if same_seq.is_some_and(|shown| shown.chain_hash != stub.chain_hash) {
            self.violation(format!(
                "{at}: another chain hash at seq {} than the run showed before",
                envelope.seq
            ));
        }
        // The `seq` before a sequence's first item is 0, where it starts from 32 zero
        // bytes: its first item follows nothing (Switch wire 6.6).
        if before.is_some_and(|shown| shown.chain_hash != envelope.prev_chain_hash) {
            self.violation(if envelope.seq == 1 {
                format!(
                    "{at}: the stub at seq 1 of generation {} follows something, where a \
                     sequence starts",
                    envelope.generation
                )
            } else {
                format!(
                    "{at}: the stub at seq {} doesn't follow the one the run showed before it",
                    envelope.seq
                )
            });
        }
        if after.is_some_and(|shown| shown.prev.is_some_and(|prev| prev != stub.chain_hash)) {
            self.violation(format!(
                "{at}: the stub the run showed at seq {} doesn't follow this one",
                envelope.seq.saturating_add(1)
            ));
        }
        // A sequence holds the generations from the one it started in to the account's.
        if envelope.generation < since
            || current.is_some_and(|current| envelope.generation > current)
        {
            self.violation(format!(
                "{at}: a stub of generation {}, outside the sequence the account's generation \
                 is in",
                envelope.generation
            ));
        }
        Some(envelope)
    }

    /// A feed item shown in full: its document hashes to its envelope's item hash, and a
    /// service transition is the service's.
    fn item(&mut self, stub: &Value, item: &Value, item_type: &str, at: &str) {
        let item_type = match item_type {
            "op" => ItemType::Op,
            "identity" => ItemType::Identity,
            "service" => ItemType::Service,
            other => {
                self.violation(format!("{at}: an item of the unknown type {other}"));
                return;
            }
        };
        // The stub itself is checked where the walk reaches it.
        let Some(envelope) = Stub::from_value(stub)
            .ok()
            .and_then(|stub| stub.open().ok())
        else {
            return;
        };
        let Ok(signed) = serde_json::from_value::<SignedDoc>(item.clone()) else {
            self.violation(format!("{at}: an item that isn't a signed document"));
            return;
        };
        match signed.doc_bytes() {
            Ok(bytes) => {
                if Verifier::check_item(&envelope, item_type, &bytes).is_err() {
                    self.violation(format!(
                        "{at}: the item at seq {} doesn't hash to its envelope's item hash",
                        envelope.seq
                    ));
                }
            }
            Err(_) => self.violation(format!("{at}: an item that isn't a signed document")),
        }
        if item_type == ItemType::Service
            && let Some(key) = self.key_for("a service transition", at)
            && ServiceTransition::verify(&signed, &key, &self.identity).is_err()
        {
            self.violation(format!(
                "{at}: the transition at seq {} isn't signed with the key that signed the answer",
                envelope.seq
            ));
        }
    }

    /// A transition proof: its signature, and its stub.
    fn proof(&mut self, proof: &Value, at: &str) {
        let Ok(signed) = serde_json::from_value::<SignedDoc>(proof.clone()) else {
            self.violation(format!("{at}: a proof that isn't a signed document"));
            return;
        };
        let Some(key) = self.key_for("a proof", at) else {
            return;
        };
        match TransitionProof::verify(&signed, &key, &self.identity) {
            Ok(proof) => {
                self.stub(&proof.body().chain, &format!("{at}, its stub"));
            }
            Err(_) => self.violation(format!(
                "{at}: the proof's signature doesn't verify with the key that signed the answer"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use pubky_switch_client::transport::Header;
    use pubky_switch_core::chain::ChainTip;
    use pubky_switch_core::enc::b64;
    use pubky_switch_core::http::sign_response;
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_core::records::{IdentityBody, IdentityPolicy, Inbox};
    use serde_json::json;

    use super::*;

    const TIME: &str = "2026-01-01T00:00:00.000Z";

    fn key(n: u8) -> IdentityKey {
        IdentityKey::from_secret([n; 32])
    }

    fn alice() -> IdentityKey {
        key(1)
    }

    fn request(method: &str, route: &str, body: &Value) -> Request {
        let id = alice().id();
        let path = match route {
            "enroll" => "/v1/enroll".to_owned(),
            route => format!("/v1/{id}/{route}"),
        };
        Request {
            method: method.into(),
            origin: "https://switch.example".into(),
            path_and_query: path,
            headers: vec![Header::new(header::IDENTITY, &id)],
            body: serde_json::to_vec(body).unwrap(),
            timeout: pubky_switch_client::transport::TimeoutClass::default(),
        }
    }

    /// An answer to `request` that `service` signs.
    fn answer(request: &Request, service: &IdentityKey, status: u16, body: &Value) -> Response {
        let body = serde_json::to_vec(body).unwrap();
        let signature = sign_response(
            service,
            &ResponseParts {
                status,
                request: SentRequest::of(request).received(true),
                server_time: TIME,
                head: None,
                body: &body,
            },
        );
        Response {
            status,
            headers: vec![
                Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
                Header::new(header::SERVER_TIME, TIME),
            ],
            body,
        }
    }

    /// A checker that knows alice's account, the run having brought `service`'s key.
    fn checker(service: &IdentityKey) -> Checker {
        let checker = Checker::default();
        checker.account(&alice().id(), alice().public(), service.public());
        checker.switch_key(key(42).public());
        checker
    }

    /// alice's `identity.json` of `generation`, naming `service`'s key.
    fn document(generation: u64, service: &IdentityKey, recovery_from: Option<u64>) -> Value {
        let inbox = Inbox {
            url: "https://switch.example".into(),
            service_key: service.public(),
        };
        let mut body =
            IdentityBody::first(alice().public(), [7; 16], inbox, IdentityPolicy::default());
        body.generation = generation;
        body.version = generation;
        body.recovery_from = recovery_from;
        let doc = IdentityDoc::sign(&alice(), body).unwrap();
        json!({ "identity": doc.signed() })
    }

    /// Deliver alice's document of `generation` naming `named`, answered `200` by `by`.
    fn deliver(
        checker: &Checker,
        generation: u64,
        named: &IdentityKey,
        by: &IdentityKey,
        recovery_from: Option<u64>,
    ) -> Result<SignedWith, String> {
        let put = request(
            "PUT",
            "identity",
            &document(generation, named, recovery_from),
        );
        checker.signature(&put, &answer(&put, by, 200, &json!({})))
    }

    /// What the checker finds wrong in an answer `service` signs with `body`.
    fn violations(checker: &Checker, service: &IdentityKey, body: &Value) -> Vec<String> {
        let get = request("GET", "feed", &json!(null));
        let answer = answer(&get, service, 200, body);
        let signed = checker.signature(&get, &answer).ok();
        checker.contents(&get, &answer, signed)
    }

    /// The first `count` stubs of a sequence of `generation`, from the zero hash.
    fn stubs(generation: u64, count: u64) -> Vec<Stub> {
        let mut tip = ChainTip {
            generation,
            seq: 0,
            chain_hash: ZERO_HASH,
        };
        (1..=count)
            .map(|seq| {
                let (stub, next) = tip
                    .append(seq, 1_000, ItemType::Identity, [seq as u8; 32], None)
                    .unwrap();
                tip = next;
                stub
            })
            .collect()
    }

    fn shown(stubs: &[&Stub]) -> Value {
        let stubs: Vec<Value> = stubs.iter().map(|stub| stub.to_value()).collect();
        json!({ "stubs": stubs })
    }

    #[test]
    fn test_enrollment_key_is_taken_only_when_its_answer_verifies_with_it() {
        let (first, next) = (key(2), key(3));
        let checker = checker(&first);
        let enroll = request("POST", "enroll", &json!({}));
        let names_next = json!({ "service_key": b64(&next.public()) });
        // Signed with another key than the one it names: the named key isn't taken.
        let forged = answer(&enroll, &first, 200, &names_next);
        assert_eq!(
            checker.signature(&enroll, &forged),
            Ok(SignedWith::Brought(1))
        );
        let get = request("GET", "apps", &json!(null));
        assert!(
            checker
                .signature(&get, &answer(&get, &next, 200, &json!({})))
                .is_err(),
            "a key no verified enrollment answer named"
        );
        // Signed with the key it names: the run's second key.
        let honest = answer(&enroll, &next, 200, &names_next);
        assert_eq!(
            checker.signature(&enroll, &honest),
            Ok(SignedWith::Brought(2))
        );
        assert_eq!(
            checker.signature(&get, &answer(&get, &next, 200, &json!({}))),
            Ok(SignedWith::Brought(2))
        );
        // A refusal names no key.
        let refused = answer(
            &enroll,
            &key(4),
            400,
            &json!({ "service_key": b64(&key(4).public()) }),
        );
        assert!(checker.signature(&enroll, &refused).is_err());
    }

    #[test]
    fn test_generation_key_is_the_one_its_document_names() {
        let (first, next) = (key(2), key(3));
        let checker = checker(&first);
        let get = request("GET", "apps", &json!(null));
        let signs = |service: &IdentityKey| {
            checker.signature(&get, &answer(&get, service, 200, &json!({})))
        };
        assert_eq!(signs(&first), Ok(SignedWith::Brought(1)));
        assert_eq!(
            deliver(&checker, 1, &first, &first, None),
            Ok(SignedWith::Generation(1, 1))
        );
        assert_eq!(signs(&first), Ok(SignedWith::Generation(1, 1)));
        // The next generation's key, brought and not delivered: both sign for now.
        checker.account(&alice().id(), alice().public(), next.public());
        assert_eq!(signs(&next), Ok(SignedWith::Brought(2)));
        assert_eq!(signs(&first), Ok(SignedWith::Generation(1, 1)));
        assert_eq!(
            deliver(&checker, 2, &next, &next, Some(1)),
            Ok(SignedWith::Generation(2, 2))
        );
        assert_eq!(signs(&next), Ok(SignedWith::Generation(2, 2)));
        // The outgoing key is held no longer.
        assert!(signs(&first).is_err(), "the outgoing generation's key");
        // A switch's key, for no account the run knows, stays so.
        assert_eq!(signs(&key(42)), Ok(SignedWith::SwitchKey));
    }

    #[test]
    fn test_signature_name_stays_the_same_across_recovery() {
        let service = key(2);
        let checker = checker(&service);
        let get = request("GET", "apps", &json!(null));
        let refused = answer(&get, &service, 403, &json!({ "code": "not_current" }));
        let name = || {
            let with = checker.signature(&get, &refused).unwrap();
            with.to_string()
        };
        let enrolled = name();
        deliver(&checker, 1, &service, &service, None).unwrap();
        assert_eq!(name(), enrolled);
        deliver(&checker, 2, &service, &service, Some(1)).unwrap();
        assert_eq!(name(), enrolled);
        let next = key(3);
        checker.account(&alice().id(), alice().public(), next.public());
        deliver(&checker, 3, &next, &next, Some(2)).unwrap();
        let with = checker
            .signature(&get, &answer(&get, &next, 403, &json!({})))
            .unwrap();
        assert_ne!(with.to_string(), enrolled);
    }

    #[test]
    fn test_generation_key_refuses_a_delivery_under_another_key() {
        let (first, next, third) = (key(2), key(3), key(4));
        let checker = checker(&first);
        checker.account(&alice().id(), alice().public(), next.public());
        // Answered with a key the account holds, but not the one the document names.
        let wrong = deliver(&checker, 1, &first, &next, None);
        assert!(wrong.is_err_and(|error| error.contains("its document names")));
        assert_eq!(
            deliver(&checker, 1, &first, &first, None),
            Ok(SignedWith::Generation(1, 1))
        );
        // Another key for a generation whose document is taken.
        checker.account(&alice().id(), alice().public(), third.public());
        let other = deliver(&checker, 1, &third, &third, None);
        assert!(other.is_err_and(|error| error.contains("another service key")));
        // A document of a generation before the account's.
        assert_eq!(
            deliver(&checker, 2, &next, &next, Some(1)),
            Ok(SignedWith::Generation(2, 2))
        );
        let earlier = deliver(&checker, 1, &next, &next, None);
        assert!(earlier.is_err_and(|error| error.contains("generation 1 was taken")));
        // A refused delivery settles nothing.
        let put = request("PUT", "identity", &document(3, &third, Some(2)));
        assert_eq!(
            checker.signature(&put, &answer(&put, &next, 400, &json!({}))),
            Ok(SignedWith::Generation(2, 2))
        );
    }

    #[test]
    fn test_head_verifies_with_the_key_that_signed_its_answer() {
        let (first, next) = (key(2), key(3));
        let checker = checker(&first);
        deliver(&checker, 1, &first, &first, None).unwrap();
        checker.account(&alice().id(), alice().public(), next.public());
        let tip = |generation| ChainTip {
            generation,
            seq: 0,
            chain_hash: ZERO_HASH,
        };
        let head = |service: &IdentityKey, generation| json!({ "head": SignedHead::sign(service, &alice().public(), &tip(generation)).to_value() });
        assert_eq!(
            violations(&checker, &first, &head(&first, 1)),
            Vec::<String>::new()
        );
        // Signed with a key the account holds, but not the one that signed the answer.
        let other = violations(&checker, &first, &head(&next, 1));
        assert!(
            other.iter().any(|v| v.contains("the head's signature")),
            "{other:?}"
        );
        // Of another generation than the account's.
        let ahead = violations(&checker, &first, &head(&first, 2));
        assert!(
            ahead.iter().any(|v| v.contains("a head of generation 2")),
            "{ahead:?}"
        );
        // In an answer about no account.
        let unattached = violations(&checker, &key(42), &head(&first, 1));
        assert!(
            unattached
                .iter()
                .any(|v| v.contains("in an answer about no account")),
            "{unattached:?}"
        );
    }

    /// An answer to `request` that `service` signs carrying `head` as its `Switch-Head`.
    fn answer_with_head(request: &Request, service: &IdentityKey, head: &str) -> Response {
        let body = b"{}".to_vec();
        let signature = sign_response(
            service,
            &ResponseParts {
                status: 200,
                request: SentRequest::of(request).received(true),
                server_time: TIME,
                head: Some(head),
                body: &body,
            },
        );
        Response {
            status: 200,
            headers: vec![
                Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
                Header::new(header::SERVER_TIME, TIME),
                Header::new(header::HEAD, head),
            ],
            body,
        }
    }

    #[test]
    fn test_signature_refuses_what_a_client_refuses() {
        // As the client's check (Switch wire 7.1): a signed response header sent twice, and a
        // head that doesn't verify as the account's, fail the answer.
        let service = key(2);
        let checker = checker(&service);
        deliver(&checker, 1, &service, &service, None).unwrap();
        let get = request("GET", "feed", &json!(null));
        let plain = answer(&get, &service, 200, &json!({}));
        assert!(checker.signature(&get, &plain).is_ok());
        for name in [header::SERVICE_SIGNATURE, header::SERVER_TIME] {
            let mut repeated = plain.clone();
            let copy = repeated.header(name).unwrap().to_owned();
            repeated.headers.push(Header::new(name, &copy));
            assert!(checker.signature(&get, &repeated).is_err(), "{name}");
        }
        let tip = ChainTip {
            generation: 1,
            seq: 0,
            chain_hash: ZERO_HASH,
        };
        let good = SignedHead::sign(&service, &alice().public(), &tip).to_header();
        let headed = answer_with_head(&get, &service, &good);
        assert!(checker.signature(&get, &headed).is_ok());
        let mut doubled = headed.clone();
        doubled.headers.push(Header::new(header::HEAD, &good));
        assert!(checker.signature(&get, &doubled).is_err());
        // Signed by another key, or not a head at all.
        let forged = SignedHead::sign(&key(9), &alice().public(), &tip).to_header();
        for head in [forged.as_str(), "not a head"] {
            let answer = answer_with_head(&get, &service, head);
            assert!(checker.signature(&get, &answer).is_err(), "{head}");
        }
    }

    /// An answer to `request` that `service` signs over the empty body field, as one given
    /// before the body is read.
    fn unread_answer(
        request: &Request,
        service: &IdentityKey,
        status: u16,
        body: &Value,
    ) -> Response {
        let body = serde_json::to_vec(body).unwrap();
        let signature = sign_response(
            service,
            &ResponseParts {
                status,
                request: SentRequest::of(request).received(false),
                server_time: TIME,
                head: None,
                body: &body,
            },
        );
        Response {
            status,
            headers: vec![
                Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
                Header::new(header::SERVER_TIME, TIME),
            ],
            body,
        }
    }

    #[test]
    fn test_signature_takes_the_empty_body_field_only_before_the_body() {
        // As the client's check (Switch wire 7.1): only a `413 too_large`, a `429
        // rate_limited` and a `404 not_found` may verify over the empty body field, each with
        // the status its code fixes; any other answer so signed fails.
        let service = key(2);
        let checker = checker(&service);
        deliver(&checker, 1, &service, &service, None).unwrap();
        let put = request("POST", "ops", &json!({ "ops": [] }));
        let error = |code: &str| json!({ "code": code, "message": "m" });
        for (status, code) in [
            (413, "too_large"),
            (429, "rate_limited"),
            (404, "not_found"),
        ] {
            let answer = unread_answer(&put, &service, status, &error(code));
            assert!(checker.signature(&put, &answer).is_ok(), "{code}");
        }
        for (status, body) in [
            (200, json!({})),
            (400, error("bad_request")),
            (503, error("unavailable")),
            (409, error("too_large")),
            (404, error("rate_limited")),
        ] {
            let answer = unread_answer(&put, &service, status, &body);
            assert!(checker.signature(&put, &answer).is_err(), "{status} {body}");
        }
    }

    #[test]
    fn test_chain_stubs_link_both_ways_from_the_zero_hash() {
        let service = key(2);
        let checker = checker(&service);
        deliver(&checker, 1, &service, &service, None).unwrap();
        let chain = stubs(1, 3);
        // The third first, then the first two: every link holds in any order.
        assert_eq!(
            violations(&checker, &service, &shown(&[&chain[2]])),
            Vec::<String>::new()
        );
        assert_eq!(
            violations(&checker, &service, &shown(&[&chain[0], &chain[1]])),
            Vec::<String>::new()
        );
        // Another stub at a `seq` shown.
        let (other, _) = ChainTip {
            generation: 1,
            seq: 1,
            chain_hash: chain[0].chain_hash,
        }
        .append(2, 2_000, ItemType::Identity, [9; 32], None)
        .unwrap();
        let replaced = violations(&checker, &service, &shown(&[&other]));
        assert!(
            replaced
                .iter()
                .any(|v| v.contains("another chain hash at seq 2")),
            "{replaced:?}"
        );
        assert!(
            replaced
                .iter()
                .any(|v| v.contains("at seq 3 doesn't follow this one")),
            "{replaced:?}"
        );
    }

    #[test]
    fn test_chain_first_item_follows_nothing() {
        let service = key(2);
        let checker = checker(&service);
        deliver(&checker, 1, &service, &service, None).unwrap();
        let (first, _) = ChainTip {
            generation: 1,
            seq: 0,
            chain_hash: [5; 32],
        }
        .append(1, 1_000, ItemType::Identity, [1; 32], None)
        .unwrap();
        let found = violations(&checker, &service, &shown(&[&first]));
        assert!(
            found.iter().any(|v| v.contains("follows something")),
            "{found:?}"
        );
    }

    #[test]
    fn test_chain_starts_afresh_at_a_recovery_only() {
        let (first, next) = (key(2), key(3));
        let old = stubs(1, 2);
        // A recovery: the lost chain is forgotten, and the new one starts from zero.
        let checker = checker(&first);
        deliver(&checker, 1, &first, &first, None).unwrap();
        assert_eq!(
            violations(&checker, &first, &shown(&[&old[0], &old[1]])),
            Vec::<String>::new()
        );
        checker.account(&alice().id(), alice().public(), next.public());
        deliver(&checker, 2, &next, &next, Some(1)).unwrap();
        let fresh = stubs(2, 2);
        assert_eq!(
            violations(&checker, &next, &shown(&[&fresh[0], &fresh[1]])),
            Vec::<String>::new()
        );
        // A stub of the lost generation in the new sequence.
        let lost = violations(&checker, &next, &shown(&[&old[1]]));
        assert!(
            lost.iter().any(|v| v.contains("a stub of generation 1")),
            "{lost:?}"
        );

        // A recovery chained onto the lost chain's tip.
        let checker = self::checker(&first);
        deliver(&checker, 1, &first, &first, None).unwrap();
        checker.account(&alice().id(), alice().public(), next.public());
        deliver(&checker, 2, &next, &next, Some(1)).unwrap();
        let (chained, _) = ChainTip {
            generation: 2,
            seq: 0,
            chain_hash: old[1].chain_hash,
        }
        .append(1, 3_000, ItemType::Service, [8; 32], None)
        .unwrap();
        let onto = violations(&checker, &next, &shown(&[&chained]));
        assert!(
            onto.iter().any(|v| v.contains("follows something")),
            "{onto:?}"
        );

        // A next generation that is no recovery goes on in the same sequence.
        let checker = self::checker(&first);
        deliver(&checker, 1, &first, &first, None).unwrap();
        assert_eq!(
            violations(&checker, &first, &shown(&[&old[0], &old[1]])),
            Vec::<String>::new()
        );
        checker.account(&alice().id(), alice().public(), next.public());
        deliver(&checker, 2, &next, &next, None).unwrap();
        let on = |from: [u8; 32]| {
            ChainTip {
                generation: 2,
                seq: 2,
                chain_hash: from,
            }
            .append(3, 3_000, ItemType::Identity, [3; 32], None)
            .unwrap()
            .0
        };
        let unlinked = violations(&checker, &next, &shown(&[&on([6; 32])]));
        assert!(
            unlinked
                .iter()
                .any(|v| v.contains("at seq 3 doesn't follow")),
            "{unlinked:?}"
        );
        // A sequence started again where it goes on.
        let again = violations(&checker, &next, &shown(&[&stubs(2, 1)[0]]));
        assert!(
            again
                .iter()
                .any(|v| v.contains("another chain hash at seq 1")),
            "{again:?}"
        );
    }

    #[test]
    fn test_proof_verifies_with_the_key_that_signed_its_answer() {
        let (first, next) = (key(2), key(3));
        let checker = checker(&first);
        deliver(&checker, 1, &first, &first, None).unwrap();
        checker.account(&alice().id(), alice().public(), next.public());
        let proof = |service: &IdentityKey| {
            let body = pubky_switch_core::chain::ProofBody {
                chain: stubs(1, 1).remove(0),
                object: "identity".into(),
                step: None,
                version: Some(1),
                state: json!({}),
            };
            let proof = TransitionProof::sign(service, &alice().public(), body).unwrap();
            json!({ "proofs": [proof.signed()] })
        };
        assert_eq!(
            violations(&checker, &first, &proof(&first)),
            Vec::<String>::new()
        );
        let other = violations(&checker, &first, &proof(&next));
        assert!(
            other.iter().any(|v| v.contains("the proof's signature")),
            "{other:?}"
        );
    }
}
