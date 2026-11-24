//! The next-write base and the observation that selected its application (Switch spec 10.3).

use super::*;
use pubky_switch_core::recovery::UploadVersion;

/// One write followed alongside the content the app took. The application carries its
/// signed operation's item hash. A verified feed stub can authenticate a version without
/// providing a transition proof that can be passed on.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FollowedWrite {
    #[serde(with = "write_version_serde")]
    pub(super) version: WriteVersion,
    #[serde(with = "revision_serde")]
    pub(super) applied: ApplicationRef,
    pub(super) proof: Option<SignedDoc>,
    pub(super) deleted: bool,
    pub(super) named: bool,
}

mod write_version_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Version {
        #[serde(with = "version_serde")]
        version: RecordVersion,
        authenticated: bool,
        #[serde(with = "version_serde")]
        expected: RecordVersion,
    }

    pub(super) fn serialize<S: Serializer>(v: &WriteVersion, s: S) -> Result<S::Ok, S::Error> {
        Version {
            version: v.version,
            authenticated: v.authenticated,
            expected: v.expected_version,
        }
        .serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<WriteVersion, D::Error> {
        let v = Version::deserialize(d)?;
        Ok(WriteVersion {
            version: v.version,
            authenticated: v.authenticated,
            expected_version: v.expected,
        })
    }
}

pub(super) fn position(generation: u64, seq: u64) -> FeedPosition {
    FeedPosition { generation, seq }
}

/// The two independent comparisons, made with the verified operation and the answer that
/// showed it. A local reopening supplies no new observation of the service.
#[derive(Clone, Copy)]
pub(super) struct Placement {
    pub(super) content: Order,
    pub(super) base: Order,
    pub(super) at: Option<FeedPosition>,
    pub(super) historical: Option<Historical>,
    /// The version number the service installed in the uploaded operation's generation.
    pub(super) upload_version: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Historical {
    Overtaken(ShownWrite, RecordVersion),
    Unordered,
}

impl Historical {
    pub(super) fn read(self) -> WriteRead {
        match self {
            Self::Overtaken(write, at) => WriteRead::Overtaken(write, at),
            Self::Unordered => WriteRead::Unordered,
        }
    }
}

impl App {
    pub(in crate::app) fn covers(&self, at: FeedPosition, earlier: FeedPosition) -> bool {
        self.received_order(at, earlier)
            .is_some_and(std::cmp::Ordering::is_ge)
    }

    pub(super) fn place_write(
        &self,
        write: &FollowedWrite,
        writer: [u8; 16],
        evidence: &Evidence<'_>,
        held: Option<&HeldRecord>,
    ) -> Result<Placement, String> {
        let item = write.applied.item_hash;
        let version = write.version;
        let current_at = evidence.current_at;
        let at = match current_at {
            CurrentAt::Answer(v) | CurrentAt::BeforeUpload(v) | CurrentAt::KeyAtKnownTip(v, _) => {
                Some(position(v.generation, v.version))
            }
            CurrentAt::Itself => Some(position(
                version.version.generation,
                version.version.version,
            )),
            CurrentAt::Local => None,
        };
        let compare = |v: &WriteVersion, hash| {
            compare_with_held(&version, (item, writer), v, hash, current_at)
        };
        let content = match held {
            Some(h) => compare(&h.write_version(), h.item_hash)?,
            None => Order::Newer,
        };
        let base = match held.and_then(|h| h.follow.as_ref()) {
            Some(f) => compare(&f.version, f.applied.item_hash)?,
            None => content,
        };
        let historical = match (base, content) {
            (Order::Overtaken(w, at), _) | (_, Order::Overtaken(w, at)) => {
                Some(Historical::Overtaken(w, at))
            }
            _ => at.zip(held).and_then(|(at, h)| {
                let (_, applied, _) = h.base_write();
                let application = position(write.applied.generation, write.applied.seq);
                let selected = position(applied.generation, applied.seq);
                let selects_application = matches!(base, Order::Newer | Order::Equal)
                    || version.version == h.base_write().0;
                let observation_order = self.received_order(at, h.observed);
                let application_order = if selects_application {
                    self.received_order(application, selected)
                } else {
                    Some(std::cmp::Ordering::Equal)
                };
                match (observation_order, application_order) {
                    (Some(std::cmp::Ordering::Less), _) | (_, Some(std::cmp::Ordering::Less)) => {
                        let shown = ShownWrite {
                            version: version.version,
                            authenticated: version.authenticated,
                            item_hash: item,
                            writer,
                        };
                        Some(Historical::Overtaken(
                            shown,
                            RecordVersion::new(at.generation, at.seq),
                        ))
                    }
                    (None, _) | (_, None) => Some(Historical::Unordered),
                    _ => None,
                }
            }),
        };
        Ok(Placement {
            content,
            base,
            at,
            historical,
            upload_version: evidence
                .view_version
                .zip(at)
                .filter(|(v, at)| {
                    is_upload_version(*v, write.applied, version, at.generation, Some(&self.state))
                })
                .map(|(v, _)| v.version),
        })
    }
}

/// Check a reported installation against the write and the newest permitted generation.
/// A stored record is checked against the current identity again before use.
fn is_upload_version(
    installed: RecordVersion,
    applied: ApplicationRef,
    write: WriteVersion,
    generation: u64,
    state: Option<&crate::app::AppState>,
) -> bool {
    let Some(bound) = UploadVersion::bound(write.version.generation, write.expected_version) else {
        return false;
    };
    // A receipt for the lost generation can replace an unproved lower bound.
    let can_date = !write.authenticated
        && write.version == bound.version
        && state.is_none_or(|s| s.own_doc.body().recovery_from == Some(installed.generation));
    installed.generation < applied.generation
        && applied.generation <= generation
        && state.is_none_or(|s| {
            applied.generation <= s.meta.generation
                && s.own_doc
                    .body()
                    .recovery_from
                    .is_some_and(|lost| installed.generation <= lost)
        })
        && installed.generation == write.version.generation
        && installed > write.expected_version
        && (1..=pubky_switch_core::json::MAX_INT).contains(&installed.version)
        && (installed == write.version || installed == bound.version || can_date)
}

impl HeldRecord {
    /// The installed version the stored write and its observation allow.
    pub(super) fn installed_version(
        &self,
        state: Option<&crate::app::AppState>,
    ) -> Option<RecordVersion> {
        let seq = self.upload_version?;
        let (write, applied) = match &self.follow {
            Some(f) => (f.version, f.applied),
            None => (self.write_version(), self.applied),
        };
        let installed = RecordVersion::new(write.version.generation, seq);
        is_upload_version(installed, applied, write, self.observed.generation, state)
            .then_some(installed)
    }
}

impl FollowedWrite {
    /// Retain the strongest evidence for this same operation across another observation.
    pub(super) fn retain(&mut self, version: WriteVersion, proof: Option<&SignedDoc>) {
        if version.authenticated && !self.version.authenticated {
            self.version = version;
            self.proof = proof
                .cloned()
                .or_else(|| self.proof.take().filter(|p| proof_at(p, version.version)));
        } else if self.proof.is_none() {
            self.proof = proof
                .filter(|p| !self.version.authenticated || proof_at(p, self.version.version))
                .cloned();
        }
    }
}

pub(super) fn proof_at(proof: &SignedDoc, version: RecordVersion) -> bool {
    TransitionProof::peek(proof).is_ok_and(|p| {
        let e = p.envelope();
        (e.generation, e.seq) == (version.generation, version.version)
    })
}

/// Check the local fields together on every read, including the scope-limited previous
/// installation reader. Only the original verification can establish authentication.
impl<'de> Deserialize<'de> for HeldRecord {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let mut held = Self::deserialize(d)?;
        held.applied.check().map_err(D::Error::custom)?;
        if held.applied.item_hash != held.item_hash
            || held.observed.generation == 0
            || (held.gone && held.delete_base().is_none())
        {
            return Err(D::Error::custom("invalid held record application"));
        }
        if held.installed_version(None).is_none() {
            held.upload_version = None;
        }
        let Some(f) = &held.follow else {
            return Ok(held);
        };
        f.applied.check().map_err(D::Error::custom)?;
        let v = f.version.version;
        let expected = f.version.expected_version;
        let valid = |x: RecordVersion| applied_at(x, f.applied.item_hash).check().is_ok();
        if !valid(v) || !(expected.is_none() || valid(expected)) || v <= expected {
            return Err(D::Error::custom("invalid followed record version"));
        }
        if f.applied.item_hash == held.item_hash
            && (expected != held.expected
                || (f.version.authenticated && held.authenticated && v != held.version))
        {
            return Err(D::Error::custom(
                "followed write disagrees with the held record",
            ));
        }
        if let Some(doc) = &f.proof {
            let proof = TransitionProof::peek(doc).map_err(D::Error::custom)?;
            let envelope = proof.envelope();
            if envelope.item_hash != f.applied.item_hash
                || envelope.generation != v.generation
                || (f.version.authenticated
                    && (envelope.seq != v.version
                        || !SignedOp::peek(&held.op).is_ok_and(|op| {
                            matches!(&op.body().kind,
                        OpKind::RecordPut(put) if proof.body().object == b64(&put.key))
                        })))
            {
                return Err(D::Error::custom("proof does not match the followed record"));
            }
        }
        Ok(held)
    }
}

impl Serialize for HeldRecord {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Self::serialize(self, s)
    }
}
