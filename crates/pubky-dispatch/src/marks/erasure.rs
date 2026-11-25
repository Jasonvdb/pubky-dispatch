//! Pending erasure attempts are uncertainty, never completed deletion (wire 7.3 Table 3).

use super::*;

/// The exact authenticated deletion whose outcome is still being established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErasureAttempt {
    #[serde(with = "hex_bytes")]
    pub token: [u8; 32],
    pub created_at_ms: u64,
    pub erased_at_ms: u64,
    pub identity_hash: Option<[u8; 32]>,
}

impl ErasureAttempt {
    pub fn new(
        created_at_ms: u64,
        erased_at_ms: u64,
        identity_hash: Option<[u8; 32]>,
    ) -> Result<Self, MarkStoreError> {
        let mut token = [0; 32];
        getrandom::fill(&mut token).map_err(|_| MarkStoreError::Random)?;
        Ok(Self {
            token,
            created_at_ms,
            erased_at_ms,
            identity_hash,
        })
    }

    pub fn bytes(&self) -> Result<Vec<u8>, MarkStoreError> {
        serde_json::to_vec(self).map_err(|error| MarkStoreError::StoreUnreadable(error.to_string()))
    }
}

impl MarkStore {
    pub(crate) async fn erasure_attempt(
        &self,
        identity: &str,
    ) -> Result<Option<ErasureAttempt>, MarkStoreError> {
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        blocking(move || {
            inner.reading(RecordScope::Identity(&identity), |_| {
                Ok(inner.attempts.lock().get(&identity).cloned())
            })
        })
        .await
    }

    pub(crate) async fn begin_erasure(
        &self,
        identity: &str,
        attempt: ErasureAttempt,
    ) -> Result<(), MarkStoreError> {
        self.check_gate()?;
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        self.write(move |gate| {
            inner.writing(gate.as_ref(), RecordScope::Identity(&identity), |_| {
                inner.write_atomic(&inner.attempts_dir().join(&identity), &attempt.bytes()?)
            })
        })
        .await
    }

    /// Remove only the attempt whose outcome was established under the identity lock.
    pub(crate) async fn clear_erasure_attempt(
        &self,
        identity: &str,
        attempt: ErasureAttempt,
    ) -> Result<(), MarkStoreError> {
        self.check_gate()?;
        let inner = self.inner.clone();
        let identity = valid_identity(identity)?;
        self.write(move |gate| {
            inner.writing(gate.as_ref(), RecordScope::Identity(&identity), |_| {
                if inner.attempts.lock().get(&identity) != Some(&attempt) {
                    return Err(MarkStoreError::StoreUnreadable(
                        "the erasure attempt changed".into(),
                    ));
                }
                inner.remove_durably(&inner.attempts_dir().join(&identity))
            })
        })
        .await
    }
}

impl Inner {
    pub(super) fn attempts_dir(&self) -> PathBuf {
        self.accounts().join("erasure-attempts")
    }

    pub(super) fn confirm_attempt(&self, identity: &str) -> Result<(), MarkStoreError> {
        let path = self.attempts_dir().join(identity);
        let bytes = read_record_file(&path, MAX_MARK_FILE)?;
        let pending = self.pending.lock().get(&path).cloned();
        let expected = match &pending {
            Some(bytes) => bytes.clone(),
            None => self
                .attempts
                .lock()
                .get(identity)
                .map(ErasureAttempt::bytes)
                .transpose()?,
        };
        if bytes != expected {
            return Err(MarkStoreError::StoreUnreadable(
                "an erasure attempt changed".into(),
            ));
        }
        if pending.is_some() {
            self.sync_dir(&self.attempts_dir())?;
        }
        Ok(())
    }
}

pub(super) fn attempt_from_bytes(
    bytes: Option<&[u8]>,
) -> Result<Option<ErasureAttempt>, MarkStoreError> {
    let Some(bytes) = bytes else { return Ok(None) };
    let attempt: ErasureAttempt = serde_json::from_slice(bytes)
        .map_err(|error| MarkStoreError::StoreUnreadable(error.to_string()))?;
    if attempt.erased_at_ms < attempt.created_at_ms {
        return Err(MarkStoreError::StoreUnreadable(
            "an erasure predates its account".into(),
        ));
    }
    Ok(Some(attempt))
}

pub(super) fn read_attempts(dir: &Path) -> Result<HashMap<String, ErasureAttempt>, MarkStoreError> {
    let mut attempts = HashMap::new();
    for (name, path) in store_files(dir, "erasure-attempts")? {
        if !is_ledger_name(&name) {
            return Err(MarkStoreError::InvalidIdentity);
        }
        if let Some(attempt) =
            attempt_from_bytes(read_record_file(&path, MAX_MARK_FILE)?.as_deref())?
        {
            attempts.insert(name, attempt);
        }
    }
    Ok(attempts)
}
