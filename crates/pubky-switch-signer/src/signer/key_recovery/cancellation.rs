//! Disposition of an ordinary existing enrollment before the recovery signs its version
//! (Switch spec 12.8, Switch account binding 3).

use super::{
    AccountObservation, Enrollment, EnrollmentAnswer, Flow, Held, KeyEnrollmentStep,
    KeyRecoveryStop, RecordsFault, Refusal, RequestClient, Result, Signer, Target, UserConfirmed,
    gate, stop,
};

impl Signer {
    /// The original service for a locally pending ordinary recovery, before the install
    /// signs its version (Switch spec 12.8). The host can offer to resume or stop here.
    pub fn pending_key_recovery(&self) -> Option<&str> {
        match &self.flow {
            Some(Flow::KeyRecover { origin, .. }) => Some(origin),
            _ => None,
        }
    }

    /// Stop a pending ordinary key recovery on the holder's confirmation (Switch spec 12.8).
    /// Where its enrollment may already have been sent, retry that exact enrollment to
    /// obtain its result. The call signs no identity document. With the result already
    /// recorded, or before the first possible send, it needs no network.
    ///
    /// # Errors
    ///
    /// [`Refusal::NoPendingKeyRecovery`] after the recovery signed its version or with
    /// another operation pending. An unverifiable, unavailable or differently bound
    /// enrollment answer leaves the original recovery available for retry.
    pub async fn cancel_key_recovery(&mut self, _confirmed: UserConfirmed) -> Result<()> {
        self.refresh().await?;
        let Some(Flow::KeyRecover {
            origin,
            enrollment,
            step,
            fresh,
            ..
        }) = self.flow.clone()
        else {
            return Err(Refusal::NoPendingKeyRecovery.into());
        };
        // Even a wholly local stop requires the original store and its identity key.
        drop(gate::key_recovery_key(&self.keyring, &self.store)?);
        let (observed, signed) = enrollment.existing(&self.state.identity, &origin)?;
        let held = if fresh { Held::Fresh } else { Held::InPlace };
        if matches!(step, KeyEnrollmentStep::Sending) {
            let answer = self.key_enrollment_answer(&observed, &signed, held).await?;
            if answer.service_key != observed.body().service_key {
                return Err(stop(KeyRecoveryStop::NotServing));
            }
        }
        if held == Held::InPlace && self.state.before_first_version() {
            // The original signed creation was retired when the holder selected this
            // serving account. A fresh survey still needs that authenticated selection.
            let flow = Flow::FirstAccountPresent {
                origin,
                observation: observed.carried().clone(),
            };
            return self.commit(self.state.clone(), Some(flow)).await;
        }
        self.clear_key_recovery(held).await
    }

    /// Persist possible dispatch before HTTP and a verified success before another survey.
    /// Over damaged records, the first local change remains the recovery version's commit.
    pub(super) async fn key_enrollment_answer(
        &mut self,
        observed: &AccountObservation,
        signed: &Enrollment,
        held: Held,
    ) -> Result<EnrollmentAnswer> {
        if held != Held::Unusable {
            match &self.flow {
                Some(Flow::KeyRecover {
                    step: KeyEnrollmentStep::Applied(answer),
                    ..
                }) => {
                    return Ok((**answer).clone());
                }
                Some(Flow::KeyRecover {
                    step: KeyEnrollmentStep::Sending,
                    ..
                }) => {}
                Some(Flow::KeyRecover {
                    step: KeyEnrollmentStep::Unsent,
                    ..
                }) => {
                    self.record_enrollment_step(KeyEnrollmentStep::Sending)
                        .await?;
                }
                _ => return Err(RecordsFault::Invariant("missing key recovery enrollment").into()),
            }
        }
        let target = Target {
            origin: &observed.body().origin,
            pinned: Some(observed.body().service_key),
            created: signed.body().intent.created(),
            identity: self.state.identity,
        };
        let answer = RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
            .enroll(signed)
            .await?;
        if Some(answer.created) != target.created {
            return Err(stop(KeyRecoveryStop::NotServing));
        }
        // Ordinary recovery has its own key-change handling. Only the originally
        // selected service key can settle the enrollment for an offline stop.
        if held != Held::Unusable && answer.service_key == observed.body().service_key {
            self.record_enrollment_step(KeyEnrollmentStep::Applied(Box::new(answer.clone())))
                .await?;
        }
        Ok(answer)
    }

    async fn record_enrollment_step(&mut self, next: KeyEnrollmentStep) -> Result<()> {
        let mut flow = self.flow.clone();
        let Some(Flow::KeyRecover { step, .. }) = &mut flow else {
            return Err(RecordsFault::Invariant("missing key recovery enrollment").into());
        };
        *step = next;
        self.commit(self.state.clone(), flow).await
    }

    pub(super) async fn clear_key_recovery(&mut self, held: Held) -> Result<()> {
        match held {
            Held::Fresh => {
                self.delete_records().await?;
                self.flow = None;
                self.unsure = true;
                Ok(())
            }
            Held::InPlace => self.commit(self.state.clone(), None).await,
            Held::Unusable => Ok(()),
        }
    }
}
