//! Confirmed restoration of a serving account from a pending first setup (Switch account binding 3).

use crate::alert::FirstEnrollmentStop;
use pubky_switch_core::records::{Enrollment, IdentityDoc};

use super::{
    BackupFound, BackupView, Held, KeyPlan, KeyRecoveryConfirmed, KeyRecoverySurvey, RestoreLocal,
    Signer, UserConfirmed, gate, marks_of,
};
use crate::error::{KeyRecoveryStop, Refusal, Result, SignerError};
use crate::state::{Flow, SignerState};

/// The current account and recovery the holder can choose on the installation that still
/// holds a signed first creation (Switch account binding 3). The earlier send may have
/// committed. The service's current signed history supplies the starting version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstEnrollmentRestore {
    /// The creation of the account the selected service currently serves, in Unix milliseconds.
    pub created: u64,
    /// The verified identity document served at this creation, including its exact signed bytes.
    pub identity_doc: IdentityDoc,
    /// The current signer, version, generation, backup and app consequences to show the user.
    pub recovery: KeyRecoverySurvey,
    original: [u8; 32],
    backup: Option<[u8; 32]>,
}

impl Signer {
    /// Recover the local routing field without sending or replacing the signed creation
    /// (Switch account binding 3, Switch spec 12.8).
    pub(in crate::signer) async fn repair_first_origin(
        mut self,
        state: SignerState,
        mut flow: Flow,
    ) -> Result<Self> {
        let sources = self.read_published().await?;
        let view = sources
            .opened
            .as_ref()
            .ok_or(Refusal::NoBackup)?
            .as_ref()
            .ok_or(Refusal::UnreadableBackup)?;
        let expected = &view.identity_doc.inbox().url;
        let original = flow
            .first_creation_at(&state.identity, expected)?
            .ok_or(Refusal::FirstEnrollmentUnavailable)?;
        let observed = original
            .observation()
            .ok_or(Refusal::FirstEnrollmentUnavailable)?;
        let plan = self
            .key_plan_from(
                &state,
                &marks_of(&state)?,
                Some(expected),
                None,
                &sources,
                Some(observed),
            )
            .await?;
        if view.account_created != plan.created || view.identity_doc.signed() != plan.copy.signed()
        {
            return Err(Refusal::StaleBackup.into());
        }
        let Flow::Enroll { origin, .. } = &mut flow else {
            return Err(Refusal::FirstEnrollmentUnavailable.into());
        };
        origin.clone_from(expected);
        self.commit(state, Some(flow)).await?;
        Ok(self)
    }

    /// Read the ordinary recovery at the original service while the first signed creation
    /// is pending (Switch account binding 3). Reads account and backup evidence without
    /// sending an enrollment or retiring its continuation.
    ///
    /// # Errors
    ///
    /// [`Refusal::FirstEnrollmentUnavailable`] when the original setup or current service
    /// binding cannot qualify. Otherwise the refusal of [`Self::survey_key_recovery`].
    pub async fn survey_first_enrollment_restore(
        &mut self,
        origin: &str,
    ) -> Result<FirstEnrollmentRestore> {
        self.refresh().await?;
        let original = self.pending_first_creation(origin)?;
        let (shown, _, _) = Box::pin(self.serving_first_account(&original)).await?;
        Ok(shown)
    }

    /// Restore the account in `shown` once the user accepts that their previous creation
    /// may have committed and confirms the recovery, including any apps `dropped` where
    /// the backup cannot be used (Switch account binding 3 and spec 12.8). The exact
    /// original receipt, when available, continues the original setup.
    ///
    /// # Errors
    ///
    /// The original enrollment error unless its pinned service authenticates a changed
    /// binding. [`KeyRecoveryStop::SurveyChanged`] when the confirmed authority changed.
    /// A refusal before committing the restore keeps the original creation.
    pub async fn restore_first_enrollment(
        &mut self,
        shown: &FirstEnrollmentRestore,
        dropped: &[[u8; 16]],
        _confirmed: UserConfirmed,
    ) -> Result<()> {
        self.refresh().await?;
        let origin = &shown.recovery.origin;
        let original = self.pending_first_creation(origin)?;
        if let Some(error) = gate::refusal(&self.state) {
            return Err(error);
        }
        if original.hash() != shown.original {
            return Err(Refusal::FirstEnrollmentUnavailable.into());
        }
        match Box::pin(self.enroll(origin, original.signed(), original.body().policy)).await {
            Ok(()) => return Box::pin(self.resume()).await,
            Err(SignerError::Switch(error))
                if FirstEnrollmentStop::from_error(&error)
                    == Some(FirstEnrollmentStop::Changed) => {}
            Err(error) => return Err(error),
        }
        let (current, plan, backup) = Box::pin(self.serving_first_account(&original)).await?;
        if current != *shown {
            return Err(Refusal::KeyRecovery(KeyRecoveryStop::SurveyChanged).into());
        }
        if let Some(view) = backup {
            let local = RestoreLocal::intact(self.state.clone())?;
            Box::pin(self.restore_from_copy(view, plan.answer, Some(local), None)).await?;
        } else {
            let confirmed = KeyRecoveryConfirmed::shown_and_confirmed(&current.recovery, dropped);
            let marks = marks_of(&self.state)?;
            Box::pin(self.start_key_recovery(
                self.state.clone(),
                &marks,
                Held::InPlace,
                plan,
                confirmed,
            ))
            .await?;
        }
        Ok(())
    }

    /// Read the ordinary recovery once, including the backup bytes it would actually use.
    /// The pending creation selects neither a new provider nor a new signer history.
    async fn serving_first_account(
        &self,
        original: &Enrollment,
    ) -> Result<(FirstEnrollmentRestore, KeyPlan, Option<BackupView>)> {
        if let Some(error) = gate::refusal(&self.state) {
            return Err(error);
        }
        let old = original
            .observation()
            .ok_or(Refusal::FirstEnrollmentUnavailable)?;
        let sources = self.read_published().await?;
        let marks = marks_of(&self.state)?;
        let plan = self
            .key_plan_from(
                &self.state,
                &marks,
                Some(&old.body().origin),
                None,
                &sources,
                Some(old),
            )
            .await?;
        let backup = if plan.survey.backup == BackupFound::Matches {
            let view = sources.opened.flatten().ok_or(Refusal::StaleBackup)?;
            if view.account_created != plan.created
                || view.identity_doc.inbox() != plan.copy.inbox()
                || view.identity_doc.generation() != plan.copy.generation()
            {
                return Err(Refusal::StaleBackup.into());
            }
            Some(view)
        } else {
            None
        };
        let shown = FirstEnrollmentRestore {
            created: plan.created,
            identity_doc: plan.copy.clone(),
            original: original.hash(),
            recovery: plan.survey.clone(),
            backup: sources.backup_hash,
        };
        Ok((shown, plan, backup))
    }
}
