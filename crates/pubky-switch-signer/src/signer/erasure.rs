//! Erasing the identity's account at its switch, when the user stops using the Switch (Switch
//! spec 12.7; Switch wire 7.4.16).
//!
//! [`Signer::close_account`] commits the erasure as a flow, then:
//!
//! 1. deletes `identity.json` and every app record it knows of from the Homeserver, so
//!    counterparties find no identity on the Switch instead of one whose switch doesn't
//!    answer, and asks the user to revoke the Pubky grant of each app, listed or removed,
//!    whose reminder isn't raised yet ([`Alert::GrantRevocationOwed`]), since the Pubky SDK
//!    offers no call for it (design note, decision 4);
//! 2. sends `POST /v1/{id}/erase` naming the account's creation time, as its enrollment
//!    answer gave it, and, once this install delivered a version there, the hash of its mark
//!    as `identity_hash`, the same body again until it is answered or, after
//!    a request in doubt, the check's read meets the switch's `404`, marking before each
//!    request that it may land. A `200` confirms the erasure. After a request that may have
//!    landed, as a lost `200` leaves it, so does the `404` the pinned key signed for an
//!    identity the service doesn't host, at once. A `404` the pinned key didn't sign, which
//!    may be an intermediary's, confirms it only once every check has met it for 24 hours:
//!    until then the account is erased but unconfirmed ([`Refusal::ErasureUnconfirmed`]), the
//!    time of the first `404` kept in the flow, and any other answer the pinned key signs, at
//!    any read, ends the wait (Switch wire 7.4.16 "The signer's `404`", spec 12.7 step 5). A
//!    `404` is never itself a lost answer: with no request in doubt it is an error, and the
//!    mark goes back. No answer, or another answer the pinned key didn't sign, such as a
//!    gateway's `503`, keeps the mark; only an answer the pinned key signed shows the account
//!    still exists, and clears it.
//!
//! Every deletion and every request comes after a fresh check that this install still signs,
//! since the flow may be resumed much later: every copy, as before a delivery
//! ([`Signer::check_copies`]), before the first deletion and each request, and the switch's
//! copy and the Homeserver's `identity.json` before each later deletion; then the signing
//! gate. Another install found signing ends the erasure without erasing, with nothing more
//! deleted, sent or published by this install; an alarm or records behind keep it in
//! progress, with nothing deleted or sent while the alarm is held; a copy that can't be read
//! takes no step. After a request in doubt, the signed `404` of an identity the service
//! doesn't host to the check, with every other copy clean, is the erasure done, and an
//! unsigned `404` so is taken once it has held for 24 hours, no other request going out
//! meanwhile. Revocations are refused during an erasure, and none pending is
//! sent: it signs nothing else (spec 12.7 step 5).
//!
//! A `409 conflict`, signed, is the switch refusing it: another creation time, another
//! `identity.json` than the mark, or a move in progress. Every one names the creation time it
//! was checked against: one other than the request named is kept as the account's and the
//! erasure sent again naming it, once, as a signer that holds none, after a restore or a
//! hand-over, learns it; a `409` without a readable one stops the erasure there, in progress,
//! and tells the user (Switch wire 7.4.16). At an account that answers the notice, where `GET
//! /apps` answers the notice too, the `409` also carries the copy the account holds, which is
//! judged as every copy and named in the erasure sent again, a copy older than the newest
//! delivered there included: the state the account lost. The request didn't land, so it is no longer in doubt,
//! and the switch's copy is judged first, as every copy: another install's newer copy ends
//! the erasure as any other install found signing does, this install's own keeps it as
//! records behind, and a copy that went back raises the alarm. With the mark still held, the
//! erasure ends without erasing: `identity.json` is published again, and the grant reminders
//! it raised for apps still listed are withdrawn; a removed app's stays. An unsigned `409` is
//! no refusal: the request stays in doubt. [`Signer::abort_erasure`] ends it the same way on
//! the user's word, while no request may have landed. The app records it deleted stay
//! deleted until each app writes its own again.
//!
//! Once erased, the records stay (Switch spec 12.7 step 4): the App IDs revoked for good among
//! them, which a later enrollment names again. What only the erased account could settle is
//! dropped: the alerts of revocations not yet sent there and of an owed closing, and an owed
//! backup. Nothing more is signed for the account, and a revocation or a restore is refused.
//! The signer backup on the Homeserver stays, sealed to the identity's own backup key,
//! naming the erased switch. Enrolling again after an erasure starts the account as after a
//! provider loss (Switch wire 7.4.16): [`Signer::declare_provider_loss`], at the same service
//! or another.

use pubky_switch_client::ClientError;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::records::{IDENTITY_PATH, app_record_path};

use pubky_switch_core::records::IdentityDoc;
use pubky_switch_core::sig::SignedDoc;

use super::revocation::UserConfirmed;
use super::{Signer, Verdict, gate};
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::state::{Flow, ShownCopy};

impl Signer {
    /// Erase the identity's account at its switch, once the user has confirmed it (Switch spec
    /// 12.7 step 5): `identity.json` and the app records leave the Homeserver, the user is
    /// asked to revoke the apps' grants, then the switch erases the account.
    ///
    /// For the identity's apps this is a provider loss, and lookups of `identity.json` fail
    /// closed (Switch spec 12.7 step 5): the host shows the user that before asking.
    ///
    /// # Errors
    ///
    /// The signing gate's refusals, as before every signing step: another install signs, an
    /// alarm is held, a hand-over or a take-over is in progress, a flow is in progress, or the
    /// account is erased already ([`Refusal::Erased`]). When the switch refuses it (`409
    /// conflict`), what its copy shows: [`SignerError::NotNamed`] for another install's newer
    /// copy, [`Refusal::RecordsBehind`] for this install's own, the alarm for a copy that went
    /// back, and [`Refusal::ErasureRefused`] with the mark still held. Otherwise the
    /// Homeserver's, the switch's or the store's error, the erasure kept and finished by
    /// [`Signer::resume`].
    pub async fn close_account(&mut self, _confirmed: UserConfirmed) -> Result<()> {
        // An account that answers the notice lets the erasure through (Switch wire 7.3, Table
        // 2), and its `GET /apps` answers the notice too: the erasure starts on the checks
        // before that read, and its first step checks the other copies and the gate
        // ([`Signer::still_erasing`]) before anything is deleted or sent.
        match self.ready().await {
            Err(SignerError::Switch(error)) if answers_the_notice(&error) => {}
            ready => ready?,
        }
        let flow = Flow::Erase {
            unpublished: false,
            reminded: Vec::new(),
            unanswered: false,
            first_404_ms: None,
            shown: None,
        };
        // Unpublished from the first deletion on: an erasure that ends without erasing, after
        // any part of the Homeserver's files went, has `identity.json` published again.
        let mut state = self.state.clone();
        if let Some(newest) = state.newest.as_mut() {
            newest.published = false;
        }
        self.commit(state, Some(flow)).await?;
        self.resume().await
    }

    /// End the erasure in progress without erasing, on the user's word: `identity.json` is
    /// published again, and the grant reminders the erasure raised are withdrawn. The app
    /// records it deleted stay deleted until each app writes its own again.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotErasing`] when no erasure is in progress; [`Refusal::ErasureUnanswered`]
    /// when a request of it went unanswered and may have erased the account, which
    /// [`Signer::resume`] finds out; otherwise as [`Signer::resume`].
    pub async fn abort_erasure(&mut self) -> Result<()> {
        self.refresh().await?;
        let Some(Flow::Erase {
            reminded,
            unanswered,
            ..
        }) = self.flow.clone()
        else {
            return Err(Refusal::NotErasing.into());
        };
        if unanswered {
            return Err(Refusal::ErasureUnanswered.into());
        }
        self.end_erasure(&reminded).await?;
        self.resume().await
    }

    /// The erasure's next step: the Homeserver's files unless `unpublished`, then the
    /// erasure at the switch.
    pub(super) async fn erase(
        &mut self,
        unpublished: bool,
        reminded: Vec<[u8; 16]>,
        unanswered: bool,
    ) -> Result<()> {
        if !unpublished {
            return self.unpublish().await;
        }
        // A request in doubt, then the switch's `404` and every other copy clean: erased
        // already, at once when the pinned key signed it, else once it has held for 24 hours,
        // and no other request goes out without an ownership read (Switch wire 7.4.16).
        match self.still_erasing(unanswered, true).await? {
            Checked::Signing => {}
            Checked::NotHosted => return self.erased().await,
            Checked::ErasedAlready => {
                return self.erased_after_doubt(reminded, self.erasure_wait()).await;
            }
        }
        // Before the request: it may land, however its answer goes.
        if !unanswered {
            let flow = Flow::Erase {
                unpublished,
                reminded: reminded.clone(),
                unanswered: true,
                first_404_ms: None,
                shown: self.erasure_shown(),
            };
            self.commit(self.state.clone(), Some(flow)).await?;
        }
        self.send_erasure(unpublished, reminded, unanswered, true)
            .await
    }

    /// The erasure's request, and what its answer makes of the flow. With `relearn`, a signed
    /// `409` naming another creation time than the request did has it kept as the account's
    /// and the request sent once more, naming it (Switch wire 7.4.16).
    async fn send_erasure(
        &mut self,
        unpublished: bool,
        reminded: Vec<[u8; 16]>,
        unanswered: bool,
        relearn: bool,
    ) -> Result<()> {
        // Through the signing gate, as every signing step: the erasure is the identity's
        // to ask for only while this install signs. It names the account's creation time and
        // the mark it follows, so a delivery since the last check, such as another install's
        // take-over, makes the switch refuse it, and so does a later account of the identity
        // there; a retry names the same (Switch wire 7.4.16).
        let (created, following) = self.erasure_names()?;
        let answer = {
            let key = self.signing_key()?;
            let client = self.signing_client(&key)?;
            drop(key);
            client.erase(created, following).await
        };
        match answer {
            Ok(()) => self.erased().await,
            // After a request that went unanswered, the `404` the pinned key signed for an
            // identity the service doesn't host, bound to this request: the erasure is
            // confirmed at once (Switch wire 7.4.16 "The signer's `404`", spec 12.7 step 5).
            Err(error) if unanswered && error.is_not_hosted() => self.erased().await,
            // An unsigned `404`, which may be an intermediary's, after a request that went
            // unanswered: the service may host no account for the identity, as after a lost
            // `200`, once it has held for 24 hours (Switch wire 7.4.16). The wait is the
            // flow's as it stands after the check, which ends it on a signed answer.
            Err(ClientError::BadServiceSignature { status: 404 }) if unanswered => {
                self.erased_after_doubt(reminded, self.erasure_wait()).await
            }
            // A `404` is never a lost answer: a signed one means the switch hosted no account
            // when it answered, an intermediary's that the request wasn't routed. With no
            // request in doubt before, it erased nothing, and it never sets the doubt itself.
            Err(error @ ClientError::BadServiceSignature { status: 404 }) => {
                let flow = Flow::Erase {
                    unpublished,
                    reminded,
                    unanswered: false,
                    first_404_ms: None,
                    shown: self.erasure_shown(),
                };
                self.commit(self.state.clone(), Some(flow)).await?;
                Err(error.into())
            }
            // No answer, or another answer the pinned key didn't sign, such as a gateway's
            // `502`, `503` or `504`, which can hide a forwarded request: the request may have
            // landed, and the mark stays.
            Err(error @ (ClientError::Transport(_) | ClientError::BadServiceSignature { .. })) => {
                Err(error.into())
            }
            // Every `409` to an erasure names the creation time it was checked against; without
            // one, the erasure stops here, in progress, and the user is told (Switch wire
            // 7.4.16).
            Err(ClientError::Switch {
                code: ErrorCode::Conflict,
                current,
                ..
            }) if checked_against(&current).is_none() => {
                let flow = Flow::Erase {
                    unpublished,
                    reminded,
                    unanswered: false,
                    first_404_ms: None,
                    shown: self.erasure_shown(),
                };
                self.commit(self.state.clone(), Some(flow)).await?;
                Err(ClientError::InvalidResponse(
                    "Switch wire 7.4.16: a 409 to the erasure without the creation time".into(),
                )
                .into())
            }
            // At an account that answers the notice, the `409` carries the copy the account
            // holds, which is judged, then named in the erasure sent again (Switch wire
            // 7.4.16).
            Err(ClientError::Switch {
                code: ErrorCode::Conflict,
                current,
                ..
            }) if relearn && current.get("identity").is_some() => {
                self.erase_naming_the_shown_copy(unpublished, reminded, &current)
                    .await
            }
            // One other than the request named is the account's: it is kept, and the erasure
            // is sent again naming it, whatever time was held, once (Switch wire 7.4.16).
            Err(ClientError::Switch {
                code: ErrorCode::Conflict,
                current,
                ..
            }) if relearn && checked_against(&current) != created => {
                let mut state = self.state.clone();
                if let Some(service) = state.service.as_mut() {
                    service.created = checked_against(&current);
                }
                let flow = Flow::Erase {
                    unpublished,
                    reminded: reminded.clone(),
                    unanswered: false,
                    first_404_ms: None,
                    shown: self.erasure_shown(),
                };
                self.commit(state, Some(flow)).await?;
                Box::pin(self.send_erasure(unpublished, reminded, false, false)).await
            }
            // Signed with the service key, so the request didn't land: another
            // `identity.json`, or a move in progress. The switch's copy is judged first, as
            // every copy (Switch spec 4.3): another install's newer copy ends the erasure
            // without erasing, this install's own newer one keeps it as records behind, and a
            // copy that went back raises the alarm. A switch still holding the mark refused for
            // another reason: the erasure ends, and the user may ask again.
            Err(ClientError::Switch {
                code: ErrorCode::Conflict,
                ..
            }) => {
                let flow = Flow::Erase {
                    unpublished,
                    reminded: reminded.clone(),
                    unanswered: false,
                    first_404_ms: None,
                    shown: self.erasure_shown(),
                };
                self.commit(self.state.clone(), Some(flow)).await?;
                self.switch_at_mark().await?;
                self.end_erasure(&reminded).await?;
                Err(Refusal::ErasureRefused.into())
            }
            // An answer the pinned key signed that does not confirm an erasure: the
            // erasure didn't land, and the next request is a first one again.
            Err(error @ (ClientError::Switch { .. } | ClientError::InvalidResponse(_))) => {
                let flow = Flow::Erase {
                    unpublished,
                    reminded,
                    unanswered: false,
                    first_404_ms: None,
                    shown: self.erasure_shown(),
                };
                self.commit(self.state.clone(), Some(flow)).await?;
                Err(error.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// What the erasure's body names (Switch wire 7.4.16 Request), in one place: `created`,
    /// the account's creation time its enrollment answer gave, or a `409` since, `None` where
    /// this install holds none, after a restore or a hand-over; and `identity_hash`, the
    /// document hash of the `identity.json` this install knows the account to hold: the copy
    /// a `409` at an account that answers the notice showed, once one did
    /// ([`Signer::erase_naming_the_shown_copy`]); else the mark's, once it names this
    /// account's service, that is, once this install delivered a version here; `None` before,
    /// as at a staged account it delivered nothing to, which holds none.
    fn erasure_names(&self) -> Result<(Option<u64>, Option<[u8; 32]>)> {
        let Some(service) = self.state.service.as_ref() else {
            return Ok((None, None));
        };
        if let Some(shown) = self.erasure_shown() {
            return Ok((service.created, shown.hash));
        }
        let following = self
            .state
            .newest_doc()?
            .filter(|mark| mark.inbox().service_key == service.service_key)
            .map(|mark| mark.hash());
        Ok((service.created, following))
    }

    /// The copy a `409` at an account that answers the notice showed, as the erasure in
    /// progress keeps it.
    fn erasure_shown(&self) -> Option<ShownCopy> {
        match &self.flow {
            Some(Flow::Erase { shown, .. }) => *shown,
            _ => None,
        }
    }

    /// A signed `409` to the erasure at an account that answers the notice, which carries
    /// `current.identity`, the copy the account holds, and `current.created`, the creation
    /// time it checked against (Switch wire 7.4.16). The copy is judged as every copy (Switch
    /// spec 4.3) before the erasure is sent again naming both, once:
    ///
    /// - this install's mark, or none or a copy older than the newest version delivered
    ///   there, which is the state the account lost: it is named, and the rule against going
    ///   back doesn't stop the erasure;
    /// - a newer copy is taken as every newer copy is: another install's ends the erasure
    ///   without erasing, this install's own keeps it as records behind;
    /// - another body at the mark's version raises the alarm, and the erasure waits;
    /// - a copy that doesn't verify stops the erasure there, in progress, and tells the user.
    async fn erase_naming_the_shown_copy(
        &mut self,
        unpublished: bool,
        reminded: Vec<[u8; 16]>,
        current: &serde_json::Value,
    ) -> Result<()> {
        let kept = |shown: Option<ShownCopy>| Flow::Erase {
            unpublished,
            reminded: reminded.clone(),
            unanswered: false,
            first_404_ms: None,
            shown,
        };
        let held = current.get("identity").unwrap_or(&serde_json::Value::Null);
        let copy = if held.is_null() {
            None
        } else {
            let verified = serde_json::from_value::<SignedDoc>(held.clone())
                .ok()
                .and_then(|signed| IdentityDoc::verify(&signed, &self.state.identity).ok());
            let Some(copy) = verified else {
                self.commit(self.state.clone(), Some(kept(self.erasure_shown())))
                    .await?;
                return Err(ClientError::InvalidResponse(
                    "Switch wire 7.4.16: a 409 to the erasure with a copy that doesn't verify"
                        .into(),
                )
                .into());
            };
            Some(copy)
        };
        match self.judge_copy(copy.as_ref()) {
            Ok(Verdict::AtMark) | Err(Alert::Rollback { .. }) => {}
            Ok(Verdict::Newer) if copy.is_none() => {}
            Ok(Verdict::Newer) => {
                self.commit(self.state.clone(), Some(kept(self.erasure_shown())))
                    .await?;
                let signed = copy.as_ref().map(|copy| copy.signed().clone());
                self.confirm_copy(signed.as_ref()).await?;
                self.end_erasure(&reminded).await?;
                return Err(Refusal::ErasureRefused.into());
            }
            Err(alert) => {
                self.commit(self.state.clone(), Some(kept(self.erasure_shown())))
                    .await?;
                return self.alarm(alert).await;
            }
        }
        let mut state = self.state.clone();
        if let Some(service) = state.service.as_mut() {
            service.created = checked_against(current);
        }
        let shown = ShownCopy {
            hash: copy.as_ref().map(IdentityDoc::hash),
        };
        self.commit(state, Some(kept(Some(shown)))).await?;
        Box::pin(self.send_erasure(unpublished, reminded, false, false)).await
    }

    /// Before each step of an erasure that deletes or asks to erase, a fresh check that this
    /// install still signs, as before a delivery (Switch spec 4.3, Switch wire 3.13). In `full`,
    /// every copy ([`Signer::check_copies`]): it is named, the switch's copy is its mark, the
    /// signer backup names no other install that took over, and the Homeserver holds nothing
    /// newer. Otherwise the switch's copy, where a take-over shows first, since an install that
    /// takes over delivers there before it writes its backup or publishes (wire 3.13), and the
    /// Homeserver's `identity.json`, a defence against a switch read that lags or lies. A check
    /// that can't read a copy fails, and nothing is deleted or sent: the flow stays, and
    /// [`Signer::resume`] tries again. A passing check then meets the signing gate
    /// ([`gate::refusal`]), as at every signing step: while an alarm is held, nothing is
    /// deleted or sent either.
    ///
    /// Another install found signing ends the erasure without erasing, in the commit that
    /// records it ([`Signer::end_erasure_in`]), and nothing is published by this install, which
    /// no longer signs. An alarm keeps the erasure in progress, nothing deleted or sent: it
    /// goes on once the user has cleared it, or is aborted while no request is in doubt.
    /// Records behind keep it too, nothing deleted, sent or published, but the switch's copy is
    /// still read: another install's version there ends the erasure, and after a request in
    /// doubt the switch's `404` shows it erased. A user who wants the account back restores
    /// on a new install, which takes over; this install then finds it and ends its erasure.
    ///
    /// With a request in doubt, `unanswered`, the `404` the pinned key signed for an identity
    /// the service doesn't host, to the switch's read, is the erasure landed (Switch wire
    /// 7.4.16 "The signer's `404`"): once the signer backup and the Homeserver show no other
    /// install, the caller takes it as erased at once ([`Checked::NotHosted`]). An unsigned
    /// `404` may be the service's after the erasure, or an intermediary's: on the same check
    /// of the other copies the account looks erased already, on the unauthenticated evidence
    /// wire 7.4.16 accepts for a retry's `404`, and no other request goes out: the caller
    /// takes it as erased once the `404` has held for 24 hours
    /// ([`Signer::erased_after_doubt`]). Any other answer the pinned key signs, here or at any
    /// other read, ends that wait ([`Signer::read_apps`]), and an install that delivered
    /// behind a proxy answering `404` is never erased.
    async fn still_erasing(&mut self, unanswered: bool, full: bool) -> Result<Checked> {
        // Records behind block every step that deletes or sends, not the read-only check of
        // the switch's copy, nor a conclusion drawn from it: another install's version there
        // ends the erasure, and the switch's `404` after a request in doubt shows it done.
        // Only that refusal of `check_named` is passed for the read; every other stops here.
        let behind = matches!(
            self.check_named(),
            Err(SignerError::Refused(Refusal::RecordsBehind { .. }))
        );
        let checked = if behind {
            self.switch_at_mark().await.map(drop)
        } else if full {
            self.check_copies().await.map(drop)
        } else {
            self.switch_and_homeserver().await
        };
        let checked = match checked {
            Err(SignerError::Switch(error)) if unanswered && error.is_not_hosted() => self
                .copies_but_the_switch()
                .await
                .map(|()| Checked::NotHosted),
            Err(SignerError::Switch(ClientError::BadServiceSignature { status: 404 }))
                if unanswered =>
            {
                self.copies_but_the_switch()
                    .await
                    .map(|()| Checked::ErasedAlready)
            }
            // An account that answers the notice holds its copy back from `GET /apps` and
            // shows it in a `409` to the erasure instead (Switch wire 7.4.16): the other
            // copies are judged, and the step goes on.
            Err(SignerError::Switch(error)) if answers_the_notice(&error) => {
                self.copies_at_a_notice().await.map(|()| Checked::Signing)
            }
            checked => checked.map(|()| Checked::Signing),
        };
        // An alarm or records behind keep the erasure in the commit that records them
        // (`Signer::erasure_kept`); another install found signing ends it in its own.
        let checked = checked?;
        // The gate holds back a deletion or a request, not the conclusion that the account is
        // erased already: wire 7.4.16 takes the switch's `404` after a request in doubt as
        // done whatever alarm is held, and `erased` keeps the alarm's alerts. Records still
        // behind after the read, as when the switch holds this install's own newer version or
        // the mark, are among the gate's refusals: no step.
        if checked == Checked::Signing
            && let Some(refused) = gate::refusal(&self.state)
        {
            return Err(refused);
        }
        Ok(checked)
    }

    /// The switch's copy and the Homeserver's `identity.json`, as before each later deletion.
    async fn switch_and_homeserver(&mut self) -> Result<()> {
        self.check_named()?;
        self.switch_at_mark().await?;
        if let Some(newest) = self.state.newest_doc()? {
            self.judge_homeserver(&newest).await?;
        }
        Ok(())
    }

    /// The copies but the switch's, where the account answers the notice, before an erasure
    /// step: this install is named, its records aren't behind, and neither the signer backup
    /// nor the Homeserver's `identity.json` shows another install or a newer version (Switch
    /// spec 4.3, wire 3.13).
    async fn copies_at_a_notice(&mut self) -> Result<()> {
        self.check_named()?;
        self.check_backup_copy().await?;
        if let Some(newest) = self.state.newest_doc()? {
            self.judge_homeserver(&newest).await?;
        }
        Ok(())
    }

    /// The copies but the switch's, after a request in doubt and a `404` from the switch: the signer backup and the Homeserver's `identity.json`, judged for another
    /// install signing, which stops it. This install's own newer version there, records behind,
    /// doesn't: the account is gone at the switch whatever this install's records say (Switch
    /// wire 7.4.16).
    async fn copies_but_the_switch(&mut self) -> Result<()> {
        let own_newer = |checked: Result<()>| match checked {
            Err(SignerError::Refused(Refusal::RecordsBehind { .. })) => Ok(()),
            checked => checked,
        };
        own_newer(self.check_named())?;
        own_newer(self.check_backup_copy().await)?;
        if let Some(newest) = self.state.newest_doc()? {
            own_newer(self.judge_homeserver(&newest).await.map(drop))?;
        }
        Ok(())
    }

    /// When the erasure's wait for an unsigned `404` to hold started, as the flow holds it
    /// now: an answer the pinned key signed since ends it ([`Signer::read_apps`]).
    fn erasure_wait(&self) -> Option<u64> {
        match &self.flow {
            Some(Flow::Erase { first_404_ms, .. }) => *first_404_ms,
            _ => None,
        }
    }

    /// A `404` the pinned key didn't sign after a request in doubt, at a run of the erasure:
    /// how a landed erasure may look, taken as one only once every check has met it for 24
    /// hours, as an app takes an erasure it can't check (Switch wire 7.4.16, spec 12.7 step 5). `first_404_ms` is when a check
    /// first met it, kept durably in the flow.
    ///
    /// The time is the device clock's, the only one there is: the `404` carries no time
    /// anyone can authenticate. The wait ends at the first run 24 hours after the first `404`,
    /// so it takes two runs a day apart. A device clock set back below the first `404` starts
    /// the wait again from then; one set forward shortens it, and a jump of a day ends it at
    /// the next run, the user's own doing.
    async fn erased_after_doubt(
        &mut self,
        reminded: Vec<[u8; 16]>,
        first_404_ms: Option<u64>,
    ) -> Result<()> {
        let now = self.env.clock.now_ms();
        let since_ms = first_404_ms.filter(|at| *at <= now).unwrap_or(now);
        if now.saturating_sub(since_ms) >= ERASURE_CONFIRMATION_MS {
            return self.erased().await;
        }
        if first_404_ms != Some(since_ms) {
            let flow = Flow::Erase {
                unpublished: true,
                reminded,
                unanswered: true,
                first_404_ms: Some(since_ms),
                shown: self.erasure_shown(),
            };
            self.commit(self.state.clone(), Some(flow)).await?;
        }
        Err(Refusal::ErasureUnconfirmed { since_ms }.into())
    }

    /// The account is erased: what only it could settle goes, and the records stay.
    async fn erased(&mut self) -> Result<()> {
        let mut state = self.state.clone();
        state.erased = true;
        state.backup_owed = false;
        state.alerts.retain(|alert| {
            !matches!(
                alert,
                Alert::ReductionNotClosed { .. }
                    | Alert::RevocationPending { .. }
                    | Alert::RevocationUnconfirmed { .. }
                    | Alert::BackupNotWritten
            )
        });
        self.commit(state, None).await
    }

    /// End the erasure without erasing: withdraw the grant reminders it raised for apps the
    /// newest version still lists, and leave `identity.json` unpublished, which the next run
    /// publishes again. A removed app's reminder stays: its grant's revocation is owed whether
    /// or not the account is erased (Switch spec 12.2 step 1).
    async fn end_erasure(&mut self, reminded: &[[u8; 16]]) -> Result<()> {
        let mut state = self.state.clone();
        withdraw_reminders(&mut state, reminded)?;
        self.commit(state, None).await
    }

    /// End the erasure in progress, if any, without erasing, in `state`, which the caller
    /// commits with no flow: as [`Signer::end_erasure`], when another install is found signing.
    /// Its newest version may be that install's now.
    pub(super) fn end_erasure_in(&self, state: &mut crate::state::SignerState) -> Result<()> {
        if let Some(Flow::Erase { reminded, .. }) = &self.flow {
            withdraw_reminders(state, reminded)?;
        }
        Ok(())
    }

    /// Delete `identity.json` and every app record the signer knows of from the Homeserver,
    /// and ask the user to revoke the grant of each app, listed or removed, not reminded yet
    /// (Switch spec 12.2 step 1, 12.7 step 5).
    async fn unpublish(&mut self) -> Result<()> {
        let newest = self.state.newest_doc()?;
        let apps: Vec<[u8; 16]> = newest
            .iter()
            .flat_map(|doc| doc.body().apps.iter().map(|a| a.app_id))
            .chain(self.state.cleanup.iter().copied())
            .chain(self.state.deletion_checks.iter().copied())
            .collect();
        // Each deletion only after a fresh check: another install may take over between two
        // of them, and its files are never this install's to delete. The first after the
        // full check, each later one after the switch's copy, where a take-over shows first.
        for (index, path) in std::iter::once(IDENTITY_PATH.to_owned())
            .chain(apps.iter().map(app_record_path))
            .enumerate()
        {
            // With no request in doubt, the check never takes the account as erased.
            self.still_erasing(false, index == 0).await?;
            self.env
                .homeserver
                .delete(&path)
                .await
                .map_err(SignerError::Homeserver)?;
        }
        let mut state = self.state.clone();
        let mut reminded = Vec::new();
        for app_id in apps {
            if !state.grant_reminded.contains(&app_id) {
                state.alert(Alert::GrantRevocationOwed { app_id });
                state.grant_reminded.push(app_id);
                reminded.push(app_id);
            }
        }
        state.cleanup.clear();
        state.deletion_checks.clear();
        if let Some(newest) = state.newest.as_mut() {
            newest.published = false;
        }
        let flow = Flow::Erase {
            unpublished: true,
            reminded,
            unanswered: false,
            first_404_ms: None,
            shown: None,
        };
        self.commit(state, Some(flow)).await
    }
}

/// Withdraw from `state` the grant reminders an erasure raised, `reminded`, for apps its newest
/// version still lists. A removed app's reminder stays: its grant's revocation is owed whether
/// or not the account is erased (Switch spec 12.2 step 1).
pub(super) fn withdraw_reminders(
    state: &mut crate::state::SignerState,
    reminded: &[[u8; 16]],
) -> Result<()> {
    let newest = state.newest_doc()?;
    let listed: Vec<[u8; 16]> = reminded
        .iter()
        .copied()
        .filter(|app| {
            newest
                .as_ref()
                .is_some_and(|doc| doc.listed_cert(app).is_some())
        })
        .collect();
    state.alerts.retain(
        |alert| !matches!(alert, Alert::GrantRevocationOwed { app_id } if listed.contains(app_id)),
    );
    state
        .grant_reminded
        .retain(|app_id| !listed.contains(app_id));
    Ok(())
}

/// How long every check must meet a `404` the pinned key didn't sign after a request in
/// doubt before the erasure is taken as done: 24 hours, as for an app (Switch spec 12.7 step
/// 5).
const ERASURE_CONFIRMATION_MS: u64 = 24 * 60 * 60 * 1000;

/// What a passing check before an erasure step found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Checked {
    /// This install still signs: the step goes on.
    Signing,
    /// The account is erased: a request in doubt, then the `404` the pinned key signed for
    /// an identity the service doesn't host, with no other install anywhere (Switch wire
    /// 7.4.16 "The signer's `404`").
    NotHosted,
    /// The account looks erased already: a request in doubt, then a `404` the pinned key
    /// didn't sign, with no other install anywhere; taken as erased once it has held for 24
    /// hours.
    ErasedAlready,
}

/// The creation time a `409` to an erasure was checked against, its `current.created`
/// (Switch wire 7.4.16); `None` where it is missing or isn't a time.
fn checked_against(current: &serde_json::Value) -> Option<u64> {
    current
        .get("created")
        .and_then(serde_json::Value::as_str)
        .and_then(|text| pubky_switch_core::time::parse_rfc3339(text).ok())
}

/// Whether `error` is the switch's signed notice that the account awaits a recovery, `503
/// recovery_required` (Switch wire 7.3, Table 2; 7.6).
fn answers_the_notice(error: &ClientError) -> bool {
    error.code() == Some(ErrorCode::RecoveryRequired)
}
