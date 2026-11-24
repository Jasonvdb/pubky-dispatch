# Pubky Switch known issues

Pubky Switch is in development and is not yet safe for real keys or funds. This page describes what protocol authors and host apps can rely on today, where an apparently successful call can give the wrong impression, and which interfaces and stored formats will change. It describes the `main` branch: a change that fixes an item removes it from this page in the same pull request, and a newly found issue is added the same way.

## What will still change

Record policies can name `create_scope` and `delete_scope` (Switch wire 6.2). Code using a `Policy` literal supplies both fields as `Option<Box<str>>`, for example `create_scope: Some("tasks".into())`. `Policy::new` leaves both absent. Use `with_create_scope` or `with_delete_scope` to require an operation-specific grant. Code matching `ops::Need::AnyScope` uses `Need::Record(put)` and `put.allows_writer(cert)`. Use `labels::derive::POLICY` for every policy. The permanent policy hash uses the common policy label and a tagged generation (Switch wire 1.5). This changes permanent record keys. Operators start with the initial schema containing the nullable role columns. Recovery callers pass renewal and removal cutoffs in `UploadContext` and to `CheckedUpload::review_records`. Load stored dates for its incoming `record_candidates()` and held writes. Persist every entry in `ReviewedRecords::record_dates` and apply its discarded hashes and eligible records in one transaction. When `RecordComparison::reinstate` selects a parent, keep its signed operation and certificate alongside the undated child. The child's signed base supplies the parent's exact version. Restore the parent if the child is withdrawn. Release its bytes when the child qualifies at a proved time or another proved or local write replaces it. Import callers use the installed records directly.

Signer hosts that save a user's approval across restart keep `AppReview::consent()` with the original requests. If the signer has already issued the claim, deliver it with its original capabilities. Otherwise apply the saved choice to a fresh review with `ApprovalConsent::apply_to`. A changed review needs fresh user confirmation: `Signer::approve` and `ApprovalConsent::apply_to` return `Refusal::ApprovalChanged` when any term the review showed differs from what the signer would sign. `Signer::approve` now returns it in two cases that had other outcomes: a decline the protocols now refuse, which returned `Refusal::ProtocolRule`, and a kept review approved again after its claim was delivered, which renewed the certificate without asking. Show a fresh review in both; the protocol's rule then comes from `AppReview::decline`. `approve` on a request whose claim is issued and not yet reported delivered returns that claim.

Signer hosts that implement `SecretVault` change `delete(&self)` to `delete(&self, expected: &IdentitySecret)`. Compare the stored bytes with `expected` and erase them in one atomic step for all callers sharing the vault. An empty slot or a different secret is a successful no-op. Return a `VaultError` only when the vault cannot check or delete the secret.

`identity.json` names the admission policy `peer_list` (`policy.admission`, core `Admission::PeerList`) in place of `contacts_and_conversations`: signers write the new value and readers refuse the old one. Certificates name the permission that grants reply access `reply.add`, and the service transition an invitation writes is `reply.add` (`ServiceTransition::ReplyAdd`). `allow.put` and `allow.delete` name the admission reason in `reason`, `kept` or `reply`. The core's `PeerReason` replaces `AllowKind`, in operations and in `ProofState::Allow { reason }`, and `ops::List` names `KeptPeers` and `ReplyPeers`. An export carries one `admission` part per peer, with both reasons (`Part::Admission`), in place of separate contact and conversation parts; `export::ConversationPart` and `export::Writer` are removed, and `Import::admissions` replaces both lists.

Hosts keep a peer with `App::keep_peer` and remove that reason with `App::remove_kept_peer`. Use `App::invite` to grant reply access and `App::remove_reply` to remove it. Protocols name the outgoing kinds and messages that grant replies with `adds_reply` and `message_adds_reply`. After provider loss, return the peers to invite in `LossActions::reply_peers` and check `RecoveryInfo::reply_peers_left_out` for omissions. Further renames: `RecoveryStep::Conversations` is `RecoveryStep::ReplyPeers`, `AppEvent::ListsDiffer`'s `unverified_contacts` is `unverified_kept_peers`, `MAX_LOSS_CONVERSATIONS` is `MAX_LOSS_REPLY_PEERS`, and `client::answers::UploadLists::contacts` is `kept`.

Operators who set the admission limits must rename `max_contacts` to `max_kept_peers` and `max_conversations` to `max_reply_peers`. A peer with both reasons uses one slot in each quota. On a refused addition, `current.limit` names the full quota as `kept_peers` or `reply_peers`.

The client store and app backups spell kept peers `kept`. Kept peer rows move from `lc/contact/<pubky>` to `lc/kept/<pubky>`, and their loss removals from `loss/list-removed/lc/contact/` to `loss/list-removed/lc/kept/`. List positions move from `chain/list-effect/contact/` to `chain/list-effect/kept/`, and a backup's `ahead` entries from `contact/<id>` to `kept/<id>`. A backup's provider-loss list inputs (`input`, `remaining` and `observed` in `loss_lists`) name their member `kept` in place of `contacts`, and so do the list cursor (`loss/lists-pending`, and `loss_lists.waiting.cursor` in a backup) and the list staging (`loss/list-staging`). There is no migration: rows under the old keys are not read, and a stored value or backup in the old shape is refused. Hosts discard a store or backup a development build wrote with the old spellings.

A recovery upload whose deny entries don't fit the new service's deny list is refused whole with `429 quota_exceeded`, `current` `{ "limit": "deny", "over" }`. An upload carrying more distinct deny entries than the limit is `400`. Apps get `Refusal::DenyListFull { over }` and `AppEvent::RecoveryDenyListFull`, also from the client's own check before it sends, and the recovery stays at its list step until the user unblocks peers to make room: `App::undeny` during that step also leaves the peer out of the upload, and an app with only `lists.read` may call it for that. `App::recovery_deny_entries` lists the denials the upload carries, each a `RecoveryDenyEntry` saying whether the upload also keeps the peer. A removal made while the upload is owed, `undeny` or `remove_kept_peer`, is left out of every page not yet accepted, and the backup carries those removals. The deny list holds at most 10,000 entries at every service (`pubky_switch_core::ops::MAX_DENY`): operators remove `max_deny` from their configuration, which no longer accepts it, and `ops::Limits` has no `max_deny` member. The largest peer list answer is 33 MiB, and `HttpConfig::max_response_bytes` defaults to that.

`App::read_record_application` returns a `RecordApplication`. Callers read its named `record`, `installed_version`, `application` and `evidence` fields.

Recovery stores call `merge_checked_record` with the current record, its known predecessor, and the retained signed operations. Apply the returned `RecordComparison` in one transaction. Keep the writer certificate and any proved version with each divergent operation so a later proof can promote it to current. `AccountTxn::put_divergent_upload` takes the retained position and those fields.

A restore, onto a fresh store or in place, tells again every duty event the protocols hadn't acknowledged when the backup was taken, other than a recovery notice, its clearing, an erased account and a deny list gap's refused writes. Expect `EffectRefused`, `EffectUncertain`, `Parked`, `MessageUndelivered`, `RecordJobStopped`, `KeptBatchDropped`, `AttemptDropped`, `CertificateRefused`, `MemberChanged` and the other duty events after a restore onto a new device. An event whose stored entry the backup didn't carry still comes: `App::parked_entry` then answers `None`, which means the entry's content is gone, not that the event is resolved. A backup whose unacknowledged duties do not fit one restore commit on a new device is refused with `Refusal::DutiesTooLarge`: acknowledge the duties acted on and take it again.

`AppEvent::PutBackRefused` has a fourth reason, `generation_changed`: the app followed a move or a key change in place past the deletion's generation. A provider loss now also ends a wait that had no replacement signed yet, with `provider_loss`. Treat either as the end of the wait: read the record and write it again under the new generation if it is still needed. The event's new `batch_id` names a replacement already sent; `App::kept_batch` tells whether it is still kept, applied, refused, or dropped with its outcome unknown.

Embedded services must remove `Service::with_lock_freshness` (now available only in tests or with `test-util`), the call to `Store::hold_instance_lock` and its keeper. Use `Service::start` and handle its lock error, or call `Store::lock_for_service` and pass the returned store to `Service::new`. Keeping your old lock makes either path wait 25 seconds and return `StoreError::InUse` for your own session. Run migrations after taking the lock and before serving, as the executable does. While serving, never write through your own `Store` on that database. Direct transactions, migrations and account creation bypass the guard. If the keeper cannot confirm the lock while serving, another process may hold it. The keeper immediately exits the whole host process with status 1 without running destructors so no request or background task can commit further writes. Run the service in a process you can restart.

Before closing the database, await `Service::shutdown` or, if the service has yet to be constructed, `ServiceStore::shutdown`. A service dropped without it keeps the lock until the work it accepted has ended. The lock stops a second process from starting to commit; a commit already sent when a process stops may still land after another takes the lock (`docs/configuration.md`, "Embedding the service").

### Caller changes already on main

#### App and transport integration

- `MessageFields::to_json_with_body` is no longer public. Pass the body as a JSON object to `Message::new`, then call `Message::to_json` to encode the message. To sign exact bytes, pass the complete encoded message to `MessagePlaintext::sign_json`.

- Read `AllowList::peers` for the result of `App::allow_list` or `SwitchClient::allow`. Each peer has a `kept` flag and an optional `reply` grant. The grant records the original app or invitation hash, its creation time and its last use when known.

- Register invitations with a code hash, expiry and use count. Keep invitation notes in the host. On receipt, use the nullable `invite_code_hash` to identify the code redeemed for that message. An ordinary follow-up carries `null`.

- Keep an app display name in the host's local settings. Callers that set `AppConfig::label` or construct `AppRecordBody` with a `label` field must remove that assignment.

- Register the protocol that owns an outgoing kind if its messages should grant the recipient replies. A kind without a registered owner adds no reply grant.

- Pass an explicit `TimeoutClass` as the final argument to `SwitchClient::sign_request`. Replace `TimeoutClass::default()` with the class appropriate for the call when constructing a transport `Request`. Use `Bulk` for claim, app-record, receive-key or shared-record writes and for batches with `record_current` or `claim_step` conditions. A small batch can return a claim view for each successful claim or a held record or claim view in a conflict.

- Custom transports used with `OpBatch::first_send_before` must implement `Transport::send_before`. Forward the supplied `FirstSend` through queues and wrappers. Check it with `FirstSend::check` after waiting for readiness, immediately before releasing the first request bytes. If bytes may already have been sent, report an uncertain transport failure. The default implementation returns `FirstSendUnavailable` without sending. The native HTTPS transport implements the check.

- `PeerIdentity::read_at_ms` changed from `u64` to `Option<u64>`. `Some(at)` is the time a Homeserver or Switch read supplied the selected identity version. `None` means that version has no qualifying read time, as can happen when it came only from the directory. Before acting on the peer's public records, call `PeerIdentity::may_act` and follow its wait or refresh result. Substituting the current time would make a directory-only version appear fresh.
- `PublicIdentity` now carries the verified service time. Callers that constructed this response with a struct literal must obtain it from `SwitchClient::public_identity`. Callers that destructure it can use `PublicIdentity { identity, freeze, .. }`. The signed time is available through `server_time_ms()`.

- Callers requiring the terminal service to confirm the selected identity document
  should await the `SwitchLookup` from `App::begin_identity_lookup` and check
  `answer.confirms(&already_authorized.doc)` before passing that same answer to
  `App::finish_identity_lookup`. Require the returned `PeerIdentity` to still match
  that document and pass `peer.may_act(...)` and the current-app checks before acting.
  `answer.read()` can succeed after a staged successor while retaining the predecessor's
  document. That does not confirm any document at the terminal service.

- Protocols waiting for required data return `Outcome::Defer` with a content-free reason and the custody their receive rule requires. Hosts see `AppEvent::ProtocolDeferred` on the read. Keep `Outcome::Retry` for failures of the store or host.

- `Protocol::missed` receives `MissedEntries::read_at_ms`, the authenticated time of the feed page that first reported the missing entries. Retries keep that original time. Callers constructing a `MissedEntries` must supply the observed page time.

- When an upgrade drops a registered protocol, call `App::retire_protocol` with that protocol still registered. Load the same App ID with the reduced set after it succeeds. A backup made before retirement can still require the former registration. The [app host guide](app-host-guide.md#running-several-protocols) describes how to finish outstanding work and take a backup for the new set.

- An attempted message still unaccepted 30 days less the 5-minute clock tolerance after its first possible send is given up and reported as `AppEvent::DeliveryUnknown` (and in `OutboxReport::unknown`). A message accepted only on a later try is re-sent only until that deadline. Reconcile through the counterparty or shared state; do not send a replacement the recipient could act on twice.

An app can receive a stopped read with a durable recovery notice. Hosts can show
`App::recovery_required` and `App::provider_health`, and keep an attempt held
on `Refusal::RecoveryRequired` until the app verifies service again or follows
a later generation. A host displaying recovery progress can use `RecoveryInfo::step`.
A signed `not_hosted` reply prompts the app to recheck its signed provider document.
If the document still names this service, repeated unavailable reads count toward
the outage reported by `provider_health`.

A separate display process that can exit during a peek needs a durable original
transport reply. Reserve the signed page with `App::begin_display_read`, render
with `App::display_preview` and pass the retained receipt to the state owner on
reopen using `App::finish_display_read`.

#### Records and publications

The client provides record answers that tell an older write from an overtaken one and carry the signed service head, pending duty events with their owners, the delivery outcome `DeliveryUnknown`, permanent record policies, and the certificate-renewal hook `Protocol::member_for`. After recovery, record reads and collection pages used to discover uploaded records must cover the relevant upload. An earlier or unordered answer keeps the read or page outstanding across restart. A direct fresh lookup reports an inconclusive result when its answer predates an outstanding upload. A replay can learn the signed write from that earlier view and keep the divergence flag until a covering observation settles it.

- Handle `Publication::AwaitingRecord` as an unfinished publication, not a failed read.
  A newer retained signed record or unsigned owner edit defers repair of the older
  accepted record, including after restore. Finish the owner's choice and delivery or
  read its verified acceptance or supersession. An accepted-only restore still repairs
  a missing public copy. No record is published before its acceptance is established.

- App-record writers can use `App::set_protocol_member_with_expiry` with `RecordExpiry`
  and read their registered owner's desired state with `App::protocol_record`. Existing
  member setters now retain a blocked member change together with its expiry. A refusal
  still means the change has not been signed or published; `ProtocolRecord::pending`
  reports that local intent. Use `App::record` and the publication result separately.
  Explicit policy-only renewals retain their existing meaning. Backups include
  `record_members`, even when empty. An in-place
  restore refuses to replace a different pending member choice or import an unsigned
  edit whose signed basis predates a newer local record. Finish the current choice and
  take a backup carrying it before restoring. A newer local signature protects the
  intent even while its delivery is pending; it is not proof of publication.

Hosts that exhaustively match `PolicyFamily` must add a `PermanentGenerations` arm. The family reads permanent records across named generations. Use a fixed target with the generation of the record to read or write an individual record.

A protocol can use `Protocol::qualify_record_mark` to bind a readable value and its mark to the actual record key. A local write that fails this check is refused before signing. After another installation has written the record, the client retains its service revision and the last qualified mark across restart. Hosts must check the shared record's `flagged` and `not_taken` fields before using its contents. A later qualifying write can make the record usable again. A message handler sees the record, mark and application established by earlier entries in the same receive call.

A protocol that needs evidence from successive verified record writes can implement `Protocol::observe_record`. Its local writes commit with the record and can be included in its selected backup layer. The observation carries the signed operation, the accepted and previously held records, and whether the source covers pending uploads. The host receives an error if the protocol cannot store its observation. The read or outstanding batch can then be retried.

A collection page can end at an inbox entry after the last chain operation. An explicit `App::read_record_fresh` can then return `RecordRead::Fresh` for the same signed write, application and divergence at the same signed chain tip, including after the app reloads.

A refused first shared-record read can retain its verified signature and checked version
without accepting its value. `App::read_record_fresh` keeps reporting `Kept/Refused` on
reread and after reload. An authorized `put_record` can replace that write using the
retained base. Hosts must keep unreadable and flagged content out of use. A response
without verifiable signature, key binding or plausible placement establishes no base.

If your protocol holds the cursor while it waits for another app to replace a deleted record, installations using the same App ID share that cursor. Use one authoritative durable store, or stop the old installation and transfer its cursor, deletion evidence, pending duties and submissions before the new installation advances the cursor.

A collection can return `PutBack::Write` for a verified deletion or `PutBackSuccessor::Merge` for a verified live successor. The client journals the exact conditional write before submission. The service cursor can pass the deletion with its atomic replacement, after a covering read the owner accepts, or when the duty is released. A move or key change in place past the deletion's generation ends the duty with `PutBackRefused` (`generation_changed`).

Collection listings show live records. A protected deletion can therefore be absent from a completed page while a read by key still returns its signed delete.

#### Signer integration

The signer can recover with the identity key alone, at the account's service or, when that service is gone, refusing or behind, at a service the user picks.

- Surface `Alert::ReductionNotClosed` while a reduction still owes its closing delivery. Call `Signer::resume` or `Signer::run_due` when the account is reachable and any signing alarm is cleared. After one exact retry for the original proof, the signer can use the service time of a verified read of the same document. The signer retains which version the proof retry covered.

- First setup can wait with `SignerStatus::FirstEnrollmentHeld`. Show the reason in `Alert::FirstEnrollmentHeld` after reopening. Keep the original request and let the user choose the applicable recovery or clear the alert to retry that step. Both `resume` and `run_due` return `Refusal::FirstEnrollmentHeld` while the alert is held.

- When first discovery returns an account or its mark before creation is signed, `SignerStatus::FirstAccountPresent` and `Refusal::FirstAccountPresent` direct hosts to confirmed signer restore. Display the original service from `Signer::first_enrollment_origin`. The signer retains this result across reopen.

- To restore an existing account from a signed first setup, offer `Signer::survey_first_enrollment_restore` at the original service. Show the account, the survey's signed `identity_doc` and the recoverable history, explain that the earlier send may have committed, and call `Signer::restore_first_enrollment` only after confirmation. A fresh setup with no signed creation uses the ordinary restore described above.

- A signer host offering a same-service restart after first enrollment expires can read the original origin from `Signer::first_enrollment_origin` after reopening. Show it, explain that creation may have committed and pass the confirmed origin to `Signer::restart_first_enrollment`. Keep `Signer::resume` for an unattended retry of the current action.

- The signer host can offer `Signer::cancel_key_recovery` when `pending_key_recovery` identifies the original service. Show the holder that a stop may retry that exact enrollment before it can finish. Existing calls to `resume` continue recovery. After reopening, the signer distinguishes an unsent enrollment, one it may have sent, and one with a verified result.

- `Signer::restore_over_unusable` can recover an outstanding document delivery when its locally retained sealed backup also survives at the Homeserver. Show the usual record-loss confirmation. On `Refusal::FlowInProgress` keep the pending operation. After an interrupted replacement, reopen the same store and call `resume`.

Hosts handling signer storage errors can offer the existing confirmed restore for `RecordsFault::Damaged`. It reports an invalid binding in the stored signer state. A failed store read or write retains its own error.

### Stores and backups

- **Client.** A pending collection listing records its upload position, generation and reader certificate. When a renewal changes what a listing can see, continue `App::list_collection` while `CollectionListed::more` is true, or `App::list_collections` while it returns true. This includes a grant gaining its first readable collection. The client can adopt a wider certificate while a protocol still owes a callback. The protocol receives its earlier work before the newly visible records. Restoring an app backup starts a new listing of its registered collections.
- **Service.** The service stores both admission reasons in one row per peer. Rust callers inspecting the store use `AccountTxn::peer_admissions` and `denied_peers` in place of `list_entries`. The rollback mark records acknowledged changes and a service-time floor. The database records which service run last stamped the account.

- **Client backups.** App backups include `put_backs`, `record_settlements`, `duties`, `duties_left_behind` and `peers`, even when the lists are empty or the count is zero. `duties` replaces the earlier `protocol_notices` and `delivery_unknown`; a backup without it is refused. `peers` is the app's copy of the lists with its reply observations; when the lists don't fit beside the rest of the backup it holds the deny entries alone, and when those don't fit either it is empty. A backup without it is refused. A backup taken during a provider loss's list step also carries the entries left out of the owed upload, a required member. After a restore, a kept peer or reply grant the backup carries neither admits in `App::admits` nor counts as held until a list read or a change to that peer verifies it, so a send writes the grant again, and a cooperative move doesn't keep such a peer again. A provider loss does contribute it, as the only copy left. The backup's deny entries apply at once, and on a restore in place every deny entry the store holds is kept beside them. `AppEvent::ListsUnverified`, a duty event kept until acknowledged, tells the host how many kept peers and reply grants the restore brought back, what the backup left out of its lists, and how many unverified kept peers a loss contributed. A kept row's value is now empty, or one byte for a row a restore brought back; any other value reads as such a row.

### Future changes

Stored formats may change before release.

Cooperative moves between providers and a public generator for the complete test-vector set are deferred. The published vectors are available for checking implementations now.

The service's store begins every transaction through a helper of its own, because sqlx 0.8 can leave a transaction open on a connection when its `BEGIN` is cut short. Once the store moves to an sqlx release that fixes this, the helper can go, and the store can use sqlx's own `begin`. The check that closes a connection handed back inside a transaction stays.

## Known issues

### Service

- [data] **Recovery enrollment can acknowledge exclusions a restore loses.** A successful enrollment during account creation or while an account needs recovery can leave the rollback mark without evidence of the exclusions it acknowledged. A restore can then lose an App ID the signer expected the service to keep. Preserve the complete database for this account before recovering at the same provider.
- [data] **Takeover can lose the generation recorded before the first chain item.** When the database loses that account, replacing its surviving mark can clear the generation needed for recovery. Keep the service stopped for the affected identity until a database that retains the acknowledged state is available or the signer completes a separately confirmed recovery at another provider.
- [data] **A database restore can repeat a webhook.** The send worker's attempt count and its decision to use a registration are not both covered by the account's rollback mark. Keep outbound push delivery disabled on a restored database until its registrations and pending deliveries are reconciled.
- [authorization] **Recovery can install a write made after a grant ended.** Only during service recovery, when the original time cannot be proved, the service judges a receiptless upload by the scopes on the original writer's certificate. An app that once held the required scopes can have a create or delete installed after its certificate expired or its renewal closed, provided the app has not been removed. A reader refuses another app's undated write if the writer's only qualifying certificate is closed. It can accept that writer's undated write, including a delete, if the writer still has a listed or open certificate with the required scopes. For its own undated write the reader trusts its earlier local check of standing and checks the required scopes on one certificate of its own key, even a closed one. A writer that never held the required scope cannot use this path. As before, a write-scope holder's update can fill an empty key during recovery even when no create is shown.
- [authorization] **Removing an app erases the cutoff of an earlier grant.** A renewal can remove a scope and close the earlier certificate at `until`. Removing the app then erases that closure. A read, recovery upload, import or retained deletion can then count a write made at or after `until` and at or before `distrust_from` under the earlier certificate, provided the write falls within that certificate's lifetime. This judgment changes with the following change, which preserves the closed renewal on removal.
- [data] **Recovery can select the wrong shared record.** An upload without proof from the lost service can displace a proven write, and the first upload at an empty key can determine its collection and policy. Independently reconcile records that authorize an irreversible action before using a recovered value.
- [data] **Erasure can report that an account is absent while its data remains.** This happens when an older account is still in storage beside a newer rollback mark that has no chain head. A `not_hosted` response in that state does not confirm erasure.
- [wrong result] **Retiring a forked account can report success for the wrong generation.** When stored account state is a generation ahead of the mark, retirement can leave the recovery notice marked temporary. Check the notice's `permanent` field before telling a user the loss is final.

### Client

- [authorization] **A deletion callback can still run after its writer's removal cutoff.** When the owner was unavailable, retry delivers the retained deletion observation even if a newer removal now disqualifies the dated delete. The owner can receive that callback once. This retry behavior changes with the following change.
- [data] **Installations sharing an App ID share its service cursor.** Use one authoritative store or an exclusive synchronized handoff of pending observations and signed publications. An independent copy can advance that shared cursor before the other copy has restored the record. Keep independent evidence of completed actions when an absent record would otherwise allow the action again.
- [wrong result] **A restored backup can deliver a message the app already gave up on.** A backup taken before a message was withdrawn still holds it for delivery. Restoring that backup onto another store, after the protocol was told `MessageUndelivered` and acknowledged it, can deliver the original. Keep the original message ID, and do not issue a replacement the recipient would act on twice while an older backup can still be restored.
- [data] **A device clock change can reopen a batch's retry window.** After a long suspension, a clock set back close to its earlier value can make an old service-time sample look recent, allowing a retry after the service forgot the batch ID. Reconcile the original effect before repeating work that could apply twice.
- [data] **A restore can lose earlier provider-loss work and list history.** A backup taken during registration or the evidence upload can omit the unfinished step. A backup taken before a removal still carries the removed kept peer or deny entry. A later provider loss contributes them again, the kept peer included (Switch spec 12.6 step 2), and a cooperative move the deny entry; ask the user to look over the kept peers when `AppEvent::ListsUnverified` says a loss contributed some. A backup that couldn't carry its kept peers contributes none of them, and one that couldn't carry its deny entries none of those. The interrupted list upload and subsequent protocol answers have portable checkpoints. Restore replaces an outstanding unchecked deny change with a fresh list read, which can omit the individual change.
- [data] **A waiting message can disappear between feed pages.** The client detects a different item at a position for which it kept an observation, but a later page can omit that position entirely. A cursor past the position is insufficient evidence that the protocol received the message.
- [data] **One stalled protocol can cost another messages.** A shared deny-list change or missing list baseline can stop the whole app's feed until every protocol catches up. Monitor stalled callbacks and listings because other protocols can miss entries if the app falls behind retention or fills its inbox.
- [availability] **A held message keeps the app's shared feed cursor behind it.** Protocols that are ready can still receive later messages while the cursor waits. If the owning protocol needs data before it can decide, return `Outcome::Defer` with `DeferCustody::Immediate` to save the message locally on this read, or `DeferCustody::AfterBoundedWait` to save it on a read after the wait expires. Once saved, the cursor can pass the message. The host can use the reason in `AppEvent::ProtocolDeferred` to fetch the missing data and call `receive` again. This shared cursor is expected to stay for now.
- [data] **Senders share the limit on messages waiting locally.** At the total limit, traffic from two admitted senders can cause another sender's waiting entries to be discarded. Consume the durable drop notices and request the missing messages again where the protocol permits it.
- [data] **Some discarded work cannot be identified after restart.** A stored message outside the bounded waiting pool can fail a check on retry and disappear with only an in-memory event, while an in-place restore can reduce some unreadable pending duties to a count. An empty queue cannot establish that every obligation completed.
- [wrong result] **A newly held peer can still gain inbox admission.** If a batch adding its reply grant was already sent and the answer was lost, the client can retry that batch after the host places the hold. Treat admission as unresolved until the earlier write is reconciled.
- [availability] **Two successive provider losses can leave a record readable but unwritable.** The client can retain the original proven version while the latest service reconstructs a lower version for the same write. Retrying the same conditional update keeps failing, and treating the record as absent risks repeating its effect.
- [availability] **An incorrect service clock can make an app's records unusable.** A far-future signed time can become the minimum timestamp for later app records, including after the device clock moves backward. Other apps can reject every such record as too far in the future even after the service clock is corrected.
- [data] **Two devices of one app can overwrite each other's protocol member.** When both change the same member, the later record wins and the earlier change is not merged. The protocol on the device that lost is told with `MemberChanged`; write the member again there if it still applies. A member taken from another device's record also arrives without that device's expiry request, so the next plain renewal signs it with no deadline; the protocol is told with `MemberChanged` and can set the expiry again.
- [availability] **One protocol's expiry can block app-record signing for all protocols.** A fixed expiry request can block app-record signing for every protocol once its deadline passes, also when its protocol has no member in the record. At a certificate renewal such a request is dropped and reported with `MemberDropped`, but ordinary signing still refuses. Clear or renew the request before its deadline.
- [availability] **Larger valid lists and backups can exceed one local commit.** The client installs a list copy or restores a backup in a single transaction, so raised service limits can permit data the app cannot refresh or restore. Exercise both operations at the largest sizes the host intends to support.
- [wrong result] **A duplicate can be reported as conflicting before the sender's authority is checked.** This can happen when a previously stored copy is released and its bytes differ from the processed copy. The conflict flag alone is insufficient grounds to accuse or block the sender.
- [wrong result] **Requeuing a signed message can report the wrong kind of error.** `queue_stored` can report caller misuse when today's message rules reject previously valid bytes, or store corruption when different bytes reuse a retained message ID. Check the rules, ID and original bytes before taking action on the store.
- [wrong result] **The recovery count can overstate how many peers were left out.** A peer beyond the reply grant limit can be counted once for each protocol that named it. Display `reply_peers_left_out` as an upper bound on distinct peers.
- [wrong result] **A custom request can reach a different target from the one signed.** The low-level transport accepts methods outside the Switch wire format, some of which encode the request target differently. Hosts constructing requests directly should use only the methods defined for the endpoint.

### Signer

- [keys] **A hand-over can strand the only sealed copy of the identity key.** If the receiver recorded that its take-over won, it can finish installing the key in its original vault after the service disappears, then use confirmed recovery at another provider. If the receiver has only an offer and could still have lost to a withdrawal, it needs the original service's decision or an independent copy of the identity key. Retain that copy until the receiving vault has confirmed possession.
- [keys] **Some damaged signer stores cannot be restored in place.** An interrupted certificate renewal can resume on its original install when only the preceding document's account binding is missing and the private backup and original service both verify it. A pending app removal, epoch completion, hand-over restriction or alarm can still block replacement. Preserve the store and the identity key because discarding the records can discard restrictions on who may sign.
- [availability] **First enrollment at a changed account.** When the original account observation expires, hosts can offer `Signer::restart_first_enrollment` at the same service after explicit confirmation. A signed changed binding can lead to confirmed same-service restore when the original service now serves a verified identity document for the current account. Other permanent refusals and a surviving mark retain the applicable recovery options.
- [availability] **Changing answers can prevent key recovery from finishing.** If a read changes what the user confirmed, recovery at a serving account returns `SurveyChanged`. Survey again when the sources are stable. A provider loss declared with the key can proceed when a source shows less than before, but new evidence still requires confirmation.
- [data] **Key recovery at a lost service can drop revoked App IDs without saying how many.** When more revoked IDs exist than one enrollment carries, the extra ones that no version of the identity document lists are dropped, and the survey does not show the count. A dropped ID comes back only through a new approval by the user.
- [data] **A temporary rate limit can cause recovery to skip usable backup data.** If the backup's service returns `429` during its check, key recovery can proceed without the backup's key-bundle parts and with limits taken from enrollment. Retry after the rate limit clears before relying on the reconstructed state.

### Specification

- [keys] **Changing a service key does not retire its authority for every account.** The specification leaves the signer notification and authenticated link between successive keys undefined, so clients can continue trusting a compromised old key while their identity documents name it. Replacing the operator's key alone is insufficient to secure those accounts.
- [specification] **A failover during a running service can briefly expose an older account time.** A fresh service run uses the separate mark's time floor. If the database switches underneath a running process, a restored stamp can still belong to that same run until it detects the lost instance lock. Stop the service before restoring or switching databases and restart it afterwards.
- [specification] **Enrollment reports only some effective service limits.** Clients receive limits such as batch size and storage quota, but must assume defaults for others, including the kept peer and reply grant counts. Handle limit refusals even when a request fits the published default.
- [specification] **The specification doesn't say which kept batches go on after a provider loss.** Section 12.5 "Kept batches" says none of its rules holds after a loss, and 12.6 step 5 covers only kept `attempt`s, which are dropped as uncertain. The client signs every other kept batch again for the new generation and sends it there after its upload; the harness pins that behaviour, which the specification doesn't yet state.

## Not yet covered by tests or measurements

Some checks for write-lock ownership, recovery evidence and pending work still lack a test that fails when the individual check is removed. Large recovery transactions, slow connections and outbox operations that repeatedly scan and verify retained messages need measurements at realistic sizes. Cleanup remains in duplicated decision logic, test fixtures and host guidance.

