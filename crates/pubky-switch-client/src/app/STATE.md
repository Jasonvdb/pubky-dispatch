# App state in the store

The app layer keeps all of one app's durable state in the host's `StateStore`, namespace
`client/<app_id>` (the App ID in z-base-32). One record per key; no blob is rewritten whole.
Every value is `{"v":1,"d":<record>}` (`SCHEMA_VERSION`): any other `v` is corrupt. Two
kinds of list membership rows are the exceptions: `lc/kept/` and `lc/deny/` hold an empty
value, the key alone being the fact, but for a restored kept row's one-byte mark, and `lc/r/` holds the binary observation its row gives. A
backup carries the same `v`, with or without protocol layers. Keys are ASCII. Numbers in keys
are zero-padded to 20 digits so keys sort numerically. The record types are in `state.rs`.

## Rules for every change

- **Sign once, commit, send, commit the outcome.** A signed artifact goes into the store
  before it is first sent, and is resent byte for byte until answered (Switch wire 2.1).
  Examples: the join batch (`join`), a registration (`rk/<n>.pending`), a received message's
  effect (`pending/effect`), a record delivery (`pending/record`). A record is published on
  the Homeserver only once its delivery's answer is committed (`pending/publish`), in the
  bytes the switch holds.
- **The cursor moves only with, or after, what it covers** (Switch spec 8.2, 11). The
  effect's batch carries the cursor move, with the record writes and claim entries the
  protocol added through its receive context. The processed pair, what the batch's
  operations settle (record writes cached at their proofs' versions, claim proofs kept), the
  protocol's local writes and the cursor are committed together with the answer. A claim
  the receive step asks for (`Outcome::Need`) is read and kept (`claim/`, `clent/`) in a
  commit of its own, which moves no cursor; the step then runs again. A step that ends in
  `Outcome::Retry` commits nothing of its own: only, with the page, its count under
  `retry/`, and the entry under `parked/` once the cursor passes it. A step that waits for
  a scope key (`Outcome::AwaitKey`, or an effect applied with a write the context couldn't
  seal for want of the current data epoch's key) commits nothing of its own either: after
  at most one fetch of the key bundle, its own commits, the entry goes under `parked/` as
  `AwaitingKey` with the page, and the cursor passes it (Switch spec 3.5, 8.2).
- **A protocol waiting for data leaves the input owed.** `Outcome::Defer` discards
  callback writes and clears the input's store-failure count. The original input stays
  behind the feed cursor or moves into `parked/` as `ProtocolDeferred` before the cursor
  passes. Its receipt and acceptance time stay with it. Normal stored reads retry it
  outside the shared sender, key and admission pool.
- **An input waiting for admission stays unprocessed.** Both admission outcomes discard
  callback-staged operations, locals and pair-forgets. `Outcome::AwaitAdmissionWithCustody`
  adds its explicit owner-local writes to the transaction that retains or drops the input.
  These writes are ordinary protocol state under the owner's prefix. The shared
  sender/key/admission selector counts the incoming input before the cursor passes it.
  Its retained payload or exact payload-free drop notice, all selected deletions and the
  cursor/seen change commit together. A later due retry keeps its original local ID,
  acceptance and first durable observed receipt. Capacity alone neither retries the input
  again in that read nor prevents unrelated eligible inputs from proceeding.
- **A batch refused with `409 stale_epoch`** is gone from `opq/` with the refusal; the app
  takes the newer `identity.json` and key bundle, each in its own commit, and the batch
  sealed again is signed and kept under a new batch ID before it is first sent.
- **A kept batch has one ID for its whole life:** the batch ID it is first kept under
  (`opq/<batch_id>`). Signed again for a later generation, its bytes carry a new batch ID
  and stay under the same key, so `AppError::Kept`, every event about it and
  `App::kept_batch` name the first one; the wire ID is in the record's body. The commit
  that applies or drops it writes its end (`kb/<batch_id>`, `kbt/`) with that change, so
  no crash leaves a batch neither kept nor ended.
- **A passed entry keeps nothing** (`Outcome::Pass`): the cursor moves past it as past a
  processed one, or `seen/<seq>` marks it past a held one, and nothing else is written: no
  `proc/` or `proct/` pair, so a re-send of the message is delivered again (Switch spec
  11), no `parked/` entry, no `duty/` event, nothing the context added. An entry stored
  locally that the protocol passes stays as it is under `parked/`, with its `sretry/` count.
- **A retired receive key goes only after the cursor's commit** that passes the next key's
  registration (Switch spec 3.6).
- **Any commit carries everything read before it.** A page's writes go in the next commit
  point, so no commit records a cursor past items whose writes it lacks.
- **After a failed commit the app reloads** from the store before its next call. A
  pending alarm and verified service-time evidence are first retried in one commit;
  a failed or unknown outcome leaves them held in memory and stops the call. Every app
  commit carries the pending alarm, including a compromise's required leave. Only a
  confirmed successful write clears its pending status, so a reload cannot erase the
  evidence that stopped the app (Switch spec 3.6, 4.3, 10.1). Before that first successful
  write the evidence is held only in the running app, not promised durable across a crash.
- **A kept batch or effect is never sent again past its window**, whatever the generation:
  30 days from its first send, less an hour, both ends in verified service time, erring
  older. Its first send is stamped (`kept_ms`) at the earlier of the device clock and the
  highest service time verified with the current service key, and the stamp is committed
  before the request leaves. The service's stamped time never goes back, so that stamp is
  at or before the time the service applies the batch however old the held time is; the
  app reads a time first only when it holds none of the current key, or one more than a day
  behind the device clock, so that the window doesn't end much sooner than it could. The
  read is of a feed page with no items (`limit=0`, Switch wire 7.4.4). A batch never sent
  has no stamp and no window, can't be ambiguous, and is never judged for age, and a call
  that needs a time and can't verify one leaves it kept and unsent. An effect is stamped
  the same way when it is kept, right before its first send. Its age is judged at the later
  of the device clock and a service time verified in the call that sends it again, which
  the same read fetches when no answer of the call brought one; a time verified more than
  10 minutes before by the device clock, or with the device clock gone back since, is read
  again. One past the window by the clocks at hand
  already, the device clock or the service time held, needs no reading. Past it a retry
  would get `409 conflict` once the service dropped its proofs, or be taken as new once it
  forgot the ID (Switch wire 6.4 step 5): the effect's entry is parked as uncertain, the
  batch dropped with its attempts, unsent.
- **A refusal of a batch sent again tells only from the batch ID lookup on** (Switch wire
  6.4 step 5). One made before it is about the caller, such as `403 cert_expired`, or about
  these bytes, such as `400`. About the caller, it tells nothing of the batch: a kept effect
  or batch stays as it is, to go again unchanged once the service accepts the app's
  requests, and a renewed certificate is taken before a kept effect goes again; past the
  window it is parked or dropped as uncertain. About these bytes, it will come again: the
  effect's entry is parked as uncertain, or the batch dropped with its attempts, at once.
  The codes are classified in one place (`refusal_place`).
- **A duty event goes in the commit of what it reports** (`duty/<id>`), and is reported
  only once that commit is done: a failed commit reports nothing, and a crash after it
  loses nothing, since every load reports the kept duty events again. A commit that
  answers `StoreError::Unknown` may have been applied: the reload after it reports every
  kept duty event no call reported yet. An acknowledgement removes only events handed to
  the host since the app was loaded, by `take_events`, a call's report or
  `unacknowledged_events`. `pending_duty_events` inspects the same kept duties in ascending
  ID order after any automatic reload owed by a failed commit, without handing them over,
  consuming the next report or extending acknowledgement eligibility. Inspection adds no
  stored queue of its own. The host still handles every delivered duty through an ID before
  acknowledging it.
- **Only the host's acknowledgement removes a duty event,** with one exception: the commit
  that takes an erased account back (`AccountBack`, Switch spec 12.7) removes the
  `AccountGone` events not yet acknowledged, which no longer hold. The app sets no cap on
  `duty/`: a cap would have to lose a duty event, or stop reading the feed (which never
  stalls, Switch spec 8.2), giving up undeliverable messages (Switch spec 11) or following
  a provider change (Switch spec 12.5, 12.6). A host acknowledges each one once its
  protocol has kept what it says.
- **Exact acknowledgment and local handling are atomic:** `App::ack_event_with` removes
  only the acknowledging protocol from the delivered, still-owed EventId and writes bounded qualified protocol locals in one commit.
  Foreign, undelivered and absent IDs refuse without writes. After an unknown result the
  caller uses its own durable handling marker; absence alone is not success.
- **Both backups carry waiting custody and owed drop notices:** required common `waiting`
  contains sender/key/admission payloads, retry position and metadata, held feed receipts
  and exact notices. The protocol layer carries other parked inputs, including a pending
  effect's uncertain copy. Restore validates signed custody bytes and structural notice
  consistency before installing anything, selects bounds in the installation transaction,
  and preserves snapshot payload semantics. In-place duties are retained; identical stable
  notice IDs deduplicate only with identical content. An older restored layer owes its
  backed-up notice again if it no longer carries the handling effect. A receipt records the
  original authenticated page's time and key; it is not portable signature proof. A notice
  has no plaintext with which to reverify the historical message signature.
- **Kept custody is read, not judged again:** load, reload, intake, a drop notice and
  restore read a waiting input by its authenticated common fields only, every body member
  opaque, so a protocol's changed body rules never make the store corrupt; the input's next
  retry judges current rules and drops one that no longer passes at that check, with the
  same `StoredEntryDropped` duty event (`DropReason::Rules`) as a bound drop, in its commit. The
  service's facts about an entry are checked when its page is read: a page that shows an
  entry accepted after the page's time, or after the observation kept for it, is refused,
  so a kept observation that precedes its entry's acceptance is a corrupt store.
- A foreign record deletion whose owner cannot yet save its observation is kept under
  `delobs/<key>/<generation>/<version>/<item hash>`. Its original signed delete,
  preceding signed readable write when available, certificates, proof, prior mark
  and verified feed-page time travel together. The owner waits there while another
  owner can continue. Proof of an app's own submission settles its record write while
  an earlier foreign observation remains owed. Both backup forms carry unanswered observations. A restore
  verifies the deletion, checks the predecessor's identity against the signed base or
  dated proof, and keeps outstanding observations from the same install.
- The owner's bounded observation writes and their acknowledgement commit together.
  `delack/<key>/<generation>/<version>/<item hash>` holds the identity of the
  observed deletion, owner, read scope and application position. It contains no record
  body. A later authenticated write, a different current view or confirmed absence
  within the app's read scope retires it. Only a layered backup carries this
  acknowledgement, inside the layer whose writes it identifies. An older layer can
  receive the deletion again. During an in-place restore its owner can read its
  own earlier installation's local state and return verified evidence to retain. The
  owner can stream its collection's held records from the old namespace. One record
  is read at a time, under both certificates' read scopes. The write, writer and
  opened bytes are checked before returning its existing version and flags. A fresh
  installation and the backup's standalone check supply no previous records.
  A prepared observation moves to `hold/<key>/<generation>/<version>/<item hash>`.
  The hold retains the same signed delete and predecessor and whether this app still
  protects the deletion at the service. Its wait notice names the exact deletion.
  The hold also carries the signed conditional operation, its first-send time and any
  cursor generation sent with it. A backup carries the same outstanding submission.
  A competing write can satisfy the hold independently. A sent operation whose exact
  target was displaced, or whose generation the app left by a move or a key change in
  place, can move to `opq/` for its original result within the deciding window; outside
  it, or with no room there, it is dropped, of unknown outcome. It keeps
  its signed bytes and batch ID across reload and restore.
  The earliest protected position of the cursor's generation bounds a cursor request other
  than its own atomic replacement. On restore the
  first verified service cursor reconciles the held positions. A local in-place hold
  survives an older owner layer and the owner can save its evidence again. A
  compatible applied write, owner release, loss of write scope, departure, provider
  loss, or a move or key change in place past the delete's generation retires the
  applicable hold. No hold of an earlier generation is kept: one first seen after the change
  ends at its observation, one met by a try ends there, and one still waiting for its first
  observation is left for it and ends at the owner's answer. A restore keeps such a hold
  only to end it so: it protects no position and waits for no cursor. A second delete of the key
  keeps its own identity.
  An ordinary reader compares a repair with its held signed record and the retained
  predecessor before retirement. These comparisons need no separate stored history.
  Each feed item reserves 8 MiB for both signed records, the prior mark, owner writes
  of up to 4 MiB and their acknowledgement. Restoring still has to fit one 32 MiB store commit.
- **A restore is one commit:** the namespace cleared, the app's restored state and each
  registered protocol's backup layer under its `p/<name>/`, all checked before it, so a
  failure leaves none of them. A layer of a protocol not registered refuses the restore,
  and a newly registered protocol without a layer is handed none, as every protocol is
  for a plain backup. A layered backup carries its original registered protocol roster
  with `seen/`, `parked/` and `proc/` of the same moment (`beyond_cursor`). Before any
  restore callback, that nonempty, unique roster must match the layer owners exactly,
  including layers with empty state; processed kinds with registered owners must belong
  to that roster. This keeps seen marks bound to their layers even after processed pairs
  expire. These are the entries which the layers
  may reflect, so no entry is handed to a protocol twice. A kept
  effect's entry goes in as a stored uncertain copy with its `seq` in `seen`, as the app
  passes an entry it stores: its processed pair ages out after 30 days, and the `seq`
  keeps a restore from an older backup from handing it over again unless the host
  releases the copy.
- **A layered backup reads one moment:** `App::backup_layered` is several store reads in
  sequence, and they agree because the call takes `&mut self`, so no call of the app commits
  between them, and the store allows one writer per namespace (`StateStore`, rule 4), so no
  other process does. Before those reads it commits the shared waiting bounds, even while
  an alarm stops intake, so it needs a writable store. Those drops stay committed if the
  backup is then refused; the alarm remains intact. It makes no network call: the entry a kept effect (`pending/effect`) belongs
  to, stored or read from the feed, goes into the backup as `Uncertain`, its flags kept,
  with the processed pair of its message, since a restore never carries the kept effect;
  the live store keeps the effect as it is. An entry read from the feed takes a local ID the
  live store reserves first by moving `parkid` on, on a halted app too (its commit also
  keeps a service time not yet committed), so no later
  entry of the live store takes it.
  When the protocol bounds first handoff, the queued batch also keeps that exclusive
  deadline. A body-bound service answer can establish timely handoff for the hash of
  those exact bytes. The pre-send stamp alone leaves that question open.

- A kept message and its signed plaintext queued again use the common message fields even if the protocol narrows its body rules. The protocol still decides whether to send it.

- **A backup carries the outbox:** every `out/` record as it stands, a message refused for
  good included, so the restored app reports it failed until it is forgotten; oldest queued
  first, within `MAX_CARRIED_OUTBOX_BYTES` (8 MiB), so the restore's one commit fits, the
  messages past it named so the restore keeps a give-up duty event (`MessageUndelivered` or `DeliveryUnknown`) for each;
  and the backup's time, the device's and the highest service time verified then. Both
  kinds of backup read it from the store, a layered one in the same moment as the rest, and
  both check that the restore fits one commit before they return. A restore writes the
  records back in its one commit, so a message queued before the backup goes after the
  restore with the same `msg_id`, signed plaintext and last sealed envelope.
- **A give-up says "undelivered" only when no request can have carried the message:** an
  `out/` record keeps `envelope_sent`, always written, committed immediately before the
  first transport append (and rolled back only if a pre-transport hold stops that call
  before any transport request leaves). Once a transport call is attempted, it is never
  cleared. A give-up of a message not accepted
  before keeps `MessageUndelivered` only without it and without a replay deadline, which
  marks a copy that may already have been sent or that another store may have delivered;
  else `DeliveryUnknown`, as does a refusal
  for good of a message with it. A message a backup left out past its budget is
  `DeliveryUnknown` too, unless it was accepted before. A backup carries every give-up the
  protocols haven't acknowledged as its duty event (`AppBackup::duties`), and every restore
  tells it again. No restore delivers or tells a second time a message whose give-up a duty
  event tells, the backup's or, in place, the store's, carried or left behind for a protocol
  no longer registered: it marks the give-up again and puts the backup's record back only
  for what else it owes, a refusal for good as it stands or an accepted message's owed
  record job.
- **Replay deadlines bound attempted, restored, reconstructed and re-sent deliveries**
  (`replay_until_ms` on `out/` and `sent/`):
  - A message queued by this store and never tried has no `replay_until_ms`.
  - In the commit right before the first transport append (together with `envelope_sent:
    true`), an item that does not already carry a deadline is given the device clock then
    less the clock tolerance plus `SENT_RETENTION_MS` (30 days); an unsent item that
    already carries one (from a restore, `App::queue_stored`, or a re-send) keeps its
    existing deadline. If a pre-transport hold stops that call before any transport
    request leaves, `envelope_sent` and `replay_until_ms` both roll back to their previous
    values.
  - An item that carried no deadline in, accepted in the try that committed its first
    possible send with every earlier append of that try a verified refusal (`401
    stale_timestamp`, `409 stale_key`, `409 identity_needed`), has `replay_until_ms`
    cleared before the acceptance commits, so `out/` and `sent/` carry none and re-sends
    run for `SENT_RETENTION_MS` from `accepted_at`. Otherwise (accepted in a later try or
    after an unverified answer, or carrying a deadline from a restore, `App::queue_stored`
    or a re-send) it stays on `out/` and goes into `sent/`, the earliest kept.
  - A restored delivery is given the earliest of any deadline it carries already (including
    one from an earlier first possible send before the backup), its first acceptance plus
    `SENT_RETENTION_MS` when it was accepted before, and the backup's verified service time
    (or its device time without one) less the clock tolerance plus `SENT_RETENTION_MS`.
  - An `App::queue_stored` copy is given `created_at` less the clock tolerance plus
    `SENT_RETENTION_MS`, and a re-send is given the earliest of its carried deadline and
    its first acceptance plus `SENT_RETENTION_MS`.
  - Any earlier copy the recipient processed is dropped as a duplicate until then: the
    recipient's switch answers a retry of the same envelope with its first answer while it
    holds the entry (Switch wire 7.4.3 step 1), and the recipient's apps drop a copy taken
    as new by its processed pair, kept 30 days and the tolerance from processing, which is
    at or after the first possible send and first acceptance (Switch spec 11). Every try of
    an item that already carries a deadline on entry checks it before delivery at the later
    of the device clock and a service time verified in the call, which a read of a feed
    page with no items fetches when the device clock says the deadline hasn't passed (a
    deadline newly committed for a first attempt is not enforced inside that same call):
    past it the delivery is given up in one commit with a give-up duty event
    (`DeliveryUnknown`, or `MessageUndelivered` with `resend: true` for a re-send), a
    message never accepted deleted, one accepted before kept for its owed record job, its
    sealed envelope dropped. A later backup carries the deadline and a later restore keeps
    the earlier of it and its own.
- **Outgoing origin is explicit** on every `out/`, `sent/` and `opq/` queued copy: original
  queued work or reconstructed signed plaintext (Switch spec 11). Acceptance, re-sends,
  retained-batch settlement and snapshot restore preserve it. Overlapping retained copies
  agree on identity, signed bytes and origin. Queuing stored plaintext inherits an exact
  kept-only original intent's origin without changing that batch; an existing reconstructed
  copy is never promoted by a later queue. The inventory scans every retained producer,
  not the latest message-status index, and uses dispatch's hold and protocol decisions.
- **A protocol batch can mark its first local keep.** `OpBatch::keep_id_at` stores the stable 16-byte ID under its own local key in the transaction that first records `opq/`. Ordinary retries keep that ID. A batch resealed after a definitive stale-epoch refusal replaces its earlier marker in the new batch’s first commit. The protocol can delete its marker with the applied batch’s local writes. Its backup layer determines which outstanding markers survive a restore.
- **A backup doesn't carry `opq/`, `sent/` or `sentt/`.** A kept batch's messages go into
  the outbox only with the batch's answer, so a restored app neither sends the batch nor
  delivers the messages it would have queued; the restore's reconcile mode reads the shared
  records and claims, and the protocol queues what it still owes again: a message such a
  batch queued, when the batch was applied and a record it wrote stores the message, goes
  again from that record's signed plaintext through `App::queue_stored`, with the same
  bytes and `msg_id`, its replay deadline 30 days from its `created_at`, less the clock
  tolerance (Switch spec 11). Nor does it carry
  the ends of kept batches and their indexes (`kb/`, `kbt/`, `kbm/`, `kba/`): a restored
  app's `App::kept_batch`, `App::kept_attempt` and `App::delivery` know nothing of a batch
  kept before the restore. A restored app
  answers re-send requests only for what it delivers after the restore.

## Keys

| Key | Holds | Sensitive |
|---|---|---|
| `meta` | identity, App ID, switch origin, pinned service key, generation followed | |
| `keys` | the app's signing and bundle secrets (`AppKeys`) | yes |
| `cert` | the certificate the app presents (signed) | |
| `cert/renewal` | a signed renewed certificate and its `cert.put` feed position, until the app takes or refuses it. A feed or directory position that lists the held certificate is saved with the listing identity, so reopening before adoption preserves the order of the widened record listing. A listed certificate the app holds no `cert.put` for, a renewal another device took whose `cert.put` the feed showed only as a stub once that device's record carried it, is taken at a read's start from the own record in the directory, under the renewal checks, as after a restore; a look that doesn't find it, or fails, is made again at most every `DOC_CACHE_MS` (10 minutes, in memory) while the listing lasts, and the read goes on; a `403 not_current` refusal of the app's record write makes the next read look at once. A take keeps a later renewal held from `cert.put` that renews the certificate taken; a record change kept under the earlier certificate is signed anew under the taken one, later than both, and delivered; the taken record is noted as accepted (`record/accepted`) and the published copy checked against it. A certificate the app's protocols can't run with, one holding a scope root no registered protocol owns or one a protocol's `check_own_certificate` refuses, is never taken, by any of these paths: the app keeps presenting the one it holds, so it still loads, and the held renewal that is it goes, with `CertificateRefused` (a duty event, for every protocol, naming the root or the protocol) and `cert/refused` in one commit | |
| `cert/refused` | the hash of the newest renewed certificate refused as above: a read that finds it again, in the own record another device put, refuses it without a second event; deleted in the commit that takes a certificate. A backup carries it (`AppBackup::cert_refused`) with its `CertificateRefused`, and a restore puts it back; in place, the store's own mark wins | |
| `record` | the app record the service holds or is being given (signed) | |
| `naming` | the naming key | yes |
| `scope/<epoch>/<scope>` | one scope key | yes |
| `bundle` | `keys_through`, and when a full bundle was requested (the service's `requested` time), until no key is missing or the feed shows a part stored at or after that time, which asks again for a key still missing: at most once per such part (Switch wire 7.4.11). While it is requested, an entry that waits for a key fetches nothing: the answer comes as a part the feed shows. A backup carries it and a restore drops it, so the restored app's first read fetches and asks once if a key is still missing | |
| `ident/<pubky>/doc` | the newest `identity.json` taken for an identity, own or a sender's, with the Homeserver and public switch read times for that exact version, if any | |
| `ident/<pubky>/floor` | the highest version and generation seen | |
| `ident/<pubky>/body/<version>` | the body hash seen at a version, for equivocation | |
| `ident/<pubky>/equivocated` | the version at which another body was seen | |
| `ident/<pubky>/sw` | the version covered by the lookup, its starting time capped by the signed time of each service needed to complete it, its number, and whether the switch copy was read, stale or unavailable | |
| `ident/<pubky>/swn` | the number of the last switch lookup begun for a counterparty, which orders the lookups whatever the clock reads | |
| `rk/<n>` | a held receive key: secret, signed record, registration `seq` and service time, pending batch | yes |
| `kid/<kid>` | a kid this app or one of its devices made, kept after the key is deleted | |
| `reg/<n>` | a registration of the own app whose key this device doesn't hold: own, awaiting device sync, or unaccounted after a restore. One rule judges a registration no device of the app made wherever it is met (the restore's key check, the feed, a registration conflict, a provider loss's, the re-registration after a move or a key change in place, and the device sync): while the `restore` record is held, one after the backup's newest key and before the key the restored app registered is unaccounted, and only the user's "no" is a compromise (Switch spec 12.4); any other is a compromise at once, or awaits the device sync on an app that shares its keys. The record is in the store, so it holds across a crash between following a provider change and the restore's key check | |
| `rotation` | the last rotation's time, and whether an envelope to the current key was opened since | |
| `device` | whether the app shares its keys across devices | |
| `cursor` | the processed position, the cursor the service holds, the deferral, the cursor's time, and `sent`: the furthest `seq` of this sequence a record replacement's first send carried the cursor to, kept once that replacement's batch ended applied or of unknown outcome (`App::end_kept_batch`), which the held cursor counts as sent; never lowered, reset with the sequence at a provider loss, carried by a backup. While the move is the hold's (`cursor_generation`) or a kept batch's (`cursor_seq` in `opq/`, read from its index `opqm/`), the held cursor counts it from there, and a refused batch takes it away with it | |
| `chain` | the chain view's small fields: tip, open batch, pending heads and checkpoint, newest head, the continuity gap, held marks, restore state, and `read_through` (generation, highest authenticated feed `scanned_through`). The latter includes inbox items outside the chain and only bounds `told/` on reload; it never authorizes delivery, acknowledgment or continuity. It is written with the page, carried unchanged through a cooperative move and backup/restore, and starts at zero in the new sequence after a provider loss | |
| `chain/at/<seq>` | the verified chain hash at a `seq`, from a little behind the cursor on: the hashes behind it are forgotten in steps | |
| `chain/batch/<id>` | a batch ID in the 30-day window, with its first stub's time | |
| `chain/list-batch/<id>` | verified generation, sequence and operation hashes for unanswered peer and deny writes. Settlement binds the complete ordered batch to its original signed operations. Entries expire with the chain's batch ID. | |
| `chain/list-effect/<list>/<peer>` | latest verified change to a kept peer, reply grant or deny entry, `<list>` being `kept`, `reply` or `deny`. Its position commits with its membership, including a removal. Keep it until the feed has passed it and the last unanswered submission on that key has settled. A backup carries the positions ahead of its cursor, as `ahead` entries `<list>/<peer>`; a restore refuses a backup with any other kind, as an earlier `contact/` one. A full list has its own signed cutoff. | |
| `proc/<sender>/<msg_id>` | a processed message's kind, hash and time. Only the registered owner of its kind may forget it (any protocol when no registered protocol owns the kind) (`ReceiveContext::forget_processed`, in the step's commit with its other writes, or `App::forget_processed`, in one commit with the protocol's local writes): the pair and its `proct/` entry go, so a re-send is delivered again and nothing is left to prune; refused while the message's effect is kept (`pending/effect`) or an entry stored locally holds it | |
| `proct/<time>/<sender>/<msg_id>` | the time index for pruning processed pairs | |
| `seen/<seq>` | an entry processed past a held one | |
| `held/<seq>` | an entry of the feed the cursor stays before, unprocessed, whatever it waits for (its sender's check, a callback retry, a claim read, a conflict, a stale data epoch, a call its protocol owes), processed past an earlier one (`seen/<seq>`), or whose effect is kept: since when it was first held, its first durable observed receipt (entry ID, hash of the invitation redeemed for that entry or null, verifying service key and that page's authenticated time) and the acceptance time that page showed. Staged before handling the entry, so a separately committed resend callback, key fetch or saved effect keeps the first observation. Deleted when the cursor passes it | |
| `retry/<seq>` | an entry on the feed whose receive step the protocol's store or the host kept from finishing (`Outcome::Retry`): the reads in a row that ended so, and when the first was; it goes once the entry is processed or stored to wait for a key, or moves to `sretry/<id>` when the entry is stored locally for another reason | |
| `sretry/<id>` | the same count for the entry stored locally at local ID `id`, until it is processed, stored for good or stored again to wait for a key | |
| `parked/<id>` | an entry stored locally and passed, keyed by its local ID, which never changes: the `seq` and generation it was read at, the opened plaintext, sender, certificate, acceptance time, original observed receipt, reason (waiting for protocol admission, an unverifiable sender, a quota or a store failure of the receive step, tried again; a scope key the receive step waits for, with its data epoch (`AwaitingKey`) and how many scope keys the app held when its step last ran (`keys_at`), tried again only once the app holds every key of that epoch its certificate is given and holds another number of keys than then, so a key the certificate is never given runs its step again only when a key comes; one whose step waits again for the same epoch stays stored as it is, its count brought up to date, with no event; one whose step ran while a reopening was owed (`reopen`), such as after a key its page or its own fetch took, keeps no count; none is tried while a reopening is owed, which its step may read, so its count stays and it is due once the reopening is done: at the retries at the start of a read, or, for one a fetch later in the read brought the keys of, at the end of a read that doesn't stop and owes no listing, at most `PARKED_RETRIES_PER_READ` there, so one whose key never comes costs a read nothing; an effect refused for good, over one batch, too large for the store to keep or commit, carrying an operation the app layer builds itself, or kept past the window in which its resend tells whether it was applied, not tried again; one the host released after such a window, `Released`, tried again). The host forgets any one (`App::forget_parked`) while no unacknowledged duty event names it or another entry stored for its message, and no kept effect (`pending/effect`) is one of theirs: in one commit with those entries, their `sretry/` counts and, unless none of them had its sender's standing checked and read as a message, its processed pair if none is kept, so a re-send stays a duplicate. Or the host releases an uncertain one (`App::release_parked`), in one commit that removes its processed pair, and marks it `released`, which it keeps whatever it is stored for again, through a backup and a restore, so each later run is handed over as released; a run of it that ends as a duplicate keeps a `ReleasedDuplicate` duty event. Entries stored as `Unverifiable`, `AwaitingKey` or `AwaitingAdmission` share one pool. Bounds include each incoming input atomically, run locally before every read even when halted, before a layered backup, and during restore installation (Switch spec 8.2): kept at most `MAX_UNVERIFIED_AGE_MS` (21 days) from acceptance on the highest verified service time, `MAX_UNVERIFIED_PER_SENDER` (64) per sender identity and `MAX_UNVERIFIED_TOTAL` (128) in all; one past a bound goes, accepted earliest, of its sender or, for the total, of the identity holding the most (of those holding as many, the one whose newest entry is newest), with its `sretry/` count and a `StoredEntryDropped` duty event in the same commit, at most `UNVERIFIED_DROPS_PER_COMMIT` (64) per upkeep commit; an incoming selection is indivisible. The entry a kept effect (`pending/effect`) belongs to is neither counted nor dropped until the effect settles. Entries stored for other reasons aren't counted | yes |
| `asked/<seq>` | A retained or completed callback for this feed item. True identifies a missed notice. A layered backup carries still-unpassed missed positions with the owners' local effects. | |
| `parkn` | where the retries of entries stored locally stand in their round: its number and the next local ID. The round covers the entries stored in an earlier round, each `parked/` record naming the round it was stored in; each read tries at most `PARKED_RETRIES_PER_READ`, in local ID order, and an entry stored later waits for the next round, so every entry is tried within two rounds | |
| `parkid` | the local ID the next entry stored locally takes: it only goes up, and is never below one past the highest `parked/` key, so no ID is used twice in one store. A backup carries it; a restore starts past the backup's, the one of the store it restores in place (past that store's `parked/` and `sretry/` keys when its counter doesn't read), and every ID a carried duty event names | |
| `retell` | after a restore that brought back entries stored for good: the next local ID to tell the protocol of again and the end of the restored IDs (Switch spec 12.4). Each step after the restore's commit keeps a `Parked` duty event for at most 64 of them not already named by a kept duty event, and moves the next ID past them in the same commit; the last step deletes it. A read finishes what a crash left | |
| `owed/<generation>/<seq>` | A pending resend, missed-entries or deny list change callback. `to` lists the protocols whose responses still need to commit. The last owner's commit removes the entry. See [callback delivery, restore and provider changes](#what-the-app-owes-its-protocol-restores-and-provider-changes). | |
| `dgap` | a gap in the deny list's history not told to every protocol yet (after a checkpoint past the cursor, a provider loss, a change whose writer the directory no longer lists, an upload transition that added to the lists after the complete list read, a deny entry an app with `lists.read` alone leaves out of a loss's owed upload while the copy holds its row for the upload (`loss/list-held/`), a restore, which notes one at the restored cursor in its own commit, whatever the backup held, after the namespace's delete takes the store's `dgap`, or a copy of the lists not known complete, as after a join, a renewal that added `lists.read` or a gap told without the list (`App::refresh_lists_if_owed`), or `App::allow_list`, which commits it on its own before it replaces the copy): the position the history is complete through, the earliest owed, and the protocols it is owed to (`to`), always every registered protocol, written with `lc/lists_at` deleted, by a restore with the namespace's delete, by every other writer in the same commit (`App::note_deny_gap`). Every protocol takes deny list changes and gaps, so a gap noted is owed to every registered protocol, also to one that took a gap still owed to another. Told after the owed calls, with one list answer for the whole pass, each protocol response in its own commit (`Protocol::deny_list_gap`); the gap remains owed to all throughout intermediate commits, so an interrupted pass starts again for all from a fresh answer; one that fails keeps it owed to every one of them, those told too, and the read holds, so the tell that takes the copy hands each protocol the list the copy is taken from; the final successful callback commit deletes it and invalidates `lc/lists_at`, and the copy of the lists is then taken from the same answer, best effort. Only that replacement can mark the baseline complete; a failed replacement leaves it unknown after reload. A gap owed to no protocol, or to one not registered, is a corrupt store. Whenever the copy is taken whole from a list read, every protocol gets that list as a gap: `App::allow_list`'s copy is followed by its gap's tell, which takes the copy again from the list it tells. An answer that verifies but can't be read tells it without the list (`list_read` false): the commit in which every protocol takes it deletes `lc/lists_at` as well, so the next read owes a gap again: such a protocol is told `list_read` false at each read for as long as the answer can't be read. While it is owed the read hands nothing. It waits, and the read holds, while a protocol it is owed to isn't told through its position (`told/<name>`), a call or a listing from at or before it being kept for that protocol. Every gap noted is told, also at a position a gap was told at before, whose list may predate what the new one covers; a gap told again hands each protocol the full list again, which sets the same state | |
| `departed/<app_id>` | another own app's departure verified in the chain, and its time | |
| `join` | the join step: the registration batch while it is owed | |
| `pending/effect` | a received message's effect batch and its outcome writes, the keys of the processed pairs its step forgets (`forget`) among them, with the deadlines of the claims it writes, and the opened entry, to store it locally if the batch outlives the batch ID window; its local writes are kept in base64 (`kept_local`) | yes |
| `pending/record` | an `app.put` batch | |
| `pending/publish` | a publication is owed, for an app that publishes its record: written with `record/accepted`, and by a check that found the Homeserver copy missing or different when the repair's write failed, or when the copy is missing on an app whose devices share its keys and the call hasn't shown the app current (written back only once the switch has: in a read, after its feed, or right after the switch accepts the app's `app.put`); gone once the Homeserver copy is the newest accepted record, or a later one of the app's, which is never written over. While it is held every read tries the publication once, without waiting out `PUBLISHED_CHECK_MS`: right after a delivery the switch accepted at the read's start, or else after its feed, once the feed shows the app current; a read whose owed listing waits for a key reads no feed, and publishes as a call outside a read does. A check counts against the interval only once what it found is committed | |
| `record/accepted` | the newest record the switch accepted from the app, the one a publication writes: written in the commit that records an accepted `app.put` (a delivery, the join's registration, a re-registration at a new service), and never from a refused one. A `409 conflict` naming no record is an acceptance only when the switch's directory shows it holds the very record; one whose directory shows a later record of the app, another device's, drops `pending/record` as superseded and, when the later record carries the certificate the app presents, takes it here and as `record`, in the same commit: the app's next record builds on it, so the dropped body is never signed again. One carrying a renewal another device took that the newest `identity.json` lists is first taken with that certificate, as after a restore, and then so; one under any other certificate, which only a faulty switch shows, is never taken: `pending/record` is dropped alone. A backup carries it apart from `record`, which may hold a record whose `app.put` was refused or never answered, and a restore takes it from there, never from `record` (none from a backup without it); the record held then goes to the switch only with the next change, signed anew, and is never published before the switch accepts it. A provider loss deletes it until the new service accepts the re-registration | |
| `alarm` | the alarm that stopped the app | |
| `restore` | after a restore: the backup's highest `n`, the key check, the end of the registrations the restore asks about (set at the key check: the key it registered, or one above the backup's highest when the restored key was current), whether the key check found the restored key current (`key_current`, for the held cursor's verdict; null before the key check), reconcile mode; it goes when reconciliation ends with the key check done, and no registration is judged by the restore rule after. Before the key check the app reads its directory: it takes the own `identity.json` there if newer than the backup's, and the certificate that lists from its own record, under the renewal checks, so a renewal another device of the app took since, whose `cert.put` is a stub by then, is taken at the first read | |
| `hcur` | the last restore's check of the cursor the service holds (Switch spec 12.4 "The held cursor"): the backup's committed position, when the restore ran, and the verdict (`HeldCursor`), settled at the first page that isn't a frozen service's read once the own `identity.json` was confirmed after the restore, `Unknown` at once if a batch carrying a cursor move is sent first; written in the restore's commit and in the settling page's, and deleted with `restore` when reconciliation ends with the key check done. A clean verdict turns ahead when a later page reports a cursor ahead of the furthest position the app committed or sent, for an app whose devices don't share its cursor, and reads unknown once the backup's generation is no longer of the current sequence | |
| `hgap` | The sequence and highest held cursor handed to the protocols as a missed notice. A layered backup installs this progress with their effects. Each still-owed higher report at the same comparison position has a separate `owed/<generation>/<seq>/<held>` entry. | |
| `leave` | a leave in progress or done, committed before a publishing app deletes its Homeserver record: from then on nothing is published, across a restart too. A two-step leave calls `leave` only once the delete is made; an immediate leave and a compromise's call it whatever the delete's outcome, the call's mode deciding, so also after a two-step leave whose delete failed | |
| `service_time` | the highest comparable service time verified, its key, and the optional offset from the latest stamped answer | |
| `protos` | the registered protocol names, written by a join, a restore or `App::retire_protocol`. Retirement commits the smaller roster, removal of the outgoing owner's feed position and expiry policy, and any signed app record owed for its advertised kinds together. A load checks the complete stored roster before writing | |
| `p/<name>/...` | the local state of the protocol `name` (`LocalWrite`): every write a protocol hands over, through a callback, a batch (`OpBatch::for_protocol`), `App::protocol_commit` or `App::forget_processed`, is qualified where it enters the app, and kept so in `pending/effect` and `opq/`, so one protocol's writes, a `DeletePrefix` of its whole key space included, never reach another's | the protocol's |
| `rcd` | the protocols that ended the reconcile mode under way (`App::end_reconcile_for`); the mode ends, and `rcd` goes, when the last registered protocol ends it. Deleted in every commit that starts the mode: a restore (with the namespace), the commit that starts a provider loss, and the read's commit that continues from a checkpoint with continuity unverified, so every protocol reconciles again | |
| `rexp` | each registered protocol's expiry policy: `Never`, `At` a writable absolute time, or `Lifetime` a positive duration. Absolute deadlines remain fixed; each new record resolves lifetimes from its exact `updated_at`, capped by the current identity's `record_max_age`, and signs the earliest finite expiry. The policy map, record and pending `app.put` commit together. An exact retry keeps its bytes; conflict and certificate re-signing resolve policies again. An unchanged lifetime setter preserves policy and finishes delivery: accepted and pending records keep their bytes, while an unaccepted restored record is signed anew with the saved policies. Removal clears that protocol's policy. A renewal the app takes signs each member with the ask its protocol gives with it (`Protocol::member_for`), in the commit that takes the certificate, and no ask for a member removed; a record taken as it is from another device clears the asks of members absent from it. An unusable sibling policy refuses signing. A policy-only renewal keeps the valid caller's ask; a member setter instead keeps its requested member and ask atomically in `rmem` and `rexp`, so protocols can each replace or withdraw their members in turn. A backup carries the policies (`record_expiries`); restore validates owner, bounds and unique owner names before replacement (Switch spec 4.2, wire 3.2) | |
| `rmem` | unsigned member edits, at most one per registered protocol. A present null removes the member; an absent name leaves it unchanged. Each edit has an explicit policy in `rexp`, written in the same commit. The optional `_changes` member keeps requested accepts, each edited owner's previous policy and whether it requested a renewal even with the same body. A verified time read can finish these changes after a restart. When a draft's own deadline has passed, the read restores its previous policy and reports the refusal once. A draft saved without the previous policy retains the held record's signed expiry as its bound. The map is bounded by the operation byte cap, and each setter checks the resulting record's JSON and minimum operation size before retaining it. Every signature checks the exact resolved finite or null expiry against the operation cap; a lapsed sibling's future expiry is not invented for the unsigned check. Every local signature applies the edits, including after a record conflict, before a renewed certificate's protocol callbacks, and during retirement of another owner. The record and pending `app.put` commit deletes applied edits; an unanswered delivery then retries the exact signed bytes. The desired-state accessor reports pending edits separately from the held signed record and publication result. Backups require `record_members` and carry `_changes` as `record_changes` when present; restore validates owners, unique names, matching policies, form and size. In-place restore refuses to replace a different live pending choice or reintroduce an incoming edit whose signed basis is older than a verified local held or accepted record, unless the exact pair remains pending locally. A newer local signature establishes newer intent independently of delivery; it is not called publication. Retirement waits for the retiring owner's edit to be signed (Switch spec 4.2, 12.4) | |
| `duty/<id>` | a duty event (`AppEvent::is_duty`) with its remaining protocol recipients, written in the commit of the change it reports, until the host acknowledges it (`App::ack_events` or exact `App::ack_event_with`); one per entry stored for good, kept batch or `attempt` dropped, kept batch refused for good, outbox message given up, outbox record job given up (`RecordJobDropped`) or stopped at a delete it wasn't queued against (`RecordJobStopped`), protocol call whose local writes were over the bound (`LocalWritesRefused`), record write whose mark was over its bound (`RecordUncheckable`), record a view first showed divergent (`RecordDivergent`, in the commit that writes `rcdiv/<key>`, kept after the mark is removed), recovery notice raised or cleared (`RecoveryRequired`, `RecoveryNoticeCleared`), what a restore in place left behind (`RestoreLeftBehind`), restored lists not yet verified or left out of a backup, in the restore's commit and in a provider loss's (`ListsUnverified`), entry waiting for sender standing, a key or admission that was dropped past the shared bounds or failed a recipient check when tried again (`StoredEntryDropped`, with its exact message identity, waiting reason, original observed receipt and stable notice ID, without payload or any claim that another copy/effect is absent), released entry that ran as a duplicate (`ReleasedDuplicate`), or account taken as erased (`AccountGone`, in the commit that writes `gone`, and removed unacknowledged in the commit that takes the account back). Only acknowledgements remove them, apart from that: nothing bounds them for a host that never acknowledges | |
| `dutyn` | the counter the next duty event takes; it only goes up in one store, and a restore in place keeps it | |
| `dutye` | the store's event epoch, random, chosen once when the store starts empty (the first join, or a restore onto a store without one); every duty event ID carries it with its counter | |

Deleting the keys on a leave removes `keys`, `naming`, `rk/`, `scope/`, `parked/`,
`pending/`, `p/` (every protocol's), `duty/`, `owed/` and `told/`, and marks `leave`.

## Extending the schema

- New records take new keys under a prefix of their own; existing keys keep their meaning.
- A changed record type bumps `SCHEMA_VERSION` with a migration that runs on load.
- Protocol state stays under `p/<name>/`, written only through `LocalWrite`.

## Moves, recovery and push

`provider.rs` follows a cooperative move or a key change in place, and keeps that the app
isn't current any more; `recovery.rs` follows a provider loss and keeps the evidence for
uploads; `push.rs` holds the push registration. The peek (`peek.rs`) writes nothing.

| Key | Holds | Sensitive |
|---|---|---|
| `mv` | a move in progress: the signed freeze (none for a key change), the generation left, the step, the re-registration batch signed once | |
| `gens/<generation>` | a generation the app left: its origin and service key, and the last own `identity.json` taken there | |
| `loss` | a provider loss followed: the step, the old newest head, the cursor's time there, the declaration time, the clocks' offset, the new key's `n`, the batch of the current step, the reply grants still to add back, every protocol's merged (at most `MAX_LOSS_REPLY_PEERS`, the first in key order) and how many past it were left out, shown in `RecoveryInfo::reply_peers_left_out`; and the original recipients in registration order and the number of their answers committed. Each answer advances that position with its writes. The last answer ends the step and clears the roster. A protocol added on restore receives no callback for this earlier loss | |
| `loss/list-input`, `loss/lists-pending` | The lost generation, destination, and descriptor of the immutable kept peers and denies. The pending value records the two acknowledged offsets and whether kept peers are owed. Each checked upload advances it in the same commit as the recovery step. A replacement list supplies current admission independently. | |
| `loss/list-remaining`, `loss/list-removed/lc/{kept,deny}/<pubky>` | Membership still recoverable from the original contribution and its individually observed removals. A complete signed list read after the last upload retires this fallback. | |
| `loss/list-observed`, `loss-list-parts/<bank>/<descriptor>/<list>/<page>` | Membership observed at the replacement and carried through restore is retired by its next complete read. The descriptors address bounded raw ID pages. The source, target and content hashes at `loss/list-staging` identify a resumable inactive bank. It becomes visible with the loss commit. | |
| `loss/list-restored` | `()`: the owed contribution came from a backup. When its upload is done, the host is told how many kept peers it sent that nothing verified, and the mark goes in that commit; otherwise a later loss counts its kept peers with no row as unverified. A list read after the upload, a loss and leaving remove it | |
| `loss/list-waits` | the device-clock time the owed list upload was refused for want of deny room. A read doesn't send it again for an hour after it, and `App::follow_provider` always does. It goes when the upload's entries change (an entry left out), when a removal of a deny entry is seen, when a renewed certificate is taken, when the upload is done, at a loss, and when leaving. A backup doesn't carry it, so a restored app tries once more | |
| `loss/list-held/lc/deny/<pubky>` | `()`: the copy's deny row for this peer is there only because the owed list upload carries it, which the new service's list read lacked. Leaving the entry out on a removal the feed shows, or one this app settled at the service, removes the row with the mark. Leaving it out with no removal at the service, as an app with `lists.read` alone does, keeps the row and notes a deny gap (`dgap`): the new service may hold the entry by now, from an upload not read yet or a page whose answer was lost, and the gap's list read keeps or removes the row. The row written again by a read or a write loses the mark. Each complete list read writes the marks again, and leaving removes them. A backup doesn't carry them, so after a restore such a row denies until the next list read | |
| `loss/list-left-out/{kept,deny}/<pubky>` | `()`: a kept peer or deny entry removed, by this app or by another whose change it saw, while a page of the owed list upload not yet accepted carried it; the pages leave it out, so the upload never undoes the removal. A backup carries these with the contribution, and a restore in place refuses a backup that lacks one the store holds. A list read after the upload, a loss and leaving remove them | |
| `loss-lists-finished` | The last generation whose final list submission received a checked answer. An older in-place restore cannot reopen that duty. | |
| `loss/opening` | the verified first identity document chained immediately after the recovery transition, replaced on a new loss and retained on a move | |
| `pending-roster/possible-members`, `pending-roster/removal/<version>` | while the opening is unavailable, the remaining possible original App IDs and the signed documents that first removed them. The opening keeps the documents it links to original members and clears the rest. A new loss clears both | |
| `loss/removed/<app>`, `loss/removal/<version>` | each original app explicitly removed and the signed successor at that version, shared by the apps it removed | |
| `retain-loss-uploads` | the host opted in to keeping the exact inputs of its ordinary loss evidence step | |
| `loss-checkpoint/<protocol>` | the protocol-local cutoff key registered by the host for future inventories. Retiring the protocol removes its registration. Each completed inventory keeps its original digests | |
| `loss-upload/<generation>/<body hash>/<details hash>` | an indexed inventory, the account, app, service key, signed loss generation and opening hash when known, with the checked result for that inventory | |
| `loss-data/<generation>/<hash>/<part>` | exact bytes of the ordinary upload or the record applications and omitted signed entries, indexed while pending and committed before sending; retained across later losses until the host releases this generation | sealed protocol data and signed entries |
| `ev/op/<hash>` | a kept `record.put` or claim entry, with its writer's certificate and its proof when held | |
| `ev/proof/<hash>` | a kept transition proof | |
| `lc/kept/<pubky>`, `lc/deny/<pubky>` | the app's copy of the kept peers and deny list, from the feed. A deny row is empty. A kept row is empty, or the byte 1 when a restore brought it back and nothing has verified it since; any other value reads as the byte 1: such a row doesn't admit, doesn't make a reply grant unneeded, and a cooperative move doesn't keep the peer again from it, while a provider loss still contributes it. A complete list read, a change to the peer's row in the feed or by this app, and a loss rewrite or remove it. A restore installs the backup's rows, marking every kept one, and on a restore in place keeps every deny row the store held. Rows of an earlier `lc/contact/` prefix have no reader: they are ignored, never removed, and a peer kept only there is no longer kept | |
| `lc/code/<hash>` | an invite code this app registered, from the feed | |
| `push` | the push setting: relay, device token, the service it is at, the push key, the handle, whether set, a rotation in flight | the device token |
| `push/devices` | the handles of the app's other devices and the push key they are bound to, from the host's device sync, merged into the handles this device sets | the handles |
| `gone` | the app isn't current any more, or its account is gone, and since when | |
| `display_read` | one original signed GET reserved for the host display transport, with the account, pinned service, generation, cursor and random receipt ID. The foreground holds own work until this installation receives its terminal outcome. The receipt and its service-health decision are released in the same commit. | |
| `service_health` | this installation's verified recovery notice and the first time and count of consecutive unanswered own requests. A qualifying notice and its duty commit together. An in-place restore at this service and generation preserves them. A fresh installation reads the service for itself. | |
| `erasing` | since when every try met an unsigned `404` and no published `identity.json`, the last try counted and how many were | |

- **A move** commits each step: `Seen` (the freeze verified and kept), `Read` (the old feed
  read to its end, its chain view saved), `Uploaded` (the evidence sent to the next
  service), `Switched` (`meta`, the cursor's generation, the chain view and the
  re-registration batch, in one commit), `Registered`; then `mv` goes. The old feed is read
  by its pages' `next`, apart from the verified chain position. Of the batches signed for
  the old generation, `pending/record` and a pending receive key registration go at the
  switch, since the record and the newest key go in the re-registration. A kept
  `pending/effect` or `opq/<batch_id>` whose batch ID the old chain holds was applied: its
  outcome commits at the switch. Otherwise the effect goes, and its entry is read again;
  a kept `opq/` batch is signed again for the new generation, its bytes under a new wire
  batch ID, still kept under the ID it was first kept under. A
  frozen service's `410 moved` keeps them for the switch. A move the app never saw frozen,
  or a key change in place, didn't read the old feed to its end: its kept batches and
  effect stay unchanged and go again first, and the answer decides (original proofs or
  `409 conflict`: applied; `409 stale_generation`: signed again). Past 30 days less the
  clock tolerance from when it was kept, at the switch or at any later resend, or with no
  time kept, `409 stale_generation` decides nothing: a batch goes, reported as dropped,
  and an effect's entry is parked in the commit that drops the effect, never applied
  again, and the protocol is told (`EffectUncertain`).
- **A newer own `identity.json`** that names a later generation, a loss of the generation
  moved from, or another service than the freeze, supersedes a move or a loss at any step,
  a stuck one included: after a step fails at a service the app reads its `identity.json`
  from the Homeserver, gives the change up and follows the newer document.
- **A loss** starts in one commit, before any call: `meta`, a cursor and chain view from the
  start of the new sequence, `lc/lists_at` and `lc/too_large` removed, a fresh receive key with its registration batch, the
  registrations of the old service cleared, the kept writes judged against the old chain
  view as at a move (a kept batch holding an `attempt` goes instead of being signed
  again), `restore.reconcile` on, and `loss`. Each step then commits as done; the
  protocol's re-send writes commit with their step, once. A registration another device
  of the app made first is adopted, and the record then goes alone. A protocol that answers
  the re-send step with an error leaves the loss at that step, to be asked again.
- **`gone`** stops every read; `push` goes with it. It is kept only once the newest verified
  own `identity.json` removes the app or doesn't list it, a `403 not_current` came while it
  lists the app with the certificate the app holds, or the account is erased: an unsigned
  `404` and no published `identity.json` at every try, counted at 5 tries at least 6 hours
  apart by the app's clock, which `erasing` times. Any answer the pinned service key signs, or a
  published `identity.json`, ends `erasing`. An erased account seen alive again, its
  `identity.json` published and listing the app, ends `gone`: its `push` setting is kept,
  no longer set, and the other devices' handles too; an app that isn't current drops both.

## Sending, admission, records and claims

| Key | Holds | Sensitive |
|---|---|---|
| `out/<msg_id>` | a queued message, queued alone, with the answer of the batch that carried it, or again from its stored signed plaintext (`App::queue_stored`, with a replay deadline): its signed plaintext, signed once, the envelope sealed for one try with its `apps_version` and retained content key (checked against its key commitment and exact signed plaintext before use), its jobs (reply grant, delivery, record, the record job with the generation, version and operation item hash of the delete its next write built on when queued, or null if there was none) and where each stands, the last failure's text cut to 512 bytes at a character boundary (and left out of a record the store refuses for its size with it: a failure's text never decides whether the message stays queued), a re-send owed, its `envelope_sent` flag and optional `replay_until_ms` (absent on an untried message queued by this store, committed from the device clock right before the first transport append unless already set by a restore, `App::queue_stored`, or a re-send, cleared when an item with no earlier deadline is accepted in the try that first sent it with every earlier append a verified refusal (`401 stale_timestamp`, `409 stale_key`, `409 identity_needed`), and enforced on every later try; an item with `envelope_sent` set, no `replay_until_ms`, and a delivery still owed is refused as corrupt), when it was refused for good, and when a delivery was first and last answered `403 not_admitted` or `403 not_current`, which of the two the last answer was (`UndeliverableReason`), with the answers counted at least 7.5 days apart; a failed one goes after the sent-message retention, and so does a record job still owed then, from the first acceptance, given up with a `RecordJobDropped` duty event in that commit; an undeliverable one when a try is answered so again 30 days after that first answer and 5 answers were counted, or at the first flush 45 days after it in any case | yes |
| `sent/<msg_id>` | a message the recipient's inbox accepted, written in the commit that records the acceptance, kept 30 days from its first acceptance for re-sends, with the replay deadline of the outbox item it came from unless an item with no earlier deadline was accepted in the try that first sent it with every earlier append a verified refusal (`401 stale_timestamp`, `409 stale_key`, `409 identity_needed`), the earliest of those it was accepted from: a re-send queued from it goes only by that deadline, and is given up past it | yes |
| `outgone/<msg_id>` | a message whose delivery the app gave up, in the commit that gives it up and keeps its give-up duty event, or that a restore left out: `App::queue_stored` and both explicit and provider-loss re-sends refuse it (`WontDeliver::GivenUp` for the public re-send) until the time it holds, 30 days on, and while an outbox item or sent copy still holds its plaintext; removed when pruning after that time once both copies are gone. This keeps a retained record job from recreating its ended delivery or reporting it undelivered again | |
| `outnext` | where flushing the outbox stands, committed after each message's try and at the flush's end: the queue time and `msg_id` of the last message tried, from which the next flush goes on round the queue, so a message that keeps failing holds up none behind it; whether a pass a budget stopped is under way (`open`), and the first message it tried, so the next flush tries only the messages of the pass it hasn't reached. A try a failure or a crash cut short goes again first. The flush that ends the pass, and the deliveries' pass with it (`peers_doc`), says `more` false | |
| `outhold/<pubky>` | a counterparty whose messages the host holds (`App::hold_queued`), until `App::release_queued`: no delivery of a message to it is tried, a first one or a re-send, those a kept batch puts in the outbox once it settles included; a held message's replay deadline still runs, and its record job goes. Carried by a backup; a restore in place also keeps the store's own; deleted on a leave. `App::withdraw_queued` gives those messages up instead, with `outgone/` marks, removing every retained queued copy and its delivery index in the same commit | |
| `outheld/<msg_id>` | a message a protocol holds (`App::hold_message`, its own kinds only), written only while its delivery is owed (in the outbox, not refused for good, or in a kept batch's messages and neither known nor given up), until `App::release_message`: no delivery of it is tried, as for `outhold/`. Its life is the delivery's: deleted in the commit that ends it (the acceptance; a refusal for good; every commit that keeps its give-up duty event: a give-up, a withdrawal, a restore leaving it out past its budget; the drop of the kept batch that would queue it, unless the outbox or another kept batch the commit keeps holds it), and by nothing else, so a message queued again after its delivery ended starts unheld and one queued again while it is owed, by `App::queue_signed` or `App::queue_stored`, stays held. Carried by a backup for a message of its outbox owed a delivery, and a restore refuses a backup whose mark names another; a restore in place also keeps the store's own of the messages the restored outbox owes; deleted on a leave. `App::withdraw_message` gives the message up instead, removing its queued plaintext from every kept batch with its delivery index, while retaining the unrelated operations, local writes and messages; acceptance, permanent refusal and each give-up remove those producers too, before their temporary sent or give-up records can expire | |
| `sentt/<time>/<msg_id>` | the time index for pruning sent messages | |
| `dir/<pubky>` | a counterparty's directory as signed, the switch, generation and `identity.json` version it was read under, its versions, and whether it is read again before the next send; for a directory over the store's value size, only its stub: the switch, generation, versions and read time, no apps, always stale, so each send reads it again and a provider loss since is still found | |
| `rkn/<pubky>/<app_id>` | the highest receive key `n` seen for a counterparty's app | |
| `peer/<pubky>` | the version of the own `identity.json` a counterparty's switch last named, and when the app last wrote there | |
| `peers_doc` | the own `identity.json` the deliveries to recent peers were last judged against, and the counterparties still owed it: those the pass under way hasn't tried first (`untried`, how many), then those whose delivery failed, in the order they failed, so one slow failing switch holds up no other | |
| `lc/r/<base64url pubky>` | a peer's reply membership. Binary: the schema byte, then a tag, 0 for membership alone (an app grant whose first writer isn't known) and nothing after it, 1 for an app's grant followed by its 16-byte App ID, 2 for an invitation's followed by its 32-byte code hash; then the grant's creation time, the time of the observation, never before it, and the last use when known, never before the creation, each a big-endian `u64` of milliseconds. The tag's high bit (`0x80`) marks a row a restore brought back that nothing has verified since, as for a kept row; the backup carries the observation without it. A provider loss clears every row. A backup carries these observations, the kept and denied peers and the signed head of the last complete read when they fit; otherwise it carries the deny entries and their positions alone, or none when those don't fit either, and the restored app reads the lists first. Rows of an earlier `lc/conv/` prefix have no reader: they are ignored, never removed, and the app grants again where a grant is owed | |
| `lc/flag/<pubky>` | a flagged sender in the app's copy of the lists, from `GET /allow` only, which replaces it with `lc/kept/`, `lc/r/`, `lc/deny/` and `lc/code/` in one commit; kept whole, as the answer holds it, bounded by the transport's answer cap and the store's batch size as the other lists are (at most `max_flags`, 1,000, at the default limits), and never cut, since a cut list would read a flagged sender as not flagged | |
| `lc/list_position` | signed head of the last complete list applied to the copy of the lists, including an empty head: a kept, deny or reply change at or before it is covered by that read. A loss clears it; a restore installs the backup's. | |
| `lc/lists_at` | the service time of the `GET /allow` answer the copy of the lists was last replaced from, written in that commit; absent until the first, after a restore, from the commit that starts a provider loss, which keeps `lc/flag/`, from the commit of a renewal that adds `lists.read`, from the commit of every gap noted (`App::note_deny_gap`, `App::allow_list`'s own commit before it replaces the copy) and from the commit that tells a gap without the list; while it is absent the copy isn't known to be complete, and a read by an app with `lists.read` notes a deny list gap at the cursor (`dgap`), outside a move or a loss in progress, and tells it after the owed calls, the copy taken from the same answer: the copy and the protocol are set from one list. `App::allow_list` commits a gap at the cursor first, then replaces the copy, so whatever stops between them the protocol is owed the list | |
| `lc/too_large` | the service time of the last `GET /allow` answer whose lists didn't fit one commit, in a commit of its own; while it is less than `LISTS_TOO_LARGE_RETRY_MS` (a day) old by the highest service time verified, which each read's page moves on, a read doesn't note the gap a copy not known complete owes; a gap owed is still told with the lists read for it, which tries the copy once more; `allow_list()` always fetches them; a refresh that fits, a provider change (the commit that switches the service, or that starts a loss), a restore and a renewal that adds `lists.read` remove it | |
| `invite/<code_hash>` | the code of an invite code the app registered, to show it again | yes |
| `opq/<batch_id>` | a batch of operations, signed and kept before it is sent, under the batch ID it was first kept under, whatever batch ID its body carries once signed again, with what its answer settles and, from its first send on, when that left (`kept_ms`, absent while never sent): the protocol's local writes, kept in base64 as in `pending/effect`, and the signed messages it puts in the outbox; it goes with its answer or a refusal for good, and stays through anything else, except that one never sent that holds an `attempt` goes unsent, reported as dropped with its attempts, when it would be sent while the app may not attempt (reconcile mode, Switch spec 12.4). All of them together take at most `MAX_KEPT_BATCHES_BYTES` (12 MiB), so a provider change carries them in its one commit: `submit_batch` keeps no batch past it, and a record replacement a move or a key change in place would keep with no room left is dropped, of unknown outcome. A record replacement's batch keeps the cursor move its first send carried (`cursor_seq`) | the messages' |
| `opqm/<batch_id>` | the cursor move (`cursor_seq`) of a kept record replacement, written with its `opq/` entry and removed when the batch ends, so the furthest position sent is read without decoding kept batches | |
| `keptn` | the next creation number of a kept batch (`queued_n` in `opq/`, written in the commit that keeps the batch): kept batches go in that order, whether sent before or not, so no write overtakes an earlier one. A write sends at most one kept batch again before its own (`KEPT_RESENDS_PER_WRITE`); with more kept, its own is kept unsent behind them (`Refusal::KeptBatchesAhead`) | |
| `kb/<batch_id>` | the end of a batch kept under `opq/`, written in the commit that applies or drops it: when (app clock), applied or dropped and why (refused for good with its code, dropped never sent, or dropped once sent, uncertain), and the `msg_id`s and attempts it named; `App::kept_batch` answers it until `SENT_RETENTION_MS` (30 days) from that time, and the next `flush_outbox` after forgets it with `kbt/` and the `kbm/` and `kba/` entries still naming it | |
| `kbt/<time>/<batch_id>` | the time index for forgetting those ends | |
| `kbm/<msg_id>` | the batch kept last that queues this message, written in the commit that keeps it: `App::delivery` answers `Kept` while the batch is kept, `Failed` with the drop's time once it is dropped; every delivery completion removes the index with every retained copy of that message | |
| `kba/<claim_key>/<attempt_id>` | the batch kept last that carries this attempt, written in the commit that keeps it, for `App::kept_attempt` | |
| `list_due` | a listing of the collections is owed: after joining, a restore, a `missed` item (one whose times don't parse too), a certificate taken (a renewal, or the listed one from the own record) that reads a collection of the protocol the one before didn't, in the commit that takes it, or an `upload` transition that would mark more records than `MAX_RECORD_MARKS`, in the commit that passes it. While it is owed nothing is handed to the protocol: a read lists before it retries entries stored locally or owed calls, and a read that ends owing one doesn't retry the entries waiting for a key at its end, and an item that owes it mid-read ends the page there, the read listing and then reading on from the item; `missed` items side by side share one listing. A read lists at most once: a later item that owes another ends it, and the next read lists first. A listing that fails ends the read there. It stays while the certificate lacks the key, at the current data epoch, of a scope that reads a collection, even after fetching the key bundle: the read then reads no feed and hands nothing over, reports `ListingWaitsForKey`, asks for the full key bundle again once `KEY_REQUEST_RETRY_MS` (an hour, in memory) has passed since it last asked, and still deletes retired keys, rotates and flushes a due cursor move; the read after the key arrives lists. The `upload` member holds the latest capped upload position, or null. Each page must cover that position at its own sequence in the current service generation before its records, omissions or continuation count. An earlier or unordered page leaves the cursor and duty where they are across reopen. A read asks for at most `LISTING_PAGES_PER_READ` (4) listing pages; a listing that needs more ends the read before any entry, `list_at` keeping how far it got, and the next read goes on from there. It names, per protocol, the listing of that protocol's readable collections that is owed, and the feed item that owes it, (generation, `seq`), or none for one owed outside the feed (a join, a restore, a certificate taken): each protocol once, the earliest item standing, outside the feed before any. One owed outside the feed is made at the start of the next read; one a feed item owes is made for a protocol once its position (`told/<name>`) has reached that item, told through everything before it, and that protocol stays right before the item meanwhile: one in step with the item is listed in the same read, a protocol that fails the item's own call included, as with one protocol; one behind it once it has taken what comes before. A certificate taken at a feed item owes it outside the feed to the protocols in step with the item, and at the item to those behind it. A protocol's listing that waits for a scope key while another protocol can go on doesn't end the read: it takes that protocol's own position as its place, which holds that protocol there even at sequence zero, where no earlier numeric position exists; the listing itself remains a prerequisite in the central order gate. Retained calls remain explicit prerequisites there too, including at zero; listings precede calls at the same item, and a deny list gap waits for every prerequisite through its position. A read fetches missing listing keys once before checking those prerequisites, including when only one protocol waits, so a shared gap never prevents acquiring the key. The full key bundle is asked for again, and the read reports `ListingWaitsForKey` and reads the feed for the others. The commit of a protocol's last page takes its name out and writes its position. `App::listing_owed` reads it, for a protocol to tell that its copy may be incomplete | |
| `told/<name>` | how far protocol `name` has been told, (generation, `seq`): everything the read covered at or before it that was for that protocol (`order.rs`). Absent for a protocol at the cursor, as after a join or a restore. A protocol is told an item only when its position has reached it; one that doesn't take an item, a call it fails or one kept for it, stays right before it, and is told nothing later, while the read goes on for the others. Written in the commit of what moves it: a page's, a kept call's, a listing's, and with `feed_at`. A read's start sets it by what is kept (`App::settle_told`): right before the first call (`owed/`) or listing a feed item owes (`list_due`) that names the protocol, at the cursor or further when none does, so a restore, a provider change and a crash leave it right. A read that stopped on its pages goes on from `feed_at`, or from the position of a protocol behind that with a feed item next, never before the cursor. One that lags behind what was committed only starts the next read further back: what the read meets again is not handled twice (`seen/`, `proc/`, `asked/`, the record's version, a kept call's `to`). A position past the cursor and `chain.read_through` is corrupt. Deleted on a leave with `owed/` | |
| `list_at` | how far an owed listing, or an unfinished `App::list_collections`, got: the reader certificate, generation, collections listed to their end and the last key of the collection being listed, including its policy set when it admits named permanent generations, in the commit of each page it takes; deleted with `list_due`, and in the commit of every new obligation that sets `list_due`, so a listing owed again starts from the beginning: a renewal taken between reads that widens the certificate lists the collections a listing under way had listed to their end | |
| `listc/<collection>` | the reader certificate, generation, last key and applicable policy set reached by an unfinished `App::list_collection`. A newly included permanent generation starts from the beginning. The position is saved with each qualified page; deleted by the call that reaches the collection's end, and by a leave | |
| `record_reader_renewal` | the current service key, generation, listed reader certificate and last feed position searched for its signed renewal while an owner waits for a properly scoped listing. A later search resumes here without advancing the delivery cursor. A restored app obtains the certificate under its own listing obligation. Deleted when the matching renewal is found or the app leaves. | |
| `feed_at` | where a read that its budget stopped went on to (`FEED_PAGES_PER_READ` pages, or `AppConfig::call_budget_ms` once a page or item is processed), or one that stopped for a listing a `missed` item owes (a second one, or a listing past its pages), with the lowest held `seq` of that read: in the commit after the page it stopped on; the next read of the same generation goes on from there instead of the cursor, so the entries held behind the cursor don't take each read's budget again. Deleted by a read that reaches the feed's end, and passed over when the cursor is past it or the generation changed | |
| `rec/<key>` | the shared record write the app took: the signed operation, certificate and proof, its version, signed expected version and whether a verified stub or proof gave its version, the opened value, or why it isn't open: its key not held yet (`Unreadable`, its data epoch read from the operation), or not opening with its key held (`DoesNotOpen`, flagged); the write's application at the service (`applied`, an upload's position for one taken from a recovery upload); and the refused write it follows, or another write a view shows at the held version, with its checked version and signed expected version, application and item hash, matching proof when available, delete status, and whether the refusal names its writer: one refused only for the certificate the service shows or a missing date names nobody and reads as not flagged; the per-key observation position that selected the current application, and whether a read found the delete the next write builds on forgotten (`gone`), so that write creates the record. A value whose key isn't held is opened again from the kept operation when a fetch takes a scope key, and whenever the same write is read again; one that doesn't open with its key isn't tried again; neither is tried at every read; at a permanent policy, the newest generation the app saw the record live in (`live_in`, Switch spec 10.3.1 "Absence") | yes |
| `recp/<key>` | the index of the records at a permanent policy the app holds live, each with its collection's name, written with `rec/<key>`: a listing page reads it, not every held record, to find the permanent records it left out | |
| `reopen` | the records held `Unreadable` are owed a reopening: written in the commit that takes a scope key, which reopens nothing itself. The reopening runs only while no page's writes are open, after each page's commit and at the start and end of a read, so a record a page takes `Unreadable` before an item of the same page brings its key opens too. It commits as a listing does, a commit whenever one more record might not fit, and only the last removes the mark. A reopening that fails keeps the mark, is reported (`ReopeningOwed`) and is made again at the next try, at most `REOPEN_TRIES_PER_READ` (2) tries a read, the rest left to the next read; it doesn't fail the read, which goes on from the store as committed (Switch spec 3.5), but for an alarm it raises, or a failure once one is raised: that ends the read, so nothing is handed over or sent after it | |
| `recname/<key>` | the collection name of a record the app creates outside the protocol's collections, from a write or an effect, until its write is answered | |
| `hw/<key>` | the protocol's mark of what the app has seen in a record, in base64, at most `MAX_SEEN_MARK_BYTES` (64 KiB) before it. A longer one is never kept: an own write whose mark won't fit is refused before it is built; another app's write leaves the mark held as it is and keeps a `RecordUncheckable` duty event; an own write found over the bound once taken deletes the mark held and keeps the same event. The app's own delete leaves the mark held as it is: what the app saw stays seen (Switch spec 8.2), so another app's write that brings the record back without it is checked against it. So the mark of a deleted record is kept with no expiry at every own app, the deleting one included, until a later own write, or another app's write that is taken, replaces it, or a leave clears the store: for a protocol whose mark is the record's whole value, a delete doesn't remove that content from the deleting device, nor from a backup. Every backup carries the marks as stored (`AppBackup::seen_marks`), read in the same moment as the rest, and every restore, onto an empty store or in place, installs them in place of the store's own, as the last writes of its one commit and in whatever room the rest leaves (Switch spec 12.4 "Seen marks"): no size check counts them, and nothing is refused or left out for them. Those that don't fit are left out, largest first, the lowest key on a tie: the backup's check leaves them out and sets `seen_marks_incomplete`, and so does one whose entry doesn't read, which the backup skips; a restore of such a backup, or one that can't fit them all itself, raises `AppEvent::SeenMarksIncomplete` once for each registered protocol; after it, a record without a mark is checked as new. A backup without `seen_marks` and `seen_marks_incomplete` is refused, and so is one with a mark over the bound or a record named twice. A write by this app, from this device or another, is never checked against the mark, also when the feed or a view shows it before its answer, and is marked from the value written; one this device can't read yet, waiting for its scope key, leaves the mark as it is until the record reopens with the key, and is marked from its value then | the protocol's |
| `flag/<key>/<write>` | a write the app refused, by its item hash, which its writer signed: with the version it was last shown at, the app it names and the rule, cut to `MAX_REGRESSION_REASON_BYTES` (256 bytes); the same write shown again replaces its entry, and a record keeps at most eight, the one shown at the lowest version dropped first | |
| `ocert/<app_id>/<cert_hash>` | a certificate of an own app, for checking its writes | |
| `claim/<claim_key>` | the newest claim view, the proof that shows it SETTLED, the newest entry's time and the deadline the app computes, kept until the evidence's retention ends | |
| `clent/<claim_key>/<step>` | a signed claim entry and its proof | |
| `clstub` | the feed showed the stub of an operation since the claims the app follows were last marked: written with the page that passes the stub, by an app with `claims.read`, and removed in the commit that marks them (Switch wire 7.5) | |
| `clread/<claim_key>` | a claim to read again, with the device time it was marked: one the app holds and doesn't hold as finished (SETTLED with every attempt `done` or `failed`), after a stub, or one the app holds that an `upload` transition in the feed lists (Switch wire 7.4.14), by an app with `claims.read`, in the commit that passes the transition, again if already marked, so these marks are bounded by the claims the app holds; read at the end of a read, at most `CLAIM_REREADS_PER_READ` (16) per read, oldest mark first, and removed in the commit of any read of the claim, a `404` included, or when its evidence goes | |
| `rcread/<key>` | a record an `upload` transition in the feed lists, changed or divergent (Switch wire 7.4.14), to read again, with its verified feed position and the device time it was marked, in the commit that passes the transition, again if already marked; read at the end of a read that didn't stop, at most `RECORD_REREADS_PER_READ` (16) per read, oldest mark first, with `GET /records/{key}`, and removed after a covering view of this key, a current hosted absence covering the upload, or a lasting read-scope refusal. An earlier, unordered or wrong-key answer keeps the mark for a later read. A mark stays unread, and takes no place among the 16, while its record's protocol (every protocol, for a record the app can't place) is behind the read, not told through everything it covered (`App::may_tell`): the others' marks are read meanwhile, no read says `more` for it, and it is read at the end of the first read that protocol is level with. At most `MAX_RECORD_MARKS` (1,000) are kept: a transition that would mark past them, counting those held, removes them and sets `list_due` instead, keeping the marks of records the app holds outside the protocol's collections, which the listing doesn't read | |
| `rcdiv/<key>` | the latest view the app read of a record it holds shows `divergent`, judged after the view's write and only for the key asked for: `RecordDivergent`, a duty event, was kept once, in the commit that writes it, and `SharedRecord::divergent` reads it; removed by a view that doesn't, by a newer write taken, the app's own or one from the feed, and in the commit that starts a provider loss. A restore, in place or from a backup, replaces the marks: the listing it owes reads the records again, and a view that still shows a record divergent raises the event again, with a new ID. A restore in place also keeps the unacknowledged ones, so one divergence may come with two IDs. | |
| `clcert/<app_id>` | a writer of kept claim entries whose certificate the app doesn't hold in standing, one the own `identity.json` lists (so at most the app limit), written in the commit that keeps the entry, with the document version it was last looked for at (0 before the first look); at the end of a read that didn't stop, the own directory is read once when a mark is owed a look at the current version, and only certificates that verify with the identity's key and that the document gives a standing are kept; removed once the certificate is held or the document no longer lists the writer, and stamped with the version when the directory didn't show it; a failed read keeps it owed | |
| `clpage/<collection ID>/<after>` | readable membership from one bounded listing page, with its certificate, generation, sequence, next key and each shown write's application. The first page replaces the earlier pages. Omission applies only over this page's key range. | |
| `clwrite/<collection ID>/<key>` | a later feed write, own application or current record observation for this key. A completed feed read combines these observations with the listing that covers each key. An indeterminate member stays visible to the caller. | |

Deleting the keys on a leave also removes `clpage/`, `clwrite/`, `rec/`, `recp/`, `hw/`, `recname/`, `out/`, `sent/`,
`sentt/`, `invite/`, `opq/` and `opqm/`, and the ends of kept batches and their indexes (`kb/`,
`kbt/`, `kbm/`, `kba/`): a left app flushes no outbox, so nothing would prune them after. A restore replaces the namespace, these keys included, but
for the `out/` records and `hw/` marks its backup carries, and sets `list_due`. `rec/`, `clent/` and `claim/` hold the evidence of the shared state that
uploads carry (`App::shared_evidence`).

## What the app owes its protocol: restores and provider changes

### Delivering and retrying a call

Before the first callback, the app saves the call under `owed/` with every registered
protocol in `to`. For an ordinary feed-item callback, `hand_call` also writes
`asked/<seq>` and any listing or held-cursor obligation in that commit. A missed notice about a higher held cursor uses
`owed/<generation>/<seq>/<held>` so separate reports at one position can each complete.

Each owner commits its local writes, its position (`told/<name>`) and its removal from
`to` together. The last owner's commit removes the call. If an owner returns more than
`MAX_STEP_LOCAL_BYTES`, the app saves a `LocalWritesRefused` duty for that owner and
completes its part without applying its writes. An owner that returns an error or cannot
yet take the call stays in `to`. `App::owed_protocol_calls` counts the retained calls.

At the start of a read the app retries eligible calls in feed order. A protocol must
have reached the preceding item and completed listings due at or before the call.
Its later messages and collection writes wait, later calls stay queued, and records
marked by an upload stay in `rcread/`. Other owners can continue. If all owners are
waiting, the page stops. See `App::may_tell` in [order.rs](order.rs).

A resend or missed-entries call behind the cursor runs before those at the cursor,
even if a restored layer previously saw later items. For a call ahead in the current
sequence, the read delivers intervening items to its owners first. It skips the
retained item's original notification and retries the call on a subsequent read. If all
owners finish an ordinary feed item's call before the shared cursor catches up,
`asked/<seq>` prevents a duplicate callback. Synthetic higher-held-cursor notices
leave this marker available for the ordinary item.

### Deny list changes and gaps

A retained deny list change stops the feed for all protocols at its item.
All remaining owners must be ready before the app starts or resumes their callbacks.
Individual owners' local writes can survive a crash. The shared copy in `lc/deny/`
changes in the last owner's commit. If the app has lost `lists.read`, it applies a
verified change to its copy without invoking the callbacks.

If the writer's certificate lookup is temporarily unavailable, `DenyUnverified` keeps
the signed operation with the change. A later read retries the check. A temporary
failure keeps the barrier in place. A change proved invalid is removed and reported
as `DenyListChangeRefused`. If earlier history prevents verification, the app
discards the change. If it still holds `lists.read`, it records a deny list gap
(`dgap`) so owners can use the full list.

A retained change behind the cursor, including one from a sequence a provider loss
ended, could overwrite newer state. The app removes the change. If it still holds
`lists.read`, the same commit records a gap at the cursor. It first checks any
`DenyUnverified` operation as above. A
gap waits for every owner's outstanding work through its position. All owners receive
the same full list in a successful pass. If an owner fails, all receive the gap again.
A verified but unreadable answer gives them `list_read = false`. After a complete pass
the app clears the old baseline and attempts to save the list from the same answer.

### What a backup and restore carry

Once list recovery has finished, both backups carry the original loss window,
the protocol answers already committed and the remaining reply grants.
A pending reply grant batch keeps its signed bytes. After restore the client
asks only the remaining original recipients and submits the remaining reply grants.
A newly registered protocol first participates in the next loss.
The layered backup carries each protocol's local writes beside these answers.
An oversized answer keeps its unacknowledged refusal for that protocol. A restore
in place refuses an older snapshot of the same loss or a pre-loss backup while
answers or reply grants remain outstanding. Once those steps finish, a backup
from the lost generation can follow recovery from its own protocol state.

Both `App::backup` and `App::backup_layered` include outstanding resend and missed-entries
calls in `AppBackup::owed`, keyed by the suffix after `owed/` and with their remaining
owners. A backup omits deny list calls and `dgap`. Every restore with `lists.read`
records a new gap for all registered protocols at the restored cursor. Retained calls
through the cursor run before that gap. Calls ahead wait for their feed items.

Restore installs each protocol's layer, or clears its state if there is no layer.
It keeps valid backed-up calls for the registered owners they still name.

Both backups carry every duty event the protocols haven't acknowledged
(`AppBackup::duties`), with its owners, but the ones of the installation's own standing,
which the restored app learns again from its service: `RecoveryRequired`,
`RecoveryNoticeCleared`, `AccountGone` and a deny list gap's `LocalWritesRefused`.
`StoredEntryDropped` travels with the custody it reports, in the waiting entries. A duty
that doesn't read is counted (`duties_left_behind`). Every restore keeps each carried duty
for the protocols it registers, under a new ID on an empty store, and counts the rest in
`RestoreLeftBehind`. Delivery is at least once: a duty acknowledged after the backup was
taken comes back with each restore of that backup. Every backup is checked as a restore
onto an empty store before it is returned, so each one it hands out installs on a new
device; one whose duties don't fit that commit is refused with `Refusal::DutiesTooLarge`.

An in-place restore also carries the store's unacknowledged duties and retained calls in
the same commit that replaces the namespace.

- A resend present in both snapshots uses the store's value and the union of the
  remaining owners. An owner that answered after backup must answer again if restore
  replaced those writes. A store-only resend or deny list call past the backup cursor
  is owed to every registered protocol.
- A missed notice keeps the authenticated time of the original page, including zero.
  Restore uses the installed layer's progress to decide which owners still need the
  notice. An owner named by the backup gets its backed-up notice. An independently
  retained owner keeps its own time. A higher held cursor can require a new notice.
- An in-place restore preserves the store's duty epoch (`dutye`) and redelivers
  unacknowledged duties (`duty/<id>`) with their existing IDs to their remaining
  registered owners. A duty the backup carries too is kept once, owed to the union of the
  store's and the backup's owners: an owner that acknowledged it after the backup is owed
  it again, as its layer went back to the backup's. The next counter (`dutyn`) is at least the stored counter and one
  past the highest carried duty counter. A wipe or a restore to another empty store
  starts a fresh random epoch at the first counter. `App::ack_events` rejects an ID
  from another epoch without acknowledging any duties.

### Invalid entries and size limits

A read validates the complete retained-call set before invoking callbacks. A bad
position, an invalid call for that position, an empty owner list, an unknown or
repeated owner, or a `DenyUnverified` operation that fails to parse or differs from the stored change
returns `StoreError::Corrupt`. The read leaves the calls in place.

Restore filters owners to its registered roster. It skips malformed retained calls,
calls or duties with no remaining owner, and a deny list call supplied in
`AppBackup::owed`. `RestoreLeftBehind` reports the counts of discarded calls and duties.
An in-place restore can count an ordinary duty whose value cannot be decoded. If
the epoch or counter is damaged, restore keeps readable duties under a new epoch. Retry
a transient store read failure.

If the backup fits the 32 MiB commit limit on its own, built onto an empty store, but
not beside what the store holds of the earlier installation, `Refusal::CarriedTooLarge`
reports how many duties and calls the store would add beyond the backup's own. The rest
of what a restore in place keeps is carried too, and isn't counted (such as deny entries beyond the backup's, recipient and message holds, deletion observations, put-back holds, kept record replacements and a refused certificate),
so both counts can be zero. The store stays intact. Acknowledge duties already handled or let protocols answer
pending calls, then retry. Restoring to an empty store uses only the backup. A backup
that exceeds the limit on its own returns `StoreError::TooLarge`. `App::backup_layered`
checks that the backup itself fits.

### Across provider changes

Moves, key changes and provider loss preserve outstanding duties and calls.
`App::feed_order` orders the current sequence by `seq` even across generations.
Calls from a sequence ended by loss come first, ordered by `(generation, seq)`. The
loss's deny list gap follows them. A call from a generation beyond the newest own
`identity.json` waits until the app follows it.

A resend call identifies the sender and acceptance interval. The counterparty can
answer at the current service. A missed-entries call identifies the original feed
position even after loss. A loss can also request resends that were already pending.
The receiver deduplicates them by `msg_id` (Switch spec 11).
