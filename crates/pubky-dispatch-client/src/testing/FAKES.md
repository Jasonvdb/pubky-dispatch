# What the scripted Dispatch fakes or leaves out

The scripted Dispatch (`dispatch.rs`) applies every batch, submitted with `POST /ops` or
injected with `app_op` and `signer_op`, through the core's rules (Dispatch wire 6.4). Where it
differs from the spec and the service, it is listed here. Tests of these rules belong to the
service.

Where the scripted Dispatch answers an honest flow differently from the service, the list is
`crates/pubky-dispatch-harness/src/allowed.rs`. That crate runs flows of the real signer and
the real app against both, and its tests fail on a difference the list doesn't hold. This
file lists what the scripted Dispatch fakes or leaves out beyond those flows.

## Batches

- **Request authentication** (Dispatch wire 7.1, 7.2): no request signature or
  `Dispatch-Identity` check; the caller is the `Dispatch-App` header as sent, and an app of
  another identity is the `Dispatch-Identity` header as sent. A `Dispatch-Timestamp` more than 5
  minutes from the Dispatch's clock is `401 stale_timestamp`, with `current.server_time` and
  the last stamped time in `Dispatch-Server-Time`, since it commits nothing, as at the
  service; a missing or unparsable
  one isn't refused. An enrollment's timestamp is checked the same way, before the
  enrollment is looked at, and its `401` carries the clock's time in both places. Every other request stamps the clock's time. Answers to own apps and
  the signer carry `Dispatch-Head`, refusals included, but a `401`, the enrollment and the
  erasure. An injected `401` fault is answered as before the lock, with the last stamped
  time and no head; other injected faults with the clock's time and the head. A request an
  `Unreachable` fault stops keeps its body, which the test call `unreached_bodies` returns,
  in order. Each operation's signature is
  verified, and an own app must be current with an unexpired certificate.
- **Injected faults** (`fail_next`) script a network or a service that fails: an error
  answer, a lost answer (the request applied, the caller sees a timeout), a request never
  answered (nothing applied, the caller sees a timeout), a connection that fails (nothing
  sent), or an answer with a member left out. A lost answer or a failed connection can let a
  number of matching requests through first (`LoseAnswerAfter`, `Unanswered`,
  `Unreachable`), so a test
  can pick one request of several to the same path.
- **Rates** (Dispatch wire 6.4 step 7, 9.4): no operation, control, per-caller or
  failed-authentication limits; never `429 rate_limited`.
- **Quotas and per-kind limits** (Dispatch wire 9.3): the claim limits at the core's defaults,
  `max_invite_uses`, the kept peer and reply grant limits, the fixed deny limit on `deny.put`
  and on a recovery upload's deny entries, an invite code's uses and the pending connect
  requests; no inbox or storage quota.
- **Trusted time** (Dispatch wire 7.3, Dispatch spec 10.1): the test clock is trusted and may go
  back; a batch that depends on time is never `503 unavailable`.
- **Proof states** (Dispatch wire 6.5) are built by the Dispatch from each operation and the
  state after it, as the core has no function for that; a claim's is the core's claim
  view.
- **`invite_code.delete`** of a code the Dispatch doesn't hold is `404`; the core has no rule
  for it.
- **Key bundle parts** go as the service drops them, by the core's `parts_to_drop`: at a
  `key_bundle.put` and at the `cursor.set` that passes them, the parts the target's cursor
  has passed and its `keys_through` covers, unless a full-bundle request is in force: from
  the `POST /keys` until the target's cursor has passed the part that completed it, or the
  part that replaced that one, judged at a put as before the part (Dispatch wire 6.2). Where
  `keys_through` starts rises to the height the dropped parts gave. `keys_through` itself is
  the core's (7.4.12), over the parts the cursor passed.
- **A cursor of an earlier generation** is a bare `seq` here, so after `change_key_into` or
  `import_into` the drop, the request's force and `keys_through` compare it as it is. The
  service counts such a cursor as 0 until the app moves it: nothing drops, a request stays
  in force, and `keys_through` reads low.

## State and retention

- **Durability** (Dispatch spec 6.5): everything is in memory, answered at once, so a commit
  and the mark's move never fail apart: the `503 unavailable` of a mark that didn't move,
  and its retry, aren't modelled. Per-account order is a mutex.
- **One service key** (Dispatch wire 7.1): every answer, the account's and those it can't tie
  to an account (the `404` of an identity it doesn't host, an enrollment's errors), is
  signed with the Dispatch's one key, the key made from `service_secret`. A key change in place (`change_key_into`) is a Dispatch of its own under the
  new key, where the service keeps each mark's key until a start names the new one.
- **Accounts and marks** (Dispatch wire 7.3, Tables 1 to 3), in `dispatch/marks.rs`: the
  account's mark (generation, `seq`, chain hash, count, tag, key, creation time), its retired
  generations and its erasure's record lie apart from its state and survive an erasure, a
  lost account and a start afresh. An enrollment that creates the account writes (0, 0)
  first, or takes over a (0, 0) mark or a lost account's mark, its count 0 and its tag the
  zero tag; a Dispatch made with `new`, `with_generation`, `recovering` or `import_into`
  starts with its mark at its state. The Dispatch keeps its own count of changed state, as the
  service's (wire 7.3, "The state"): one more at each `seq` it gives out, at each cursor
  move, at each push registration and at each new peer copy (`PUT /peers`), the changes it
  models; it counts no other write. Each move takes a tag no other move took, a number
  where the service's is random. Within the account lifetime, a lower count is `behind`.
  A higher or equal count needs the tag
  retained at the marked count. A missing or different tag gives `fork`. A mark that records no head, only a count,
  is compared by its count alone, and an identity without an account whose mark records
  either is lost. The mark moves to the state, count and tag after each request whose
  account is healthy, never while it is behind or a fork, only forward (a later
  generation, or neither the head's `seq` nor the count lower), at a serving account
  before its first chain item to its generation with `seq` 0 once the count has moved, and
  to an injected batch's; a delivery that starts a generation writes it at the new first
  head. Step 2
  judges the two before anything else, a stale timestamp and an own app's first-call `403`
  included: the notice, `503 recovery_required` with `current { generation, reason,
  permanent }`; the `404 not_found` with `current: { "hosted": false }`; and `503
  unavailable` while the store can't be read; each with no head. The notice and the
  not-hosted answer carry the clock's time; the unavailable answer carries the last
  stamped time where the account is held, otherwise the clock's time (wire 7.1). The
  test controls: `restore_to` (the state, and its count and tag, as they were when a `seq`
  was given out, behind the mark), `fork_mark`, `lose_mark`,
  `corrupt_mark`, `set_mark_store_unreadable`, `lose_account` (the mark without the account)
  and `retire`; `mark` and `erasure_record` read them. `roll_back_to` moves the mark back
  with the chain, a faulty service that signs behind its heads. Left out:
  - Table 1's first row: nothing brings an erased account back;
  - the moves of Table 2 but `POST /recovery/upload`, which goes through only where the
    account is bounded: this Dispatch has no import, activation, abort or export calls, so an
    activation's `409 conflict` and an abort that goes through at a failing account aren't
    shown;
  - a failed mark move (above), the instance lock's freshness, and the leftover sweep at
    start: a leftover mark goes at the next request for the identity;
  - the creation time of an account enrolled right after an erasure is a millisecond past
    the erasure's record where the clock hasn't moved, so the record never covers it;
  - Table 1 is judged by this Dispatch's own copy of the rule, the generation a retirement is
    of included, not by the service's account model.
  - the time floor (wire 7.3, "Time base"): the Dispatch has no restarts, so its controls
    leave its service time as it is, where the service, run again after a restore, stamps
    the mark's floor first. A reservation runs up to one minute past the time the service
    selected for a request, even if the request failed before committing its stamp.
- **Waiting reads** (Dispatch wire 7.4.4). Use `holding_transport` to test a
  pending feed read. The ordinary `transport` returns immediately. Advancing
  the fake clock does not wake a reader. Send a request or call
  `release_held_reads` to let it observe the time. The service wakes its own
  readers when their wait expires.

  Each read waits independently, including simultaneous reads by one app.
  The fake releases its lock during the wait. A request answered through
  `holding_transport` normally wakes all held reads before returning. A read with nothing to return waits
  again. To test whether a particular change wakes a reader (a chained item,
  `start_afresh` or erasure), keep unrelated requests away. Any one of them
  could supply the missing wake. `held_reads` counts reads still waiting
  since they last checked.

  As on the service, `wait` must be an integer from 0 to 25 or the request
  gets `400`. Only a current app on a serving account can wait. Admission
  updates the app's last-seen state and ends lagging when the request arrives.
  When the read wakes, revocation or departure returns `403 not_current`;
  erasure returns `404` (wire 7.4.16). In tests, `recover_in_place` uses
  `PUT /identity` to start a new generation. Its account has no record of the
  old app, so the waiting read gets a headless `403 not_current`.

  The fake checks for available items, erasure, a generation change and
  elapsed time when a held read looks again. It reports an intervening
  account failure when it answers the held read. It checks certificate expiry at answer
  time. The service checks at the account's next commit. The fake also
  applies injected faults and the stale-timestamp check at answer time.
- **Retention and sweeps** (Dispatch wire 9.1, 7.4.4): an entry goes once every current
  target that isn't lagging has passed it, as at the service, judged at cursor moves, at
  appends and at deliveries, revocations and leaves (`keep_passed_entries` turns that off
  for a test that reads an entry again); entries never expire by time. An app whose unread
  entries pass its share of the inbox quota (`set_inbox_quota`, 64 MiB unless set) is
  marked lagging while another current app reads, the mark ending at its feed read or its
  departure, and it gets a `missed` item for what goes unread, replaced while unpassed; an
  entry left with no current target at a delivery, revocation or leave becomes an
  `unreadable` item with the entry's `entry_id`. The quota refuses nothing here: no append
  is `429 quota_exceeded`, so a full inbox with no app reading, where the service refuses
  senders, isn't shown. Marks are judged at every such request, the Dispatch's clock being
  trusted. A scripted `missed` item (`push_missed`, or `push_missed_unparsable` for one whose times don't parse) is shown to every app and a scripted
  `unreadable` item (`push_unreadable`) has an `entry_id` of its own, and both stay
  whatever the cursors. Chain retention follows the service's rule by default (`Retention`,
  Dispatch wire 7.4.4, 9.1): outside a freeze and on a serving account, it signs a checkpoint
  once `checkpoint_behind` chain items may go and drops the stubs behind it that every
  current app's cursor has passed or that are `cursor_hold_ms` old, never inside a batch
  (ended by its envelopes' `count`), never the head, and at most `per_request` at a time,
  counting the stubs that may go before the batch edge, from the latest checkpoint. As at
  the service, an app `identity.json` lists that isn't registered here yet holds nothing, a
  registered one that hasn't moved its cursor yet holds every stub, and feed pages carry
  the latest checkpoint. It differs in three ways:
  - it sweeps at each request of an own app or the signer, where the service sweeps at
    every verified caller's, an app of another identity's included;
  - its current apps (`current_app_ids`) are those whose held certificate, or a renewal of
    it still open, is the one listed, where the service counts every listed App ID that
    isn't revoked or departed; so after a renewal an app hasn't taken and that has closed,
    it drops stubs the service keeps for that app;
  - it has no trusted-time gate and no key mark, so nothing holds its sweep back for them.
  Retention is on by default, for every test: none reaches 1,000 chain items unless it
  means to. `set_retention(None)` keeps every stub, and a test may still script a
  checkpoint and the stubs dropped by hand. The harness comparison is what shows the two
  agree;
  claims are deleted only when `GET /claims` finds them deletable; batch records are never
  dropped, where the service drops one once its proofs and its stubs are gone, and their
  proofs go only when a retry finds them past `batch_proofs_ms`, which answers it `409
  conflict` as the service's sweep does.
- **Purge of removed apps** (Dispatch wire 9.1), in `dispatch/retention.rs` `purge_removed`, by
  the service's rule and at the service's requests: a revoked or departed app, or an App ID
  an enrollment named, that the newest `identity.json` lists in neither `apps` nor
  `removed`, whose departure's rotation is done and that owns no attempt open or `unknown`,
  is purged at the delivery that leaves it out, at its revocation, and at the batch or
  recovery upload that resolves the last such attempt it owned (and at the test call
  `fail_attempt` that does). Its record, certificates, receive keys, cursor, last-seen
  time, lagging mark, full-bundle request, key bundle parts and listing go; what stays for
  good is its App ID, its revocation or departure time and rotation, and its kids (Dispatch
  spec 3.6), so no app registers one of them again and an envelope wrapped to one gets
  `409 stale_key` naming the app in `not_current`, as before the purge. `GET /apps` shows it
  as the service does, with no unread entries. Unlike a move by the spec (Dispatch wire 9.1,
  10.3), `import_into` copies the kept kids to the next Dispatch.
- **Forgotten deleted keys** (Dispatch spec 10.3, wire 9.1), as at the service: a record
  whose current write is its delete, written here and not taken from a recovery upload,
  goes once the cursor of every app the held `identity.json` lists, neither revoked nor
  departed, is at or past it, lagging or not, an app with no cursor here holding every key;
  a key a divergent upload names stays, and with no document held nothing goes. Its read
  is then `404`, its delete shows as its stub and a create at it starts afresh; a
  `record_version` condition of `{0, 0}` matches it, and only then: while the delete is
  held, a write or condition names the delete's version, by the one rule of the core
  (`version_holds`) the service applies too. It has no record quota, so a create at the key
  limit is `409` here where the service may answer `429` first. Unlike
  the service: it forgets only at a cursor move, so a revocation alone frees nothing until
  the next one, not at the minute's sweep, and every such key at once, not 256 a minute;
  its cursors are `seq`s with no generation; the frozen account's exception has nothing to
  check (no freeze is served here either). The harness flows `records, a deleted key
  forgotten` and `invite code, spent and expired codes swept` look a step after what frees
  a key or spends a code, where both Dispatches have swept.
- **Superseded documents** (Dispatch wire 7.5): unlike the service, which deletes a chain
  item's document and proof once no app may read it in full, the Dispatch keeps every
  document and decides at each read which show (`Readers`). Every answer is the same, since
  a superseded document shows as its stub to every app; only a test that looks inside the
  Dispatch's items could tell. The harness flow `records, superseded writes read late` reads
  replaced writes at both Dispatches from cursors that stand before them.
- **Invite codes**: a revoked app's codes aren't withdrawn (Dispatch wire 7.4.3 "After a
  revocation"); a code planted for a faulty export never expires. Codes that expired or
  ran out go at the first request a minute of the Dispatch's clock after the last sweep,
  or at once when the clock is behind that sweep's mark, as at the service; until then `invite_uses_left` still shows a spent code at 0. Unlike
  the service, any request sweeps, a signer's or a caller's that doesn't verify included,
  and none waits for trusted time, the Dispatch's clock being trusted.
- **Lists**: `flagged` is always empty.
- **Connect requests** (Dispatch wire 7.4.7), in `dispatch/inbox.rs` `connect` and
  `dispatch/shared.rs`: as at the service (`crates/pubky-dispatch/src/service/connect.rs`), in its
  order: `503 staged` while admission is staged, whatever the policy; `403 not_admitted` with
  the policy off; check 5 by the sender's certificate: the copy lists the app with it, or
  a renewal of it still open, a closed renewal being `403 not_current`, and otherwise `409
  identity_needed` naming the held version, or none when the copy lists the app as
  removed; a sender already pending answered `pending`; the policy's `max_pending`, capped at the
  wire's default `max_connect_pending` (1,000), refusing a new sender `429 quota_exceeded`
  before the deny list; a denied sender answered `pending`, its request not kept. `GET
  /connect` needs `lists.read`, `DELETE /connect/{pubky}` `reply.add`, and an own app's
  or the signer's `POST /connect` is `403 permission_missing`. A kept peer, a reply grant
  entry or a deny list entry for the sender answers its request, the entry an invite code's
  first append writes and the entries a recovery upload's list merge writes included. Unlike the service: no `connect_per_min` or
  `stranger_per_min` (no rates, above), and no flag hits; and it reads `Dispatch-Cert` at
  check 5, after the staged and policy checks, answering a bad one `400`, where the service
  checks it before the account's lock (`400`, or `401` for a certificate that doesn't
  verify), so a staged or policy-off answer can come first here. A sender the allowlist admits is
  answered `pending` with nothing kept, as at the service. When `policy.connect_requests.push` is on,
  the service queues webhooks for registered apps that can read the list. The scripted Dispatch models registration only.
- **Records**: `divergent` is set by divergent uploads after a provider loss and cleared
  by a write here, as at the service (Recovery uploads, below). `make_divergent`, public,
  sets it for one record the Dispatch holds, without a loss or an upload (a key it holds no
  record at is refused, as a service fills such a key): the upload's `doc_hash` is kept among
  the record's divergent uploads, and an `upload` transition listing the key as divergent,
  merging nothing, is chained, so an app reading its feed reads the record again; for a
  protocol's tests of a divergent record.
- **Directory** (Dispatch wire 7.4.10): an app is reachable from its first receive key until
  it is revoked or leaves; one that stops being current otherwise, with an expired or
  closed certificate, stays reachable, and `apps_version` doesn't move for it.

## Other calls

- **Refusals as received** (Dispatch wire 7.1), as at the service and before any fault: a body
  over its call's cap is `413 too_large` over the empty body field, and a signed request
  header sent more than once, but at the public read, is `400 bad_request`, both signed with
  the service key, without a head. No flow reaches them, since the client never sends
  either; a scripted-dispatch test sends them by hand.
- **Queries** are read as the service reads them (`crates/pubky-dispatch/src/http/route.rs`,
  `parse_query`; Dispatch wire 7.1): names and values percent-decoded, and a bad escape or a
  parameter given twice `400` before the endpoint's checks, at `GET /feed` (after the
  signer's refusal, as at the service), `POST /inbox` (before the retry by content) and
  `GET /records`, and at the peer Dispatch's `POST /inbox`. The feed's `limit` (0 to 500; 0 shows no item, covers no position, ends no lagging mark, and refuses `wait`) and
  `wait` (at most 25) and the inbox's `apps_version` are digits only. A feed page scans
  every item to the end unless a test bounds the items or batches it scans
  (`max_page_scan`), which gives pages of items the reader isn't shown, with `more`.
  Each page carries `cursor`, the `seq` of the reader's own cursor, 0 before its first
  move, as the service's does (Dispatch spec 8.3, wire 7.4.4); `set_held_cursor` sets an app's
  cursor, as another instance of the app moving it would.
- **Injected entries**: `send` and `send_envelope` add entries without admission, quotas,
  size buckets or `409 stale_key`; entry IDs are made up from the `seq`.
- **`POST /inbox`** (Dispatch wire 7.4.3), in `dispatch/inbox.rs`, from apps of other
  identities and own apps:
  - the sender's `Dispatch-Cert` is verified against its identity, but its expiry and the
    sender identity's service time aren't checked (Dispatch wire 7.2 checks 3 and 4);
  - an app whose renewal has closed gets `409 identity_needed`, never `403 not_current`;
    an app the peer copy lists as removed isn't answered like a stranger before
    admission, only refused with `409 identity_needed`;
  - no size check (step 3), rate limits (step 4) or quotas and sender shares (step 6);
    only the envelope's header is parsed;
  - an own app's append uses its record's certificate, and isn't checked for being
    current;
  - retries by content are answered for as long as the Dispatch lives, and `import_into`
    doesn't carry the stored answers, so a retry after a move appends again.
- **`PUT /peers`** (Dispatch wire 7.4.5) keeps every copy it takes: no peer limit, but for
  `forget_peer_copy`.
- **`GET /records/{key}` and `GET /records`** (Dispatch wire 7.4.9), in `dispatch/shared.rs`:
  as at the service (`crates/pubky-dispatch/src/service/records.rs`): a list's query is
  percent-decoded, and a parameter given twice is `400`, before the caller is judged; only
  own apps read (the signer gets `403 permission_missing`); a key, `collection` (required)
  and `after` must be `b64(32)`, and `limit` digits from 1 to 1000 (`400`); a record by key
  needs its `read_scope` (`403 permission_missing`, with the head), and a list shows only
  the records whose `read_scope` the reader holds, by the certificate the Dispatch checks the
  app against. An own app it holds no record for meets the first-call refusal below, as
  at the service, before its query or key is read. Order by the key text, `after`
  as a key's text, `next`, the byte budget with its first view shown, deleted records shown
  by key and left out of lists, and a view's `cert`, the certificate the write was checked
  against, kept with the record whatever a renewal or revocation later changes, are the
  service's.
- **`GET /claims/{claim_key}`** (Dispatch wire 7.4.8), in `dispatch/shared.rs`: only an own app
  holding `claims.read`, checked before the key, as at the service
  (`crates/pubky-dispatch/src/service/claims.rs`); then a key that isn't `b64(32)` is `400`.
- **Calls of an app of another identity it doesn't make** (`dispatch/inbox.rs`), as at the
  service (`crates/pubky-dispatch/src/service/rules.rs`, `other_app_refusal`; Dispatch wire
  7.4, 7.6): `403 permission_missing` at the reads only own apps make (`GET /feed`, `GET
  /claims/{claim_key}`, `GET /allow`, `GET /records/{key}`, `GET /records`), the key bundle
  calls, a leave, the hand-over and the signer's calls (`PUT /identity`, revoke, `GET
  /apps`, `POST /recovery/admission`, `POST /erase`) and every other call of Dispatch wire 7.4,
  a recovery upload, push, the connect reads and the move's included; a batch `403
  not_admitted`; and a route that isn't one `404`.
- **`409 identity_needed`** to an app of another identity carries `known_version` beside
  `current`, `null` for no copy held or as to a stranger (Dispatch wire 7.1, 7.6), at the
  inbox, here and at the peer Dispatch (`peer.rs`). Both also serve `POST /connect` and
  answer it so.
- **`open_admission`** (`admit_everyone`) admits every sender the deny list doesn't hold, a
  test Dispatch only.
- **An own app's first call** (Dispatch wire 7.1 "`Dispatch-Head` on refusals", 7.2), as at
  the service (`crates/pubky-dispatch/src/service/batch/mod.rs`, `verify_own_app`): an own
  app the Dispatch holds no record for, at any call but a `POST /ops` whose batch carries its
  `app.put` or doesn't parse, gets `403 not_current`
  at authentication, before the account's lock and before a staged or frozen account's
  answer (Dispatch wire 7.3 steps 5 to 8), whatever the route: no `Dispatch-Head`,
  `Dispatch-Server-Time` the last time stamped, and the app not seen. A revoked or departed
  app that delivered its record keeps it, so it goes on to the route's checks, as at the
  service, until it is purged (Purge of removed apps, above): then it meets the first
  call's refusal, without the head, as at the service.
- **App currency outside batches**: a feed read is checked as a batch is, for an app that
  delivered its record: current, with an unexpired certificate, the stored renewed one once
  the newest `identity.json` lists it (Dispatch wire 7.2, 3.8). Other routes check only that
  the app hasn't departed. The key bundle routes (`GET` and `POST /apps/{app_id}/keys`)
  answer `403 not_current` to an app that isn't current by its record, as the service does,
  and keep nothing for it; they don't check the certificate's expiry (the service answers
  `403 cert_expired`), take any body, and answer `404` ("no route") for another app's path or
  the signer, where the service answers `403 permission_missing` (Dispatch wire 7.4.11).
- **`POST /v1/enroll`** (Dispatch wire 3.7, 7.4.1), in `dispatch/signer.rs`: at the Dispatch's
  origin, [`DISPATCH_ORIGIN`] unless it was made with `unenrolled_at`, with the default limits
  unless a test sets others (`set_enroll_limits`), and without checking the request
  signature. A Dispatch made with `unenrolled` or `unenrolled_at` answers every other call
  with the `404` of an identity it doesn't host until then. As at the service, the
  enrollment that makes the account writes its mark first (above) and sets its kept App
  IDs, every enrollment's answer names the one key, and every later one changes nothing.
  As at the service, the same enrollment again gets its kept answer first, with no other
  effect. At a serving account, as at the service, the App IDs a new enrollment names are
  held for the next generation, whose start refuses a document listing one and then keeps
  them. Unlike the service, an enrollment's `identity_doc` isn't held, so the account starts
  with no document and at the Dispatch's own generation, whatever the enrollment names. Its
  errors, injected ones included, are signed with the one key, as at the service.
- **`PUT /identity`** (Dispatch wire 3.3, 7.4.2), in `dispatch/signer.rs`: judged by the core's
  `check_delivery`, like the service, with the kept proofs taken from what it holds: each held
  record's current write proof and each live claim's entry proofs, by the generation each
  names, with the key of that generation (its own, or the earlier service's that
  `import_into` carried). A first document carrying `recovery_from` starts the recovery as
  at the service: the account takes its generation, and its chain starts with the `recovery`
  transition, unless the Dispatch was made `recovering`, which chained it already. The next
  generation naming this Dispatch's key with `recovery_from` is a provider loss in place,
  refused with `400` when it lists an App ID held for that generation, and so is the start
  above both the held document's and the mark's generation that a failing or bounded
  account takes, exempt from the compare-and-swap but at a higher version than the one held
  (`409 stale_identity` with that copy otherwise): the account starts afresh, keeping its
  creation time, its mark store, its service time, its enrollments and the App IDs
  to refuse, those held for the generation among them, and, as the service does, its upload
  limits, its hourly upload counts, the directory's `apps_version` and
  `directory_version`, which go on counting, and what a test set of its configuration (the
  feed's page limits, kept passed entries, open admission). A key change in place, without
  `recovery_from`, is answered `400`, as at the service, whose one key it can't change to.
  Unlike the service: and a staged account's generation
  change, a move's, is chained where the service answers `503`. The test call `deliver_identity` takes any document, without those
  checks, for scripting what another signer or a faulty service did. `forget_delivery_proof`
  makes a retry answer with no proof.
- **Staged admission** (Dispatch spec 12.6 step 2, wire 7.4.14), in `dispatch/signer.rs` and
  `dispatch/inbox.rs`: as at the service, staged at a recovery whose first document lists an
  app; while it lasts, a sender not otherwise admitted, a stranger asking to connect
  included, gets `503 staged` at `PUT /peers`, at the inbox and at the directory;
  `POST /recovery/admission` ends it with the `admission` transition's proof, answers no
  proof when it isn't staged, and `404` without a recovery. Unlike the service: a Dispatch
  made `recovering` doesn't stage admission. An upload carrying kept peers from an app holding
  `lists.manage` ends it, as at the service.
- **Recovery uploads after a provider loss** (Dispatch wire 7.4.14), in `dispatch.rs`
  `loss_upload` and `dispatch/shared.rs` `merge_upload`: the core's checks
  (`UploadBody::parse`, `check_permissions`, `check_upload`) and merge
  (`merge_checked_record`, `merge_upload_claim`), as at the service, so the counts and the
  changes are the service's, one `upload` transition each; `uploads_per_app_per_hour`
  (`429 rate_limited` until the next hour of the Dispatch's clock; every upload from an app
  the Dispatch holds a record for takes a slot, one refused for its body or its lists, as
  `not_current`, or with `404` at an account in neither stage included, and the refusals
  keep the wire's order past the limit; the `429` repeats `retry_after` in `Retry-After`, as every `429` of this Dispatch
  does), `max_kept_peers` (entries past it dropped; the wire's default unless a test sets it) and the
  fixed deny limit (`400` for an upload carrying more distinct entries than it, `429
  quota_exceeded` with `over` for one that doesn't fit, refused whole) as at the service; and `404` at an
  account in neither stage. Unlike the service: `max_divergent_uploads` and
  `max_attempts_per_claim` are the wire's defaults, and `GET /claims` lists whatever entries
  the Dispatch kept, with no check that a claim holds one at each step.
  For tests of what an app does with an `upload` transition, `chain_upload` chains one
  listing the changes as written, merging nothing: the test makes the merge itself, or none.
- **`GET /apps`** (Dispatch wire 7.4.12), in `dispatch/signer.rs`: by the service's rules, member
  by member, but `last_seen` and `recovery` (below):
  - every app the Dispatch holds, every App ID it keeps for good, and every app the newest
    document lists. An App ID an enrollment named shows `revoked_at` at the enrollment's time;
  - `current` in spec 3.4's sense, as the service reports it, once the app has a record: listed with its certificate, or
    renewed and open, and never once revoked, departed or kept. Expiry isn't part of it:
    `cert_expires_at` carries that, and a signer that serves an app checks both. An app with
    no record is current while it is listed and not kept;
  - `last_seen`: the time of the app's latest request past authentication, a staged
    account's refusal and its `leave` included. The scripted Dispatch doesn't authenticate an own app's
    requests one by one: it takes any app with a record that isn't revoked, departed or kept
    as authenticated. So, unlike the service, it counts an app whose certificate expired or
    isn't listed, which the service refuses at authentication (`cert_expired`,
    `not_current`) before recording anything, and it counts any scripted error other than a
    `401`;
  - `revoked_at`, `departed_at`, and `awaiting_rotation` for a departure until a delivered
    version removes it at a higher data epoch. That stays done after a purge, which keeps
    these three and clears the rest, as at the service (Purge of removed apps, above);
  - `open_attempts`: the attempts the app owns that are open or `unknown`;
  - `record_cert`, `record_at`, `full_bundle_requested`, `bundle_ranges` and
    `cert_expires_at`;
  - `keys_through` by the core's rule, counting only the stored parts the app's cursor has
    passed. It starts at the epoch of the first version that listed the app, kept only for an
    app with no row and no stored part then, as the service keeps it; otherwise the start is
    unknown, and only parts from epoch 1 count. A row is an entry in the Dispatch's apps, which
    an `app.put`, a revocation, a departure, a `cert.put` and some test calls create;
  - the account's `identity`, `recovery` as the spec's object (`declared_at` its recovery
    record's time, `admission_staged` as below), as the service sends it, and
    `proof_generations` from the same kept proofs as the delivery, the member left out when
    there are none.

  `unread_entries`, `sole_target_unread` and `lagging` are counted and set as at the
  service (Retention and sweeps, above). The test call `forget_bundle_parts` scripts a
  faulty service that lost an app's stored parts.
- **Moves and recovery** (Dispatch spec 12.5, 12.6, Dispatch wire 10): `import_into` copies the
  account in memory, with no manifest, chunks or export transfer, to serve at the origin the
  freeze names (`import_into_at` names one for a move a test scripts without a freeze); a recovery upload at a staged
  service or after a move is kept and answered with fixed changes, merging nothing.
- **Revocation** is `POST /apps/{app_id}/revoke` from the signer, and the test call
  `revoke`; an app that left is answered as one revoked already, with no proof. `leave` is a
  test call and also a route, `POST /apps/{app_id}/leave`, which checks only that the app
  hasn't departed: it takes any body, departs an app with no record or one whose certificate
  has expired or isn't listed, keeps the app's invite codes, drops its push registration, and
  stamps the test clock's time. The service refuses another app's path and the
  signer with `403 permission_missing`, where this Dispatch answers `404` (Dispatch wire
  7.4.12). `request_full_bundle` is a test call for the app's own
  route, and `forget_removal_time`
  scripts a faulty service that shows no time for a removal. Freeze and
  unfreeze are test calls, not routes.
- **`lose_identity`** scripts a faulty service that lost the account's `identity.json`.
- **The signer hand-over** (Dispatch wire 7.4.17), without the 12 MiB body cap of `PUT /handover`: `PUT /handover` runs the core's checks of a
  stored hand-over (`SignerHandover::check_stored`) for a current target with a checked
  certificate, and keeps one, replacing any it held; `GET /handover` serves it to the signer
  and to its target, also when that target isn't current, where the service answers `403
  not_current` (Dispatch wire 7.2): so a test can script a faulty Dispatch that serves a
  hand-over while holding no copy of the version handed over; the next `identity.json`
  version, whoever delivered it, drops it. Unlike the service, it serves the body it parsed
  again as JSON, not the bytes the signer sent; it answers an own app's `PUT` `404` ("no
  route") where the service answers `403 permission_missing` with the head.
  `stored_handover` names the target held; `stored_handover_body` and
  `store_handover_again` script a hand-over stored or served again after it was dropped.
- **`Fault::LeaveOut`** scripts a faulty service whose answer to an own app or the signer
  leaves out a top-level member, such as a feed page's `items`; **`Fault::Replace`** one
  whose answer carries another value for it, such as `GET /apps`' `identity` replaced by a
  copy that doesn't verify; **`Fault::SignWith`** one that applies the request and signs
  its answer with another key, such as a third key; **`Fault::ErrorSignedWith`** an
  error answer under another key, applying nothing; **`Fault::Head`** one that applies the
  request and signs its answer with an earlier head, a forked one, or none.
- **Erasure** (Dispatch wire 7.4.16), in `dispatch/signer.rs`: `POST /erase` is `401
  stale_timestamp` for a timestamp more than five minutes from the Dispatch's time base;
  then it checks the body's `created` names the account's creation time and
  `identity_hash` names the newest `identity.json` this Dispatch holds, left out only where
  it holds none (`409 conflict` otherwise, carrying `current.created` and, at an account
  that answers the notice, `current.identity`, the copy held).
  It refuses during a move (`409 conflict`): at a frozen account that doesn't fail stop,
  since this Dispatch keeps no export to tell whether it was fetched, and at a staged one
  holding an import that can still be aborted (not one staged for a key change in place).
  At a failing or bounded staged account, an import still bars erasure when its mark is
  missing or corrupt, or its generation is at or below the imported generation, even if
  retired. A mark above that generation rules the abort out and permits erasure. Other
  accounts that fail stop or are bounded permit erasure, as does a lost identity whatever
  hash it names. An app's call is `403 permission_missing`. The completed erasure record,
  account deletion and mark deletion are atomic under the Dispatch's mutex, and every call, the retry included, gets the `404` of an
  identity the Dispatch doesn't host, signed with the one key. `erased` tells a test it
  happened. App tests set `not_hosted_unpinned` to answer every call with that `404` under
  another key, the `404` an app can't check. After an erasure `POST /v1/enroll` makes a new
  account under the same key with a new (0, 0) mark; nothing of the erased account stays,
  its kept App IDs included, which the new enrollment names again. That account serves from
  its first `identity.json`, at the next generation with `recovery_from` (Dispatch wire
  7.4.16), which starts its recovery.
  `fail_next_erasure` retains an unresolved attempt with the account present or absent,
  or a committed/rejected outcome whose cleanup has not run. Unresolved reads are headless
  `503 unavailable`; an authenticated retry repeats the creation/document checks and may
  complete the erasure. Committed evidence publishes completion before not-hosted answers;
  rejected evidence withdraws the attempt. The pending retry checks the request's identity
  signature in addition to its timestamp and caller. The harness runs these observable
  outcomes and signer restarts against both models. This model has no physical PostgreSQL
  COMMIT or filesystem directory-sync boundary; those failures, exact outcome receipt
  binding, and crash/reload/database-restore ordering are exercised by the service's tests.
- **Push** (Dispatch wire 8.1). The fake models registration only. It neither
  queues nor sends webhooks for notifying entries or connect requests. Apps
  read the feed on both backends. Test relay delivery on the service
  (wire 7.4.7 and 8.2).

  The fake accepts registrations regardless of `push.enabled` and skips DNS
  resolution. A hostname that resolves to a private address can pass.
  `mint` derives push keys from a counter and the service key. There is no
  separate key store or deletion sweep. A frozen fake account returns
  `410 moved`. The current service does not freeze accounts.

  Both use `parse_push_body` and the wire 8.1 registration rules, including
  `400` for an invalid body or more than eight handles at one relay host across
  an account's apps, `403 permission_missing` for the signer,
  `403 not_current` for a noncurrent app, `503 staged` for a staged account
  and `409 conflict` for conflicting start or handle changes. Each app has
  one registration. Removal, departure, an identity document that drops the
  app, or recovery into a new generation drops its registration.

## Signer flows: what runs against the service too

The signer's own tests run against the scripted Dispatch. The harness
(`crates/pubky-dispatch-harness`) runs some of the honest paths of the same flows against the
service as well and compares the two, so for these groups a difference between the scripted
Dispatch and the service shows there:

- approval, renewals and reductions, a reduction's closing with its publication failing,
  rotations over several epochs, and an epoch completed after a rotation was given up at a
  batch (`crates/pubky-dispatch-signer/tests/approval.rs`, `renewal.rs`);
- an approval with a protocol's grant paths declined, the paths allowed at a later
  request, and a decline the protocol's rule refuses (`grant_paths.rs`);
- revocations and departures, the time a removal counts from, full-bundle requests, the
  record's cleanup and the purge, a revocation past a read that failed and one asked for
  during a recovery (`revocation.rs`, `recovery.rs`);
- publication put right, the alarm for another document on the Homeserver and its
  clearing, another install signing, and records behind (`flows.rs`);
- restore from the signer backup, in place and on a new install, with a version never
  delivered and with a revocation only the Dispatch holds (`restore.rs`); two installs
  restored at once, the second delivery refused `409 stale_identity`, which the signer's
  own tests don't run;
- the hand-over both ways, its abort, and the abort racing the take-over with either
  arriving first (`handover.rs`), the account's erasure, its lost answer and an enrollment
  at the same origin after it (`erasure.rs`), and the provider loss: declared at a new
  service and in place, declared again, refused at a new service and at the origin the
  identity was enrolled at, its staged admission ended, restored mid-recovery, and
  restored on a new install from a backup a recovery in place wrote before its version
  reached the service (`recovery.rs`).

A grant path the user declines at an approval (Dispatch spec 3.4) needs nothing here: the
declines change only the Pubky grant the host approves, never the certificate, the version
or the key bundle, so the Dispatch's traffic is the same as for an approval that allows them.

Not every honest path has a flow there. Among those without one: a stale backup refused at
a restore, a Homeserver that holds another body at a restore, and a restore in place below
the signer's mark (`restore.rs`).

What stays only on the scripted Dispatch, and why:

- **A Dispatch that misbehaves.** A removal time reported before the app was listed or after
  the answer that reports it; a copy of `identity.json` that doesn't verify, is older than
  the signer's mark, or has another body at it; an answer signed with the wrong key or
  with a member left out. The service does none of these, so only a scripted fault shows
  what the signer does about them.
- **A delivery refused for good,** other than a recovery's version over the service's app
  limit: a `400` to any other version (an ordinary or a renewing version, a restore's next
  version) or a take-over refused `400`. No conforming signer meets these at the service,
  so the tests script the refusal. A body over its call's cap is never sent: the client
  refuses it before sending, for good. The Dispatch's own `413 too_large` to such a body
  comes before it reads the body, binds the empty body field and is final for nothing; the
  test scripts it with `Fault::BeforeTheBody`, signed with the service key, as the service
  signs it.
- **Exact timing.** A crash at each commit of a flow, a store that fails or can't tell
  whether it committed, and an answer lost at one chosen call among several alike: the
  tests place these by a commit's or a request's number.
- **A backup that doesn't open or is missing,** and a Homeserver that is down for a whole
  call: the Homeserver's faults in the harness are a single failed write or deletion.
- **The warnings about an app's open attempts** at a revocation and before a lapse
  (`revocation.rs`, `renewal.rs`), whose attempts the test calls `open_attempt` and
  `fail_attempt` script directly, with no entry or proof held and without the permission or
  writer checks the service makes; `open_attempt` refuses, as the service does, a second open
  attempt on a claim and any on a SETTLED one, and `fail_attempt` names the app resolving it.

## The test Homeserver

`homeserver.rs` holds public files in memory, as a Homeserver serves them, with no
authentication: an app's writes through `HomeserverWriter` go to any path of the identity it
names, where a Homeserver checks the app's grant (Dispatch spec 3.4). `set_down` makes every
read and write fail to connect, and `identity_reads` counts the reads of an identity's
`identity.json`, those that failed included, so a test can bound how often the app reads a
counterparty's document. `fail_writes` fails the next writes, refused or with the answer
lost after the file is written, and `writes` counts the writes of a path.
