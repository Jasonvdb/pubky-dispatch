# Current-history record retention

This document is normative. It defines an explicit record-only mode of wire
7.4.14 for retained evidence newer than a carried provider-loss boundary. It
uses the existing upload endpoint, request authentication, upload transition
and per-input accounting. It does not declare another loss, replay an ordinary
write, reopen claim or list recovery, or bypass cooperative transfer.

## 1. Request and current account binding

An own app selects this mode by including `record_context` in
`POST /v1/{id}/recovery/upload`. It is an object with exactly these members:

| Member | Type | Meaning |
|---|---|---|
| `mode` | string | exactly `current_history` |
| `account_created` | time | the receiving account creation, with exactly three fractional digits |
| `barrier` | position | the carried record recovery barrier's `generation:seq` |
| `identity_hash` | base64url(32 bytes) | the exact identity document currently applied at the receiving account |
| `source_identity` | signed identity document | one exact source document for this request |
| `source_application` | transition proof or null | an identity-delivery proof for that exact source document, or null |

All members are required, including nullable `source_application`. The request's
`request_id` remains required. Only `records`, `origins` and `proofs` may accompany
this selector. `lost_identity`, `claims`, `heads` and `lists` are disallowed,
including empty or null members. `proofs` contains only record-operation proofs
qualified by this source context under Section 3. Different source documents require separate tickets.
Without `record_context`, wire 7.4.14's ordinary stage selection and original
lost-generation rules apply unchanged. There is no implicit mode switch when an
item fails those rules.

The service must be active, carry a valid record recovery barrier and its exact
originating applied source, and have established the caller's own registration.
Under the account lock and the ordinary account/mark checks of wire 7.3, it
compares `account_created`, `barrier` and `identity_hash` with the actual durable
receiving account. It does this before inspecting or changing record material.
The current identity document, rather than a supplied or merely published copy,
authorizes the source verification in Section 2. The barrier's originating
source fixes the original lost generation, denoted `L`; the receiving document's
generation is `G`.

This target binding is separate from the immutable source associations inside
the uploaded evidence. Neither the target creation nor its identity hash may be
substituted into an old statement, descriptor, proof or retained input. A clean
move can change the target service and creation while preserving the barrier;
the app obtains and binds the new target before making a new ticket. An unknown
old ticket is not treated as having failed merely because the target changed.

## 2. Bounded source authority

The identity verifies `source_identity`, whose actual signed carrying form
obeys the identity-document bound of wire 7.1 and 10.3. Its generation `S` must satisfy
`L < S <= G`, and its version must not exceed the currently applied document's
version. Another document at that current version is invalid. This range
belongs only to the selected mode; it changes neither the original loss source
nor the keys or generations that date evidence in ordinary loss uploads.

The source's service key must equal the key independently authorized for `S`
by the actual current document: its `inbox.service_key` for `G`, otherwise its
`service_keys` entry for `S`. A key found only in the supplied source is
insufficient. A missing historical key is unavailable evidence; this mode adds
no key-retention duty merely for statements and no document-history registry.

An identity signature and matching generation alone do not establish that a
source document was applied. In addition to the preceding key check, establish
its exact application by one of:

- It is byte-for-byte the current applied identity document read in the account
  transaction.
- The service already retains a checked association of that exact document with
  the carried record history. A document accepted at another erased creation,
  merely submitted, or merely published is not such an association.
- `source_application` is a valid existing identity-delivery transition proof
  (wire 6.5): its identity, generation, `identity` item type and object, exact
  signed-document item hash, version and state all bind `source_identity`.
- A valid source lineage or origin statement carried in this request names the
  exact document hash as its held `identity.json`, with the source generation,
  service signature and complete source snapshot association required by record
  lineage 3 or record origins 5. Such a statement establishes this source
  document's application, not another input's record facts or original date.

A supplied non-null `source_application` must pass its complete check even when
another route establishes application. All evidence used for these checks is
retained exactly when required by the final disposition; a consumer does not
reconstruct signed bytes or replace a selected proof with another one.

An identity-delivery proof has no account-creation member. It cannot establish
an absent creation association, associate a historical statement with a new
creation, or prove continuity to the current head. Statement creation values
remain their actual source values. A statement of the receiving generation
must name the receiving creation and service; historical statements retain the
source account association they actually attest. Conflicting source snapshot
or identity associations are invalid, not resolved by selecting the newer one.
For the receiving generation, a source snapshot or proof beyond the actual
current head is ineligible. A known fork or inconsistent retained history is
handled under wire 7.3 and spec 10.1, not accepted as continuity by this mode.

These routes authenticate restrictive source evidence. They do not prove that
the uploader observed an earlier response, that the current service previously
accepted custody of the whole input, or that an old head is its ancestor. Feed
pruning supplies no missing proof. The service's new disposition in Section 4,
not an inference about an earlier response, accounts for the named input.

## 3. Complete input validation

A record input keeps its exact operation, writer certificate, selected source
proof and required lineage/origin evidence. Original source document hashes,
account associations, application references and dates remain unchanged. An app
may submit a proofless input only when that immutable retained input actually
has no proof. It cannot strip a proof, omit restrictive material, exchange a
certificate, or choose another source context to make an outstanding input
eligible, then account for the original whole input from the reduced submission.
Present null and absent optional evidence keep their specified meanings.

The source generation qualifies the source statements and proofs, not every
historical node in a lineage. Source statements must bind `source_identity`
exactly and pass all ordinary hash, node, policy, slot and snapshot consistency
checks. Their source snapshot cannot precede their current application. A
source record proof of generation `P` must satisfy `L < P <= S`, bind its own
operation and complete proof state, and verify with the key both the exact
source document and the actual current document independently authorize for
`P`. This includes a current record view whose operation proof predates a clean
move but remains in the carried history. It neither changes the proof bytes
nor substitutes a document for the input's actual source context. Operation generations and
application references cannot be future relative to their source snapshot.
No proof of a generation at or before `L` dates an operation through this mode.
Such a proof and its original source remain an ordinary loss-upload duty;
selecting a newer document cannot redate it. A required proof that does not
qualify leaves that input unaccounted.

An ordinary record operation with generation in `(L, S]` can be considered
without a proof under the existing restrictive lower-bound rule. An operation
at or before `L` is considered here only as part of a verified complete source
record unit whose receiving application is after `L`, as when an earlier
operation was recovered and then read in the carried history. Its historical
nodes remain restrictive facts; their generation is not rewritten. Other old
operations use the ordinary loss mode. A future operation or incompatible
source association is unverified, never routed to another mode automatically.

The record-operation union, exact shape, signature, certificate authority,
immutable protection and parent/child checks remain those of wire 6.9 and
record origins. Initializer admission requires its actual dated parent-write
and child-read authority. The selected mode, the current identity document,
a lower-bound version or the upload time supplies no missing original date.
A statement accepted only as restrictive evidence does not acquire the dating
authority of verified cooperative continuity. Removed-writer restrictions
still require a qualifying original proof at or before `distrust_from`.
No proofless current-born candidate acquires clean original or initializer
authority by being uploaded. An ordinary unprotected tracked record whose
upload has no lineage bundle still uses the unknown/recovered reconstruction
of record lineage 6; this mode adds no proof requirement merely because its
operation originally carried an own-key absence condition.

Bulk `proofs` entries are checked only for the eligible proof generations
above and record operations. Per-item proof selection uses the same exact operation binding as
wire 7.4.14. A supplied per-item proof that cannot qualify does not silently
become a proofless input. An unused bulk entry accounts for no record; invalid
entries increment `unverified`. A selected proof and the certificate-bearing
node must form one coherent source unit. Reusing a proof with another
certificate or descriptor is not justified by equal operation hash, version
or lineage ID. A renewed statement may reauthenticate unchanged descriptor
bytes; it cannot invent a missing association to an older proof.

Standalone origins use record origins 7.1's complete bounded part and
matching-only strengthening rules, with the source range and application
qualification of this section. A child-observed statement can authenticate its
known initialized parent's restrictive slot, as there. An unknown slot cannot
supply a missing original or child declaration. Attached evidence remains part
of its record input and is not accounted as a separate origin index.

## 4. Disposition at the final transaction state

The service processes valid inputs with the same record comparison order,
immutable-shape checks and restrictive lineage/origin merge rules as wire
7.4.14. This mode never executes the uploaded operation as an ordinary write.
An existing current write wins; contradictory evidence is kept divergent or
unresolved subject to the same bounds. A newly retained application uses the
current upload transition's reference, distinct from its source reference.
A received source proof is retained with its exact source association where
needed; it is not a proof of that receiving application. Existing current
operation/certificate/node/proof tuples stay coherent.

For each input, the final state has one of these dispositions:

- **Retained:** its value is represented by the current or a kept divergent
  operation, with its whole required source and restrictive evidence durably
  represented. Exact duplicates are included only after this complete check.
- **Superseded:** the canonical duplicate, older-upload or upload-base
  comparison requires no further retention of its value, and every required
  restrictive lineage/origin fact remains represented after all inputs in the
  transaction. Only then may obsolete operation/certificate/proof bytes be
  discarded. Equal key, version or operation hash alone is insufficient.
- **Unaccounted:** invalid, distrusted, incompatible, ignored, incompletely
  processed or capacity-refused material, or any input whose required final
  representation cannot be established. Its omission is never proof of absence.

Only retained and superseded inputs appear in the existing `accounted_records`
or `accounted_origins` array for their actual request array. These are not new
wire status strings. Each array is required, increasing, unique and in range of
its own actual input count. The ordinary change lists and rejection counters
remain; an HTTP success, zero changes, a divergent key or a no-op reason alone
accounts for nothing. An unavailable final judgement refuses the transaction
rather than acknowledging a tentative disposition.

Final representation is checked after every input, against the final state of
one account transaction. An intermediate same-request value or deletion is not
a separate durable receiving application. Required source history and
restrictive facts from an earlier input cannot disappear merely because a later
input replaced that provisional value. Known origin facts may be represented
by an exactly equal clean slot already held, or by a compatible stronger
recovered slot. The input never turns recovered/unknown state clean. Current
value supersession is insufficient when necessary origin or lineage facts
would be lost.

Every accepted call appends exactly one current `upload` transition, including
an empty-change call or retry. The result, both accounting arrays, upload proof
and authenticated head describe its one durable transaction. Its answer is
exactly the record-upload answer of wire 7.4.14; no additional receipt or ID
registry is introduced. It does not move a cursor, set a completion bit, end
staged admission or account for another kind of work.

The existing 16 MiB body cap, whole-unit, complete-view and per-export-part
bounds, origin allocations and the existing common non-current retention
capacity all apply to the actual serialized and finally retained forms.
Recovery remains exempt from ordinary `record_quota_bytes` and
`max_record_keys` admission limits (wire 9.3). Every distinct full retained
sealed value is still counted once for subsequent ordinary growth admission.
All non-current complete inputs at a key share its existing
`max_divergent_uploads` retention budget, including differing-certificate
inputs for the same operation; there is no separate source-history allowance. Source context
and application evidence count toward the body cap. Separate small carriers
cannot evade the complete retained unit's cap, and a historical source proof
is not relabeled as a receiving proof to fit a carrier. No item is partially
accepted to fit a bound. A malformed or oversized required encoding is
`unverified`; material that cannot be retained within capacity is `refused`.
Both stay unaccounted.

## 5. Refusals and durable local accounting

Ordinary authentication, registration, account verdict and rate-limit ordering
remain wire 7.2-7.4.14's. Within this selected mode:

| Condition | Answer and effect |
|---|---|
| Malformed selector, missing required member, unknown mode or disallowed material member | `400 bad_request`; nothing merges |
| Request exceeds the upload body cap | `413 too_large`; nothing merges |
| No carried record recovery barrier at an otherwise active account | `404 not_found`; nothing merges |
| Target creation differs | `409 conflict`, `current: { "created": time }`, no `Switch-Head`; nothing merges |
| Target barrier or applied identity hash differs at that creation | `409 conflict`, `current: { "record_recovery": barrier, "identity_hash": base64url(32 bytes) }`; nothing merges |
| Barrier/source provenance or current account authority is unavailable or inconsistent | `503 unavailable`, or the required wire 7.3 fail-stop answer; nothing merges |
| Frozen or staged account | its ordinary `410 moved` or `503 staged`; this mode never ignores and accounts record members |
| Source document outside `(L, G]`, conflicting version, invalid signature, unauthorized key or unestablished application | inputs requiring it are `unverified`, both accounting arrays empty; one ordinary upload transition |
| Valid source but invalid, distrusted or capacity-refused item | existing per-item counter, no index for that item; other eligible items can merge |
| Lost, invalid or unbound response, or unknown remote commit outcome | no local accounting; keep the exact ticket and evidence |

The conflict bodies do not authorize a client to retarget an existing ticket.
A source that cannot qualify is not retried as an implicit loss upload or with
a different proof association. A new explicit ticket may carry another actual
retained unit without discharging the original one.

The app captures its live accounting run, destination, applied identity,
creation and barrier before sending, and durably binds them with the exact
whole inputs and fresh random `request_id`. It verifies the actual response's
request binding, indices, upload proof and head and reconciles that head in the
same current account history before accounting. It rechecks the run and
destination after the await. Accounting only the listed immutable inputs and
consuming the ticket commit atomically. Unknown local commit outcome requires
reloading durable state. Partial omission preserves every omitted duty.

Restart resumes the same outstanding immutable ticket. Restore invalidates old
tickets and completion markers, preserves all held whole evidence and starts a
new accounting run with new request IDs. An authenticated old response, restored
cursor, completion bit, response hash or later head cannot complete that run.
A lost response is retried by the exact ticket; the service makes a new current
disposition under the ordinary retry rule. Changed account, barrier or identity
requires reconciliation and a new explicitly bound ticket, without erasing the
old outcome uncertainty or any retained duty. A later provider loss returns
those duties to its new original-loss boundary; this mode never keeps an older
barrier alive or bypasses a new one.

A previously authenticated complete custody observation and independently
verified continuous carried account history can remain sufficient under the
ordinary rules, including lawful bounded supersession. A bare ancestor hash,
pruned segment, forked head or restored trust flag cannot establish that case.
This mode supplies a fresh named-input disposition when such custody cannot be
established; it introduces no portable custody-receipt format. Completion still
requires every local duty across all registered protocols and the guarded
`cursor.set.records_complete` of record lineage 7.

## 6. Complete retained inputs in cooperative transfer

Every complete record input still needed by the final disposition has one
bounded **retained record unit**, whether admitted through ordinary loss,
retained record-witness or current-history processing. The representation is
the same for a current upload-derived value, a conflicting value and additional
source evidence for the same operation, including another certificate. A
current record has at most one primary unit; all its non-current units share
the existing `max_divergent_uploads` capacity. It is not a history of requests:
an exact complete input already represented uses its held unit and admission
association, and a legitimately superseded unit is discarded only under
Section 4. Request IDs, tickets, unused bulk proofs and failed inputs are not
exported as retained units.

### 6.1 Unit bytes and associations

A unit is the actual UTF-8 bytes of a compact JSON object with these members,
all required except the two optional members inside `record`:

| Member | Form |
|---|---|
| `v` | `1` |
| `key` | the record key, base64url(32 bytes) |
| `admission` | the object below |
| `application` | the actual receiving application reference, or null |
| `source_identity` | the exact checked signed source identity document, or null where ordinary loss processing qualified no source |
| `source_application` | the exact qualifying identity-delivery proof, or null |
| `record` | `{ "op": signed record operation, "cert": signed writer certificate, "proof": selected source record proof or null }`, with the source input's optional `lineage` and `origin` members preserved, including present null |

The record proof is the actual checked per-item or bulk-selected proof, not a
proof invented for the receiving upload. At admission, preserve the source
bundle before constructing normalized receiving lineage. A reconstructed recovered descriptor cannot recreate an
original signed source statement. Every signed body, signature, descriptor byte
and node stays exact; the source bundle is not replaced by the
current receiving bundle. Source nodes already present elsewhere in the export
are still carried in this unit, so reassembly does not depend on chain or batch
retention. Failed or unselected proof candidates are not selected evidence.
The complete input identity compares this record material and its exact source
and application evidence, not only the operation hash or its export index.
Receiving `admission`/`application` metadata, a ticket or a fragment index
does not make another immutable input. A retry therefore cannot consume
another slot by assigning a new receiving position to the same complete input.

`admission` is exactly:

| Member | Form |
|---|---|
| `mode` | `loss` or `current_history`; `loss` includes the retained record-witness continuation |
| `created` | the actual receiving creation at admission, in wire 1.6 form with three fractional digits |
| `identity` | the exact signed identity document actually applied at that admission |
| `barrier` | its carried record recovery barrier position |
| `before` | `{ "generation": int, "seq": int, "chain_hash": base64url(32 bytes) }`, the actual account head immediately before its upload transition |
| `upload` | the position of that upload transition |

The admission's document and barrier are the authority actually checked then,
not the exporter or importer's newer document substituted afterward. Its upload
generation equals that document's and its `before.generation`; its upload
sequence is `before.seq + 1`. If this unit supplied a new receiving current
application, `application` is that reference: its generation/sequence equal
`upload`, and its item hash is the uploaded operation's. Otherwise it is null;
a same-current certificate variant does not pretend to have been the current
application. A primary current unit has a non-null application matching the
record's retained receiving revision, or the same reference derived from its
upload sequence and operation where the ordinary projection omits revision.
Its source version remains the original proved version or lower bound, not the
receiving upload sequence relabeled as a record-operation proof.

These are bounded account-state associations established atomically at
admission. They are retained with the unit through pruning and clean moves.
They are not a portable upload receipt or a client constructor for authority.
During a cooperative transfer, the authenticated frozen manifest commits the
exact unit bytes and the exporting service's assertion that this admission and
its source application qualification belong to the carried account history.
An importer checks that assertion with the complete unit and the consistency
rules below. Outside that checked transfer, parsing an admission object, an
identity signature, or restoring a local marker establishes no such fact.
A previously checked source-application association may be continued this way;
an exporter cannot create one merely to make a source document qualify.

### 6.2 Export carriers and exact bounds

A `record` part taken from an upload has required `source_unit`, the base64url
32-byte hash of its primary complete unit bytes; this member is absent otherwise. Its public
`proof` remains absent, and its operation/certificate and receiving reference
must match the primary unit. The current record's separate lineage and origin
parts still describe the final frozen receiving state. They are not carriers
for alternate source descriptors or proofs.

Every non-current unit is named by one part:

```json
{"part":"record_retained","key":"<b64(32)>","index":0,"unit":"<b64(32)>","divergent":true}
```

Its index is consecutive from zero within the key's common non-current pool,
at most seven. `divergent` says whether this unit still represents an active
conflicting value; a separately retained certificate or required restrictive
unit need not do so. Distinct complete inputs for the same operation consume
distinct slots while kept, but do not create distinct conflicting values just
because their certificate or proof bytes differ. Duplicate complete inputs,
a primary unit also listed as non-current, or more than the existing shared
capacity are invalid.

Complete units travel in `record_source` parts:

```json
{"part":"record_source","key":"<b64(32)>","unit":"<b64(32)>","index":0,"count":1,"length":123,"data":"<b64>"}
```

`unit` is `hash(unit bytes)`, `length` their total byte length, and `data` an
unmodified consecutive slice encoded as unpadded base64url. Each slice decodes
to at most 524,288 bytes. Every slice except the last has exactly that length;
the last is nonempty. `count = ceil(length / 524288)` and `index` runs from zero
to `count - 1`. A unit is at most 16,777,216 bytes including its admission and
source context, so at most 32 slices. Metadata agrees on every slice. There is
exactly one complete set for each referenced unit, and no unreferenced set.

This transport bound does not enlarge an admitted record unit, protected
bundle, current view, source context or non-current pool. All preceding logical
bounds apply independently, including the existing 16 MiB upload body limit.
Admission also checks the complete retained encoding with its required
admission context. It refuses an input that cannot be retained and exported
whole; splitting bytes cannot make an oversized logical unit eligible.

The maximal `record_source` part in the compact carrying form above is 699,230
bytes: 699,051 base64url characters for 524,288 bytes plus the fixed members
with maximal indices/count and length. Adding the maximum 103-byte chunk
wrapper gives 699,333 bytes, below 1 MiB. All actual part bytes still undergo
the hard chunk check. The current record part's `source_unit` member counts
toward its existing actual ordinary/protected part cap. The manifest counts
all fragments and bytes; the total import limit still refuses the whole
transfer rather than omitting a unit. The same sealed value appearing in
current lineage and source units is charged once by full value identity;
fragmentation does not change quota or control-reserve accounting.

### 6.3 Activation and continued authority

After ordinary manifest/chunk authentication, the importer:

1. Checks exact part shapes, ordering, indices, fragment lengths/counts and
   total bounds, reassembles each unit, and verifies its hash before parsing.
   It rejects duplicates, missing/extra fragments, unreferenced units and a
   reference to another key. Required-null and optional-presence distinctions
   survive reassembly. Malformed encodings or caps are `400 bad_request`;
   absent, substituted or inconsistent required evidence is `409 conflict`.
2. Verifies both identity signatures, when a source exists, and the exact
   record-operation union, certificate, selected proof, source bundle and
   origin facts under the recorded admission's mode and authority. The mode
   never comes from comparing the operation's generation with the export's.
   Its barrier equals the carried barrier, with the same original loss bound.
   Its admission generation/version do not exceed the frozen account's; a
   document at the same version must be the exact held document. Source
   application qualification for `current_history` remains actual checked
   application/continuation, an exact delivery proof, or a qualifying source
   statement as Section 2 requires. A supplied delivery proof must verify.
   `loss` keeps wire 7.4.14's source qualification and does not acquire a new
   delivery-proof requirement; its `source_application` is null. The frozen
   transfer can continue the stored checked association; it cannot invent an
   unavailable one or supply a missing original date.
3. For `loss`, applies the unchanged old-loss generation, proof and initializer
   rules: operation generation at or before the original loss bound, and a
   selected dating proof only of the permitted lost generation. For
   `current_history`, applies Sections 2-3 against the actual recorded
   admission context, including source and proof key authorization, bounds and
   source snapshot ceilings. Thus an authentic operation from the admission's
   own generation is permitted without calling it an ordinary write. Neither
   mode assigns a source proof to the receiving application or promotes
   unknown/recovered facts to clean authority. Import does not rejudge the
   historical admission as a fresh upload under a newer identity document.
4. Checks the admission upload position and every application against the
   frozen sequence and retained chain. A retained stub there must be a service
   upload; a full transition must agree with the unit's application and list
   its key when the unit supplied a new current application. The `before`
   hash must agree wherever the export retains that head or its successor.
   Missing pruned stubs are not fabricated or treated as ancestry evidence:
   the frozen manifest carries the bounded retained admission association.
   An existing conflicting stub/document is never ignored. The primary unit
   matches the current record's exact operation/certificate, source version
   and receiving reference. Its public record proof stays absent. Ordinary
   written current records retain their operation-chain and proof checks.
5. Verifies every active divergent value and every non-current unit's final
   role. An active divergent unit must be a conflicting operation under the
   ordinary comparison rules, not merely another certificate for the current
   operation. A non-divergent unit must match the current operation, qualify
   for a canonical terminal value comparison, or have its value divergence
   cleared by a verified ordinary receiving write after its recorded upload
   position in the continued sequence. That write does not clear required
   restrictive facts. All source restrictions still needed must agree with
   or remain represented beside the final current lineage and origin slots;
   the unit's source descriptor cannot be substituted with the current one.
   A full chain operation can additionally be justified by an exact retained
   source unit; unrelated superseded full operations remain invalid.
6. Activates records, primary and non-current complete units, exact source and
   admission associations, their common capacity, current lineage/origins,
   quota accounting and barrier together. Partial import or abort establishes
   none of them. A later export preserves these associations even after the
   source operation, upload transition or identity delivery leaves the feed.

Every retained selected record proof and retained identity-delivery application
proof whose generation is newer than the carried original loss bound is a
kept proof for wire 3.3's `proof_generations` report. This includes non-current
units and certificate variants. A move or key change must preserve the actual
key of every such generation, resolved from the actually checked source
association rather than assumed to be the current service key; activation
checks those keys against the frozen
identity's map and the recorded checked source. The existing 256-key limit and
refusal apply. Old-loss proofs continue to use their exact restrictive source
association and remain excluded from that map as wire 3.3 requires; they gain
no clean dating authority. Source statements and admission bookkeeping alone
do not add proof generations. A legitimately discarded unit releases only key
duties no other kept proof needs.

## 7. Conformance

Implementations must cover the following cases with authentic signed inputs
and the exact immutable ticket. The service, shared checker, client and durable
local accounting must agree on the disposition.

| Case | Required result |
|---|---|
| Loss boundary 3, current generation 4, restored valid whole record A from generation 4; current is A | Full validation and retention permits A's index |
| Same context, current is B, A qualifies under the canonical upload-base or supersession case and every restriction is represented | A's index; no need to retain legitimately obsolete bytes forever |
| Same context, B alone proves neither A's disposition nor its required restrictive facts | A unaccounted, or valid complete A retained restrictively before its index |
| Ordinary generation-4 A actually has no proof and no positive origin authority | May be retained unresolved under its lower bound; no clean original or initializer authority |
| A holds proof P, but upload strips P or substitutes another source/certificate | Cannot account A from that changed input |
| Exact current applied source, or exact historical applied source authenticated by an authorized generation key | Eligible restrictive source; no ancestry or original-authority inference |
| Identity-signed source only, source key absent from current authority, wrong source document hash or unavailable source association | No input accounting |
| Source generation at or before 3, or above current generation | No accounting in this mode; ordinary loss rules unchanged |
| Old operation in a verified later recovered current snapshot, whose actual public proof is absent | Preserve its old references/dates and recovered facts; a new restrictive disposition may account this exact proofless unit |
| Otherwise comparable input actually holds a proof at or before the original loss boundary | That proof and source remain an ordinary loss duty; no stripping or redating to account it here |
| Proof after the loss boundary predates a clean move, with both source and current documents authorizing its own generation key | Check its exact original generation and bytes; never label it a proof of the receiving upload |
| Per-item proof, bulk-selected proof, and no proof | Preserve exactly the selected valid evidence; no borrowing another input's permission or date |
| Same operation with a different certificate and old node/proof | Reject incoherent recombination; equality of operation hash does not account it |
| Compatible retired or child-observed standalone origin | Strengthen the same slot and account its own origin index if finally represented |
| Incompatible immutable slot fact, missing initializer authority or required node | Refuse or mark unverified as specified; no partial input effect or index |
| Required facts exceed any final view/export/retention cap | Unaccounted; no truncated acknowledgment or cursor completion |
| Whole recovery input exceeds ordinary record growth quota but fits structural and retained-input capacity | Recovery admission exemption applies; distinct retained values count against later ordinary growth |
| Several inputs at one key, including a provisional deletion | Judge every index against final committed representation and preserve required source facts |
| Wrong creation/barrier/current identity, frozen/staged target, unavailable authority | Exact refusal above, no record mutation |
| Mixed loss/current source contexts or claim/list/head material | No implicit fallback or partial mode selection |
| Duplicate, unordered or out-of-range response indices | Client rejects accounting for the response |
| Lost response, restart, restore, provider change or local commit uncertainty | Preserve duties and apply the exact ticket/run rules above |
| Current-generation proofless current upload, then pruning and a clean move | Primary unit preserves exact op/cert, lower bound and receiving reference; import accepts current-history admission without a fabricated record proof |
| Proof-bearing tracked A retained beside later ordinary B, then source/batch pruning and a clean move | Exact A cert/proof/source/descriptor and admission survive in its complete unit; B's current descriptor cannot replace them |
| Same operation with several independently checked certificate/source variants | Each exact retained non-current unit shares the eight-slot pool and transfers coherently; value divergence is not multiplied by certificate bytes |
| Loss-mode unit relabeled current-history, future admission/source, or current-generation operation with no qualifying admission | Import refuses; the operation generation alone never selects an exception |
| Truncated, reordered, duplicated, cross-key, hash-mismatched or over-bound source fragments | Import refuses before activation; fragmentation does not waive whole-unit bounds |
| Missing primary unit, missing selected proof/source, or replacement of source D with the current descriptor | Import refuses the incomplete transfer |
| Required non-current record or application proof generation omitted from the next identity | Move/key change or import refuses under the kept-proof rule |
| Ordinary write clears value divergence but a retained source restriction is still required | Clear only the value flag; transfer the needed complete unit or its qualifying final representation |
| Partial import, abort, retry, or a second clean move after feed pruning | No partial authority; exact complete unit and admission association remain bound to the frozen transfer |
