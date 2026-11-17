# Current-history record retention

This document is normative. It defines an explicit record-only mode of wire
7.4.14 for retained evidence newer than a carried provider-loss boundary. It
uses the existing upload endpoint, request authentication, upload transition
and per-input accounting. It does not declare another loss, replay an ordinary
write, reopen claim or list recovery, or change cooperative transfer.

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

## 6. Conformance

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
