# Shared record lineage

This document defines the shared record lineage of Switch spec 10.3 and
Switch wire 6.2, 6.3 and 6.9. The service keeps bounded evidence about creation and
deletion without interpreting a protocol's encrypted values. An application that
needs this evidence refuses authority when it cannot verify it. A current value,
a signature or a zero version alone is not lineage evidence.

Lineage is selected by an original's own strict absence condition, and is
required by the protected policies in [record origins](record-origins.md).
That document's retained slots, initialization and narrow birth-generation
exception apply only to those policies; ordinary records remain reusable.

## 1. Application conditions

Both conditions are objects with one member, under the rules of wire 6.3. All
members shown are required. Unknown members at every depth, wrong types, malformed
base64url and integers outside wire 1.1 are `400 bad_request`.

| Condition | Value | Holds when |
|---|---|---|
| `record_absent` | `{ "key": b64(32) }` | the service holds no live record, retained delete, divergent candidate, unknown state or allocated origin slot at `key`, and the record recovery barrier in Section 7 permits absence; record origins 2.2 defines the sole current-birth exception |
| `record_current` | `{ "key": b64(32), "lineage_id": b64(32) or null, "revision": reference, "deleted": bool }` | all four members equal the current record's state; `null` names a record without tracked lineage |

A **reference** is `{ "generation": int, "seq": int, "item_hash": b64(32) }`.
Its generation and sequence are positive. It identifies an application of a record
operation, not only the operation's claimed source version: for a normal write,
its chain position; for a recovery upload, the upload transition's position at the
receiving service. Its item hash is the hash of the signed record operation (wire 6.6),
including for an upload. A cooperative move preserves the reference. The key and,
when present, `lineage_id` scope a reference. Two uploaded operations with equal
source versions and different hashes are different references. Reapplying the
same signed operation at another position is different too.

The conditions are tested against the state before the batch, after authentication
and batch retry lookup, in wire 6.4 step 8. A record may be written only once in a
batch, so no other operation in that batch can change its record state between
this test and the write. A failed condition is `409 conflict`, with no operation
or cursor change. With the current record's read scope, `current.record_view`
contains its view, including lineage when tracked; without it, `current` is `{}`.
An absence condition blocked only by recovery returns
`current: { "record_recovery": recovery barrier }` (Section 7). Its `key` reveals
no record content or policy. An unknown key fails `record_current`.

`record_absent` is stricter than zero `record_version` or `expected_version`:
a retained delete fails it. It says nothing about a legitimately forgotten ordinary key or
an account whose witnesses were lost (Sections 5 and 7). An earlier `404` cannot
replace this condition. A repair names `record_current` with `deleted: true`, the
exact delete reference and its lineage ID. If another delete intervenes, the
condition fails even when both writes would match zero. The writer reads and
judges the new state; it does not remove the condition to make a retry succeed.

## 2. Starting and carrying lineage

An ordinary `record.put` creates tracked lineage exactly when it creates at a key the service
holds nothing for and that operation itself carries a successful `record_absent`
condition for the same key. The service draws a fresh random 32-byte `lineage_id`,
records the new write's reference as its absence origin, and sets both
`truncated` and `recovered` false. The caller cannot supply this ID or these facts.
A condition on another operation does not start lineage. A record without this
condition is a current-only record: it makes no claim about an earlier incarnation.
A protocol requiring lineage treats such a record as unavailable evidence.
Protected origins require tracked original admission; an initialized child starts
with the descriptor specified in record origins 4. Neither form can be created
as current-only state.

There is no in-place conversion of a current-only record to a proved absence
origin. An absence condition fails while either kind of record or its delete is
held. Once lineage exists, every later write inherits it, whether or not that
writer carries either new condition. Zero `expected_version`, a new batch ID,
a new writer, a different sealed value, an ordinary update, and a repeated delete
cannot clear or replace it. Conditions never authorize changing a fixed policy.

An **incarnation** is a run of non-delete writes, starting with the first non-delete
write after absence or a delete, and ending at the next delete. Its descriptor is
`{ "kind": "absent" or "replacement", "ref": reference }`. The service keeps
this descriptor unchanged through ordinary updates. For an `absent` incarnation,
its reference is the absence origin. For a `replacement`, its reference names its
first write and the service keeps that signed operation and its certificate. Its
immediate predecessor is the exact delete it replaced. A current delete carries
the preceding incarnation, or `null` when no non-delete incarnation is known.
An empty first create has an absence origin but no non-delete incarnation.

For every tracked write the service records the exact preceding current reference,
or `null` at the absence origin, in the same transaction as the write. This is not
inferred from `expected_version`. A version can match several recovery candidates;
a reference cannot substitute one candidate's signed bytes for another's.

When a delete applies, the service adds a **deletion capsule**:
`{ "delete": reference, "predecessor": reference or null,
"incarnation": incarnation or null }`. It keeps the delete, its exact predecessor
when present, and the first replacement write of the preceding incarnation when
that incarnation is a replacement. It keeps at most four capsules, in application
order. A fifth removes the oldest capsule and sets `truncated` true in the same
commit. Once true, that bit stays true while the key is retained. Nodes still
referenced elsewhere are not removed. A repeated delete is a new capsule; it
cannot erase the previous delete's meaning by claiming it was a live value.

Ordinary updates consume no capsule and do not truncate evidence. In particular,
a healthy never-deleted record can be updated indefinitely without losing its
absence origin. The service need not keep the absence origin's value after it is
superseded: absence is a service fact, not a writer's assertion about that value.
An incarnation beginning with a replacement does keep its first value. Thus an
unmarked recreation remains visible after any number of ordinary rewrites.

## 3. Bytes and authenticated statements

A tracked record view (wire 7.4.9), including a `409` view, has `revision` (its
reference) and `lineage` (the bundle below). A current-only view has `revision`
and no `lineage`. `revision` may be requested for either kind with
`GET /records/{key}?revision=1`; without that query a current-only view need not
carry it. A tracked view always carries both fields. List pages use the same
tracked view. No caller-provided field selects a different lineage.

A **lineage bundle** is:

| Member | Type | Meaning |
|---|---|---|
| `statement` | signed document | the service statement below |
| `descriptor` | b64 | exact UTF-8 JSON bytes of the descriptor below |
| `nodes` | array of node | the referenced nodes other than the current write, once each |

Every nested member of a bundle, descriptor, node, reference and incarnation is
strict: unknown members are rejected. A missing required member is not evidence
of absence. A reader verifies signatures before using their bodies.

A **node** is `{ "ref": reference, "previous": reference or null,
"applied_at": time or null, "op": signed operation,
"cert": signed<AppCert> }`. `op` is the signed record operation whose item hash is
`ref.item_hash`; its identity, key, collection and policy are the record's. The
certificate is the one checked for that write. The operation is `record.put` or
`record.initialize_child`; the latter uses its child projection and the dated
parent-write/child-read permission check in record origins 4.1, including during
recovery and import. The full operation is hashed, never its projection. `applied_at` is its original
applied service time, never its later upload time. It is `null` when that time is
not authenticated. A node's predecessor identifies the state that exact
application replaced, not an arbitrary write at its source version. A recovered
node whose predecessor is unavailable has `previous: null`; this is not an
absence claim because the descriptor has `recovered: true`.

A **descriptor** has exactly these members:

| Member | Type | Meaning |
|---|---|---|
| `v` | int | 1 |
| `key`, `lineage_id` | b64(32) | the record and its retained lineage |
| `origin` | reference or null | the service-established absence origin; `null` when unavailable |
| `incarnation` | incarnation or null | the current or most recently deleted incarnation |
| `current` | object | `{ "ref": reference, "previous": reference or null, "applied_at": time or null }` |
| `deleted` | bool | the current write has a 16-byte sealed tag |
| `truncated` | bool | an older deletion capsule was removed |
| `recovered` | bool | lineage crossed a provider loss or was rebuilt from unavailable facts |
| `deletions` | array of capsule | at most four, oldest to newest |
| `nodes` | array of b64(32) | node digests, including the current node, in reference order |

Reference order is ascending `(generation, seq, decoded item_hash bytes)`.
References and node digests occur only once. The node set is exactly the union of
`current`, each capsule's delete and non-null predecessor, and every replacement
incarnation referenced by the descriptor or a capsule. An absence origin or an
`absent` incarnation alone does not require retaining its operation. Each
required non-current node is in the bundle; the current node's operation and
certificate are the record view's, without a second copy in `nodes`. No unrelated
node is permitted. At most 14 distinct nodes are needed; aliases count once.

For hashing a reference, concatenate `u64(generation)`, `u64(seq)` and its 32-byte
item hash. An optional reference is one zero byte for `null`, or one byte `01`
followed by those reference bytes. An optional time is one zero byte for `null`,
or `01 || u64(Unix milliseconds)`. The node digest is:

`hash(lp("pubky-switch/v1/record-lineage-node", reference bytes,
optional previous bytes, optional time bytes, signed operation bytes,
signed certificate bytes))`.

Signed document bytes and `lp` are wire 2.2 and 1.4. A descriptor's digest is
`hash(lp("pubky-switch/v1/record-lineage", exact descriptor bytes))`. JSON need
not be reserialized to verify either digest. The service keeps the descriptor's
exact bytes; a cooperative import preserves them.

A **service statement** is a signed document under label
`pubky-switch/v1/record-lineage-statement`, signing `lp(label, identity, body)`
with the one service key for the current generation. Its body has exactly:

`{ "v": 1, "kind": "pubky-switch.record_lineage", "identity": pubky,
"created": time, "identity_hash": b64(32), "generation": int, "seq": int,
"chain_hash": b64(32), "key": b64(32), "lineage_id": b64(32),
"current": reference, "descriptor_hash": b64(32) }`.

`created` is this service account's creation time (wire 3.7), not that of an
account later enrolled with the same identity. `identity_hash` is the document
hash of its held `identity.json`. Generation, sequence and chain hash name the
head of the consistent snapshot from which the record and descriptor were read.
The statement's current reference, key and lineage ID equal the descriptor's and
the record view's. The service signs only after the snapshot's state is durable
and its ordinary account/mark authority checks pass (wire 7.3); a failing or
bounded account cannot attest clean lineage. A statement is not an assertion
that the client has checked the protocol's content.

The service can issue a new statement for unchanged descriptor bytes. This
reauthenticates validated state, including its original application times; it
never changes an origin, a predecessor, an incarnation, a missing date or either
uncertainty bit. Cooperative import and a key change issue statements under the
new generation's service key. Historical service keys are not retained merely
for these statements. Current records and claims keep their existing proof-key
rules. No certificate history is invented or compacted by a statement.

## 4. Reader checks and authority

A reader verifies the statement with the key of the newest own `identity.json`
it has revalidated, for that document's generation, identity and document hash.
It binds an online statement to the authenticated response's head and request;
a cached statement does not establish that its record is still current. It
checks both hashes, the complete required node set and order, every operation's
item hash, signature and policy, and every certificate under wire 6.2. A
statement dates a node only when `applied_at` is non-null and the statement is
accepted under the cooperative continuity rules of Section 6. Missing
certificate standing or a scope key remains unavailable evidence. The service's
`deleted` bit alone does not prove a delete: the node must open to empty plaintext.

The reader checks the current incarnation's first replacement against its exact
delete and predecessor, and applies its protocol's rules to every retained
capsule and replacement origin. It checks that the current value preserves the
restrictions these establish. It does not treat a later unmarked rewrite as a
new absence origin. The service preserves and authenticates the evidence; the
protocol decides which restrictions it means and whether a put-back is safe.
A proved exact predecessor can authorize an exact-copy put-back only under those
rules and an exact-current-delete application condition. Missing predecessor
content cannot be replaced by an older copy without the protocol's conservative
loss rules.

A reader with no verified local anchor, including a new app or a restore from an
old backup, obtains no authority from an untracked row, a null origin, truncated
or recovered lineage, a missing node, an invalid replacement origin, or content
that clears a required restriction. It holds the key. A reader with an already
verified local anchor may extend only the exact relationships and retained
restrictions it can establish; an uncertainty bit never certifies an omitted
relationship. Backups preserve those anchors and holds with the record state.
They do not turn a copied current value into an absence proof. A new lineage ID
after forgetting or account erasure does not erase an app's retained knowledge.

An immediate predecessor reference can advance a confirmation bound to one exact
write only when it equals that write's reference and lineage ID and the protocol's
other rules hold. Equal versions, the same marker, the same incarnation, and a
statement about a later head cannot supply missing intermediate relationships.

## 5. Bounds, quotas and forgetting

Four capsules bound deletion evidence per retained key. Crossing the bound is
explicit loss of evidence for a reader without a prior anchor; it is not proof
that the removed restrictions ended. Ordinary write count does not cause this
loss. A protocol needing more history keeps its verified state locally and
refuses actions for which that state or the shared evidence is insufficient.

Every distinct retained non-delete sealed value counts its decoded ciphertext
and tag once against the existing `record_quota_bytes`, with the current value
included and shared nodes counted once. Empty deletes count zero, as before.
A deletion retains the predecessor's already-counted value instead of freeing it;
a put-back or later update that grows the total can be refused for storage quota.
Deleting an unreferenced node releases its value bytes. Operation, certificate,
reference and statement metadata use the existing control reserve, bounded per
retained key by the node and capsule limits. This is not a bound on the number of
deleted keys an offline app can keep from being forgotten. No queue or lifetime
record history is added.

For an ordinary unprotected record, the service forgets a deleted key and all of
its lineage together, under exactly
the existing wire 9.1 rule: every current listed or open-renewal app's service
cursor has reached the delete, including unregistered and lagging apps; no
divergent upload refers to it; and the account is not frozen. A live replacement
cannot be forgotten by that rule. Removing or losing every witness can still
leave no app able to preserve a restriction; lineage does not recover information
none retains. A later genuine create after legitimate forgetting gets a new
random lineage ID and a new application-time absence origin. Retained local
knowledge is still binding at an app that has it. Protected origin slots are
never freed by this rule; record origins 3.1 retires a forgotten origin and
prevents child reinitialization.

The operation and batch limits do not change. A strict condition is part of its
signed operation's existing 512 KiB cap. Lineage is not copied into a write
request or each transition proof. A proof's record state additionally carries
`revision` and, for a tracked key, `lineage_id` and `descriptor_hash`; these bind
the committed descriptor. The full bundle is in record views.

Lineage nodes are separate export parts; a whole lineage is not one record part.
Before starting or extending tracked lineage, the service checks the actual
retained encoding: every complete export part plus its chunk wrapper must fit
1 MiB, and the complete current view with its required bundle must fit 8 MiB.
A write that would exceed either bound is `413 too_large` before commit; existing
required evidence cannot be removed to make it fit. The tighter exact protected
form caps in record origins 6 also apply to those forms. These are byte admission
and retention checks, not an assumption about every certificate's whitespace.
Nodes already supplied as the current record are not repeated. Recovery packs
whole record bundles under the existing 16 MiB request cap; a caller sends fewer
records rather than splitting one unbound bundle. Import and recovery validate
the same bounds. The implementing changes are to supply the corresponding byte
vectors and checks; no such result is asserted here.

## 6. Cooperative transfer and provider loss

An export carries a `record_lineage` part (wire 10.3) for every tracked record, including a
retained delete: its key, exact descriptor bytes and a statement issued at the
export snapshot. Each required non-current node is a `record_lineage_node` part
with key and node. Nodes are in reference order after their record's lineage
part. An operation already carried by a chain part travels there once: the node's
`op` is `null` and is reconstructed from the chain operation with the same item
hash. Otherwise it is present. A node's certificate may be `null` only when the
writer's app part carries exactly that certificate. Reconstruction precedes digest
verification. Duplicate, extra, missing or mismatched parts are `409 conflict`;
malformed shapes are `400 bad_request`.

Activation checks O's statement with the service key in the frozen account's
identity document, binds its head to the manifest, verifies every descriptor and
node, and checks agreement with every full chain item and current record the
import carries. An old superseded operation can remain full because a lineage
node still needs it; it is not mistaken for the current write. All tracked records
must have exactly one complete part set. Activation preserves lineage IDs, exact
descriptor bytes, dates and uncertainty bits atomically with the account. N may
sign the same facts under its current key only after that validation. Missing
witnesses or nodes do not become new absence origins. An abort leaves neither
partial lineage nor a record recovery completion active.

An uploaded record may carry `lineage`, in the bundle form, with its current node
supplied by that uploaded record's `op` and `cert`. A present malformed or invalid
bundle makes that uploaded record unverified and it is left out. A record without
such evidence can still be uploaded under wire 7.4.14, but supplies no lineage
authority. The upload's old service is potentially hostile: even a valid old
statement is evidence to retain, never authority to certify no omitted deletion.

Every tracked record reconstructed by an upload has `recovered: true`; the new
service never clears it by completing recovery, by a current write or by issuing
a new statement. It gives the accepted current operation the upload's application
reference and no authenticated original application time unless independently
established by a retained trusted local anchor at the reader. It does not turn
the upload's time into the writer's time. Uploaded nodes may restrict a protocol's
actions; they cannot grant a fresh absence origin. Conflicting record or lineage
evidence remains divergent and unresolved. A later ordinary write cannot clear
lineage uncertainty when it clears the ordinary divergent-upload list.

The current version merge and claim rules of wire 7.4.14 otherwise stay as written.
An upload cannot replace N's own write or silently replace its inherited lineage.
A valid upload contradicting that lineage makes it unresolved. The service retains
at most the same four most recent capsules and sets `truncated` when more valid
capsules must be omitted; unavailable order or predecessor facts keep
`recovered` true. Repeated losses cannot reset either uncertainty into a clean
origin. A cooperative move of recovered state preserves that state.

## 7. Recovery records and cursor acknowledgment

At a provider-loss recovery transition the service records its position and the
App IDs listed as current, including open renewals, in that transition's identity
document. These are the **record witnesses**. Their completion bits start false.
The bounded set has at most the account's app limit and is independent of whether
an app has registered, is lagging, is online, or holds only some scopes. It is not
the admission-staging wait: uploading contacts cannot complete record recovery.

A **recovery barrier** is `{ "position": "generation:seq",
"witnesses": [app-id], "complete": [app-id] }`, arrays sorted by decoded App ID,
unique, and `complete` a subset of `witnesses`. `GET /recovery/records` is an own-app
call returning `{ "record_recovery": barrier or null,
"record_recovery_source": signed identity document or null }`. Both members are
required. They are both null only when no provider loss began this account's
carried record history; otherwise both are present. The source is the exact
signed identity document applied when the retained barrier began, even when the
current identity document has advanced. Its identity, loss generation and fixed
witness set must agree with the barrier. A new app can read it after registration,
including after a cooperative move or key change.

The authenticated answer attests that this source was applied to create the
account's currently carried barrier. The service reads the source, barrier and
answer head in the same account transaction, after the checks of wire 7.3. It
retains the source with the accepted recovery transition; an identity document
that was only published or submitted cannot supply it. Ordinary identity
deliveries and feed pruning preserve it. Clean moves and key changes carry the
same association, a subsequent provider loss replaces it with its newly applied
source, and erasure removes it. A missing or inconsistent source is unavailable,
never a no-loss history.

An app may use this current-service answer to recover the original source when
its local state or the old feed items are unavailable. It verifies the actual
response for its current account and service, the identity-signed source and its
barrier association, and reconciles the authenticated head with the chain it
follows before accounting record work. A parsed answer, an observed future head
or an identity signature alone does not establish this authority. An existing
source at the same barrier must match exactly; it is not replaced by a different
document with the same witness set. Restore still requires reconciliation and
accounting of all retained work; neither the restored cursor nor a returned
completion bit completes that local work.

`cursor.set` may additionally carry
`"records_complete": "generation:seq"`. It names the barrier position exactly,
not an ordinary observed cursor. The caller must be a witness and its requested
cursor must reach that barrier in the same continued sequence. A wrong barrier
is `409 conflict` with the current barrier; an ineligible caller or a cursor
before it is `400 bad_request`. Once supplied correctly, a repeat is idempotent.
A witness that has not completed cannot advance its service cursor to or beyond
the barrier without this member, even in a cursor-only call: `409 conflict`.
The completion and cursor move commit together, after every operation in the
batch passed. Failure or an unknown outcome authorizes no local completion.

An honest app supplies this member only after every retained record and required
lineage, across all of its registered protocols, has been accounted for at the
recovering service. It uploads what it holds before ordinary writes, as spec
12.6 requires, except for the independent current-birth submission in record
origins 8. That exception does not complete this work or move its cursor. Partial pages, a failed upload, an omitted unreadable
record, quota failure, a kept unknown record effect or unaccounted refused
material do not complete this work. A retained value successfully uploaded as
unresolved is accounted for: it prevents absence while leaving readers held.
The app durably keeps its outstanding work before sending and resumes it after
restart. Only the exact per-input `accounted_records` acknowledgment of wire
7.4.14 accounts an uploaded item; a change list, zero rejection count or ignored
no-op is insufficient. Canonical supersession can discharge an obsolete value
only after all of its required restrictive lineage/origin facts are represented.
It does not require indefinite storage of obsolete bytes.

A backup includes the whole immutable record evidence still held by the app,
including outstanding work whose source record or discovery page was replaced.
Snapshot and restore validate the complete bounded set; a read, validation or
capacity failure refuses the operation rather than omitting a duty. An in-place
restore also preserves outstanding evidence acquired after the backup, without
substituting it for the restored protocol state. The evidence and restored app
state commit atomically. Restore starts a new accounting run, invalidates old
tickets and completion markers, and reconciles the current service before
accounting for its retained work. An unknown commit outcome requires reloading the
durable state. Restore cannot assert completion from the restored local cursor
alone.
All cursor writers, including deferred moves, suspend, batches, replay and
recovery, obey this rule. Devices sharing an app's keys must share this durable
state and cursor, as spec 3.1 requires.

Except for the own-key original predicate in record origins 2.2, strict absence
is unavailable while any incomplete witness is currently listed
or in an open renewal and neither revoked nor departed. A missing registration
or a lagging mark does not exclude it. New apps not in the witness set do not
certify lost state. Re-registration does not reset an existing completion; a
returning witness not completed must complete before new absence assertions.
The fixed witness set and completion bits are retained through cooperative moves
and key changes, even when some witnesses are offline. If an excluded witness
returns, its incomplete bit is binding again; this cannot undo a legitimate
forgetting or absence assertion made while it was excluded. Later recovered
contradictory material remains unresolved under Section 6.

The retained barrier also preserves the record-witness upload mode of wire
7.4.14. An authenticated registered own app can upload its outstanding record,
lineage and origin evidence to the active service after a clean move or key
change, even though the original provider-loss generation has ended. The source
boundary is the `recovery_from` of the barrier's retained signed identity
document, not an assumed loss of the current generation. Such uploads retain
recovered/unknown restrictions and receive current application references; they
cannot rewrite the frozen imported snapshot or complete a witness by themselves.
A staged/frozen service does not merge them, and a response from a mode that
ignored record members cannot account for those records. Non-record upload
stages and the completion/cursor rules remain separate.

A subsequent provider loss starts a new barrier from that recovery document's
current apps. No completion from the older position satisfies the new one.
An export carries the barrier, its originating signed identity document and all
completion bits in its required `record_recovery` part (wire 10.3). Import verifies the witness set against that document and
preserves it; missing or inconsistent barrier state is `409 conflict`. A fresh
non-recovery enrollment has no barrier. Erasure deletes it with the account.

Outside the exact current-birth exception, this requires offline surviving
witnesses to return and upload, or to be removed
or departed, before new tracked absence-based creations can proceed. It does not
block reads, uploads, conservative repairs of held keys or current-only records.
A current-only create made while the barrier is pending has no proved origin and
cannot be promoted after the barrier clears. Removing every witness has the
same information-loss limitation as forgetting a deletion after every witness
was removed; no current-service statement can restore those missing facts.

## 8. Protective publication before acknowledgment

A protocol receiving a record deletion may require a protective shared write or
other record effect before it can acknowledge that observation. The client
provides a durable hold and an effect outcome at this record boundary, including
on a first read and on a write the protocol refuses. The observation includes the
exact applied delete reference, available predecessor evidence, lineage and any
unavailable-evidence status. It does not substitute a locally held version for a
proved exact predecessor.

The client's local intake position is distinct from the service cursor. It may
store and pass an observation locally, but it must not move the service cursor
through that observation until every responsible protocol has either kept an
explicit no-effect decision or obtained the applied result of its required
effect. The effect's exact-current condition and `cursor.set` go in one atomic
batch where possible. A failed condition, quota refusal, local commit failure or
unknown remote result leaves the acknowledgment held durably. Unknown effects
are retried unchanged under the ordinary batch rules, never rebuilt speculatively.
A current record that superseded the delete is sufficient only after the protocol
has verified that its lineage and content satisfy the observation's restrictions.

For several protocols the service cursor is bounded by every outstanding record
hold as well as each protocol's told-through position. A later call, another
protocol, a deferred cursor flush, a backup/restore or a provider change cannot
bypass it. Reconciliation and listings preserve the same obligations. A protocol
unable to publish because it lacks a key, evidence or quota holds; it does not
acknowledge and leave a local repair for later. Such a hold can delay forgetting
and requires storage or user action; it cannot silently discard a restriction.
