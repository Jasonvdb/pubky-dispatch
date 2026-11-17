# One-time record origins

This document defines protected shared records under Switch spec 10.3 and wire
6.9. It extends [record lineage](record-lineage.md). A policy can reserve one
non-recycling origin and, optionally, one child initialized atomically with a
parent write. The service interprets neither value nor the protocol's bindings.
Ordinary policies remain reusable under their existing forgetting rules.

## 1. Policies and key derivation

An operation's `protection`, when present, is exactly one of:

```json
{"kind":"origin","birth_generation":null}
```

```json
{"kind":"initialized_child","parent_key":"<b64(32)>","parent_collection":"<b64(32)>","parent_policy_hash":"<b64(32)>","slot":"<b64(32)>"}
```

`birth_generation` is required, either null or a positive wire integer. Null
means no generation restriction. The other form's four identifiers are required
32-byte values. These objects, and every object defined below, reject unknown,
duplicate or missing members and wrong types at every depth. Null is permitted
only where expressly defined. Integers obey wire 1.1. Protected policies have
1 to 32 sorted unique `write_scopes`; each scope, including `read_scope`, has
wire 3.1's maximum of 65 ASCII bytes. An absent `protection` is an ordinary
policy, not a protected policy with missing information.

The protected policy hash is:

```
hash(lp("pubky-switch/v1/protected-policy", read_scope,
        u64(number of write_scopes), write_scope_1, ...,
        protection_bytes))
```

Binary integers are unsigned big-endian u64 within the wire integer bound.
For an origin, `protection_bytes` is `01 || 00` for null birth generation, or
`01 || 01 || u64(birth_generation)`. For a child it is `02` followed by the
decoded parent key, parent collection, parent policy hash and slot, in that
order. The ordinary policy hash is unchanged. Collection and key derivations
remain wire 1.5's; the creating operation supplies `id_inputs` and the service
recomputes them. Later writes repeat the complete policy exactly.

The parent policy contains no child declaration. Derive its hash and key first;
derive the child's policy and key from them second; sign the resulting child
declaration in the parent's original put third. Assigned application references
are installed after checking the batch. No operation or policy includes its own
hash or an application reference that must be known before signing. A child
policy is not an origin policy and cannot declare another child.

## 2. Original admission

An original origin-policy `record.put` has a non-delete value, `id_inputs`,
`expected_version: {"generation":0,"version":0}`, its own successful
`record_absent` condition, and this additional required member:

```json
{"origin":{"binding":"<b64(32)>","child":{"slot":"<b64(32)>","key":"<b64(32)>","policy_hash":"<b64(32)>"}}}
```

`origin.child` is either that exact declaration or null. Null deliberately
selects a standalone origin; it is not a vacant child. The binding and child
presence/declaration are immutable. An original delete is refused. A later put
must omit `origin` and preserves these facts; carrying it later is malformed.

In the same account transaction the service checks ordinary authorization,
current epoch, derivations, strict absence, absence of any allocated origin slot
for this key, and all capacity and byte limits. A present birth generation must
equal both the signed operation's generation and its actual original application
generation. An original signed for a future or elapsed birth generation cannot
apply. The service assigns the random lineage ID and exact original reference,
allocates the slot and applies the write together. A failed or aborted batch
allocates nothing. A preflight read is not admission.

### 2.1 Fixed admission bound

Each uninterrupted account history has at most **100,000 origin slots**. All
origin policies use the same allocator, with or without a child or birth
restriction. Each allocation reserves **577 bytes of logical slot storage**,
including when its present payload is smaller. Indexes and allocator overhead
are additional implementation storage. Ordinary live-key and ciphertext quotas
still apply. The origin limit is a format bound, not a configurable increase.

The count increases once per distinct admitted origin key and never decreases
within that history. Deletes, forgetting, all-app removal, scope or key changes,
compaction, quota pressure and cooperative moves cannot release slots. Admission
and the count are serialized with the account: two origins cannot win the last
slot, and two originals cannot win the same key. Retried batches use wire 6.4's
lookup before allocation. At the bound a new original is `429 quota_exceeded`,
`limit: "record_origins"`.

The bound does not reject an existing record's update, retained-delete put-back,
or initialization of its already reserved child. Those still obey their ordinary
key, value and storage limits. Child initialization can fail its live-key quota
without consuming another origin slot. The count and complete allocated set are
durable account state; they are checked for consistency before serving absence
or positive origin evidence. Missing, unreadable or inconsistent allocation
state stops that authority. It is never interpreted as an empty allocator.

### 2.2 Current-birth absence

Only an original ordinary `record.put` with `origin.child:null` and
`birth_generation` equal to the verified current generation can use this rule.
The signed operation and actual application must have that generation. It still
needs its own `record_absent` condition and every authorization, epoch, slot,
key, byte and rate check.

For this operation's own-key absence predicate only, an incomplete record
recovery barrier may be disregarded solely to the extent its missing witnesses
can hold evidence from strictly earlier generations. The retained recovery
identity document and source boundary must prove that restriction. Missing
source evidence, an unclassified gap, current-generation loss or uncertainty
cannot qualify. An allocated slot, current value, retained delete, divergent
candidate or unknown state at the key always defeats absence, including retained
earlier evidence that appears inconsistent with the birth restriction.

The key commits to the birth generation through the policy hash, and every first
original must actually apply in that generation. Wire 6.4's generation check
prevents a future-signed operation from applying earlier. Thus earlier witnesses
cannot hold a valid earlier original for this exact key. Concurrent operations
in the birth generation still compete under atomic absence and slot allocation;
same-generation deletion cannot reset the slot. A namespace's name alone proves
nothing.

This does not complete a witness, clear a barrier, or satisfy another operation's
absence condition. No special preflight proof or endpoint is added. Only the
verified applied original establishes admission. Missing witnesses may remain
incomplete indefinitely. Unscoped and child-bearing origins retain the strict
barrier. An existing birth-bound origin may be updated after a clean move using
its exact current reference; the first-application equality is not imposed again
on updates. A late first original is refused.

## 3. Retained slot

The slot is canonical binary carried as unpadded base64url. Concatenate:

| Field | Bytes | Values |
|---|---:|---|
| format | 1 | `01` |
| parent key, collection, policy hash | 32 each | decoded identifiers |
| birth presence | 1 | `00` null, `01` present |
| birth generation | 8 if present | positive u64 |
| parent read-scope length | 1 | 1-65; 0 only for unknown scope |
| parent read scope | length | exact ASCII |
| form | 1 | `00` unknown, `01` known |

Unknown form ends here. Its fields come from valid retained policy evidence; it
is restrictive and grants no original or child authority. An unavailable scope
does not make its tombstone readable or its key absent. Known form continues:

| Field | Bytes | Values |
|---|---:|---|
| parent lineage ID | 32 | original lineage |
| original application | 48 | u64 generation, u64 seq, item hash |
| origin binding | 32 | original put's binding |
| child presence | 1 | `00` null, `01` declared |
| child slot, key, policy hash | 32 each if declared | immutable declaration |
| initialized | 1 | `00` or `01`; `00` when child is null |
| parent acceptance application | 48 if initialized | companion put reference |
| child first application | 48 if initialized | initializer reference |
| child lineage ID | 32 if initialized | first child lineage |
| initial value hash | 32 if initialized | Section 4 |
| initialization binding | 32 if initialized | initializer's binding |
| retired | 1 | `00` or `01` |
| recovered | 1 | `00` or `01` |

References have positive generation/sequence. A known original's generation
equals a present birth generation. Other tags, trailing bytes and impossible
combinations are invalid. Maximum payload: 173 common bytes plus 404 known
initialized bytes = 577; base64url length 770. At maximal scope length an
unscoped initialized slot is 569 bytes, its vacant form 377; a standalone known
slot is 289 with birth or 281 without. Unknown is at most 173. All reserve 577.

Immutable fields never change. A declared vacant child becomes initialized at
most once. Null never becomes a child. Retired and recovered only become true.
An upload or ordinary write cannot make unknown clean; additional verified
evidence may make it known recovered, still without positive original authority.

### 3.1 Deletion and retention

While the origin value or its exact retained delete remains, its slot is retained
with it. When wire 9.1 would forget the deleted origin and its lineage, the service
atomically sets `retired` and removes only the forgettable ordinary material.
The compact slot remains permanently in this account history. A retired origin
cannot receive another original or another value, even in the same generation.
An exact protective put-back is possible only while the delete and required
provenance are retained, under ordinary authority and `record_current`.

A child delete can be forgotten under the ordinary rules, but its parent's
initialized slot remains. The child cannot be initialized again or created by
an ordinary zero-version put. A protective child put-back needs its retained
exact current delete, normal child write scope and `record_current`; it preserves
its lineage and attachment and is not initial authority. Removing every app
neither removes live shared records nor frees slots. Ordinary unprotected record
keys retain their ordinary forgetting behavior.

## 4. Atomic initialization

`record.initialize_child` is an own-app signed operation with the common fields
of wire 6.1, non-null `app_id`, and optional ordinary `conditions`. Its additional
required members are:

| Member | Type |
|---|---|
| `parent` | `{ "key": b64(32), "select": selector, "policy": parent policy }` |
| `parent_write_index` | integer, 0-7 |
| `slot`, `binding` | b64(32) each |
| `child` | `{ "key", "collection", "read_scope", "write_scopes", "protection", "id_inputs", "value_sealed" }`, with wire 6.2 types |

The parent policy has exactly `collection`, `read_scope`, `write_scopes` and
origin `protection`. The child's protection is the initialized-child form of
Section 1; its `id_inputs` and sealed value use wire 6.2. Selectors are exactly:

```json
{"kind":"current","lineage_id":"<b64(32)>","revision":{"generation":1,"seq":1,"item_hash":"<b64(32)>"}}
```

```json
{"kind":"created_in_batch","put_index":0}
```

Indices count signed operations only, excluding a cursor, and must name actual
operations. The created-in-batch selector requires `put_index ==
parent_write_index`. There is at most one initializer per batch, last among its
signed operations. Its indexed parent put precedes it and is the only write of
the parent key; no other operation writes the child key. The initializer counts
as the child's one write. Its slot update is not a second parent value write.
Eight total batch entries remains the bound. No `expected_version` appears on
the initializer.

After normal signature, generation and retry checks, in one transaction:

1. Check the full parent policy/hash against the selected parent and slot. The
   app holds a parent write scope and the child's read scope. The child policy
   names this exact parent key, collection, policy hash and slot.
2. For `current`, the selector equals the pre-batch live clean parent, whose
   known non-retired, non-recovered slot has the matching vacant declared child.
   For `created_in_batch`, validate the indexed original admission and that same
   declaration. Null children cannot initialize. Neither case uses Section 2.2.
3. Recompute child collection and key. The child differs from the parent and has
   no value, retained delete, conflicting candidate or other initializer. Its
   parent slot must not already be initialized. The strict recovery barrier must
   permit absence.
4. Check the companion normal parent put's authorization, exact selected base
   and all pre-batch conditions. Both new values are padded non-deletes. Every
   operation, byte/key quota and cursor check must pass before commit.
5. Stage the parent value, child value, both assigned references, the new child
   lineage and initialized slot atomically. Failure changes none of them.

The child's initial descriptor has `origin` and `current.ref` equal to the
initializer's application reference, `incarnation: {"kind":"absent","ref":
<that reference>}`, `current.previous:null`, the authenticated application time,
`deleted:false`, `truncated:false`, `recovered:false`, `deletions:[]`, and exactly
its current node's digest in `nodes`. The current node has `previous:null` and
the full initializer operation/certificate. Its lineage ID is newly drawn.

Each operation has its own sequence and item hash in batch order. Both paired
resulting record proof states commit to the final slot hash, containing both
references. No proof or current statement exposes an intermediate durable vacant
state. Statements describe committed batch-end snapshots. The initializer's
item type is `op`; its item hash covers its full signed document, not a child
projection. Its proof object and version are the child's key and sequence. The
parent reference is the indexed put's. Retry follows wire 6.4; no-op proves no
initialization or condition.

The retained initial sealed-value digest is:

```
hash(lp("pubky-switch/v1/initial-record-value",
        u64(value_sealed.data_epoch), value_sealed.scope,
        decoded_nonce, decoded_ct))
```

It identifies sealed bytes, not their meaning. The opaque signed initialization
binding and atomic association are retained; a protocol opens the value and
checks its own initial-content predicate.

### 4.1 Later writes and verification

Ordinary `record.put` cannot create a child-policy record. It needs an existing
live child or retained exact delete, the unchanged policy, normal child write
scope and an exact `record_current` condition. Later origin puts likewise need a
retained current parent and exact-current condition. They preserve the slot and
consume no origin admission. A retired tombstone cannot be overwritten.

All record readers, lineage-node checkers, recovery upload verifiers and clean
import verifiers recognize the operation union `record.put` or
`record.initialize_child`. For an initializer, the child projection supplies
key, collection, policy and sealed value. Its dated writer certificate must
authorize the parent write and child read, not the child's ordinary write.
Verify the exact parent policy/slot, indexed atomic association, child policy,
sealed digest and binding. This is the only initializer permission exception;
an ordinary child write cannot claim it. Initial positive authority requires
that dated standing even for a reader's own signing key. Missing date or
certificate standing holds. Apply the normal signature, identity, generation,
content, padding and current-reference checks to the projection; the initializer
has no expected-version comparison to invent.

The current initial child retains its complete initializer, certificate and
dated proof for as long as it is current, beyond batch retry-proof retention.
Writer removal or renewal does not erase them. After supersession the ordinary
bounded node rules decide what must remain. The slot retains identifiers and
bindings, not every accepted parent ciphertext. A current reader checks current
parent content independently. Equal bytes in a later write, a new nonce,
deletion/recreation or recovery never become the first application again.

## 5. Current origin evidence

Every protected direct/list/conflict record view carries its complete policy
and required `origin`, either the object below or null when recovery cannot
establish even complete restrictive slot facts. Null is unavailable evidence,
never absence. A retired parent-key GET is `200` with exactly
`{"origin_tombstone":<origin object>,"account_created":<time>}` under the retained
parent read scope, with the required response context of wire 7.4.9.
It is not `404` or a current value. Forgotten children can return `404`; their
parent slot still prohibits reinitialization.

```json
{"slot":"<base64url slot bytes>","statement":{"body":"<base64url>","sig":"<base64url>"}}
```

The service signs `lp("pubky-switch/v1/record-origin-statement", identity, body)`.
Its exact body is compact JSON in this member order:

```json
{"v":1,"kind":"pubky-switch.record_origin","identity":"<pubky>","created":"<time>","identity_hash":"<b64(32)>","generation":1,"seq":1,"chain_hash":"<b64(32)>","key":"<b64(32)>","origin_key":"<b64(32)>","slot_hash":"<b64(32)>"}
```

`slot_hash = hash(lp("pubky-switch/v1/record-origin", decoded slot bytes))`.
`key` is the requested parent or child key; `origin_key` is the parent key.
They coincide for a tombstone. Account creation time, current identity document
hash and head bind the durable authenticated snapshot as for a lineage statement.
Wire 7.3 applies. The statement's creation equals the same response's
`account_created` under wire 7.4.9, including in a collection page. A cached
statement or response context is not current evidence. Child read scope
permits this metadata, never the parent ciphertext. A feed reader fetches the
required current evidence before deriving authority from the item.

Protected record proof states add `origin_key` and `origin_slot_hash` to their
revision/lineage/descriptor fields. A later restrictive slot change does not
rewrite a historical proof. Check the historical association and the separately
current statement; a historical vacant receipt cannot override initialization,
retirement or recovery. Initialized immutable facts cannot change.

## 6. Exact byte bounds and accounting

These are admission and retention constraints for protected forms, not an
assumption that every ordinary certificate already has a compact body. Measure
compact carrying/framing JSON while preserving every signed body and descriptor
byte exactly. Whitespace inside a signed body still counts through its encoded
length; never reserialize or truncate signed bytes to fit.

| Object | Maximum bytes/count |
|---|---:|
| Signed operation carrying form | 524,288 |
| Signed writer certificate carrying form | 32,872 |
| Slot payload / reserved logical bytes | 577 |
| Origin statement carrying form | 1,024 |
| Origin object | 2,048 |
| Node including operation/certificate | 558,336 |
| Required nodes, including current | 14 |
| Exact descriptor bytes | 16,384 |
| Lineage statement carrying form | 4,096 |
| Other current-view projection/proof/framing | 8,192 |
| Complete current view and required lineage/origin | 7,864,320 |
| `record_origin` export part | 2,048 |
| `record_lineage` export part | 32,768 |
| `record_lineage_node` export part | 559,360 |
| Protected `record` export part | 567,296 |

Before committing an original, initializer or later protected write, verify that
the resulting retained nodes, complete current view and export representations
all obey these bounds, including the selected writer certificate. An oversized
certificate is refused for this form, not accepted with an unencodable future
view. Retention, reconstruction, upload validation and import activation check
the same exact bytes. A size violation is `413 too_large` on a write, an
unverified/unaccounted recovery item, or `400 bad_request` on import; no partial
effect is committed. A missing required node never counts as size reduction.

The component bound is `14*558336 + 21846 + 4096 + 2048 + 8192 = 7852886`.
The descriptor's 21,846 bytes are its base64url expansion. The view bound leaves
11,434 bytes above that sum. A maximal canonical origin statement body is 489
bytes, carrying form 758; a 577-byte slot encodes to 770, making a 1,552-byte
origin object and a 1,645-byte `record_origin` part. The 32,872 certificate figure
is both the selected cap and the maximal compact current-shape calculation;
other whitespace in signed bytes does not gain an exemption. Byte encodings at
these bounds are to be covered by the implementing changes' vectors and checks.

Each distinct retained non-delete ciphertext/tag is charged once to
`record_quota_bytes`, including predecessors retained after deletion. Aliases
between capsules/slots do not double charge it; deletes charge zero. Bounded
operation/certificate/reference metadata uses the control reserve. Origin slots
add at most 57,700,000 logical bytes, excluding other metadata/index storage.
All slots reserve the maximum at allocation, so initialization cannot enlarge
that reservation. Existing updates can continue at the admission cap subject
to ordinary growth quotas; valid values are not deleted to make room.

## 7. Transfer and loss

Exports carry every allocated slot, retired and unknown included. The meta part
has required `record_origin_limit:100000` and exact `record_origin_count`.
Each slot has one part:

```json
{"part":"record_origin","origin_key":"<b64(32)>","origin":{"slot":"<b64>","statement":{"body":"<b64>","sig":"<b64>"}}}
```

These parts are sorted by decoded parent-key bytes and have no duplicate. Their
statements use the frozen snapshot, with `key == origin_key`. Current protected
record parts name `origin_key`, preserving current operation/certificate/proof
and policy; they do not duplicate the slot. Lineage and non-current node parts
are separate. Reconstruct any omitted operation or certificate from the exact
chain/app part before checking hashes, caps and the initializer permission rule.

Attached source origin evidence still required by a retained record input
travels in that complete unit under record retention 6, with its original
source statement and document association. The account's `record_origin` part
continues to describe the final frozen slot, including retired/unknown state;
it cannot replace a source input's differing required evidence. These source
units share the same non-current capacity and do not allocate another slot.

Each added part plus wire 10.3's maximum 103-byte chunk wrapper fits the hard
1 MiB chunk bound. A whole 7.5 MiB view is not one export part. An individual
part larger than a configured smaller target gets its own chunk, still within
the hard bound. Origin parts total at most 204,800,000 bytes at their hard cap.
This does not bound the rest of the account or promise that every simultaneous
resource maximum fits the receiving service's default 4 GiB import limit. The
manifest counts the complete export. Exceeding the receiving limit refuses
transfer; no subset activates and no slot is dropped to fit.

Activation requires the exact count and complete unique part set, valid frozen
source statements bound to the manifest/identity, exact decoding/hashes and all
linked record/lineage consistency. Every child requires its parent's slot even
if retired. Missing, duplicate or conflicting evidence is `409 conflict`;
malformed shapes/caps are `400 bad_request`. Account records, slots, allocation
count and recovery barrier activate together. Partial import and abort confer
no authority. After validation the next service may issue new statements but
preserves slot bytes and original references. A key change preserves them too.

Provider loss starts a new history under the signed recovery transition. Uploaded
old slot evidence is restrictive, never proof the old provider omitted nothing.
A known uploaded slot has `recovered:true`; original references remain source
references, distinct from any receiving upload application. Completion, ordinary
rewrites and cooperative moves cannot clear recovery. Valid own-writer/policy
evidence with missing slot facts may allocate unknown restrictive state; an
isolated child does not establish parent absence. Invalid unsigned assertions
allocate nothing. Additional evidence may strengthen restrictive facts, not
manufacture a clean origin.

The existing upload endpoint continues to account for record witnesses after
clean moves and key changes, under the carried barrier and authenticated active
registration (wire 7.4.14; record lineage 7). Its retained signed source document
fixes the lost-generation boundary. This record-only continuation does not
reopen admission staging or the separate claim/list recovery modes.

[Current-history record retention](record-retention.md) provides an explicit
record-only disposition for whole retained inputs from a source newer than that
original boundary through the current generation. Its source application and
current target bindings are separate. The same matching-only slot strengthening,
non-recycling allocation, byte bounds and complete per-input accounting apply;
no proofless candidate gains clean original or initializer authority. It does
not replace the source or dating rules of ordinary loss uploads.

A current record with its complete required lineage/origin is one indivisible
upload unit under the existing 16 MiB request cap. Pack whole units, fewer per
call when necessary; each protected unit is at most 7,864,320 bytes before its
small wrapper. Retired origin evidence uses its bounded part. Every retained
restrictive slot consumes an allocation in the recovering history. Capacity
overflow, failed/unreadable evidence or unknown submitted effects remain
unaccounted, holding the witness and cursor. Completion or witness removal
cannot convert recovered/unknown into clean vacant. Clean-import retry conflicts
and provider-loss stale-generation responses retain their distinct wire 6.4
meaning; an unknown old effect is not proved never applied by either a fresh
zero read or a generic conflict.

### 7.1 Standalone restrictive recovery

The `origins` member of wire 7.4.14 carries whole `record_origin` parts in the
exact form above, at most 2,048 bytes each. It does not require or synthesize a
record operation or certificate. Parts share the upload's 16 MiB body bound.
Attached origin evidence remains part of its indivisible record input.

Verify each statement against the exact identity-signed source document carried
as `lost_identity` and named by its `identity_hash`, for this account, in the
ordinary loss and retained record-witness modes. The explicitly selected
current-history mode instead uses record retention 2-3's exact source, applied
authority and newer-generation range; the complete-part and matching rules
below remain the same. In the ordinary modes, the source
document and statement must name the same positive generation, at or before the
barrier's original lost-generation bound. Thus evidence retained before a clean
move or an earlier loss can still restrict the current recovery. A current or
future generation is not eligible in the ordinary modes. The statement's service signature, snapshot,
canonical slot hash and declared parent key must agree. This standalone rule
does not date an uploaded record operation: its source-proof generation checks
remain exactly those of wire 7.4.14. The part's `origin_key` and statement's `origin_key` equal
the slot's parent key. The statement's `key` is either that parent or the exact
declared child of a known initialized slot. Thus a checked child-view statement
can preserve its parent's restrictions after the child payload is forgotten,
without obtaining parent read scope or inventing a parent-key statement.
Different source-document hashes require separate requests. A newer document
of the same generation cannot replace the exact signing context.

Process valid record and standalone inputs together in the same account
transaction. Before acknowledgment, merge their restrictive slots as follows.
Parent key, collection, policy hash and birth restriction must match. Two known
read scopes must match; an unknown scope may acquire its verified value. Unknown
form may become verified known recovered form. Two known forms must agree on
lineage, original reference, origin binding and the complete child declaration.
A matching vacant child may become initialized. Two initialized forms must agree
on every initialization reference, lineage, value hash and binding. Preserve
initialization and take the logical OR of retired/recovered flags; a newly
recovered known slot is always recovered. Compatible less informative evidence
may be represented by the stronger slot already held. Never replace known facts
with unknown or overwrite an incompatible immutable fact. An incompatible input
is refused and unaccounted, retaining the existing slot unchanged. No partial
record/slot effect from that refused input is committed.

A new restrictive slot uses the same non-recycling allocator and reservation as
Section 2.1. An existing slot consumes no second allocation. Capacity failure
leaves that whole input unaccounted. A record and a standalone part naming one
slot cannot evade the common checks or allocate it twice. Final accounting is
against the final transaction state, including every later input in the same
request, with the same exact-input meaning as `accounted_records`.

The required `accounted_origins` response array contains strictly increasing,
unique indices within this request's `origins` array. Invalid, unverifiable,
incompatible, capacity-refused or ignored parts have no index. An empty array
is required when the stage ignores them. The authenticated request ID, exact
source/head reconciliation and atomic local ticket accounting of wire 7.4.14
apply equally. An acknowledgment does not grant clean origin authority or
complete a witness by itself.

### 7.2 Discovery and retained duties

The collection listing of wire 7.4.9 includes a required `origins` array of
`record_origin` parts for every allocated parent key in that collection whose
retained parent read scope the caller holds, including unknown and retired slots
and slots without a current record. A part's statement describes the same
account snapshot as the page. The existing `records` array still omits deleted
values. Both arrays are ordered by ASCII base64url parent/record key. Pagination
uses their union of distinct keys: `after` excludes that key from both arrays,
`limit` counts each key once, and `next` is the last included key when more
remain. A key's record and origin part stay on the same page. Their combined
bytes count toward `max_page_bytes`; the first complete key is included even
when it exceeds that page target. An empty origins array is explicit. This
listing grants no read scope beyond the existing direct-view rules.

An upload that changes a standalone slot includes its parent key in
`changes.records`, even if no record exists. That signal requires an origin-aware
reread. A retired-origin answer is retained restrictive evidence, not a missing
record that clears the work. Overflow, catch-up and missed-item fallback must
finish the origin-complete collection listing before discarding its pending
reread obligation. An unavailable scope or read cannot be treated as evidence of
an absent slot. Ordinary origin and initializer record observations also retain
their checked slot evidence with the record observation.

Before releasing an observation, the client retains the complete checked part
and exact signed source identity document needed to verify its statement, in
the same durable transaction as its read progress. If these cannot be obtained
and checked, the evidence obligation remains unresolved. Retention is independent
of current record payloads and survives their replacement or removal. Whole-work
identity distinguishes record units from standalone origin parts and binds all
carried evidence and the exact source association. Snapshot, in-place restore,
request selection, ticket consumption and witness completion include both kinds
under record lineage 7; a standalone part is never encoded as an invented op.

## 8. Client submission during earlier recovery

There is one exception to upload-before-write and draining all kept batches.
The client first adopts and revalidates its signed current own identity and
verifies its actual current-generation registration. Unknown/queued registration
does not suffice. Certificate standing/scopes, revocation/departure, epoch/keys,
recovery notice/fail-stop, request/response verification, local durability and
protocol restrictions still apply.

The eligible batch contains exactly one ordinary non-delete `record.put`, no
other operation and **no cursor**, including an automatically attached deferred
cursor. Its origin policy has birth equal to the current signed own generation.
It is either a childless original satisfying Section 2.2, or an exact-current
update of a fresh authenticated clean non-retired childless origin whose actual
first application is in that current birth generation. Updates repeat the exact
policy and guard both exact reference/lineage and ordinary expected version.
Missing slot facts, deletes/put-backs, recovered values and initializers are
ineligible.

Only this batch may precede earlier-generation upload/list completion and kept
batches whose signed operations are all strictly earlier-generation operations.
Any unknown-generation pending batch, current/mixed-generation mutation,
unresolved current registration or known same-generation uncertainty about the
record retains the ordinary gate. Do not forget or relabel pending work to
qualify. Durably journal the exact new batch before sending while retaining all
old work. At most one eligible new batch is unresolved per client instance;
record CAS and origin allocation also fence other instances. Insufficient local
storage for both old and new work refuses the new write.

This changes no recovery/reconcile flag, upload duty, witness completion bit,
cursor hold or resource reservation. It sends no `records_complete`, never
advances a service cursor and never clears a stop. Only a verified applied result
proves the new record effect. A protocol may cease intending to use an older
namespace and independently reserve in the new one without claiming the old
operation never applied; it still accounts for the old outcome and reservations.
All other operations retain their gates. These puts use the ordinary operation
rate (default 3,000 per app per minute), not the control rate. The service does
not interpret counters or issue protocol publication permissions.

### 8.1 Boundary observation

When adopting a verified new own generation/recovery boundary, the client
durably records `HistoryBoundaryObserved { generation, recovery_from,
identity_hash }` from that signed document atomically with adoption. It delivers
the notification to registered protocol observers before releasing a
post-boundary protocol action, without waiting for Upload/Lists or the later
recovery-completion callback. Failed observer persistence leaves it pending;
restart redelivers until durable acknowledgment. Initial installation follows
normal initialization, without inventing a prior loss.

The notification supports local conservative invalidation and immediate duties.
It is not service authority, signer clearance, cursor acknowledgment or recovery
completion. Protocol send/admission/deny rules and all ordinary recovery duties
remain. Neither the notification nor its acknowledgment supplies origin or child
authority on its own.
