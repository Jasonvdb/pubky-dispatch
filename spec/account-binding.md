# Account creation bindings

This document is normative. It specifies signer request authority across account creation and erasure (spec 4.3, 6.1 and 12.7; wire 3.7 and 7.1-7.4). Account creation time identifies one lifetime at one service; an identity key or service key alone does not. All encodings and signature verification use wire 1 and 2.

## 1. Existing-account requests

A signer request concerning an existing account carries exactly one `Switch-Created` header: its creation time in the wire 1.6 form with exactly three fractional digits. The header is required on every signer call except `GET /v1/{id}/account` and the `create` enrollment of Section 3. It is absent on those two calls, on app calls, and on a next service's export request. A disallowed, missing, malformed, repeated, empty or non-printable value is `400 bad_request`. The public identity read remains header-independent as wire 7.4.15 specifies.

Enrollment applies Section 3's locked intent and receipt checks. Its exact completed-receipt retry may retain a takeover intent's old creation while returning the new creation that the same intent already established; it cannot apply that intent again. Every other existing-account signer call uses the common comparison below.

The ordinary request signature appends the exact `Switch-Created` text, or an empty field when absent, after `Switch-Invite-Code`:

```
lp("pubky-switch/v1/http", method, path and query, hash(body),
   Switch-Timestamp, origin, Switch-Identity, Switch-App, Switch-Cert,
   Switch-Invite-Code, Switch-Created)
```

The response's received-request representation appends `H(Switch-Created)` after `H(Switch-Signature)`. `H` is wire 7.1's presence-preserving encoding: absent is empty, present is `lp` of every raw value in received order. All eight protected headers obey the same raw-header rule. The next service's `transfer-request` signature input is unchanged; its received-request creation field is absent. The public identity read binds all eight headers as absent.

A sender records the creation binding with the pending operation before the first send. Refreshing `Switch-Timestamp` preserves that binding and the exact signed body. A restore, hand-over, authenticated conflict or discovery of another creation cannot silently retarget a pending operation. The signer resolves that operation's outcome or obtains authorization for a distinct action; neither a missing receipt nor current absence proves that an earlier call did not commit. Section 3 specifies when an explicit recovery authorization may end an enrollment-only retry continuation without resolving its remote outcome.

Under the identity lock, after authentication and a fresh judgement of the account, mark, erasure outcome and store identity, the service compares the binding with the creation that wire 7.3 assigns the account: the mark's, or the account's own where the mark is lost. A mismatch is `409 conflict`, with no `Switch-Head` and `current` an object of exactly one member, `created`: the current creation as a valid `YYYY-MM-DDTHH:MM:SS.sssZ` string (wire 1.6). This common mismatch has the same shape whether a SQL account survives or only its mark does. Its response time is outside the comparison of the requested account lifetime's committed times (wire 7.1), and the check does not stamp an account time. A known absent account remains `404 not_found` with `current.hosted` false. Unknown store or erasure outcome remains `503 unavailable`. No request-dependent stamping, sweep, enrollment, key/mark update, last-seen update or endpoint mutation precedes this check. A request queued behind erasure is judged again after it obtains the lock. The ordinary final judgement and durable-answer rules still apply.

This comparison precedes state-dependent success and the authenticated failing/bounded account's endpoint handling. An unauthenticated caller still receives only what wire 7.3 Table 2 permits. A matching binding grants no endpoint permission or exception to the recovery, retirement, frozen, staged or erasure checks. An ordinary call with a matching creation keeps wire 7.3's account verdict: a lost account receives the existing recovery notice, while a non-retired (0, 0) mark without its SQL account remains not hosted and returns `404 not_found` with `current.hosted` false. Enrollment and erasure retain their specified handling. An erasure's body `created` must equal its header; a mismatch is `400`. Its document comparison and authenticated `409` contents otherwise remain wire 7.4.16's. A signer without the binding uses Section 2 rather than an intentionally incomplete destructive request.

## 2. Authenticated account discovery

`GET /v1/{id}/account` is a signer-only read. It has no query or body. It requires the canonical identity in the path and `Switch-Identity`, one `Switch-Timestamp` and one `Switch-Signature`; `Switch-App`, `Switch-Cert`, `Switch-Invite-Code`, `Switch-Transfer` and `Switch-Created` are absent. A caller other than the identity is refused by wire 7.2. Signature, timestamp, source limits and authenticated caller limits apply, including when the identity is not hosted. The request authenticates with the identity key independently of a stored account.

The service takes the identity lock and reads the current account, mark and completed-erasure record from the same confirmed store identity. It returns a `200` observation at staged, healthy, bounded, failing or lost accounts when those sources establish the creation; it may also observe known absence. It signs no head and performs no account creation, enrollment, delivery, admission completion, hand-over, stamping, sweep or mark change. If a covered restored account or leftover mark needs deletion before a consistent read is possible, it returns `503 unavailable`; the existing erasure cleanup completes separately. An unresolved erasure attempt is unavailable, never absence. A store identity that cannot be read or changes during the observation is also unavailable.

After a rebuilt store's new identity and current records are coherently confirmed, a later discovery may describe that store's current state under these rules. The replacement inherits no observation or receipt authority from its predecessor, does not refresh or rebind a pending action, and does not resolve an unknown prior outcome. Its new identity is not proof that an identity never had an account or that a pending request did not commit. Surviving accounts whose marks were lost still follow wire 7.3's lost-mark verdict and recovery rules. A fresh observation may support a creation or mark takeover only through a distinct authorized intent satisfying Section 3.

A readable account's creation is the mark's, or its own where the mark is lost, as in wire 7.3. A surviving mark with no SQL account, including a zero mark, has a creation and is not an absence observation. `created: null` requires no surviving account or mark after completed-erasure judgement; it describes this store's current absence, not the identity's history. Contradictory or unestablished state is unavailable.

The body is one strict JSON object. Every field below is present; unknown members, omitted fields and wrong null forms are malformed. Times have exactly three fractional digits.

| Field | Type | Value |
|---|---|---|
| `v` | int | `1` |
| `kind` | string | `pubky-switch.account` |
| `identity` | pubky | the identity in the request |
| `origin` | origin | the exact request-signature origin |
| `service_key` | `b64(32)` | the current service key signing this response |
| `store_id` | `b64(16)` | the existing mark-store identity's 16 bytes; not a new per-request value |
| `created` | time or `null` | the established creation, or known current absence |
| `erased_at` | time or `null` | the latest completed erasure record, or its established absence |
| `observed_at` | time | the trusted time used for this locked observation |
| `expires_at` | time | exactly `observed_at + 300000` milliseconds |

The existing response signature authenticates the observation. Status is `200`, `Switch-Head` is absent and `Switch-Server-Time` equals the exact `observed_at` text. This call's times are outside comparison of an account's committed service times, like enrollment. Every answer to this call is headless. An error is not an observation.

A signer checks the response against the exact request it sent before retaining any field. At first use of an explicitly selected service origin it verifies with the body's `service_key`, tied to the origin by the checked HTTPS connection, as for an enrollment. With a pin it requires that pin, except within the user-authorized provider-loss or service-key-change rules already prescribed by spec 12.5-12.6. An observation does not itself change an existing pin, start recovery, establish the current identity document or authorize a pending operation at a different creation. An unpinned signer may make this read; other unpinned calls remain restricted by wire 7.1.

### 2.1 Carrying the exact signed observation

An enrollment carries the observation as this strict object, with all four fields required:

| Field | Type | Value |
|---|---|---|
| `body` | base64url | the exact successful discovery response body bytes |
| `sig` | `b64(64)` | its `Switch-Service-Signature` |
| `request_timestamp` | time | the exact original `Switch-Timestamp` text, with no fractional digits |
| `request_signature` | `b64(64)` | the exact original `Switch-Signature` value |

This is a carried HTTP response, not a signed document under another label. To verify it, decode and strictly read `body`, reconstruct `GET /v1/{identity}/account` without a query, empty request body, the body's origin, `Switch-Identity` from the body's identity, the two carried request headers and every other protected header absent. Verify the identity's original request signature over Section 1's input. Build wire 7.1's received request for that exact request, with `hash(empty)` as body field. Verify `sig` with the body's service key over:

```
lp("pubky-switch/v1/http-response", u64(200), hash(received request),
   observed_at text, empty, hash(body bytes))
```

No reserialization, omitted original request field, arbitrary received-request hash, early unread-body representation, other route/status or added head is accepted. The original request timestamp is authenticated context; it is not rechecked as the enrollment wrapper's current timestamp. Section 2.2 controls the observation's validity. The carried body, signature and original request fields are retained byte for byte with the enrollment intent.

### 2.2 Trusted validity and retention

An observation is issued only with usable trusted time as defined by wire 7.3: the authenticated sample plus elapsed monotonic time, within the maximum sample age and uncertainty. Use that trusted time itself for `observed_at` and validity, not the wall clock, the request timestamp or a possibly future account-stamped time. An unrepresentable expiry, or a relevant creation or erasure time ahead of that trusted time, is `503 unavailable`; no fresh-creation authority is minted. Missing/unusable trusted time cannot be replaced by the ordinary request timestamp fallback.

For an action that creates an account, including a mark takeover, the locked check requires usable trusted time `now` and:

```
observed_at <= now < expires_at
expires_at = observed_at + 300000 ms
```

At the exact expiry the observation is expired. There is no extra grace, including the HTTP timestamp tolerance. A future observation cannot authorize creation; while trusted time is behind it the answer is `503 unavailable`. An expired observation is `409 conflict` with `current: { "binding": "expired" }`. A malformed expiry is `400 bad_request`. A still-valid observation authorizes nothing unless its exact identity, origin, service key, store identity and erasure/creation tuple also pass Section 3. Future or unusable trusted time never grants authority by selecting a different time base.

The five-minute bound is strictly below the existing one-day erasure-record retention floor. Even allowing two authenticated samples at opposite ends of the permitted five-minute uncertainty, `300000 + 2 * 300000 < 86400000` milliseconds. Thus an observation from before a completed erasure expires before that erasure can be collected; while the record remains, its changed exact binding rejects the observation. Collection still requires the trusted-time and leftover-cleanup rules of wire 7.3 Table 3. A caller-selected future intent time cannot extend this service-authenticated expiry. An old absence cannot become fresh authority when a record is collected or the store is replaced.

## 3. Enrollment intents and locked decisions

The signed Enrollment body of wire 3.7 gains one required strict `intent` object. The object's `kind` selects exactly one form; other members, mixed forms and omitted required fields are `400 bad_request`:

| `kind` | Other members | Request creation header | Meaning |
|---|---|---|---|
| `create` | `observation` of Section 2.1 | absent | create from an authenticated absence observation (`created: null`) |
| `existing` | `created`: time | exactly that time | enroll at that same existing account; never create an account |
| `takeover` | `created`: time, `observation` of Section 2.1 | exactly that time | explicitly authorize the existing lost-database mark takeover; observation `created` is that old mark creation |

`created` uses exactly three fractional digits. The enrollment's identity and origin and any carried observation's identity and origin agree with the actual request. For a new creation or takeover in steps 3-4 below, a carried observation is signed by the current service key and names this existing mark-store identity; a different key/store/tuple is `409 conflict` with `current: { "binding": "changed" }`, not a new binding to adopt automatically. Cryptographically invalid evidence is `401 bad_signature`. Unreadable or changing store identity and an unresolved erasure outcome are `503 unavailable`, before a receipt or absence is used.

The service authenticates the request and signed enrollment, takes the identity lock, and rejudges current durable state before any request-dependent timestamp, mark write, account insertion, remembered revoked-app set or answer receipt. It then applies this order:

1. **An exact retained receipt at the same account.** A receipt associates the hash of the exact signed enrollment bytes with the creation and store identity where it was applied, and with its application result. Return that result only if that same account still exists, its associated store identity is the currently confirmed one and the durable association is established. This is a retry, not creation or another application of `revoked_apps`. An expired observation does not invalidate this receipt. The original observation need not match a newly collected erasure record or a later service key merely to read a completed result, but the account must not be covered by an erasure or an unknown outcome. The existing service-key-change answer rules may name the current key; they never change the receipt's account association or reapply the intent.
2. **`existing`.** Require an existing SQL account and a matching creation under Section 1. Apply only wire 3.7's existing-account behavior and keep its exact receipt association. With no account, do not enter either creation branch: known absence is `404`, a surviving lost-account mark gets the existing recovery notice, and an unknown verdict is unavailable. A matching old mark alone does not authorize takeover.
3. **`create`.** Require a valid unexpired observation of absence and an equal current completed-erasure binding, with neither an account nor a surviving mark. Only then use wire 7.3 Table 3's new-account procedure. Choose creation strictly after every applicable erased creation as already required. If an account or zero mark is now present without the exact receipt of step 1, answer `409 conflict` with `current: { "binding": "changed" }`; do not assume that it belongs to this intent or that the earlier send failed.
4. **`takeover`.** Require a valid unexpired observation naming the old mark creation, equal current store/erasure binding, no SQL account, and that exact readable surviving mark, not a completed-erasure leftover. Apply only the existing Table 3 takeover: retain its generation, sequence, chain hash and retirement, choose the new creation strictly above the old creation and completed erasure, and preserve its bounded/staged restrictions. A zero mark with no account also requires this explicit bound action; it is not fresh absence. With a different creation, an account now present, no surviving mark or changed erasure evidence, answer the binding conflict. No failing/bounded account or lost mark is converted into absence.

Fresh creation and takeover retain the enrollment result atomically with the account state to which it applies, before success. Existing mark-before-account and erasure-outcome ordering is unchanged. A failure, lost answer or unknown database commit is resolved using the exact retained association and existing outcome rules. Neither a zero mark alone, an absent SQL row, expired evidence nor an evicted receipt proves non-application. Receipt eviction removes the ability to return that exact result; it never authorizes the old intent at a replacement account. No challenge, nonce ledger or new durable store is introduced.

The signer durably retains the complete signed enrollment, its selected intent, original observation where present, target origin/key and any returned creation/result before dependent delivery. Wrapper timestamp refresh may not replace the observation, change intent kind, creation or body, or infer a new intent from an error. After expiry or changed state, resolving the old outcome and authorizing a distinct enrollment are separate actions. Discovery may establish the current creation after restore or hand-over, but cannot associate an old unresolved enrollment with it by itself. A new authorized recovery may select `takeover` when the current mark justifies it; it does not assert that the old send failed.

While an enrollment remains eligible for continuation, retries retain its exact signed bytes and binding. Only the user's explicit authorization of a distinct recovery (spec 12.6) may durably end that enrollment-only retry continuation while its remote outcome remains unknown. The user accepts that the earlier enrollment may have committed; ending continuation neither cancels it remotely nor declares failure or non-commit. Once ended, that enrollment cannot be retried or rebound, and a late answer cannot advance the replacement action. A resume, background retry, error, expiry or missing receipt never makes this choice. Retention for an active continuation does not require a permanent archive of enrollments whose continuations were explicitly ended.

This choice leaves all already signed documents and their version, generation, removal and revocation obligations intact, with the existing copy, trust and ownership checks and hand-over readiness. It does not end delivery or erasure uncertainty or change their rules.

## 4. Lifecycle and conformance

After a successful creation or takeover, subsequent signer requests bind the returned new creation. Delivery retries are recognized only within that bound account, before document-content retry handling. Thus a first delivery saved from an erased account cannot activate a later staged account even when both accounts use the same service key and document bytes. An old `existing` enrollment cannot recreate an erased account. A new post-erasure creation uses a newly authorized intent and a new authenticated observation of the completed erasure.

The signer's exact pending binding and signed intent survive local reloads and retry ownership changes while the continuation remains active; an enrollment-only continuation ends only as Section 3 permits. A hand-over starts only after prior operations are resolved as its existing rules require.

The authenticated backup or hand-over carries a required non-null `account_created` with `identity_doc`, with exactly three fraction digits as Section 1 requires (wire 3.12-3.13). It binds that exact document to its original account at the document's authenticated service origin, with the document's service-key context. A restore reads this binding before its first signer request and preserves it through original-document replay and subsequent delivery, including the existing first-document, `prev` and mid-recovery paths. The hand-over receiver likewise uses it for its signer reads, take-over delivery and retries. All existing pin, copy, version, generation, signer and recovery checks still apply, including the old serving-key check on a restore. The carrier proves neither service acceptance nor the outcome of an earlier pending operation. Discovery cannot replace this target with the currently hosted account; it may support a distinct authorized action under Section 3 while earlier unknown outcomes remain unresolved.

The unchanged erasure rules retain the original authorized body/binding during unknown outcomes, permit their specified authenticated document conflict handling at the same creation, and never retarget a pending erasure to a newly discovered later creation.

Conformance covers strict field presence and signed bytes, ordinary same-account success/retry, both cross-creation replays, lock acquisition after erasure, exact receipt recovery, receipt eviction and unknown outcomes, fresh post-erasure creation, marked lost-database takeover, discovery at each applicable verdict, store replacement and unresolved erasure, and validity immediately before/at/after expiry and with future/unusable trusted time. Conformance also covers required backup/hand-over creation fields, their exact grammar and document association, original-account replay through the first-document, `prev` and mid-recovery paths, and refusal to substitute a different creation. Enrollment continuation cases cover exact retries across reloads, explicit authorized termination with the remote outcome still unknown, and a late answer that cannot advance the replacement. Generated signed cases include altered creation, origin, identity, store identity, erased time, observation time/expiry, original request fields, response status/head and signatures; each rejection isolates its own rule. The generator and ordinary byte-for-byte consumers accompany the implementation; this document supplies no manually edited signed fixture bytes.
