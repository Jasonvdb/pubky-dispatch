# Configuring and running the Pubky Switch

## Running

```sh
pubky-switch --config /etc/pubky-switch/config.toml
pubky-switch check-config --config /etc/pubky-switch/config.toml
```

- `run`, the default command, starts the service. It needs a database (`database.url` or `PUBKY_SWITCH_DATABASE_URL`) and a key store (`keys.path`), applies pending schema migrations, and stops on `SIGTERM` or Ctrl-C.
- `check-config` checks a file and prints it with every default written out.
- `check-marks` judges every account against its mark, as the service does, and lists the accounts and marks that need attention after a database restore or before a failover; it writes nothing (Checking marks after a restore, below).
- `retire <identity> <generation>` retires a lost generation of one identity, one-way, so its notice says the loss is permanent; it runs only while the service is stopped (Retiring a generation, below).
- `--config` may also be given as `PUBKY_SWITCH_CONFIG`. Without a file, every setting takes its default.

### Container

```sh
docker build -t pubky-switch .
docker run -p 127.0.0.1:9090:9090 \
  -e PUBKY_SWITCH_DATABASE_URL=postgres://switch:...@db/switch \
  -v switch-keys:/var/lib/pubky-switch/keys \
  pubky-switch
```

The image runs as a non-root user. Its default configuration, [`docker/config.toml`](../docker/config.toml), listens on every interface inside the container and keeps the key store in the `/var/lib/pubky-switch/keys` volume; mount your own file at `/etc/pubky-switch/config.toml` to change it.

## The configuration file

The file is TOML. Every section and setting is optional, and unknown settings are refused, so a misspelt name fails at start. [`config.example.toml`](../config.example.toml) lists every setting with its default.

### `[admin]`

The operator listener.

| Setting | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:9090` | address of the operator listener |

It serves:

- `GET /health/live`: `200` while the process runs.
- `GET /health/ready`: `200` when every readiness check passes, `503` otherwise, with a JSON body `{ "ready", "checks", "trusted_time" }`. Missing trusted time is reported, but doesn't make the service unready: it still serves everything that doesn't depend on time. With `"trusted_time": false` it refuses, with `503 unavailable`, what does (Switch spec 10.1): a batch whose outcome depends on the service's time, and an append, a directory read or a peer delivery that only an invite code admits. `pubky_switch_time_refusals_total` counts them.
- `GET /metrics`: metrics in the Prometheus text format.

The listener isn't authenticated. Keep it on a private network.

### `[server]`

The API listener.

| Setting | Default | Meaning |
|---|---|---|
| `origin` | none | the switch origin, exactly as `identity.json` names it in `inbox.url`: `https://` and the host, with an optional port, no path or trailing slash. Requests sign it (Switch wire 7.1). Without it the API listener stays off |
| `listen` | `127.0.0.1:8080` | address of the API listener; terminate TLS in front of it |
| `allow_insecure_origin` | `false` | allow an `http://` origin, for development only |
| `proxy.trusted` | `[]` | reverse proxies whose `proxy.header` the service believes, as addresses or networks such as `10.0.0.0/8` |
| `proxy.header` | `x-forwarded-for` | the header those proxies append the client's address to |

A request's network source, which the failed-authentication and public-read limits count by, is an IPv4 address or an IPv6 /64 (Switch wire 7.2). Behind a trusted proxy it is the nearest address in the header that isn't a trusted proxy; otherwise it is the connection's peer.

Served so far: `POST /v1/enroll`; `PUT /v1/{id}/identity` and the public `GET /v1/{id}/identity`; `POST /v1/{id}/ops`; `GET /v1/{id}/feed`; `GET /v1/{id}/claims/{key}`; `GET /v1/{id}/apps` and `POST /v1/{id}/apps/{app_id}/revoke`; `PUT /v1/{id}/peers`; `POST /v1/{id}/inbox`; `GET /v1/{id}/directory`; `GET` and `POST /v1/{id}/apps/{app_id}/keys`; `POST /v1/{id}/apps/{app_id}/leave`; `GET /v1/{id}/allow`; `GET /v1/{id}/records/{key}` and `GET /v1/{id}/records`; `POST`, `GET` and `DELETE /v1/{id}/connect`; `POST /v1/{id}/recovery/admission` and `POST /v1/{id}/recovery/upload`; `PUT` and `GET /v1/{id}/handover`; `POST /v1/{id}/erase`; `PUT /v1/{id}/push`, whose registrations receive webhooks for notifying entries and for connect requests when the account enables them. The freeze, the export and the import (the cooperative move) are answered `503 unavailable` until they land. `GET /v1/{id}/apps` fills `recovery` once the account has recovered from a provider loss. The sweeps of Switch wire 9.1 run once a minute at a request to the account, with one part not yet: forgetting a deleted key doesn't check that the account isn't frozen, since freezes aren't served (it comes with the cooperative move).

### `[log]`

| Setting | Default | Meaning |
|---|---|---|
| `format` | `json` | `json`, one object per line, or `text` |
| `filter` | `info,sqlx::postgres::notice=warn` | a `tracing` filter, such as `info,pubky_switch=debug`; `PUBKY_SWITCH_LOG` overrides it |

Logs never hold message content: no envelopes, sealed values, record bodies, signatures or keys.

### `[limits]`

Limits, quotas and rates, under their Switch wire 9.2 names, with the wire format's defaults. The defaults are for one identity on a shared service; an operator may raise them. The service refuses a file that breaks the wire format's rules:

- `app_limit` is between 1 and 255;
- `max_claim_age_ms` (400 days) and `batch_proofs_ms` (30 days) may be raised but not lowered, since apps rely on them;
- `claim_share_percent` and `sender_share_percent` are between 1 and 100;
- the other limits are at least 1.

**Chain stub retention** (Switch wire 7.4.4 "Checkpoints", 9.1) is on by default. At each request to an account with trusted time from a verified caller, the service signs a checkpoint and drops the chain stubs behind it that no current app needs. A stub goes once every current app's cursor has passed it or once it is `cursor_hold_ms` old (30 days). It is never cut inside a batch, the head never goes, and nothing goes while the account's state is behind its mark. A checkpoint is signed once `checkpoint_behind` stubs (1,000) may go past the last one, at the newest of them, or, with `checkpoint_at_head`, at the head once that many chain items were added since. The batch records whose proofs are gone go with their stubs. The settings:

- `chain_retention = false` keeps every stub and signs no checkpoint;
- `checkpoint_behind` and `cursor_hold_ms` set the two thresholds;
- `retention_per_request` (1,000) bounds the work: one request reads at most that many stubs, without their documents, and drops and deletes at most that many. It must be at least `checkpoint_behind` and 8, a batch's most items, so a batch at the start of a request's read is always whole in it.

Retention catches up a bounded amount at a time. At an account with a long chain, the first request with trusted time signs a checkpoint once 1,000 of its oldest stubs may go. It then drops those stubs, and each later request drops the next ones, oldest first, once `checkpoint_behind` more may go, until it reaches stubs a current app still needs. Those are the stubs past the lowest cursor of a listed app that isn't revoked or departed, and every stub while a registered app hasn't moved its cursor, as long as they are younger than 30 days. What goes is each stub's envelope and chain hash, and the item's document where it was still kept. Current records, claims and key bundle parts keep their own operations and proofs, so they read the same. An app reading from behind the oldest kept stub gets pages that carry the checkpoint and show no stub before it, and it continues as Switch wire 7.4.4 says: from the checkpoint, or in reconcile mode.

A configuration that raised `checkpoint_behind` above 1,000 must raise `retention_per_request` with it: the service refuses to start otherwise, naming `retention_per_request`.

Values the wire format fixes aren't configurable: the envelope cap (64 KiB), the sealed value cap (256 KiB), 8 entries per batch, 128 hand-over parts (a 12 MiB `PUT /handover` body), 1 MiB export chunks, feed pages of at most 500 items and 1000 positions, the 25-second long-poll and the 5-minute timestamp window.

### `[trusted_time]`

Trusted time (Switch spec 10.1, Switch wire 7.3).

| Setting | Default | Meaning |
|---|---|---|
| `required` | `true` | without trusted time, refuse what depends on time with `503 unavailable`; turn off only for development, where the wall clock is taken as trusted |
| `drift_ppm` | `100` | the monotonic clock's drift bound, in parts per million |
| `max_sample_age_ms` | `86400000` (24 hours) | the oldest sample that still gives trusted time |
| `max_uncertainty_ms` | `300000` (5 minutes) | the largest uncertainty trusted time may have |
| `max_disagreement_ms` | `300000` (5 minutes) | how far the wall clock may be from trusted time before the service uses trusted time and alerts |
| `sample_interval_ms` | `900000` (15 minutes) | how often the service samples its time source; at most an hour |
| `retry_interval_ms` | `60000` | how long it waits after a failed sample |

Without trusted time the service serves reads and everything else that doesn't depend on time, and refuses the rest. The `pubky_switch_trusted_time_available` metric shows whether it has trusted time, and `pubky_switch_time_disagreement_alerts_total` counts the times its wall clock disagreed with trusted time.

#### `[trusted_time.roughtime]`

The service samples trusted time from Roughtime servers (RFC 10049), asking all of them at once over UDP.

| Setting | Default | Meaning |
|---|---|---|
| `servers` | three public servers, listed in [`config.example.toml`](../config.example.toml) | each `{ name, address = "host:port", public_key = base64 Ed25519 key }`; an empty list means no time source |
| `min_agreeing` | `2` | how many checked answers must agree for a sample; at most the number of servers |
| `timeout_ms` | `2000` | how long to wait for one server's answer |
| `attempts` | `2` | how many times to ask one server per sample, each with a fresh nonce; at most 5 |
| `alert_after_ms` | `3600000` (1 hour) | how long a server may keep failing before the service alerts |

Every answer is checked before it counts:

- its version is one the request offered, RFC 10049 version 1 or the earlier draft `0x8000000c`;
- its nonce is the request's;
- the server's long-term key signed the delegation, and the delegated key signed the answer;
- the Merkle path leads from the request to the signed root;
- the midpoint lies within the delegation's validity.

Each checked answer vouches that true time lies within its midpoint plus or minus its radius. The sample is the window where at least `min_agreeing` of those intervals overlap. So a minority of wrong or hostile servers can't move it, and a server that disagrees with the others is logged. The sample's uncertainty is half that window plus the time the queries took.

Choose servers run by independent operators, and review the list before production: the public keys are pinned here, and a server that rotates its long-term key stops counting until the key is updated.

**Server health.** Every answer is counted by outcome in `pubky_switch_roughtime_answers_total{server,result}`:

- `verified`;
- `refused`, an answer that arrived and failed a check;
- `timeout`;
- `unreachable`.

When a server's samples keep failing for `alert_after_ms`, the service raises one alert:

- an `error` log line with `alert = "roughtime_server_failing"`, the server and the outcome;
- the gauge `pubky_switch_roughtime_server_alert{server}` set to 1;
- `pubky_switch_roughtime_alerts_total{server}` counted.

The alert clears when the server is verified again. A refused server most often rotated its long-term key: check its published key and update the pinned one. Act on the alert while the other servers still agree, before agreement is lost. A Prometheus rule:

```yaml
- alert: PubkySwitchRoughtimeServerFailing
  expr: pubky_switch_roughtime_server_alert == 1
  annotations:
    summary: "Roughtime server {{ $labels.server }} has failed for over an hour"
- alert: PubkySwitchNoTrustedTime
  expr: pubky_switch_trusted_time_available == 0
  for: 5m
- alert: PubkySwitchStateBehindMark
  expr: increase(pubky_switch_mark_refusals_total[5m]) > 0
  annotations:
    summary: "An account answers the recovery notice: state signed for it was lost"
```

The last rule fires on any request answered with the recovery notice, `503 recovery_required` (Switch wire 7.6): the account's state is behind its mark or beside it, its mark is lost, or its mark bounds it (No restore and continue, below). The service also writes an `error` log line with `alert = "behind_mark"`, the account and the notice's reason, once for each account while the process runs, for the first 1,024 accounts.

### `[database]`

PostgreSQL 14 or later. The service database role needs the `TEMPORARY` database privilege. Each writing connection uses a temporary table to compare the first and last values of the rows a request touches. Space usage grows with the rows touched in that transaction. PostgreSQL clears these entries at commit.

| Setting | Default | Meaning |
|---|---|---|
| `url` | none | the connection URL; `PUBKY_SWITCH_DATABASE_URL` overrides it, and keeps the password out of the file |
| `max_connections` | `16` | most connections in the request pool. The keyed section that signs an answer once its request's transaction has ended (a commit, or a refusal before the lock) takes one of them for a moment, so a request uses up to two in turn, never two at once. The first goes back to the pool only after sqlx's return-to-pool check, a ping, so a keyed section with every other connection taken may wait that one round trip. The service also opens two more, outside the pool: one for the change listener that wakes feed long-polls, and one that holds the database for the one process (Topology, below). With `snapshot_readers`, size PostgreSQL's `max_connections` for `max_connections + snapshot_readers + 2` |
| `acquire_timeout_ms` | `5000` | how long a request waits for a free connection |
| `lock_timeout_ms` | `10000` | how long a request waits for its account's lock before it gives up with `503 unavailable`; also how long an enrollment's account creation waits for an erasure of the identity still committing, and how long a push key's owed row waits for a start or a sweep holding it, each answered `503 unavailable` past it |
| `migrate_on_start` | `true` | apply pending schema migrations at start, once the process holds the database (Topology, below) |
| `snapshot_readers` | `4` | most reads at once that run after the account's lock on a snapshot of the state under it (`GET /allow`, a `GET /records` page), each on a connection of its own on top of `max_connections`; a request waits for one before it takes the lock |
| `connect_retry_ms` | `30000` | how long the service keeps trying to reach the database at start, while it refuses connections or is still starting up, before it exits. It covers the request pool only: the change listener connects once the pool is up, without this retry, and a failure there stops the service |

`divergent_uploads` bounds each record's uploads by `limits.max_divergent_uploads` in code, not by a `CHECK`, since the limit is configurable (Switch wire 9.2); an export carries at most 8 for a record (10.3), so with a value above 8 a record can hold more than the next service's import takes.

### `[push]`

Push (Switch wire 8).

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `true` | take push registrations (`PUT /v1/{id}/push`) and send webhooks; off, every registration is answered `400`, as a service that sends no pushes answers (Switch wire 8.1), and nothing is queued or sent; rows queued while it was on wait, and go unsent once their minute has passed |
| `concurrency` | `16` | the most webhooks the service sends at once; 0 is taken as 1. One account has at most 8 in flight at once, so keep it above 8 for one account's slow relay to leave room for the others |

The service keeps each own app's registration: its relay URL, at most 8 handles and a push key the service mints for it. An account's apps hold at most 8 handles at one relay host between them: a list of handles past that is answered `400`, since an entry sends at most 8 webhooks toward one host. The relay URL must be `https://` on port 443 without user info, and its host must resolve only to public addresses, which the service checks with its system resolver at each registration, within 5 seconds.

A newly kept connect request queues webhooks in its transaction when `policy.connect_requests.push` is on. Each current app with `lists.read` gets one per registered handle, at most once per app in 60 seconds of service time. The same delivery limits apply to both kinds of wake-up.

**Delivery** (Switch wire 8.2). A `notify` entry queues one webhook per handle of each target app's registration (at most 8 toward one relay host, as registration keeps them) in the append's transaction; delivery starts after commit. The queue is timed by the database's clock, never the service host's: when a row was queued, when it is due, its lease and its minute, so a failover to a host whose clock differs changes none of them; each webhook carries the trusted service time at sending. A row is claimed with `FOR UPDATE SKIP LOCKED` and leased for 30 seconds, and its attempt ends within 10 seconds of the claim, so one attempt sends it at a time. That needs the database's clock not to step (slew it, as NTP does): a step forward of more than 20 seconds makes leased rows due while their attempts run, so one row can be sent twice at once, and a step past a minute drops every queued row unsent. A claim counts each account's rows in flight once, reading the due rows and those in flight, and is cut off after 2 seconds (`statement_timeout`), so no claim holds the others' turn past an attempt's time to send. A claim takes about 20 ms at 25,000 queued rows and 60 ms at 100,000, but a queue of about 2,000,000 due rows makes every claim reach its 2 seconds: then nothing is sent for any account, the log shows a warning `push deliveries: claiming rows` at every claim and `pubky_switch_push_webhooks_total` stops growing. It recovers on its own: rows past their minute go each second whether or not a claim succeeds, so the claims are quick again within about a minute of the queue's growth stopping. A service that stops mid-attempt (a crash, a kill) leaves its row to be claimed again when the lease ends: the attempt counts as one of the 3, and a webhook the relay took just before is sent again, so delivery is at least once. Attempts run as a stream of at most `concurrency`, so a relay that never answers holds one slot and the next due row takes each slot that frees; one account has at most 8 rows in flight at once, and a free slot goes to the account with the fewest in flight first, the oldest row breaking ties. That bounds what accounts whose relays never answer take, not how many such accounts there are: with about 190 of them, the service at 16 slots can serve a third account's webhook past its minute; enrolling an account is what bounds that. Within an account, one app whose relay never answers takes the account's 8 slots, so its other apps' webhooks wait behind it. Each attempt signs a fresh body (`ts` the time sent, a new nonce) with the registration's push key, under a share lock on the registration that waits at most 1 second, so a replacement or a removal waits for the signature and the key store deletes no key that is signing; at most a quarter of `database.max_connections` attempts (at least one) hold a registration at once, and the queue's own statements (the claims, the drops, the settles) take one connection more, so with `max_connections` at 4 or more requests keep the rest of the pool. Attempts keep running while the service waits on those statements. What comes before the connection has until 5 seconds after the claim, and past that the webhook isn't sent and the attempt fails. The connection resolves the relay's host again, refuses it if any address isn't public, and connects to an address it checked, with TLS checking the host name; it follows no redirect, and has 5 seconds. A 2xx answer is a delivery. Anything else is retried 20 seconds later, at most 3 attempts, each claimed within a minute of the entry or connect request, so the last ends at most 70 seconds after it; then the row goes. A row whose registration no longer names its push key or handle, whose key is owed deleting, or whose account no longer serves here (its newest `identity.json` names another service) goes unsent; the registration stays as it is. Without trusted time nothing is sent, but rows are still queued, sent once trusted time is back within their minute, and dropped once past it. Rows go with their registration, at a replacement, and when their handle leaves the list. The queue is bounded by time: every row goes within about a minute of its entry, with or without trusted time, so it holds at most 8 rows per app for each `notify` entry of the last minute, which `limits.notify_per_min` bounds per sender identity, plus at most 8 per app for each eligible connect wake-up.

Neither relay URLs, handles nor keys are logged: delivery logs counts and failure kinds (`unresolved`, `refused`, `timeout`, `connect`, `redirect`, `status`, `late`, `internal`) only, and `pubky_switch_push_webhooks_total` counts attempts by `result` (`delivered` or a failure kind). The HTTP client's own debug logs name the hosts it connects to: keep `reqwest` and `hyper_util` at `info` or above in `log.filter`.

### `[keys]`

| Setting | Default | Meaning |
|---|---|---|
| `path` | none | the directory of the key store |
| `backup_retention_days` | none | the age in days of the oldest database backup kept; the mark store keeps each erasure's record that long, and unset keeps it for good (Erasure and restores, below) |

## Storage and durability

The service keeps its state in two places, and they are backed up differently.

- **The database** holds every account's state. Every request to an account runs in one transaction that locks the identity, then the account, so one account's operations are serialized, and a request either commits whole or leaves no trace. An enrollment holds the identity's lock from the mark's write through the account's creation, and an erasure from its record through the deletion, so the two never interleave. An answer carrying a `seq`, a transition proof or a signed head goes out only once its commit is durable (Switch spec 6.5). The service refuses a database with `fsync` off or `synchronous_commit` off, and runs its transactions at READ COMMITTED whatever isolation level the database gives new sessions. With synchronous replicas, use `synchronous_commit = on` or `remote_apply`, so a commit is durable on every replica that could be promoted; never promote an asynchronous replica to serve writes.
- **The key store** holds the **service key**, the one key the service signs every answer with (Switch wire 7.1), and one push key for each push registration (Switch wire 8.1). Beside it, in `accounts/`, lies the **mark store**: for each identity the service holds an account for, its mark, the newest head it signed for it, the service key the account is answered with, and the account's creation time; the retirements of generations; the completed records of erasures and their pending attempts; and the store's own identity record, which covers them together (Switch wire 7.3, "Accounts and marks", "The store"). A push key signs only its registration's webhooks; the database holds its public half and its ID. An app holds at most one registration, so the key store holds at most `limits.app_limit` push keys per account (32 by default), times the accounts, plus those of the requests under way: a key a start minted and no registration took, or one a request let go, is deleted when the request ends, even when its client hangs up first. A push key the service lets go, at a replacement, when its app stops being current, at a recovery in place or at an erasure, is owed deleting in the same transaction and deleted after the commit; one minted for a start is owed deleting before it is generated, until the committed registration names it, so a failure or a crash leaves no key behind for good: one whose deletion failed goes at the next sweep and at start. Keep the key store on a disk that database backups don't cover, and back it up as "Backing up and restoring the key store", below, says: losing the service key loses the key every client pinned. Every state is judged against its mark at every request (Switch wire 7.3, Table 1), so after a database restore the accounts whose state went back answer the recovery notice instead of serving a history that lost acknowledged writes. The layout under `keys.path`:
  - `service-key`: the service key's secret seed, made at the first start;
  - `keys/<id>`: the push keys;
  - `accounts/store-id`, `accounts/marks/<identity>`, `accounts/retired/<identity>.<generation>`, `accounts/erasures/<identity>`, `accounts/erasure-attempts/<identity>`: the marks, retirements, completed erasures and unresolved erasure attempts;
  - `lock`: the one-process lock (Topology, below).
- **Erasure and restores.** An erasure records its authenticated attempt in the mark store before deletion, commits the deletion and its exact outcome receipt together in PostgreSQL, then publishes a completed erasure record in the mark store before answering success (Switch wire 7.3, Table 3). An attempt alone never authorizes deletion or a not-hosted confirmation. A restart reconciles matching receipts; a definitive rejection withdraws the attempt, while a missing or uncertain outcome remains `503 unavailable`, without a head. Neither account presence nor absence resolves uncertainty after a restore. The signer can resolve it with a fresh authenticated erasure that repeats the current creation-time and document-hash checks; an absent account is bound by the pending attempt. No operator approval is needed. The receipt is removed after the attempt is durably resolved; failed receipt cleanup is retried in bounded pages at startup. Keep pending attempts with the mark store, outside database backups, just like completed records. A database restored from a backup taken before an erasure brings the account back; the service erases it again before anything is served or signed for it: at start, before the API listener opens, for every identity an erasure's record names, and at every request for the identity, its enrollment included, and before a queued webhook of it is signed, so one restored under a running service goes too. Only an account created at or before the erasure's record is erased again: an enrollment after an erasure creates its account, and its mark, later than the record. A mark the erasure left behind, at a crash between the deletion and the mark's, is deleted at the next request for the identity or at start. Set `keys.backup_retention_days` to the age of the oldest database backup you keep, with a margin: above the age at which your backup job actually deletes a backup, and counting WAL archives kept for point-in-time recovery as backups. The mark store forgets an erasure's record that much later, and never less than a day after it, by trusted time, at start and at each erasure, once the marks it covers are gone; 0 is refused. Keep every backup younger than that, or a restore from an older one serves an erased account again. Unset, the mark store keeps every erasure's record for good: it then grows by one small file per erased identity, all read when the service starts and held in memory. A store rebuilt after its loss holds no record either: an erased account a later restore brings back then fails stop as one that lost its mark, never serves, and stays until its signer erases it again (Switch wire 7.3, under Table 1).
- **Backing up and restoring the key store.** Its parts are treated differently, so that no restore can quietly undo a mark or an erasure. Restore with the service stopped, and only by merging, never by putting an older copy in place of the directory:
  - **The service key** (`service-key`): back it up, encrypted, once; it never changes. Without it the service makes a new key at its next start, which no client has pinned: every account then answers under a key its apps refuse, as after a service key change (Switch spec 12.5). Copy it back before the service starts.
  - **Push keys** (`keys/`): back them up with the service key. To restore, copy back a missing key file only if the database names it as a push registration's; never one the database no longer names, which a request deleted or still owes deleting, and never in place of a file that is there.
  - **The mark store** (`accounts/`: the marks, the retirements and the erasures' records) is never restored from a backup: it lies apart from the state a backup restores (Switch wire 7.3, "The store"). A restored mark is older than the one it replaces, and an older mark restored together with an older database passes every check: the very rollback the mark is there to catch; erasures' records restored older forget erasures. `accounts/` lies inside `keys.path`, so a snapshot of the key store's volume rolls it back with the keys: mount a volume of its own at `<keys.path>/accounts` (or make it a symbolic link to a directory on one) that has no snapshot restore, is replicated synchronously if replicated, and is left out of the key store's backups. Make the service depend on the volume's own mount point: with systemd, name it in `RequiresMountsFor=` (systemd does not follow a symbolic link, so name the link's target). A file in `accounts/` that no writer makes, in name or content (a stray file such as `.DS_Store` included, or a retirement of generation 0), makes the mark store unreadable, apart from a mark file that doesn't read as a mark, which is a lost mark: every account then answers `503 unavailable` until the file is moved out or fixed. An unmounted or emptied `accounts/` has no `store-id`, or a new one: the service then can't read the mark store, and answers every account `503 unavailable` while it can't (Switch wire 7.3, Table 2), or, for a store rebuilt with a new identity, finds every account's mark lost, and every account answers the recovery notice `mark_lost` until its signer starts a new generation (Switch spec 12.6). The service never creates `accounts/` over one that exists.

### Topology

One process serves: the service runs as a single active process on its database and its key store, and nothing else writes to either. It enforces this at start: it takes an exclusive lock on `<keys.path>/lock` before it reads the key store, and a session-level advisory lock in the database, held on a connection of its own, before it migrates or serves anything. A second process on the same key store refuses to start at once.

**The database lock.** The service never terminates a database backend, its own or another's. Instead the lock's session asks the server to close it soon after its client is gone, so its lock goes with it:

- `idle_session_timeout` 15 s: a session whose client sends nothing, such as one whose connection a network fault froze, is closed 15 seconds after its last statement ended;
- over TCP, keepalives after 5 quiet seconds, one a second, up to 15, with `tcp_user_timeout` 15 s: on Linux a session whose peer stopped answering, keepalives or data, is closed about 15 seconds after it last heard from it; a server on another system ignores the user timeout and closes it on the keepalives, after about 20 seconds. Over a Unix socket these don't apply (they read 0); the socket of a process that is gone closes at once, and the idle close covers one that sends nothing;
- `statement_timeout` 5 s.

The service asks its session every 5 seconds whether it still holds the lock, so a live session is never idle for long. An answer confirms the lock only as of the moment its check was sent. The service stops, with an `error` log line, at the first check that gets no answer within what is left of 10 seconds since the last confirmed check was sent, or finds the lock gone (a database restart, a failover), or that starts, or gets its answer, more than 10 seconds after it: the lock may have been free in that gap and another process may have held it, so the service doesn't take it again and serve on. Time is read on two clocks, and a gap on either counts: the monotonic clock sees a stalled or stopped process; the wall clock also sees a system suspend, a stopped VM or a restored snapshot, once the host has set it again. A wall clock set forward only stops a healthy service, the safe direction; one set back is ignored. So, while its timers run, it serves without a confirmed lock for at most 10 seconds, and the server closes a session that stopped answering only after that, at 15 seconds: another process can't take the lock from a session of a process still serving. Run the service under a supervisor that starts it again, such as systemd with `Restart=on-failure`: a start waits up to 25 seconds for the lock, longer than the server takes to close an earlier run's session, and then refuses, naming the session that holds it (its backend pid, address and start time), saying that the database didn't answer, or with the database's error. When the service stops it exits still holding the lock, if its session lives, so another process can't take it while this one could still answer.

What this needs, and what it can't tell apart:

- PostgreSQL 14 or later (`idle_session_timeout`), over TCP or a Unix socket (above).
- A direct connection to PostgreSQL, or a pooler in session mode: a pooler in transaction mode hands a session's statements to any server connection, so the lock no longer belongs to one session, and two processes could both hold it.
- After a database restart or a failover another process can take the lock at once, and this one stops at its next check: the two serve together for up to 10 seconds. A failover must stop or fence the old primary first: a process whose checks still reach an old primary that runs on keeps its lock there.
- A paused process can't run its checks. When it resumes, it is stopped by the first of its timers that fires: at once for a pause its monotonic clock counted (a stopped process, a stalled runtime), and within one check, 5 seconds, for one only the wall clock counted (a system suspend, a stopped VM). Until then it serves, new requests included, while another process may hold the lock by then. A pause the wall clock doesn't show either, such as a restored snapshot whose clock the host hasn't set again yet, is caught only by the checks: within 10 seconds.
- A copy of a running process, such as a restored snapshot of its host, has no usable lock connection of its own: it stops within 10 seconds of starting to run (at its first check when the server refuses its connection at once; when its packets are dropped and its clocks show no gap, when that check gets no answer), serving new requests until then, and its restart finds the original's session holding the lock and is refused. A copy that keeps the original's address, its TCP connection and its clocks in step can't be told apart from the original by any session lock.
- A start can be refused once by its own leftover session: a try that timed out after it was granted the lock leaves a session that holds it until the server closes it. The next start, after the supervisor's restart, takes the lock.
- The key store's lock is taken on the directory at start: never replace or rename `keys.path` under a running process.

The supported deployment:
- **The database** with a synchronous standby (`synchronous_commit = on` or `remote_apply`, so a commit is durable on every node that could be promoted); never an asynchronous replica promoted to serve writes (Storage and durability, above).
- **The key store** on a volume of its own, attached to the host that runs the process. On failover, stop the old process (or make sure its host is down), move the key store's volume to the new host, and start the process there; the locks refuse a start while the old process still holds them.
- **One process, no replicas of it**: requests, the sweeps and the push worker all run in it. Scale it up, not out.

**The key store's storage**, as a baseline for a first deployment:
- a dedicated volume, mounted only on the service's host and never shared between hosts (a network file system's locks can't be trusted to keep two processes apart);
- encrypted at rest by the platform, such as the provider's volume encryption or LUKS, with the encryption key outside the volume;
- the directory owned by the service's user, with the permissions the service creates: `0700` for its directories and `0600` for its files, readable by no one else;
- left out of the host's general backups and snapshots; the key store is backed up on its own (Storage and durability, above).

The service holds no per-account key in a KMS: the keys are files on that volume, read into memory by the one process.

### No restore and continue

Restoring a database backup, failing over to a replica that may lag, or replaying an incomplete log is a loss of committed state (Switch spec 6.5). The service never continues from it under the same generation:

1. The marks stop the affected accounts on their own, and the readiness answer stays up for the others: their requests answer the recovery notice, `503 recovery_required`, with the generation and the reason (`behind`, `fork`, `mark_lost`; Switch wire 7.6).
2. Find them with `pubky-switch check-marks` (Checking marks after a restore, below).
3. Bring back a state at or past every mark if one exists: restore a newer backup, or fail over to a database that holds it (Choosing a database to fail over to, below), and the accounts serve again. For each account where none exists, retire the lost generation (Retiring a generation, below), so its notice says the loss is permanent.
4. Tell their users, by whatever means you reach them outside the service, that a provider loss must be declared. Their signers see the notice, and declare it here or at another service: the account starts a new generation, under the same service key. The notice is how they learn it; a note sent any other way is optional context that starts nothing.
5. Never serve the lost generation again.

Database backups are for disaster recovery only: after a restore, every account whose state went back takes the steps above.

### Checking marks after a restore

`pubky-switch check-marks [--replica <url>] [--all]` finds the accounts of step 2 above. It reads the configuration file as the service does, and then, per account, its mark, then its chain head, generation, creation time and held `identity.json` from the database, the service key and the mark store's erasures' records from `keys.path`, and judges them as the service does at a request (Switch wire 7.3, Table 1). It writes nothing: the database is read on one connection whose session is read only (so it also works against a hot standby), with no durability check, no migration and no instance lock, and the key store is read without creating, locking or changing a file. It can run beside the running service: a mark moves only after its head is committed, and the check reads each mark before its head, so a running service never shows as `behind`. After the accounts it judges every mark that no account has. It needs `server.origin` set, and fails without it: the origin tells the serving accounts.

Each line gets one state:

| State | Meaning |
|---|---|
| `healthy` | the state is at or past the mark |
| `staged` | a staged account at its (0, 0) mark |
| `bounded` | a staged account holding no chain, whose mark records a head |
| `behind` | the state is behind the mark: of an earlier generation, at a lower `seq` in the same generation, or at a lower count in the selected account lifetime (`head_count` below `mark_count`): a write the service acknowledged is missing, a chain item or any other, such as an inbox entry, a cursor move or a peer's `identity.json` |
| `fork` | the chain hash disagrees at the marked position, or the account lacks the matching tag at `mark_count`. A database can report `fork` even when its `head_count` is higher. Choose a database that retains the acknowledged history. |
| `mark_lost` | the account's mark is missing or doesn't read as a mark |
| `unknown` | the account lifetime cannot be determined, for example when a mark is unreadable and the database has no account for it. Keep the mark in place. Check the authoritative mark store and rerun `check-marks` against a database that holds the account before promoting a replica. |
| `lost` | a mark that records something acknowledged, a head or a count above 0, with no account and no erasure's record covering it: the database lost the account |
| `leftover` | a mark an erasure's record covers, with no account; the service deletes it |
| `erased_again` | an account created at or before an erasure's record; the service erases it again |

`healthy` and `staged` need no attention; every other state does, serving or not, since a database to fail over to must hold what the service signed for every account.

A healthy account can have committed writes waiting for its mark to advance. The database retains up to 1,024 newer tags. At that limit a request that would record another change returns `503 unavailable` and rolls back. Once the authoritative mark store is writable, a public `GET /v1/{id}/identity` on the healthy account covers its committed position. Retry the write. The next counted commit keeps the tag at the covered position and discards older ones.

It prints JSON lines: one object per line that needs attention (every one with `--all`), with `account`, `hosted`, `serving`, `state`, the notice's `generation` and `permanent` where it gives one, `retired` (the generations retired for the identity, ascending), `head_seq` and `mark_seq`, `head_count` and `mark_count`, and `head_tag` and `mark_tag` (the counts' tags, in hex); then one `{"summary": ...}` line with the database read (`configured` or `replica`), the number of accounts, of serving ones, of lines that need attention, and of each state. It prints no key material and no document. The exit code is 0 when nothing needs attention, 2 when something does, and 1 when the check itself failed (the reason on stderr).

**Choosing a database to fail over to.** `--replica <url>` (or `PUBKY_SWITCH_REPLICA_URL`) checks the same key store against that database instead of the configured one. Prefer the variable when the URL holds a password: a command line is visible to other users of the host. A standby still applying the primary's log can read as `behind` or `lost` until it has caught up: run the check again once it has, or once the primary has stopped. An exit code of 0 means the candidate passed every account's mark check, including ordinary writes acknowledged for healthy accounts (Switch spec 6.5). Check the recovery-enrollment and webhook limitations before resuming either operation after a restore. See [Known issues](known-issues.md). The accounts a candidate leaves behind need their signers to start a new generation (Switch spec 12.6), as in the steps above; pick the candidate that leaves none, or the fewest.

### Retiring a generation

`pubky-switch retire <identity> <generation>` records that the generation of one identity is lost for good (Switch spec 6.5, "Retiring a generation"). Until then a failing account's notice isn't permanent: the operator may still bring back a state at or past the mark, and the account then serves again. Retire only once no state at or past the mark can be brought back, from any backup or replica: the step is one-way. Nothing removes a retirement, not an enrollment, not an erasure; only a mark store rebuilt after its loss holds none (Switch wire 7.3, Table 3).

What it does: from then on the identity's requests answer the recovery notice with `permanent: true`, and the reason the account had (`behind`, `fork` or `mark_lost`; `behind` for a lost identity). The signer still declares the loss and starts a new generation, here or elsewhere; the retirement counts only up to the retired generation, so the new one serves. The retirement lies beside the marks in `accounts/retired/`, apart from the backups, so it holds where the mark itself is lost.

It refuses, and records nothing, unless:

- the generation is above 0;
- the identity is lost (no account, and a mark that records a head or a count, no erasure's record covering it: `lost` in `check-marks`), or its account fails stop and its newest `identity.json` names this service (`serving` in `check-marks`, and `behind`, `fork` or `mark_lost`). A healthy account is refused, and so is every staged one, such as a move's target, bounded or failing: its ways out stay the abort and the erasure (Switch wire 7.3, Table 2);
- the generation given is the one the retirement is of: the mark's, or the account's where the mark is lost. It is the `generation` `check-marks` reports for the line, and a refusal for another names it.

It reads the configuration file as the service does (it needs `server.origin`, `keys.path` and the database), and runs only while the service is stopped: it takes the key store's lock, `<keys.path>/lock`, and refuses while the running service holds it, since the service reads the retirements when it starts. Under the lock it judges the identity as `check-marks` does, reading only, then records the retirement durably. Start the service again afterwards. It prints one JSON line: `account`, the generation `retired`, `already_retired` (`true` when that generation was retired already: nothing changed, and the exit code is still 0), and the `notice` the identity's requests now get. A refusal or a failure exits 1, with the reason on stderr.

## Known limits

- **The identity document grows with every certificate renewal.** Each renewal adds an entry for the earlier certificate to `identity.json`, and nothing purges a closed entry before its app is removed (Switch spec 19, question 26). The service takes a document only within the 256 KiB body caps of `PUT /identity` and `POST /enroll` (Switch wire 7.1), and a move's enrollment, which carries the document encoded twice, reaches its cap first: with renewal every half lifetime, after about 1.9 years at the 255-app limit and about 17.5 years at 32 apps. A signer warns its user at three quarters of a cap and signs nothing that would pass it, so an identity near the cap has to revoke apps to renew or to move. A handful of apps stays far from it for decades.
- **A signer hand-over grows with it.** It carries the full certificate, up to 3,599 bytes, for every certificate the document references, the earlier ones of its renewals included (Switch wire 3.12); a signer's backup carries the same (Switch wire 3.13). The largest state the other limits allow fits `max_handover_parts`, 128 envelopes and about 8 MiB (Switch wire 9.2), within the 12 MiB body cap of `PUT /handover`: the service stores one hand-over of up to that size for an account, until the next `identity.json` version it takes.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `pubky_switch_build_info{version}` | gauge | always 1 |
| `pubky_switch_trusted_time_available` | gauge | 1 with trusted time, 0 without |
| `pubky_switch_trusted_time_uncertainty_ms` | gauge | the uncertainty of trusted time |
| `pubky_switch_time_samples_total{result}` | counter | time samples, `ok` or `error` |
| `pubky_switch_time_disagreement_alerts_total` | counter | readings where the wall clock disagreed with trusted time beyond `max_disagreement_ms` |
| `pubky_switch_roughtime_answers_total{server,result}` | counter | Roughtime answers by outcome: `verified`, `refused`, `timeout`, `unreachable` |
| `pubky_switch_roughtime_server_failing_ms{server}` | gauge | how long the server's samples have been failing; 0 when healthy |
| `pubky_switch_roughtime_server_alert{server}` | gauge | 1 while the server has failed for `alert_after_ms`, 0 otherwise |
| `pubky_switch_roughtime_alerts_total{server}` | counter | alerts raised for the server |
| `pubky_switch_time_refusals_total{call}` | counter | requests refused with `503 unavailable` because they depend on the service's time and trusted time is missing (Switch spec 10.1), by call: `ops`, `append`, `directory`, `put_peers` |
| `pubky_switch_mark_refusals_total{reason}` | counter | requests answered with the recovery notice (Switch wire 7.3, 7.6), by its reason: `behind`, `fork`, `mark_lost`; any increase means state signed for an account was lost, or its mark bounds it (No restore and continue, above) |
