# Alert observability source boundary

> Status: local schema, pure evaluator/parser and archive-crypto contracts, an
> evaluator runtime-status/lease/bootstrap repository, a bounded audit source
> repository, a bounded OAuth-report source repository, and a bounded logout
> delivery source repository. None of these repositories is imported by the
> Worker entry point or a scheduler. Remaining fan-out and Queue metric sources,
> `alert_state`/`security_alert`/`alert_outbox` CAS, Cron,
> Queue/Email/admin delivery, same-run proof, the `0021` R2 archive
> implementation, and deployment remain absent. Production records remain
> through migration `0012`.

## What `0020` provides

The additive migration creates six alert D1 sources, extends OAuth report
provenance, and defines one key-continuity sentinel:

- `alert_state`: one immutable rule/environment/dimension identity with current
  bounded lossless evidence, nullable per-severity definition thresholds,
  typed pending-breach severity, hysteresis counters, a persisted notification
  scheduling clock, generation, and revision;
- `security_alert`: incident generations with one unresolved row per dedupe
  state and closed open/acknowledged/resolved transitions;
- `alert_outbox`: D1-first Email-only delivery work with a canonical payload,
  SHA-256 field, stable idempotency key, recurring notification sequence that
  starts at one and remains contiguous within `1..1,000,000,000`, lease,
  attempts, replay generation, and a closed transition graph;
- `alert_delivery_attempt`: pre-I/O attempt evidence bound to the exact active
  replay/attempt/lease, with unique `(outbox_id, replay_count, attempt_number)`
  tuples and immutable terminal outcomes;
- `alert_runtime_status`: bounded evaluator/delivery/Queue health watermarks,
  monotonic clocks, and five-minute maximum ownership leases;
- `alert_evaluator_bootstrap`: one immutable evaluator-first-success anchor tied
  by restricted foreign key to the runtime component and guarded against its
  exact generation and revision;
- `audit_event.actor_ref`/`actor_ref_hash_version` and
  `oauth_client_report.reporter_ref`/`reporter_ref_hash_version`: nullable
  persistent provenance for rows whose raw actor/reporter FK may later become
  null. A row cannot introduce the reference without the corresponding raw FK;
- `alert_hash_key_sentinel`: one immutable, domain-separated fingerprint of the
  v1 alert subject HMAC key. It stores no secret and must match before evaluation.

The source contract derives that fingerprint as HMAC-SHA-256 over the exact
UTF-8 bytes `pgid-alert-v1\0key_sentinel\0pgid.alert_subject_hash_key.v1`, using
the decoded 32-byte alert HMAC key, and stores the canonical unpadded base64url
result with hash version `1`. This key-sentinel domain is not an alert dimension
and is not interchangeable with subject, actor, client, reporter or archive-KEK
references. The local audit source slice verifies the singleton before deriving
hashed observations; this does not mean an evaluator or production writer is
deployed.

Rule IDs are restricted to reviewed PGID registration, restricted-account,
recovery, Passkey step-up, OAuth-report, admin, audit-fanout, logout, alert
runtime, and approximate Queue-DLQ sources. D1 evidence is marked `d1_exact`;
the Queue metrics rule is explicitly `queue_approximate`. Threshold values live
in the reviewed versioned definitions and pure evaluator/parser tests, not in
this migration. Those modules are not imported by the Worker entry point and do
not collect, persist, schedule, or deliver an alert.

Each primary component records a closed metric name plus its exact kind/unit,
value, threshold, ratio numerator/denominator, minimum sample count, and positive
minimum numerator where applicable. A state threshold is null when that selected
metric/window has no definition for the corresponding severity; at least one of
warning/critical must exist, and stored last-breach evidence must meet an
applicable threshold. The incident and outbox hold the one selected severity
threshold and reject evidence below it.

Primary metric names are also closed per rule. Fanout-gap evidence uses only the
typed older-than query's `missing` count; it does not persist an age that cannot
be reconciled with a bounded event window. Approximate Queue-DLQ evidence uses
either `depth` or `consecutive_nonzero_samples`, and its dimension is exactly one
of `security_events_dlq`, `logout_deliveries_dlq`, `alert_deliveries_dlq`, or
`audit_archive_dlq`. The exact runtime mapping is respectively `security_dlq`,
`logout_dlq`, `alert_dlq`, and `audit_archive_dlq`. Metric-bearing runtime
components are the corresponding four Queue/DLQ pairs, including exact
`audit_archive_queue` and `audit_archive_dlq` names. Runtime updates increment
`revision` exactly once. No runtime clock or watermark may exceed `updated_at`.
Lease acquisition increments generation, renewal keeps the same owner before
expiry, release is permitted only by an unexpired owner, and takeover requires
the prior lease to have expired; every acquired or renewed lease expires no
more than five minutes after its update. Samples cannot regress; a positive
sample increments only at an exact 60-second interval, a late/missing sample
restarts at one, and zero resets both continuity fields. Schema presence does
not prove that the sampling loop exists. In particular, D1 cannot prove that an
inserted `healthy`/`last_success_at` pair came from executed evaluator work. The
local evaluator runtime repository starts the evaluator component as `disabled`
with null history. It acquires and renews the bounded evaluator lease and records
terminal success or failure by exact generation/revision/lease compare-and-swap.
On its first repository-controlled success, one ordered D1 batch updates the
runtime row to `healthy` with non-null success evidence, then inserts
`alert_evaluator_bootstrap` with `INSERT ... SELECT` from that exact runtime row.
The anchor is immutable and its parent runtime row cannot be deleted or
replaced. This proves the persisted repository transition, not the external
work itself; status, generation, or revision alone is never bootstrap evidence.
The repository also owns the exact projection read below. It is local source
only: the Worker entry point and scheduler do not import or invoke it, and no
full audit/other metric-source evaluation or same-run execution proof exists.

The bounded audit repository executes its fourteen closed projections in one
awaited D1 batch. Canonical ratio numerator/denominator fields and recovery
denied/started fields stop at `1,000,000`; ordinary count fields retain the
`1,000,000,000` evidence bound. A well-shaped cohort above its applicable bound
makes only that rule/dimension incomplete. It cannot invalidate or manufacture
zeroes for otherwise usable cohorts.

Per-identity zero fill reads only state whose lifecycle can still affect a
future evaluation: active severity, a pending breach/clear, or a cooldown. Five
code-owned rule branches each use `alert_state_tracked_evaluation_idx` and apply
`LIMIT 1001` before the compound result is materialized. The 1001st row marks
only that rule/dimension incomplete. A fully inactive row with no pending
counter or cooldown is historical and is the only lifecycle shape omitted.

The pure parser fixes this exact repository-owned projection and column order:

```sql
SELECT
  b.component AS bootstrap_component,
  b.first_success_at AS first_success_at,
  b.source_generation AS source_generation,
  b.source_revision AS source_revision,
  r.component AS runtime_component,
  r.status AS runtime_status,
  r.generation AS runtime_generation,
  r.revision AS runtime_revision,
  r.last_started_at AS runtime_last_started_at,
  r.last_success_at AS runtime_last_success_at,
  r.last_error_at AS runtime_last_error_at,
  r.last_error_code AS runtime_last_error_code,
  r.updated_at AS runtime_updated_at
FROM (SELECT 'evaluator' AS expected_component) AS e
LEFT JOIN alert_evaluator_bootstrap AS b
  ON b.component = e.expected_component
LEFT JOIN alert_runtime_status AS r
  ON r.component = e.expected_component
```

All four bootstrap aliases null means pre-bootstrap, regardless of the runtime
row. Any non-null bootstrap alias means post-bootstrap forever; a corrupt or
missing runtime projection is missing threshold input, never a return to
pre-bootstrap. The parser accepts only component `evaluator`, canonical
timestamps, source generation `1..1,000,000`, source revision
`1..1,000,000,000`, a current generation/revision not behind the anchor, and the
closed runtime status/error domains. It also requires
`first_success_at <= last_success_at <= updated_at <= asOf` and
`last_started_at <= updated_at`; current `last_started_at` need not precede the
retained `last_success_at` after a later run starts.

Logout health has two different time domains. `dead` counts every row currently
dead until replay changes its state, and `oldest_unresolved_age_seconds` scans
every current pending/processing/retry/dead row, even when it was created before
the 60-minute cohort window. Only the eligible/unresolved ratio and
lease-expired attempt cohorts are windowed. Separate status-first and
created-time-first covering indexes support both paths; an old stuck/dead row
must not age out of health reporting.

The local logout source repository executes nine projections in one awaited D1
batch: key continuity, tracked clients, sparse timestamp integrity, independent
global/client current snapshots, delivery-created cohorts, and terminal-attempt
cohorts. Current evidence includes every pending/processing/retry/dead row with
`created_at < asOf`, without a 60-minute lower bound. Eligible/unresolved
delivery cohorts and terminal `outcome=lease_expired` attempt cohorts use exact
half-open 5/15/60-minute windows. Lease expiry counts attempts, not distinct
deliveries or a currently expired processing lease that runtime has not yet
terminalized. Two sparse `0020` partial indexes retain pre-existing malformed
timestamp evidence while four guards reject future noncanonical writes; either
integrity bit makes both source dimensions incomplete before lexical windows
can hide the row.

Global evidence remains independently usable when only the HMAC key/sentinel or
client projection is unavailable. The client side is all-or-incomplete: raw
client IDs exist only while deriving the sentinel-protected `client_hmac`, all
three client projections and tracked zero-fill use `LIMIT 1001`, and every
complete client projection must exactly rebuild global counters and oldest age.
Malformed rows, counts, timestamps, HMAC collisions, or inconsistent
projections cannot manufacture a clear or expose endpoint, token, `jti`, `sid`,
client ID, metadata, or PII. This repository is local source only. It is not
imported by the Worker or scheduler and does not alter logout delivery, replay,
Queue, Cron, configuration, artifact identity, or operator behavior.

OAuth reporter coverage is a whole-evaluation gate. Until every in-window row
has either its legacy raw reporter ID or the persisted reporter reference, the
evaluator reports the source as partial, records runtime `source_incomplete`, and
does not emit a lower distinct-reporter count as exact. Production must backfill
the reference under the active key and prove complete coverage; this migration
does not perform a remote backfill.

The local OAuth source repository executes the key-sentinel, tracked-client, and
report-group projections in one awaited D1 batch. It reads exact half-open
5/15/60-minute cohorts, counts every report and the closed
`impersonation`/`phishing` high-risk subset, derives client and reporter identity
with separate `client_hmac` and `reporter_hmac` domains, and applies `LIMIT 1001`
to both bounded projections. Missing or mismatched reporter provenance makes the
affected distinct count null and marks the whole rule incomplete without
discarding otherwise proven total/high-risk evidence. Invalid source shape,
overflow, missing key continuity, or query failure cannot manufacture a clear
or expose a raw client/reporter identifier. This repository is local source
only: neither the Worker entry point nor a scheduler imports or invokes it.

Admin actor coverage follows the same rule because `audit_event.actor_user_id`
also becomes null when its user is deleted. If a relevant admin event in the
60-minute rule window plus evaluator skew has neither raw actor ID nor
`actor_ref`, the entire actor-based evaluation is incomplete and records
`source_incomplete`; it does not silently exclude that row. Production
enablement requires a reviewed recent backfill and zero such rows. Future audit
writers populate the ref in the same mutation batch, but this schema slice does
not change current writers or perform a remote backfill.

Raw actor/reporter FKs cannot be reassigned after insert. A first reference,
whether supplied on insert or added later, requires that exact row's raw FK to
remain non-null while the writer derives and verifies the domain-separated
value. The only later identity change allowed is the existing non-null-to-null
`ON DELETE SET NULL` action; the paired HMAC reference survives that deletion
and, once populated, is immutable. If a raw ID is already null and no reference
exists, a later writer cannot invent one; that row remains explicitly
incomplete. This preserves account deletion semantics without permitting an
unproved stored-only reference or attribution to a different identity.

Lifecycle state is restart-safe and compare-and-swap shaped. No pristine
none/unknown row is stored: the first positive evaluation creates an inactive
generation/revision-zero row carrying exactly one typed warning/critical
candidate; the next matching evaluation opens or escalates. Four persisted
clear evaluations remain active,
and the fifth resolves with a cooldown exactly 30 minutes after that evaluation.
Inactive updates preserve that cooldown until its exact expiry, then may clear
it; they cannot clear early, create, extend, or slide it. A pending warning also
cannot confirm while cooldown remains active, while canonical immediate
critical causes retain their break-glass path. Every revision has a strictly newer
`last_evaluated_at`, preventing
the same Cron `asOf` from incrementing a streak twice. Counter/generation jumps
and candidate-free transitions are rejected. Only logout `dead` and runtime
`evaluator_missing`/`dead_outbox` may enter critical immediately. A reviewed
manual resolution code permits active-to-inactive only after the same-generation
incident is resolved with a versioned operator reference; `healthy` automatic
resolution carries no operator reference, still requires the fifth clear, and
no old generation is a bypass. Fanout-gap is manual-only: it cannot accumulate
automatic clear samples or use `healthy` resolution.
Active warning or critical state also requires a canonical
`last_notification_scheduled_at`; inactive/pending state requires it to be null.

The two current all-of expressions additionally store one fixed secondary
count/events component: `count` then `known_surfaces` for restricted sensitive
denials, or `high_risk_count` then `distinct_reporters` for OAuth client reports.
The five secondary fields are all-null or all-present, meet their own threshold,
and are matched exactly into the immutable Email payload. Restricted
`known_surfaces` is additionally no greater than the primary denied count or the
closed seven-surface domain. This schema version
supports at most two ordered components; adding a three-component expression
requires a reviewed migration and payload version.

Alert rows allow only fixed enums, bounded integers/timestamps, opaque IDs, and
version-1 HMAC subject references. They do not contain raw user IDs, email/IP,
session or token material, credential IDs, provider response messages, webhook
URLs, or arbitrary metadata. `alert_outbox` accepts only the reviewed Email
channel. Its canonical JSON must equal all persisted snapshot columns, and an
insert trigger requires those columns to match the exact incident evidence and
immutable state dimensions. The future Email adapter must recompute and verify
`payload_sha256` before delivery. A mismatch is permanently classified as
`payload_integrity` in both attempt and outbox evidence and may transition only
to `dead`, not retry, rather than being collapsed into an arbitrary provider
error.

Semantic state identity is unique across rule, environment, source kind, and
the closed subject/Queue dimension; a writer cannot create parallel incidents by
changing an opaque dedupe hash or context fields. Restricted sensitive denial,
OAuth report, and admin rules require a canonical version-1 HMAC subject
reference; recovery Passkey, Passkey step-up, and logout may carry one; all
remaining non-Queue rules forbid it. All 32-byte base64url references use the
canonical 43-character encoding, including the complete 16-character final
alphabet `A/E/I/M/Q/U/Y/c/g/k/o/s/w/0/4/8`. The evaluator's current dimensions
do not include provider/reason/surface context, so those reserved snapshot
columns remain null. Numeric fields declared as integers also require SQLite
integer storage, preventing REAL values from passing affinity-based range checks.

The future delivery Worker must use ordered D1 batches for both sides of the
attempt contract. New work starts pending, due, attempt/replay zero, and without
lease or terminal evidence. A claim cannot precede its due time and its lease
must expire after the claim. The matching in-flight attempt starts at or after
that claim and before expiry. The exact attempt terminalizes before the outbox
moves to the same accepted/retry/dead result; terminal timestamps cannot predate
the attempt, retry is scheduled strictly after its update, and replay due time
cannot predate replay creation. Provider completion must precede lease expiry;
at or after expiry, only `lease_expired` may consume the claim.

## Audit cursor decision

`0020` does not add an `audit_event` sequence or backfill. Existing audit IDs
are UUIDs, and guarded mutations may insert then delete an audit row in the same
D1 batch when a later condition fails. Creating an archive cursor here would
either leave phantom sequence state or prematurely define retention semantics.

Instead, `0020` adds
`audit_event_type_subject_time_bounded_idx(event_type, subject_id,
occurred_at DESC, id)` for deterministic bounded per-subject scans. The existing
type/time index remains available. Additional covering indexes close the exact
global/type/actor audit, OAuth reporter, logout delivery, and logout-attempt
cohort paths described by the pure evaluator's source contracts. The bounded
local audit repository executes only the reviewed audit paths; later D1
repositories must execute and prove the remaining source paths.
`alert_state_tracked_evaluation_idx(environment, rule_id, subject_ref,
hash_version)` is a partial index over only ongoing exact-D1 lifecycle state;
the local audit repository uses it for bounded tracked-identity zero fill.

The local archive-crypto module separately seals and opens bounded canonical v1
records. It preserves the nullable `actorRef`/`actorRefHashVersion` pair and
authenticates `checkpointFromSequence` across the header, manifest, and AES-GCM
AAD. This is a record/envelope primitive, not an archive service. Migration
`0021` must still define the monotonic source ledger, immutable batch membership,
KEK custody/sentinel, trigger-coupled finalization/checkpoint/BLOB cleanup, and
the repository contract. The R2 writer/restore path, Queue/DLQ, retention and
external backup are also absent. There is no `audit-archive.ts` runtime module or
`AUDIT_ARCHIVE` R2 binding, so `encrypted_r2_archive` remains
`dependency_missing`.

## Local verification

From a clean worktree with the frozen dependency set:

```bash
pnpm --filter @pg72/id exec vitest run test/observability-schema.spec.ts
pnpm --filter @pg72/id exec vitest run \
  test/alert-audit-source-repository.spec.ts \
  test/alert-logout-source-repository.spec.ts \
  test/alert-oauth-source-repository.spec.ts \
  test/alert-evaluator.spec.ts test/alert-rules.spec.ts \
  test/audit-archive-crypto.spec.ts
node --test scripts/public-readiness/d1-manifest.test.mjs \
  scripts/public-readiness/dependency-contracts.test.mjs \
  scripts/public-readiness/report.test.mjs
pnpm test:public-readiness
pnpm --filter @pg72/id check
pnpm --filter @pg72/test-rp test
git diff --check
```

The focused schema suite applies all migrations through `0020` and rejects
invalid enums/metrics, provenance mismatch, duplicate unresolved incidents,
duplicate notification/idempotency/attempt tuples, malformed leases, mutable
payloads, invalid incident/delivery transitions, unsupported channels,
fabricated snapshot evidence, and attempt evidence that does not match the exact
active outbox lease. It also rejects invented primary domains, missing ratio
minimum numerators, fictitious severity thresholds, partial or below-threshold
secondary components, and evidence that changes between incident and outbox.
The suite proves the existing audit insert/delete compensation still works and
no sequence table was introduced. The pure evaluator suites verify the exact
15-rule matrix, redacted dimensions, source projections, deterministic lifecycle
and persistence shape without performing D1 writes or scheduling work. The
OAuth source suite verifies exact half-open cohorts, total/high-risk/distinct
counts, nullable reporter evidence, domain-separated raw/stored provenance,
sentinel continuity, bounded tracked zero-fill, query plans, and redacted
failure behavior without wiring an evaluator. The logout source suite verifies
old current failures, exact delivery/attempt boundaries, closed status/outcome
semantics, sparse timestamp integrity and guards, global/client reconciliation,
sentinel continuity, tracked zero-fill, exact caps, bounded query plans, and
redacted failures without wiring an evaluator or changing delivery runtime. The
archive suite verifies the record/envelope crypto and checkpoint binding without
D1, R2 or Queue I/O.

## Remaining gates

Schema, pure evaluator/parser, the unwired evaluator runtime-status repository,
and the bounded local `audit_event`, OAuth-report, and logout-delivery source
repositories must still report observability as `source_present_unverified`,
leaving continuity
and drills blocked. Later reviewed slices must add the remaining fan-out and
Queue sources; D1 state/incident CAS; wire the runtime repository
into evaluator Cron with repository-controlled successful-run and same-run
proof; dedicated alert Queue/DLQ; Email Service adapter; admin
acknowledge/resolve/replay operations; and redaction/race/failure tests. Pure
archive crypto does not satisfy the separate encrypted archive dependency;
`encrypted_r2_archive` remains `dependency_missing` until the `0021` repository,
R2 writer/restore, Queue/DLQ and external-backup exercise exist.

Isolated Preview must then apply the ordered migration ledger, tune thresholds,
exercise exact D1 and approximate Queue evidence, prove real Email receipt and
operator acknowledgement, and rehearse rollback. No migration, pure module or
local test authorizes a push, deploy, remote D1/R2 operation, production alert
claim, public registration, or Production GO.
