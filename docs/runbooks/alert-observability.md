# Alert observability source boundary

> Status: local schema, pure evaluator/parser and archive-crypto contracts,
> evaluator runtime-status/lease/bootstrap and alert state/incident/outbox CAS
> repositories, bounded audit, OAuth-report, global fan-out-gap, and logout
> delivery source repositories, a bounded approximate Queue-DLQ source and D1
> streak repository, `0021` archive-ledger source, and the additive `0022`
> evaluator run/source/decision proof ledger with compatible local run and
> lifecycle-state proof repositories. None of these repositories is imported
> by the Worker entry point or a scheduler. Evaluator Cron, alert/archive
> Queue/DLQ, Email/admin delivery, complete same-run execution proof, R2 archive
> runtime, bounded restore, external backup, and deployment remain absent.
> Production records remain through migration `0012`.

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
- `audit_event_invalid_occurred_at_idx` and
  `oauth_client_report_invalid_created_at_idx`: sparse single-column indexes
  containing only legacy source rows that are not exact 24-character UTC
  millisecond text after a `+0 seconds` round trip. Paired insert/update guards
  reject future non-canonical source timestamps while still allowing an old row
  to be repaired to canonical text;
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

## What `0022` provides

`0022_alert_evaluator_run_proof.sql` adds exactly three redacted proof tables:

- `alert_evaluator_run` owns one logical `(* * * * *, scheduledTime)` occurrence,
  an exact evaluator runtime generation/lease fence, nullable-once `asOf`,
  immutable source/decision manifests, and a closed run lifecycle;
- `alert_evaluator_run_source` owns the exact closed nine-source set and only
  bounded status/count/digest evidence;
- `alert_evaluator_run_decision` attributes each immutable planned decision to
  one source proof and optionally to the exact resulting alert-state revision.

Run insert/renewal and runtime terminal triggers are reverse-coupled inside one
SQLite statement. A failed CAS aborts the outer statement; direct legacy
evaluator acquire, renew, idle status, and terminal updates cannot bypass the
run ledger after `0022`. Workerd regression fixes the observed D1 accounting:
acquire changes two rows, expired takeover three, renewal two, and terminal two,
while the next SQL `changes()` remains one for the outer statement. Exact
source rows are required before sealing; healthy requires all nine complete,
the sealed decision count, no suppressed-partial decision, and a terminal time
after every proof write. Failure status/error pairs are closed.

The local `alert-run-repository` owns occurrence acquire/renew, one-time `asOf`
binding, the closed nine-source proof set, canonical source/decision manifests,
plan sealing, source-attributed suppressed/no-state proof, and exact terminal
success/failure. Every mutation validates the complete run/runtime lease fence
and uses exact readback to distinguish contention, replay, and response loss.
Direct legacy evaluator lease/terminal methods remain rejected by the `0022`
guards.

The local lifecycle repository reads state and current-generation incident rows
in one D1 snapshot and fails closed on ambiguous incidents, non-canonical
identity/dedupe material, chronology, or evidence mismatch. Its optional run
proof path writes an `applied` decision immediately after the authoritative
state/incident/outbox `changes()` chain in that same D1 batch; zero product CAS
cannot mint proof. A `no_state_change` proof is admitted only while the exact
semantic state identity is absent. Exact proof/state coordinates and canonical
product readback are required before response-loss or concurrent retries return
`duplicate`.

These are local, unwired transaction contracts. No Cron import, source/decision
orchestration, Queue binding, Email adapter, config, secret, remote migration,
or deployment is part of this checkpoint. Applying `0022` while continuing to
call the legacy evaluator runtime lease methods would fail closed, so rollout
still requires a Worker that uses the compatible run path.

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
local evaluator runtime repository initializes the evaluator component as
`disabled` with null history and owns the exact health-source projection. After
`0022`, the compatible run repository acquires and renews the bounded evaluator
lease and records terminal success or failure by exact run/runtime fence. On its
first repository-controlled success, one ordered D1 batch updates the runtime
row to `healthy` with non-null success evidence, then
inserts
`alert_evaluator_bootstrap` with `INSERT ... SELECT` from that exact runtime row.
The anchor is immutable and its parent runtime row cannot be deleted or
replaced. This proves the persisted repository transition, not the external
work itself; status, generation, or revision alone is never bootstrap evidence.
Runtime generation and revision are monotonic JavaScript-safe fencing counters,
both bounded inclusively at `9,007,199,254,740,991`. Every ownership grant
increments generation and every persisted transition increments revision; they
never wrap or reset. Acquire and renew reserve one final revision for terminal
success or failure. The repository reports the fixed redacted code
`counter_headroom_low` when either counter has at most `1,000,000` increments
remaining and `counter_exhausted` at the bound. Workers Logs must alert on both
codes independently of the alert delivery path. Acquisition or renewal that
cannot preserve its required increment plus terminal revision fails closed with
the fixed repository error `counter_exhausted`; ordinary lease contention still
returns no lease.
The runtime repository also owns the exact projection read below. Both modules
are local source only: the Worker entry point and scheduler do not import or
invoke them, and no complete source-collection/decision orchestration exists.

The bounded audit repository executes one timestamp-integrity projection and
its fourteen closed rule projections in one awaited D1 batch. The integrity
statement uses `EXISTS`, `INDEXED BY audit_event_invalid_occurred_at_idx`, and
`LIMIT 1`; any row or malformed projection fails the entire source closed before
lexical windows are interpreted. Canonical ratio numerator/denominator fields
and recovery
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
timestamps, source generation and revision
`1..9,007,199,254,740,991`, a current generation/revision not behind the anchor,
and the closed runtime status/error domains. It also requires
`first_success_at <= last_success_at <= updated_at <= asOf` and
`last_started_at <= updated_at`; current `last_started_at` need not precede the
retained `last_success_at` after a later run starts.

This in-place `0020` source correction is allowed only while the target ledger
has never applied the old `0020` bytes. Production is recorded through `0012`,
but every target still needs explicit ledger evidence before migration. Recreate
disposable local or isolated Preview databases that applied the old migration
and rehearse the complete ordered ledger again. If any persistent D1 already
contains the old `0020`, stop: editing the migration file will not rerun it.
Ship a separately reviewed additive replacement-table migration with exact row
copy/swap, deferred foreign-key handling, and full integrity/FK proof instead.
Never reset the counters. An older Worker with the former caps is not a durable
rollback once values pass those caps, so rollout evidence must record the
minimum compatible Worker version and coordinate any D1 restore with it.

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

The local Queue source is deliberately narrower than Queue operation or alert
delivery. A caller injects exactly one request-scoped Cloudflare Queue binding,
and the repository awaits its official `metrics()` method. The provider result
may contain only finite, nonnegative safe-integer `backlogCount` and
`backlogBytes` plus an optional `oldestMessageTimestamp`; a nonempty Queue must
have a finite `Date` no later than the sample clock, while an empty Queue must
have zero bytes and no oldest timestamp. The provider promise completion-time
clock is the canonical `sampledAt` and evaluator `asOf`; oldest age is floored
to whole seconds. These values remain best-effort point-in-time
`queue_approximate` evidence, never exact Queue accounting.

The four closed Queue dimensions map only to `security_dlq`, `logout_dlq`,
`alert_dlq`, and `audit_archive_dlq` rows in `alert_runtime_status`. One awaited
D1 batch applies a revision-bounded, unleased compare-and-swap, reads
`changes()`, and projects that exact row. A positive sample increments its
streak only at exactly 60 seconds, a gap restarts at one, and zero resets the
streak and start time. A `changes() = 0` exact duplicate is a response-loss
replay only while the strict projection proves `updated_at` still equals that
sample time and both lease fields remain null. A later status/revision
transition retaining the metrics, any retained lease, out-of-order samples,
contradictory concurrent losers, stale or malformed provider/D1 results, and all
read/write failures yield a fixed, redacted unknown observation instead of a
clear. This module is not imported by the Worker or scheduler and adds no
binding, configuration, Cron, Queue producer/consumer, or production behavior.

OAuth reporter coverage is a whole-evaluation gate. Until every in-window row
has either its legacy raw reporter ID or the persisted reporter reference, the
evaluator reports the source as partial, records runtime `source_incomplete`, and
does not emit a lower distinct-reporter count as exact. Production must backfill
the reference under the active key and prove complete coverage; this migration
does not perform a remote backfill.

The local OAuth source repository executes the sparse timestamp-integrity,
key-sentinel, tracked-client, and report-group projections in one awaited D1
batch. The first statement requires the
`oauth_client_report_invalid_created_at_idx` covering probe to be empty before
it reads exact half-open
5/15/60-minute cohorts, counts every report and the closed
`impersonation`/`phishing` high-risk subset, derives client and reporter identity
with separate `client_hmac` and `reporter_hmac` domains, and applies `LIMIT 1001`
to both bounded projections. Missing or mismatched reporter provenance makes the
affected distinct count null and marks the whole rule incomplete without
discarding otherwise proven total/high-risk evidence. Invalid source shape,
overflow, missing key continuity, or query failure cannot manufacture a clear
or expose a raw client/reporter identifier. This repository is local source
only: neither the Worker entry point nor a scheduler imports or invokes it.

The local fan-out-gap source repository first checks the same global
`audit_event_invalid_occurred_at_idx` projection in the D1 batch, then reads the
exact half-open
`[asOf - 60m, asOf)` `audit_event` cohort and left-joins
`security_event_delivery.event_id`. A missing marker counts only when the source
timestamp is strictly older than five or fifteen minutes, so an event exactly on
either grace boundary remains outside that older cohort. The query uses the
bounded audit time index and marker primary-key index, projects only aggregate
counters, retains selected-row timestamp validation, validates both exact D1
result shapes, and turns
well-shaped evidence above `1,000,000,000` into an incomplete global source
rather than a false clear. This is an unwired detector source only. It does not
create a durable security-event outbox, replay a missing event, sample Queue
state, or establish delivery reliability.

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

`0020` itself does not add an `audit_event` sequence or backfill. The additive
local `0021_audit_archive.sql` slice now owns that separate ledger while
preserving compensation deletion before an event is snapshotted.

Before `0021` assigns a source sequence, its insert guard looks up the parent by
`audit_event.id` and requires the same canonical UTC millisecond round trip.
The backfill is one statement, so one uncorrected legacy row aborts all sequence
allocation instead of fixing a lexical misordering into the ledger. Repair the
row through the `0020` timestamp update guard, rerun integrity/FK checks, and
only then retry the unapplied `0021` migration.

Instead, `0020` adds
`audit_event_type_subject_time_bounded_idx(event_type, subject_id,
occurred_at DESC, id)` for deterministic bounded per-subject scans. The existing
type/time index remains available. Additional covering indexes close the exact
global/type/actor audit, OAuth reporter, logout delivery, and logout-attempt
cohort paths described by the pure evaluator's source contracts. The local
two sparse invalid-timestamp indexes are separate from those time-window
indexes: their healthy path is an empty covering-index `EXISTS ... LIMIT 1`
probe, never an unindexed base-table validation scan. The local
runtime repository owns only evaluator lease/status/bootstrap state; it does not
execute metric-source queries or persist alert state, incidents, or outbox work.
The bounded local audit repository executes only the reviewed audit paths;
later D1 repositories must execute and prove the remaining source paths.
`alert_state_tracked_evaluation_idx(environment, rule_id, subject_ref,
hash_version)` is a partial index over only ongoing exact-D1 lifecycle state;
the local audit repository uses it for bounded tracked-identity zero fill.

The local archive-crypto module separately seals and opens bounded canonical v1
records. It preserves the nullable `actorRef`/`actorRefHashVersion` pair and
authenticates `checkpointFromSequence` across the header, manifest, and AES-GCM
AAD. Migration `0021` now owns the monotonic source ledger, deterministic
backfill, immutable batch snapshots, archive-key sentinel schema, and terminal
checkpoint/BLOB-cleanup transaction described in
[`audit-archive.md`](./audit-archive.md). The unwired request-scoped archive D1
repository owns fingerprint-only sentinel continuity, bounded source selection,
canonical batch persistence, exact lease/terminal receipts, and audited dead
replay. These remain local source contracts, not an archive service: there is no
`audit-archive.ts` runtime module, archive-domain fingerprint derivation or KEK
custody, `AUDIT_ARCHIVE` R2 binding/writer, Queue/DLQ, Cron, bounded restore,
retention exercise, or external backup. `encrypted_r2_archive` therefore
remains `dependency_missing`.

The local `alert-state-repository` reconstructs one lifecycle/CAS snapshot from
the state and current-generation incident rows, then accepts one already-
evaluated pure lifecycle decision and an exact expected state
revision/generation/watermark plus current incident identity. One ordered D1
batch applies the guarded state transition, incident insert/update, and optional
immutable Email outbox snapshot. Every
dependent write is gated by the preceding mutation, so a stale writer performs
no partial incident or delivery work. The result is explicitly `applied`,
`conflict`, or `duplicate`; response-loss retries preserve one incident and one
canonical delivery/idempotency identity. Payload bytes use the exact schema key
order and are hashed before insertion. The API accepts only global, Queue, or
versioned HMAC dimensions and never accepts a raw actor, subject, or client ID.
With an exact sealed run fence it also records the source-attributed decision
proof in the same product batch, or proves no semantic state separately for a
`no_state_change` decision. This repository does not read metric sources,
schedule evaluation, claim or deliver outbox work, or provide operator mutation
APIs.

## Local verification

From a clean worktree with the frozen dependency set:

```bash
pnpm --filter @pg72/id exec vitest run \
  test/observability-schema.spec.ts test/alert-runtime-repository.spec.ts \
  test/alert-run-proof-schema.spec.ts test/alert-run-proof-bootstrap.spec.ts \
  test/alert-run-proof.spec.ts test/alert-run-repository.spec.ts \
  test/alert-state-repository.spec.ts test/alert-state-run-proof.spec.ts \
  test/audit-archive-schema.spec.ts
pnpm --filter @pg72/id exec vitest run \
  test/alert-audit-source-repository.spec.ts \
  test/alert-fanout-source-repository.spec.ts \
  test/alert-logout-source-repository.spec.ts \
  test/alert-oauth-source-repository.spec.ts \
  test/alert-queue-source-repository.spec.ts \
  test/alert-evaluator.spec.ts test/alert-rules.spec.ts \
  test/audit-archive-crypto.spec.ts \
  test/audit-archive-repository.spec.ts
node --test scripts/public-readiness/alert-source-time-integrity-migration.test.mjs \
  scripts/public-readiness/audit-archive-migration.test.mjs \
  scripts/public-readiness/d1-manifest.test.mjs \
  scripts/public-readiness/dependency-contracts.test.mjs \
  scripts/public-readiness/report.test.mjs
pnpm test:public-readiness
pnpm --filter @pg72/id check
pnpm --filter @pg72/test-rp test
git diff --check
```

The focused observability schema suite validates `0020` and rejects
invalid enums/metrics, provenance mismatch, duplicate unresolved incidents,
duplicate notification/idempotency/attempt tuples, malformed leases, mutable
payloads, invalid incident/delivery transitions, unsupported channels,
fabricated snapshot evidence, and attempt evidence that does not match the exact
active outbox lease. It also rejects invented primary domains, missing ratio
minimum numerators, fictitious severity thresholds, partial or below-threshold
secondary components, and evidence that changes between incident and outbox.
It also proves source timestamp insert/update guards and empty covering sparse
indexes. The migration regression seeds offset, far-low/far-high, bad-calendar,
and numeric legacy values before `0020`, proves both invalid indexes find them,
repairs them to canonical text, and proves the indexes become empty without a
base-table scan.
It proves the existing audit insert/delete compensation still works before the
separate source ledger is added. The archive schema/migration suites apply the
ordered ledger through `0021`, verify its six-table transaction contract, and
retain that compensation behavior. The pure evaluator suites verify the exact
15-rule matrix, redacted dimensions, source projections, deterministic lifecycle
and persistence shape without scheduling work. The state repository suites use
real Workerd D1 to verify stale-revision races, duplicate evaluations, trigger
rollback, canonical snapshot reconstruction, critical/warning/cooldown/manual-
only transitions, contiguous reminders, canonical payload digests, HMAC-only
dimensions, same-batch decision proof, no-state proof, response loss, and full
state/incident/outbox/proof rollback. The run-proof suites verify the schema,
closed source/decision manifests, exact lease fencing, terminal/bootstrap
coupling, replay, takeover, and strict rejection of legacy evaluator mutation.
The runtime repository suite retains initialization, source projection, counter
boundaries, and explicit legacy-mutation rejection. The OAuth
source suite verifies its global sparse-index preflight, exact half-open
cohorts, total/high-risk/distinct counts,
nullable reporter evidence, domain-separated raw/stored provenance, sentinel
continuity, bounded tracked zero-fill, query plans, and redacted failure behavior
without wiring an evaluator. The fan-out source suite verifies its global
preflight, one-hour half-open lookback, exact grace boundaries, marker matching,
selected timestamp validation, safe caps, cohort nesting, bounded query plans,
and redacted fail-closed behavior without wiring an evaluator or Queue. The
logout source suite verifies old current failures, exact delivery/attempt
boundaries, closed status/outcome semantics, sparse timestamp integrity and
guards, global/client reconciliation, sentinel continuity, tracked zero-fill,
exact caps, bounded query plans, and redacted failures without wiring an
evaluator or changing delivery runtime. The Queue source suite verifies all four
closed mappings, promise-completion sample time, age flooring, finite caps,
exact 60-second increment/reset behavior, 15-minute critical duration, D1
revision/lease/`changes()` CAS, exact replay ownership, response-loss replay,
out-of-order and concurrent losers, strict provider/D1 parsing, fixed redacted
errors, and primary-key query plans without adding a binding, Cron, or evaluator
wiring. The archive schema and migration suites verify that one invalid parent
aborts backfill and that a repaired canonical parent succeeds, plus the `0021`
ledger transaction contract. The archive-crypto and repository suites verify the
record/envelope/checkpoint binding, bounded source and persistence behavior,
exact lease/terminal/replay receipts, response-loss retries, and concurrent
losers without R2 or Queue I/O.

## Remaining gates

Schema, pure evaluator/parser, the unwired source/run/state repositories, the
unwired `0022` proof-ledger transaction foundation, and the
bounded local `audit_event`, OAuth-report, fan-out-gap, logout-delivery, and
approximate Queue-DLQ source repositories must still report observability as
`source_present_unverified`, leaving continuity and drills blocked. Later
reviewed slices must wire the compatible run/state repositories and all bounded
source repositories into Cron with one orchestrated source/decision plan and
repository-controlled terminal proof; and add dedicated
alert Queue/DLQ, an Email Service adapter, admin acknowledge/resolve/replay
operations, and redaction/race/failure tests. Archive crypto plus the `0021`
ledger and unwired D1 repository do not satisfy the separate encrypted archive
dependency; `encrypted_r2_archive` remains `dependency_missing` until
archive-domain fingerprint derivation and KEK custody, the R2 writer/bounded
restore, Queue/DLQ, Cron redrive, retention proof, and external-backup exercise
exist.

Isolated Preview must then apply the ordered migration ledger, tune thresholds,
exercise exact D1 and approximate Queue evidence, prove real Email receipt and
operator acknowledgement, and rehearse rollback. No migration, pure module or
local test authorizes a push, deploy, remote D1/R2 operation, production alert
claim, public registration, or Production GO.
