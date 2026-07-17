# Alert observability schema boundary

> Status: local schema source only. Migration `0020_alert_observability.sql`
> does not run an evaluator, send a Queue message or Email, expose operator
> endpoints, or satisfy the observability execution proof. Production records
> remain through migration `0012`.

## What `0020` provides

The additive migration creates five alert D1 sources, extends OAuth report
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
- `audit_event.actor_ref`/`actor_ref_hash_version` and
  `oauth_client_report.reporter_ref`/`reporter_ref_hash_version`: nullable
  persistent provenance for rows whose raw actor/reporter FK may later become
  null;
- `alert_hash_key_sentinel`: one immutable, domain-separated fingerprint of the
  v1 alert subject HMAC key. It stores no secret and must match before evaluation.

Rule IDs are restricted to reviewed PGID registration, restricted-account,
recovery, Passkey step-up, OAuth-report, admin, audit-fanout, logout, alert
runtime, and approximate Queue-DLQ sources. D1 evidence is marked `d1_exact`;
the Queue metrics rule is explicitly `queue_approximate`. Threshold values
belong to versioned rule definitions and tests in the future evaluator slice,
not this migration.

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
inserted `healthy`/`last_success_at` pair came from executed evaluator work. Only
the future evaluator repository may publish that pair inside its controlled
successful-run transaction, and consumers must require the
`repository_controlled_successful_run_only` parser contract; status, generation,
or revision alone is not bootstrap evidence.

Logout health has two different time domains. `dead` counts every row currently
dead until replay changes its state, and `oldest_unresolved_age_seconds` scans
every current pending/processing/retry/dead row, even when it was created before
the 60-minute cohort window. Only the eligible/unresolved ratio and
lease-expired attempt cohorts are windowed. Separate status-first and
created-time-first covering indexes support both paths; an old stuck/dead row
must not age out of health reporting.

OAuth reporter coverage is a whole-evaluation gate. Until every in-window row
has either its legacy raw reporter ID or the persisted reporter reference, the
evaluator reports the source as partial, records runtime `source_incomplete`, and
does not emit a lower distinct-reporter count as exact. Production must backfill
the reference under the active key and prove complete coverage; this migration
does not perform a remote backfill.

Admin actor coverage follows the same rule because `audit_event.actor_user_id`
also becomes null when its user is deleted. If a relevant admin event in the
60-minute rule window plus evaluator skew has neither raw actor ID nor
`actor_ref`, the entire actor-based evaluation is incomplete and records
`source_incomplete`; it does not silently exclude that row. Production
enablement requires a reviewed recent backfill and zero such rows. Future audit
writers populate the ref in the same mutation batch, but this schema slice does
not change current writers or perform a remote backfill.

Raw actor/reporter FKs cannot be reassigned after insert. The only identity
change allowed is their existing non-null-to-null `ON DELETE SET NULL` action;
the paired HMAC reference survives that deletion and, once populated, is
immutable. If a raw ID is already null and no reference exists, a later writer
cannot invent one; that row remains explicitly incomplete. This preserves
account deletion semantics without permitting a row to be attributed to a
different identity.

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
cohort paths used by the future evaluator. The separate encrypted archive slice
owns its monotonic source ledger and backfill in future migration `0021`.

## Local verification

From a clean worktree with the frozen dependency set:

```bash
pnpm --filter @pg72/id exec vitest run test/observability-schema.spec.ts
node --test scripts/public-readiness/d1-manifest.test.mjs \
  scripts/public-readiness/report.test.mjs
pnpm test:public-readiness
pnpm --filter @pg72/id check
pnpm --filter @pg72/test-rp test
git diff --check
```

The focused suite applies all migrations through `0020` and rejects invalid
enums/metrics, provenance mismatch, duplicate unresolved incidents, duplicate
notification/idempotency/attempt tuples, malformed leases, mutable payloads,
invalid incident/delivery transitions, unsupported channels, fabricated
snapshot evidence, and attempt evidence that does not match the exact active
outbox lease. It also rejects invented primary domains, missing ratio minimum
numerators, fictitious severity thresholds, partial or below-threshold secondary
components, and evidence that changes between incident and outbox. The suite
proves the existing audit insert/delete compensation still works and no sequence
table was introduced.

## Remaining gates

Source presence alone must report observability as
`source_present_unverified`, leaving continuity and drills blocked. A later
reviewed slice must add the deterministic evaluator, versioned rule definitions,
repository-controlled successful-run projection/parser and same-run proof,
dedicated alert Queue/DLQ, Email Service adapter, admin
acknowledge/resolve/replay operations, and redaction/race/failure tests.

Isolated Preview must then apply the ordered migration ledger, tune thresholds,
exercise exact D1 and approximate Queue evidence, prove real Email receipt and
operator acknowledgement, and rehearse rollback. No `0020` source or local test
authorizes a push, deploy, remote D1 operation, production alert claim, public
registration, or Production GO.
