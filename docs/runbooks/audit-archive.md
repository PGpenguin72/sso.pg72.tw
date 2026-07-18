# Audit archive D1 repository and unwired writer boundary

> Status: local, request-scoped, unwired D1 repository and pure R2 writer.
> Migration
> `0021_audit_archive.sql`, `0023_audit_archive_r2_evidence.sql`, and
> `worker/audit-archive-repository.ts` still do not read a KEK or access R2.
> `worker/audit-archive-r2-writer.ts` accepts injected D1, R2 and envelope
> verification dependencies, but no entry point, Wrangler binding, Queue,
> scheduler or production mode imports it. Neither module restores R2, publishes
> or consumes Queue messages, schedules Cron work, deletes retained objects, or
> provides an operator endpoint. Production records remain through migration
> `0012`.

## What `0021` and `0023` provide

`0021` is additive after `0020_alert_observability.sql` and creates
exactly six durable tables:

- `audit_archive_source` assigns a safe monotonic sequence to every committed
  `audit_event`. Existing rows are backfilled deterministically by
  `(occurred_at, id)` after the insert capture trigger is installed, but only
  after a parent-primary-key guard proves every captured timestamp is canonical
  UTC millisecond text. One invalid legacy parent aborts the whole backfill
  statement before it can allocate a misleading sequence.
- `audit_archive_key_sentinel` stores only an archive-specific KEK fingerprint
  per explicit key version. The migration creates no row and never reads a key.
- `audit_archive_checkpoint` is a singleton cursor initialized at revision and
  sequence zero. It advances only from a terminal archived batch.
- `audit_archive_batch` owns the immutable v1 manifest, bounded encrypted D1
  envelope, delivery state, R2 read-back evidence and BLOB-GC timestamp.
- `audit_archive_batch_item` is the immutable per-event snapshot. It has a
  deferred batch FK but intentionally has no FK back to mutable audit/source
  rows.
- `audit_archive_attempt` records every claimed lease and its one terminal
  result.

There is no seventh GC table. The batch row owns envelope cleanup evidence;
the checkpoint owns only the monotonic cursor.

`0023` rebuilds only the immutable attempt-evidence table. It preserves an
existing `0021` object-conflict receipt as `legacy_0021_full` without inventing
an observed size or stored checksum. New conflict receipts must instead use the
closed `observed_v1` format with an observed byte count. A successful archive
transition requires observed bytes, R2 stored SHA-256, and full readback
SHA-256 to match the immutable batch object identity before the envelope can be
cleared or the checkpoint can advance.

## What the local repository provides

The repository accepts only a pre-derived, archive-domain fingerprint
reference for sentinel initialize/verify. Raw KEK material never enters D1,
repository output, or repository errors. The derivation and custody layer is
still absent and must be reviewed separately.

One checkpoint-consistent read selects at most 101 source rows in monotonic
sequence order, then returns the largest nonempty head prefix within 100 records
and 384 KiB of canonical plaintext. It never skips an oversized or invalid head
row. Queue preparation validates the canonical record array, manifest, object
digest/key, encrypted-envelope digest/size, checkpoint predecessor and key
version before one item-first/parent `D1Database.batch()` persists them.

Dispatch-generation claim, lease-bound claimed-envelope reads, bounded
due/expired/checkpoint work selection, same-lease renewal, terminal
success/failure/expiry and dead replay use
exact compare-and-swap predicates. Adjacent `changes()` gates prevent dependent
writes or projections from treating a concurrent no-op as success; exact
immutable attempt/audit receipts distinguish response-loss retry from a
divergent concurrent loser. These functions are not imported by the Worker
entry point and perform no R2, Queue or Cron work.

## What the unwired writer provides

`worker/audit-archive-r2-writer.ts` is a bounded service over the repository's
lease-bound immutable envelope reader. It accepts only a narrow R2 binding
surface and an injected KEK/envelope verification provider; the writer itself
does not read a secret or define a binding. Before upload it decrypts and
validates a copied envelope through that provider. It then uses a single-part
create-only R2 PUT with `If-None-Match: *`, the exact content type and
`no-store`, one canonical manifest metadata value, and the immutable object
SHA-256.

A null conditional result and a thrown PUT both enter the same immediate
readback path. The writer uses R2 binding consistency directly, rejects unsafe
metadata, buffers at most the reviewed 512 KiB object cap, computes the full
readback SHA-256, compares stored and computed hashes plus body bytes, and asks
the envelope provider to decrypt the readback again. Only that exact result can
call the repository's atomic archive finalizer. A matching pre-existing object
is an idempotent success; a bounded mismatch records the error-specific full or
partial `0023` evidence. Pre-R2 cryptographic failure records no R2 evidence.
R2/provider transient failures use the D1-owned 30/120/480/900-second schedule,
attempt five becomes dead, and work at or after lease expiry uses the repository
expiry path. A lease with less than 60 seconds remaining is CAS-renewed before
new R2 I/O. The injected raw clock is normalized to a strictly increasing
logical millisecond sequence: equal raw samples advance by one millisecond,
while a true raw reversal fails before the next R2 operation. Lease renewal,
completion and expiry comparisons use that logical time. Caller-owned envelope,
readback and checksum buffers are cleared in `finally` paths where the runtime
permits it.

This source is deliberately not imported by `worker/index.ts`; there is no R2
binding, KEK adapter, Queue consumer, Cron path, real bucket access or remote
proof. Source presence is not encrypted archive continuity.

## Source and snapshot invariants

Source rows cannot be updated or directly deleted. Deletion is allowed only as
the FK cascade after the parent audit row is absent, which preserves the
Passkey step-up compensation transaction. Conflict-aware insert guards protect
both source and `audit_event` identity when SQLite runs with
`recursive_triggers=OFF`; an archived event ID cannot be introduced again.
The parent-time guard is independent of lexical ordering: it reads one parent by
the `audit_event.id` primary key and applies the exact 24-character `+0 seconds`
round-trip predicate. A legacy invalid row remains visible through the `0020`
sparse index and must be repaired there before retrying an unapplied `0021`.

The local repository inserts one bounded canonical record array through one
`json_each(?)` item statement, then inserts its parent batch in the same
`D1Database.batch()`. Item insertion is permanently sealed as soon as that
parent exists, including while it is pending and after it is archived. The
parent trigger requires:

- the exact current checkpoint revision and predecessor sequence;
- a nonempty head prefix with ordinals `1..event_count`;
- both directions of source/item set equality within the selected range;
- an exact live source/audit join for every finalized column;
- the canonical plaintext byte total and v1 manifest/object identity.

Sequence gaps caused by legitimate compensated or deleted unsnapshotted audit
rows are valid. Omitting, duplicating, swapping or changing an item makes the
whole item/parent transaction fail, including its deferred FK.

## Attempt and checkpoint transaction

A due pending/retry claim increments the attempt number, installs a new
five-minute-maximum lease and trigger-inserts its unique in-flight attempt.
The same owner may extend that lease only before its old expiry, with the same
lease ID/generation/attempt, a strictly later timestamp and expiry, and a new
expiry no more than five minutes after renewal. Renewal never creates a second
attempt and cannot alter manifest, membership, envelope, R2/error or replay
state.
Canonical timestamps compare at millisecond precision; work completed 400 ms
before expiry is still before expiry, while `lease_expired` is accepted exactly
at expiry. A retry due time cannot precede its terminal completion time. An
equal millisecond is valid persisted evidence, but cannot be reclaimed at that
same instant because every batch transition must advance `updated_at`.

Only the matching in-flight attempt may terminalize. Retry is bounded to
attempts one through four; attempt five becomes dead. Integrity/object
conflicts become `corrupt` and cannot enter automatic or manual replay.
Dead-only manual replay requires a same-batch successful audit event, increments
the dispatch generation and resets attempts without changing manifest,
envelope or object identity.

The success path is one nested SQLite transaction:

```text
terminal attempt UPDATE validates object bytes + stored/readback SHA-256
  -> batch UPDATE writes archived + complete R2 evidence
     + archived/GC time + encrypted_envelope = NULL
  -> checkpoint UPDATE advances exact predecessor revision/sequence
```

If the lease or checkpoint is stale, any trigger abort rolls back the terminal
attempt, batch state, R2 evidence, BLOB clear and cursor together. R2 I/O stays
outside the D1 transaction. The unwired writer verifies an existing create-only
object before issuing this terminal update, but no runtime calls it yet.

## Local verification

From a clean worktree with the frozen dependency set:

```bash
pnpm --filter @pg72/id exec vitest run \
  test/audit-archive-schema.spec.ts \
  test/audit-archive-crypto.spec.ts \
  test/audit-archive-repository.spec.ts \
  test/audit-archive-r2-writer.spec.ts
node --test scripts/public-readiness/alert-source-time-integrity-migration.test.mjs \
  scripts/public-readiness/audit-archive-migration.test.mjs \
  scripts/public-readiness/d1-manifest.test.mjs \
  scripts/public-readiness/dependency-contracts.test.mjs
pnpm test:public-readiness
pnpm --filter @pg72/id check
pnpm --filter @pg72/test-rp test
git diff --check
```

The focused suites cover fresh and seeded-`0020` migration, `0021` to `0023`
active-lease and legacy-conflict preservation, deterministic backfill,
invalid-parent transactional abort and canonical repair,
bounded/byte-capped source selection, sentinel continuity, deferred canonical
item-first persistence and rollback, hostile replace/update/delete with
recursive triggers disabled, Passkey-compatible source cascade, response-loss
retry, concurrent creator/claim/terminal/replay losers, exact same-owner lease
renewal, millisecond expiry boundaries, attempts one through five, full-evidence
corrupt state, audited manual replay, stale-checkpoint all-or-nothing rollback,
BLOB cleanup, strict projection parsing, pinned query plans, private
backup/isolated restore, `quick_check` and foreign-key integrity.

The writer suite additionally covers create success, exact conditional and
uncertain-PUT readback, uncertain conflicting objects, GET null/throw, absent or
wrong stored checksums, extra/missing/wrong metadata, zero/short/oversized and
overflowing bodies with cancellation, full body and post-readback crypto
mismatches, pre-R2 crypto failure without R2 evidence, terminal response-loss
duplicate classification, D1 retry timing through attempt five,
unavailable/throwing verifier redaction, stale/expired/renewal-conflict leases,
expiry after a committed PUT, and clearing caller-owned temporary buffers.

## Remaining gates

Schema, repository and pure writer presence do not satisfy encrypted archive
continuity. The dependency must remain `dependency_missing` until a separately
reviewed slice adds all of the following and executes their proof in the same
run:

- archive-domain fingerprint derivation, KEK custody and key escrow;
- add the closed KEK adapter, writer runtime integration and remote proof, and
  implement the bounded non-HTTP restore;
- dedicated Queue, DLQ consumer and D1-authoritative Cron redrive;
- key escrow, external non-Cloudflare backup and restore exercise;
- owner-approved retention/Bucket Lock policy, Preview failure drills and
  measured RPO/RTO.

Same-account R2 is not an external backup. Worker rollback first disables the
future archive mode and leaves all six tables, triggers, objects and checkpoint
evidence intact. Migration rollback requires an owner-controlled backup/Time
Travel restore or a reviewed forward fix; never delete ledger rows or migration
records by hand.
