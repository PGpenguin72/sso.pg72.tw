import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import {
  AuditArchiveRepositoryError,
  acquireAuditArchiveLease,
  adoptAuditArchiveLease,
  expireAuditArchiveLease,
  failAuditArchiveLease,
  finalizeAuditArchiveLease,
  initializeOrVerifyAuditArchiveKey,
  queueAuditArchiveBatch,
  readClaimedAuditArchiveBatch,
  renewAuditArchiveLease,
  replayDeadAuditArchiveBatch,
  selectAuditArchiveRuntimeWork,
  selectAuditArchiveSource,
  type AuditArchiveLease,
  type AuditArchiveR2Evidence,
  type QueueAuditArchiveBatchInput,
} from "../worker/audit-archive-repository";
import {
  sealAuditArchiveV1,
  type AuditArchiveManifestV1,
} from "../worker/audit-archive-crypto";

const START = Date.parse("2026-07-18T08:00:00.000Z");
const KEY_VERSION = "v1";
const ZERO_KEK = "A".repeat(43);
const FINGERPRINT = reference(91);

async function dropArchiveLedger(): Promise<void> {
  const triggers = await env.PG72_ID_DB.prepare(
    `SELECT name FROM sqlite_schema
      WHERE type = 'trigger'
        AND (name GLOB 'audit_archive_*' OR name GLOB 'audit_event_archive_*')
      ORDER BY name`,
  ).all<{ name: string }>();
  for (const { name } of triggers.results) {
    if (!/^[a-z0-9_]+$/.test(name)) throw new Error("unsafe test trigger name");
    await env.PG72_ID_DB.prepare(`DROP TRIGGER "${name}"`).run();
  }
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_attempt"),
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_batch_item"),
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_batch"),
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_checkpoint"),
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_key_sentinel"),
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_source"),
  ]);
  await env.PG72_ID_DB.prepare("DELETE FROM audit_event").run();
}

async function applyArchiveMigration(migrationName: string): Promise<void> {
  const migration = env.TEST_MIGRATIONS.find(({ name }) => name === migrationName);
  if (!migration) throw new Error(`missing archive migration: ${migrationName}`);
  await env.PG72_ID_DB.batch(
    migration.queries.map((query) => env.PG72_ID_DB.prepare(query)),
  );
}

async function resetArchiveLedger(): Promise<void> {
  await dropArchiveLedger();
  await applyArchiveMigration("0021_audit_archive.sql");
  await applyArchiveMigration("0023_audit_archive_r2_evidence.sql");
  await applyArchiveMigration("0024_audit_archive_r2_evidence_guard.sql");
}

async function expectArchiveIntegrity(): Promise<void> {
  expect(
    (await env.PG72_ID_DB.prepare("PRAGMA foreign_key_check").all()).results,
  ).toEqual([]);
  expect(
    await env.PG72_ID_DB.prepare("PRAGMA quick_check").first<string>(
      "quick_check",
    ),
  ).toBe("ok");
}

function mutateBatchResult(
  database: D1Database,
  mutate: (results: D1Result[]) => void,
): D1Database {
  return new Proxy(database, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          const results = await target.batch(statements);
          mutate(results);
          return results;
        };
      }
      const result: unknown = Reflect.get(target, property, target);
      return typeof result === "function" ? result.bind(target) : result;
    },
  });
}

function mutateAllResult(
  database: D1Database,
  mutate: (result: D1Result) => void,
): D1Database {
  const wrap = (statement: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "all") {
          return async () => {
            const result = await target.all();
            mutate(result);
            return result;
          };
        }
        if (property === "bind") {
          return (...values: unknown[]) => wrap(target.bind(...values));
        }
        const result: unknown = Reflect.get(target, property, target);
        return typeof result === "function" ? result.bind(target) : result;
      },
    });
  return new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => wrap(target.prepare(query));
      }
      const result: unknown = Reflect.get(target, property, target);
      return typeof result === "function" ? result.bind(target) : result;
    },
  });
}

function at(milliseconds: number): string {
  return new Date(START + milliseconds).toISOString();
}

function base64Url32(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function reference(seed?: number): string {
  const bytes = seed === undefined
    ? crypto.getRandomValues(new Uint8Array(32))
    : new Uint8Array(32).fill(seed);
  return base64Url32(bytes);
}

async function expectRepositoryError(
  promise: Promise<unknown>,
  code: AuditArchiveRepositoryError["code"],
  forbidden: readonly string[] = [],
): Promise<void> {
  try {
    await promise;
    throw new Error("expected repository error");
  } catch (error) {
    expect(error).toBeInstanceOf(AuditArchiveRepositoryError);
    const repositoryError = error as AuditArchiveRepositoryError;
    expect(repositoryError.code).toBe(code);
    expect(repositoryError.message).toBe(`Audit archive repository failed (${code})`);
    for (const value of forbidden) expect(repositoryError.message).not.toContain(value);
  }
}

async function insertAuditEvent(
  index: number,
  options: {
    eventId?: string;
    metadata?: Record<string, boolean | number | string>;
    occurredAt?: string;
  } = {},
): Promise<string> {
  const eventId = options.eventId ?? `archive.repo.${index}.${crypto.randomUUID()}`;
  await env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, subject_id, outcome, metadata_json, occurred_at)
     VALUES (?, 'test.archive.repository', ?, 'success', ?, ?)`,
  )
    .bind(
      eventId,
      `subject:${index}`,
      JSON.stringify(options.metadata ?? { kind: "archive_repo_test", ordinal: index }),
      options.occurredAt ?? at(index * 100),
    )
    .run();
  return eventId;
}

async function initializeKey(createdAt = at(1)): Promise<void> {
  await initializeOrVerifyAuditArchiveKey(env.PG72_ID_DB, {
    createdAt,
    fingerprintRef: FINGERPRINT,
    keyVersion: KEY_VERSION,
  });
}

interface CandidateFixture {
  input: QueueAuditArchiveBatchInput;
  manifest: AuditArchiveManifestV1;
}

async function buildCandidate(
  createdAt: string,
  options: {
    batchKey?: string;
    keyVersion?: string;
  } = {},
): Promise<CandidateFixture> {
  const selection = await selectAuditArchiveSource(env.PG72_ID_DB);
  if (selection.records.length === 0) throw new Error("missing archive source");
  const sealed = await sealAuditArchiveV1({
    batchGeneration: selection.checkpoint.revision + 1,
    checkpointFromSequence: selection.checkpoint.lastSequence,
    createdAt,
    kek: ZERO_KEK,
    keyVersion: options.keyVersion ?? KEY_VERSION,
    records: selection.records,
  });
  return {
    input: {
      batchKey: options.batchKey ?? reference(),
      checkpoint: selection.checkpoint,
      encryptedEnvelope: sealed.objectBytes,
      manifest: sealed.manifest,
      records: selection.records,
    },
    manifest: sealed.manifest,
  };
}

async function queuedFixture(index = 1): Promise<CandidateFixture> {
  await initializeKey();
  await insertAuditEvent(index);
  const fixture = await buildCandidate(at(10_000 + index));
  expect(await queueAuditArchiveBatch(env.PG72_ID_DB, fixture.input)).toBe("queued");
  return fixture;
}

async function acquire(
  fixture: CandidateFixture,
  claimedAt: string,
  leaseExpiresAt: string,
  leaseId = reference(),
  dispatchGeneration = 1,
): Promise<AuditArchiveLease> {
  const result = await acquireAuditArchiveLease(env.PG72_ID_DB, {
    batchKey: fixture.input.batchKey,
    claimedAt,
    dispatchGeneration,
    leaseExpiresAt,
    leaseId,
  });
  expect(result.status).toBe("acquired");
  if (result.lease === null) throw new Error("missing acquired lease");
  return result.lease;
}

function evidence(
  manifest: AuditArchiveManifestV1,
  completedAt: string,
  suffix = "1",
): AuditArchiveR2Evidence {
  return {
    etag: `etag-${suffix}`,
    observedBytes: manifest.objectBytes,
    readbackAt: completedAt,
    readbackSha256: manifest.objectSha256,
    storedSha256: manifest.objectSha256,
    version: `version-${suffix}`,
  };
}

async function driveFixtureToDead(
  fixture: CandidateFixture,
): Promise<{ completedAt: string; firstFailure: Parameters<typeof failAuditArchiveLease>[1] }> {
  let claimAt = 11_000;
  let firstFailure: Parameters<typeof failAuditArchiveLease>[1] | null = null;
  let completedAt = at(0);
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const lease = await acquire(
      fixture,
      at(claimAt),
      at(claimAt + 300_000),
    );
    completedAt = at(claimAt + 1_000);
    const failure = {
      completedAt,
      errorCode: "r2_transient" as const,
      evidence: null,
      lease,
      nextAttemptAt: attempt === 5 ? null : completedAt,
    };
    if (attempt === 1) firstFailure = failure;
    expect(await failAuditArchiveLease(env.PG72_ID_DB, failure)).toBe("applied");
    expect(await failAuditArchiveLease(env.PG72_ID_DB, failure)).toBe("duplicate");
    claimAt += 1_001;
  }
  if (firstFailure === null) throw new Error("missing first failure");
  return { completedAt, firstFailure };
}

describe.sequential("audit archive D1 repository", () => {
  beforeEach(resetArchiveLedger);

  it("initializes and verifies a fingerprint-only sentinel without returning key material", async () => {
    const first = await initializeOrVerifyAuditArchiveKey(env.PG72_ID_DB, {
      createdAt: at(1),
      fingerprintRef: FINGERPRINT,
      keyVersion: KEY_VERSION,
    });
    expect(first).toEqual({
      createdAt: at(1),
      initialized: true,
      keyVersion: KEY_VERSION,
    });
    expect(JSON.stringify(first)).not.toContain(FINGERPRINT);
    expect(JSON.stringify(first)).not.toContain(ZERO_KEK);

    const verified = await initializeOrVerifyAuditArchiveKey(env.PG72_ID_DB, {
      createdAt: at(2),
      fingerprintRef: FINGERPRINT,
      keyVersion: KEY_VERSION,
    });
    expect(verified).toEqual({
      createdAt: at(1),
      initialized: false,
      keyVersion: KEY_VERSION,
    });
    await expectRepositoryError(
      initializeOrVerifyAuditArchiveKey(env.PG72_ID_DB, {
        createdAt: at(3),
        fingerprintRef: reference(92),
        keyVersion: KEY_VERSION,
      }),
      "key_mismatch",
      [FINGERPRINT, reference(92), ZERO_KEK],
    );
    await expectRepositoryError(
      initializeOrVerifyAuditArchiveKey(env.PG72_ID_DB, {
        createdAt: at(3),
        fingerprintRef: FINGERPRINT,
        keyVersion: "v2",
      }),
      "key_mismatch",
      [FINGERPRINT, ZERO_KEK],
    );
  });

  it("serializes concurrent sentinel initialization and rejects the divergent loser", async () => {
    const same = await Promise.all([
      initializeOrVerifyAuditArchiveKey(env.PG72_ID_DB, {
        createdAt: at(10),
        fingerprintRef: FINGERPRINT,
        keyVersion: KEY_VERSION,
      }),
      initializeOrVerifyAuditArchiveKey(env.PG72_ID_DB, {
        createdAt: at(10),
        fingerprintRef: FINGERPRINT,
        keyVersion: KEY_VERSION,
      }),
    ]);
    expect(same.map(({ initialized }) => initialized).toSorted()).toEqual([
      false,
      true,
    ]);

    const divergent = await Promise.allSettled([
      initializeOrVerifyAuditArchiveKey(env.PG72_ID_DB, {
        createdAt: at(20),
        fingerprintRef: reference(20),
        keyVersion: "v2",
      }),
      initializeOrVerifyAuditArchiveKey(env.PG72_ID_DB, {
        createdAt: at(20),
        fingerprintRef: reference(21),
        keyVersion: "v2",
      }),
    ]);
    expect(divergent.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    const rejection = divergent.find(({ status }) => status === "rejected");
    expect(rejection).toMatchObject({
      reason: { code: "key_mismatch" },
      status: "rejected",
    });
  });

  it("preserves an active 0021 lease while rebuilding the evidence table", async () => {
    await dropArchiveLedger();
    await applyArchiveMigration("0021_audit_archive.sql");
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    expect(
      (await env.PG72_ID_DB.prepare(
        "PRAGMA table_info(audit_archive_attempt)",
      ).all<{ name: string }>()).results.map(({ name }) => name),
    ).not.toContain("r2_observed_bytes");

    await applyArchiveMigration("0023_audit_archive_r2_evidence.sql");
    await applyArchiveMigration("0024_audit_archive_r2_evidence_guard.sql");
    expect(
      (await env.PG72_ID_DB.prepare(
        "PRAGMA table_info(audit_archive_attempt)",
      ).all<{ name: string }>()).results.map(({ name }) => name),
    ).toEqual(expect.arrayContaining([
      "r2_conflict_evidence_format",
      "r2_observed_bytes",
      "r2_stored_sha256",
    ]));
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT outcome, lease_id, r2_observed_bytes, r2_stored_sha256
           FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(lease.leaseId)
        .first(),
    ).toEqual({
      lease_id: lease.leaseId,
      outcome: "in_flight",
      r2_observed_bytes: null,
      r2_stored_sha256: null,
    });
    const claimed = await readClaimedAuditArchiveBatch(env.PG72_ID_DB, { lease });
    expect(claimed?.objectSha256).toBe(fixture.manifest.objectSha256);
    claimed?.encryptedEnvelope.fill(0);
    const completedAt = at(20_000);
    expect(
      await finalizeAuditArchiveLease(env.PG72_ID_DB, {
        completedAt,
        evidence: evidence(fixture.manifest, completedAt),
        lease,
      }),
    ).toBe("applied");
  });

  it("preserves legacy 0021 conflict evidence without inventing observations", async () => {
    await dropArchiveLedger();
    await applyArchiveMigration("0021_audit_archive.sql");
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const completedAt = at(20_000);
    const legacy = {
      etag: "legacy-conflict-etag",
      readbackSha256: "f".repeat(64),
      version: "legacy-conflict-version",
    };
    await env.PG72_ID_DB.prepare(
      `UPDATE audit_archive_attempt
          SET outcome = 'corrupt', resulting_status = 'corrupt',
              r2_version = ?, r2_etag = ?, r2_readback_sha256 = ?,
              r2_readback_at = ?, error_code = 'r2_object_conflict',
              completed_at = ?
        WHERE id = ?`,
    )
      .bind(
        legacy.version,
        legacy.etag,
        legacy.readbackSha256,
        completedAt,
        completedAt,
        lease.leaseId,
      )
      .run();

    await applyArchiveMigration("0023_audit_archive_r2_evidence.sql");
    await applyArchiveMigration("0024_audit_archive_r2_evidence_guard.sql");
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT outcome, error_code, r2_version, r2_etag,
                r2_observed_bytes, r2_stored_sha256, r2_readback_sha256,
                r2_readback_at, r2_conflict_evidence_format
           FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(lease.leaseId)
        .first(),
    ).toEqual({
      error_code: "r2_object_conflict",
      outcome: "corrupt",
      r2_conflict_evidence_format: "legacy_0021_full",
      r2_etag: legacy.etag,
      r2_observed_bytes: null,
      r2_readback_at: completedAt,
      r2_readback_sha256: legacy.readbackSha256,
      r2_stored_sha256: null,
      r2_version: legacy.version,
    });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, last_error_code,
                encrypted_envelope IS NOT NULL AS has_envelope
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(fixture.input.batchKey)
        .first(),
    ).toEqual({
      has_envelope: 1,
      last_error_code: "r2_object_conflict",
      status: "corrupt",
    });
    await expectArchiveIntegrity();
  });

  it.each(["crypto_integrity", "r2_readback_mismatch"] as const)(
    "preserves already-committed 0023 null-observed %s evidence exactly",
    async (errorCode) => {
      await dropArchiveLedger();
      await applyArchiveMigration("0021_audit_archive.sql");
      await applyArchiveMigration("0023_audit_archive_r2_evidence.sql");
      const fixture = await queuedFixture();
      const lease = await acquire(fixture, at(11_000), at(311_000));
      const completedAt = at(20_000);
      await env.PG72_ID_DB.prepare(
        `UPDATE audit_archive_attempt
            SET outcome = 'corrupt', resulting_status = 'corrupt',
                r2_version = 'version-current', r2_etag = 'etag-current',
                r2_stored_sha256 = ?, r2_readback_sha256 = ?,
                r2_readback_at = ?, error_code = ?, completed_at = ?
          WHERE id = ?`,
      )
        .bind(
          fixture.manifest.objectSha256,
          "f".repeat(64),
          completedAt,
          errorCode,
          completedAt,
          lease.leaseId,
        )
        .run();
      const before = await env.PG72_ID_DB.prepare(
        `SELECT * FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(lease.leaseId)
        .first();
      if (before === null) throw new Error("missing pre-0024 evidence row");

      await applyArchiveMigration("0024_audit_archive_r2_evidence_guard.sql");
      expect(
        await env.PG72_ID_DB.prepare(
          `SELECT * FROM audit_archive_attempt WHERE id = ?`,
        )
          .bind(lease.leaseId)
          .first(),
      ).toEqual(before);
      expect(before).toMatchObject({
        error_code: errorCode,
        outcome: "corrupt",
        r2_observed_bytes: null,
      });
      await expectArchiveIntegrity();
    },
  );

  it("blocks new current corrupt evidence without observed bytes after 0024", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const completedAt = at(20_000);
    for (const errorCode of [
      "crypto_integrity",
      "r2_readback_mismatch",
    ] as const) {
      await expect(
        env.PG72_ID_DB.prepare(
          `UPDATE audit_archive_attempt
              SET outcome = 'corrupt', resulting_status = 'corrupt',
                  r2_version = 'version-current', r2_etag = 'etag-current',
                  r2_stored_sha256 = ?, r2_readback_sha256 = ?,
                  r2_readback_at = ?, error_code = ?, completed_at = ?
            WHERE id = ?`,
        )
          .bind(
            fixture.manifest.objectSha256,
            "f".repeat(64),
            completedAt,
            errorCode,
            completedAt,
            lease.leaseId,
          )
          .run(),
      ).rejects.toThrow(/current R2 evidence requires observed bytes/);
    }
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT outcome, r2_version, r2_observed_bytes, completed_at
           FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(lease.leaseId)
        .first(),
    ).toEqual({
      completed_at: null,
      outcome: "in_flight",
      r2_observed_bytes: null,
      r2_version: null,
    });
    await expectArchiveIntegrity();
  });

  it("selects a monotonic head prefix, preserves legitimate gaps, and caps at 100", async () => {
    expect(await selectAuditArchiveSource(env.PG72_ID_DB)).toEqual({
      checkpoint: {
        lastArchivedAt: null,
        lastBatchKey: null,
        lastSequence: 0,
        revision: 0,
      },
      hasMore: false,
      records: [],
    });
    const first = await insertAuditEvent(1);
    const removed = await insertAuditEvent(2);
    await insertAuditEvent(3);
    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(removed)
      .run();
    for (let index = 4; index <= 103; index += 1) await insertAuditEvent(index);

    const selection = await selectAuditArchiveSource(env.PG72_ID_DB);
    expect(selection.records).toHaveLength(100);
    expect(selection.hasMore).toBe(true);
    expect(selection.records[0]?.eventId).toBe(first);
    expect(selection.records[1]!.sequence - selection.records[0]!.sequence).toBe(2);
    expect(selection.records.every((record, index, records) =>
      index === 0 || record.sequence > records[index - 1]!.sequence
    )).toBe(true);
  });

  it("stops at the canonical plaintext byte cap without skipping the head", async () => {
    const metadata = Object.fromEntries(
      Array.from({ length: 32 }, (_, index) => [
        `field${index}`,
        `${index}`.padEnd(250, "x"),
      ]),
    );
    for (let index = 1; index <= 60; index += 1) {
      await insertAuditEvent(index, { metadata });
    }
    const selection = await selectAuditArchiveSource(env.PG72_ID_DB);
    expect(selection.records.length).toBeGreaterThan(1);
    expect(selection.records.length).toBeLessThan(60);
    expect(selection.hasMore).toBe(true);
    expect(selection.records.at(-1)!.sequence).toBe(
      selection.records[0]!.sequence + selection.records.length - 1,
    );
  });

  it("queues one exact item-first batch and classifies response loss idempotently", async () => {
    await initializeKey();
    await insertAuditEvent(1);
    const tailSelection = await selectAuditArchiveSource(env.PG72_ID_DB);
    const fixture = await buildCandidate(at(10_000));
    await insertAuditEvent(2, { occurredAt: at(9_000) });
    expect(tailSelection.records).toHaveLength(1);
    expect(await queueAuditArchiveBatch(env.PG72_ID_DB, fixture.input)).toBe("queued");
    expect(await queueAuditArchiveBatch(env.PG72_ID_DB, fixture.input)).toBe("duplicate");
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT count(*) AS count FROM audit_archive_batch_item
          WHERE batch_key = ?`,
      )
        .bind(fixture.input.batchKey)
        .first<number>("count"),
    ).toBe(1);
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT manifest_json, length(encrypted_envelope) AS envelope_bytes
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(fixture.input.batchKey)
        .first(),
    ).toEqual({
      envelope_bytes: fixture.manifest.objectBytes,
      manifest_json: JSON.stringify(fixture.manifest),
    });
  });

  it("rejects a manifest that does not describe the canonical records before writing", async () => {
    await initializeKey();
    await insertAuditEvent(1);
    const fixture = await buildCandidate(at(10_000));
    await expectRepositoryError(
      queueAuditArchiveBatch(env.PG72_ID_DB, {
        ...fixture.input,
        manifest: {
          ...fixture.manifest,
          eventCount: fixture.manifest.eventCount + 1,
        },
      }),
      "invalid_input",
      [fixture.input.batchKey, fixture.manifest.objectSha256],
    );
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_batch",
      ).first<number>("count"),
    ).toBe(0);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_batch_item",
      ).first<number>("count"),
    ).toBe(0);
  });

  it("lets one concurrent batch creator win and leaves no loser membership", async () => {
    await initializeKey();
    await insertAuditEvent(1);
    const first = await buildCandidate(at(10_000));
    const second = await buildCandidate(at(10_000));
    const results = await Promise.all([
      queueAuditArchiveBatch(env.PG72_ID_DB, first.input),
      queueAuditArchiveBatch(env.PG72_ID_DB, second.input),
    ]);
    expect(results.toSorted()).toEqual(["conflict", "queued"]);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_batch",
      ).first<number>("count"),
    ).toBe(1);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_batch_item",
      ).first<number>("count"),
    ).toBe(1);
  });

  it("rolls back stale source membership and rejects a missing key sentinel", async () => {
    await initializeKey();
    const eventId = await insertAuditEvent(1);
    const stale = await buildCandidate(at(10_000));
    await env.PG72_ID_DB.prepare("DELETE FROM audit_event WHERE id = ?")
      .bind(eventId)
      .run();
    await expectRepositoryError(
      queueAuditArchiveBatch(env.PG72_ID_DB, stale.input),
      "write_failed",
      [eventId, stale.input.batchKey],
    );
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_batch_item",
      ).first<number>("count"),
    ).toBe(0);

    await insertAuditEvent(2);
    const missingKey = await buildCandidate(at(20_000), { keyVersion: "v2" });
    await expectRepositoryError(
      queueAuditArchiveBatch(env.PG72_ID_DB, missingKey.input),
      "key_unavailable",
      [missingKey.input.batchKey, ZERO_KEK],
    );
  });

  it("acquires a due lease once and recognizes an exact response retry", async () => {
    const fixture = await queuedFixture();
    const leaseId = reference();
    const input = {
      batchKey: fixture.input.batchKey,
      claimedAt: at(11_000),
      dispatchGeneration: 1,
      leaseExpiresAt: at(311_000),
      leaseId,
    };
    const first = await acquireAuditArchiveLease(env.PG72_ID_DB, input);
    expect(first.status).toBe("acquired");
    expect(first.lease).toMatchObject({
      attemptNumber: 1,
      leaseId,
      startedAt: at(11_000),
      updatedAt: at(11_000),
    });
    const duplicate = await acquireAuditArchiveLease(env.PG72_ID_DB, input);
    expect(duplicate).toEqual({ lease: first.lease, status: "duplicate" });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_attempt",
      ).first<number>("count"),
    ).toBe(1);
  });

  it("rejects early/oversized claims and gives one concurrent claimant the lease", async () => {
    const fixture = await queuedFixture();
    expect(
      await acquireAuditArchiveLease(env.PG72_ID_DB, {
        batchKey: fixture.input.batchKey,
        claimedAt: at(9_000),
        dispatchGeneration: 1,
        leaseExpiresAt: at(309_000),
        leaseId: reference(),
      }),
    ).toEqual({ lease: null, status: "conflict" });
    await expectRepositoryError(
      acquireAuditArchiveLease(env.PG72_ID_DB, {
        batchKey: fixture.input.batchKey,
        claimedAt: at(11_000),
        dispatchGeneration: 1,
        leaseExpiresAt: at(311_001),
        leaseId: reference(),
      }),
      "invalid_input",
    );

    const results = await Promise.all([
      acquireAuditArchiveLease(env.PG72_ID_DB, {
        batchKey: fixture.input.batchKey,
        claimedAt: at(11_000),
        dispatchGeneration: 1,
        leaseExpiresAt: at(311_000),
        leaseId: reference(),
      }),
      acquireAuditArchiveLease(env.PG72_ID_DB, {
        batchKey: fixture.input.batchKey,
        claimedAt: at(11_000),
        dispatchGeneration: 1,
        leaseExpiresAt: at(311_000),
        leaseId: reference(),
      }),
    ]);
    expect(results.map(({ status }) => status).toSorted()).toEqual([
      "acquired",
      "conflict",
    ]);
  });

  it("fences stale and future Queue generations across a manual replay", async () => {
    const fixture = await queuedFixture();
    for (const dispatchGeneration of [2, 1_000_000]) {
      expect(
        await acquireAuditArchiveLease(env.PG72_ID_DB, {
          batchKey: fixture.input.batchKey,
          claimedAt: at(11_000),
          dispatchGeneration,
          leaseExpiresAt: at(311_000),
          leaseId: reference(),
        }),
      ).toEqual({ lease: null, status: "conflict" });
    }

    await driveFixtureToDead(fixture);
    const replayedAt = at(2_000_000);
    expect(
      await replayDeadAuditArchiveBatch(env.PG72_ID_DB, {
        auditEventId: `archive.replay.${crypto.randomUUID()}`,
        batchKey: fixture.input.batchKey,
        dispatchGeneration: 1,
        nextAttemptAt: replayedAt,
        replayedAt,
      }),
    ).toBe("applied");
    for (const dispatchGeneration of [1, 3]) {
      expect(
        await acquireAuditArchiveLease(env.PG72_ID_DB, {
          batchKey: fixture.input.batchKey,
          claimedAt: at(2_000_001),
          dispatchGeneration,
          leaseExpiresAt: at(2_300_001),
          leaseId: reference(),
        }),
      ).toEqual({ lease: null, status: "conflict" });
    }
    const exact = await acquireAuditArchiveLease(env.PG72_ID_DB, {
      batchKey: fixture.input.batchKey,
      claimedAt: at(2_000_001),
      dispatchGeneration: 2,
      leaseExpiresAt: at(2_300_001),
      leaseId: reference(),
    });
    expect(exact.status).toBe("acquired");
    expect(exact.lease?.dispatchGeneration).toBe(2);
  });

  it("reads one immutable envelope only for the exact active lease", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const claimed = await readClaimedAuditArchiveBatch(env.PG72_ID_DB, { lease });
    expect(claimed).not.toBeNull();
    expect(claimed).toMatchObject({
      batchKey: fixture.input.batchKey,
      checkpointFromSequence: fixture.manifest.checkpointFromSequence,
      checkpointRevision: fixture.manifest.batchGeneration - 1,
      contentType: fixture.manifest.contentType,
      keyVersion: fixture.manifest.keyVersion,
      manifest: fixture.manifest,
      objectBytes: fixture.manifest.objectBytes,
      objectKey: fixture.manifest.objectKey,
      objectSha256: fixture.manifest.objectSha256,
    });
    expect(claimed?.encryptedEnvelope).not.toBe(fixture.input.encryptedEnvelope);
    expect(Array.from(claimed?.encryptedEnvelope ?? [])).toEqual(
      Array.from(fixture.input.encryptedEnvelope),
    );
    claimed?.encryptedEnvelope.fill(0);

    for (const staleLease of [
      { ...lease, leaseId: reference() },
      { ...lease, dispatchGeneration: lease.dispatchGeneration + 1 },
      { ...lease, updatedAt: at(12_000) },
    ]) {
      expect(
        await readClaimedAuditArchiveBatch(env.PG72_ID_DB, { lease: staleLease }),
      ).toBeNull();
    }
  });

  it("fails the claimed-envelope reader closed on shape and digest corruption", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const shapeDatabase = mutateAllResult(env.PG72_ID_DB, (result) => {
      const row = result.results[0];
      if (typeof row === "object" && row !== null) {
        result.results[0] = { ...row, unexpected: true };
      }
    });
    await expectRepositoryError(
      readClaimedAuditArchiveBatch(shapeDatabase, { lease }),
      "source_invalid",
      [fixture.input.batchKey, lease.leaseId],
    );

    const missingDatabase = mutateAllResult(env.PG72_ID_DB, (result) => {
      const row = result.results[0];
      if (typeof row === "object" && row !== null) {
        result.results[0] = { ...row, encrypted_envelope: null };
      }
    });
    await expectRepositoryError(
      readClaimedAuditArchiveBatch(missingDatabase, { lease }),
      "source_invalid",
    );

    const lengthDatabase = mutateAllResult(env.PG72_ID_DB, (result) => {
      const row = result.results[0];
      if (typeof row === "object" && row !== null) {
        result.results[0] = { ...row, envelope_bytes: fixture.manifest.objectBytes - 1 };
      }
    });
    await expectRepositoryError(
      readClaimedAuditArchiveBatch(lengthDatabase, { lease }),
      "source_invalid",
    );

    const sparseDatabase = mutateAllResult(env.PG72_ID_DB, (result) => {
      const row = result.results[0];
      if (typeof row === "object" && row !== null) {
        result.results[0] = {
          ...row,
          encrypted_envelope: new Array(fixture.manifest.objectBytes),
        };
      }
    });
    await expectRepositoryError(
      readClaimedAuditArchiveBatch(sparseDatabase, { lease }),
      "source_invalid",
    );

    const digestDatabase = mutateAllResult(env.PG72_ID_DB, (result) => {
      const row = result.results[0];
      if (typeof row !== "object" || row === null) return;
      const corrupted = Array.from(fixture.input.encryptedEnvelope);
      corrupted[corrupted.length - 1] ^= 1;
      result.results[0] = { ...row, encrypted_envelope: corrupted };
    });
    await expectRepositoryError(
      readClaimedAuditArchiveBatch(digestDatabase, { lease }),
      "source_invalid",
      [fixture.manifest.objectSha256, lease.leaseId],
    );
  });

  it("selects bounded due, expired, and checkpoint-blocking runtime work", async () => {
    expect(
      await selectAuditArchiveRuntimeWork(env.PG72_ID_DB, {
        asOf: at(1),
        limit: 25,
      }),
    ).toEqual({
      checkpointBatch: null,
      due: [],
      dueHasMore: false,
      expired: [],
      expiredHasMore: false,
    });

    const fixture = await queuedFixture();
    const beforeDue = await selectAuditArchiveRuntimeWork(env.PG72_ID_DB, {
      asOf: at(10_000),
      limit: 25,
    });
    expect(beforeDue).toEqual({
      checkpointBatch: { batchKey: fixture.input.batchKey, status: "pending" },
      due: [],
      dueHasMore: false,
      expired: [],
      expiredHasMore: false,
    });
    const due = await selectAuditArchiveRuntimeWork(env.PG72_ID_DB, {
      asOf: fixture.manifest.createdAt,
      limit: 25,
    });
    expect(due.due).toEqual([{
      batchKey: fixture.input.batchKey,
      dispatchGeneration: 1,
    }]);
    expect(due.checkpointBatch?.status).toBe("pending");

    const lease = await acquire(fixture, at(11_000), at(311_000));
    const beforeExpiry = await selectAuditArchiveRuntimeWork(env.PG72_ID_DB, {
      asOf: at(310_999),
      limit: 25,
    });
    expect(beforeExpiry.due).toEqual([]);
    expect(beforeExpiry.expired).toEqual([]);
    expect(beforeExpiry.checkpointBatch).toEqual({
      batchKey: fixture.input.batchKey,
      status: "processing",
    });
    const atExpiry = await selectAuditArchiveRuntimeWork(env.PG72_ID_DB, {
      asOf: lease.leaseExpiresAt,
      limit: 25,
    });
    expect(atExpiry.expired).toEqual([lease]);
    expect(atExpiry.expiredHasMore).toBe(false);
  });

  it("caps runtime discovery at 25 and reports the 26th row", async () => {
    const fixture = await queuedFixture();
    const dueDatabase = mutateBatchResult(env.PG72_ID_DB, (results) => {
      if (!results[0]) return;
      results[0].results = Array.from({ length: 26 }, (_, index) => ({
        batch_key: reference(index + 1),
        dispatch_generation: 1,
        next_attempt_at: fixture.manifest.createdAt,
        status: "pending",
      }));
    });
    const due = await selectAuditArchiveRuntimeWork(dueDatabase, {
      asOf: fixture.manifest.createdAt,
      limit: 25,
    });
    expect(due.due).toHaveLength(25);
    expect(due.dueHasMore).toBe(true);

    await acquire(fixture, at(11_000), at(311_000));
    const expiredDatabase = mutateBatchResult(env.PG72_ID_DB, (results) => {
      if (!results[1]) return;
      results[1].results = Array.from({ length: 26 }, (_, index) => ({
        attempt_number: 1,
        batch_key: reference(index + 1),
        dispatch_generation: 1,
        lease_expires_at: at(311_000),
        lease_id: reference(index + 101),
        outcome: "in_flight",
        started_at: at(11_000),
        updated_at: at(11_000),
      }));
    });
    const expired = await selectAuditArchiveRuntimeWork(expiredDatabase, {
      asOf: at(311_000),
      limit: 25,
    });
    expect(expired.expired).toHaveLength(25);
    expect(expired.expiredHasMore).toBe(true);

    for (const limit of [0, 26]) {
      await expectRepositoryError(
        selectAuditArchiveRuntimeWork(env.PG72_ID_DB, {
          asOf: at(311_000),
          limit,
        }),
        "invalid_input",
      );
    }
  });

  it("renews the same in-flight attempt with exact CAS and no second attempt row", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(211_000));
    const input = {
      lease,
      leaseExpiresAt: at(310_000),
      renewedAt: at(20_000),
    };
    const renewed = await renewAuditArchiveLease(env.PG72_ID_DB, input);
    expect(renewed.status).toBe("renewed");
    expect(renewed.lease).toEqual({
      ...lease,
      leaseExpiresAt: at(310_000),
      updatedAt: at(20_000),
    });
    expect(await renewAuditArchiveLease(env.PG72_ID_DB, input)).toEqual({
      lease: renewed.lease,
      status: "duplicate",
    });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_attempt",
      ).first<number>("count"),
    ).toBe(1);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT started_at FROM audit_archive_attempt WHERE id = ?",
      )
        .bind(lease.leaseId)
        .first<string>("started_at"),
    ).toBe(lease.startedAt);
  });

  it("adopts only a live strict descendant of the same in-flight lease fence", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(211_000));
    expect(
      await adoptAuditArchiveLease(env.PG72_ID_DB, {
        asOf: at(12_000),
        lease,
      }),
    ).toEqual({ lease, status: "current" });

    const renewal = await renewAuditArchiveLease(env.PG72_ID_DB, {
      lease,
      leaseExpiresAt: at(310_000),
      renewedAt: at(20_000),
    });
    if (renewal.lease === null) throw new Error("missing renewed test lease");
    expect(
      await adoptAuditArchiveLease(env.PG72_ID_DB, {
        asOf: at(21_000),
        lease,
      }),
    ).toEqual({ lease: renewal.lease, status: "adopted" });

    for (const [asOf, candidate] of [
      [at(19_000), lease],
      [at(310_000), lease],
      [at(21_000), { ...lease, leaseId: reference() }],
      [
        at(21_000),
        { ...lease, leaseExpiresAt: at(311_000), updatedAt: at(21_000) },
      ],
    ] as const) {
      expect(
        await adoptAuditArchiveLease(env.PG72_ID_DB, {
          asOf,
          lease: candidate,
        }),
      ).toEqual({ lease: null, status: "conflict" });
    }

    expect(
      await failAuditArchiveLease(env.PG72_ID_DB, {
        completedAt: at(22_000),
        errorCode: "r2_transient",
        evidence: null,
        lease: renewal.lease,
        nextAttemptAt: at(52_000),
      }),
    ).toBe("applied");
    expect(
      await adoptAuditArchiveLease(env.PG72_ID_DB, {
        asOf: at(23_000),
        lease,
      }),
    ).toEqual({ lease: null, status: "conflict" });
  });

  it("adopts the single winner of concurrent same-fence renewals", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(211_000));
    const concurrent = await Promise.all([
      renewAuditArchiveLease(env.PG72_ID_DB, {
        lease,
        leaseExpiresAt: at(310_000),
        renewedAt: at(20_000),
      }),
      renewAuditArchiveLease(env.PG72_ID_DB, {
        lease,
        leaseExpiresAt: at(311_000),
        renewedAt: at(21_000),
      }),
    ]);
    expect(concurrent.filter(({ status }) => status === "renewed")).toHaveLength(1);
    expect(concurrent.filter(({ status }) => status === "conflict")).toHaveLength(1);
    const winner = concurrent.find(({ status }) => status === "renewed")?.lease;
    if (winner === null || winner === undefined) {
      throw new Error("missing concurrent renewal winner");
    }
    expect(
      await adoptAuditArchiveLease(env.PG72_ID_DB, {
        asOf: at(22_000),
        lease,
      }),
    ).toEqual({ lease: winner, status: "adopted" });
  });

  it("fails renewal closed for stale, wrong, non-increasing, expired, and oversized leases", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(211_000));
    for (const [renewedAt, expiresAt] of [
      [at(12_000), at(211_000)],
      [at(211_000), at(310_000)],
      [at(12_000), at(312_001)],
    ] as const) {
      await expectRepositoryError(
        renewAuditArchiveLease(env.PG72_ID_DB, {
          lease,
          leaseExpiresAt: expiresAt,
          renewedAt,
        }),
        "invalid_input",
      );
    }
    expect(
      await renewAuditArchiveLease(env.PG72_ID_DB, {
        lease: { ...lease, leaseId: reference() },
        leaseExpiresAt: at(310_000),
        renewedAt: at(12_000),
      }),
    ).toEqual({ lease: null, status: "conflict" });
    for (const staleLease of [
      { ...lease, dispatchGeneration: lease.dispatchGeneration + 1 },
      { ...lease, attemptNumber: lease.attemptNumber + 1 },
    ]) {
      expect(
        await renewAuditArchiveLease(env.PG72_ID_DB, {
          lease: staleLease,
          leaseExpiresAt: at(310_000),
          renewedAt: at(12_000),
        }),
      ).toEqual({ lease: null, status: "conflict" });
    }

    const first = await renewAuditArchiveLease(env.PG72_ID_DB, {
      lease,
      leaseExpiresAt: at(310_000),
      renewedAt: at(12_000),
    });
    expect(first.status).toBe("renewed");
    expect(
      await renewAuditArchiveLease(env.PG72_ID_DB, {
        lease,
        leaseExpiresAt: at(309_000),
        renewedAt: at(13_000),
      }),
    ).toEqual({ lease: null, status: "conflict" });
  });

  it("finalizes once, clears only the D1 envelope, and advances the exact checkpoint", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const completedAt = at(310_500);
    const input = {
      completedAt,
      evidence: evidence(fixture.manifest, completedAt),
      lease,
    };
    const concurrent = await Promise.all([
      finalizeAuditArchiveLease(env.PG72_ID_DB, input),
      finalizeAuditArchiveLease(env.PG72_ID_DB, input),
    ]);
    expect(concurrent.toSorted()).toEqual(["applied", "duplicate"]);
    expect(await finalizeAuditArchiveLease(env.PG72_ID_DB, input)).toBe("duplicate");
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, encrypted_envelope IS NULL AS envelope_cleared,
                r2_version, r2_etag, r2_readback_sha256, r2_readback_at,
                archived_at, envelope_gc_at
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(fixture.input.batchKey)
        .first(),
    ).toEqual({
      archived_at: completedAt,
      envelope_cleared: 1,
      envelope_gc_at: completedAt,
      r2_etag: "etag-1",
      r2_readback_at: completedAt,
      r2_readback_sha256: fixture.manifest.objectSha256,
      r2_version: "version-1",
      status: "archived",
    });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT revision, last_sequence, last_batch_key, last_archived_at
           FROM audit_archive_checkpoint WHERE id = 1`,
      ).first(),
    ).toEqual({
      last_archived_at: completedAt,
      last_batch_key: fixture.input.batchKey,
      last_sequence: fixture.manifest.lastSequence,
      revision: fixture.manifest.batchGeneration,
    });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_key_sentinel",
      ).first<number>("count"),
    ).toBe(1);
  });

  it("rejects archive success evidence that disagrees with immutable object identity", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const completedAt = at(20_000);
    const correct = evidence(fixture.manifest, completedAt);
    for (const invalidEvidence of [
      { ...correct, observedBytes: correct.observedBytes - 1 },
      { ...correct, storedSha256: "f".repeat(64) },
      { ...correct, readbackSha256: "f".repeat(64) },
    ]) {
      expect(
        await finalizeAuditArchiveLease(env.PG72_ID_DB, {
          completedAt,
          evidence: invalidEvidence,
          lease,
        }),
      ).toBe("conflict");
    }
    await expectRepositoryError(
      Reflect.apply(finalizeAuditArchiveLease, undefined, [
        env.PG72_ID_DB,
        {
          completedAt,
          evidence: { ...correct, storedSha256: null },
          lease,
        },
      ]),
      "invalid_input",
    );
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, lease_id,
                encrypted_envelope IS NOT NULL AS has_envelope
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(fixture.input.batchKey)
        .first(),
    ).toEqual({ has_envelope: 1, lease_id: lease.leaseId, status: "processing" });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT outcome FROM audit_archive_attempt WHERE id = ?",
      )
        .bind(lease.leaseId)
        .first<string>("outcome"),
    ).toBe("in_flight");
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT revision, last_sequence, last_batch_key, last_archived_at
           FROM audit_archive_checkpoint WHERE id = 1`,
      ).first(),
    ).toEqual({
      last_archived_at: null,
      last_batch_key: null,
      last_sequence: 0,
      revision: 0,
    });
  });

  it("rolls back a mismatched readback digest and keeps the active lease and BLOB", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const completedAt = at(20_000);
    const wrongDigest = "f".repeat(64);
    expect(
      await finalizeAuditArchiveLease(env.PG72_ID_DB, {
        completedAt,
        evidence: {
          ...evidence(fixture.manifest, completedAt),
          readbackSha256: wrongDigest,
        },
        lease,
      }),
    ).toBe("conflict");
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, encrypted_envelope IS NOT NULL AS has_envelope,
                lease_id FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(fixture.input.batchKey)
        .first(),
    ).toEqual({ has_envelope: 1, lease_id: lease.leaseId, status: "processing" });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT outcome FROM audit_archive_attempt WHERE id = ?",
      )
        .bind(lease.leaseId)
        .first<string>("outcome"),
    ).toBe("in_flight");
  });

  it("records bounded transient attempts one through five and keeps immutable receipts", async () => {
    const fixture = await queuedFixture();
    const { firstFailure } = await driveFixtureToDead(fixture);
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, attempts, last_error_code,
                encrypted_envelope IS NOT NULL AS has_envelope
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(fixture.input.batchKey)
        .first(),
    ).toEqual({
      attempts: 5,
      has_envelope: 1,
      last_error_code: "r2_transient",
      status: "dead",
    });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_attempt",
      ).first<number>("count"),
    ).toBe(5);
    expect(await failAuditArchiveLease(env.PG72_ID_DB, firstFailure)).toBe("duplicate");
  });

  it("terminalizes expired leases only at the exact boundary through attempt five", async () => {
    const fixture = await queuedFixture();
    let claimAt = 11_000;
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const expiry = claimAt + 300_000;
      const lease = await acquire(fixture, at(claimAt), at(expiry));
      if (attempt === 1) {
        await expectRepositoryError(
          expireAuditArchiveLease(env.PG72_ID_DB, {
            completedAt: at(expiry - 1),
            lease,
            nextAttemptAt: at(expiry),
          }),
          "invalid_input",
        );
        await expectRepositoryError(
          finalizeAuditArchiveLease(env.PG72_ID_DB, {
            completedAt: at(expiry),
            evidence: evidence(fixture.manifest, at(expiry)),
            lease,
          }),
          "invalid_input",
        );
      }
      const expired = {
        completedAt: at(expiry),
        lease,
        nextAttemptAt: attempt === 5 ? null : at(expiry),
      };
      expect(await expireAuditArchiveLease(env.PG72_ID_DB, expired)).toBe("applied");
      expect(await expireAuditArchiveLease(env.PG72_ID_DB, expired)).toBe("duplicate");
      claimAt = expiry + 1;
    }
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, attempts, last_error_code FROM audit_archive_batch
          WHERE batch_key = ?`,
      )
        .bind(fixture.input.batchKey)
        .first(),
    ).toEqual({ attempts: 5, last_error_code: "lease_expired", status: "dead" });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT count(*) AS count FROM audit_archive_attempt
          WHERE outcome = 'lease_expired'`,
      ).first<number>("count"),
    ).toBe(5);
  });

  it("records pre-R2 crypto integrity failure without inventing R2 evidence", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const completedAt = at(20_000);
    const input = {
      completedAt,
      errorCode: "crypto_integrity" as const,
      evidence: null,
      lease,
      nextAttemptAt: null,
    };
    expect(await failAuditArchiveLease(env.PG72_ID_DB, input)).toBe("applied");
    expect(await failAuditArchiveLease(env.PG72_ID_DB, input)).toBe("duplicate");
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT outcome, error_code, r2_version, r2_etag,
                r2_observed_bytes, r2_stored_sha256,
                r2_readback_sha256, r2_readback_at,
                r2_conflict_evidence_format
           FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(lease.leaseId)
        .first(),
    ).toEqual({
      error_code: "crypto_integrity",
      outcome: "corrupt",
      r2_conflict_evidence_format: null,
      r2_etag: null,
      r2_observed_bytes: null,
      r2_readback_at: null,
      r2_readback_sha256: null,
      r2_stored_sha256: null,
      r2_version: null,
    });
  });

  it("records bounded metadata-only object conflicts without a body hash", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const completedAt = at(20_000);
    const conflictEvidence = {
      etag: "etag-existing-oversized",
      observedBytes: 524_289,
      readbackAt: completedAt,
      readbackSha256: null,
      storedSha256: null,
      version: "version-existing-oversized",
    };
    expect(
      await failAuditArchiveLease(env.PG72_ID_DB, {
        completedAt,
        errorCode: "r2_object_conflict",
        evidence: conflictEvidence,
        lease,
        nextAttemptAt: null,
      }),
    ).toBe("applied");
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT outcome, error_code, r2_version, r2_etag,
                r2_observed_bytes, r2_stored_sha256,
                r2_readback_sha256, r2_readback_at,
                r2_conflict_evidence_format
           FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(lease.leaseId)
        .first(),
    ).toEqual({
      error_code: "r2_object_conflict",
      outcome: "corrupt",
      r2_conflict_evidence_format: "observed_v1",
      r2_etag: conflictEvidence.etag,
      r2_observed_bytes: conflictEvidence.observedBytes,
      r2_readback_at: completedAt,
      r2_readback_sha256: null,
      r2_stored_sha256: null,
      r2_version: conflictEvidence.version,
    });
  });

  it("requires a full body hash for readback mismatch evidence", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const completedAt = at(20_000);
    await expectRepositoryError(
      Reflect.apply(failAuditArchiveLease, undefined, [
        env.PG72_ID_DB,
        {
          completedAt,
          errorCode: "r2_readback_mismatch",
          evidence: {
            ...evidence(fixture.manifest, completedAt, "incomplete"),
            readbackSha256: null,
          },
          lease,
          nextAttemptAt: null,
        },
      ]),
      "invalid_input",
    );
    const corruptionEvidence = {
      ...evidence(fixture.manifest, completedAt, "corrupt"),
      readbackSha256: "f".repeat(64),
    };
    expect(
      await failAuditArchiveLease(env.PG72_ID_DB, {
        completedAt,
        errorCode: "r2_readback_mismatch",
        evidence: corruptionEvidence,
        lease,
        nextAttemptAt: null,
      }),
    ).toBe("applied");
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, last_error_code,
                encrypted_envelope IS NOT NULL AS has_envelope,
                r2_version FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(fixture.input.batchKey)
        .first(),
    ).toEqual({
      has_envelope: 1,
      last_error_code: "r2_readback_mismatch",
      r2_version: null,
      status: "corrupt",
    });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT revision, last_sequence FROM audit_archive_checkpoint WHERE id = 1",
      ).first(),
    ).toEqual({ last_sequence: 0, revision: 0 });
  });

  it("lets one divergent terminal intent win and classifies the other as conflict", async () => {
    const fixture = await queuedFixture();
    const lease = await acquire(fixture, at(11_000), at(311_000));
    const completedAt = at(20_000);
    const results = await Promise.all([
      finalizeAuditArchiveLease(env.PG72_ID_DB, {
        completedAt,
        evidence: evidence(fixture.manifest, completedAt),
        lease,
      }),
      failAuditArchiveLease(env.PG72_ID_DB, {
        completedAt,
        errorCode: "r2_transient",
        evidence: null,
        lease,
        nextAttemptAt: completedAt,
      }),
    ]);
    expect(results.toSorted()).toEqual(["applied", "conflict"]);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_archive_attempt WHERE outcome = 'in_flight'",
      ).first<number>("count"),
    ).toBe(0);
  });

  it("atomically audits dead replay, recognizes response loss, and preserves the envelope", async () => {
    const fixture = await queuedFixture();
    await driveFixtureToDead(fixture);
    const replay = {
      auditEventId: `archive.replay.${crypto.randomUUID()}`,
      batchKey: fixture.input.batchKey,
      dispatchGeneration: 1,
      nextAttemptAt: at(2_000_000),
      replayedAt: at(2_000_000),
    };
    expect(await replayDeadAuditArchiveBatch(env.PG72_ID_DB, replay)).toBe("applied");
    expect(await replayDeadAuditArchiveBatch(env.PG72_ID_DB, replay)).toBe("duplicate");
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT status, dispatch_generation, attempts, manual_replay_audit_id,
                length(encrypted_envelope) AS envelope_bytes
           FROM audit_archive_batch WHERE batch_key = ?`,
      )
        .bind(fixture.input.batchKey)
        .first(),
    ).toEqual({
      attempts: 0,
      dispatch_generation: 2,
      envelope_bytes: fixture.manifest.objectBytes,
      manual_replay_audit_id: replay.auditEventId,
      status: "pending",
    });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT count(*) AS count FROM audit_archive_source
          WHERE event_id = ?`,
      )
        .bind(replay.auditEventId)
        .first<number>("count"),
    ).toBe(1);
  });

  it("gives one concurrent replay the audited reset without an orphan loser audit", async () => {
    const fixture = await queuedFixture();
    await driveFixtureToDead(fixture);
    const common = {
      batchKey: fixture.input.batchKey,
      dispatchGeneration: 1,
      nextAttemptAt: at(2_000_000),
      replayedAt: at(2_000_000),
    };
    const auditIds = [
      `archive.replay.${crypto.randomUUID()}`,
      `archive.replay.${crypto.randomUUID()}`,
    ];
    const results = await Promise.all(auditIds.map((auditEventId) =>
      replayDeadAuditArchiveBatch(env.PG72_ID_DB, { ...common, auditEventId })
    ));
    expect(results.toSorted()).toEqual(["applied", "conflict"]);
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT count(*) AS count FROM audit_event
          WHERE id IN (?, ?)`,
      )
        .bind(...auditIds)
        .first<number>("count"),
    ).toBe(1);
    const winner = await env.PG72_ID_DB.prepare(
      `SELECT manual_replay_audit_id FROM audit_archive_batch WHERE batch_key = ?`,
    )
      .bind(fixture.input.batchKey)
      .first<string>("manual_replay_audit_id");
    expect(auditIds).toContain(winner);
  });

  it("fails replay generation exhaustion before touching D1", async () => {
    const batchKey = reference();
    const auditEventId = `archive.replay.${crypto.randomUUID()}`;
    await expectRepositoryError(
      replayDeadAuditArchiveBatch(env.PG72_ID_DB, {
        auditEventId,
        batchKey,
        dispatchGeneration: 1_000_000,
        nextAttemptAt: at(2_000_000),
        replayedAt: at(2_000_000),
      }),
      "counter_exhausted",
      [batchKey, auditEventId],
    );
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT count(*) AS count FROM audit_event WHERE id = ?",
      )
        .bind(auditEventId)
        .first<number>("count"),
    ).toBe(0);
  });

  it("fails closed on malformed result shape, unsafe counters, and noncanonical time", async () => {
    await insertAuditEvent(1);
    const shapeDatabase = mutateBatchResult(env.PG72_ID_DB, (results) => {
      const row = results[0]?.results[0];
      if (typeof row === "object" && row !== null) {
        results[0]!.results[0] = { ...row, unexpected: true };
      }
    });
    await expectRepositoryError(
      selectAuditArchiveSource(shapeDatabase),
      "source_invalid",
    );

    const counterDatabase = mutateBatchResult(env.PG72_ID_DB, (results) => {
      const row = results[0]?.results[0];
      if (typeof row === "object" && row !== null) {
        results[0]!.results[0] = {
          ...row,
          revision: Number.MAX_SAFE_INTEGER + 1,
        };
      }
    });
    await expectRepositoryError(
      selectAuditArchiveSource(counterDatabase),
      "source_invalid",
    );

    const timestampDatabase = mutateBatchResult(env.PG72_ID_DB, (results) => {
      const row = results[1]?.results[0];
      if (typeof row === "object" && row !== null) {
        results[1]!.results[0] = {
          ...row,
          occurred_at: "2026-07-18T08:00:00Z",
        };
      }
    });
    await expectRepositoryError(
      selectAuditArchiveSource(timestampDatabase),
      "source_invalid",
      ["2026-07-18T08:00:00Z"],
    );
  });

  it("pins source, due, expired-lease, and identity query plans", async () => {
    const sourcePlan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN
       SELECT source.sequence
         FROM audit_archive_source AS source
        WHERE source.sequence > ?
        ORDER BY source.sequence
        LIMIT 101`,
    )
      .bind(0)
      .all<{ detail: string }>();
    expect(sourcePlan.results.map(({ detail }) => detail).join("\n")).toMatch(
      /SEARCH source USING INTEGER PRIMARY KEY \(rowid>\?\)/,
    );

    const duePlan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN
       SELECT batch_key FROM audit_archive_batch
        WHERE status IN ('pending', 'retry') AND next_attempt_at <= ?
        ORDER BY status, next_attempt_at, batch_key
        LIMIT 26`,
    )
      .bind(at(1))
      .all<{ detail: string }>();
    expect(duePlan.results.map(({ detail }) => detail).join("\n")).toContain(
      "audit_archive_batch_due_idx",
    );

    const expiredPlan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN
       SELECT batch.batch_key
         FROM audit_archive_batch AS batch
         JOIN audit_archive_attempt AS attempt
           ON attempt.batch_key = batch.batch_key
          AND attempt.dispatch_generation = batch.dispatch_generation
          AND attempt.attempt_number = batch.attempts
          AND attempt.lease_id = batch.lease_id
        WHERE batch.status = 'processing'
          AND batch.lease_expires_at <= ?
          AND attempt.outcome = 'in_flight'
        ORDER BY batch.lease_expires_at, batch.batch_key
        LIMIT 26`,
    )
      .bind(at(1))
      .all<{ detail: string }>();
    expect(expiredPlan.results.map(({ detail }) => detail).join("\n")).toContain(
      "audit_archive_batch_expired_lease_idx",
    );

    const identityPlan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN
       SELECT status FROM audit_archive_batch WHERE batch_key = ?`,
    )
      .bind(reference())
      .all<{ detail: string }>();
    expect(identityPlan.results.map(({ detail }) => detail).join("\n")).toContain(
      "sqlite_autoindex_audit_archive_batch_1",
    );
  });
});
